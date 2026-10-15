{-# LANGUAGE OverloadedStrings #-}
module Lantern.TLS.Handshake (serverHandshake, parseClientHello, ClientHello(..)) where
import Control.Monad (unless, when)
import Crypto.Error (CryptoFailable(..))
import Crypto.Hash (SHA256(..))
import qualified Crypto.PubKey.Curve25519 as X
import qualified Crypto.PubKey.RSA.PSS as PSS
import Crypto.Random (getRandomBytes)
import Data.ByteArray (convert, constEq)
import qualified Data.ByteString as B
import Data.List (nub)
import Lantern.TLS.Credentials
import Lantern.TLS.Crypto
import Lantern.TLS.Record
import Lantern.TLS.Wire

data ClientHello = ClientHello
  { helloSession :: B.ByteString, helloKey :: B.ByteString, helloALPN :: [B.ByteString]
  } deriving (Eq, Show)

parseClientHello :: B.ByteString -> Either String ClientHello
parseClientHello bytes = runParser parser bytes
  where
    parser = do
      version <- uint 2
      unless (version == 0x0303) (fail "legacy version must be TLS 1.2")
      _ <- takeN 32
      session <- vec 1
      unless (B.length session <= 32) (fail "invalid session ID")
      suites <- vec 2
      offeredSuites <- sub (parseList (uint 2)) suites
      unless (0x1301 `elem` offeredSuites) (fail "AES-128-GCM required")
      compression <- vec 1
      unless (compression == "\x00") (fail "invalid compression")
      extBytes <- vec 2
      exts <- either fail pure (parseExtensions extBytes)
      unless (length exts <= 128 && length exts == length (nub (map fst exts))) (fail "duplicate or excessive extensions")
      versions <- required 43 exts >>= sub (vec 1) >>= sub (parseList (uint 2))
      unless (0x0304 `elem` versions) (fail "TLS 1.3 required")
      groups <- required 10 exts >>= sub (vec 2) >>= sub (parseList (uint 2))
      unless (29 `elem` groups) (fail "X25519 group required")
      signatures <- required 13 exts >>= sub (vec 2) >>= sub (parseList (uint 2))
      unless (0x0804 `elem` signatures) (fail "RSA-PSS-RSAE-SHA256 required")
      shares <- required 51 exts >>= sub (vec 2) >>= sub (parseList ((,) <$> uint 2 <*> vec 2))
      unless (length shares == length (nub (map fst shares)) && all (\(g,_) -> g `elem` groups) shares) $
        fail "invalid key shares"
      key <- maybe (fail "an X25519 key share is required; HelloRetryRequest unsupported") pure (lookup 29 shares)
      unless (B.length key == 32) (fail "invalid X25519 key size")
      when (lookup 42 exts /= Nothing) (fail "early data unsupported")
      when (lookup 41 exts /= Nothing) $ do
        unless (not (null exts) && fst (last exts) == 41 && lookup 45 exts /= Nothing) (fail "invalid PSK extension ordering")
      protocols <- case lookup 16 exts of
        Nothing -> pure []
        Just b -> sub (vec 2) b >>= sub (parseList (vec 1))
      unless (all (not . B.null) protocols) (fail "empty ALPN protocol")
      -- Validate SNI structure even though certificate selection uses the configured SAN chain.
      case lookup 0 exts of
        Nothing -> pure ()
        Just b -> do
          names <- sub (vec 2) b >>= sub (parseList ((,) <$> uint 1 <*> vec 2))
          unless (not (null names) && length names == length (nub (map fst names)) &&
                  all (\(t,n) -> t == 0 && not (B.null n) && B.all (\c -> c > 32 && c < 127 && c /= 0) n) names) $
            fail "invalid SNI"
      pure (ClientHello session key protocols)
    sub p b = either fail pure (runParser p b)
    required k exts = maybe (fail "missing required TLS extension") pure (lookup k exts)

-- Returns read/write application secrets after authenticating client Finished.
serverHandshake :: RecordIO -> Credentials -> [B.ByteString] -> IO (B.ByteString,B.ByteString)
serverHandshake io credentials protocols = do
  clientWire <- readHello B.empty (0 :: Int)
  clientBody <- either abort pure (runParser (do
    kind <- uint 1
    unless (kind == 1) (fail "ClientHello required")
    vec 3) clientWire)
  hello <- either abort pure (parseClientHello clientBody)
  selected <- if null (helloALPN hello) then pure Nothing else
    maybe (abort "no mutually supported ALPN") (pure . Just) (firstMatch protocols (helloALPN hello))
  private <- X.generateSecretKey
  peer <- case X.publicKey (helloKey hello) of CryptoPassed p -> pure p; CryptoFailed _ -> abort "invalid X25519 key"
  let shared = convert (X.dh peer private) :: B.ByteString
  ensure (not (shared `constEq` B.replicate 32 0)) "invalid X25519 shared secret"
  random <- getRandomBytes 32
  let public = convert (X.toPublic private) :: B.ByteString
      extensions = extension 43 "\x03\x04" <> extension 51 ("\x00\x1d" <> vector 2 public)
      serverHello = message 2 ("\x03\x03" <> random <> vector 1 (helloSession hello) <>
                                "\x13\x01\x00" <> vector 2 extensions)
      transcript0 = clientWire <> serverHello
      zeros = B.replicate 32 0
      earlySecret = extract zeros zeros
      handshakeSecret = extract (deriveSecret earlySecret "derived" B.empty) shared
      clientHS = deriveSecret handshakeSecret "c hs traffic" transcript0
      serverHS = deriveSecret handshakeSecret "s hs traffic" transcript0
      alpnExt = maybe B.empty (extension 16 . vector 2 . vector 1) selected
      encryptedExtensions = message 8 (vector 2 alpnExt)
      certificate = message 11 ("\x00" <> vector 3
        (B.concat [vector 3 cert <> "\x00\x00" | cert <- certificateChain credentials]))
      transcript1 = transcript0 <> encryptedExtensions <> certificate
      signatureInput = B.replicate 64 32 <> "TLS 1.3, server CertificateVerify\x00" <> sha256 transcript1
  signature <- PSS.signSafer (PSS.defaultPSSParams SHA256) (signingKey credentials) signatureInput
    >>= either (const (abort "RSA signature failed")) pure
  let certificateVerify = message 15 ("\x08\x04" <> vector 2 signature)
      transcript2 = transcript1 <> certificateVerify
      serverFinished = message 20 (finished serverHS transcript2)
      transcript3 = transcript2 <> serverFinished
      masterSecret = extract (deriveSecret handshakeSecret "derived" B.empty) zeros
      clientApp = deriveSecret masterSecret "c ap traffic" transcript3
      serverApp = deriveSecret masterSecret "s ap traffic" transcript3
  sendPlain io 22 serverHello
  -- Compatibility CCS is allowed but is not part of the transcript or key schedule.
  unless (B.null (helloSession hello)) (sendPlain io 20 "\x01")
  _ <- sendProtected io serverHS 0 22 (encryptedExtensions <> certificate <> certificateVerify <> serverFinished)
  clientFinished <- readFinished clientHS 0 B.empty (0 :: Int)
  ensure (B.drop 4 clientFinished `constEq` finished clientHS transcript3) "client Finished verification failed"
  pure (clientApp,serverApp)
  where
    readHello buffer records = do
      ensure (records < 128) "too many ClientHello fragments"
      (kind,version,payload) <- readRaw io
      ensure (kind == 22 && version `elem` [0x0301,0x0303] && not (B.null payload) && B.length payload <= 16384) "invalid ClientHello record"
      let combined = buffer <> payload
      ensure (B.length combined <= 65536) "ClientHello too large"
      case handshakeLength combined of
        Nothing -> readHello combined (records+1)
        Just n -> if B.length combined < n then readHello combined (records+1) else do
          ensure (B.length combined == n) "unexpected handshake after ClientHello"
          pure combined
    readFinished secret sequenceNo buffer ccsCount = do
      (kind,version,payload) <- readRaw io
      if kind == 20 then do
        ensure (version == 0x0303 && payload == "\x01" && ccsCount < 2) "invalid CCS"
        readFinished secret sequenceNo buffer (ccsCount+1)
      else do
        (innerType,plain) <- either abort pure (unprotect secret sequenceNo kind version payload)
        ensure (innerType == 22 && not (B.null plain)) "client Finished required"
        let combined = buffer <> plain
        ensure (B.length combined <= 36) "invalid client Finished size"
        case handshakeLength combined of
          Just 36 | B.length combined == 36 -> do
            ensure (B.head combined == 20) "client Finished required"
            pure combined
          Just n | n /= 36 -> abort "invalid Finished message"
          _ -> readFinished secret (sequenceNo+1) combined ccsCount
    firstMatch [] _ = Nothing
    firstMatch (a:as) offered = if a `elem` offered then Just a else firstMatch as offered

handshakeLength :: B.ByteString -> Maybe Int
handshakeLength b
  | B.length b < 4 = Nothing
  | otherwise = Just (4 + B.foldl' (\n c -> n*256+fromIntegral c) 0 (B.take 3 (B.drop 1 b)))
