{-# LANGUAGE OverloadedStrings #-}
module Lantern.TLS.Handshake (serverHandshake, parseClientHello, ClientHello(..)) where
import Control.Monad (unless, when, forM_)
import Crypto.Hash (SHA256(..))
import qualified Crypto.PubKey.RSA.PSS as PSS
import Crypto.Random (getRandomBytes)
import Data.ByteArray (constEq)
import qualified Data.ByteString as B
import Data.List (nub, isSubsequenceOf)
import Lantern.TLS.KeyExchange
import Lantern.TLS.Negotiation
import Lantern.TLS.Credentials
import Lantern.TLS.Crypto
import Lantern.TLS.Record
import Lantern.TLS.Wire

data ClientHello = ClientHello
  { helloSession :: B.ByteString, helloShares :: [(Int,B.ByteString)], helloALPN :: [B.ByteString]
  , helloGroups :: [Int], helloPrefix :: B.ByteString, helloExtensions :: [(Int,B.ByteString)]
  , helloPSKs :: [B.ByteString]
  } deriving (Eq, Show)

parseClientHello :: B.ByteString -> Either String ClientHello
parseClientHello bytes = runParser parser bytes
  where
    parser = do
      version <- uint 2
      unless (version == 0x0303) (fail "legacy version must be TLS 1.2")
      random <- takeN 32
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
      unless (not (null groups) && length groups <= 128 && length groups == length (nub groups) && any (`elem` supportedGroups) groups) (fail "no supported ECDHE group")
      signatures <- required 13 exts >>= sub (vec 2) >>= sub (parseList (uint 2))
      unless (0x0804 `elem` signatures) (fail "RSA-PSS-RSAE-SHA256 required")
      shares <- required 51 exts >>= sub (vec 2) >>= sub (parseList ((,) <$> uint 2 <*> vec 2))
      unless (length shares == length (nub (map fst shares)) && map fst shares `isSubsequenceOf` groups && all (not . B.null . snd) shares) $
        fail "invalid key shares"
      mapM_ (\(g,key) -> when (g `elem` supportedGroups) (either fail pure (validateShare g key))) shares
      when (lookup 42 exts /= Nothing) (fail "early data unsupported")
      when (lookup 44 exts /= Nothing) (fail "unsolicited client cookie")
      forM_ (lookup 21 exts) $ \padding -> unless (B.all (==0) padding) (fail "nonzero padding")
      psks <- case lookup 41 exts of
        Nothing -> pure []
        Just pskBytes -> do
          unless (not (null exts) && fst (last exts) == 41) (fail "invalid PSK extension ordering")
          modes <- required 45 exts >>= sub (vec 1)
          unless (not (B.null modes)) (fail "empty PSK modes")
          (identities,binders) <- sub ((,) <$> vec 2 <*> vec 2) pskBytes
          entries <- sub (parseList (do identity <- vec 2; _ <- takeN 4; unless (not (B.null identity)) (fail "empty PSK identity"); pure identity)) identities
          values <- sub (parseList (vec 1)) binders
          unless (not (null entries) && length entries == length values && all ((>=32) . B.length) values) (fail "invalid PSK binders")
          pure entries
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
      let prefix=encode 2 (fromIntegral version) <> random <> vector 1 session <> vector 2 suites <> vector 1 compression
      pure (ClientHello session shares protocols groups prefix exts psks)
    sub p b = either fail pure (runParser p b)
    required k exts = maybe (fail "missing required TLS extension") pure (lookup k exts)

-- Returns read/write application secrets after authenticating client Finished.
serverHandshake :: RecordIO -> Credentials -> [B.ByteString] -> IO (B.ByteString,B.ByteString)
serverHandshake io credentials protocols = do
  firstWire <- readHello False B.empty (0 :: Int) (0 :: Int)
  first <- decodeHello firstWire
  let available=[(g,key) | g <- supportedGroups, Just key <- [lookup g (helloShares first)]]
  (hello,group,peerKey,prefix,retried) <- case available of
    (g,key):_ -> pure (first,g,key,firstWire,False)
    [] -> do
      group <- maybe (abort "no common ECDHE group") pure (firstMatch supportedGroups (helloGroups first))
      let retry=serverHelloWire retryRandom (helloSession first)
            (extension 43 "\x03\x04" <> extension 51 (encode 2 (fromIntegral group)))
      sendPlain io 22 retry
      unless (B.null (helloSession first)) (sendPlain io 20 "\x01")
      nextWire <- readHello True B.empty 0 0
      next <- decodeHello nextWire
      let stable=filter (\(kind,_) -> kind `notElem` [21,41,51]) . helloExtensions
      ensure (helloPrefix first == helloPrefix next && stable first == stable next &&
              helloPSKs next `isSubsequenceOf` helloPSKs first) "ClientHello changed during retry"
      key <- case helloShares next of
        [(g,value)] | g == group -> pure value
        _ -> abort "retry requires exactly the requested key share"
      pure (next,group,key,retryTranscript firstWire retry <> nextWire,True)
  selected <- if null (helloALPN hello) then pure Nothing else
    maybe (abort "no mutually supported ALPN") (pure . Just) (firstMatch protocols (helloALPN hello))
  private <- newShare group
  shared <- agree private peerKey
  random <- getRandomBytes 32
  let extensions = extension 43 "\x03\x04" <> extension 51 (encode 2 (fromIntegral group) <> vector 2 (sharePublic private))
      serverHello = serverHelloWire random (helloSession hello) extensions
      transcript0 = prefix <> serverHello
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
  unless (retried || B.null (helloSession hello)) (sendPlain io 20 "\x01")
  _ <- sendProtected io serverHS 0 22 (encryptedExtensions <> certificate <> certificateVerify <> serverFinished)
  clientFinished <- readFinished clientHS 0 B.empty (0 :: Int)
  ensure (B.drop 4 clientFinished `constEq` finished clientHS transcript3) "client Finished verification failed"
  pure (clientApp,serverApp)
  where
    decodeHello wire = do
      body <- either abort pure (runParser (do
        kind <- uint 1
        unless (kind == 1) (fail "ClientHello required")
        vec 3) wire)
      either abort pure (parseClientHello body)
    readHello :: Bool -> B.ByteString -> Int -> Int -> IO B.ByteString
    readHello retry buffer records ccsCount = do
      ensure (records < 128) "too many ClientHello fragments"
      (kind,version,payload) <- readRaw io
      if kind == 20 then do
        ensure (retry && version == 0x0303 && payload == "\x01" && ccsCount < 2 && B.null buffer) "invalid retry CCS"
        readHello retry buffer (records+1) (ccsCount+1)
      else do
        ensure (kind == 22 && (version == 0x0303 || (not retry && version == 0x0301)) && not (B.null payload) && B.length payload <= 16384) "invalid ClientHello record"
        let combined = buffer <> payload
        ensure (B.length combined <= 65536) "ClientHello too large"
        case handshakeLength combined of
          Nothing -> readHello retry combined (records+1) ccsCount
          Just n -> if B.length combined < n then readHello retry combined (records+1) ccsCount else do
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
