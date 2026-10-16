{-# LANGUAGE OverloadedStrings #-}
-- TLS wire/state code is ours; PKIX certificate-path verification is a
-- cryptographic trust primitive delegated to crypton-x509-validation.
module Lantern.TLS.Client (clientHandshake, TrustStore, systemTrust, trustFile) where
import Control.Monad (unless)
import Crypto.Hash (SHA256(..))
import qualified Crypto.PubKey.RSA.PSS as PSS
import qualified Crypto.PubKey.RSA.Types as RSA
import Crypto.PubKey.ECC.Types (CurveName(SEC_p256r1))
import Crypto.Random (getRandomBytes)
import Data.ByteArray (constEq)
import qualified Data.ByteString as B
import qualified Data.ByteString.Char8 as C
import Data.Char (isAscii, isAlphaNum, toLower)
import Data.IP (IP(..), fromIPv4, fromIPv6)
import Data.IORef
import Data.List (nub)
import Data.X509
import Data.X509.CertificateStore
import Data.X509.Validation
import Text.Read (readMaybe)
import System.X509 (getSystemCertificateStore)
import Lantern.TLS.CertificateEncoding
import Lantern.TLS.CertificatePolicy
import Lantern.TLS.KeyExchange
import Lantern.TLS.Negotiation
import Lantern.TLS.Crypto
import Lantern.TLS.Record
import Lantern.TLS.Wire

type TrustStore = CertificateStore
systemTrust :: IO TrustStore
systemTrust = getSystemCertificateStore
trustFile :: FilePath -> IO TrustStore
trustFile path = readCertificateStore path >>= maybe (abort "cannot load trust store") pure

clientHandshake :: RecordIO -> TrustStore -> String -> IO (B.ByteString,B.ByteString)
clientHandshake io trust hostname = do
  let reference=map toLower hostname
      ip=readMaybe reference :: Maybe IP
  ensure (maybe (validDNS reference) (const True) ip) "invalid TLS hostname"
  firstKey <- newShare 29
  random <- getRandomBytes 32
  session <- getRandomBytes 32
  let common = (case ip of Nothing -> extension 0 (vector 2 ("\x00" <> vector 2 (C.pack reference))); Just _ -> B.empty) <>
        extension 10 (vector 2 "\x00\x1d\x00\x17") <>
        extension 13 (vector 2 "\x08\x04\x04\x03\x08\x07") <>
        extension 50 (vector 2 certificateSignatureSchemes) <>
        extension 16 (vector 2 (vector 1 "http/1.1")) <>
        extension 43 (vector 1 "\x03\x04")
      buildHello key cookie = message 1 ("\x03\x03" <> random <> vector 1 session <>
        vector 2 "\x13\x01" <> "\x01\x00" <> vector 2 (common <>
          maybe B.empty (extension 44 . vector 2) cookie <>
          extension 51 (vector 2 (encode 2 (fromIntegral (shareGroup key)) <> vector 2 (sharePublic key)))))
      clientHello = buildHello firstKey Nothing
      readServer allowCCS ccs = do
        wire <- plainHandshake io allowCCS ccs B.empty 0
        (body,kind) <- decodeMessage wire
        ensure (kind == 2) "ServerHello required"
        parsed <- either abort pure (runParser (parseServerHello session) body)
        pure (wire,parsed)
      sendHello bytes = do
        ensure (B.length bytes <= 65536) "ClientHello too large"
        let loop remaining = do
              let (front,back)=B.splitAt 16384 remaining
              sendPlain io 22 front
              unless (B.null back) (loop back)
        loop bytes
  ccs <- newIORef (0 :: Int)
  sendHello clientHello
  (firstServer,firstResponse) <- readServer False ccs
  (private,serverHello,serverKey,prefix,retried) <- case firstResponse of
    ServerKey group key -> do
      ensure (group == shareGroup firstKey) "server selected an unoffered key share"
      pure (firstKey,firstServer,key,clientHello,False)
    RetryRequest group cookie -> do
      nextKey <- case group of
        Nothing -> pure firstKey
        Just selected -> do
          ensure (selected /= shareGroup firstKey) "retry requested an already offered group"
          newShare selected
      let nextHello=buildHello nextKey cookie
      sendPlain io 20 "\x01"
      sendHello nextHello
      (wire,response) <- readServer True ccs
      key <- case response of
        RetryRequest{} -> abort "second HelloRetryRequest"
        ServerKey selected key -> do
          ensure (selected == shareGroup nextKey) "server changed retry group"
          pure key
      pure (nextKey,wire,key,retryTranscript clientHello firstServer <> nextHello,True)
  shared <- agree private serverKey
  let zeros = B.replicate 32 0
      handshakeSecret = extract (deriveSecret (extract zeros zeros) "derived" B.empty) shared
      transcript0 = prefix <> serverHello
      serverHS = deriveSecret handshakeSecret "s hs traffic" transcript0
      clientHS = deriveSecret handshakeSecret "c hs traffic" transcript0
  ccsSeen <- readIORef ccs
  encryptedState <- newIORef (0,B.empty,ccsSeen)
  let next = encryptedHandshake io serverHS encryptedState
  ee <- next
  (eeBody,eeKind) <- decodeMessage ee
  ensure (eeKind == 8) "EncryptedExtensions required"
  exts <- either abort pure (runParser (vec 2) eeBody >>= parseExtensions)
  ensure (length exts <= 2 && length exts == length (nub (map fst exts)) && all ((`elem` (case ip of Nothing -> [0,16]; Just _ -> [16])) . fst) exts) "unsolicited server extension"
  case lookup 0 exts of Nothing -> pure (); Just b -> ensure (B.null b) "invalid SNI acknowledgement"
  case lookup 16 exts of
    Nothing -> pure ()
    Just b -> ensure (runParser (vec 2 >>= \p -> either fail pure (runParser (vec 1) p)) b == Right "http/1.1") "invalid server ALPN"
  certificate <- next
  (certificateBody,certificateKind) <- decodeMessage certificate
  ensure (certificateKind == 11) "Certificate required"
  chainBytes <- either abort pure (runParser parseCertificates certificateBody)
  mapM_ (either abort pure . certificateEncodingPolicy) chainBytes
  chain <- mapM (either (const (abort "invalid X.509 certificate")) pure . decodeSignedCertificate) chainBytes
  let referenceName = case ip of
        Nothing -> AltNameDNS reference
        Just (IPv4 address) -> AltNameIP (B.pack (map fromIntegral (fromIPv4 address)))
        Just (IPv6 address) -> AltNameIP (B.pack (concatMap (\w -> [fromIntegral (w `div` 256),fromIntegral w]) (fromIPv6 address)))
  either abort pure (certificatePolicy trust chain referenceName)
  let cache = ValidationCache (\_ _ _ -> pure ValidationCacheUnknown) (\_ _ _ -> pure ())
      checks = defaultChecks {checkStrictOrdering=True,checkLeafKeyPurpose=[KeyUsagePurpose_ServerAuth],checkLeafKeyUsage=[KeyUsage_digitalSignature]}
      hooks=defaultHooks {hookValidateName = \_ -> validateIdentity reference ip}
  failures <- validate HashSHA256 hooks checks trust cache (reference,B.empty) (CertificateChain chain)
  ensure (null failures) "server certificate validation failed"
  pub <- case chain of
    c:_ -> pure (certPubKey (getCertificate c))
    [] -> abort "empty server certificate chain"
  cv <- next
  (cvBody,cvKind) <- decodeMessage cv
  ensure (cvKind == 15) "CertificateVerify required"
  (scheme,signature) <- either abort pure (runParser ((,) <$> uint 2 <*> vec 2) cvBody)
  let transcript1 = transcript0 <> ee <> certificate
      signatureInput = B.replicate 64 32 <> "TLS 1.3, server CertificateVerify\x00" <> sha256 transcript1
      valid = case (scheme,pub) of
        (0x0804,PubKeyRSA rsa) -> RSA.public_size rsa >= 256 && RSA.public_size rsa <= 1024 && PSS.verify (PSS.defaultPSSParams SHA256) rsa signatureInput signature
        (0x0403,PubKeyEC (PubKeyEC_Named SEC_p256r1 _)) -> verifySignature (SignatureALG HashSHA256 PubKeyALG_EC) pub signatureInput signature == SignaturePass
        (0x0807,PubKeyEd25519 _) -> verifySignature (SignatureALG_IntrinsicHash PubKeyALG_Ed25519) pub signatureInput signature == SignaturePass
        _ -> False
  ensure valid "server CertificateVerify failed"
  serverFinished <- next
  (verifyData,finishedKind) <- decodeMessage serverFinished
  let transcript2 = transcript1 <> cv
  ensure (finishedKind == 20 && verifyData `constEq` finished serverHS transcript2) "server Finished verification failed"
  (_,left,_) <- readIORef encryptedState
  ensure (B.null left) "server Finished must end its record"
  let transcript3 = transcript2 <> serverFinished
      masterSecret = extract (deriveSecret handshakeSecret "derived" B.empty) zeros
      serverApp = deriveSecret masterSecret "s ap traffic" transcript3
      clientApp = deriveSecret masterSecret "c ap traffic" transcript3
  unless retried (sendPlain io 20 "\x01")
  _ <- sendProtected io clientHS 0 22 (message 20 (finished clientHS transcript3))
  pure (serverApp,clientApp)

parseCertificates :: Parser [B.ByteString]
parseCertificates = do
  context <- vec 1
  unless (B.null context) (fail "nonempty server certificate context")
  bytes <- vec 3
  certs <- either fail pure $ runParser (parseList (do
    cert <- vec 3
    unless (not (B.null cert) && B.length cert <= 65536) (fail "invalid certificate length")
    exts <- vec 2 >>= either fail pure . parseExtensions
    unless (length exts <= 128 && length exts == length (nub (map fst exts))) (fail "duplicate certificate extensions")
    pure cert)) bytes
  unless (not (null certs) && length certs <= 8) (fail "invalid certificate chain length")
  pure certs

decodeMessage :: B.ByteString -> IO (B.ByteString,Int)
decodeMessage = either abort pure . runParser (do k <- uint 1; b <- vec 3; pure (b,k))
messageSize :: B.ByteString -> Maybe Int
messageSize b | B.length b < 4 = Nothing
              | otherwise = Just (4+B.foldl' (\n c -> n*256+fromIntegral c) 0 (B.take 3 (B.drop 1 b)))

plainHandshake :: RecordIO -> Bool -> IORef Int -> B.ByteString -> Int -> IO B.ByteString
plainHandshake io allowCCS ccs buffer fragments = do
  ensure (fragments < 128) "too many ServerHello fragments"
  (kind,version,payload) <- readRaw io
  if kind == 20 then do
    seen <- readIORef ccs
    ensure (allowCCS && seen < 2 && version == 0x0303 && payload == "\x01" && B.null buffer) "invalid retry server CCS"
    writeIORef ccs (seen+1)
    plainHandshake io allowCCS ccs buffer (fragments+1)
  else do
    ensure (kind == 22 && version == 0x0303 && not (B.null payload) && B.length payload <= 16384) "invalid ServerHello record"
    let combined = buffer <> payload
    ensure (B.length combined <= 65536) "ServerHello too large"
    case messageSize combined of
      Just n | B.length combined >= n -> ensure (B.length combined == n) "extra plaintext handshake data" >> pure combined
      _ -> plainHandshake io allowCCS ccs combined (fragments+1)

encryptedHandshake :: RecordIO -> B.ByteString -> IORef (Word,B.ByteString,Int) -> IO B.ByteString
encryptedHandshake io secret ref = do
  (sequenceNo,buffer,ccsCount) <- readIORef ref
  case messageSize buffer of
    Just n | B.length buffer >= n -> do
      ensure (n <= 196608) "handshake message too large"
      writeIORef ref (sequenceNo,B.drop n buffer,ccsCount)
      pure (B.take n buffer)
    Just n | n > 196608 -> abort "handshake message too large"
    _ -> do
      (kind,version,payload) <- readRaw io
      if kind == 20 then do
        ensure (version == 0x0303 && payload == "\x01" && ccsCount < 2) "invalid server CCS"
        writeIORef ref (sequenceNo,buffer,ccsCount+1)
      else do
        (inner,plain) <- either abort pure (unprotect secret (fromIntegral sequenceNo) kind version payload)
        ensure (inner == 22 && not (B.null plain)) "encrypted handshake required"
        ensure (B.length buffer+B.length plain <= 212992) "handshake buffer too large"
        writeIORef ref (sequenceNo+1,buffer<>plain,ccsCount)
      encryptedHandshake io secret ref

-- RFC 9525 identity policy is stricter than the certificate verifier's legacy
-- default (which falls back to Common Name, including for IP-only SANs).
-- Keep chain/signature/time/purpose verification in the established primitive.
validateIdentity :: String -> Maybe IP -> Certificate -> [FailedReason]
validateIdentity reference ip cert =
  if any matches names then [] else [NameMismatch reference]
  where
    names=case extensionGet (certExtensions cert) of
      Just (ExtSubjectAltName entries) -> entries
      Nothing -> []
    matches (AltNameIP bytes)=case ip of
      Just (IPv4 address) -> bytes==B.pack (map fromIntegral (fromIPv4 address))
      Just (IPv6 address) -> bytes==B.pack (concatMap (\n -> [fromIntegral (n `div` 256),fromIntegral n]) (fromIPv6 address))
      Nothing -> False
    matches (AltNameDNS name)=case ip of
      Just _ -> False
      Nothing -> let normalized=map toLower name in
        case splitLabels normalized of
          "*":suffix -> not (null suffix) && validDNS (joinLabels suffix) &&
                        tail (splitLabels reference)==suffix
          _ -> validDNS normalized && normalized==reference
    matches _=False
    joinLabels []=""
    joinLabels [x]=x
    joinLabels (x:xs)=x++"."++joinLabels xs

validDNS :: String -> Bool
validDNS name=not (null name) && length name<=253 && all label (splitLabels name)
  where label value=not (null value) && length value<=63 && head value/='-' && last value/='-' &&
          all (\c -> isAscii c && (isAlphaNum c || c=='-')) value

splitLabels :: String -> [String]
splitLabels name=case break (=='.') name of
  (part,[]) -> [part]
  (part,_:rest') -> part:splitLabels rest'
