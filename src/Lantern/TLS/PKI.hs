{-# LANGUAGE OverloadedStrings #-}
-- | Key and CSR glue for ACME. All RSA operations remain crypton primitives.
module Lantern.TLS.PKI
  ( Key, generateKey, decodeKeyPEM, encodeKeyPEM, publicParts, signSHA256
  , createCSR, base64URL, certificateTimes
  ) where
import Control.Monad (unless)
import Crypto.Hash (SHA256(..))
import qualified Crypto.PubKey.RSA as R
import qualified Crypto.PubKey.RSA.PKCS15 as P
import qualified Data.ByteString as B
import qualified Data.ByteString.Char8 as C
import Data.Hourglass (Elapsed(..),timeGetElapsed)
import Data.X509 (decodeSignedCertificate,getCertificate,certValidity)
import Lantern.TLS.Credentials (decodePrivateKey,pem)
import Lantern.TLS.Wire (abort)

newtype Key = Key R.PrivateKey

generateKey :: IO Key
generateKey = Key . snd <$> R.generate 256 65537
decodeKeyPEM :: B.ByteString -> Either String Key
decodeKeyPEM = fmap Key . decodePrivateKey
encodeKeyPEM :: Key -> B.ByteString
encodeKeyPEM (Key k) = pemEncode "RSA PRIVATE KEY" (seqD (B.concat (map intD
  [0,R.public_n p,R.public_e p,R.private_d k,R.private_p k,R.private_q k,R.private_dP k,R.private_dQ k,R.private_qinv k])))
  where p=R.private_pub k
publicParts :: Key -> (B.ByteString,B.ByteString)
publicParts (Key k) = (unsigned (R.public_n p),unsigned (R.public_e p)) where p=R.private_pub k
signSHA256 :: Key -> B.ByteString -> IO B.ByteString
signSHA256 (Key k) bytes = P.signSafer (Just SHA256) k bytes >>= either (const (abort "RSA signing failed")) pure

createCSR :: Key -> [B.ByteString] -> IO B.ByteString
createCSR key names = do
  unless (not (null names) && all valid names) (abort "invalid CSR DNS names")
  let (n,e)=publicParts key
      algorithm = seqD (tag 6 "\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01" <> tag 5 B.empty)
      spki = seqD (algorithm <> tag 3 ("\x00" <> seqD (positive n <> positive e)))
      subject = seqD B.empty
      san = seqD (tag 6 "\x55\x1d\x11" <> tag 4 (seqD (B.concat (map (tag 130) names))))
      attributes = tag 160 (seqD (tag 6 "\x2a\x86\x48\x86\xf7\x0d\x01\x09\x0e" <> tag 49 (seqD san)))
      info = seqD (intD 0 <> subject <> spki <> attributes)
      signatureAlgorithm = seqD (tag 6 "\x2a\x86\x48\x86\xf7\x0d\x01\x01\x0b" <> tag 5 B.empty)
  signature <- signSHA256 key info
  pure (seqD (info <> signatureAlgorithm <> tag 3 ("\x00" <> signature)))
  where valid name = not (B.null name) && B.length name <= 253 && B.all (\c ->
          (c >= 48 && c <= 57) || (c >= 97 && c <= 122) || c `B.elem` ".-") name

certificateTimes :: B.ByteString -> Either String (Integer,Integer)
certificateTimes bytes = do
  certs <- pem "CERTIFICATE" bytes
  first <- case certs of c:_ -> Right c; _ -> Left "empty certificate chain"
  cert <- decodeSignedCertificate first
  let (start,end)=certValidity (getCertificate cert)
      seconds t = let Elapsed s=timeGetElapsed t in toInteger s
  pure (seconds start,seconds end)

unsigned :: Integer -> B.ByteString
unsigned n | n <= 0 = "\x00"
           | otherwise = B.reverse (B.unfoldr (\v -> if v == 0 then Nothing else Just (fromInteger (v `mod` 256),v `div` 256)) n)
positive :: B.ByteString -> B.ByteString
positive b = tag 2 (if B.head b >= 128 then "\x00"<>b else b)
intD :: Integer -> B.ByteString
intD = positive . unsigned
seqD :: B.ByteString -> B.ByteString
seqD = tag 48
tag :: Int -> B.ByteString -> B.ByteString
tag t b = B.singleton (fromIntegral t) <> len <> b
  where size=B.length b
        raw=unsigned (fromIntegral size)
        len=if size < 128 then B.singleton (fromIntegral size) else B.singleton (128+fromIntegral (B.length raw)) <> raw

base64With :: B.ByteString -> Bool -> B.ByteString -> B.ByteString
base64With alphabet padding = B.pack . go . B.unpack
  where
    at n = B.index alphabet (fromIntegral n)
    go []=[]
    go [a]=[at (a `div` 4),at ((a `mod` 4)*16)] ++ if padding then [61,61] else []
    go [a,b]=[at (a `div` 4),at ((a `mod` 4)*16+b `div` 16),at ((b `mod` 16)*4)] ++ if padding then [61] else []
    go (a:b:c:xs)=[at (a `div` 4),at ((a `mod` 4)*16+b `div` 16),at ((b `mod` 16)*4+c `div` 64),at (c `mod` 64)] ++ go xs
base64URL :: B.ByteString -> B.ByteString
base64URL = base64With "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_" False
pemEncode :: B.ByteString -> B.ByteString -> B.ByteString
pemEncode name bytes = "-----BEGIN " <> name <> "-----\n" <> C.unlines (chunks encoded) <> "-----END " <> name <> "-----\n"
  where encoded=base64With "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/" True bytes
        chunks b | B.null b = []
                 | otherwise = B.take 64 b:chunks (B.drop 64 b)
