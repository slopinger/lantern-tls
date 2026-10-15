{-# LANGUAGE OverloadedStrings #-}
module Lantern.TLS.Crypto
  ( sha256, mac, extract, expandLabel, deriveSecret, finished, trafficKey, nextSecret
  , seal, unseal, nonceFor
  ) where
import Crypto.Cipher.AES (AES128)
import Crypto.Cipher.Types
import Crypto.Error
import Crypto.Hash (SHA256(..), Digest, hash)
import qualified Crypto.KDF.HKDF as H
import qualified Crypto.MAC.HMAC as M
import Data.Bits (xor)
import Data.ByteArray (convert)
import qualified Data.ByteString as B
import Data.Word (Word64)
import Lantern.TLS.Wire

sha256 :: B.ByteString -> B.ByteString
sha256 b = convert (hash b :: Digest SHA256)
mac :: B.ByteString -> B.ByteString -> B.ByteString
mac key b = convert (M.hmac key b :: M.HMAC SHA256)
extract :: B.ByteString -> B.ByteString -> B.ByteString
extract salt ikm = convert (H.extract salt ikm :: H.PRK SHA256)
expandLabel :: B.ByteString -> B.ByteString -> B.ByteString -> Int -> B.ByteString
expandLabel secret label context len = H.expand (H.extractSkip secret :: H.PRK SHA256)
  (encode 2 (fromIntegral len) <> vector 1 ("tls13 " <> label) <> vector 1 context) len
-- | context is the complete handshake transcript, not a precomputed hash.
deriveSecret :: B.ByteString -> B.ByteString -> B.ByteString -> B.ByteString
deriveSecret secret label transcript = expandLabel secret label (sha256 transcript) 32
finished :: B.ByteString -> B.ByteString -> B.ByteString
finished secret transcript = mac (expandLabel secret "finished" B.empty 32) (sha256 transcript)
trafficKey :: B.ByteString -> (B.ByteString,B.ByteString)
trafficKey secret = (expandLabel secret "key" B.empty 16,expandLabel secret "iv" B.empty 12)
nextSecret :: B.ByteString -> B.ByteString
nextSecret secret = expandLabel secret "traffic upd" B.empty 32
nonceFor :: B.ByteString -> Word64 -> B.ByteString
nonceFor iv seqNo = B.pack (B.zipWith xor iv (B.replicate 4 0 <> encode 8 (fromIntegral seqNo)))

aead :: B.ByteString -> B.ByteString -> Either String (AEAD AES128)
aead key nonce = do
  cipher <- result (cipherInit key :: CryptoFailable AES128)
  result (aeadInit AEAD_GCM cipher nonce)
  where result (CryptoPassed x) = Right x
        result (CryptoFailed _) = Left "invalid cipher parameters"
seal :: B.ByteString -> B.ByteString -> B.ByteString -> B.ByteString -> Either String B.ByteString
seal key nonce aad plaintext = do
  c <- aead key nonce
  let (tag,encrypted) = aeadSimpleEncrypt c aad plaintext 16
  pure (encrypted <> convert tag)
unseal :: B.ByteString -> B.ByteString -> B.ByteString -> B.ByteString -> Either String B.ByteString
unseal key nonce aad ciphertext = do
  unlessLength
  c <- aead key nonce
  let (encrypted,tag) = B.splitAt (B.length ciphertext - 16) ciphertext
  maybe (Left "record authentication failed") Right (aeadSimpleDecrypt c aad encrypted (AuthTag (convert tag)))
  where unlessLength = if B.length ciphertext >= 16 then Right () else Left "short authenticated record"
