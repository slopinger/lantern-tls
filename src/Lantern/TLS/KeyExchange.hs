{-# LANGUAGE OverloadedStrings #-}
-- Wire encodings and group policy are ours; curve arithmetic and entropy are
-- established Crypton primitives. Private keys deliberately have no Show instance.
module Lantern.TLS.KeyExchange
  ( KeyShare, supportedGroups, newShare, shareGroup, sharePublic, validateShare, agree ) where
import Crypto.Error
import qualified Crypto.PubKey.Curve25519 as X
import qualified Crypto.PubKey.ECC.P256 as P
import Data.ByteArray (convert, constEq)
import qualified Data.ByteString as B
import Lantern.TLS.Wire

data KeyShare = XShare X.SecretKey | PShare P.Scalar
supportedGroups :: [Int]
supportedGroups = [29,23]
newShare :: Int -> IO KeyShare
newShare 29 = XShare <$> X.generateSecretKey
newShare 23 = do
  scalar <- P.scalarGenerate
  if P.scalarIsZero scalar || P.scalarCmp scalar P.scalarN /= LT then newShare 23 else pure (PShare scalar)
newShare _ = abort "unsupported key exchange group"
shareGroup :: KeyShare -> Int
shareGroup XShare{} = 29
shareGroup PShare{} = 23
sharePublic :: KeyShare -> B.ByteString
sharePublic (XShare key) = convert (X.toPublic key)
sharePublic (PShare key) = "\x04" <> P.pointToBinary (P.toPoint key)

p256Point :: B.ByteString -> Either String P.Point
p256Point bytes
  | B.length bytes /= 65 || B.take 1 bytes /= "\x04" = Left "invalid uncompressed P-256 key share"
  | otherwise = case P.pointFromBinary (B.drop 1 bytes) of
      CryptoPassed point | not (P.pointIsAtInfinity point) -> Right point
      _ -> Left "invalid P-256 point"
validateShare :: Int -> B.ByteString -> Either String ()
validateShare 29 bytes = if B.length bytes == 32 then Right () else Left "invalid X25519 key size"
validateShare 23 bytes = () <$ p256Point bytes
validateShare _ _ = Left "unsupported key exchange group"
agree :: KeyShare -> B.ByteString -> IO B.ByteString
agree key bytes = do
  shared <- case key of
    XShare scalar -> case X.publicKey bytes of
      CryptoPassed peer -> pure (convert (X.dh peer scalar))
      CryptoFailed _ -> abort "invalid X25519 key"
    PShare scalar -> P.pointDh scalar <$> either abort pure (p256Point bytes)
  ensure (B.length shared == 32 && not (shared `constEq` B.replicate 32 0)) "invalid ECDHE shared secret"
  pure shared
