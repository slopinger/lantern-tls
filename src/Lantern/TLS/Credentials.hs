{-# LANGUAGE OverloadedStrings #-}
-- Minimal strict PEM/DER decoding for local RSA server credentials. No trust-store
-- or remote certificate validation API is provided by this server-only library.
module Lantern.TLS.Credentials (Credentials(..), loadCredentials, decodePrivateKey, pem) where
import Control.Monad (unless)
import qualified Crypto.PubKey.RSA.Types as RSA
import qualified Data.ByteString as B
import qualified Data.ByteString.Char8 as C
import Data.List (elemIndex)
import System.IO (withBinaryFile,IOMode(ReadMode))
import Lantern.TLS.Wire

data Credentials = Credentials { certificateChain :: [B.ByteString], signingKey :: RSA.PrivateKey }
-- Deliberately no Show instance: errors and logging must never print private keys.

loadCredentials :: FilePath -> FilePath -> IO Credentials
loadCredentials certFile keyFile = do
  certPEM <- boundedRead certFile
  keyPEM <- boundedRead keyFile
  let result = do
        certs <- pem "CERTIFICATE" certPEM
        unless (not (null certs) && length certs <= 8 && all ((<=65536) . B.length) certs) $ Left "invalid certificate chain size"
        keys <- pemKey keyPEM
        key <- decodeKey keys
        first <- case certs of c:_ -> Right c; [] -> Left "empty certificate chain"
        (n,e) <- certPublic first
        unless (n == RSA.public_n (RSA.private_pub key) && e == RSA.public_e (RSA.private_pub key)) $ Left "certificate/key mismatch"
        pure (Credentials certs key)
  either (const (abort "invalid RSA certificate/private key (RSA 2048..8192, unencrypted PEM required)")) pure result
  where
    boundedRead file = do
      b <- withBinaryFile file ReadMode (\h -> B.hGet h 1048577)
      ensure (B.length b <= 1048576) "credential file too large"
      pure b

pemKey :: B.ByteString -> Either String B.ByteString
pemKey bytes
  | "-----BEGIN PRIVATE KEY-----" `B.isInfixOf` bytes = do
      blocks <- pem "PRIVATE KEY" bytes
      case blocks of
        [b] -> do
          fields <- sequenceDER b
          case fields of
            [(2,v),(48,alg),(4,key)] | integerValue v == Right 0 -> rsaAlgorithm alg >> pure key
            _ -> Left "invalid PKCS8"
        _ -> Left "exactly one key required"
  | otherwise = do
      blocks <- pem "RSA PRIVATE KEY" bytes
      case blocks of [b] -> pure b; _ -> Left "exactly one key required"

pem :: B.ByteString -> B.ByteString -> Either String [B.ByteString]
pem name input = go (C.lines input) []
  where
    begin = "-----BEGIN " <> name <> "-----"
    end = "-----END " <> name <> "-----"
    clean = C.filter (/= '\r')
    go [] acc = Right (reverse acc)
    go (l:ls) acc
      | clean l == begin = case break ((==end) . clean) ls of
          (_,[]) -> Left "unterminated PEM"
          (payload,_:remaining) -> do
            b <- base64 (B.concat (map clean payload))
            go remaining (b:acc)
      | C.all (`elem` [' ','\r','\t']) l = go ls acc
      | otherwise = Left "unexpected PEM data"

base64 :: B.ByteString -> Either String B.ByteString
base64 input
  | B.length input `mod` 4 /= 0 = Left "invalid base64 size"
  | otherwise = B.pack <$> go (C.unpack input)
  where
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    val c = maybe (Left "invalid base64 character") (Right . fromIntegral) (elemIndex c alphabet)
    go [] = Right []
    go [a,b,'=','='] = do x <- val a; y <- val b
                          unless (y `mod` 16 == 0) (Left "noncanonical base64")
                          pure [x*4+y `div` 16]
    go [a,b,c,'='] = do x <- val a; y <- val b; z <- val c
                        unless (z `mod` 4 == 0) (Left "noncanonical base64")
                        pure [x*4+y `div` 16,y*16+z `div` 4]
    go (a:b:c:d:xs) = do
      x <- val a; y <- val b; z <- val c; w <- val d
      more <- go xs
      pure (x*4+y `div` 16:y*16+z `div` 4:z*64+w:more)
    go _ = Left "invalid base64"

-- DER short/long definite lengths, canonical encodings only, at most 1 MiB.
der :: Parser (Int,B.ByteString)
der = do
  tag <- uint 1
  first <- uint 1
  size <- if first < 128 then pure first else do
    let n = first-128
    unless (n >= 1 && n <= 3) (fail "invalid DER length")
    b <- takeN n
    unless (not (B.null b) && B.head b /= 0) (fail "noncanonical DER length")
    let len = B.foldl' (\a c -> a*256+fromIntegral c) 0 b
    unless (len >= 128 && len <= 1048576) (fail "invalid DER length")
    pure len
  payload <- takeN size
  pure (tag,payload)
sequenceDER :: B.ByteString -> Either String [(Int,B.ByteString)]
sequenceDER b = do
  (tag,payload) <- runParser der b
  unless (tag == 48) (Left "expected DER sequence")
  runParser (parseList der) payload
integerValue :: B.ByteString -> Either String Integer
integerValue b = do
  unless (not (B.null b) && B.head b < 128 && B.length b <= 1025) $ Left "invalid integer"
  unless (B.length b == 1 || B.head b /= 0 || B.index b 1 >= 128) $ Left "noncanonical integer"
  pure (B.foldl' (\n c -> n*256+fromIntegral c) 0 b)

decodeKey :: B.ByteString -> Either String RSA.PrivateKey
decodeKey bytes = do
  fields <- sequenceDER bytes
  ints <- mapM (\(t,b) -> if t == 2 then integerValue b else Left "integer expected") fields
  case ints of
    [0,n,e,d,p,q,dp,dq,qi] -> do
      let size = (bitLength n+7) `div` 8
      unless (bitLength n >= 2048 && bitLength n <= 8192 && e >= 3 && odd e &&
          p > 1 && q > 1 && p /= q && n == p*q && dp == d `mod` (p-1) &&
          dq == d `mod` (q-1) && (qi*q) `mod` p == 1 && (e*d) `mod` lcm (p-1) (q-1) == 1) $
        Left "invalid RSA parameters"
      pure (RSA.PrivateKey (RSA.PublicKey size n e) d p q dp dq qi)
    _ -> Left "invalid RSA key sequence"
  where bitLength :: Integer -> Int
        bitLength n | n <= 0 = 0
                    | otherwise = 1+bitLength (n `div` 2)

rsaAlgorithm :: B.ByteString -> Either String ()
rsaAlgorithm bytes = do
  fields <- runParser (parseList der) bytes
  unless (fields == [(6,"\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01"),(5,B.empty)]) $ Left "rsaEncryption required"

certPublic :: B.ByteString -> Either String (Integer,Integer)
certPublic bytes = do
  cert <- sequenceDER bytes
  tbs <- case cert of
    [(48,t),(48,_),(3,_)] -> runParser (parseList der) t
    _ -> Left "invalid certificate"
  let stripped = case tbs of (160,_):xs -> xs; xs -> xs
  spki <- case drop 5 stripped of (48,body):_ -> Right body; _ -> Left "missing SPKI"
  fields <- runParser (parseList der) spki
  bits <- case fields of [(48,alg),(3,b)] -> rsaAlgorithm alg >> Right b; _ -> Left "invalid SPKI"
  unless (not (B.null bits) && B.head bits == 0) $ Left "invalid BIT STRING"
  key <- sequenceDER (B.tail bits)
  case key of [(2,n),(2,e)] -> (,) <$> integerValue n <*> integerValue e
              _ -> Left "invalid public key"

decodePrivateKey :: B.ByteString -> Either String RSA.PrivateKey
decodePrivateKey bytes = pemKey bytes >>= decodeKey
