{-# LANGUAGE OverloadedStrings #-}
module Main (main) where
import Control.Monad (unless)
import Data.Bits (xor)
import qualified Data.ByteString as B
import Data.Char (digitToInt,isHexDigit)
import Data.Word (Word64)
import Lantern.TLS.Crypto
import Lantern.TLS.Record
import System.Exit (exitFailure)
import Test.QuickCheck

hex :: String -> B.ByteString
hex = B.pack . go . filter isHexDigit
  where go (a:b:xs) = fromIntegral (digitToInt a*16+digitToInt b):go xs
        go [] = []
        go _ = error "invalid test vector"
check :: String -> Bool -> IO ()
check name ok = unless ok (fail name)
main :: IO ()
main = do
  -- RFC 5869, case 1. Numeric test data, not implementation code.
  let salt = hex "000102030405060708090a0b0c"
      prk = extract salt (B.replicate 22 0x0b)
  check "RFC5869 extract" (prk == hex "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5")
  -- RFC 8448, section 3: independent known answers for the TLS key schedule.
  let early = extract (B.replicate 32 0) (B.replicate 32 0)
  check "RFC8448 early" (early == hex "33ad0a1c607ec03b09e6cd9893680ce210adf300aa1f2660e1b22e10f170f92a")
  check "RFC8448 derived" (deriveSecret early "derived" B.empty == hex "6f2615a108c702c5678f54fc9dbab69716c076189c48250cebeac3576c3611ba")
  let serverTraffic = hex "b67b7d690cc16c4e75e54213cb2d37b4e9c912bcded9105d42befd59d391ad38"
      (key,iv) = trafficKey serverTraffic
  check "RFC8448 traffic key" (key == hex "3fce516009c21727d0f2e4e86ee403bc")
  check "RFC8448 traffic IV" (iv == hex "5d313eb2671276ee13000b30")
  check "GCM empty known answer" (seal (B.replicate 16 0) (B.replicate 12 0) B.empty B.empty ==
    Right (hex "58e2fccefa7e3061367f1d57a4e7455a"))
  check "sequence key cap" (case protect serverTraffic 8388608 23 "x" of Left _ -> True; _ -> False)
  check "record size cap" (case protect serverTraffic 0 23 (B.replicate 16385 1) of Left _ -> True; _ -> False)
  result <- quickCheckWithResult stdArgs {maxSuccess=3000,maxSize=4096} propRecords
  unless (isSuccess result) exitFailure
  putStrLn "TLS known-answer vectors and 3000 authenticated-record properties passed"

propRecords :: [Word] -> Word64 -> Property
propRecords input n = ioProperty $ do
  let secret = B.replicate 32 42
      body = B.pack (map fromIntegral (take 4096 input))
      seqNo = n `mod` 8388608
  case protect secret seqNo 23 body of
    Left _ -> pure False
    Right wire -> do
      let encrypted = B.drop 5 wire
          changed = B.init encrypted <> B.singleton (B.last encrypted `xor` 1)
          ok = unprotect secret seqNo 23 0x0303 encrypted == Right (23,body)
          reject v = case v of Left _ -> True; Right _ -> False
      pure (ok && reject (unprotect secret seqNo 23 0x0303 changed) &&
        reject (unprotect secret (seqNo+1) 23 0x0303 encrypted) &&
        reject (unprotect secret seqNo 22 0x0303 encrypted) &&
        reject (unprotect secret seqNo 23 0x0301 encrypted))
