{-# LANGUAGE OverloadedStrings #-}
module Lantern.TLS.Negotiation
  ( ServerHello(..), parseServerHello, serverHelloWire, retryRandom, retryTranscript ) where
import Control.Monad (unless)
import qualified Data.ByteString as B
import Data.List (nub)
import Lantern.TLS.Crypto (sha256)
import Lantern.TLS.KeyExchange (supportedGroups, validateShare)
import Lantern.TLS.Wire

data ServerHello = ServerKey Int B.ByteString | RetryRequest (Maybe Int) (Maybe B.ByteString) deriving (Eq,Show)
retryRandom :: B.ByteString
retryRandom = B.pack [0xcf,0x21,0xad,0x74,0xe5,0x9a,0x61,0x11,0xbe,0x1d,0x8c,0x02,0x1e,0x65,0xb8,0x91,
                     0xc2,0xa2,0x11,0x16,0x7a,0xbb,0x8c,0x5e,0x07,0x9e,0x09,0xe2,0xc8,0xa8,0x33,0x9c]
retryTranscript :: B.ByteString -> B.ByteString -> B.ByteString
retryTranscript firstHello retry = message 254 (sha256 firstHello) <> retry
serverHelloWire :: B.ByteString -> B.ByteString -> B.ByteString -> B.ByteString
serverHelloWire random session extensions = message 2 ("\x03\x03" <> random <> vector 1 session <>
                                                        "\x13\x01\x00" <> vector 2 extensions)
parseServerHello :: B.ByteString -> Parser ServerHello
parseServerHello session = do
  version <- uint 2
  unless (version == 0x0303) (fail "invalid legacy version")
  random <- takeN 32
  sid <- vec 1
  unless (sid == session) (fail "session ID mismatch")
  suite <- uint 2
  compression <- uint 1
  unless (suite == 0x1301 && compression == 0) (fail "unexpected cipher/compression")
  exts <- vec 2 >>= either fail pure . parseExtensions
  unless (length exts <= 3 && length exts == length (nub (map fst exts)) && lookup 43 exts == Just "\x03\x04") (fail "invalid ServerHello extensions")
  if random == retryRandom then do
    unless (all ((`elem` [43,44,51]) . fst) exts) (fail "unsolicited retry extension")
    group <- case lookup 51 exts of
      Nothing -> pure Nothing
      Just bytes -> do
        g <- either fail pure (runParser (uint 2) bytes)
        unless (g `elem` supportedGroups) (fail "unsupported retry group")
        pure (Just g)
    cookie <- case lookup 44 exts of
      Nothing -> pure Nothing
      Just bytes -> do
        value <- either fail pure (runParser (vec 2) bytes)
        unless (not (B.null value)) (fail "empty retry cookie")
        pure (Just value)
    unless (group /= Nothing || cookie /= Nothing) (fail "retry changes nothing")
    pure (RetryRequest group cookie)
  else do
    unless (length exts == 2) (fail "invalid ServerHello extensions")
    key <- maybe (fail "missing key share") pure (lookup 51 exts)
    either fail pure $ runParser (do
      group <- uint 2
      share <- vec 2
      either fail pure (validateShare group share)
      pure (ServerKey group share)) key
