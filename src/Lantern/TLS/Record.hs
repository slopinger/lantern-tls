{-# LANGUAGE OverloadedStrings #-}
module Lantern.TLS.Record
  ( RecordIO, newRecordIO, readRaw, sendPlain, protect, unprotect, sendProtected
  ) where
import Control.Monad (when)
import qualified Data.ByteString as B
import Data.IORef
import Data.Word (Word64)
import Lantern.TLS.Crypto
import Lantern.TLS.Wire

data RecordIO = RecordIO (IO B.ByteString) (B.ByteString -> IO ()) (IORef B.ByteString)
newRecordIO :: IO B.ByteString -> (B.ByteString -> IO ()) -> IO RecordIO
newRecordIO recv send = RecordIO recv send <$> newIORef B.empty

exact :: RecordIO -> Int -> IO B.ByteString
exact (RecordIO recv _ ref) count = go count []
  where
    go 0 chunks = pure (B.concat (reverse chunks))
    go left chunks = do
      buf <- readIORef ref
      if B.null buf then do
        more <- recv
        ensure (not (B.null more)) "truncated TLS record"
        -- Backends are required to return <=64 KiB per read, keeping buffering bounded.
        ensure (B.length more <= 65536) "TLS backend read exceeds 64 KiB"
        writeIORef ref more
        go left chunks
      else do
        let (piece,remaining) = B.splitAt left buf
        writeIORef ref remaining
        go (left-B.length piece) (piece:chunks)

readRaw :: RecordIO -> IO (Int,Int,B.ByteString)
readRaw io = do
  hdr <- exact io 5
  (kind,version,size) <- either abort pure $ runParser ((,,) <$> uint 1 <*> uint 2 <*> uint 2) hdr
  ensure (size <= 16640) "TLS record overflow"
  payload <- exact io size
  pure (kind,version,payload)

sendPlain :: RecordIO -> Int -> B.ByteString -> IO ()
sendPlain (RecordIO _ send _) kind b = do
  ensure (B.length b <= 16384) "plaintext record overflow"
  send (encode 1 (fromIntegral kind) <> "\x03\x03" <> vector 2 b)

protect :: B.ByteString -> Word64 -> Int -> B.ByteString -> Either String B.ByteString
protect secret seqNo kind bytes = do
  if seqNo >= 8388608 || B.length bytes > 16384 then Left "TLS traffic key exhausted or oversized content" else pure ()
  let (key,iv) = trafficKey secret
      hdr = "\x17\x03\x03" <> encode 2 (fromIntegral (B.length bytes+17))
  encrypted <- seal key (nonceFor iv seqNo) hdr (bytes <> encode 1 (fromIntegral kind))
  pure (hdr <> encrypted)

unprotect :: B.ByteString -> Word64 -> Int -> Int -> B.ByteString -> Either String (Int,B.ByteString)
unprotect secret seqNo kind version bytes = do
  if seqNo >= 8388608 || kind /= 23 || version /= 0x0303 || B.length bytes < 17 || B.length bytes > 16640
    then Left "invalid encrypted record" else pure ()
  let (key,iv) = trafficKey secret
      hdr = "\x17\x03\x03" <> encode 2 (fromIntegral (B.length bytes))
  plain <- unseal key (nonceFor iv seqNo) hdr bytes
  let unpadded = B.dropWhileEnd (==0) plain
  if B.null unpadded then Left "missing inner content type" else do
    let innerType = fromIntegral (B.last unpadded)
        content = B.init unpadded
    if innerType `notElem` [21,22,23] || B.length content > 16384
      then Left "invalid inner record" else Right (innerType,content)

sendProtected :: RecordIO -> B.ByteString -> Word64 -> Int -> B.ByteString -> IO Word64
sendProtected (RecordIO _ send _) secret sequenceNo kind payload = go sequenceNo payload
  where
    go n bytes = do
      let (front,remaining) = B.splitAt 16384 bytes
      wire <- either abort pure (protect secret n kind front)
      send wire
      let next = n+1
      when (next == 0) (abort "TLS sequence overflow")
      if B.null remaining then pure next else go next remaining
