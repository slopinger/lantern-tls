{-# LANGUAGE OverloadedStrings #-}
-- | An experimental TLS 1.3 server protocol. Caller owns and closes the backend.
-- Primitives come from crypton. No dependency on any existing TLS library.
module Lantern.TLS
  ( Credentials, Context, TLSError(..), loadCredentials, accept, connect, TrustStore, systemTrust, trustFile, receive, send, close
  ) where
import Control.Concurrent.MVar
import Control.Exception (onException)
import Control.Monad (unless, when)
import qualified Data.ByteString as B
import Data.IORef
import Data.Word (Word64)
import System.Timeout (timeout)
import Lantern.TLS.Credentials
import Lantern.TLS.Client
import Lantern.TLS.Crypto (nextSecret)
import Lantern.TLS.Handshake
import Lantern.TLS.Record
import Lantern.TLS.Wire

data Traffic = Traffic B.ByteString Word64
data ConnectionState = Open | Closed | Failed deriving Eq
data Context = Context RecordIO (MVar Traffic) (MVar Traffic) (IORef ConnectionState) Bool

-- | Single server handshake, 10 second absolute deadline. The backend receive
-- callback must return <=64 KiB, and empty bytes only at EOF.
accept :: Credentials -> [B.ByteString] -> IO B.ByteString -> (B.ByteString -> IO ()) -> IO Context
accept credentials protocols recv transmit = do
  io <- newRecordIO recv transmit
  result <- timeout 10000000 (serverHandshake io credentials protocols)
  (rx,tx) <- maybe (abort "TLS handshake timeout") pure result
  Context io <$> newMVar (Traffic rx 0) <*> newMVar (Traffic tx 0) <*> newIORef Open <*> pure False

-- | Client handshake with restricted certificate identity/time/path validation against an
-- explicit trust store. No insecure mode. Uses our own TLS handshake and records.
connect :: TrustStore -> String -> IO B.ByteString -> (B.ByteString -> IO ()) -> IO Context
connect trust hostname recv transmit = do
  io <- newRecordIO recv transmit
  result <- timeout 10000000 (clientHandshake io trust hostname)
  (rx,tx) <- maybe (abort "TLS client handshake timeout") pure result
  Context io <$> newMVar (Traffic rx 0) <*> newMVar (Traffic tx 0) <*> newIORef Open <*> pure True

-- | One reader and one writer may operate concurrently. A key update is applied
-- before returning any later application data. Truncation is an error, not EOF.
receive :: Context -> IO B.ByteString
receive context@(Context io rx _ closed tickets) = (modifyMVar rx $ \initial -> do
  done <- readIORef closed
  case done of
    Closed -> pure (initial,B.empty)
    Failed -> abort "TLS context is poisoned"
    Open -> loop initial B.empty (0 :: Int))
    `onException` writeIORef closed Failed
  where
    loop state@(Traffic secret seqNo) pending emptyRecords = do
      ensure (emptyRecords < 64) "too many empty TLS records"
      (kind,version,payload) <- readRaw io
      (innerType,plain) <- either abort pure (unprotect secret seqNo kind version payload)
      let advanced = Traffic secret (seqNo+1)
      case innerType of
        23 -> do
          ensure (B.null pending) "application data interrupted handshake message"
          if B.null plain then loop advanced pending (emptyRecords+1) else pure (advanced,plain)
        21 -> do
          ensure (B.null pending && B.length plain == 2 && B.head plain `elem` [1,2]) "invalid alert"
          if B.index plain 1 == 0 then do
            writeIORef closed Closed
            sendClose context
            pure (advanced,B.empty)
          else abort "peer TLS alert"
        22 -> do
          let combined = pending <> plain
          ensure (not (B.null plain) && B.length combined <= 65536) "invalid post-handshake message"
          handlePost advanced combined emptyRecords
        _ -> state `seq` abort "unexpected TLS content"
    handlePost traffic@(Traffic secret _) combined count
      | B.length combined < 4 = loop traffic combined (count+1)
      | otherwise = do
          let size = 4+B.foldl' (\n c -> n*256+fromIntegral c) 0 (B.take 3 (B.drop 1 combined))
          ensure (size <= 65536) "post-handshake message too large"
          if B.length combined < size then loop traffic combined (count+1) else do
            let packet = B.take size combined
                trailing = B.drop size combined
            case B.head packet of
              24 -> do
                ensure (size == 5 && B.null trailing && B.index packet 4 <= 1) "invalid KeyUpdate boundary"
                when (B.index packet 4 == 1) (updateWrite context)
                loop (Traffic (nextSecret secret) 0) B.empty (count+1)
              4 | tickets -> do
                -- No resumption: validate envelope and discard the opaque ticket.
                _ <- either abort pure (runParser (do
                  _ <- uint 4; _ <- uint 4; _ <- vec 1
                  ticket <- vec 2
                  ensureP (not (B.null ticket))
                  _ <- vec 2
                  pure ()) (B.drop 4 packet))
                if B.null trailing then loop traffic B.empty (count+1)
                  else handlePost traffic trailing (count+1)
              _ -> abort "unexpected post-handshake message"
    ensureP ok = unless ok (fail "empty session ticket")


send :: Context -> B.ByteString -> IO ()
send (Context io _ tx closed _) bytes = unless (B.null bytes) $ (modifyMVar_ tx $ \state -> do
  done <- readIORef closed
  ensure (done == Open) "TLS connection closed or poisoned"
  Traffic secret seqNo <- rotateIfNeeded io state
  next <- sendProtected io secret seqNo 23 bytes
  pure (Traffic secret next)) `onException` writeIORef closed Failed

-- Re-key well before the conservative 2^23-record AES-GCM usage cap.
rotateIfNeeded :: RecordIO -> Traffic -> IO Traffic
rotateIfNeeded io state@(Traffic secret n)
  | n < 1048576 = pure state
  | otherwise = do
      _ <- sendProtected io secret n 22 "\x18\x00\x00\x01\x00"
      pure (Traffic (nextSecret secret) 0)

updateWrite :: Context -> IO ()
updateWrite (Context io _ tx _ _) = modifyMVar_ tx $ \(Traffic secret n) -> do
  _ <- sendProtected io secret n 22 "\x18\x00\x00\x01\x00"
  pure (Traffic (nextSecret secret) 0)

sendClose :: Context -> IO ()
sendClose (Context io _ tx _ _) = modifyMVar_ tx $ \(Traffic secret n) -> do
  next <- sendProtected io secret n 21 "\x01\x00"
  pure (Traffic secret next)

close :: Context -> IO ()
close (Context io _ tx closed _) = modifyMVar_ tx $ \state@(Traffic secret n) -> do
  already <- atomicModifyIORef' closed (\old -> (if old == Open then Closed else old,old))
  if already /= Open then pure state else do
    next <- sendProtected io secret n 21 "\x01\x00"
    pure (Traffic secret next)
