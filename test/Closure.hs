{-# LANGUAGE OverloadedStrings #-}
module Main (main) where
import Control.Concurrent
import Control.Exception
import Control.Monad (unless)
import qualified Data.ByteString as B
import Data.IORef
import System.Environment (getArgs)
import System.Timeout (timeout)
import qualified Lantern.TLS as TLS

-- Real handshakes over ordered in-memory transports, with no socket timing race.
-- Both peers must retain their opposite direction after a close_notify.
main :: IO ()
main = do
  [cert,key] <- getArgs
  creds <- TLS.loadCredentials cert key
  roots <- TLS.trustFile cert
  mapM_ (scenario creds roots) ["directional", "truncated", "failed-close"]
  putStrLn "TLS closure passed: directional data, idempotence, truncation, failed alert poisoning"

scenario :: TLS.Credentials -> TLS.TrustStore -> String -> IO ()
scenario creds roots mode = do
  toServer <- newChan
  toClient <- newChan
  done <- newEmptyMVar
  writes <- newIORef (0 :: Int)
  broken <- newIORef False
  let transmit b = do
        failWrite <- readIORef broken
        if failWrite then ioError (userError "synthetic alert write failure")
          else modifyIORef' writes (+ B.length b) >> writeChan toClient b
  let server = do
        ctx <- TLS.accept creds ["http/1.1"] (readChan toServer) transmit
        TLS.send ctx "ready"
        if mode == "failed-close" then do
          writeIORef broken True
          failed <- try (TLS.close ctx) :: IO (Either IOError ())
          case failed of Left _ -> pure (); Right () -> fail "failed alert write accepted"
          writeIORef broken False
          expectPoison (TLS.send ctx "forbidden")
          expectPoison (TLS.receive ctx)
        else do
          TLS.close ctx
          before <- readIORef writes
          TLS.close ctx
          after <- readIORef writes
          unless (before == after) (fail "repeated close emitted another record")
          if mode == "truncated" then do
            missing <- try (TLS.receive ctx) :: IO (Either TLS.TLSError B.ByteString)
            case missing of Left _ -> pure (); Right _ -> fail "local close hid unauthenticated EOF"
            expectPoison (TLS.receive ctx)
          else do
            payload <- TLS.receive ctx
            unless (payload == "after-close") (fail "local close discarded peer application data")
            eof <- TLS.receive ctx
            unless (B.null eof) (fail "expected authenticated peer closure")
            again <- TLS.receive ctx
            unless (B.null again) (fail "peer closure was not persistent")
      client = do
        ctx <- TLS.connect roots "localhost" (readChan toClient) (writeChan toServer)
        ready <- TLS.receive ctx
        unless (ready == "ready") (fail "missing ready payload")
        unless (mode == "failed-close") $ do
          eof <- TLS.receive ctx
          unless (B.null eof) (fail "missing server closure alert")
          if mode == "truncated" then writeChan toServer B.empty else do
            -- Receipt of the server's alert must not close our write direction.
            TLS.send ctx "after-close"
            TLS.close ctx
            TLS.close ctx
  owner <- myThreadId
  result <- timeout 5000000 $ do
    _ <- forkFinally server (\r -> putMVar done r >> either (throwTo owner) (const (pure ())) r)
    client
    takeMVar done >>= either throwIO pure
  maybe (fail "directional closure deadlocked") pure result

expectPoison :: IO a -> IO ()
expectPoison action = do
  result <- try (action >> pure ()) :: IO (Either TLS.TLSError ())
  case result of Left _ -> pure (); Right () -> fail "failed TLS context remained usable"
