{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}
module Main (main) where
import Control.Concurrent (forkFinally)
import Control.Exception
import Control.Monad (forever,void,unless)
import qualified Data.ByteString as B
import Network.Socket hiding (accept,close)
import qualified Network.Socket as N
import qualified Network.Socket.ByteString as S
import System.Environment (getArgs)
import System.IO
import qualified Lantern.TLS as TLS

main :: IO ()
main = do
  [cert,key,port] <- getArgs
  creds <- TLS.loadCredentials cert key
  bracket (socket AF_INET Stream defaultProtocol) N.close $ \server -> do
    setSocketOption server ReuseAddr 1
    bind server (SockAddrInet (fromIntegral (read port :: Int)) (tupleToHostAddress (127,0,0,1)))
    listen server 128
    hPutStrLn stderr "ready"
    forever $ do
      (peer,_) <- N.accept server
      void $ forkFinally (do
        context <- TLS.accept creds ["http/1.1"] (S.recv peer 16384) (S.sendAll peer)
        let loop = do
              b <- TLS.receive context
              unless (B.null b) (TLS.send context b >> loop)
        loop) (\result -> do
          case result of Left (e :: SomeException) -> hPutStrLn stderr (displayException e); Right () -> pure ()
          N.close peer)
