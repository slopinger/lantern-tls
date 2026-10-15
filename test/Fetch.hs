{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}
module Main (main) where
import Control.Exception (bracket,bracketOnError,catch,IOException)
import Control.Monad (unless)
import qualified Data.ByteString as B
import qualified Data.ByteString.Char8 as C
import Network.Socket hiding (connect,close)
import qualified Network.Socket as N
import qualified Network.Socket.ByteString as S
import System.Environment (getArgs)
import qualified Lantern.TLS as TLS

main :: IO ()
main = do
  [host,port,trustPath,target] <- getArgs
  trust <- if trustPath == "system" then TLS.systemTrust else TLS.trustFile trustPath
  addresses <- getAddrInfo (Just defaultHints {addrSocketType=Stream}) (Just host) (Just port)
  bracket (connectAny addresses) N.close $ \s -> do
    context <- TLS.connect trust host (S.recv s 16384) (S.sendAll s)
    TLS.send context ("GET " <> C.pack target <> " HTTP/1.1\r\nHost: " <> C.pack host <> "\r\nConnection: close\r\n\r\n")
    let loop = do
          b <- TLS.receive context
          unless (B.null b) (B.putStr b >> loop)
    loop
  where
    connectAny [] = fail "no reachable address"
    connectAny (a:as) = (bracketOnError (socket (addrFamily a) Stream defaultProtocol) N.close $ \s ->
      N.connect s (addrAddress a) >> pure s) `catch` \(_ :: IOException) -> connectAny as
