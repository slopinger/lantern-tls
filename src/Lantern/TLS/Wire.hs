{-# LANGUAGE DeriveDataTypeable #-}
module Lantern.TLS.Wire
  ( TLSError(..), abort, ensure, Parser, runParser, takeN, uint, vec, rest
  , encode, vector, message, extension, parseExtensions, parseList
  ) where
import Control.Exception (Exception, throwIO)
import Control.Monad (unless)
import qualified Data.ByteString as B
import Data.Typeable (Typeable)

data TLSError = TLSError String deriving (Show,Typeable)
instance Exception TLSError
abort :: String -> IO a
abort = throwIO . TLSError
ensure :: Bool -> String -> IO ()
ensure ok reason = unless ok (abort reason)

newtype Parser a = Parser { unParser :: B.ByteString -> Either String (a,B.ByteString) }
instance Functor Parser where
  fmap f (Parser p) = Parser (\b -> do (a,r) <- p b; pure (f a,r))
instance Applicative Parser where
  pure a = Parser (\b -> Right (a,b))
  Parser p <*> Parser q = Parser (\b -> do (f,r) <- p b; (a,s) <- q r; pure (f a,s))
instance Monad Parser where
  Parser p >>= f = Parser (\b -> do (a,r) <- p b; unParser (f a) r)
instance MonadFail Parser where
  fail e = Parser (const (Left e))
runParser :: Parser a -> B.ByteString -> Either String a
runParser p b = do
  (a,r) <- unParser p b
  if B.null r then Right a else Left "trailing wire bytes"
takeN :: Int -> Parser B.ByteString
takeN n = Parser (\b -> if n >= 0 && B.length b >= n then Right (B.take n b,B.drop n b) else Left "truncated wire value")
uint :: Int -> Parser Int
uint n = B.foldl' (\a c -> a*256 + fromIntegral c) 0 <$> takeN n
vec :: Int -> Parser B.ByteString
vec n = uint n >>= takeN
rest :: Parser B.ByteString
rest = Parser (\b -> Right (b,B.empty))
parseList :: Parser a -> Parser [a]
parseList p = Parser go
  where go b | B.null b = Right ([],B.empty)
             | otherwise = do
                 (a,r) <- unParser p b
                 if B.length r >= B.length b then Left "non-progressing parser" else do
                   (xs,s) <- go r; pure (a:xs,s)
encode :: Int -> Integer -> B.ByteString
encode n x = B.pack [fromInteger ((x `div` (256^i)) `mod` 256) | i <- reverse [0..n-1]]
vector :: Int -> B.ByteString -> B.ByteString
vector n b = encode n (fromIntegral (B.length b)) <> b
message :: Int -> B.ByteString -> B.ByteString
message kind body = encode 1 (fromIntegral kind) <> vector 3 body
extension :: Int -> B.ByteString -> B.ByteString
extension kind body = encode 2 (fromIntegral kind) <> vector 2 body
parseExtensions :: B.ByteString -> Either String [(Int,B.ByteString)]
parseExtensions = runParser (parseList ((,) <$> uint 2 <*> vec 2))
