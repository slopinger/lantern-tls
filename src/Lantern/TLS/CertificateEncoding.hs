-- Structural algorithm policy uses the established ASN.1 decoder/parser.
-- It runs before X.509 decoding can discard RSA-PSS parameters.
module Lantern.TLS.CertificateEncoding (certificateEncodingPolicy) where
import Control.Monad (unless, when)
import qualified Data.ByteString as B
import Data.ASN1.Types
import Data.ASN1.Encoding (decodeASN1')
import Data.ASN1.BinaryEncoding (DER(..))
import Data.ASN1.Parse

certificateEncodingPolicy :: B.ByteString -> Either String ()
certificateEncodingPolicy bytes = do
  tokens <- either (const (Left "invalid certificate ASN.1")) Right (decodeASN1' DER bytes)
  (tbs,outer) <- runParseASN1 (onNextContainer Sequence $ do
    tbs <- getNextContainer Sequence
    outer <- getNextContainer Sequence
    _ <- getNext
    pure (tbs,outer)) tokens
  let version = case tbs of Start (Container Context 0):_ -> True; _ -> False
  inner <- runParseASN1 (do
    when version (getNextContainer (Container Context 0) >> pure ())
    _ <- getNext -- serial number; the X.509 decoder validates its type
    algorithm <- getNextContainer Sequence
    _ <- getMany getNext
    pure algorithm) tbs
  unless (inner == outer) (Left "inconsistent certificate AlgorithmIdentifiers")
  case outer of
    OID [1,2,840,113549,1,1,10] : parameters -> do
      (digest,mgfDigest,salt) <- runParseASN1 (onNextContainer Sequence $ do
        digest <- onNextContainer (Container Context 0) (getNextContainer Sequence)
        mgf <- onNextContainer (Container Context 1) (getNextContainer Sequence)
        mgfDigest <- either throwParseError pure $ runParseASN1 (do
          oid <- getNext
          unless (oid == OID [1,2,840,113549,1,1,8]) (throwParseError "unsupported PSS MGF")
          getNextContainer Sequence) mgf
        salt <- onNextContainer (Container Context 2) getNext
        pure (digest,mgfDigest,salt)) parameters
      h <- hashOID digest
      m <- hashOID mgfDigest
      let expected = lookup h [([2,16,840,1,101,3,4,2,1],32),
                              ([2,16,840,1,101,3,4,2,2],48),
                              ([2,16,840,1,101,3,4,2,3],64)]
      unless (h == m && maybe False (\n -> salt == IntVal n) expected)
        (Left "unsupported RSA-PSS certificate parameters")
    _ -> pure ()
  where
    hashOID [OID oid] = Right oid
    hashOID [OID oid,Null] = Right oid
    hashOID _ = Left "invalid PSS digest identifier"
