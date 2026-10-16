-- Additional application policy over Crypton's decoded certificates. Signature,
-- ASN.1, key, and path verification remain with the established primitives.
module Lantern.TLS.CertificatePolicy (certificatePolicy, certificateSignatureSchemes) where

import qualified Crypto.PubKey.RSA.Types as RSA
import Crypto.PubKey.ECC.Types (CurveName(..))
import Control.Monad (unless, forM_)
import Data.Bits ((.&.), testBit)
import qualified Data.ByteString as B
import Data.Char (toLower, isAscii, isAlphaNum)
import Data.List (isSuffixOf, nub)
import Data.X509
import Data.X509.CertificateStore

-- This exact allow-list is also encoded in ClientHello signature_algorithms_cert.
certificateSignatureSchemes :: B.ByteString
certificateSignatureSchemes = B.pack
  [0x04,0x01,0x05,0x01,0x06,0x01,0x04,0x03,0x05,0x03,0x06,0x03,
   0x08,0x04,0x08,0x05,0x08,0x06,0x08,0x07]

-- Require the presented chain in leaf-first order. Apply every issuer's
-- constraints independently, which implements intersection without weakening a
-- parent when an intermediate omits NameConstraints. Include the trust anchor.
certificatePolicy :: CertificateStore -> [SignedCertificate] -> AltName -> Either String ()
certificatePolicy store presented reference = do
  unless (not (null presented)) (Left "empty certificate chain")
  path <- selectPath presented
  let certificates = map getCertificate path
  mapM_ (keyPolicy . certPubKey) certificates
  -- Only signatures actually used to establish the path are checked. An
  -- independently installed anchor's own signature does not establish trust.
  forM_ (zip path (drop 1 certificates)) $ \(child,parent) -> do
    let outer = signedAlg (getSigned child)
    unless (certSignatureAlg (getCertificate child) == outer)
      (Left "inconsistent certificate signature algorithms")
    unless (signatureAllowed outer (certPubKey parent))
      (Left "unsupported certificate signature algorithm")
  forM_ (zip certificates (drop 1 certificates)) $ \(child,parent) ->
    unless (certIssuerDN child == certSubjectDN parent) (Left "unordered certificate chain")
  forM_ (zip [0..] certificates) $ \(index,issuer) -> do
    let Extensions raw = certExtensions issuer
        extensions = maybe [] id raw
        oids = [oid | ExtensionRaw oid _ _ <- extensions]
    unless (length oids <= 128 && length oids == length (nub oids)) (Left "duplicate X.509 extension")
    unless (all (\(ExtensionRaw oid critical _) -> not critical || oid `elem`
      [[2,5,29,19],[2,5,29,15],[2,5,29,37],[2,5,29,14],[2,5,29,17],[2,5,29,35],[2,5,29,30]]) extensions)
      (Left "unsupported critical X.509 extension")
    case extensionGet (certExtensions issuer) of
      Just (ExtSubjectAltName names) -> unless (length names <= 128) (Left "too many certificate names")
      Nothing -> pure ()
    -- A malformed recognized extension must not become an absent extension.
    let requireDecoded oid decoded =
          unless (oid `notElem` oids || decoded) (Left "malformed X.509 extension")
    requireDecoded [2,5,29,19] (case extensionGet (certExtensions issuer) :: Maybe ExtBasicConstraints of Just _ -> True; _ -> False)
    requireDecoded [2,5,29,15] (case extensionGet (certExtensions issuer) :: Maybe ExtKeyUsage of Just _ -> True; _ -> False)
    requireDecoded [2,5,29,30] (case extensionGet (certExtensions issuer) :: Maybe ExtNameConstraints of Just _ -> True; _ -> False)
    requireDecoded [2,5,29,37] (case extensionGet (certExtensions issuer) :: Maybe ExtExtendedKeyUsage of Just _ -> True; _ -> False)
    requireDecoded [2,5,29,17] (case extensionGet (certExtensions issuer) :: Maybe ExtSubjectAltName of Just _ -> True; _ -> False)
    case extensionGet (certExtensions issuer) of
      Just (ExtExtendedKeyUsage purposes) ->
        unless (KeyUsagePurpose_ServerAuth `elem` purposes || KeyUsagePurpose_Unknown [2,5,29,37,0] `elem` purposes)
          (Left "certificate purpose excludes TLS server authentication")
      Nothing -> pure ()
    case extensionGet (certExtensions issuer) of
      Nothing -> pure ()
      Just (ExtNameConstraints permitted excluded) -> do
        unless (index > 0 && not (null (permitted ++ excluded)) && length permitted + length excluded <= 64) (Left "invalid name constraints")
        mapM_ supported (permitted ++ excluded)
        let names = reference : concatMap subjectNames (take index certificates)
        mapM_ (checkNames permitted excluded) names
  where
    -- Match the primitive verifier's first trusted issuer, not merely the last
    -- supplied certificate: a store may directly trust an intermediate with
    -- tighter constraints than another certificate for the same public key.
    selectPath [] = Left "empty certificate path"
    selectPath (current:remaining) =
      case findCertificate (certIssuerDN (getCertificate current)) store of
        Just anchor -> Right (current : [anchor | anchor /= current])
        Nothing -> case remaining of
          [] -> Right [current] -- the cryptographic verifier reports UnknownCA
          _ -> (current :) <$> selectPath remaining
    keyPolicy (PubKeyRSA key) =
      unless (RSA.public_n key >= 2^(2047 :: Int) && RSA.public_n key < 2^(8192 :: Int) &&
              odd (RSA.public_n key) && RSA.public_e key >= 3 &&
              RSA.public_e key <= 4294967295 && odd (RSA.public_e key))
        (Left "RSA certificate key outside supported bounds")
    keyPolicy (PubKeyEC (PubKeyEC_Named curve _)) =
      unless (curve `elem` [SEC_p256r1,SEC_p384r1,SEC_p521r1]) (Left "unsupported certificate curve")
    keyPolicy PubKeyEd25519{} = Right ()
    keyPolicy _ = Left "unsupported certificate public key"
    signatureAllowed (SignatureALG digest PubKeyALG_RSA) PubKeyRSA{} =
      digest `elem` [HashSHA256,HashSHA384,HashSHA512]
    signatureAllowed (SignatureALG digest PubKeyALG_RSAPSS) PubKeyRSA{} =
      digest `elem` [HashSHA256,HashSHA384,HashSHA512]
    signatureAllowed (SignatureALG digest PubKeyALG_EC) (PubKeyEC (PubKeyEC_Named curve _)) =
      (digest,curve) `elem` [(HashSHA256,SEC_p256r1),(HashSHA384,SEC_p384r1),(HashSHA512,SEC_p521r1)]
    signatureAllowed (SignatureALG_IntrinsicHash PubKeyALG_Ed25519) PubKeyEd25519{} = True
    signatureAllowed _ _ = False
    subjectNames c = case extensionGet (certExtensions c) of
      Nothing -> []
      Just (ExtSubjectAltName ns) -> ns
    supported (GeneralSubtree name minimum' maximum') = do
      unless (minimum' == 0 && maximum' == Nothing) (Left "unsupported name constraint distance")
      case name of
        AltNameDNS value -> unless (validConstraintDNS value) (Left "invalid DNS constraint")
        AltNameIP value -> do
          unless (B.length value `elem` [8,32]) (Left "invalid IP constraint")
          let mask = B.drop (B.length value `div` 2) value
              bits = concatMap (\byte -> map (testBit byte) [7,6..0]) (B.unpack mask)
          unless (all not (dropWhile id bits)) (Left "noncontiguous IP constraint mask")
        _ -> Left "unsupported name constraint type"
    validConstraintDNS value =
      let domain = if take 1 value == "." then drop 1 value else value
          labels [] = [""]
          labels input = case break (== '.') input of
            (front,[]) -> [front]
            (front,_:rest) -> front : labels rest
          label part = not (null part) && length part <= 63 &&
            head part /= '-' && last part /= '-' &&
            all (\c -> isAscii c && (isAlphaNum c || c == '-')) part
      in not (null domain) && length domain <= 253 && all label (labels domain)
    checkNames permitted excluded name = do
      let relevant = filter (sameType name . subtreeName) permitted
      unless (null relevant || any (matches name . subtreeName) relevant) (Left "name outside permitted subtrees")
      unless (not (any (matches name . subtreeName) excluded)) (Left "name in excluded subtree")
    subtreeName (GeneralSubtree name _ _) = name
    sameType AltNameDNS{} AltNameDNS{} = True
    sameType AltNameIP{} AltNameIP{} = True
    sameType _ _ = False
    matches (AltNameDNS name) (AltNameDNS subtree) =
      let n=map toLower name; s=map toLower subtree
      in if take 1 s == "." then s `isSuffixOf` n && length n > length s
         else n == s || ('.':s) `isSuffixOf` n
    matches (AltNameIP address) (AltNameIP subtree) =
      let (network,mask)=B.splitAt (B.length subtree `div` 2) subtree
      in B.length address == B.length network &&
         B.zipWith (.&.) address mask == B.zipWith (.&.) network mask
    matches _ _ = False
