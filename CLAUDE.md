# lantern-tls
- Independent experimental TLS 1.3 client/server wire protocol in Haskell; public MIT.
- No dependency on tls, OpenSSL, Warp, or an HTTP library. Crypton primitives and
  crypton-x509 PKIX verification are explicitly retained; never rewrite primitives.
- src/Lantern/TLS/{Handshake,Client,Record,Crypto,Wire,Credentials,PKI}.hs;
  src/Lantern/TLS.hs is the stateful public API.
- Supported profile and intentional gaps are in README and docs/security.md.
- Checks: nix build; nix flake check (vectors, OpenSSL server/client interoperability).
- Test keys, certificates, and key-log secrets are generated only in temporary dirs.
- tls-echo is a loopback test tool, not a hardened public service. No host module.
- No production-security or complete-conformance claims without independent review.

- Client identity policy is SAN-only (DNS or exact IPv4/IPv6 bytes), complete
  leftmost DNS wildcards only; no CN fallback. IP literals omit SNI. The pinned
  verifier's legacy identity hook is replaced, not its PKIX/crypto verification.
- Client test tool accepts an optional TLS reference name after the existing four
  arguments; this separates loopback test connections from certificate identity.

- KeyExchange.hs owns opaque ephemeral-share encodings/policy (X25519/P-256),
  delegating all curve primitives to Crypton. Negotiation.hs validates ServerHello/
  HRR and constructs the synthetic retry transcript. Private shares must not log.
- Both roles support one HelloRetryRequest within the original 10-second budget;
  client supports cookies, server holds bounded state and never selects PSKs.
- test/negotiation.py adds adversarial retry/point/ClientHello2 checks and fully
  authenticated OpenSSL retries to both groups; flake checks run it offline.

- PKIX security audit replaced vulnerable crypton-x509-validation 1.6.14 with 1.10.0
  and Crypton 2.2.1. nix/crypto-packages.nix exports a coherent primitive set through
  flake lib.cryptoPackages; consumers must use it (ram/time-hourglass types).
- CertificatePolicy.hs supplements dependency verification with bounded DNS/IP
  constraints, intermediate EKU and extension policy. Unsupported constraint forms
  fail closed. test/pkix.py generates chains offline; included in flake checks.
- The shared primitive set carries nix/name-constraints-inheritance.patch: retain
  issuer constraints across a subordinate CA without its own extension. Keep the
  independent ancestor checks and root acceptance/rejection regressions. This is
  a policy fix; no signature or arithmetic primitive is changed.
- CertificatePolicy also bounds exact RSA modulus/exponent values throughout the
  path and restricts certificate signatures/curves. Its certificate scheme list
  feeds ClientHello. Anchors skip only their own signature check, not key policy.
  Keep weak-key rejection and strong mixed-algorithm chain acceptance fixtures.
- CertificateEncoding.hs checks raw inner/outer algorithms and PSS parameters
  before X.509 decoding discards MGF/salt fields. Use established ASN.1 primitives;
  do not rely on decoded SignatureALG alone or a Nix-only dependency patch.

PKI exposes `validateCertificateDNSNames` for DNS-only ACME issuance consistency:
exact unordered case-insensitive SAN set, no wildcard/CN fallback or extra names;
one well-formed SAN extension, bounded inputs. This does not verify chain trust.
