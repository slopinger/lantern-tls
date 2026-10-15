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
