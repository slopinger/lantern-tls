# lantern-tls

An independent, experimental TLS 1.3 protocol library in Haskell. The handshake,
transcript, key schedule, records, nonce construction, Finished checks, alerts,
KeyUpdate, PEM/DER server-key decoding, and PKCS#10 CSR encoding live here. It does
not wrap OpenSSL, the Haskell `tls` package, or an HTTP framework.

Crypton supplies cryptographic primitives. Its X.509 packages supply client-side
certificate decoding and PKIX path/hostname/time/purpose verification. The server
credential parser and CSR encoder are ours. Socket ownership stays with callers.

```haskell
credentials <- loadCredentials "chain.pem" "key.pem"
context <- accept credentials ["http/1.1"] receiveBytes sendBytes
plaintext <- receive context
send context plaintext
close context
```

For a client, load `systemTrust` or an explicit `trustFile`, then call
`connect trust hostname receiveBytes sendBytes`. There is no skip-verification
mode. Backends return at most 64 KiB per receive; empty means EOF. Own and close the
backend yourself. There may be one reader and one writer concurrently. Any I/O or
protocol failure poisons the session; close the underlying transport. Application
reads/writes require caller deadlines. Both handshakes have a 10-second deadline.

Supported profile: TLS 1.3, X25519, AES-128-GCM/SHA-256. Servers require an
unencrypted RSA 2048–8192-bit PKCS#1/PKCS#8 key and PEM certificate chain, and use
RSA-PSS-SHA256. Clients verify RSA-PSS, ECDSA P-256/SHA-256, and Ed25519 server
CertificateVerify. ALPN is configurable on servers; the client offers HTTP/1.1.
Application records stream in 16 KiB pieces. KeyUpdate and authenticated closure
are implemented. Client session tickets are validated structurally and discarded.

Not implemented: TLS 1.2, HelloRetryRequest, P-256 key agreement, resumption/PSK,
0-RTT, client certificates, OCSP fetching, certificate revocation, session exporters,
or post-quantum key exchange. This is a limited TLS profile, not a claim of full
RFC compliance. RSA private values and traffic secrets are not guaranteed to be
wiped from managed memory. Do not treat passing tests as an audit.

```sh
nix build
nix flake check
nix develop -c cabal test --offline
nix develop -c python test/interop.py --binary ./result/bin/tls-echo
nix develop -c python test/client.py --binary ./result/bin/tls-fetch
```

The development executables `tls-echo` and `tls-fetch` are protocol test tools;
`tls-echo` deliberately binds loopback and has no server admission policy.
[Lantern](https://git.freifick.net/slop/lantern) supplies connection limits,
deadlines, routing, HTTP, ACME, and service integration.

See [research](docs/research.md) and [security model](docs/security.md).
