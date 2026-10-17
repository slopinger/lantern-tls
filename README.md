# lantern-tls

An independent, experimental TLS 1.3 protocol library in Haskell. The handshake,
transcript, key schedule, records, nonce construction, Finished checks, alerts,
KeyUpdate, PEM/DER server-key decoding, and PKCS#10 CSR encoding live here. It does
not wrap OpenSSL, the Haskell `tls` package, or an HTTP framework.

Crypton supplies cryptographic primitives. Its X.509 packages supply client-side
certificate decoding and PKIX path/time/purpose verification. The server
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

`close` sends one close_notify for the write direction; repeated calls are no-ops.
It does not end reads: `receive` continues until the peer sends its authenticated
close_notify, and bare backend EOF remains an error. Receiving peer closure ends
reads but permits remaining application writes. Call `close` explicitly when those
writes are complete; there is no automatic closure reply. A failed close poisons
the context, like a failed send or receive. Close the backend on failure.

Supported profile: TLS 1.3, X25519 or P-256 ECDHE, AES-128-GCM/SHA-256. Servers require an
unencrypted RSA 2048–8192-bit PKCS#1/PKCS#8 key and PEM certificate chain, and use
RSA-PSS-SHA256. Clients verify RSA-PSS, ECDSA P-256/SHA-256, and Ed25519 server
CertificateVerify. ALPN is configurable on servers; the client offers HTTP/1.1.
Application records stream in 16 KiB pieces. KeyUpdate and authenticated closure
are implemented. Client session tickets are validated structurally and discarded.

Not implemented: TLS 1.2, resumption/PSK,
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
nix develop -c python test/negotiation.py --server ./result/bin/tls-echo --client ./result/bin/tls-fetch
```

The development executables `tls-echo` and `tls-fetch` are protocol test tools;
`tls-echo` deliberately binds loopback and has no server admission policy.
[Lantern](https://github.com/slopinger/lantern) supplies connection limits,
deadlines, routing, HTTP, ACME, and service integration.

See [research](docs/research.md) and [security model](docs/security.md).

The client requires Subject Alternative Names: DNS names (including only complete
leftmost-label wildcards) or an exact IP-address SAN. Common Name fallback and
partial wildcards are rejected. IP literals do not send the SNI extension; DNS
reference names and SNI are normalized to lowercase. The identity policy is ours;
certificate decoding, chain signatures, validity and usage checks remain Crypton.

HelloRetryRequest is implemented in both roles. The client offers X25519 initially
and advertises P-256 for retry; it echoes a server cookie, rejects a second retry
and never accepts an unoffered/changed group or cipher. The server selects an
available supported share, or requests a mutually supported group once. A second
ClientHello retains its random, session, ciphers and immutable extensions; padding
and structurally valid PSK binder/age changes are handled without selecting a PSK.
The original ClientHello is replaced by its synthetic message_hash in the retry
transcript. Both flights share the existing absolute ten-second handshake budget.

Certificate-chain validation pins Crypton 2.2.1 and crypton-x509-validation 1.10.0.
The client adds bounded DNS/IP name-constraint and intermediate-purpose policy;
unsupported constraint forms fail closed. See [security limits](docs/security.md).
Consumers sharing Crypton types should use `lib.cryptoPackages pkgs` from this
flake so the program links one consistent primitive stack (`ram`, not `memory`).
Certificate public keys and signature algorithms also have explicit bounds;
RSA moduli must contain 2048–8192 bits throughout the selected path. P-384/P-521
issuer signatures and RSA-PSS/SHA-512 are supported independently of the more
limited handshake CertificateVerify profile. See the security profile for details.

PKI exposes `validateCertificateDNSNames` for DNS-only ACME issuance consistency:
exact unordered case-insensitive SAN set, no wildcard/CN fallback or extra names;
one well-formed SAN extension, bounded inputs. This does not verify chain trust.

Client reference names must be supplied as ASCII DNS A-labels or IP literals
(maximum 253 characters, no whitespace/control characters). Validate the original
string before ASCII case normalization/IP parsing; Unicode lowercasing must not
alias an unsupported name to an ASCII certificate identity. IDNA conversion is
the caller's responsibility. Client tests cover Kelvin/dotted-I rejection, ASCII
A-label and case success, and zero ClientHello bytes for invalid reference input.
Cryptographic primitives and PKIX verification are unchanged.
