# Security model and limits

This is experimental protocol software. It has not received an independent
security audit. Report issues privately to the repository owner before publishing
exploit details against deployments; no dedicated security mailbox is configured.

Remote peers control record bytes, lengths, ordering, fragmentation, extensions,
and timing. The backend, local credential files, explicit trust roots, random
source, and Crypton primitives are trusted. The library is memory-safe Haskell,
but logical protocol errors, unbounded CPU, heap retention, and dependency flaws
remain possible. The runtime does not guarantee erasure of copied ByteStrings or
RSA Integer values. Do not log Context, keys, or traffic secrets.

After any exception from send or receive, both directions become unusable. Close
the backend. The API must not be resumed after a failure; authenticated read
results already returned remain the caller's responsibility. Clean EOF is only
returned after close_notify. An unauthenticated backend EOF is truncation.

A server handshake has a ten-second absolute deadline; the server application
must bound concurrent handshakes/connections. Application calls also need absolute
deadlines. The test echo tool is not a public service. Metadata limits and key
usage limits supplement admission controls; they do not replace them.

The exposed Crypto/Wire/Record modules are low-level protocol/test interfaces.
They accept raw secrets and allow constructions the high-level session API would
forbid. Applications should use Lantern.TLS, never assemble their own sessions.
Certificate validation uses the configured roots, hostname, wall clock, key usage,
and purpose. Revocation, OCSP stapling enforcement, and certificate transparency
policy are not implemented here. No trust checks can be disabled through the API.

The limited profile intentionally rejects some otherwise valid TLS peers. It is
not a drop-in replacement for a complete TLS library. Fatal errors close the
connection; detailed standards-specific alerts are not implemented. Automatic
memory wiping, formal protocol verification, and broad fuzzing remain open work.

Client identity checks use an explicit SAN-only policy rather than the pinned
certificate verifier's legacy name hook. IPv4/IPv6 references match only exact IP
SAN bytes; DNS references match only valid DNS SANs and complete leftmost-label
wildcards covering one label. Subject Common Names never establish identity.
Literal IPs omit SNI. This follows [RFC 9525](https://www.rfc-editor.org/rfc/rfc9525.html)
and [RFC 6066 section 3](https://www.rfc-editor.org/rfc/rfc6066.html#section-3).
The initial crypton-x509-validation 1.6.14 pin was found vulnerable to missing
name-constraint and critical-extension enforcement and has been replaced. The
current pin is 1.10.0 with Crypton 2.2.1; certificate signatures, decoding and
path/time checks remain delegated to those dependencies. Our SAN-only hook
replaces their default identity policy.
Client interoperability fixtures cover IP-only SANs, incorrect IPs, numeric DNS SANs,
CN-only certificates, wildcard depth, partial wildcards, case and captured SNI.

## Certificate-chain policy

`CertificatePolicy.hs` adds bounded application checks over decoded X.509 data:
leaf-first ordered chains, duplicate and malformed known extensions, a restricted
critical-extension set, server-auth purpose throughout the chain, and DNS/IPv4/
IPv6 permitted and excluded subtrees. Every issuer (including the selected trust
anchor) constrains all subordinate SANs and the actual reference identity; a
missing intermediate constraint cannot weaken an ancestor. IP masks are applied
to address bytes. DNS comparisons are case insensitive and respect label boundaries.
The cryptographic path validator runs as well; this policy cannot bypass it.

Only DNS and IP constraint forms with minimum zero and absent maximum are supported.
Other forms fail closed, including directoryName, URI and email constraints.
Self-issued intermediate exceptions and alternate-path discovery are not implemented;
some otherwise valid constrained chains are rejected by this restricted profile or
by the dependency's stricter DNS constraint behavior. The Nix primitive set
includes a one-line RFC 5280 inheritance fix: a CA omitting NameConstraints
inherits its issuer's constraints. Our policy independently enforces all ancestors. Each certificate has at most
128 extensions and 128 SANs, and each constraint extension at most 64 subtrees.
Revocation, policy-tree processing and broad PKIX conformance remain outside this
profile. Unknown critical extensions are rejected rather than ignored.

`test/pkix.py` generates independent root/intermediate/leaf chains and checks both
acceptance and rejection, including that no HTTP request reaches rejected peers.
The old pin accepted DNS and IP constraint violations and an unknown critical
extension; these are regression cases, not evidence of a deployment compromise.

## Key exchange and retry boundaries

X25519 and P-256 use Crypton key generation and ECDH. P-256 wire points must be
65-byte SEC1 uncompressed values with prefix 04; Crypton's point decoder validates
coordinates and curve membership, and infinity is rejected. Fresh P-256 scalars
are nonzero and below the group order. Shared secrets retain their 32-byte width;
all-zero ECDHE output is rejected. Private share values have no Show instance.
These checks do not establish a blanket timing or memory-erasure guarantee.

Only one retry is accepted. ServerHello/HRR share strict version, echoed session,
fixed cipher and extension checks. A requested group must have been advertised
and not already supplied; the final group must match it. A cookie-only retry is
supported by the client. Cookie bytes are opaque and can only affect the echoed
extension, not trust roots or identity. They remain within the 64 KiB handshake
message cap and 128-record fragmentation cap. Supported-group lists and
certificate-entry extension lists have 128-entry caps, checked before duplicate
scans; ServerHello/HRR and encrypted extensions have stricter allowed-set caps. The server keeps retry state in the
bounded handshake and does not issue cookies or promise stateless DoS protection.

The server verifies second-ClientHello immutable fields and extension order/data,
allows zero padding changes, and allows PSK ages/binders to update or identities
to be removed without permitting new identities. PSKs are never selected or used
for authentication. Early data remains rejected. Compatibility CCS messages are
bounded and excluded from transcripts. Authentication covers the synthetic
message_hash, retry and both hello flights before application data is returned.

The independent negotiation fixture checks authenticated OpenSSL retries to both
groups, fragmented retries/ClientHello2, large cookies, invalid points, second
retries, group/cipher/session changes, changed SNI/ALPN, and unsolicited extensions.
OpenSSL stateless-cookie tests exercise full certificate/Finished authentication
for both cookie-only and P-256 retries. These tests supplement, not replace, review.

## Certificate algorithms and keys

Every selected certificate key, including a trust anchor used to verify a child,
must be RSA with an exact 2048–8192-bit odd modulus and odd exponent 3–2^32−1,
a named P-256/P-384/P-521 EC key, or Ed25519. A rounded byte count is insufficient:
2047-bit moduli occupy 256 bytes. Explicit EC parameters and other key types fail
closed. The upper RSA/exponent bounds also limit verification work.

The client advertises and permits SHA-256/384/512 RSA PKCS#1/PSS certificate
signatures, the corresponding P-256/384/521 ECDSA signatures, and Ed25519. This
list is shared with ClientHello construction. SHA-1, MD5, SHA-224 and unsupported
schemes cannot establish a path. Inner and outer certificate algorithm identifiers
must agree. An installed trust anchor's own signature is exempt; its public key
still meets the key policy. Signature verification remains Crypton code.

Generated-chain regressions cover sub-2048-bit leaf/issuer RSA keys, SHA-1 leaf
rejection and SHA-1 anchor acceptance, SHA-224 rejection, SHA-384/512 RSA, RSA-PSS,
and P-384/P-521 issuers. The independent fixture lowers OpenSSL's server-only
security level to offer intentionally weak certificates; the library's policy
has no verification bypass.

Before X.509 decoding, CertificateEncoding.hs uses Crypton's ASN.1 primitives to
compare the inner/outer AlgorithmIdentifier structures and validate PSS MGF1/hash
and salt parameters. The decoded X.509 type discards those fields, so checking
only its hash/key enums is insufficient. This check lives in our library and
applies to Cabal consumers too; it does not depend on a packaging-only parser fix.
Both wrong-MGF and wrong-salt fixtures reproduced acceptance before this check.

Client reference names must be supplied as ASCII DNS A-labels or IP literals
(maximum 253 characters, no whitespace/control characters). Validate the original
string before ASCII case normalization/IP parsing; Unicode lowercasing must not
alias an unsupported name to an ASCII certificate identity. IDNA conversion is
the caller's responsibility. Client tests cover Kelvin/dotted-I rejection, ASCII
A-label and case success, and zero ClientHello bytes for invalid reference input.
Cryptographic primitives and PKIX verification are unchanged.
