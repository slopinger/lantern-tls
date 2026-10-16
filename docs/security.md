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
The pinned crypton-x509-validation 1.6.14 source was inspected: its default name
hook permits Common Name fallback and checks IP SANs only when DNS SANs also exist.
Our hook replaces only identity matching, retaining PKIX cryptographic verification.
Client interoperability fixtures cover IP-only SANs, incorrect IPs, numeric DNS SANs,
CN-only certificates, wildcard depth, partial wildcards, case and captured SNI.

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
