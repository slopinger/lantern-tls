# TLS protocol research

Reviewed 2026-10-16. Sources below distinguish the implemented wire profile from
standard requirements and future work. All decisions below are our engineering
choices; the references do not certify this implementation.

## Current specification and historical vectors

[RFC 9846](https://datatracker.ietf.org/doc/html/rfc9846) is the July 2026 TLS 1.3
specification and supersedes RFC 8446. The implementation uses the TLS 1.3
handshake transcript, separate handshake/application traffic secrets, record
nonces, and epoch boundaries described there. In particular, a Finished message
must be authenticated before application input is exposed. A new key epoch starts
with sequence number zero. KeyUpdate is protected with the old key and must end its
record. This implementation deliberately omits required general-purpose features,
including server ECDSA credentials, and does not claim complete conformance.

[RFC 8446](https://datatracker.ietf.org/doc/html/rfc8446) remains useful when
reading older implementations and traces. [RFC 8448](https://datatracker.ietf.org/doc/html/rfc8448)
provides independent TLS 1.3 known answers. Tests compare selected early-secret,
derived-secret, traffic-key, and IV values against these traces rather than merely
checking that our encoder and decoder agree with each other.

[RFC 5869](https://www.rfc-editor.org/rfc/rfc5869.html) specifies HKDF. Our glue
constructs TLS labels and contexts, while Crypton performs extract/expand and
HMAC. Its test case 1 supplies an independent extract check.

## Primitive boundary

The user explicitly requested independently implemented TLS and HTTP libraries,
while retaining established cryptographic primitives. Thus there is no `tls`
package or OpenSSL binding in the protocol. Crypton supplies AES-GCM, SHA-256,
HMAC/HKDF, X25519/P-256 ECDH, secure random bytes, and RSA signing/verification. We build the
protocol encodings, transcripts, key transitions, and error policy.

[RFC 7748](https://www.rfc-editor.org/rfc/rfc7748.html) is the X25519 reference.
The application checks the all-zero shared-secret result and uses fresh ephemeral
keys for every handshake. [NIST SP 800-38D](https://csrc.nist.gov/pubs/sp/800/38/d/final)
is the GCM reference. Record sequence numbers are XORed into the static IV, never
reused in an epoch, and authenticated together with the record header. Record
content is not returned until its tag verifies. Keys are capped conservatively
and send-side rotation starts well before the cap.

[RFC 8017](https://datatracker.ietf.org/doc/html/rfc8017) is the RSA reference.
Private-key operations use Crypton's blinded signing APIs, not home-grown
big-integer exponentiation. Server CertificateVerify uses RSA-PSS with the
SHA-256 parameters. ACME and CSRs use separate PKCS#1-v1.5 signature glue.

## Credentials and client authentication of servers

[RFC 5280](https://datatracker.ietf.org/doc/html/rfc5280) describes certificate
paths and names. Implementing a new TLS state machine is not a reason to weaken
PKIX checks. The client delegates cryptographic path/time/purpose checks
to crypton-x509-validation, uses explicit roots, and exposes no insecure mode.
It separately verifies the handshake CertificateVerify and Finished messages.
Default path validation does not provide live revocation/OCSP lookups.

The server owns a small, bounded PEM/DER decoder for RSA credentials. It checks
canonical integer/length encodings, private-key algebra, and matching certificate
public key. The chain is administrator-provided; this API does not implement a
new trust store. [RFC 2986](https://datatracker.ietf.org/doc/html/rfc2986) informs
our CSR encoder, including the SAN extension request used by ACME. Primitive
signing is kept distinct from constructing the signed DER bytes.

## Scope and operational design

[RFC 9325](https://www.rfc-editor.org/rfc/rfc9325.html) and
[RFC 9852](https://www.rfc-editor.org/rfc/rfc9852.html) inform version and
configuration policy. Lantern implements TLS 1.3 only, disables early data by
not negotiating it, never selects compression, and does not expose legacy modes.
This choice sacrifices compatibility; it does not make a novel implementation
production-ready. Resumption, other cipher suites, and mutual
TLS need their own state-machine design and tests before support is advertised.

Receive and send state have separate locks, allowing one reader and one writer.
The write sequence and key-update transitions share one lock. Any exception
poisons the context so a caller cannot retry a partial write under a reused nonce.
Record/handshake metadata has byte limits; non-progressing/empty messages have
count limits. The host server still owns admission limits and absolute I/O
deadlines. Protocol errors terminate the connection; fatal-alert diagnostics are
not fully enumerated.

## Evidence and remaining work

The suite covers known answers and randomized record mutation/sequence checks,
real OpenSSL client/server handshakes, RSA and ECDSA certificates, hostname and
unknown-root rejection, large transfers, transport and handshake fragmentation,
concurrency, KeyUpdate, and authenticated closure. A bridge changes a Finished
MAC while recomputing a valid AEAD tag using temporary test-only OpenSSL key-log
secrets; rejection checks transcript verification independently of GCM integrity.

An independently implemented client also fetched Let's Encrypt's staging
ACME directory over an authenticated TLS connection. The Lantern repository
records issuance/renewal tests. Interoperability is evidence of supported paths,
not a proof about adversarial paths. Independent review, coverage-guided fuzzing,
managed-memory secret handling, broader signature/group support, and a formal
state-machine audit remain necessary before a production-security claim.

## Key groups and HelloRetryRequest

[RFC 9846 sections 4.1, 4.2.2, 4.2.4 and 4.3.8](https://datatracker.ietf.org/doc/html/rfc9846)
were rechecked against the current published text. The corresponding historical
RFC 8446 rules were also consulted. Retry authentication hashes the first hello
into a synthetic message_hash; concatenating just ClientHello2 and ServerHello
would omit the negotiation history. The existing absolute handshake deadline is
not reset by the retry. Negotiation is fixed to the offered SHA-256 cipher suite.

Our server prefers an already supplied X25519 share, then P-256; only a missing
compatible share causes a retry. Our client advertises both, initially generating
only X25519 to keep its common-case flight small. A P-256-only server requests it
in a retry; a cookie-only request retains the first share. A second retry, an
already supplied or unsupported requested group, or a changed final group fails.
Second client hellos preserve immutable fields, allowing the specified key share,
padding and unselected PSK age/binder changes. No session-resumption primitive or
PSK authentication was added.

Crypton 1.0.6's P-256 source was inspected before use. The dedicated P256 module
provides point decoding/validation, fixed-width serialization, scalar generation,
base multiplication and ECDH. Its raw point representation is 64 coordinate bytes;
TLS adds the SEC1 04 prefix. Private scalars are range-checked before multiplication.
We use the primitive's pointDh API rather than implementing curve arithmetic or
using the generic variable-time Integer ECC path. This is a dependency boundary,
not an independent constant-time audit of Crypton or GHC.

Testing uses OpenSSL as an independent authenticated peer for both retry groups,
including stateless cookies. A separate Python wire peer probes illegal retries
and second-hello modifications and inspects cookie/key-share reconstruction. It
also tests malformed P-256 encodings, nonzero padding, PSK-identity additions and
large fragmented cookies. Test keys and peer secrets are temporary and unpublished.
