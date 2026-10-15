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
