# TLS 1.2 support

SharpTls implements TLS 1.2 as a separate, strict protocol engine rather than
sharing TLS 1.3 transcript, key-schedule, or record-protection state. A mixed-version
ClientHello is built and sent once; the authenticated ServerHello dispatches that
exact offer and transcript to the selected TLS 1.3 or TLS 1.2 state machine.

## Executable subset

- ECDHE_RSA and ECDHE_ECDSA full handshakes with X25519, P-256, P-384, or P-521.
- AES-128-GCM, AES-256-GCM, and ChaCha20-Poly1305 AEAD cipher suites.
- SHA-256 and SHA-384 TLS PRFs, Extended Master Secret, key expansion, and Finished.
- RSA-PSS with RSAE or RSASSA-PSS keys, RSA-PKCS1 with RSAE keys, and ECDSA
  ServerKeyExchange authentication with SHA-256 or stronger.
- System certificate-chain and hostname validation, SNI, ALPN, CertificateStatus framing,
  SCT extension framing, RSA/ECDSA client certificate authentication, protocol-mandated
  empty client Certificate fallback, and HTTP/1.1 application data.
- Partial stream reads/writes, record fragmentation, cancellation, alerts, close_notify,
  bounded parsing, constant-time Finished comparison, and secret zeroization.
- RFC 8449 `record_size_limit` in ServerHello, with independent inbound/outbound
  limits and protected Finished/application fragmentation.
- Authenticated session-ID abbreviated handshakes through a bounded caller-owned
  `Tls12SessionCache`. Entries are origin, cipher-suite, certificate-lifetime,
  and expiry bound; master secrets are copied, never exposed publicly, and zeroized.
  Resumption verifies the server Finished before sending the client CCS/Finished and
  has a managed TCP application-data interoperability test.
- RFC 5077 stateless ticket offering and renewal, including a fresh non-empty
  distinguishing ClientHello session ID, exact ticket extension replacement, lifetime
  capping, mandatory ServerHello/NewSessionTicket consistency, and transcript inclusion.
  ALPN remains a per-connection negotiation as required by RFC 7301 rather than a
  property inherited blindly from the cached TLS 1.2 session.

Extended Master Secret (RFC 7627) and secure-renegotiation signalling (RFC 5746) are
mandatory by default. The client rejects duplicate or unoffered extensions, malformed
vectors, downgrade sentinels, invalid ServerKeyExchange signatures or points, unexpected
state transitions, authentication failures, and TLS records with illegal versions.

## Deliberately disabled

CBC, RC4, static RSA key exchange, SHA-1 authentication, finite-field DHE,
renegotiation, and protocol versions below TLS 1.2 are not executable. Older suites
may appear in an exact fingerprint profile, but a server selecting one is rejected.
RFC 5705 exporters are available through `ExportKeyingMaterial`. TLS 1.2 client
CertificateVerify supports
RSA-PSS-RSAE, RSA-PSS-PSS, RSA-PKCS#1, and exact-curve ECDSA with SHA-256 or stronger;
SHA-1 remains disabled.

The implementation follows RFC 5246, RFC 5288, RFC 5746, RFC 7627, RFC 7905, and the
TLS 1.2 compatibility and downgrade requirements in RFC 9846. It uses only .NET
cryptographic primitives and the managed key-share providers already present in SharpTls.
