# Changelog

All notable changes to SharpTls are documented here. The project follows
[Semantic Versioning](https://semver.org/spec/v2.0.0.html) before and after 1.0; during
the preview period, minor releases may intentionally revise public APIs.

## [Unreleased]

## [0.9.0-preview.3] - 2026-07-18

### Fixed

- Include the SharpFuzz runtime dependency closure, use the upstream framework-dependent
  libFuzzer launch contract, and defer instrumented target construction until the native
  coverage map is initialized during release qualification.

## [0.9.0-preview.2] - 2026-07-18

### Added

- GitHub-ready project presentation, contribution templates and automated tag releases.
- Reproducible NuGet package and symbol publication through GitHub Actions.

### Fixed

- Accept RFC 5746 `TLS_EMPTY_RENEGOTIATION_INFO_SCSV` as the initial TLS 1.2 secure-
  renegotiation signal while continuing to require Extended Master Secret.
- Normalize platform-provider invalid NIST ECDH point errors to the protocol's
  `illegal_parameter` alert on every supported operating system.
- Classify custom-root chain termination failures consistently as `unknown_ca` across
  platform X.509 providers.
- Load Windows Schannel interoperability credentials through a non-ephemeral test key
  container and update hosted actions to their Node.js 24 releases.

## [0.9.0-preview.1] - 2026-07-18

### Added

- Pure managed TLS 1.3 client/server and secure TLS 1.2 subset.
- Byte-exact ClientHello builder, semantic/raw ordered extensions, GREASE,
  GREASE ECH, padding and record fragmentation.
- Forty pinned upstream uTLS wire IDs, package-bound family aliases, coherent
  randomization and bounded origin-aware Roller.
- Strict capture import, JSON v6 interchange, deterministic test snapshots and
  defensive pre-send inspection.
- RFC 9849 ECH and RFC 9848 HTTPS/SVCB bootstrap over UDP/TCP DNS, DoT and DoH.
- Session resumption, external PSK, replay-gated 0-RTT, KeyUpdate, exporters and
  post-handshake client authentication.
- Standard certificate validation, client certificates, delegated credentials,
  OCSP/SCT policy and certificate compression.
- X25519, NIST curves, X25519MLKEM768 and the historical Kyber draft group needed
  by pinned wire profiles.
- Recordless QUIC-TLS client/server adapters and an HTTP/1.1 interoperability sample.

### Security

- CBC, RC4, static RSA, SHA-1 authentication, renegotiation and TLS 1.0/1.1 are
  non-executable.
- Independent cryptographic review and hosted release evidence remain 1.0 gates.
