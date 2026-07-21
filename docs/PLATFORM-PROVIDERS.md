# Platform and cryptographic provider matrix

SharpTls targets `net9.0` and later. TLS framing, transcript handling, state machines,
ClientHello construction, HKDF orchestration and protocol validation are managed C# on
every platform. This matrix identifies the primitive provider beneath those protocol
components and the release gate applied when a primitive is unavailable.

| Capability | Provider on .NET 9+ | Fallback | Availability policy |
|---|---|---|---|
| AES-128/256-GCM | `System.Security.Cryptography.AesGcm` | none | `AesGcm.IsSupported` is required before an advertised AES-GCM path executes. |
| ChaCha20-Poly1305 | `System.Security.Cryptography.ChaCha20Poly1305` | none | `ChaCha20Poly1305.IsSupported` controls profile randomization, HPKE selection and record execution. |
| SHA-256/384/512 and HMAC | .NET hashing/HMAC APIs | none | Required on every supported .NET 9 platform. |
| SHA3-256/512 and SHAKE256 | .NET SHA-3/SHAKE APIs when available | bounded managed FIPS 202 implementation | Runtime and fallback paths share published-vector tests. |
| P-256/P-384/P-521 ECDH | `ECDiffieHellman` named curves | none | Capability probing rejects an unavailable curve before network I/O. |
| P-256/P-384/P-521 ECDSA | `ECDsa` named curves | none | Curve and signature-scheme compatibility are enforced before signing or verification. |
| RSA-PSS / RSA PKCS#1 verification | `RSA` | none | PSS SPKI constraints, MGF1 hash, salt length and trailer field are validated explicitly. |
| X25519 | managed RFC 7748 fixed-iteration ladder | none | Published vectors, low-order rejection, single-use key ownership and zeroization gates apply. |
| ML-KEM-768 | managed FIPS 203 | none | FIPS vectors, implicit rejection, hybrid transcript ordering and hostile-key tests gate execution. |
| X25519MLKEM768 | managed X25519 + ML-KEM-768 composition | none | Both component providers must pass capability and vector gates. |
| X25519Kyber768Draft00 | managed compatibility construction | none | Kept separate from the standards-track hybrid group and tested against its accumulated vectors. |
| ECH HPKE NIST KEMs | .NET ECDH plus managed RFC 9180 labeling | none | Each curve is probed; unsupported configurations are skipped rather than partially executed. |
| ECH HPKE X25519 | managed X25519 plus .NET AEAD/HMAC | none | KEM, KDF and AEAD must all be executable before config selection. |
| X.509 parsing and PKIX | `X509Certificate2` / `X509Chain` | none | System trust is always required; known revocation is fatal, unavailable revocation evidence has configurable soft/hard failure, and SharpTls adds RFC 9525 identity and TLS signature checks. |
| Zlib/Brotli certificate compression | `ZLibStream` / `BrotliStream` | none | Offered-only selection plus compressed and decompressed size bounds. |
| Entropy | `RandomNumberGenerator` | none in production | The deterministic source is reachable only through explicit test/snapshot APIs. |

Ed25519 and Ed448 are not advertised on .NET 9 because there is no portable runtime
primitive and SharpTls does not substitute a new custom EdDSA implementation. Legacy
CBC, RC4, 3DES, static-RSA key exchange, TLS 1.0/1.1 and SHA-1 authentication are wire
representation features only and never become executable negotiation paths.

## Operating-system qualification

| Host | Deterministic suite | SharpTls client/server loopback | Platform TLS peer | Release requirement |
|---|---:|---:|---:|---|
| Linux | required | TLS 1.2, TLS 1.3 and QUIC-TLS | `SslStream` client and server rows | Hosted .NET 9 job plus scheduled public interop and Linux coverage fuzz. |
| Windows | required | TLS 1.2, TLS 1.3 and QUIC-TLS | `SslStream` client and server rows | Hosted .NET 9 job; all advertised runtime primitives must pass. |
| macOS | required | TLS 1.2, TLS 1.3 and QUIC-TLS | Platform TLS 1.2 server row | Hosted .NET 9 job; SharpTls-owned protocol paths remain fully exercised. |

The .NET 9 Apple `SslStream` client is not used as a server-interop oracle: it neither
exposes the required TLS 1.3 client path nor emits the combination of TLS 1.2 Extended
Master Secret and secure-renegotiation signals required by SharpTls policy. Those peer
rows run on Linux and Windows, while macOS still runs the complete managed engine and a
platform TLS 1.2 server peer. SharpTls does not weaken its protocol policy to accommodate
a test provider.

## Evidence and fail-closed behavior

The normal three-OS workflow builds with warnings as errors and runs the entire
deterministic suite. The scheduled/manual/tag jobs add public interoperability and
coverage-guided fuzzing. A release record must capture the runner image, exact .NET
runtime, job/run ID and any skipped capability. A capability-dependent test may skip
only when the public runtime probe reports that primitive unavailable; the corresponding
profile or algorithm must then be filtered or rejected before I/O, never silently
downgraded.

Authored workflow coverage is not hosted evidence by itself. A production `1.0.0`
release still requires retained Linux/macOS/Windows run IDs and the external evidence
listed in [RELEASE-HARDENING.md](RELEASE-HARDENING.md).
