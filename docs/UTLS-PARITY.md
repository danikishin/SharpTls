# uTLS-class feature parity matrix

This matrix tracks SharpTls against the safe client-facing capability classes made
popular by uTLS. It is a release-control document, not a claim that the two projects
share code or identical APIs. SharpTls continues to implement TLS directly in managed
C#. Runtime cryptographic primitives are preferred; managed X25519, FIPS 202 and
FIPS 203 implementations exist because .NET 9 lacks portable primitives for them.

Status vocabulary: **done** is implemented and verified, **active** is the current
milestone, **planned** has an explicit roadmap gate, and **non-goal** is intentionally
excluded for security or scope reasons.

| Capability | Status | Target phase | Notes |
|---|---:|---:|---|
| Exact built-in extension ordering | done | 4 | Existing immutable profile model. |
| Arbitrary opaque extension and mixed ordering | done | 14 | Opaque extensions fail if a server requires unsupported semantics. |
| Caller-owned transport and standard Stream API | done | 15 | Caller ownership, partial reads and one-read/one-write concurrency are explicit. |
| Captured ClientHello to reusable specification | done | 16, 24 | Bare and record-fragmented import preserve reusable structure plus record boundaries/versions; ephemeral keys, randoms and binders are regenerated securely, and visible ECH outer values normalize to fresh semantic GREASE ECH. |
| Versioned JSON profile interchange | done | 16, 24 | Strict v6 schema with v1–v5 compatibility, exact GREASE-ECH suites, shuffle policy, duplicate/unknown rejection, and bounded hostile-input tests. |
| Randomized coherent fingerprints | done | 17, 24 | Runtime filtering, weighted ALPN, conditional PSK/0-RTT slots, ALPS/GREASE-ECH controls, arbitrary GREASE classes, padding/order/key-share randomization, property/distribution corpora, and public interop. |
| Roller with successful-profile cache | done | 17, 24 | uTLS-family default pool plus randomized member, full client-option propagation, pre-I/O compatibility filtering, bounded retry/backoff and origin LRU; peer negotiation alerts only, never certificate/authentication failures. |
| Chrome/Firefox/Safari/iOS/Edge/Android profiles | done | 18, 20, 21, 23, 24 | All 40 concrete wire IDs in pinned upstream `UTLSIdToSpec` are present, including Chrome 115/120 PQ, Chrome 120/131/133, Firefox 148 and Safari 26.3. Thirty-nine are securely executable; exact 360/7.5 is wire-only because it omits EMS. |
| Versioned profile manifest/catalog | done | 18 | Executable capture normalization, source SHA-256, ALPN dependencies, strict IDs, and thread-safe registry are implemented. |
| TLS 1.3 AES-GCM/ChaCha full handshake | done | 1–13 | RFC 9846 baseline. |
| P-256/P-384/P-521 and HRR | done | 5, 7, 19 | Fresh single-use shares; P-521 has runtime, CertificateVerify, and public-server evidence. |
| X25519 and RSA-PSS-PSS | done | 19 | Managed fixed-ladder RFC 7748 X25519 and runtime RSA-PSS-PSS are complete with OID/parameter enforcement and interop. EdDSA remains unadvertised because .NET 9 has no portable primitive. |
| Hybrid post-quantum key agreement | done | 19 | X25519MLKEM768 uses managed FIPS 203 ML-KEM-768 plus X25519; historical X25519Kyber768Draft00 has its distinct ordering/final hash. Official accumulated vectors, invalid-key tests, TLS and recordless QUIC client/server interop pass. Independent audit remains a phase-29 release gate. |
| Production TLS 1.2 AEAD client | done | 20, 25 | Separate state/transcript/PRF; ECDHE_RSA/ECDHE_ECDSA; AES-GCM/ChaCha20-Poly1305; mandatory EMS and secure-renegotiation signalling; full and session-ID abbreviated handshakes with application-data interop. CBC, RC4, static RSA, SHA-1 and renegotiation remain disabled. |
| TLS 1.3 session cache/PSK resumption | done | 21, 25 | Bounded origin/port/ALPN/hash-bound cache, single-use tickets, bounded multiple identities, per-hash/HRR binders, arbitrary valid server-selected index, `psk_dhe_ke`, authentication-lifetime caps, ticket rotation, and public/managed interop. |
| Replay-aware 0-RTT | done | 21 | Disabled by default; explicit risk acknowledgement and retransmission policy; accepted/rejected managed TCP interop plus RFC vectors. |
| Mutable handshake/master-secret access | non-goal | — | Upstream exposes internal handshake and master-secret state. SharpTls exposes exact pre-send ClientHello bytes and redacted negotiated events, but never raw secrets or mutable live transcript/state. |
| Fake arbitrary master-secret connection | non-goal | — | Conflicts with authenticated, non-placeholder crypto invariants. |
| Fake session tickets/PSKs | non-goal | — | Upstream permits caller-fabricated resumption state for fingerprint tricks. SharpTls accepts only authenticated server-issued tickets or explicit RFC 8446 external PSKs and never converts fake state into a successful connection. |
| KeyUpdate and long-lived traffic | done | 22 | Peer/local ratchets, requested response, automatic AEAD-limit rotation, counters, and public interop. |
| Client certificates/post-handshake auth | done | 22, 25 | Caller-owned RSA/ECDSA chains, TLS 1.2/1.3 CertificateVerify, empty fallback, opt-in PHA, unique contexts, transcript forks, async/cancellable per-request selection, SPKI-bound external signers, and loopback/platform interop. |
| Exporters/channel binding | done | 22 | RFC 9846 exporter_secret construction, label/length validation, and KeyUpdate stability. |
| OCSP/SCT/certificate compression | done | 18, 23, 25, 28 | Bounded TLS 1.2/1.3 evidence framing, offered-only server presentation, RFC 8879 Brotli/Zlib client decompression and server compression, plus an async fail-closed evidence-policy hook are implemented. RFC 9162 `transparency_info` is a separate newer CT-v2 feature, not an upstream uTLS parity claim. |
| `signature_algorithms_cert` / `record_size_limit` | done | 23 | Independent certificate-signature preferences plus RFC 8449 asymmetric TLS 1.2/1.3 negotiation, protected-handshake/application fragmentation, 0-RTT ticket binding, and `record_overflow` enforcement. |
| Delegated credentials | done | 23, 25 | RFC 9345 server and client authentication with DelegationUsage, lifetime, exact ECDSA/RSA-PSS-PSS SPKI, delegation-context signatures, leaf-only CertificateEntry encoding, dual CertificateRequest algorithm authorization, delegated CertificateVerify, async signer, PHA and managed interop. |
| ALPS/application_settings | done | 23, 25 | Experimental 17513/17613 uTLS code points, semantic profile/capture/JSON support, ALPN binding, authenticated bidirectional payloads, transcript integration, persistent ticket binding, guarded 0-RTT, and hostile resumed-setting rejection. |
| RFC 9849 ECH/GREASE-ECH | done | 23, 27, 28 | Real X25519/P-256/P-384/P-521 HPKE, inner/outer handshakes, accepted HRR interop, source-bound PSK/0-RTT with outer GREASE identities, rejection alert, authenticated retry configs, outer-extension compression, GREASE-ECH, RFC 9848 HTTPS/SVCB bootstrap, standard TCP server reception, and recordless QUIC client/server ECH are implemented. Strict DoT/DoH and an accepted public Cloudflare ECH handshake complete the public-client gate. |
| HTTP/1.1 interoperability example | done | 12 | Demonstrates direct application records; it is not a reusable HTTP client. |
| Current pinned profile corpus and `Auto` aliases | done | 24 | All 40 IDs build deterministically; 39 authenticate against two public deployments, exact 360/7.5 fails pre-I/O as wire-only, structural/order tests cover hybrid profiles, and family Auto aliases resolve only to executable profiles. |
| Pre-send ClientHello inspection observer | done | 24 | Initial/HRR direct, ECH-outer and GREASE-ECH flights expose defensive exact handshake and planned TLS-record copies, record versions/boundaries, before emission; callback failure prevents the write. |
| Persistent sessions, external PSK and TLS 1.2 resumption | done | 25 | AES-256-GCM authenticated TLS 1.3 persistence/key rotation, external PSK `ext binder`/HRR, bounded multi-ticket PSK offers, and origin/suite-bound TLS 1.2 session-ID plus RFC 5077 ticket/renewal resumption are done with managed-TCP interop. Fabricated secrets are never accepted. |
| Dynamic client-certificate selection and signer abstraction | done | 25 | Per-request async/cancellable selection for TLS 1.2, TLS 1.3 and PHA; serialized caller-owned HSM/KMS/runtime signer with exact leaf-SPKI and scheme binding, cancellation and managed mutual-auth interop. |
| Connection state and redacted handshake events | done | 26 | Immutable secret-free connection snapshots publish negotiated state plus defensive certificate/OCSP/SCT/ALPS/ECH results; serialized non-reentrant redacted events expose ordering and lengths without message bytes or secrets. |
| Opt-in NSS key logging | done | 26 | Caller-owned serialized sink, disabled by default, explicit exposure acknowledgement, TLS 1.3 early/handshake/application/exporter and TLS 1.2 CLIENT_RANDOM labels, temporary-buffer zeroization. |
| Mutable live AEAD keystream access | non-goal | — | Test-only bounded hooks replace production state mutation. |
| Obsolete TLS/extension execution | non-goal | — | TLS 1.0/1.1, CBC/RC4/3DES/static-RSA suites, renegotiation, NPN, Token Binding and Channel ID are not executable. Their bytes can be represented as opaque ClientHello extensions where needed for capture fidelity, but no unsupported server selection is accepted. |
| `HttpClient`, HTTP/2/HPACK and browser HTTP fingerprints | non-goal | — | Application protocols belong in separate integration packages. ALPN remains a TLS feature. |
| QUIC TLS handshake adapter | done | 27 | Recordless client/server CRYPTO reassembly, secrets, transport parameters, HRR, ECH accept/reject, client auth, protected tickets and replay-gated ECH-aware 0-RTT; no QUIC transport or HTTP/3. |
| Full QUIC transport and HTTP/3 | non-goal | — | Packet protection integration, recovery, congestion control, streams, QPACK and HTTP/3 belong elsewhere. |
| Standard TLS 1.3/secure TLS 1.2 server | done | 28 | Strict server engine, listener, certificate selection, RFC 9849 ECH keys/accept/reject/HRR, client auth, session-ID/ticket resumption, exporters, KeyUpdate and certificate evidence/compression; no server fingerprint-mimicry API. |
| Server-side fingerprint customization | non-goal | — | uTLS's specialized mimicry surface is ClientHello/client-side. |
| Continuous fuzzing/release qualification/NuGet 1.0 | planned | 29 | Deterministic target-specific structural corpora, managed mutation and instrumented SharpFuzz/libFuzzer harnesses, retained scheduled corpora, budgets, API baseline, reproducible `.nupkg`/`.snupkg`, clean restore, engineering threat model, immutable-action three-OS CI, scheduled public interop and tag provenance are implemented. Hosted multi-day campaign records, hosted matrix run IDs and independent review evidence remain release gates. |

## Definition of parity

SharpTls reaches uTLS-class parity when a caller can select, import, randomize, roll,
inspect and safely execute modern ClientHello profiles over an idiomatic transport;
complete the required TLS versions, algorithms, resumption and post-handshake flows;
and consume an authenticated application-data `Stream` plus safe diagnostic state.
HTTP/2, HTTP/3 and a full QUIC transport are not part of this definition. A recordless
QUIC-TLS adapter and the standard TLS server engine are included to match upstream
uTLS's protocol surface, without inventing server-side fingerprint mimicry.
A wire pattern alone does not count if the server can legally select or acknowledge
it and SharpTls cannot complete the corresponding protocol path.

The pinned, executable feature baseline now satisfies this definition. Phase 29 is
still required before a production `1.0.0` release: hosted cross-platform evidence,
long-running fuzz campaigns, packaging provenance and an independent security audit
cannot be manufactured by unit tests in one local workspace.
