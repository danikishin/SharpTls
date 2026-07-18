# Security policy and invariants

SharpTls processes attacker-controlled network bytes. The following are non-negotiable invariants rather than optional hardening:

## Supported versions

| Version | Security fixes |
|---|---|
| Latest `0.9.x` preview | Supported |
| Older previews | Upgrade to the latest preview |

Until 1.0, security fixes may ship together with necessary API corrections. Published
package versions are immutable and are never silently replaced.

The assets, trust boundaries, attacker capabilities, abuse cases and residual release
risks are maintained in [the 1.0 threat model](docs/THREAT-MODEL.md).

1. Every vector length is checked against its enclosing message and a configured absolute limit before allocation or slicing.
2. TLS plaintext fragments never exceed 16,384 bytes; TLSCiphertext never exceeds 16,640 bytes; handshake messages are bounded by policy.
3. Parsers consume their complete input. Trailing bytes, truncated integers/vectors, duplicate extensions, illegal enum values in negotiated fields, and forbidden state transitions fail closed with a protocol alert classification.
4. Transcript bytes are the exact encoded handshake messages, including their four-byte handshake headers. Record headers and compatibility CCS records are not transcripted.
5. AEAD nonces use the RFC sequence-number construction. Sequence numbers never wrap and authentication failures never release plaintext.
6. Secret buffers are privately owned, are never exposed by public APIs, and are zeroed on replacement/disposal with `CryptographicOperations.ZeroMemory`.
7. NIST TLS ECDHE and HPKE point operations and validation use runtime cryptographic providers. HPKE private scalars use RFC 9180 HKDF-based `DeriveKeyPair` and are imported into that provider; no custom Weierstrass point arithmetic is used. .NET 9 has no portable raw X25519 TLS primitive, so the isolated managed RFC 7748 implementation uses a fixed-iteration Montgomery ladder, official vectors, contributory-behavior checks, single-use keys, and zeroization; no other custom curve or AEAD primitive is permitted.
8. Certificate acceptance requires all of: successful system-chain validation, server-auth EKU policy, time validity, hostname matching, and a valid TLS 1.3 CertificateVerify signature.
9. TLS 1.3 RSA CertificateVerify accepts only RSA-PSS with the exact RSAE or RSASSA-PSS SubjectPublicKeyInfo OID selected by the signature scheme. RSASSA-PSS key hash, MGF1, minimum salt, and trailer constraints are DER-validated before the runtime RSA provider is invoked. ECDSA signatures use the exact curve/hash pairing. TLS 1.2 additionally permits SHA-256-or-stronger RSA-PKCS#1 with RSAE keys.
10. Deterministic mode is opt-in, test-only behavior. The default entropy source is `RandomNumberGenerator` and deterministic configuration is rejected unless explicitly enabled.
11. Cancellation and EOF never become successful truncation. Unexpected EOF during a record or handshake is a fatal decode failure.
12. Unsupported algorithms and extensions are never silently substituted. Negotiated parameters must have been offered.
13. Ordinary application bytes are neither sent nor returned before both Finished messages authenticate the connection. The sole exception is explicitly configured TLS 1.3 0-RTT: construction requires replay-risk acknowledgement, a ticket must authorize the complete payload, early bytes are never returned by the client API, and rejected bytes are retransmitted only under an explicit caller policy.
14. When RFC 8449 is negotiated, protected handshake and application records are bounded independently in each direction. TLS 1.3 accounting includes the inner content type and zero padding; an authenticated peer overrun is fatal `record_overflow`. Unprotected records are not incorrectly constrained.
15. A delegated credential never bypasses normal X.509 chain or hostname validation. It is accepted only on the leaf entry with non-critical DelegationUsage, digitalSignature usage, bounded lifetime, an offered executable algorithm, a matching DER SPKI, and a valid leaf-key delegation signature; CertificateVerify is then checked only with that delegated key.
16. Experimental application settings are accepted only at the exact offered code point and for the selected advertised ALPN. Peer payloads are not exposed before peer Finished authenticates them; the client response is transcripted before client Finished. ALPS with 0-RTT is rejected until settings are ticket-bound.
17. All externally supplied collection options are snapshotted and validated before network I/O. `TlsClientCertificate` snapshots public chain bytes, serializes private-key operations, never exports private key material, and remains explicitly caller-owned for the clients that reference it.
18. TLS 1.3 tickets are origin/port/ALPN/hash bound, atomically removed when offered, lifetime- and authentication-age-capped, and zeroized on disposal. Resumption never bypasses a prior authenticated certificate handshake.
19. Client CertificateRequest contexts are connection-unique. Post-handshake authentication is accepted only when advertised, uses an independently forked initial-handshake transcript and the current application traffic secret, and sends each response block without interleaving.
20. ECH acceptance is derived only from the RFC 9849 confirmation bound to ClientHelloInner and the exact selected TLS transcript. On rejection, the public name is authenticated before any retry configuration is trusted; origin client credentials and negotiated application state are withheld, a protected `ech_required` alert is sent, and the connection is never exposed for application data.
21. An ECH HelloRetryRequest consumes the same HPKE context exactly once, carries an empty `enc`, preserves both ClientHello random/session-ID values, and is transcript-bound. HPKE authentication failure does not advance the sequence, contexts are single-owner disposable objects, and their keys/nonces/exporter secrets are zeroed.
22. GREASE ECH is never treated as a real encrypted offer. It uses a random configuration ID, a valid freshly generated X25519 encapsulated public key, a length-shaped random payload, and an executable plausible HPKE suite. HRR copies the complete value; server ECH responses are syntax-checked but retry configurations are neither trusted nor retained.
23. ECH outer-extension compression is accepted only for distinct non-sensitive references that are contiguous in ClientHelloInner, retain relative order in ClientHelloOuter, and encode identical bodies. The ECH marker and compression marker cannot be referenced. Reconstruction is a bounded forward scan so missing, duplicate, reordered, or amplification-oriented inputs fail closed.
24. RFC 9848 discovery completes before any ClientHello is emitted. DNS messages, decompressed names, records, alias depth, retries, timeouts, and cache entries are bounded. HTTPS/SVCB parameters are consumed exactly, malformed RRsets are rejected, origin SNI/certificate identity never changes to TargetName, and an all-ECH compatible endpoint set forbids direct fallback.
25. A DNS authenticated-data bit is never represented as local DNSSEC validation. Requiring it is an explicit trust assertion about the configured recursive resolver and the client-to-resolver channel. Transport/SERVFAIL fallback is disabled by default because it is downgradeable; enabling it is a caller policy decision.
26. A ticket learned through accepted ECH is reusable only for the same origin and exact `ECHConfigList` source. Its real identity and binder are encoded only in ClientHelloInner; ClientHelloOuter uses independently random length-matched GREASE fields. Outer PSK selection is fatal, early keys bind to Inner, and ECH rejection can never trigger private-data retransmission on the public-name connection.
27. Protected DNS requires explicit bootstrap IP endpoints and a separate authenticated resolver name. DoT/DoH never falls back to plaintext DNS; PKIX and hostname validation complete before DNS bytes are trusted. HTTP and DNS framing are bounded, and cached TTLs cannot exceed freshness remaining after HTTP `Age`/`max-age` processing.
28. Server resumption state is either stored in a bounded, zeroizing TLS 1.2 cache or authenticated by an AES-256-GCM ticket protector. Tickets are bound to protocol, suite/hash, SNI and ALPN as applicable; age, lifetime, binder and Finished authentication are verified before resumed application state is exposed.
29. QUIC-TLS adapters never process packet or stream data. CRYPTO bytes are independently bounded and overlap-checked at each encryption level; traffic-secret events are disposable. QUIC 0-RTT acceptance additionally requires an authenticated ticket, compatible remembered transport limits and a caller-supplied atomic anti-replay decision.
30. Server OCSP/SCT values and TLS 1.3 compressed certificates are emitted only after the client offered the corresponding extension. Certificate compression uses runtime Zlib/Brotli streams, authenticates the compressed wire message in the transcript, and retains strict compressed and declared-uncompressed size bounds.
31. Hybrid key establishment keeps the classical and KEM components in the exact construction-specific order. X25519MLKEM768 rejects non-canonical ML-KEM public keys and uses FIPS 203 implicit rejection on decapsulation; the obsolete X25519Kyber768Draft00 compatibility group applies its distinct Round-3 final transform and is never substituted for the standards-track group. Private seeds, polynomial state, raw component secrets and combined secrets are zeroized on every success and failure path. Managed FIPS 202/FIPS 203 code is vector-tested but is not represented as a FIPS-validated cryptographic module; an independent side-channel and cryptographic audit remains mandatory before 1.0.
32. An ECH server snapshots and validates every caller-owned HPKE key before network input, requires unique configuration IDs and a TLS-1.3-only policy, and treats initial HPKE authentication or inner reconstruction failure only as rejection so it does not expose a decryption oracle. Once an accepted ECH handshake enters HRR, a changed configuration, non-empty retry `enc`, authentication failure, outer identity change or malformed reconstructed Inner is fatal. Rejected Inner buffers, HPKE state and private key copies are zeroized.

## Reporting

Use GitHub private vulnerability reporting when it is enabled for the repository. If it
is unavailable, contact the maintainers through a private repository contact channel
before sharing details. Do not open a public issue for a suspected vulnerability.

Include the affected SharpTls version, runtime/platform, realistic impact, a minimal
reproducer and a redacted capture summary when possible. Do not include live secrets,
private keys, session tickets, decrypted traffic, customer hostnames or unredacted
captures. Maintainers will acknowledge a complete report privately, reproduce it, and
coordinate disclosure and a fixed release according to severity.
