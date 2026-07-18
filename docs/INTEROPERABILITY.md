# Interoperability and packet-capture procedure

Public-network tests are opt-in so the normal test suite remains deterministic and
does not depend on DNS, Internet reachability, or a third-party endpoint.

Run the complete public-server matrix with:

```shell
SHARPTLS_RUN_INTEROP=1 dotnet test SharpTls.slnx \
  --filter 'Category=Interop' --logger 'console;verbosity=normal'
```

The matrix exercises a complete authenticated handshake, client Finished,
encrypted HTTP/1.1 request, authenticated response data, and `close_notify` for:

| Cipher suite | Key exchange | Path |
|---|---|---|
| TLS_AES_128_GCM_SHA256 | P-256 | Direct ServerHello |
| TLS_AES_256_GCM_SHA384 | P-384 | Direct ServerHello |
| TLS_AES_128_GCM_SHA256 | P-521 | Direct ServerHello |
| TLS_CHACHA20_POLY1305_SHA256 | P-256 | Direct ServerHello |
| TLS_AES_128_GCM_SHA256 | P-256 | Forced HelloRetryRequest via an empty initial key_share |
| Server-selected TLS 1.3 suite | Server-selected group | HTTP/1.1 ALPN against `www.google.com` |
| Android 11 OkHttp TLS 1.2 profile | X25519/ECDHE AEAD | Authenticated HTTP/1.1 application traffic |
| TLS 1.3 `psk_dhe_ke` | Server-selected group | Ticket resumption at `example.com` and `www.google.com` |
| TLS 1.3 `psk_dhe_ke` | P-256 HRR | Ticket resumption with a recomputed second-ClientHello binder |
| Pinned Chrome 96/100, Firefox 102/105, iOS 13 profiles | X25519/P-256 | Authenticated TLS 1.3 public-server handshakes |

The current profile qualification additionally runs every one of the 39 securely
executable pinned profiles against both `example.com` and `www.cloudflare.com`, checking
that the authenticated version and cipher suite were offered by the exact profile. The
40th wire ID, 360/7.5, is covered by deterministic full-wire tests but intentionally
fails connection-policy validation before I/O because its historical capture omits
Extended Master Secret. It is not counted as an executable secure TLS 1.2 profile.

This matrix, including the additional pinned profile corpus, passed against the
documented endpoints on 2026-07-17. Public endpoints are
smoke-test evidence, not a permanent conformance oracle. Normal deterministic CI keeps
these tests disabled; the commit-pinned weekly, manual-dispatch and release-tag job sets
the environment variable explicitly and archives its hosted result.

Accepted and rejected 0-RTT are covered deterministically by the managed loopback
peer in `Tls13EarlyDataLoopbackTests`; it verifies the binder, early records,
`EndOfEarlyData`, both Finished values, and explicit 1-RTT retransmission. A public
0-RTT smoke test is additionally available only when the operator supplies a server
that currently advertises early data:

```shell
SHARPTLS_RUN_INTEROP=1 \
SHARPTLS_EARLY_DATA_HOST=early-data.example \
dotnet test SharpTls.slnx \
  --filter 'FullyQualifiedName~ReplayAcknowledgedEarlyHttpRequestIsAccepted'
```

There is deliberately no default public 0-RTT endpoint: deployment policy changes
frequently, and most well-configured public sites disable replayable early data.

`RecordSizeLimitInteropTests` uses a fully managed authenticated TLS 1.3 peer to
negotiate asymmetric 128/64-byte limits. It verifies fragmentation of certificate
handshake traffic and application data, then separately sends a validly authenticated
oversized record and requires the client to fail with `record_overflow`.

`DelegatedCredentialInteropTests` uses an RSA certificate carrying DelegationUsage with
both P-256 and constrained RSA-PSS delegated keys. The peer completes CertificateVerify
and application traffic with each delegated key. The hostile variant corrupts the
delegation signature and observes the client's fatal `illegal_parameter` alert over the
encrypted handshake keys. The reverse-role cases issue the client a P-256 delegated
credential, advertise it through CertificateRequest, verify its client-context delegation
signature and delegated CertificateVerify, and complete both initial and post-handshake
client authentication over managed TLS records.

`RsaPssInteropTests` uses an end-entity certificate whose SubjectPublicKeyInfo OID is
RSASSA-PSS with SHA-256/MGF1/salt constraints. The managed peer signs CertificateVerify
with `rsa_pss_pss_sha256`; the client validates its chain and constrained key, completes
both Finished messages, sends an RSAE client certificate, and exchanges application data.

`ApplicationSettingsInteropTests` runs both experimental uTLS code points against a
managed authenticated TLS 1.3 peer. It verifies ClientHello offer parsing, ALPN binding,
encrypted server settings, client EncryptedExtensions, transcript-dependent Finished,
mutual certificate authentication, and application traffic. Parser tests separately
cover wrong code points, missing/ineligible ALPN, duplicates, and early-data conflicts.

`CertificateEvidenceInteropTests` sends leaf CertificateEntry OCSP and SCT values from
the managed TLS 1.3 peer. It verifies that the additional async policy runs only after
system trust/hostname validation, receives defensive copies, gates application traffic,
and that an invalid staple produces the dedicated protected
`bad_certificate_status_response` fatal alert.

`EchInteropTests` uses a fully managed RFC 9849 TLS 1.3 peer. The acceptance path
decrypts ClientHelloInner with an RFC 9180 receiver context, verifies that the inner
key share and transcript drive the handshake, authenticates the private name, and
round-trips application data. The rejection path authenticates only `public_name`,
returns a retry `ECHConfigList`, requires an empty client-certificate response, and
observes the protected `ech_required` alert; no rejected application transport is
published. The HRR path reuses the HPKE context with an empty second `enc`, switches to
P-384, verifies post-HRR acceptance and both Finished values, and exchanges application
data. A GREASE-only path validates and ignores retry configurations while completing a
normal public-name handshake. Resumption paths verify an automatically issued,
ECHConfigList-bound ticket, Inner-only binder authentication, length-matched Outer GREASE
identity/binder fields, accepted 0-RTT using the Inner transcript, HRR binder recomputation,
fatal outer-PSK selection, and rejection without private-data retransmission. The opt-in
public matrix additionally bootstraps `crypto.cloudflare.com` through authenticated
Cloudflare DoH, verifies the advertised `cloudflare-ech.com` public name differs from the
origin, and completes an accepted ECH TLS 1.3 handshake against an advertised IP hint.
Both accepted paths enable `ech_outer_extensions`; the peer performs a single forward
scan over ClientHelloOuter, reconstructs the true inner extensions, and then verifies
that reconstructed key exchange, certificate authentication, transcript, and traffic.

RFC 9848 bootstrap has deterministic coverage in `DnsWireTests`,
`TlsEchDnsResolverTests`, and `DnsTransportTests`. These suites include the RFC 9460
Appendix D Figure 9 wire vector, exact ECHConfigList SvcParam parsing, unknown mandatory
keys, ALPN/default-ALPN compatibility, AliasMode selection/loops/final-QNAME fallback,
ECH-reliant and mixed deployments, TTL cache expiry, hostile compression pointers and
lengths, DNS error policy, and a real loopback UDP-truncated-to-fragmented-TCP exchange.
`ProtectedDnsTransportTests` adds authenticated managed DoT and DoH loopback peers,
one-byte fragmentation, chunked trailers, cancellation, size bounds, and hostile HTTP
framing. Opt-in tests authenticate Google DoT and Cloudflare DoH. Public services remain
smoke-test evidence rather than a stable deterministic conformance oracle.

Client authentication has deterministic end-to-end coverage in
`ClientCertificateInteropTests`: a managed TLS 1.3 peer verifies the client chain,
RSA-PSS CertificateVerify, handshake Finished, PHA application-secret Finished,
empty-certificate fallback and fatal negative paths. A platform TLS 1.2 server verifies
mutual authentication and application traffic. These test peers are validation
harnesses only; the SharpTls library itself never delegates TLS processing to them.

## Capturing the wire image

Captures are an operator action, not a library dependency. SharpTls never starts
`tcpdump`, Wireshark, a proxy, or another TLS implementation. On macOS, for
example, start a capture in a separate privileged terminal:

```shell
sudo tcpdump -i any -s 0 -w captures/sharptls.pcapng 'tcp port 443'
```

Then run either the sample or the opt-in matrix and stop the capture. Useful
Wireshark display filters are:

```text
tls.handshake.type == 1
tls.handshake.type == 2
tls.record.content_type == 23
```

The plaintext ClientHello can be checked for exact cipher-suite, extension,
supported-group, signature-scheme, key-share, ALPN, SNI, GREASE, padding, session
ID, and record-fragment ordering. Deterministic ClientHello snapshots should be
generated only through `BuildDeterministicForTesting`; its fixed test keys and
entropy must never be placed on a network.

SharpTls has an explicitly acknowledged, caller-owned NSS key-log sink for controlled
diagnostics. It is disabled by default and never writes files itself. Without that sink,
captures verify only visible ClientHello and record behavior; with it, the caller is
responsible for protecting and deleting the exported live traffic secrets.
