# Standard TLS server engine

`CustomTlsServer` is the standard, non-fingerprinting server half of SharpTls. It
implements TLS 1.3 and the documented secure TLS 1.2 subset directly over a connected
`Socket` or readable/writable `Stream`. It never calls `SslStream` or a native TLS stack.

The caller supplies exactly one static `TlsServerCertificate` or an asynchronous
`ServerCertificateSelector`. Credentials snapshot public certificate bytes but leave
caller-supplied private-key handles caller-owned. Selection receives defensive SNI,
ALPN and signature-algorithm values and can reject an unknown name by returning `null`.

```csharp
using var credential = new TlsServerCertificate(certificateWithPrivateKey, issuers);

await using var listener = new CustomTlsListener(
    new IPEndPoint(IPAddress.Any, 443),
    () => new CustomTlsServerOptions
    {
        ServerCertificate = credential,
        SupportedVersions =
        [
            TlsProtocolVersion.Tls13,
            TlsProtocolVersion.Tls12,
        ],
        AlpnProtocols = ["http/1.1"],
        RequireAlpn = true,
        CertificateCompressionAlgorithms =
        [
            TlsCertificateCompressionAlgorithm.Brotli,
            TlsCertificateCompressionAlgorithm.Zlib,
        ],
    });

listener.Start();
await using var connection = await listener.AcceptConnectionAsync(cancellationToken);
await using var stream = connection.AsStream(leaveServerOpen: true);
```

`CustomTlsListener` authenticates one accepted socket per call and returns an independent
connection object. The caller chooses its accept-loop concurrency and application
protocol dispatch. Disposing an owned listener stops accepts; a caller-owned listener
is left open when configured that way. Failed authentication disposes the accepted
socket and never returns a partially authenticated server.

## Authentication and certificate presentation

TLS 1.3 supports RSA-PSS and curve-matched ECDSA CertificateVerify. TLS 1.2 supports
the six advertised ECDHE_RSA/ECDHE_ECDSA AES-GCM/ChaCha20-Poly1305 suites, mandatory
extended master secret and secure-renegotiation signaling. Weak CBC, RC4, 3DES, static
RSA, SHA-1 authentication and renegotiation remain disabled even when an obsolete
ClientHello carries their wire identifiers.

`ClientAuthentication` can request or require an initial client certificate. The
configured trust policy validates the client chain; CertificateVerify is separately
authenticated. `PeerCertificateChain` returns defensive DER copies only after success.

`TlsServerCertificatePresentation` can attach stapled OCSP and legacy SCT values. They
are sent only when the ClientHello requested the corresponding extension. For TLS 1.3
they are leaf CertificateEntry extensions; for TLS 1.2 they use CertificateStatus and
the ServerHello SCT extension. Presence is not a claim that SharpTls generated or
validated the evidence—the server operator remains responsible for freshness and
cryptographic validity.

RFC 8879 certificate compression is opt-in and preference ordered. The server selects
only Zlib or Brotli values actually offered by the client, compresses the exact TLS 1.3
Certificate body, and otherwise sends an ordinary Certificate. Decompressed length,
compressed payload and handshake size remain bounded.

## Encrypted ClientHello

TLS 1.3 server policies may configure caller-owned `TlsEchServerKey` values through
`EncryptedClientHelloKeys`. Each key verifies that its raw HPKE private key matches the
public key in the exact RFC 9849 `ECHConfig`; configuration IDs must be unique. A direct
`CustomTlsServer` snapshots private key bytes during construction and zeroizes its copy on
disposal.

On acceptance, SNI, ALPN, groups, key shares, PSKs, client-authentication policy and the
transcript all come from the reconstructed ClientHelloInner. Direct and HRR handshakes emit
the required acceptance confirmation. On rejection, negotiation remains bound to Outer,
the public-name certificate must authenticate, and only configurations marked
`sendAsRetry` are returned in authenticated EncryptedExtensions. A GREASE ECH offer remains
an ordinary public-name connection and never becomes an accepted private-name connection.

ECH keys require `SupportedVersions = [TlsProtocolVersion.Tls13]`; SharpTls does not claim
a TLS 1.2 ClientHelloOuter server path. `EncryptedClientHelloOffered`,
`EncryptedClientHelloAccepted`, and `EncryptedClientHelloOuterServerName` expose the final
non-secret outcome.

## Sessions and long-lived connections

- TLS 1.3 resumption uses `Tls13ServerSessionTicketProtector`. State is protected with
  AES-256-GCM, bound to SNI/ALPN/hash, age checked, and compatible with key rotation.
- TLS 1.2 can use bounded `Tls12ServerSessionCache` session IDs, stateless
  `Tls12ServerSessionTicketProtector` RFC 5077 tickets, or both.
- Protector/cache objects are caller-owned and should be shared by connections that
  must resume one another. Disposing a connection does not dispose them.
- `IssueSessionTicketAsync` emits a fresh TLS 1.3 ticket after authentication;
  automatic ticket count is bounded. TLS 1.2 renewals occur in the version-specific
  handshake flow.
- `RequestKeyUpdateAsync` and automatic key-usage rotation apply to TLS 1.3. TLS 1.2
  reconnects before AEAD limits. `ExportKeyingMaterial` supports both versions.

The TCP server does not accept replayable TLS 0-RTT. Replay-gated early-data secrets are
available on the recordless QUIC-TLS server, where the surrounding transport can enforce
remembered packet/stream limits and an atomic replay policy.

All reads and writes are cancellation-aware. One reader and one writer may operate
concurrently; same-direction operations are serialized. Application data is unavailable
until Finished authentication succeeds, fatal alerts fail the connection, abrupt EOF is
truncation, and authenticated `close_notify` is the only clean peer EOF.

The deterministic suite exercises both SharpTls roles against each other and uses the
platform TLS stack as an independent peer. A platform `SslStream` client connects to the
SharpTls TLS 1.2 and TLS 1.3 server on Linux and Windows CI and exchanges authenticated
application traffic. .NET 9's Apple TLS client provider exposes neither the required TLS
1.3 path nor a TLS 1.2 ClientHello containing both mandatory EMS and secure-renegotiation
signals, so those two client-role rows are discovery-time skipped on macOS rather than
weakening the server policy. A platform TLS 1.2 server remains covered on macOS.
