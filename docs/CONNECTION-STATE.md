# Redacted connection state

After an authenticated handshake, `CustomTlsClient.GetConnectionState()` returns an
immutable snapshot of TLS-visible connection results:

```csharp
TlsConnectionState state = client.GetConnectionState();
Console.WriteLine($"{state.ProtocolVersion} {state.CipherSuite} {state.ApplicationProtocol}");
Console.WriteLine($"ECH accepted: {state.EncryptedClientHelloAccepted}");
```

The snapshot includes the authenticated reference identity, version, suite, ECDHE
group, ALPN, HelloRetryRequest, ticket resumption/external-PSK selection and early-data outcomes, real/GREASE ECH,
ALPS/application settings, record limits, delegated-credential result, key-update and
post-handshake-authentication counters, DER certificate-chain copies, stapled OCSP,
SCT encodings, TLS 1.2 `tls-unique` channel binding, and close state. `TlsUnique` is
null for TLS 1.3 because RFC 5929 does not define that binding for TLS 1.3. TLS 1.3 CertificateEntry OCSP/SCT values and TLS 1.2
CertificateStatus/ServerHello values are retained only after their containing handshake
messages pass strict framing and the complete handshake authenticates.

Every byte-array property returns a defensive copy. A snapshot does not change when the
live connection later receives a KeyUpdate or closes; call `GetConnectionState()` again
for a newer view. Calling it before handshake completion throws.

The API deliberately contains no PSK, traffic secret, private key, exporter secret,
transcript state, record sequence number, nonce, or mutable cipher object.

## Redacted handshake events

`CustomTlsClientOptions.HandshakeEventObserver` receives a serialized sequence of
immutable `TlsHandshakeEvent` values for ClientHello/HRR, authenticated server-flight
messages, client Finished, handshake completion and supported post-handshake messages.
Events contain only a per-connection sequence number, classification, direction,
active version, encoded length and (for ClientHello) flight identity. They never copy
message bytes, randoms, key shares, certificate contents, transcript hashes or secrets.

The observer runs synchronously at the relevant state boundary. Its exception aborts
the handshake; a ClientHello-event exception occurs before any ClientHello bytes are
written. Callbacks are serialized and explicit re-entry is rejected. Keep observers
fast and move expensive telemetry processing to a separate bounded application queue.

## Explicitly dangerous NSS key logging

Packet decryption is available only through a separately constructed
`TlsNssKeyLogSink`. Its constructor requires `acknowledgeSecretExposure: true`, and the
secure default in `CustomTlsClientOptions.DangerousNssKeyLog` is null:

```csharp
await using var file = File.Create("sslkeys.log");
await using var keyLog = new TlsNssKeyLogSink(
    file,
    acknowledgeSecretExposure: true,
    leaveOpen: false);

var options = new CustomTlsClientOptions
{
    ServerName = "example.com",
    DangerousNssKeyLog = keyLog,
};
```

TLS 1.3 emits client/server handshake traffic secrets, traffic secret 0 and the
exporter secret; 0-RTT also emits the client early traffic secret. TLS 1.2 emits the
standard `CLIENT_RANDOM` master-secret line. Each line is serialized for shared sinks,
flushed for packet analyzers, and assembled in a temporary byte buffer that is zeroized
after writing. The sink is caller-owned so several clients may share it safely.

Anyone who obtains this log can decrypt captured traffic. Never enable it in ordinary
production, telemetry, crash reports, or application logs. Delete it securely after
the debugging session. The redacted event API and dangerous key-log API are deliberately
separate; enabling one never enables the other.
