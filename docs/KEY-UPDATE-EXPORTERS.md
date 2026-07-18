# TLS 1.3 KeyUpdate and exporters

SharpTls keeps the application traffic-secret ratchets alive after the handshake and
implements both directions of RFC 9846 `KeyUpdate`.

```csharp
await client.RequestKeyUpdateAsync(
    requestPeerUpdate: true,
    cancellationToken);

var binding = client.ExportKeyingMaterial(
    "EXPORTER-my-protocol",
    contextBytes,
    32);
try
{
    // Bind the upper-layer protocol to this authenticated TLS connection.
}
finally
{
    CryptographicOperations.ZeroMemory(binding);
}
```

An outgoing KeyUpdate is authenticated under the current client application key and
the sending secret is ratcheted only after the complete message is written. An
authenticated incoming update ratchets the server receiving secret before the next
record. `update_requested` receives an `update_not_requested` response under the
correct current client key unless the sender epoch has reached RFC 9846's `2^48-1`
limit, in which case the request flag is ignored as required. Key changes are
record-boundary aligned; malformed
values, coalesced post-update bytes, and invalid state transitions fail closed.

The record layer reserves capacity for a KeyUpdate and automatically rotates the
client secret before its conservative AEAD usage limit would be exhausted. Public
`ClientKeyUpdateCount` and `ServerKeyUpdateCount` 64-bit counters expose completed ratchets
without exposing traffic secrets.

Repeated peer `request_update` messages received while the client has not emitted
application data are coalesced into one response before its next application record.
After sending `request_update=1`, the client rejects another requested update until an
authenticated peer KeyUpdate arrives. These rules prevent update loops while retaining
the RFC sender-epoch limit; the receiver does not impose that sender-only cap on a peer.

`ExportKeyingMaterial` implements RFC 9846 section 7.5 with the normal
`exporter_secret`; no early exporter is exposed. Labels must be printable ASCII,
must fit the HKDF label encoding, and cannot use the RFC 5705 reserved labels. The
returned bytes are sensitive and caller-owned. Exporter output is connection-bound
and intentionally remains stable across application traffic-key updates.

Client authentication is implemented separately and documented in
[Client authentication](CLIENT-AUTHENTICATION.md); exporter output never exposes its
private key or mutable traffic-secret state.
