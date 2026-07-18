# Caller-owned transports and application streams

SharpTls can either create its own TCP socket with `ConnectAsync`, or authenticate an
already-connected readable/writable `Stream`. The latter keeps TCP establishment,
binding and transport composition under caller control without delegating TLS.

```csharp
using var socket = new Socket(SocketType.Stream, ProtocolType.Tcp);
await socket.ConnectAsync("example.com", 443, cancellationToken);
await using var network = new NetworkStream(socket, ownsSocket: false);

await using var client = new CustomTlsClient(options);
await client.AuthenticateAsync(
    network,
    referenceIdentity: "example.com",
    leaveOpen: true,
    cancellationToken);

await using var tls = client.OpenApplicationStream(leaveClientOpen: true);
await tls.WriteAsync(request, cancellationToken);
var read = await tls.ReadAsync(buffer, cancellationToken);
```

`referenceIdentity` is used for certificate hostname validation and SNI unless
`CustomTlsClientOptions.ServerName` supplies the explicit identity. A client instance
can connect or authenticate only once.

## Ownership

- `ConnectAsync` owns and closes the socket it creates.
- `AuthenticateAsync(..., leaveOpen: false)` owns and disposes the supplied stream.
- `leaveOpen: true` removes the transport from SharpTls without disposing it after a
  close or failed handshake. Consumed TLS bytes still make it unsuitable for reuse as
  a fresh protocol stream.
- `OpenApplicationStream(leaveClientOpen: false)` makes stream disposal close and
  dispose the TLS client. Set it to true when the client has a separate owner.

Only one `CustomTlsStream` can be opened per connection because it owns the plaintext
read buffer. The underlying `CustomTlsClient` continues to enforce serialized reads
and serialized writes while permitting one read and one write concurrently.

## Stream behavior

`CustomTlsStream` is non-seekable. It removes TLS record boundaries: a caller can read
one byte or a large buffer, and unread plaintext from the current authenticated record
is retained for the next call. A zero return means authenticated `close_notify`; an
abrupt transport EOF remains a TLS truncation error. Writes are fully consumed or
throw and are fragmented according to `ApplicationDataFragmentation`.

Buffered plaintext is cleared after consumption or disposal. Cancellation is passed
to the active network operation and never converted into EOF or successful shutdown.
