# SharpTls

**Own the handshake. Shape every byte.**

SharpTls is a pure managed C# TLS stack for .NET 9+ with uTLS-style, byte-exact
`ClientHello` control. It implements TLS directly over caller-owned transports and
does not use `SslStream`, native TLS libraries, P/Invoke, proxies or external processes.

## Install

```shell
dotnet add package SharpTls --prerelease
```

## Minimal client

```csharp
using SharpTls;

var options = new CustomTlsClientOptions
{
    ServerName = "example.com",
    ClientHello = ClientHelloProfiles.Custom(builder => builder
        .WithTls13()
        .WithAlpn("http/1.1")),
};

await using var client = new CustomTlsClient(options);
await client.ConnectAsync("example.com", 443, cancellationToken);

await using var tls = client.OpenApplicationStream(leaveClientOpen: true);
await tls.WriteAsync(requestBytes, cancellationToken);
var bytesRead = await tls.ReadAsync(responseBuffer, cancellationToken);
```

## Included surface

- Exact semantic/raw extension layout, cipher suites, groups, key shares, signatures,
  versions, SNI, ALPN, GREASE, padding, session ID and record fragmentation.
- Forty pinned upstream uTLS wire IDs, coherent randomization, bounded origin-aware
  Roller, capture import, strict JSON v6 and defensive pre-send inspection.
- TLS 1.3 and a deliberately restricted TLS 1.2 client/server core.
- System chain and hostname validation by default, explicit lab-only trust bypass,
  configurable revocation-availability policy,
  RSA-PSS/ECDSA authentication, resumption,
  external PSK, replay-gated 0-RTT, KeyUpdate, exporters and client certificates.
- RFC 9849 ECH, RFC 9848 HTTPS/SVCB discovery, X25519MLKEM768, delegated credentials,
  certificate compression and recordless QUIC-TLS client/server adapters.

HTTP/2, HTTP/3, generic `HttpClient` integration and full QUIC transport are outside
the TLS library boundary.

> SharpTls is pre-1.0. Independent cryptographic review and hosted release evidence
> remain explicit 1.0 gates. Review the repository security policy and exact supported
> surface before production adoption.

The package contains the complete documentation set, security policy, changelog,
license and third-party notices. The package project URL points to the source repository
for current guides, examples and issue reporting.
