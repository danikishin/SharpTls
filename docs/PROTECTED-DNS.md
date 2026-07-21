# Authenticated DNS-over-TLS and DNS-over-HTTPS

`TlsEchDnsResolver` can obtain RFC 9848 HTTPS records over plaintext DNS,
authenticated DNS-over-TLS (DoT), or authenticated DNS-over-HTTPS (DoH). Protected
transports are implemented with SharpTls itself: they do not call `SslStream`, an HTTP
stack, a native TLS provider, or another DNS/TLS implementation.

## Security model

The resolver authentication name and bootstrap IP addresses are deliberately separate.
SharpTls connects only to caller-supplied IP endpoints, sends the resolver name as SNI,
and requires PKIX plus hostname validation before accepting DNS bytes. This avoids using
plaintext recursive DNS to locate the protected resolver. Selecting DoT or DoH never
falls back to port 53. `AllowDirectFallbackOnDnsError` governs the later origin/ECH policy;
it does not downgrade the resolver transport.

System trust is the default. `CertificateValidation` supports the same revocation and
custom-root policy as an ordinary `CustomTlsClient`. Online revocation is attempted by
default, while unavailable evidence soft-fails unless `AllowUnknownRevocationStatus` is
disabled. A bootstrap environment that disables certificate downloads or revocation
lookups should supply a deliberate policy, because performing those lookups can otherwise
create another name-resolution dependency.

The shared `DangerouslySkipServerCertificateValidation` option is also available for
controlled tests, but enabling it removes resolver authentication and therefore violates
the strict DoT/DoH security model described here. It is never enabled implicitly.

## DNS-over-TLS

RFC 7858 uses TCP port 853, completes TLS before sending DNS, and frames every DNS message
with a two-octet length. RFC 8310 strict privacy requires an authenticated encrypted channel
and forbids opportunistic plaintext fallback. By default SharpTls enforces TLS 1.3,
semantic SNI, no ALPN, strict certificate validation, partial-read handling, and the
configured DNS message bound.

```csharp
var resolver = new TlsEchDnsResolver(new TlsEchDnsResolverOptions
{
    DnsOverTls = new TlsEchDnsOverTlsOptions
    {
        ResolverName = "dns.google",
        BootstrapEndpoints =
        [
            new IPEndPoint(IPAddress.Parse("8.8.8.8"), 853),
            new IPEndPoint(IPAddress.Parse("2001:4860:4860::8888"), 853),
        ],
    },
    SupportedAlpnProtocols = ["http/1.1"],
});
```

## DNS-over-HTTPS

The current DoH transport implements RFC 8484 POST over managed HTTP/1.1. It sends and
requires `application/dns-message`, uses DNS transaction ID zero for HTTP cache sharing,
authenticates the URI host, and accepts bounded Content-Length, chunked, or close-delimited
2xx responses. Conflicting lengths, unsupported transfer codings, header folding, invalid
media types, control bytes, oversized headers/bodies, and malformed chunks fail closed.

HTTP `Age` is subtracted from DNS TTLs. When a valid `Cache-Control: max-age` is present,
the remaining HTTP freshness lifetime also caps every DNS TTL. This prevents a shared HTTP
cache from extending an already-aged DNS answer.

```csharp
var resolver = new TlsEchDnsResolver(new TlsEchDnsResolverOptions
{
    DnsOverHttps = new TlsEchDnsOverHttpsOptions
    {
        Endpoint = new Uri("https://cloudflare-dns.com/dns-query"),
        BootstrapEndpoints =
        [
            new IPEndPoint(IPAddress.Parse("1.1.1.1"), 443),
            new IPEndPoint(IPAddress.Parse("2606:4700:4700::1111"), 443),
        ],
    },
    SupportedAlpnProtocols = ["http/1.1"],
});
```

DoH currently creates one authenticated HTTP/1.1 connection per query. HTTP/2,
connection pooling, resolver discovery, Oblivious DoH, and a recursive DNSSEC validator
are optional resolver-layer work, not SharpTls core parity gates, and are not claimed.

## Bounds and verification

All transport attempts share the resolver's per-endpoint timeout and cancellation token.
DNS messages, HTTP headers, framing lines, chunks, trailers, records, aliases, and cache
entries are bounded before allocation or accumulation. Deterministic loopback tests use a
real managed SharpTls server for both DoT and DoH, fragment frames down to individual bytes,
and cover hostile HTTP framing. Opt-in public tests authenticate Google DoT and Cloudflare
DoH, then use the returned Cloudflare HTTPS record to complete an accepted public ECH
handshake for a private origin name.

Normative references: RFC 7858 §§3.2–3.4, RFC 8310 §§3–5, RFC 8484 §§4–5, RFC 9460,
and RFC 9848.
