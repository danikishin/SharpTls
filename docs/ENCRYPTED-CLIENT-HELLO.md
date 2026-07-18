# Encrypted ClientHello

SharpTls implements RFC 9849 Encrypted ClientHello for TLS 1.3 clients, the standard
TCP server, and both recordless QUIC-TLS roles. This is real HPKE-protected ECH, not a
cosmetic extension or a fake-success mode. A client supplies a network-encoded
`ECHConfigList`; SharpTls selects the first executable configuration and cipher suite
in wire preference order. A server supplies caller-owned decryption keys whose public
configurations are validated against their private keys before any connection starts.

## Supported path

- strict, bounded current-version `ECHConfigList` parsing, including unknown-version
  skipping, duplicate rejection, mandatory-extension filtering, public-name validation,
  and defensive snapshots;
- DHKEM(X25519, HKDF-SHA256), DHKEM(P-256, HKDF-SHA256),
  DHKEM(P-384, HKDF-SHA384), and DHKEM(P-521, HKDF-SHA512), with HPKE
  HKDF-SHA256/SHA384/SHA512 and AES-128-GCM, AES-256-GCM, or ChaCha20-Poly1305
  when the runtime supports it. NIST point operations and validation use the runtime ECDH
  provider; RFC 9180 deterministic key derivation preserves byte-repeatable test mode;
- separate immutable ClientHelloInner and ClientHelloOuter profiles with exact extension
  ordering; SNI in the outer hello is replaced by the selected `public_name`;
- RFC 9849 inner encoding, zero padding, outer AAD construction, secure ephemeral entropy,
  and one same-context HelloRetryRequest retry with an empty second `enc`;
- optional bounded `ech_outer_extensions` compression with caller-selected types,
  pre-network order/value checks, exact true-inner transcript preservation, and linear
  reconstruction semantics;
- initial ServerHello, HRR, and post-HRR acceptance confirmation with the selected TLS
  cipher-suite hash, synthetic `message_hash` where required, and fixed-time comparison;
- private-name certificate authentication on acceptance and public-name authentication on
  rejection;
- source-bound TLS 1.3 resumption and replay-aware 0-RTT: real PSK identities/binders remain
  only in ClientHelloInner, ClientHelloOuter carries length-matched GREASE PSK fields,
  early traffic keys bind to the inner transcript, and HRR recomputes only the inner binder;
- authenticated retry configurations from EncryptedExtensions. Rejection sends a protected
  fatal `ech_required` alert and throws `TlsEchRejectedException`; application data, ALPN,
  ALPS state, client identity, and traffic keys are not exposed.
- standard TCP and recordless QUIC server reception with strict outer framing, HPKE opening,
  zero-padding checks, `ech_outer_extensions` reconstruction, TLS-1.3-only inner validation,
  private SNI/ALPN/key-share/PSK negotiation, direct and HRR acceptance confirmation, and
  authenticated retry-configuration emission on rejection;
- recordless QUIC client/server ECH with source-bound resumption and replay-gated 0-RTT.
  Real identities and binders remain in Inner and both roles derive early secrets from the
  authenticated Inner transcript;
- RFC 9848 HTTPS-record bootstrap over a bounded RFC 9460 resolver: IDNA origin names,
  EDNS(0), UDP with TCP truncation fallback, CNAME/AliasMode traversal and loop limits,
  ServiceMode priority/shuffle, mandatory-key and ALPN compatibility, exact `ech`
  `ECHConfigList` values, IP hints, TTL/LRU caching, and ECH-reliant fallback policy.

The HPKE sender and receiver are covered by RFC 9180 published X25519, P-256, and P-521
vectors plus a P-384 deterministic sender/receiver round trip. Managed end-to-end tests cover
accepted and rejected ECH, certificate identity selection, transcript/key-share selection,
mutual-auth privacy, retry-config authentication, alerts, HRR context reuse, and application
traffic. Acceptance calculations also have fixed independent vectors.

## Usage

Resolve HTTPS records before constructing or sending any ClientHello. The endpoint retains the
origin as SNI/certificate identity while exposing the alternative TCP target and port:

```csharp
var resolver = new TlsEchDnsResolver(new TlsEchDnsResolverOptions
{
    SupportedAlpnProtocols = ["http/1.1"],
    // RequireAuthenticatedData is meaningful only with a trusted validating resolver.
});
var resolution = await resolver.ResolveAsync("private.example", 443, cancellationToken);
var endpoint = resolution.Endpoints[0];

var options = new CustomTlsClientOptions
{
    ClientHello = ClientHelloProfiles.Custom(builder => builder
        .WithTls13()
        .WithAlpn("http/1.1")),
};
endpoint.ConfigureClient(options);

await using var client = new CustomTlsClient(options);
await client.ConnectAsync(endpoint.TargetName, endpoint.Port, cancellationToken);
```

`FallbackPolicy == EchRequired` means every compatible alternative endpoint carried `ech`;
the caller must not attempt the origin or another non-ECH endpoint if those attempts fail.
Mixed ECH/non-ECH RRsets are exposed through `IsMixedEchDeployment` and retain the legitimate
direct alternatives. Equal-priority records and IP hints are securely shuffled. If AliasMode
was processed, RFC 9460's final-QNAME endpoint is appended only for SVCB-optional results.
Malformed SVCB RRs reject the complete RRset and use non-SVCB fallback as RFC 9460 requires;
transport, timeout, and SERVFAIL errors fail closed by default. The latter fallback requires
explicit `AllowDirectFallbackOnDnsError = true`.

The resolver's AD-bit requirement does not perform DNSSEC validation itself. It is only an
assertion about a trusted recursive resolver and its channel. The caller may select plaintext
UDP/TCP, authenticated DoT, or authenticated DoH; protected modes require explicit bootstrap
IPs and never downgrade to plaintext DNS.

An application that obtains the encoded configuration through another authenticated channel
can parse and pass it explicitly:

```csharp
var echConfigList = TlsEchConfigList.Parse(encodedEchConfigList);

var options = new CustomTlsClientOptions
{
    ServerName = "private.example",
    ClientHello = ClientHelloProfiles.Custom(builder => builder
        .WithTls13()
        .WithAlpn("http/1.1")),
    EncryptedClientHello = new TlsEchOptions
    {
        ConfigList = echConfigList,
        CompressedOuterExtensions =
        [
            TlsExtensionType.SupportedGroups,
            TlsExtensionType.SignatureAlgorithms,
        ],
        OuterClientHello = ClientHelloProfiles.Custom(builder => builder
            .WithTls13()
            .WithAlpn("http/1.1")),
    },
};

await using var client = new CustomTlsClient(options);
try
{
    await client.ConnectAsync("private.example", 443, cancellationToken);
}
catch (TlsEchRejectedException rejection) when (rejection.RetryConfigurations is not null)
{
    // Policy decision: create a completely fresh client/connection using the authenticated
    // retry list. SharpTls never silently retries an origin connection after ECH rejection.
    var retryList = rejection.RetryConfigurations;
}
```

To receive ECH, construct a key from the exact public configuration and its matching raw
HPKE private key. The key remains caller-owned; `CustomTlsServer` snapshots and later
zeroizes its own copy. Listener factories that create more servers must keep the key alive
until their final options snapshot:

```csharp
var configList = TlsEchConfigList.Parse(encodedEchConfigList);
using var echKey = new TlsEchServerKey(
    configList.Configurations[0],
    rawHpkePrivateKey,
    sendAsRetry: true);

await using var server = new CustomTlsServer(new CustomTlsServerOptions
{
    SupportedVersions = [TlsProtocolVersion.Tls13],
    ServerCertificate = privateNameCredential,
    EncryptedClientHelloKeys = [echKey],
});
```

Configuration IDs must be unique within a server policy. `sendAsRetry` includes that
configuration in the authenticated retry list after rejection. The deployed certificate
selector must also be able to authenticate the public name on the rejection path; otherwise
the client correctly fails public-name authentication and never trusts the retry list.

`CustomTlsQuicClientOptions.EncryptedClientHello` and
`CustomTlsQuicClientOptions.EncryptedClientHelloGrease` use the same client policy.
`CustomTlsQuicServerOptions.Tls.EncryptedClientHelloKeys` uses the same server keys.
The surrounding QUIC transport still owns packets, Retry, recovery and application streams.

Both profiles must currently be TLS-1.3-only, contain semantic SNI slots, and have compatible
supported groups. Origin-sensitive extensions belong only in ClientHelloInner. The outer
profile must not contain ALPS/application_settings because a rejected connection cannot expose
origin application state. When a session cache is configured, both profiles must contain
semantic `psk_dhe_ke`, conditional `early_data`, and final `pre_shared_key` slots; the outer
slot is populated only with RFC 9849 GREASE data.
Compressed types must be consecutive in the actual inner profile, have the same relative
order in the outer profile, and produce byte-identical bodies. SNI and both ECH control
extensions are forbidden. Runtime-generated values such as independent key shares therefore
cannot be compressed unless a future profile mechanism can prove exact equality.

When no authenticated configuration is available, GREASE ECH can exercise the network path
without changing the connection identity or claiming privacy:

```csharp
var options = new CustomTlsClientOptions
{
    ServerName = "public.example",
    EncryptedClientHelloGrease = new TlsEchGreaseOptions(),
};
```

Each connection chooses an executable plausible HPKE suite with secure randomness, creates a
random config ID and valid X25519 encapsulated public key, and fills a payload sized like a
padded inner hello plus the AEAD expansion. A second ClientHello copies the complete extension.
ECH extensions returned by the server are syntax-checked and ignored; retry configurations are
not saved. GREASE ECH remains eligible for ordinary TLS 1.3 resumption because it is not a real
ECH offer.

## Explicit limits

- RFC 9848 discovery is a separate pre-handshake component; the TLS layer never performs hidden
  DNS or fallback. The resolver supports plaintext UDP/TCP plus strict authenticated DoT and
  DoH/HTTP-1.1, but does not implement a recursive DNSSEC validator, A/AAAA resolution, or
  Happy Eyeballs. IP hints remain non-authoritative endpoint metadata.
- ECH resumption state is deliberately limited to the exact encoded `ECHConfigList` source.
  A refreshed or authenticated retry list does not consume tickets from the previous source.
- Rejection retry is deliberately caller-controlled and always uses a fresh connection. There
  is no automatic retry loop or silent fallback to a private-name plaintext ClientHello.
- NIST HPKE configurations are executable only when the runtime ECDH provider exposes the
  corresponding curve. Unsupported configurations remain in the parsed list but are skipped
  without changing wire preference among executable entries. TLS key exchange remains
  independently configurable.
- TLS 1.2 ClientHelloOuter is not claimed. Public accepted-ECH interoperability is covered by
  an opt-in Cloudflare handshake after authenticated DoH bootstrap.
- ECH server keys require a TLS-1.3-only server policy. The standard TCP server deliberately
  does not accept replayable 0-RTT; ECH 0-RTT is available only through the recordless QUIC
  adapter with its mandatory anti-replay callback and remembered transport-limit checks.
- ECH does not make IP addresses, record sizes/timing, the selected public name, or later
  application traffic metadata private.

These limits keep the public API fail-closed without expanding the TLS library into an HTTP
or full QUIC transport stack.
The resolver architecture and normative section mapping are detailed in
[RFC 9848 ECH DNS bootstrap](ECH-DNS-BOOTSTRAP.md).
