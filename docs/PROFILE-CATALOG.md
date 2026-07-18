# Versioned capture-backed profile catalog

Browser and application profile names are evidence records, not timeless aliases.
`ClientHelloProfileManifest.Import` turns one reviewed capture into immutable
provenance plus an executable `ClientHelloSpec`:

```csharp
var manifest = ClientHelloProfileManifest.Import(
    id: "example-client/123.4",
    family: "example-client",
    version: "123.4",
    capturedAt: DateTimeOffset.Parse("2026-07-17T12:00:00Z"),
    sourceCapture: capturedClientHello);

var catalog = new ClientHelloProfileCatalog();
catalog.Register(manifest);

var profile = catalog.GetRequired("example-client/123.4").CreateProfile();
```

The manifest stores the stable identifier, explicit family/version, capture time,
source framing, captured SNI provenance, source SHA-256, normalized immutable spec,
and its ALPN application-layer dependencies. It does not retain the source capture,
ClientHello random, public/private key shares, or other ephemeral wire bytes. Input
is snapshotted under the capture size bound while it is parsed and hashed, then the
temporary buffer is zeroed.

The catalog is thread-safe, rejects duplicate exact identifiers, and returns sorted
snapshots. Built-in family `Auto` properties are version-bound aliases to the newest
executable pinned profile shipped by the installed SharpTls package; they never inspect
the local browser and change only in a package release. Current browser captures can
require features such as hybrid ML-KEM, PSK/resumption,
RFC 9849 ECH, or TLS algorithms outside the restricted executable subset. These are not
all executable in SharpTls yet. A branded manifest enters the shipped catalog
only with reviewed capture provenance, a fully executable semantic path, masked
wire snapshots, application-protocol checks, and public interoperability evidence.
