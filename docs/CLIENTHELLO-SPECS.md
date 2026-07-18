# ClientHello specifications and opaque extensions

`ClientHelloSpec` is an immutable, transport-independent offer. It contains ordered
cipher suites, groups, signature schemes, ALPN values, session-ID policy and a single
ordered extension layout. Connection random and ephemeral private keys are never
stored in a specification; they are generated afresh when an executable profile
builds a connection.

Create a reusable specification and profile with:

```csharp
var spec = new ClientHelloBuilder()
    .WithTls13()
    .WithAlpn("h2", "http/1.1")
    .WithExtensionLayout(
        ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.ServerName),
        ClientHelloExtensionSpec.Raw(0xFDE8, [1, 2, 3]),
        ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.SupportedVersions),
        ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.SupportedGroups),
        ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.SignatureAlgorithms),
        ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.KeyShare),
        ClientHelloExtensionSpec.BuiltIn(
            ClientHelloExtensionKind.ApplicationLayerProtocolNegotiation))
    .BuildSpec();

var profile = ClientHelloProfiles.FromSpec(spec);
```

Every enabled semantic built-in must occur exactly once. Raw bodies are copied when
created and copied again when a layout/spec/profile is snapshotted. Raw types cannot
collide with a semantic SharpTls extension, duplicate another raw type, or combine a
fixed raw GREASE type with semantic GREASE generation. Aggregate raw body data is
limited to 48 KiB in the current defensive policy.

`ClientHelloGreasePolicy` controls equality relationships without fixing code points.
`Consistent` uses one fresh value in all five semantic positions, `PerSlot` generates
five distinct values, and `Create(...)` can express arbitrary shared-value classes.
Actual GREASE values remain fresh per connection and the complete selection is
preserved across HelloRetryRequest.

`WithExtensionShuffling()` enables Chrome 106-style per-connection order
randomization. Semantic GREASE, padding and `pre_shared_key` remain positionally
invariant, while HRR reuses the initially selected order. The shuffle uses secure
runtime entropy in production and the deterministic source in snapshot tests.

`WithGreaseEncryptedClientHello(...)` binds a semantic GREASE-ECH offer to a profile.
Optional arguments pin candidate pre-encryption payload lengths; without arguments the
payload is shaped from a padded ClientHello model. The profile generates fresh config
IDs, X25519 encapsulation and payload bytes without claiming ECH acceptance.

## Semantic versus opaque

A semantic built-in is safe to negotiate because SharpTls constructs its request and
implements the corresponding server response/state transition. An opaque extension
is only a wire-image facility. If the peer ignores it, the handshake can continue.
If the peer returns it in EncryptedExtensions, SharpTls fails with
`unsupported_extension` because inventing response semantics would be unsafe.

This separation is intentional. Future policy-complete OCSP/SCT and RFC 9849 ECH
extensions graduate from raw values to dedicated semantic handlers
only after their complete response paths and negative tests are implemented.

`WithCertificateSignatureAlgorithms(...)` independently controls
`signature_algorithms_cert`; null omits it and falls back to the CertificateVerify
signature list. `WithRecordSizeLimit(...)` controls semantic extension 28 and activates
directional record-layer enforcement. Both fields survive capture import and strict
versioned JSON round trips without changing their extension positions.

`WithDelegatedCredentials(...)` controls RFC 9345 extension 34. Historical profiles
may retain a non-executable legacy scheme only through the explicit wire-fidelity flag;
peer selection of that scheme is always rejected. See
[Delegated credentials](DELEGATED-CREDENTIALS.md) for the authenticated response path.

`WithApplicationSettings(...)` controls the semantic experimental ALPS slot for uTLS
code point 17513 or 17613. Its protocol list must be a subset of ALPN. Server settings
are authenticated before publication and the matching client payload is sent in a
transcripted client EncryptedExtensions message. See
[ALPS/application_settings](APPLICATION-SETTINGS.md); this compatibility feature is
not an IETF standard.

## HelloRetryRequest

The second ClientHello preserves the specification's raw extensions and their order.
When the server supplies a cookie, SharpTls inserts the semantic cookie immediately
before the semantic key_share slot, generates a fresh share for the selected group,
and preserves all RFC 9846 retry invariants.

## Deterministic output

`BuildDeterministicForTesting` remains test-only. It reproduces the full mixed layout
byte-for-byte, but uses fixed test ECDH keys and must never be transmitted. Executable
connections always use secure entropy and fresh runtime-provider private keys.

## Pre-send wire inspection

`CustomTlsClientOptions.ClientHelloInspector` observes the exact encoded handshake
message immediately before each ClientHello is written. The callback runs for the
initial flight and again after HelloRetryRequest. `TlsClientHelloInspection` identifies
direct, ECH-outer, and GREASE-ECH wire forms and returns a new caller-owned array from
`GetEncodedHandshake()` on every call. It also exposes the planned
`LegacyRecordVersion`, exact `RecordFragmentSizes`, and a defensive byte-for-byte record
image through `GetEncodedTlsRecords()`.

```csharp
var options = new CustomTlsClientOptions
{
    ClientHello = ClientHelloProfiles.UTlsChrome102,
    ClientHelloInspector = inspection =>
    {
        var exactHandshakeBytes = inspection.GetEncodedHandshake();
        var exactTlsRecords = inspection.GetEncodedTlsRecords();
        // Hash, persist, or compare the caller-owned copy.
    },
};
```

The observer cannot mutate SharpTls's live ClientHello, key shares, transcript, or
record writer. It is synchronous so the observed bytes and the following write have a
clear order. Throwing from the callback aborts the attempt before that ClientHello is
written. The callback should therefore remain short and must not be treated as a place
to alter protocol state; all wire customization belongs in `ClientHelloSpec` and
`ClientHelloBuilder`.

Semantic GREASE ECH is an explicit `EncryptedClientHello` extension slot. The default
builder places it before a final PSK slot. An exact `WithExtensionOrder` or
`WithExtensionLayout` must contain it exactly once; SharpTls never silently inserts it
somewhere else after an exact layout has been supplied.
