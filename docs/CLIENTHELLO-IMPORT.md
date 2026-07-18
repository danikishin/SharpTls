# Captured ClientHello import and JSON interchange

`ClientHelloCapture.Import` accepts either one bare TLS Handshake message or a
sequence of TLSPlaintext Handshake records. Record fragments are reassembled under a
caller-configurable 256 KiB default limit. The parser rejects trailing bytes,
truncation, duplicate extensions, invalid vector lengths, malformed EC points,
non-zero padding, and unsupported negotiation fields.

```csharp
var imported = ClientHelloCapture.Import(capturedBytes);
var profile = ClientHelloProfiles.FromSpec(imported.Spec);
var capturedFragmentation = imported.CreateRecordFragmentation();

var json = ClientHelloSpecJson.Serialize(imported.Spec);
var restored = ClientHelloSpecJson.Deserialize(json);
```

The captured SNI value is returned separately as `CapturedServerName`. The reusable
specification records that SNI occupies a particular extension slot, but the actual
name continues to come from the new connection's reference identity. Captured
ClientHello random, ECDHE public/private material, and—by default—the legacy session
ID are not replayed. Set `PreserveSessionId` only when an exact cosmetic session-ID
value is required; it is not a TLS session-resumption mechanism.

For record-framed input, `RecordFragmentSizes` and `RecordVersions` retain the exact
TLSPlaintext boundary metadata. `CreateRecordFragmentation()` recreates those boundaries
for an equal-length rebuilt ClientHello. Bare Handshake input reports empty record
metadata. Record versions outside the TLS 1.3-compatible `0x0301`/`0x0303` values are
rejected.

Unknown extensions are snapshotted as bounded opaque bodies and retain their exact
positions. Known extensions are parsed into semantic fields so SharpTls can generate
fresh, internally coherent wire values. A capture is rejected rather than imported
when it advertises an algorithm or semantic extension that the current client cannot
execute safely.

A structurally valid visible `encrypted_client_hello` outer value is normalized as
semantic GREASE ECH: the selected supported HPKE suite, exact extension position and
pre-encryption payload length are retained, while config ID, X25519 encapsulated key and
payload bytes are generated afresh. Malformed or unsupported ECH outer values are rejected
instead of being replayed as opaque bytes. Authenticated real ECH still requires a current
caller-supplied `TlsEchConfigList`; a capture never supplies private ECH policy.

## Version 6 JSON rules

The JSON format identifier is `sharptls-clienthello-spec` and its current version is
`6`; versions 1 through 5 remain accepted for compatibility. Version 4 added
Chrome-style extension-shuffle policy and semantic GREASE-ECH payload candidates;
version 5 added the secondary GREASE-extension shape, and version 6 records the exact
ordered GREASE-ECH HPKE cipher-suite candidates rather than only payload lengths.
Documents contain only
reusable offer policy: ordered suites, groups, key-share
groups, signature algorithms, ALPN, session-ID policy, padding, GREASE value-sharing
classes, SNI policy, record-size/delegated-credential policy, experimental
application-settings code point/protocols, extension shuffling, GREASE-ECH policy, and
the mixed extension layout. Random, generated public keys, binders, traffic secrets,
and session-ticket secrets are not schema fields.

JSON parsing is case-sensitive, disallows comments, trailing commas, unknown fields,
duplicate property names at every nesting level, unsupported enum names, ambiguous
extension unions, and semantic/raw extension collisions. Input and output are
bounded to 256 KiB by default and at most 4 MiB when explicitly configured.

## Current capture compatibility

The importer currently executes captures composed from TLS 1.3 or the restricted
TLS 1.2 ECDHE/AEAD subset, X25519/P-256/P-384/P-521, X25519MLKEM768 and the
historical X25519Kyber768Draft00 group, the implemented
RSA-PSS-RSAE/RSA-PSS-PSS/RSA-PKCS1/ECDSA signatures, SNI, ALPN, experimental semantic ALPS,
padding, opaque extensions, and
arbitrary five-slot GREASE equality patterns.

Generated key shares, random values and binders are always replaced with fresh coherent
values. A capture that contains a PSK binder or an extension whose response semantics
cannot be reconstructed safely is rejected or retained only as an opaque ignored offer;
it is never silently weakened or falsely marked executable. Stateful resumption offers
come from the caller-owned session cache, not from replaying captured ticket identities.
