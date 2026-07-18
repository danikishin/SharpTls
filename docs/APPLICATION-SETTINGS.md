# Experimental ALPS/application_settings

SharpTls implements the two experimental `application_settings` wire code points used
by uTLS-compatible clients:

| API value | Wire value | Provenance |
|---|---:|---|
| `LegacyDraft` | 17513 | `draft-vvv-tls-alps-01` / historical Chromium profiles |
| `ChromeExperiment` | 17613 | later Chromium/uTLS experiment |

This is compatibility functionality, not an IETF Standards Track claim. The ALPS
Internet-Draft is expired and archived, and neither code point is assigned in the IANA
TLS ExtensionType registry. The public enum and XML documentation therefore retain
the word *experimental*.

Configure the visible ClientHello protocol list and the encrypted client payload
separately:

```csharp
var profile = ClientHelloProfiles.Custom(builder => builder
    .WithAlpn("h2", "http/1.1")
    .WithApplicationSettings(
        TlsApplicationSettingsCodePoint.ChromeExperiment,
        "h2"));

var options = new CustomTlsClientOptions
{
    ClientHello = profile,
    ClientApplicationSettings = new Dictionary<string, byte[]>
    {
        ["h2"] = clientHttp2Settings,
    },
};
```

The ClientHello body is a 16-bit vector of 8-bit-length-prefixed ALPN identifiers and
preserves caller order exactly. Each listed protocol must be unique, must also appear
in ALPN, and requires a TLS-1.3-capable profile. Raw extensions 17513 and 17613 cannot
masquerade as the semantic slot.

When the server returns the offered code point in EncryptedExtensions, SharpTls
requires it to select a listed ALPN protocol. The opaque server payload is retained
but is not published through `NegotiatedPeerApplicationSettings` until server Finished
has authenticated the transcript. SharpTls then sends the matching opaque client
payload in a client EncryptedExtensions message before client Certificate and Finished;
that complete message is included in the Finished transcript. Wrong code points,
duplicates, missing/ineligible ALPN, malformed vectors, illegal message order, and
unbound ALPS combined with accepted early data fail closed.

When a NewSessionTicket follows an authenticated ALPS handshake, SharpTls persists the
selected code point and exact peer/client payloads with the ticket. Persistent cache
state uses the same binding and remains backward-readable; older unbound tickets can
resume at 1-RTT but are never eligible to send ALPS-associated 0-RTT. A bound ticket is
eligible only when the caller still configures the same code point and byte-exact client
payload for the cached ALPN. During resumption the server must return the same code point,
ALPN, and peer payload; any change is fatal `illegal_parameter`. This permits guarded
ALPS+0-RTT without treating unauthenticated or stale settings as current configuration.

The ordinary replay risks of 0-RTT still apply. Ticket binding prevents settings
confusion; it cannot make an early application operation non-replayable.

Normative provenance: [expired ALPS draft](https://datatracker.ietf.org/doc/draft-vvv-tls-alps/01/).
Registry status: [IANA TLS ExtensionType Values](https://www.iana.org/assignments/tls-extensiontype-values/).
