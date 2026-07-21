# TLS 1.3 resumption and early data

SharpTls implements TLS 1.3 ticket resumption with ephemeral ECDHE (`psk_dhe_ke`).
It does not implement PSK-only key exchange. A resumed connection therefore retains
forward secrecy for new application traffic and authenticates the handshake with a
fresh key share plus the ticket PSK.

## Session cache

`Tls13SessionCache` is caller-owned and can be shared by independent
`CustomTlsClient` instances:

```csharp
using var sessions = new Tls13SessionCache();

var options = new CustomTlsClientOptions
{
    ServerName = "example.com",
    ClientHello = ClientHelloProfiles.ModernTls13,
    SessionCache = sessions,
};

await using var first = new CustomTlsClient(options);
await first.ConnectAsync("example.com", 443, cancellationToken);
// Read application data so post-handshake NewSessionTicket messages are consumed.

await using var resumed = new CustomTlsClient(options);
await resumed.ConnectAsync("example.com", 443, cancellationToken);
Console.WriteLine(resumed.SessionWasResumed);
```

The cache is bounded and thread-safe. It binds tickets to the normalized reference
identity, port, certificate-validation mode, negotiated ALPN, and compatible TLS 1.3
transcript hash. A ticket learned with the explicit dangerous certificate bypass is
never offered by a default validated client, or vice versa. Tickets are removed atomically
when offered, are never offered twice by the cache, expire no later than seven days, and
cannot extend the authentication lifetime of the original certificate handshake.
Eviction, clearing, disposal, and failed offers zeroize owned ticket identities and PSKs.

Tickets created by an accepted ECH handshake are additionally bound to the SHA-256 hash
of the exact bootstrapping `ECHConfigList`. They are never offered by a non-ECH connection
or by an ECH connection using a different configuration source. This deliberately
conservative scope prevents persisted resumption state from crossing RFC 9849 public-name
and recovery boundaries.

### Encrypted persistence and key rotation

The in-memory cache can be exported to a database or file without exposing ticket PSKs.
`Tls13SessionStateProtector` uses a caller-supplied, random 32-byte key with
AES-256-GCM. The authenticated header carries a printable key identifier so an
application can retain an old decrypt-only key while new exports use a rotated key:

```csharp
var julyKey = RandomNumberGenerator.GetBytes(32); // load from a real secret store
using var july = new Tls13SessionStateProtector("2026-07", julyKey);
byte[] persisted = sessions.ExportEncrypted(july);

var augustKey = RandomNumberGenerator.GetBytes(32);
using var august = new Tls13SessionStateProtector("2026-08", augustKey);
august.AddDecryptionKey("2026-07", julyKey);

using var restored = new Tls13SessionCache();
restored.ImportEncrypted(persisted, august);
```

Imports authenticate before parsing and update the cache only after the entire plaintext
has passed structural, algorithm, lifetime, origin and field validation. Tampering,
unknown keys, truncation, unsupported versions and oversized state fail without a partial
import. Expired tickets are discarded by the destination cache; capacity, per-origin,
ALPN, ECH-source and single-use rules remain in force. Protector and cache disposal
zeroize owned key/PSK copies. The application must keep protection keys in an appropriate
secret store and must not reuse them for another protocol.

Tickets issued after experimental ALPS/application_settings negotiation additionally
persist the code point and byte-exact authenticated peer/client settings. Such a ticket
is offered only when the configured client settings still match. Older persisted state
without this binding remains readable but cannot authorize ALPS-associated 0-RTT. State
written before validation-mode binding remains readable as validated-mode state and can
never enter the dangerous bypass partition implicitly.

`ModernTls13` and the TLS-1.3-capable pinned uTLS profiles contain conditional PSK
slots. With no cached ticket, `early_data` and `pre_shared_key` are omitted and the
pinned initial ClientHello wire image is unchanged. When a ticket is offered,
`pre_shared_key` is always the final extension. By default SharpTls offers up to four
matching ticket identities; `MaximumOfferedTls13PskIdentities` can bound this from one
to 64. Every identity receives a binder using its own transcript hash, including a
hash-specific synthetic `message_hash` after HelloRetryRequest. The server may select
any encoded index. Offered cache tickets are atomically consumed to prevent concurrent
reuse.

## Replay-aware 0-RTT

Early data has weaker security than ordinary application data: an active attacker can
replay it. It is disabled by default. Enabling it requires a non-empty payload and an
explicit replay-risk acknowledgement:

```csharp
var request = "HEAD / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n"u8.ToArray();

var options = new CustomTlsClientOptions
{
    ServerName = "example.com",
    ClientHello = ClientHelloProfiles.ModernTls13,
    SessionCache = sessions,
    EarlyData = new Tls13EarlyDataOptions(
        request,
        acknowledgeReplayRisk: true,
        Tls13EarlyDataRejectionPolicy.ReturnToCaller),
};
```

SharpTls sends 0-RTT only when the selected cached ticket explicitly carries a
non-zero `max_early_data_size`, the complete payload fits that limit and the ticket's
original cipher suite is offered. It derives separate client-early traffic keys,
honors record fragmentation and AEAD usage limits, and sends `EndOfEarlyData` only
when the server accepts the early data. HelloRetryRequest always rejects the early
data while preserving PSK resumption with a recomputed binder.

For ALPS/application_settings profiles, 0-RTT additionally requires a ticket produced
by an authenticated handshake with the same code point, ALPN, peer payload, and client
payload. The server's resumed EncryptedExtensions must reproduce the ticket-bound peer
state or the client sends `illegal_parameter`. This binding prevents configuration
confusion but does not remove the fundamental replayability of early data.

TLS 1.3 associates early data with PSK identity zero. When several cached tickets match,
SharpTls promotes an early-data-capable ticket to index zero and derives early traffic
keys only from that PSK. A server may select another identity only while rejecting early
data; accepting 0-RTT with any nonzero identity is fatal.

With ECH, the real identity and binder exist only in ClientHelloInner. ClientHelloOuter
contains an independently random identity, age, and binder with matching lengths, plus
the required `psk_key_exchange_modes` and conditional `early_data` signal. Early traffic
keys use the inner transcript hash. If ECH is rejected, selection of the outer GREASE PSK
is fatal `illegal_parameter`, and private early bytes are never retransmitted on the
authenticated public-name connection even when ordinary rejection policy requested
1-RTT retransmission.

After `ConnectAsync`, inspect `EarlyDataStatus`:

- `NotConfigured`: no early-data request was configured.
- `Unavailable`: no suitable early-data ticket existed and no bytes were sent.
- `Accepted`: the server accepted the 0-RTT records.
- `Rejected`: the server rejected them and SharpTls did not resend them.
- `RejectedAndRetransmitted`: the caller explicitly selected
  `RetransmitAfterHandshake`, so the identical bytes were sent once under authenticated
  1-RTT application keys.

The default rejection policy is `ReturnToCaller`. SharpTls never assumes that replaying
or retransmitting an application operation is safe. Use early data only for operations
whose complete application semantics are idempotent and replay-tolerant; an HTTP method
name alone is not sufficient proof.

## Validation and limits

The implementation verifies the full PSK binder, including RFC 9846's synthetic
`message_hash` construction after HelloRetryRequest; enforces ticket lifetime,
obfuscated age, nonce uniqueness and per-connection ticket limits; rejects illegal PSK
selection, ALPN changes, certificate messages on a resumed path, malformed ticket
extensions, and unsolicited early-data acceptance; and keeps the session cache out of
the public secret surface.

Tests include RFC 8448 PSK/binder and early-traffic key vectors, concurrent cache
ownership, expiry/origin/ALPN/hash isolation, malformed ticket and extension inputs,
HRR binder reconstruction, real public-server resumption, and fully managed loopback
servers that verify accepted and rejected/retransmitted 0-RTT over TCP. ECH coverage
verifies automatically issued source-bound tickets, inner binders, outer GREASE PSKs,
accepted 0-RTT, HRR recomputation, illegal outer selection, and rejection without private
1-RTT retransmission.

## External TLS 1.3 PSKs

`CustomTlsClientOptions.ExternalPsk` accepts a caller-owned `Tls13ExternalPsk`. SharpTls
copies the identity/key during option snapshotting, zeroes every owned key copy on
dispose, encodes a zero obfuscated ticket age, and calculates the distinct RFC 8446
`ext binder` including the HRR transcript when required. External PSKs require a
TLS-1.3-only profile with a final semantic `pre_shared_key` slot and a compatible
cipher-suite hash. Ticket-cache resumption and 0-RTT cannot be combined with this mode.

Selection is required by default: if the server ignores the identity, SharpTls sends
`handshake_failure` instead of silently changing authentication modes. Set
`requireSelection: false` only when explicit certificate-authenticated fallback is
part of the caller's policy. A managed TCP peer test verifies the binder, ECDHE,
bidirectional Finished messages, and application records. This API configures a real
PSK handshake; it does not accept traffic secrets, sequence numbers, or fabricated
authenticated state.

Automatic application replay is intentionally not implemented. TLS 1.2 session-ID and
RFC 5077 ticket resumption are implemented
through their separate cache and policy. None of these are implied by TLS 1.3 resumption.

Normative sections: RFC 9846 §§2.2, 4.2.4, 4.2.9–4.2.11, 4.3.11, 4.7, 7.1 and 8;
RFC 9849 §§6.1–6.1.6 and 10.12.3.
