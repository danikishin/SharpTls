# Recordless QUIC-TLS adapter

`CustomTlsQuicClient` and `CustomTlsQuicServer` implement only the TLS 1.3 portion of
QUIC. They consume and emit raw TLS Handshake bytes at QUIC encryption levels. The
surrounding transport owns UDP, packet numbers, header and payload protection, CRYPTO
frames, Retry, loss recovery, congestion control, streams, connection IDs and
HANDSHAKE_DONE. HTTP/3 and QPACK are not part of this library.

The client starts with `StartHandshake`; the server starts when it receives Initial
CRYPTO bytes through `ProcessCryptoDataAsync`. Every returned `TlsQuicProcessResult`
contains ordered events:

- `TlsQuicCryptoDataEvent`: bytes and offset for the level's local CRYPTO stream;
- `TlsQuicTrafficSecretEvent`: sensitive TLS traffic secret to install for packet
  protection, then dispose;
- `TlsQuicPeerTransportParametersEvent`: peer parameters released after authentication;
- `TlsQuicDiscardKeysEvent`: a level whose packet keys can be discarded;
- `TlsQuicHandshakeCompletedEvent`: TLS completion, distinct from QUIC confirmation;
- `TlsQuicEarlyDataReadyEvent`: ticket-authenticated remembered server limits for 0-RTT.

Input CRYPTO ranges may be fragmented, reordered, duplicated or overlapping. Reassembly
requires overlapping bytes to match, tracks independent offsets for each level, rejects
gaps beyond the configured bound, and never feeds a partial Handshake message to the
state machine. CRYPTO frames at the 0-RTT level and TLS KeyUpdate are protocol errors.

Traffic-secret events own secret memory. Install or derive the packet keys immediately
and dispose the event/result; copies returned by `CopySecret` or packet-key accessors are
caller-owned and must be zeroized. `TlsQuicInitialSecrets.Derive` separately derives QUIC
v1/v2 Initial secrets from a destination connection ID.

## Handshake features

Both roles support strict transport-parameter parsing, unknown-parameter preservation,
role-specific parameter validation, SNI, mandatory ALPN, all SharpTls TLS 1.3 AEADs and
groups, HRR, certificate compression/evidence, optional initial client authentication,
stateless protected tickets, PSK-DHE resumption and Application-level
NewSessionTicket processing. HRR rewrites the binder transcript using synthetic
`message_hash`; the second ClientHello cannot retain early_data.

Both roles also support RFC 9849 ECH. The client uses
`CustomTlsQuicClientOptions.EncryptedClientHello` or GREASE policy; the server uses
`CustomTlsQuicServerOptions.Tls.EncryptedClientHelloKeys`. Accepted direct/HRR handshakes
negotiate and transcript the reconstructed Inner, while authenticated rejection exposes
retry configurations through `TlsEchRejectedException`. ECH-bound tickets, binders and
0-RTT secrets remain tied to Inner. This does not add QUIC packet or HTTP/3 behavior.

The client ticket cache is origin/port/ALPN/hash bound. The server protector authenticates
ticket state and age. `IssueSessionTicketAsync` emits one manual Application CRYPTO
message after the client Finished; automatic ticket issuance is also bounded.

## Replayable 0-RTT

QUIC 0-RTT is disabled by default. The client must construct
`TlsQuicEarlyDataOptions(acknowledgeReplayRisk: true)`. This authorizes early-secret
generation, not application replay safety. The transport decides what replay-tolerant
frames to send and must obey the remembered parameters in `TlsQuicEarlyDataReadyEvent`.

The server additionally requires `EnableEarlyData`, a ticket protector, and an atomic
`EarlyDataReplayValidator`. It accepts only a valid QUIC ticket carrying the mandated
`uint.MaxValue` TLS early-data size, no HRR, compatible remembered transport limits and
a successful anti-replay decision. Reduced flow-control, stream, datagram or connection-ID
limits reject early data while allowing PSK resumption. Acceptance emits the matching
server read secret; rejection emits no early secret and is visible to both state machines.

The adapter deliberately does not promise that a QUIC connection is usable merely because
TLS completed. The surrounding transport must follow RFC 9000/RFC 9001 confirmation,
key-discard, Retry and transport-parameter rules before exposing its own connection API.
