# Record size limits

SharpTls implements RFC 8449 `record_size_limit` as a negotiated protocol feature,
not as an opaque ClientHello fingerprint byte string.

Configure the maximum protected plaintext that the client is willing to receive:

```csharp
var profile = ClientHelloProfiles.Custom(builder => builder
    .WithRecordSizeLimit(4096));
```

The accepted ClientHello range is 64 through 16385 bytes. A null value removes the
extension. The slot is a normal `ClientHelloExtensionKind.RecordSizeLimit`, so it can
be placed at an exact position with `WithExtensionOrder` or `WithExtensionLayout`.
Raw extension type 28 is rejected because it would bypass response semantics.

## Directional semantics

The ClientHello value limits protected records sent by the server. The value returned
by the server limits protected records sent by the client; the values need not match.
After connection they are exposed as:

- `NegotiatedReceiveRecordSizeLimit` — server-to-client protected plaintext;
- `NegotiatedSendRecordSizeLimit` — client-to-server protected plaintext.

Both properties are null when the server does not negotiate the extension.

For TLS 1.3, the length is the complete `TLSInnerPlaintext`, including content,
the one-byte inner content type, and zero padding. The maximum is 16385. The client
retroactively validates the encrypted record carrying EncryptedExtensions because
that response is itself protected by keys produced by the current handshake. All
later protected handshake, alert, and application records are checked immediately.

For TLS 1.2, the length is the plaintext passed to AEAD protection and the protocol
maximum is 16384. ServerHello establishes the limit before either endpoint switches
to protected records. Unprotected ClientHello, ServerHello, certificate-flight, CCS,
and alert records are not subject to RFC 8449.

## Fragmentation and failures

Protected handshake and application writes are split so their plaintext stays within
the peer's value. TLS 1.3 application padding reduces the available content in each
record. If configured padding leaves no room for content, the write fails rather than
silently changing the requested fingerprint. An authenticated inbound overrun raises
`TlsProtocolException` with `TlsAlertDescription.RecordOverflow`.

Malformed bodies, values below 64, TLS 1.3 values above 16385, TLS 1.2 server values
above 16384, duplicate responses, and unoffered responses fail closed. TLS 1.3 0-RTT
uses the peer limit stored with the ticket from the handshake that produced the early
traffic keys, as RFC 8449 requires; a newly negotiated limit is not applied backwards
to those records. If a peer returns both deprecated `maximum_fragment_length` and
`record_size_limit`, the handshake fails with `illegal_parameter` as required by
RFC 8449 section 5.
