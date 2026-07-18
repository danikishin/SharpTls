using SharpTls.Protocol;

namespace SharpTls;

/// <summary>Classifies a redacted TLS handshake or post-handshake event.</summary>
public enum TlsHandshakeEventKind
{
    /// <summary>A ClientHello is about to be sent.</summary>
    ClientHello,
    /// <summary>A HelloRetryRequest was validated.</summary>
    HelloRetryRequest,
    /// <summary>A ServerHello was validated.</summary>
    ServerHello,
    /// <summary>EncryptedExtensions was validated.</summary>
    EncryptedExtensions,
    /// <summary>A CertificateRequest was validated.</summary>
    CertificateRequest,
    /// <summary>A Certificate or CompressedCertificate was validated.</summary>
    Certificate,
    /// <summary>CertificateVerify was authenticated.</summary>
    CertificateVerify,
    /// <summary>A ServerKeyExchange was authenticated.</summary>
    ServerKeyExchange,
    /// <summary>A ServerHelloDone was validated.</summary>
    ServerHelloDone,
    /// <summary>A ClientKeyExchange was sent.</summary>
    ClientKeyExchange,
    /// <summary>A Finished message was authenticated or sent.</summary>
    Finished,
    /// <summary>The complete TLS handshake became usable.</summary>
    HandshakeCompleted,
    /// <summary>A NewSessionTicket was validated.</summary>
    NewSessionTicket,
    /// <summary>A KeyUpdate was validated or sent.</summary>
    KeyUpdate,
}

/// <summary>Identifies the wire direction of a redacted TLS event.</summary>
public enum TlsHandshakeEventDirection
{
    /// <summary>The client sent the message.</summary>
    ClientToServer,
    /// <summary>The server sent the message.</summary>
    ServerToClient,
    /// <summary>The event is a local state transition rather than a wire message.</summary>
    Local,
}

/// <summary>
/// Immutable secret-free handshake event. It intentionally exposes no message bytes,
/// certificate contents, randoms, key shares, transcript hashes, or traffic secrets.
/// </summary>
public sealed class TlsHandshakeEvent
{
    internal TlsHandshakeEvent(
        long sequenceNumber,
        TlsHandshakeEventKind kind,
        TlsHandshakeEventDirection direction,
        TlsProtocolVersion? protocolVersion,
        int encodedLength,
        TlsClientHelloFlight? clientHelloFlight)
    {
        SequenceNumber = sequenceNumber;
        Kind = kind;
        Direction = direction;
        ProtocolVersion = protocolVersion;
        EncodedLength = encodedLength;
        ClientHelloFlight = clientHelloFlight;
    }

    /// <summary>Gets the one-based event order for this client connection.</summary>
    public long SequenceNumber { get; }
    /// <summary>Gets the redacted event classification.</summary>
    public TlsHandshakeEventKind Kind { get; }
    /// <summary>Gets the message direction or local-transition marker.</summary>
    public TlsHandshakeEventDirection Direction { get; }
    /// <summary>Gets the active protocol version when known.</summary>
    public TlsProtocolVersion? ProtocolVersion { get; }
    /// <summary>Gets the encoded handshake length, or zero for local transitions.</summary>
    public int EncodedLength { get; }
    /// <summary>Gets the ClientHello flight for ClientHello events, or null.</summary>
    public TlsClientHelloFlight? ClientHelloFlight { get; }
}
