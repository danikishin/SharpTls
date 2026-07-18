using SharpTls.Protocol;

namespace SharpTls.Quic;

/// <summary>QUIC versions whose TLS key-separation labels are implemented.</summary>
public enum TlsQuicVersion : uint
{
    /// <summary>RFC 9000 QUIC version 1.</summary>
    Version1 = 0x00000001,
    /// <summary>RFC 9369 QUIC version 2.</summary>
    Version2 = 0x6B3343CF,
}

/// <summary>RFC 9001 TLS/QUIC encryption levels.</summary>
public enum TlsQuicEncryptionLevel
{
    /// <summary>Initial CRYPTO data; keys are derived by QUIC from the destination CID.</summary>
    Initial,
    /// <summary>Replayable client 0-RTT packet protection; CRYPTO frames never use this level.</summary>
    EarlyData,
    /// <summary>TLS handshake CRYPTO data and secrets.</summary>
    Handshake,
    /// <summary>Authenticated 1-RTT data and post-handshake CRYPTO data.</summary>
    Application,
}

/// <summary>Direction of a TLS-produced QUIC traffic secret.</summary>
public enum TlsQuicSecretDirection
{
    /// <summary>Packets written by the local endpoint.</summary>
    Write,
    /// <summary>Packets read from the peer.</summary>
    Read,
}

/// <summary>Endpoint role used for transport-parameter context validation.</summary>
public enum TlsQuicEndpointRole
{
    /// <summary>QUIC client.</summary>
    Client,
    /// <summary>QUIC server.</summary>
    Server,
}

/// <summary>Errors owned by the QUIC transport rather than the TLS alert registry.</summary>
public enum TlsQuicTransportError : ulong
{
    /// <summary>RFC 9000 PROTOCOL_VIOLATION.</summary>
    ProtocolViolation = 0x0A,
    /// <summary>RFC 9000 TRANSPORT_PARAMETER_ERROR.</summary>
    TransportParameterError = 0x08,
    /// <summary>RFC 9000 CRYPTO_BUFFER_EXCEEDED.</summary>
    CryptoBufferExceeded = 0x0D,
}

/// <summary>A fail-closed QUIC transport error raised by the recordless TLS boundary.</summary>
public sealed class TlsQuicTransportException : IOException
{
    /// <summary>Creates a QUIC transport failure.</summary>
    public TlsQuicTransportException(TlsQuicTransportError error, string message)
        : base(message)
    {
        Error = error;
    }

    /// <summary>Gets the RFC 9000 transport error.</summary>
    public TlsQuicTransportError Error { get; }

    /// <summary>Maps a fatal TLS alert to the RFC 9001 CRYPTO_ERROR range.</summary>
    public static ulong GetCryptoErrorCode(TlsAlertDescription alert) =>
        0x100UL + (byte)alert;
}

/// <summary>Known QUIC transport-parameter identifiers. Unknown IDs remain supported.</summary>
public enum TlsQuicTransportParameterId : ulong
{
    /// <summary>Connection ID from the client's first Initial packet.</summary>
    OriginalDestinationConnectionId = 0x00,
    /// <summary>Maximum idle timeout in milliseconds.</summary>
    MaxIdleTimeout = 0x01,
    /// <summary>Server-only 16-byte stateless reset token.</summary>
    StatelessResetToken = 0x02,
    /// <summary>Largest UDP datagram payload accepted by the endpoint.</summary>
    MaxUdpPayloadSize = 0x03,
    /// <summary>Initial connection-level flow-control limit.</summary>
    InitialMaxData = 0x04,
    /// <summary>Initial local bidirectional-stream flow-control limit.</summary>
    InitialMaxStreamDataBidiLocal = 0x05,
    /// <summary>Initial peer bidirectional-stream flow-control limit.</summary>
    InitialMaxStreamDataBidiRemote = 0x06,
    /// <summary>Initial unidirectional-stream flow-control limit.</summary>
    InitialMaxStreamDataUni = 0x07,
    /// <summary>Initial peer-opened bidirectional-stream count.</summary>
    InitialMaxStreamsBidi = 0x08,
    /// <summary>Initial peer-opened unidirectional-stream count.</summary>
    InitialMaxStreamsUni = 0x09,
    /// <summary>Exponent used to decode ACK delay.</summary>
    AckDelayExponent = 0x0A,
    /// <summary>Maximum ACK delay in milliseconds.</summary>
    MaxAckDelay = 0x0B,
    /// <summary>Empty flag disabling active connection migration.</summary>
    DisableActiveMigration = 0x0C,
    /// <summary>Server-only preferred IPv4/IPv6 address and connection ID.</summary>
    PreferredAddress = 0x0D,
    /// <summary>Minimum number of active connection IDs the endpoint can store.</summary>
    ActiveConnectionIdLimit = 0x0E,
    /// <summary>Sender's Initial source connection ID.</summary>
    InitialSourceConnectionId = 0x0F,
    /// <summary>Server source connection ID carried in Retry.</summary>
    RetrySourceConnectionId = 0x10,
    /// <summary>RFC 9368 chosen and available compatible versions.</summary>
    VersionInformation = 0x11,
    /// <summary>RFC 9221 maximum DATAGRAM frame size.</summary>
    MaxDatagramFrameSize = 0x20,
    /// <summary>RFC 9287 empty grease_quic_bit capability.</summary>
    GreaseQuicBit = 0x2AB2,
}
