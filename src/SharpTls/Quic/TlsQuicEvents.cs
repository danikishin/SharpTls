using SharpTls.Protocol;

namespace SharpTls.Quic;

/// <summary>Base type for recordless TLS events consumed by a QUIC transport.</summary>
public abstract class TlsQuicEvent
{
    private protected TlsQuicEvent()
    {
    }
}

/// <summary>Contiguous TLS Handshake bytes to place in CRYPTO frames at one encryption level.</summary>
public sealed class TlsQuicCryptoDataEvent : TlsQuicEvent
{
    private readonly byte[] _data;

    internal TlsQuicCryptoDataEvent(
        TlsQuicEncryptionLevel level,
        ulong offset,
        ReadOnlySpan<byte> data)
    {
        Level = level;
        Offset = offset;
        _data = data.ToArray();
    }

    /// <summary>Gets the CRYPTO encryption level.</summary>
    public TlsQuicEncryptionLevel Level { get; }

    /// <summary>Gets the offset in the local unidirectional CRYPTO stream for this level.</summary>
    public ulong Offset { get; }

    /// <summary>Gets a defensive copy of the Handshake bytes.</summary>
    public byte[] Data => (byte[])_data.Clone();
}

/// <summary>A caller-owned TLS traffic secret ready for QUIC packet-key installation.</summary>
public sealed class TlsQuicTrafficSecretEvent : TlsQuicEvent, IDisposable
{
    internal TlsQuicTrafficSecretEvent(TlsQuicTrafficSecret secret)
    {
        Secret = secret;
    }

    /// <summary>
    /// Gets sensitive traffic-secret material. The event or secret must be disposed after
    /// the transport has installed its packet-protection keys.
    /// </summary>
    public TlsQuicTrafficSecret Secret { get; }

    /// <inheritdoc />
    public void Dispose() => Secret.Dispose();
}

/// <summary>Authenticated peer transport parameters released after peer Finished.</summary>
public sealed class TlsQuicPeerTransportParametersEvent : TlsQuicEvent
{
    internal TlsQuicPeerTransportParametersEvent(TlsQuicTransportParameters parameters)
    {
        Parameters = TlsQuicTransportParameters.Parse(parameters.Encode());
    }

    /// <summary>Gets an immutable ordered parameter set including unknown IDs.</summary>
    public TlsQuicTransportParameters Parameters { get; }
}

/// <summary>
/// Supplies ticket-authenticated remembered server parameters for replayable client 0-RTT.
/// Fresh authenticated parameters still arrive later in PeerTransportParametersEvent.
/// </summary>
public sealed class TlsQuicEarlyDataReadyEvent : TlsQuicEvent
{
    internal TlsQuicEarlyDataReadyEvent(TlsQuicTransportParameters rememberedParameters)
    {
        RememberedServerTransportParameters = TlsQuicTransportParameters.Parse(
            rememberedParameters.Encode());
    }

    /// <summary>Gets the remembered limits governing 0-RTT packet and stream use.</summary>
    public TlsQuicTransportParameters RememberedServerTransportParameters { get; }
}

/// <summary>Signals that the transport can discard packet-protection keys for a level.</summary>
public sealed class TlsQuicDiscardKeysEvent : TlsQuicEvent
{
    internal TlsQuicDiscardKeysEvent(TlsQuicEncryptionLevel level)
    {
        Level = level;
    }

    /// <summary>Gets the encryption level whose read and write keys can be discarded.</summary>
    public TlsQuicEncryptionLevel Level { get; }
}

/// <summary>Signals completion of the TLS handshake, not QUIC handshake confirmation.</summary>
public sealed class TlsQuicHandshakeCompletedEvent : TlsQuicEvent
{
    internal TlsQuicHandshakeCompletedEvent(
        TlsCipherSuite cipherSuite,
        NamedGroup group,
        string negotiatedAlpn)
    {
        CipherSuite = cipherSuite;
        Group = group;
        NegotiatedAlpn = negotiatedAlpn;
    }

    /// <summary>Gets the negotiated TLS 1.3 cipher suite.</summary>
    public TlsCipherSuite CipherSuite { get; }

    /// <summary>Gets the negotiated ECDHE group.</summary>
    public NamedGroup Group { get; }

    /// <summary>Gets the mandatory negotiated QUIC ALPN identifier.</summary>
    public string NegotiatedAlpn { get; }
}

/// <summary>
/// One atomic output batch from the QUIC TLS state machine. Dispose the result after
/// installing every contained traffic secret; disposal zeroes unconsumed secret material.
/// </summary>
public sealed class TlsQuicProcessResult : IDisposable
{
    private readonly TlsQuicEvent[] _events;
    private bool _disposed;

    internal TlsQuicProcessResult(IEnumerable<TlsQuicEvent> events)
    {
        _events = events.ToArray();
    }

    /// <summary>Gets events in the exact order in which TLS produced them.</summary>
    public IReadOnlyList<TlsQuicEvent> Events => Array.AsReadOnly(_events);

    /// <inheritdoc />
    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }
        _disposed = true;
        foreach (var item in _events.OfType<IDisposable>())
        {
            item.Dispose();
        }
    }
}
