namespace SharpTls.Quic;

/// <summary>Immutable input to an application-supplied QUIC 0-RTT anti-replay decision.</summary>
public sealed class TlsQuicEarlyDataContext
{
    private readonly byte[] _ticketIdentity;

    internal TlsQuicEarlyDataContext(string? serverName, string alpn, ReadOnlySpan<byte> identity)
    {
        ServerName = serverName;
        NegotiatedAlpn = alpn;
        _ticketIdentity = identity.ToArray();
    }

    /// <summary>Gets the resumed SNI name.</summary>
    public string? ServerName { get; }

    /// <summary>Gets the resumed ALPN protocol.</summary>
    public string NegotiatedAlpn { get; }

    /// <summary>Gets a defensive copy of the authenticated ticket identity.</summary>
    public byte[] TicketIdentity => (byte[])_ticketIdentity.Clone();
}

/// <summary>Returns true only when one authenticated ticket may consume its 0-RTT replay window.</summary>
public delegate ValueTask<bool> TlsQuicEarlyDataReplayValidator(
    TlsQuicEarlyDataContext context,
    CancellationToken cancellationToken);

/// <summary>Configures a recordless TLS 1.3 server handshake for a caller-owned QUIC transport.</summary>
public sealed class CustomTlsQuicServerOptions
{
    /// <summary>
    /// Gets or sets the standard TLS server policy. Record fragmentation and compatibility
    /// CCS settings are ignored because QUIC carries raw TLS Handshake bytes.
    /// </summary>
    public CustomTlsServerOptions Tls { get; set; } = new();

    /// <summary>Gets or sets the server transport parameters emitted in EncryptedExtensions.</summary>
    public TlsQuicTransportParameters? TransportParameters { get; set; }

    /// <summary>Gets or sets the maximum buffered bytes in each peer CRYPTO stream.</summary>
    public int MaximumCryptoStreamLength { get; set; } = 8 * 1024 * 1024;

    /// <summary>Gets or sets whether issued QUIC tickets authorize 0-RTT.</summary>
    public bool EnableEarlyData { get; set; }

    /// <summary>
    /// Gets or sets the mandatory atomic anti-replay decision used before accepting 0-RTT.
    /// </summary>
    public TlsQuicEarlyDataReplayValidator? EarlyDataReplayValidator { get; set; }

    internal CustomTlsQuicServerConfiguration Snapshot()
    {
        ArgumentNullException.ThrowIfNull(Tls);
        ArgumentNullException.ThrowIfNull(TransportParameters);
        if (MaximumCryptoStreamLength is < 1024 or > 32 * 1024 * 1024)
        {
            throw new ArgumentOutOfRangeException(nameof(MaximumCryptoStreamLength));
        }

        TransportParameters.ValidatePeer(TlsQuicEndpointRole.Server);
        if (EnableEarlyData && (Tls.SessionTicketProtector is null ||
            EarlyDataReplayValidator is null))
        {
            throw new ArgumentException(
                "QUIC 0-RTT requires a session-ticket protector and anti-replay validator.");
        }
        var shared = Tls.Snapshot();
        try
        {
            if (shared.AlpnProtocols.Length == 0)
            {
                throw new ArgumentException(
                    "A QUIC TLS server must configure at least one ALPN protocol.",
                    nameof(Tls));
            }
            return new CustomTlsQuicServerConfiguration(
                shared,
                TlsQuicTransportParameters.Parse(TransportParameters.Encode()),
                MaximumCryptoStreamLength,
                EnableEarlyData,
                EarlyDataReplayValidator);
        }
        catch
        {
            shared.Dispose();
            throw;
        }
    }
}

internal sealed record CustomTlsQuicServerConfiguration(
    CustomTlsServerConfiguration Shared,
    TlsQuicTransportParameters TransportParameters,
    int MaximumCryptoStreamLength,
    bool EnableEarlyData,
    TlsQuicEarlyDataReplayValidator? EarlyDataReplayValidator) : IDisposable
{
    public void Dispose() => Shared.Dispose();
}
