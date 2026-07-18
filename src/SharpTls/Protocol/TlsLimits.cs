namespace SharpTls.Protocol;

/// <summary>Configurable defensive allocation and message-size limits.</summary>
public sealed record TlsLimits
{
    /// <summary>Default production limits.</summary>
    public static TlsLimits Default { get; } = new();

    /// <summary>Maximum encoded handshake message length, including neither record nor handshake header.</summary>
    public int MaxHandshakeMessageSize { get; init; } = 4 * 1024 * 1024;

    /// <summary>Maximum aggregate encoded certificate-list size.</summary>
    public int MaxCertificateListSize { get; init; } = 3 * 1024 * 1024;

    /// <summary>Maximum number of certificates accepted from a peer.</summary>
    public int MaxCertificateCount { get; init; } = 16;

    /// <summary>Maximum number of TLS 1.3 tickets accepted on one connection.</summary>
    public int MaxSessionTicketsPerConnection { get; init; } = 16;

    /// <summary>Maximum caller-configured TLS 1.3 early application data.</summary>
    public int MaxEarlyDataSize { get; init; } = 256 * 1024;

    /// <summary>Maximum retained TLS 1.3 transcript bytes when post-handshake auth is enabled.</summary>
    public int MaxHandshakeTranscriptSize { get; init; } = 8 * 1024 * 1024;

    /// <summary>Maximum post-handshake CertificateRequest messages accepted on one connection.</summary>
    public int MaxPostHandshakeAuthenticationRequests { get; init; } = 16;

    internal void Validate()
    {
        if (MaxHandshakeMessageSize is < 1024 or > 0xFFFFFF)
        {
            throw new ArgumentOutOfRangeException(nameof(MaxHandshakeMessageSize));
        }

        if (MaxCertificateListSize is < 1024 or > 0xFFFFFF ||
            MaxCertificateListSize > MaxHandshakeMessageSize)
        {
            throw new ArgumentOutOfRangeException(nameof(MaxCertificateListSize));
        }

        if (MaxCertificateCount is < 1 or > 256)
        {
            throw new ArgumentOutOfRangeException(nameof(MaxCertificateCount));
        }

        if (MaxSessionTicketsPerConnection is < 1 or > 256)
        {
            throw new ArgumentOutOfRangeException(nameof(MaxSessionTicketsPerConnection));
        }

        if (MaxEarlyDataSize is < 1 or > 4 * 1024 * 1024)
        {
            throw new ArgumentOutOfRangeException(nameof(MaxEarlyDataSize));
        }

        if (MaxHandshakeTranscriptSize is < 1024 or > 32 * 1024 * 1024)
        {
            throw new ArgumentOutOfRangeException(nameof(MaxHandshakeTranscriptSize));
        }

        if (MaxPostHandshakeAuthenticationRequests is < 1 or > 256)
        {
            throw new ArgumentOutOfRangeException(nameof(MaxPostHandshakeAuthenticationRequests));
        }

    }
}
