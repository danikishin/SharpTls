using SharpTls.Certificates;
using SharpTls.Protocol;

namespace SharpTls.Quic;

/// <summary>Explicitly enables replayable QUIC 0-RTT key generation.</summary>
public sealed class TlsQuicEarlyDataOptions
{
    /// <summary>Creates a 0-RTT request only after explicit replay-risk acknowledgement.</summary>
    public TlsQuicEarlyDataOptions(bool acknowledgeReplayRisk)
    {
        if (!acknowledgeReplayRisk)
        {
            throw new ArgumentException(
                "QUIC 0-RTT is replayable and requires explicit risk acknowledgement.",
                nameof(acknowledgeReplayRisk));
        }
    }
}

/// <summary>Configures a recordless TLS 1.3 client handshake for a caller-owned QUIC transport.</summary>
public sealed class CustomTlsQuicClientOptions
{
    /// <summary>Gets or sets the SNI and mandatory certificate reference identity.</summary>
    public string ServerName { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets the exact ClientHello profile. It must be TLS-1.3-only, offer ALPN,
    /// and contain a semantic <see cref="ClientHelloExtensionKind.QuicTransportParameters"/> slot.
    /// </summary>
    public ClientHelloProfile ClientHello { get; set; } = ClientHelloProfiles.ModernTls13;

    /// <summary>Gets or sets defensive parser and transcript limits.</summary>
    public TlsLimits Limits { get; set; } = TlsLimits.Default;

    /// <summary>Gets or sets the server X.509 and reference-identity validation policy.</summary>
    public CustomTlsCertificateValidationOptions CertificateValidation { get; set; } = new();

    /// <summary>Gets or sets a static client credential for initial client authentication.</summary>
    public TlsClientCertificate? ClientCertificate { get; set; }

    /// <summary>Gets or sets an asynchronous initial client-credential selector.</summary>
    public TlsClientCertificateSelector? ClientCertificateSelector { get; set; }

    /// <summary>Gets or sets the origin-bound TLS 1.3 ticket cache used for QUIC resumption.</summary>
    public Tls13SessionCache? SessionCache { get; set; }

    /// <summary>Gets or sets RFC 9849 Encrypted ClientHello for QUIC TLS.</summary>
    public TlsEchOptions? EncryptedClientHello { get; set; }

    /// <summary>Gets or sets RFC 9849 GREASE ECH when no real configuration is available.</summary>
    public TlsEchGreaseOptions? EncryptedClientHelloGrease { get; set; }

    /// <summary>Gets or sets the origin port used to bind cached tickets.</summary>
    public int ServerPort { get; set; } = 443;

    /// <summary>Gets or sets explicit replayable 0-RTT enablement.</summary>
    public TlsQuicEarlyDataOptions? EarlyData { get; set; }

    /// <summary>Gets or sets the maximum buffered bytes in each peer CRYPTO stream.</summary>
    public int MaximumCryptoStreamLength { get; set; } = 8 * 1024 * 1024;

    internal CustomTlsQuicClientConfiguration Snapshot()
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(ServerName);
        ArgumentNullException.ThrowIfNull(ClientHello);
        ArgumentNullException.ThrowIfNull(Limits);
        ArgumentNullException.ThrowIfNull(CertificateValidation);
        if (MaximumCryptoStreamLength is < 1024 or > 32 * 1024 * 1024)
        {
            throw new ArgumentOutOfRangeException(nameof(MaximumCryptoStreamLength));
        }
        if (ServerPort is < 1 or > ushort.MaxValue)
        {
            throw new ArgumentOutOfRangeException(nameof(ServerPort));
        }

        var spec = ClientHello.Spec;
        if (!spec.SupportedVersions.SequenceEqual([TlsProtocolVersion.Tls13]) ||
            spec.AlpnProtocols.Count == 0 ||
            spec.QuicTransportParameters is null ||
            !spec.Extensions.Any(extension =>
                extension.BuiltInKind == ClientHelloExtensionKind.QuicTransportParameters))
        {
            throw new ArgumentException(
                "A QUIC ClientHello must be TLS-1.3-only and contain semantic ALPN and transport parameters.",
                nameof(ClientHello));
        }
        if (spec.SupportsPostHandshakeAuthentication ||
            spec.ApplicationSettingsCodePoint.HasValue)
        {
            throw new NotSupportedException(
                "The QUIC adapter does not permit post-handshake authentication or experimental ALPS.");
        }
        if (EncryptedClientHello is { } ech)
        {
            ArgumentNullException.ThrowIfNull(ech.OuterClientHello);
            var outer = ech.OuterClientHello.Spec;
            if (!outer.SupportedVersions.SequenceEqual([TlsProtocolVersion.Tls13]) ||
                outer.AlpnProtocols.Count == 0 ||
                outer.QuicTransportParameters is null ||
                !outer.Extensions.Any(extension =>
                    extension.BuiltInKind ==
                        ClientHelloExtensionKind.QuicTransportParameters))
            {
                throw new ArgumentException(
                    "QUIC ClientHelloOuter must be TLS-1.3-only and contain semantic ALPN and transport parameters.",
                    nameof(EncryptedClientHello));
            }
        }
        var hasPsk = spec.Extensions.Any(extension =>
            extension.BuiltInKind == ClientHelloExtensionKind.PreSharedKey);
        var hasPskModes = spec.Extensions.Any(extension =>
            extension.BuiltInKind == ClientHelloExtensionKind.PskKeyExchangeModes);
        if (SessionCache is not null && (!hasPsk || !hasPskModes))
        {
            throw new ArgumentException(
                "A QUIC session cache requires semantic psk_key_exchange_modes and pre_shared_key slots.",
                nameof(ClientHello));
        }
        if (EarlyData is not null && (SessionCache is null ||
            !spec.Extensions.Any(extension =>
                extension.BuiltInKind == ClientHelloExtensionKind.EarlyData)))
        {
            throw new ArgumentException(
                "QUIC 0-RTT requires a session cache and semantic early_data slot.",
                nameof(EarlyData));
        }

        var shared = new CustomTlsClientOptions
        {
            ServerName = ServerName,
            ClientHello = ClientHello,
            Limits = Limits,
            CertificateValidation = CertificateValidation,
            ClientCertificate = ClientCertificate,
            ClientCertificateSelector = ClientCertificateSelector,
            SessionCache = SessionCache,
            EncryptedClientHello = EncryptedClientHello,
            EncryptedClientHelloGrease = EncryptedClientHelloGrease,
            SendCompatibilityChangeCipherSpec = false,
            UseInitialCompatibilityRecordVersion = false,
        }.Snapshot();
        return new CustomTlsQuicClientConfiguration(
            ServerName,
            ServerPort,
            ClientHello,
            shared,
            MaximumCryptoStreamLength,
            EarlyData is not null);
    }
}

internal sealed record CustomTlsQuicClientConfiguration(
    string ServerName,
    int ServerPort,
    ClientHelloProfile ClientHello,
    CustomTlsClientConfiguration Shared,
    int MaximumCryptoStreamLength,
    bool EnableEarlyData) : IDisposable
{
    public void Dispose() => Shared.Dispose();
}
