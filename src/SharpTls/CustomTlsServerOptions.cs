using SharpTls.Certificates;
using SharpTls.Protocol;

namespace SharpTls;

/// <summary>Controls initial TLS 1.3 client-certificate authentication.</summary>
public enum TlsServerClientAuthenticationMode
{
    /// <summary>Do not request a client certificate.</summary>
    None,
    /// <summary>Request a certificate but permit an empty response.</summary>
    Request,
    /// <summary>Require a valid certificate and CertificateVerify.</summary>
    Require,
}

/// <summary>Managed RFC 8879 certificate-compression algorithms.</summary>
public enum TlsCertificateCompressionAlgorithm : ushort
{
    /// <summary>DEFLATE with the zlib wrapper.</summary>
    Zlib = 1,

    /// <summary>Brotli compression.</summary>
    Brotli = 2,
}

/// <summary>Immutable input presented to an asynchronous server-certificate selector.</summary>
public sealed class TlsServerCertificateSelectionContext
{
    private readonly string[] _alpn;
    private readonly SignatureScheme[] _signatures;

    internal TlsServerCertificateSelectionContext(
        string? serverName,
        IReadOnlyList<string> alpn,
        IReadOnlyList<SignatureScheme> signatures)
    {
        ServerName = serverName;
        _alpn = alpn.ToArray();
        _signatures = signatures.ToArray();
    }

    /// <summary>Gets the offered SNI host name, or null.</summary>
    public string? ServerName { get; }

    /// <summary>Gets client ALPN values in wire preference order.</summary>
    public IReadOnlyList<string> AlpnProtocols => Array.AsReadOnly((string[])_alpn.Clone());

    /// <summary>Gets client CertificateVerify algorithms in wire preference order.</summary>
    public IReadOnlyList<SignatureScheme> SignatureAlgorithms =>
        Array.AsReadOnly((SignatureScheme[])_signatures.Clone());
}

/// <summary>Selects a caller-owned server credential for one ClientHello.</summary>
public delegate ValueTask<TlsServerCertificate?> TlsServerCertificateSelector(
    TlsServerCertificateSelectionContext context,
    CancellationToken cancellationToken);

/// <summary>Configures one pure managed TLS server connection.</summary>
public sealed class CustomTlsServerOptions
{
    /// <summary>Gets or sets protocol versions in server preference order.</summary>
    public IReadOnlyList<TlsProtocolVersion> SupportedVersions { get; set; } =
        [TlsProtocolVersion.Tls13, TlsProtocolVersion.Tls12];

    /// <summary>Gets or sets the static caller-owned server credential.</summary>
    public TlsServerCertificate? ServerCertificate { get; set; }

    /// <summary>Gets or sets an asynchronous SNI/ALPN-aware credential selector.</summary>
    public TlsServerCertificateSelector? ServerCertificateSelector { get; set; }

    /// <summary>Gets or sets TLS 1.3 cipher-suite server preference.</summary>
    public IReadOnlyList<TlsCipherSuite> CipherSuites { get; set; } =
    [
        TlsCipherSuite.TlsAes128GcmSha256,
        TlsCipherSuite.TlsAes256GcmSha384,
        TlsCipherSuite.TlsChaCha20Poly1305Sha256,
    ];

    /// <summary>Gets or sets secure TLS 1.2 ECDHE+AEAD suites in server preference order.</summary>
    public IReadOnlyList<TlsCipherSuite> Tls12CipherSuites { get; set; } =
    [
        TlsCipherSuite.TlsEcdheEcdsaWithAes128GcmSha256,
        TlsCipherSuite.TlsEcdheRsaWithAes128GcmSha256,
        TlsCipherSuite.TlsEcdheEcdsaWithAes256GcmSha384,
        TlsCipherSuite.TlsEcdheRsaWithAes256GcmSha384,
        TlsCipherSuite.TlsEcdheEcdsaWithChaCha20Poly1305Sha256,
        TlsCipherSuite.TlsEcdheRsaWithChaCha20Poly1305Sha256,
    ];

    /// <summary>
    /// Gets or sets key-establishment group preference, including supported classical
    /// ECDHE and hybrid post-quantum groups.
    /// </summary>
    public IReadOnlyList<NamedGroup> SupportedGroups { get; set; } =
    [NamedGroup.X25519, NamedGroup.Secp256r1, NamedGroup.Secp384r1];

    /// <summary>
    /// Gets or sets caller-owned RFC 9849 ECH keys. Configuring keys requires a TLS-1.3-only
    /// server policy. Each accepted connection snapshots the private key bytes and zeroizes
    /// its copy on disposal.
    /// </summary>
    public IReadOnlyList<TlsEchServerKey> EncryptedClientHelloKeys { get; set; } = [];

    /// <summary>
    /// Gets or sets opt-in RFC 8879 certificate-compression preference. The server sends
    /// CompressedCertificate only when the client offered a configured algorithm.
    /// </summary>
    public IReadOnlyList<TlsCertificateCompressionAlgorithm> CertificateCompressionAlgorithms
        { get; set; } = [];

    /// <summary>Gets or sets supported ALPN values in server preference order.</summary>
    public IReadOnlyList<string> AlpnProtocols { get; set; } = [];

    /// <summary>Gets or sets whether a connection without a common ALPN fails.</summary>
    public bool RequireAlpn { get; set; }

    /// <summary>Gets or sets plaintext and protected handshake fragmentation.</summary>
    public TlsRecordFragmentation HandshakeFragmentation { get; set; } =
        TlsRecordFragmentation.Default;

    /// <summary>Gets or sets protected application-data fragmentation.</summary>
    public TlsRecordFragmentation ApplicationDataFragmentation { get; set; } =
        TlsRecordFragmentation.Default;

    /// <summary>Gets or sets zero padding bytes appended to every TLS 1.3 application record.</summary>
    public int ApplicationDataPaddingLength { get; set; }

    /// <summary>Gets or sets parser, transcript and certificate limits.</summary>
    public TlsLimits Limits { get; set; } = TlsLimits.Default;

    /// <summary>Gets or sets whether the server emits a compatibility CCS after ServerHello.</summary>
    public bool SendCompatibilityChangeCipherSpec { get; set; } = true;

    /// <summary>Gets or sets initial client-certificate policy.</summary>
    public TlsServerClientAuthenticationMode ClientAuthentication { get; set; }

    /// <summary>Gets or sets chain validation for a supplied client certificate.</summary>
    public CustomTlsCertificateValidationOptions ClientCertificateValidation { get; set; } = new();

    /// <summary>Gets or sets accepted client CertificateVerify algorithms in wire order.</summary>
    public IReadOnlyList<SignatureScheme> ClientCertificateSignatureAlgorithms { get; set; } =
    [
        SignatureScheme.EcdsaSecp256r1Sha256,
        SignatureScheme.EcdsaSecp384r1Sha384,
        SignatureScheme.EcdsaSecp521r1Sha512,
        SignatureScheme.RsaPssRsaeSha256,
        SignatureScheme.RsaPssRsaeSha384,
        SignatureScheme.RsaPssRsaeSha512,
        SignatureScheme.RsaPssPssSha256,
        SignatureScheme.RsaPssPssSha384,
        SignatureScheme.RsaPssPssSha512,
    ];

    /// <summary>
    /// Gets or sets a caller-owned cache shared by connections for TLS 1.2 session-ID resumption.
    /// </summary>
    public Tls12ServerSessionCache? Tls12SessionCache { get; set; }

    /// <summary>
    /// Gets or sets a caller-owned stateless RFC 5077 TLS 1.2 ticket protector.
    /// </summary>
    public Tls12ServerSessionTicketProtector? Tls12SessionTicketProtector { get; set; }

    /// <summary>Gets or sets the lifetime advertised by TLS 1.2 session tickets.</summary>
    public TimeSpan Tls12SessionTicketLifetime { get; set; } = TimeSpan.FromHours(24);

    /// <summary>
    /// Gets or sets the caller-owned stateless TLS 1.3 ticket protector. When present,
    /// the server can issue and authenticate PSK-DHE resumption tickets.
    /// </summary>
    public Tls13ServerSessionTicketProtector? SessionTicketProtector { get; set; }

    /// <summary>Gets or sets the lifetime advertised on newly issued tickets.</summary>
    public TimeSpan SessionTicketLifetime { get; set; } = TimeSpan.FromHours(24);

    /// <summary>Gets or sets how many tickets are sent immediately after a full or resumed handshake.</summary>
    public int AutomaticSessionTicketCount { get; set; } = 2;

    /// <summary>Gets or sets accepted skew between the protected issue time and obfuscated ticket age.</summary>
    public TimeSpan SessionTicketAgeTolerance { get; set; } = TimeSpan.FromMinutes(10);

    internal CustomTlsServerConfiguration Snapshot()
    {
        if ((ServerCertificate is null) == (ServerCertificateSelector is null))
        {
            throw new ArgumentException(
                "Configure exactly one static server certificate or certificate selector.");
        }
        ArgumentNullException.ThrowIfNull(CipherSuites);
        ArgumentNullException.ThrowIfNull(SupportedVersions);
        ArgumentNullException.ThrowIfNull(Tls12CipherSuites);
        ArgumentNullException.ThrowIfNull(SupportedGroups);
        ArgumentNullException.ThrowIfNull(EncryptedClientHelloKeys);
        ArgumentNullException.ThrowIfNull(CertificateCompressionAlgorithms);
        ArgumentNullException.ThrowIfNull(AlpnProtocols);
        ArgumentNullException.ThrowIfNull(HandshakeFragmentation);
        ArgumentNullException.ThrowIfNull(ApplicationDataFragmentation);
        ArgumentNullException.ThrowIfNull(Limits);
        ArgumentNullException.ThrowIfNull(ClientCertificateValidation);
        ArgumentNullException.ThrowIfNull(ClientCertificateSignatureAlgorithms);
        Limits.Validate();

        var versions = SupportedVersions.ToArray();
        var suites = CipherSuites.ToArray();
        var tls12Suites = Tls12CipherSuites.ToArray();
        var groups = SupportedGroups.ToArray();
        var echKeyInputs = EncryptedClientHelloKeys.ToArray();
        var certificateCompression = CertificateCompressionAlgorithms.ToArray();
        var alpn = AlpnProtocols.ToArray();
        if (suites.Length == 0 || suites.Distinct().Count() != suites.Length ||
            suites.Any(suite => suite is not (
                TlsCipherSuite.TlsAes128GcmSha256 or
                TlsCipherSuite.TlsAes256GcmSha384 or
                TlsCipherSuite.TlsChaCha20Poly1305Sha256)))
        {
            throw new ArgumentException("Server cipher suites are empty, duplicate, or unsupported.");
        }
        if (versions.Length == 0 || versions.Distinct().Count() != versions.Length ||
            versions.Any(version => version is not (
                TlsProtocolVersion.Tls13 or TlsProtocolVersion.Tls12)))
        {
            throw new ArgumentException("Server versions are empty, duplicate, or unsupported.");
        }
        if (tls12Suites.Length == 0 ||
            tls12Suites.Distinct().Count() != tls12Suites.Length)
        {
            throw new ArgumentException("TLS 1.2 cipher suites are empty or duplicate.");
        }
        foreach (var tls12Suite in tls12Suites)
        {
            _ = Cryptography.Tls12CipherSuiteInfo.Get(tls12Suite);
        }
        if (groups.Length == 0 || groups.Distinct().Count() != groups.Length ||
            groups.Any(group => group is not (
                NamedGroup.X25519 or NamedGroup.Secp256r1 or
                NamedGroup.Secp384r1 or NamedGroup.Secp521r1 or
                NamedGroup.X25519MlKem768 or NamedGroup.X25519Kyber768Draft00)))
        {
            throw new ArgumentException("Server groups are empty, duplicate, or unsupported.");
        }
        if (echKeyInputs.Any(key => key is null) ||
            echKeyInputs.Select(key => key.Configuration.ConfigId).Distinct().Count() !=
                echKeyInputs.Length)
        {
            throw new ArgumentException(
                "ECH server keys are null or contain duplicate configuration identifiers.",
                nameof(EncryptedClientHelloKeys));
        }
        if (echKeyInputs.Length != 0 &&
            !versions.SequenceEqual([TlsProtocolVersion.Tls13]))
        {
            throw new ArgumentException(
                "ECH server keys require SupportedVersions to contain only TLS 1.3.",
                nameof(EncryptedClientHelloKeys));
        }
        if (certificateCompression.Distinct().Count() != certificateCompression.Length ||
            certificateCompression.Any(algorithm => algorithm is not (
                TlsCertificateCompressionAlgorithm.Zlib or
                TlsCertificateCompressionAlgorithm.Brotli)))
        {
            throw new ArgumentException(
                "Certificate-compression algorithms are duplicate or unsupported.");
        }
        if (alpn.Distinct(StringComparer.Ordinal).Count() != alpn.Length ||
            alpn.Any(value => string.IsNullOrEmpty(value) ||
                value.Length > TlsConstants.MaxAlpnProtocolLength ||
                value.Any(character => character > 0x7F)))
        {
            throw new ArgumentException("Server ALPN values are duplicate or invalid.");
        }
        if (RequireAlpn && alpn.Length == 0)
        {
            throw new ArgumentException("RequireAlpn needs at least one configured protocol.");
        }
        if (ApplicationDataPaddingLength < 0 ||
            ApplicationDataPaddingLength + 1 + TlsConstants.AeadTagLength >
                TlsConstants.MaxCiphertextLength)
        {
            throw new ArgumentOutOfRangeException(nameof(ApplicationDataPaddingLength));
        }

        if (!Enum.IsDefined(ClientAuthentication))
        {
            throw new ArgumentOutOfRangeException(nameof(ClientAuthentication));
        }
        if (SessionTicketLifetime <= TimeSpan.Zero ||
            SessionTicketLifetime > TimeSpan.FromDays(7))
        {
            throw new ArgumentOutOfRangeException(nameof(SessionTicketLifetime));
        }
        if (Tls12SessionTicketLifetime <= TimeSpan.Zero ||
            Tls12SessionTicketLifetime > TimeSpan.FromDays(7))
        {
            throw new ArgumentOutOfRangeException(nameof(Tls12SessionTicketLifetime));
        }
        if (AutomaticSessionTicketCount is < 0 or > 16)
        {
            throw new ArgumentOutOfRangeException(nameof(AutomaticSessionTicketCount));
        }
        if (SessionTicketAgeTolerance < TimeSpan.Zero ||
            SessionTicketAgeTolerance > TimeSpan.FromHours(24))
        {
            throw new ArgumentOutOfRangeException(nameof(SessionTicketAgeTolerance));
        }
        if (SessionTicketProtector is not null &&
            ClientAuthentication != TlsServerClientAuthenticationMode.None)
        {
            throw new ArgumentException(
                "Stateless resumption is disabled when initial client-certificate authentication is configured.",
                nameof(SessionTicketProtector));
        }
        if (ClientCertificateValidation.EvidenceValidator is not null ||
            ClientCertificateValidation.RequireValidStapledOcspResponse ||
            ClientCertificateValidation.MinimumValidSignedCertificateTimestamps != 0 ||
            ClientCertificateValidation.DangerouslySkipServerCertificateValidation)
        {
            throw new ArgumentException(
                "Server-side client authentication does not consume server-certificate " +
                "bypass or server OCSP/SCT evidence options.",
                nameof(ClientCertificateValidation));
        }
        if (ClientCertificateValidation.UrlRetrievalTimeout < TimeSpan.Zero)
        {
            throw new ArgumentOutOfRangeException(
                nameof(ClientCertificateValidation.UrlRetrievalTimeout));
        }
        var clientSignatures = ClientCertificateSignatureAlgorithms.ToArray();
        if (clientSignatures.Length == 0 ||
            clientSignatures.Distinct().Count() != clientSignatures.Length ||
            clientSignatures.Any(scheme => scheme is not (
                SignatureScheme.EcdsaSecp256r1Sha256 or
                SignatureScheme.EcdsaSecp384r1Sha384 or
                SignatureScheme.EcdsaSecp521r1Sha512 or
                SignatureScheme.RsaPssRsaeSha256 or
                SignatureScheme.RsaPssRsaeSha384 or
                SignatureScheme.RsaPssRsaeSha512 or
                SignatureScheme.RsaPssPssSha256 or
                SignatureScheme.RsaPssPssSha384 or
                SignatureScheme.RsaPssPssSha512)))
        {
            throw new ArgumentException(
                "Client CertificateVerify algorithms are empty, duplicate, or unsupported.");
        }

        TlsEchServerKeyConfiguration[] echKeys = [];
        System.Security.Cryptography.X509Certificates.X509Certificate2Collection? roots = null;
        try
        {
            echKeys = echKeyInputs.Select(key => key.Snapshot()).ToArray();
            var retryConfigurations =
                TlsEchServerKeyConfiguration.BuildRetryConfigurationList(echKeys);
            if (retryConfigurations is not null)
            {
                System.Security.Cryptography.CryptographicOperations.ZeroMemory(
                    retryConfigurations);
            }
            if (ClientCertificateValidation.CustomTrustRoots is { Count: > 0 } configuredRoots)
            {
                roots = new System.Security.Cryptography.X509Certificates.X509Certificate2Collection();
                foreach (var root in configuredRoots)
                {
                    ArgumentNullException.ThrowIfNull(root);
                    roots.Add(System.Security.Cryptography.X509Certificates.X509CertificateLoader
                        .LoadCertificate(root.RawData));
                }
            }
            var clientCertificatePolicy = new CertificateValidationPolicy(
                ClientCertificateValidation.RevocationMode,
                ClientCertificateValidation.RevocationFlag,
                ClientCertificateValidation.DisableCertificateDownloads,
                ClientCertificateValidation.UrlRetrievalTimeout,
                roots,
                AllowUnknownRevocationStatus:
                    ClientCertificateValidation.AllowUnknownRevocationStatus);

            return new CustomTlsServerConfiguration(
                ServerCertificate,
                ServerCertificateSelector,
                versions,
                suites,
                tls12Suites,
                groups,
                echKeys,
                certificateCompression,
                alpn,
                RequireAlpn,
                HandshakeFragmentation,
                ApplicationDataFragmentation,
                ApplicationDataPaddingLength,
                Limits with { },
                SendCompatibilityChangeCipherSpec,
                ClientAuthentication,
                clientCertificatePolicy,
                clientSignatures,
                Tls12SessionCache,
                Tls12SessionTicketProtector,
                checked((uint)Math.Ceiling(Tls12SessionTicketLifetime.TotalSeconds)),
                SessionTicketProtector,
                checked((uint)Math.Ceiling(SessionTicketLifetime.TotalSeconds)),
                AutomaticSessionTicketCount,
                SessionTicketAgeTolerance);
        }
        catch
        {
            foreach (var key in echKeys)
            {
                key.Dispose();
            }
            if (roots is not null)
            {
                foreach (var root in roots)
                {
                    root.Dispose();
                }
            }
            throw;
        }
    }
}

internal sealed record CustomTlsServerConfiguration(
    TlsServerCertificate? ServerCertificate,
    TlsServerCertificateSelector? ServerCertificateSelector,
    TlsProtocolVersion[] SupportedVersions,
    TlsCipherSuite[] CipherSuites,
    TlsCipherSuite[] Tls12CipherSuites,
    NamedGroup[] SupportedGroups,
    TlsEchServerKeyConfiguration[] EncryptedClientHelloKeys,
    TlsCertificateCompressionAlgorithm[] CertificateCompressionAlgorithms,
    string[] AlpnProtocols,
    bool RequireAlpn,
    TlsRecordFragmentation HandshakeFragmentation,
    TlsRecordFragmentation ApplicationDataFragmentation,
    int ApplicationDataPaddingLength,
    TlsLimits Limits,
    bool SendCompatibilityChangeCipherSpec,
    TlsServerClientAuthenticationMode ClientAuthentication,
    CertificateValidationPolicy ClientCertificateValidation,
    SignatureScheme[] ClientCertificateSignatureAlgorithms,
    Tls12ServerSessionCache? Tls12SessionCache,
    Tls12ServerSessionTicketProtector? Tls12SessionTicketProtector,
    uint Tls12SessionTicketLifetimeSeconds,
    Tls13ServerSessionTicketProtector? SessionTicketProtector,
    uint SessionTicketLifetimeSeconds,
    int AutomaticSessionTicketCount,
    TimeSpan SessionTicketAgeTolerance) : IDisposable
{
    public void Dispose()
    {
        foreach (var key in EncryptedClientHelloKeys)
        {
            key.Dispose();
        }
        if (ClientCertificateValidation.CustomTrustRoots is not { } roots)
        {
            return;
        }
        foreach (var root in roots)
        {
            root.Dispose();
        }
    }
}
