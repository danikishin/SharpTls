namespace SharpTls;

/// <summary>Configures RFC 9849 Encrypted ClientHello for a TLS 1.3 connection.</summary>
public sealed class TlsEchOptions
{
    /// <summary>Gets or sets the parsed ECH configuration list used for this origin.</summary>
    public required TlsEchConfigList ConfigList { get; set; }

    /// <summary>
    /// Gets or sets the public ClientHelloOuter profile. Its SNI is always replaced with the
    /// selected ECH configuration's public_name. Keep origin-sensitive values in ClientHelloInner.
    /// </summary>
    public ClientHelloProfile OuterClientHello { get; set; } =
        ClientHelloProfiles.Custom(builder => builder.WithTls13());

    /// <summary>
    /// Gets or sets extension types removed from EncodedClientHelloInner and referenced through
    /// RFC 9849 ech_outer_extensions. Values must be contiguous in ClientHelloInner, occur in the
    /// same relative order in ClientHelloOuter, and encode byte-identical bodies.
    /// </summary>
    public IReadOnlyList<Protocol.TlsExtensionType> CompressedOuterExtensions { get; set; } =
        Array.Empty<Protocol.TlsExtensionType>();
}

/// <summary>
/// Configures RFC 9849 GREASE ECH when no authenticated ECH configuration is available.
/// This does not encrypt ClientHello or change the connection's authentication identity.
/// </summary>
public sealed class TlsEchGreaseOptions
{
    internal static readonly IReadOnlyList<TlsHpkeSymmetricCipherSuite> DefaultCipherSuites =
        Array.AsReadOnly<TlsHpkeSymmetricCipherSuite>(
        [
            new(TlsHpkeKdfId.HkdfSha256, TlsHpkeAeadId.Aes128Gcm),
            new(TlsHpkeKdfId.HkdfSha256, TlsHpkeAeadId.ChaCha20Poly1305),
        ]);

    /// <summary>
    /// Gets or sets plausible HPKE suites from which one is selected with secure randomness for
    /// each connection. Unsupported runtime choices are removed during option validation.
    /// </summary>
    public IReadOnlyList<TlsHpkeSymmetricCipherSuite> CipherSuites { get; set; } =
        DefaultCipherSuites;

    /// <summary>
    /// Gets or sets candidate pre-encryption payload lengths. Null derives a plausible
    /// length from the padded ClientHello; browser profiles may pin exact candidates.
    /// </summary>
    public IReadOnlyList<int>? PayloadLengths { get; set; }
}

/// <summary>
/// Reports an authenticated RFC 9849 ECH rejection. The rejected connection is never exposed for
/// application data; callers may create a fresh connection with authenticated retry configurations.
/// </summary>
public sealed class TlsEchRejectedException : IOException
{
    internal TlsEchRejectedException(
        string publicName,
        TlsEchConfigList? retryConfigurations)
        : base("The server authenticated ClientHelloOuter but rejected Encrypted ClientHello.")
    {
        PublicName = publicName;
        RetryConfigurations = retryConfigurations;
    }

    /// <summary>Gets the authenticated ECH public_name.</summary>
    public string PublicName { get; }

    /// <summary>
    /// Gets authenticated retry configurations supplied by the server, or null when the server
    /// securely disabled ECH for this endpoint.
    /// </summary>
    public TlsEchConfigList? RetryConfigurations { get; }
}

internal sealed record TlsEchClientConfiguration(
    TlsEchConfigList ConfigList,
    EchConfigSelection Selection,
    ClientHelloProfile OuterClientHello,
    Protocol.TlsExtensionType[] CompressedOuterExtensions,
    byte[] ConfigListHash) : IDisposable
{
    public void Dispose() =>
        System.Security.Cryptography.CryptographicOperations.ZeroMemory(ConfigListHash);
}

internal sealed record TlsEchGreaseConfiguration(
    TlsHpkeSymmetricCipherSuite[] CipherSuites,
    int[]? PayloadLengths = null);
