using SharpTls.Protocol;
using SharpTls.Quic;

namespace SharpTls;

/// <summary>
/// Immutable, transport-independent description of a TLS ClientHello offer.
/// Ephemeral random and key-share material is generated only when a connection is built.
/// </summary>
public sealed class ClientHelloSpec
{
    private readonly ClientHelloConfiguration _configuration;

    internal ClientHelloSpec(ClientHelloConfiguration configuration)
    {
        _configuration = configuration.Snapshot();
    }

    /// <summary>Gets the cipher suites in exact wire order.</summary>
    public IReadOnlyList<TlsCipherSuite> CipherSuites =>
        Array.AsReadOnly((TlsCipherSuite[])_configuration.CipherSuites.Clone());

    /// <summary>Gets supported_versions values in exact wire order.</summary>
    public IReadOnlyList<TlsProtocolVersion> SupportedVersions =>
        Array.AsReadOnly((TlsProtocolVersion[])_configuration.SupportedVersions.Clone());

    /// <summary>Gets supported groups in exact preference order.</summary>
    public IReadOnlyList<NamedGroup> SupportedGroups =>
        Array.AsReadOnly((NamedGroup[])_configuration.SupportedGroups.Clone());

    /// <summary>Gets initial key-share groups in exact order.</summary>
    public IReadOnlyList<NamedGroup> KeyShareGroups =>
        Array.AsReadOnly((NamedGroup[])_configuration.KeyShareGroups.Clone());

    /// <summary>Gets CertificateVerify signature schemes in exact order.</summary>
    public IReadOnlyList<SignatureScheme> SignatureAlgorithms =>
        Array.AsReadOnly((SignatureScheme[])_configuration.SignatureAlgorithms.Clone());

    /// <summary>Gets whether duplicate signature_algorithms entries are retained for wire fidelity.</summary>
    public bool AllowsDuplicateSignatureAlgorithms =>
        _configuration.AllowDuplicateSignatureAlgorithms;

    /// <summary>
    /// Gets certificate-chain signature schemes in preference order, or null when the
    /// CertificateVerify signature list also applies to certificate signatures.
    /// </summary>
    public IReadOnlyList<SignatureScheme>? CertificateSignatureAlgorithms =>
        _configuration.CertificateSignatureAlgorithms is null
            ? null
            : Array.AsReadOnly(
                (SignatureScheme[])_configuration.CertificateSignatureAlgorithms.Clone());

    /// <summary>Gets the advertised RFC 8449 protected-record receive limit, or null.</summary>
    public int? RecordSizeLimit => _configuration.RecordSizeLimit;

    /// <summary>Gets accepted RFC 9345 delegated-credential signature schemes, or null.</summary>
    public IReadOnlyList<SignatureScheme>? DelegatedCredentialSignatureAlgorithms =>
        _configuration.DelegatedCredentialSignatureAlgorithms is null
            ? null
            : Array.AsReadOnly(
                (SignatureScheme[])_configuration.DelegatedCredentialSignatureAlgorithms.Clone());

    /// <summary>Gets whether historical non-executable delegated schemes are retained on wire.</summary>
    public bool AllowsUnsupportedDelegatedCredentialAlgorithmsForWireFidelity =>
        _configuration.AllowUnsupportedDelegatedCredentialAlgorithmsForWireFidelity;

    /// <summary>Gets ordered local QUIC transport parameters, or null when not configured.</summary>
    public TlsQuicTransportParameters? QuicTransportParameters =>
        _configuration.QuicTransportParameters is null
            ? null
            : TlsQuicTransportParameters.Parse(_configuration.QuicTransportParameters);

    /// <summary>Gets ALPN protocol identifiers in exact order.</summary>
    public IReadOnlyList<string> AlpnProtocols =>
        Array.AsReadOnly((string[])_configuration.AlpnProtocols.Clone());

    /// <summary>
    /// Gets the selected experimental ALPS/application_settings code point, or null when disabled.
    /// </summary>
    public TlsApplicationSettingsCodePoint? ApplicationSettingsCodePoint =>
        _configuration.ApplicationSettingsCodePoint;

    /// <summary>Gets the ALPN protocols for which experimental application settings are offered.</summary>
    public IReadOnlyList<string> ApplicationSettingsProtocols =>
        Array.AsReadOnly((string[])_configuration.ApplicationSettingsProtocols.Clone());

    /// <summary>Gets a copy of the fixed legacy session ID, or null for a fresh ID per connection.</summary>
    public byte[]? SessionId => _configuration.SessionId is null
        ? null
        : (byte[])_configuration.SessionId.Clone();

    /// <summary>Gets the exact fixed padding body length, or null when disabled.</summary>
    public int? PaddingLength => _configuration.PaddingLength;

    /// <summary>Gets whether the profile uses the BoringSSL dynamic ClientHello padding rule.</summary>
    public bool UseBoringPadding => _configuration.UseBoringPadding;

    /// <summary>Gets whether Chrome-style per-connection extension shuffling is enabled.</summary>
    public bool ShuffleExtensions => _configuration.ShuffleExtensions;

    /// <summary>Gets whether the profile automatically emits semantic GREASE ECH.</summary>
    public bool GreaseEncryptedClientHello =>
        _configuration.GreaseEchPayloadLengths is not null;

    /// <summary>Gets the ordered GREASE-ECH HPKE-suite candidates.</summary>
    public IReadOnlyList<TlsHpkeSymmetricCipherSuite> GreaseEchCipherSuites => Array.AsReadOnly(
        _configuration.GreaseEchCipherSuites is null
            ? []
            : (TlsHpkeSymmetricCipherSuite[])_configuration.GreaseEchCipherSuites.Clone());

    /// <summary>Gets configured GREASE-ECH pre-encryption payload lengths.</summary>
    public IReadOnlyList<int> GreaseEchPayloadLengths => Array.AsReadOnly(
        _configuration.GreaseEchPayloadLengths is null
            ? []
            : (int[])_configuration.GreaseEchPayloadLengths.Clone());

    /// <summary>Gets whether semantic RFC 8701 GREASE generation is enabled.</summary>
    public bool Grease => _configuration.GreasePolicy is not null;

    /// <summary>Gets a snapshot of the GREASE value-sharing policy, or null when disabled.</summary>
    public ClientHelloGreasePolicy? GreasePolicy => _configuration.GreasePolicy?.Snapshot();

    /// <summary>Gets the fixed GREASE key_share body, or null when a random byte is generated.</summary>
    public byte[]? FixedGreaseKeyShareBody => _configuration.FixedGreaseKeyShareBody is null
        ? null
        : (byte[])_configuration.FixedGreaseKeyShareBody.Clone();

    /// <summary>Gets a copy of the optional second GREASE extension body.</summary>
    public byte[]? SecondaryGreaseExtensionBody => _configuration.SecondaryGreaseExtensionBody is null
        ? null
        : (byte[])_configuration.SecondaryGreaseExtensionBody.Clone();

    /// <summary>Gets whether the semantic SNI extension is enabled.</summary>
    public bool IncludeSni => _configuration.IncludeSni;

    /// <summary>Gets snapshotted extension slots in exact wire order.</summary>
    public IReadOnlyList<ClientHelloExtensionSpec> Extensions => Array.AsReadOnly(
        _configuration.ExtensionLayout.Select(extension => extension.Snapshot()).ToArray());

    /// <summary>Gets whether the profile has an executable conditional TLS 1.3 PSK slot.</summary>
    public bool SupportsSessionResumption => _configuration.SupportsSessionResumption;

    /// <summary>Gets whether the profile can conditionally offer replay-aware TLS 1.3 early data.</summary>
    public bool SupportsEarlyData => _configuration.SupportsEarlyData;

    /// <summary>Gets whether the profile advertises TLS 1.3 post-handshake authentication.</summary>
    public bool SupportsPostHandshakeAuthentication =>
        _configuration.SupportsPostHandshakeAuthentication;

    internal ClientHelloConfiguration SnapshotConfiguration() => _configuration.Snapshot();
}
