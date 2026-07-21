using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using SharpTls.Certificates;
using SharpTls.Protocol;

namespace SharpTls;

/// <summary>Configures a <see cref="CustomTlsClient"/> connection.</summary>
public sealed class CustomTlsClientOptions
{
    /// <summary>Gets or sets the SNI and certificate reference identity. Null uses the connect host.</summary>
    public string? ServerName { get; set; }

    /// <summary>Gets or sets the immutable ClientHello profile.</summary>
    public ClientHelloProfile ClientHello { get; set; } = ClientHelloProfiles.ModernTls13;

    /// <summary>Gets or sets plaintext handshake record fragmentation.</summary>
    public TlsRecordFragmentation HandshakeFragmentation { get; set; } = TlsRecordFragmentation.Default;

    /// <summary>Gets or sets application-data record fragmentation.</summary>
    public TlsRecordFragmentation ApplicationDataFragmentation { get; set; } = TlsRecordFragmentation.Default;

    /// <summary>Gets or sets zero padding bytes added to each protected application record.</summary>
    public int ApplicationDataPaddingLength { get; set; }

    /// <summary>Gets or sets defensive allocation limits.</summary>
    public TlsLimits Limits { get; set; } = TlsLimits.Default;

    /// <summary>Gets or sets certificate-chain policy.</summary>
    public CustomTlsCertificateValidationOptions CertificateValidation { get; set; } = new();

    /// <summary>Gets or sets whether the TCP socket disables Nagle's algorithm.</summary>
    public bool TcpNoDelay { get; set; } = true;

    /// <summary>Gets or sets whether a middlebox-compatibility CCS is sent before client Finished.</summary>
    public bool SendCompatibilityChangeCipherSpec { get; set; } = true;

    /// <summary>Gets or sets whether the initial ClientHello record uses legacy version 0x0301.</summary>
    public bool UseInitialCompatibilityRecordVersion { get; set; } = true;

    /// <summary>
    /// Gets or sets the caller-owned TLS 1.3 session cache. Null disables ticket storage and resumption.
    /// Share one cache across client instances that should resume sessions.
    /// </summary>
    public Tls13SessionCache? SessionCache { get; set; }

    /// <summary>
    /// Gets or sets the maximum number of cached TLS 1.3 ticket identities offered in one
    /// ClientHello. The server may select any encoded identity; early data always uses index zero.
    /// </summary>
    public int MaximumOfferedTls13PskIdentities { get; set; } = 4;

    /// <summary>
    /// Gets or sets a caller-owned TLS 1.2 session-ID/RFC 5077 ticket cache. The current
    /// resumption path requires a TLS-1.2-only ClientHello profile.
    /// </summary>
    public Tls12SessionCache? Tls12SessionCache { get; set; }

    /// <summary>
    /// Gets or sets a caller-owned RFC 8446 external PSK. The option snapshot copies the
    /// secret, so the caller may dispose its object after constructing the client.
    /// External PSK and ticket-cache authentication are intentionally mutually exclusive.
    /// </summary>
    public Tls13ExternalPsk? ExternalPsk { get; set; }

    /// <summary>
    /// Gets or sets an explicit replay-aware TLS 1.3 early-data request. Null keeps 0-RTT disabled.
    /// </summary>
    public Tls13EarlyDataOptions? EarlyData { get; set; }

    /// <summary>
    /// Gets or sets RFC 9849 Encrypted ClientHello. Null sends the configured ClientHello directly.
    /// </summary>
    public TlsEchOptions? EncryptedClientHello { get; set; }

    /// <summary>
    /// Gets or sets RFC 9849 GREASE ECH for connections without an ECH configuration.
    /// This is mutually exclusive with <see cref="EncryptedClientHello"/>.
    /// </summary>
    public TlsEchGreaseOptions? EncryptedClientHelloGrease { get; set; }

    /// <summary>
    /// Gets or sets opaque client ALPS/application_settings payloads keyed by ALPN protocol.
    /// This experimental feature is used only when the ClientHello profile enables a supported
    /// application_settings code point. Missing entries send an empty payload.
    /// </summary>
    public IReadOnlyDictionary<string, byte[]>? ClientApplicationSettings { get; set; }

    /// <summary>
    /// Gets or sets the caller-owned RSA or ECDSA client credential used when a server requests
    /// certificate authentication. Null sends the protocol-mandated empty Certificate response.
    /// </summary>
    public TlsClientCertificate? ClientCertificate { get; set; }

    /// <summary>
    /// Gets or sets an asynchronous, cancellable credential selector invoked for each
    /// initial or post-handshake CertificateRequest. It is mutually exclusive with the
    /// static <see cref="ClientCertificate"/> property.
    /// </summary>
    public TlsClientCertificateSelector? ClientCertificateSelector { get; set; }

    /// <summary>
    /// Gets or sets a synchronous observer invoked immediately before each ClientHello is written.
    /// The observer receives a defensive copy and cannot mutate the live handshake. If it throws,
    /// the connection attempt is aborted and that ClientHello is not written.
    /// </summary>
    public Action<TlsClientHelloInspection>? ClientHelloInspector { get; set; }

    /// <summary>
    /// Gets or sets a caller-owned, explicitly dangerous NSS key-log sink. Null is the secure
    /// default. The sink receives live connection secrets suitable for Wireshark decryption.
    /// </summary>
    public TlsNssKeyLogSink? DangerousNssKeyLog { get; set; }

    /// <summary>
    /// Gets or sets a synchronous observer for immutable, secret-free handshake events.
    /// Observer exceptions abort the connection; callbacks are serialized and non-reentrant.
    /// </summary>
    public Action<TlsHandshakeEvent>? HandshakeEventObserver { get; set; }

    internal CustomTlsClientConfiguration Snapshot()
    {
        ArgumentNullException.ThrowIfNull(ClientHello);
        ArgumentNullException.ThrowIfNull(HandshakeFragmentation);
        ArgumentNullException.ThrowIfNull(ApplicationDataFragmentation);
        ArgumentNullException.ThrowIfNull(Limits);
        ArgumentNullException.ThrowIfNull(CertificateValidation);
        Limits.Validate();

        if (ServerName is not null && string.IsNullOrWhiteSpace(ServerName))
        {
            throw new ArgumentException("ServerName cannot be empty or whitespace.", nameof(ServerName));
        }
        if (ApplicationDataPaddingLength < 0 ||
            ApplicationDataPaddingLength + 1 + TlsConstants.AeadTagLength > TlsConstants.MaxCiphertextLength)
        {
            throw new ArgumentOutOfRangeException(nameof(ApplicationDataPaddingLength));
        }
        if (CertificateValidation.UrlRetrievalTimeout < TimeSpan.Zero)
        {
            throw new ArgumentOutOfRangeException(nameof(CertificateValidation.UrlRetrievalTimeout));
        }
        if (CertificateValidation.MinimumValidSignedCertificateTimestamps is < 0 or > 256)
        {
            throw new ArgumentOutOfRangeException(
                nameof(CertificateValidation.MinimumValidSignedCertificateTimestamps));
        }
        if ((CertificateValidation.RequireValidStapledOcspResponse ||
             CertificateValidation.MinimumValidSignedCertificateTimestamps != 0) &&
            CertificateValidation.EvidenceValidator is null)
        {
            throw new ArgumentException(
                "Required OCSP/SCT evidence needs an evidence validator.",
                nameof(CertificateValidation.EvidenceValidator));
        }
        if (CertificateValidation.RequireValidStapledOcspResponse &&
            !ClientHello.Spec.Extensions.Any(extension =>
                extension.RawExtensionType == (ushort)TlsExtensionType.StatusRequest))
        {
            throw new ArgumentException(
                "Required stapled OCSP needs a status_request ClientHello extension.",
                nameof(CertificateValidation.RequireValidStapledOcspResponse));
        }
        if (CertificateValidation.MinimumValidSignedCertificateTimestamps != 0 &&
            !ClientHello.Spec.Extensions.Any(extension =>
                extension.RawExtensionType ==
                    (ushort)TlsExtensionType.SignedCertificateTimestamp))
        {
            throw new ArgumentException(
                "Required SCT validation needs a signed_certificate_timestamp ClientHello extension.",
                nameof(CertificateValidation.MinimumValidSignedCertificateTimestamps));
        }
        if (ClientCertificate is not null && ClientCertificateSelector is not null)
        {
            throw new ArgumentException(
                "Configure either a static client certificate or a dynamic selector, not both.",
                nameof(ClientCertificateSelector));
        }

        var offeredVersions = ClientHello.Spec.SupportedVersions;
        if (!offeredVersions.Contains(TlsProtocolVersion.Tls13) &&
            !offeredVersions.Contains(TlsProtocolVersion.Tls12))
        {
            throw new NotSupportedException("SharpTls requires a ClientHello that offers TLS 1.3 or TLS 1.2.");
        }
        if (offeredVersions.Contains(TlsProtocolVersion.Tls12))
        {
            ValidateTls12Offer(ClientHello.Spec);
        }
        if (!offeredVersions.Contains(TlsProtocolVersion.Tls13) && ApplicationDataPaddingLength != 0)
        {
            throw new ArgumentException(
                "TLS 1.2 AEAD records do not support TLS 1.3-style application padding.",
                nameof(ApplicationDataPaddingLength));
        }
        if (SessionCache is not null && !ClientHello.Spec.SupportsSessionResumption)
        {
            throw new ArgumentException(
                "A session cache requires a ClientHello profile with an executable pre_shared_key slot.",
                nameof(SessionCache));
        }
        if (MaximumOfferedTls13PskIdentities is < 1 or > 64)
        {
            throw new ArgumentOutOfRangeException(
                nameof(MaximumOfferedTls13PskIdentities),
                "Between 1 and 64 TLS 1.3 PSK identities may be offered.");
        }
        if (Tls12SessionCache is not null &&
            (offeredVersions.Count != 1 || offeredVersions[0] != TlsProtocolVersion.Tls12))
        {
            throw new ArgumentException(
                "TLS 1.2 session-ID resumption currently requires a TLS-1.2-only ClientHello profile.",
                nameof(Tls12SessionCache));
        }
        if (ExternalPsk is not null)
        {
            if (SessionCache is not null)
            {
                throw new ArgumentException(
                    "External PSK and ticket-cache resumption cannot be selected together.",
                    nameof(ExternalPsk));
            }
            if (!ClientHello.Spec.SupportsSessionResumption)
            {
                throw new ArgumentException(
                    "An external PSK requires a ClientHello profile with an executable pre_shared_key slot.",
                    nameof(ExternalPsk));
            }
            if (offeredVersions.Count != 1 || offeredVersions[0] != TlsProtocolVersion.Tls13)
            {
                throw new ArgumentException(
                    "External PSK authentication requires a TLS-1.3-only ClientHello profile.",
                    nameof(ExternalPsk));
            }
            if (!ClientHello.Spec.CipherSuites.Contains(ExternalPsk.CipherSuite))
            {
                throw new ArgumentException(
                    "The ClientHello must offer the external PSK's hash-bound cipher suite.",
                    nameof(ExternalPsk));
            }
        }
        if (EarlyData is not null)
        {
            if (SessionCache is null || !ClientHello.Spec.SupportsEarlyData)
            {
                throw new ArgumentException(
                    "TLS early data requires a session cache and a profile with an early_data slot.",
                    nameof(EarlyData));
            }
            if (offeredVersions.Count != 1 || offeredVersions[0] != TlsProtocolVersion.Tls13)
            {
                throw new ArgumentException(
                    "TLS early data requires a TLS-1.3-only ClientHello profile.",
                    nameof(EarlyData));
            }
            if (EarlyData.Length > Limits.MaxEarlyDataSize)
            {
                throw new ArgumentOutOfRangeException(
                    nameof(EarlyData),
                    "TLS early data exceeds the configured defensive limit.");
            }
        }

        var clientApplicationSettings = SnapshotApplicationSettings(ClientHello.Spec);
        var ech = SnapshotEchConfiguration(ClientHello.Spec);
        var echGrease = SnapshotEchGreaseConfiguration(ClientHello.Spec);

        X509Certificate2Collection? roots = null;
        Tls13ExternalPskConfiguration? externalPsk = null;
        try
        {
            externalPsk = ExternalPsk?.Snapshot();
            if (CertificateValidation.CustomTrustRoots is { Count: > 0 } configuredRoots)
            {
                roots = new X509Certificate2Collection();
                foreach (var root in configuredRoots)
                {
                    ArgumentNullException.ThrowIfNull(root);
                    roots.Add(X509CertificateLoader.LoadCertificate(root.RawData));
                }
            }

            var certificatePolicy = new CertificateValidationPolicy(
                CertificateValidation.RevocationMode,
                CertificateValidation.RevocationFlag,
                CertificateValidation.DisableCertificateDownloads,
                CertificateValidation.UrlRetrievalTimeout,
                roots,
                CertificateValidation.EvidenceValidator,
                CertificateValidation.RequireValidStapledOcspResponse,
                CertificateValidation.MinimumValidSignedCertificateTimestamps,
                CertificateValidation.AllowUnknownRevocationStatus,
                CertificateValidation.DangerouslySkipServerCertificateValidation);

            return new CustomTlsClientConfiguration(
                ServerName,
                ClientHello,
                HandshakeFragmentation,
                ApplicationDataFragmentation,
                ApplicationDataPaddingLength,
                Limits with { },
                certificatePolicy,
                TcpNoDelay,
                SendCompatibilityChangeCipherSpec,
                UseInitialCompatibilityRecordVersion,
                SessionCache,
                MaximumOfferedTls13PskIdentities,
                Tls12SessionCache,
                externalPsk,
                EarlyData?.Snapshot(),
                ech,
                echGrease,
                clientApplicationSettings,
                ClientCertificate,
                ClientCertificateSelector,
                ClientHelloInspector,
                DangerousNssKeyLog,
                HandshakeEventObserver);
        }
        catch
        {
            if (roots is not null)
            {
                foreach (var root in roots)
                {
                    root.Dispose();
                }
            }
            externalPsk?.Dispose();
            throw;
        }
    }

    private TlsEchClientConfiguration? SnapshotEchConfiguration(ClientHelloSpec innerSpec)
    {
        if (EncryptedClientHello is null)
        {
            return null;
        }

        ArgumentNullException.ThrowIfNull(EncryptedClientHello.ConfigList);
        ArgumentNullException.ThrowIfNull(EncryptedClientHello.OuterClientHello);
        if (innerSpec.SupportedVersions.Count != 1 ||
            innerSpec.SupportedVersions[0] != TlsProtocolVersion.Tls13)
        {
            throw new ArgumentException(
                "RFC 9849 ClientHelloInner must be TLS-1.3-only.",
                nameof(EncryptedClientHello));
        }

        var outer = EncryptedClientHello.OuterClientHello;
        var outerSpec = outer.Spec;
        if (outerSpec.SupportedVersions.Count != 1 ||
            outerSpec.SupportedVersions[0] != TlsProtocolVersion.Tls13)
        {
            throw new ArgumentException(
                "The current ECH connection path requires a TLS-1.3-only ClientHelloOuter.",
                nameof(EncryptedClientHello));
        }
        if (!innerSpec.IncludeSni || !outerSpec.IncludeSni)
        {
            throw new ArgumentException(
                "ECH requires semantic SNI slots in ClientHelloInner and ClientHelloOuter.",
                nameof(EncryptedClientHello));
        }
        if (outerSpec.ApplicationSettingsCodePoint.HasValue)
        {
            throw new ArgumentException(
                "ClientHelloOuter application_settings is disabled because rejected connections cannot expose application state.",
                nameof(EncryptedClientHello));
        }
        if (SessionCache is not null && !outerSpec.SupportsSessionResumption)
        {
            throw new ArgumentException(
                "ECH resumption requires conditional psk_dhe_ke, early_data, and final pre_shared_key slots in ClientHelloOuter for GREASE PSK.",
                nameof(EncryptedClientHello));
        }
        if (EarlyData is not null && !outerSpec.SupportsEarlyData)
        {
            throw new ArgumentException(
                "ECH early data requires a conditional early_data slot in ClientHelloOuter.",
                nameof(EncryptedClientHello));
        }
        if (innerSpec.Extensions.Concat(outerSpec.Extensions).Any(extension =>
            extension.RawExtensionType == (ushort)TlsExtensionType.EncryptedClientHello))
        {
            throw new ArgumentException(
                "ECH owns encrypted_client_hello; profiles cannot supply it as a raw extension.",
                nameof(EncryptedClientHello));
        }
        if (innerSpec.Extensions.Concat(outerSpec.Extensions).Any(extension =>
            extension.RawExtensionType == (ushort)TlsExtensionType.EchOuterExtensions))
        {
            throw new ArgumentException(
                "ech_outer_extensions exists only in EncodedClientHelloInner and cannot be supplied by a profile.",
                nameof(EncryptedClientHello));
        }
        if (innerSpec.SupportedGroups.Any(group =>
            !outerSpec.SupportedGroups.Contains(group)))
        {
            throw new ArgumentException(
                "ClientHelloOuter must support every group that ClientHelloInner can select through HelloRetryRequest.",
                nameof(EncryptedClientHello));
        }

        var configList = TlsEchConfigList.Parse(
            EncryptedClientHello.ConfigList.GetEncodedList());
        var selection = configList.SelectSupportedConfiguration() ??
            throw new NotSupportedException(
                "ECHConfigList has no executable HPKE configuration and cipher suite.");
        ArgumentNullException.ThrowIfNull(EncryptedClientHello.CompressedOuterExtensions);
        var compressedOuterExtensions =
            EncryptedClientHello.CompressedOuterExtensions.ToArray();
        if (compressedOuterExtensions.Length > 127 ||
            compressedOuterExtensions.Distinct().Count() !=
                compressedOuterExtensions.Length)
        {
            throw new ArgumentException(
                "ECH outer-extension compression accepts at most 127 distinct extension types.",
                nameof(EncryptedClientHello));
        }
        if (compressedOuterExtensions.Any(type => type is
            TlsExtensionType.EncryptedClientHello or
            TlsExtensionType.EchOuterExtensions or
            TlsExtensionType.ServerName or
            TlsExtensionType.PreSharedKey))
        {
            throw new ArgumentException(
                "ECH compression cannot reference encrypted_client_hello, ech_outer_extensions, server_name, or pre_shared_key.",
                nameof(EncryptedClientHello));
        }
        ValidateCompressedOuterExtensionLayout(
            innerSpec,
            outerSpec,
            compressedOuterExtensions);
        var encodedConfigList = configList.GetEncodedList();
        byte[]? configListHash = null;
        try
        {
            configListHash = SHA256.HashData(encodedConfigList);
            var result = new TlsEchClientConfiguration(
                configList,
                selection,
                outer,
                compressedOuterExtensions,
                configListHash);
            configListHash = null;
            return result;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(encodedConfigList);
            if (configListHash is not null)
            {
                CryptographicOperations.ZeroMemory(configListHash);
            }
        }
    }

    private static void ValidateCompressedOuterExtensionLayout(
        ClientHelloSpec inner,
        ClientHelloSpec outer,
        IReadOnlyList<TlsExtensionType> compressed)
    {
        if (compressed.Count == 0)
        {
            return;
        }

        var innerTypes = GetConfiguredExtensionTypes(inner);
        var outerTypes = GetConfiguredExtensionTypes(outer);
        var innerIndices = compressed
            .Select(type => Array.IndexOf(innerTypes, (ushort)type))
            .ToArray();
        var outerIndices = compressed
            .Select(type => Array.IndexOf(outerTypes, (ushort)type))
            .ToArray();
        if (innerIndices.Any(index => index < 0) || outerIndices.Any(index => index < 0))
        {
            throw new ArgumentException(
                "Every compressed ECH extension must have a configured inner and outer slot.",
                nameof(EncryptedClientHello));
        }
        for (var index = 1; index < compressed.Count; index++)
        {
            if (innerIndices[index] != innerIndices[0] + index ||
                outerIndices[index] <= outerIndices[index - 1])
            {
                throw new ArgumentException(
                    "Compressed ECH extensions must be contiguous in ClientHelloInner and retain relative order in ClientHelloOuter.",
                    nameof(EncryptedClientHello));
            }
        }
    }

    private static ushort?[] GetConfiguredExtensionTypes(ClientHelloSpec spec) =>
        spec.Extensions.Select(extension => extension.RawExtensionType ??
            extension.BuiltInKind switch
            {
                ClientHelloExtensionKind.ServerName => (ushort)TlsExtensionType.ServerName,
                ClientHelloExtensionKind.SupportedVersions =>
                    (ushort)TlsExtensionType.SupportedVersions,
                ClientHelloExtensionKind.Cookie => (ushort)TlsExtensionType.Cookie,
                ClientHelloExtensionKind.SupportedGroups =>
                    (ushort)TlsExtensionType.SupportedGroups,
                ClientHelloExtensionKind.SignatureAlgorithms =>
                    (ushort)TlsExtensionType.SignatureAlgorithms,
                ClientHelloExtensionKind.SignatureAlgorithmsCert =>
                    (ushort)TlsExtensionType.SignatureAlgorithmsCert,
                ClientHelloExtensionKind.KeyShare => (ushort)TlsExtensionType.KeyShare,
                ClientHelloExtensionKind.PskKeyExchangeModes =>
                    (ushort)TlsExtensionType.PskKeyExchangeModes,
                ClientHelloExtensionKind.EarlyData => (ushort)TlsExtensionType.EarlyData,
                ClientHelloExtensionKind.PreSharedKey =>
                    (ushort)TlsExtensionType.PreSharedKey,
                ClientHelloExtensionKind.ApplicationLayerProtocolNegotiation =>
                    (ushort)TlsExtensionType.ApplicationLayerProtocolNegotiation,
                ClientHelloExtensionKind.ApplicationSettings =>
                    (ushort?)spec.ApplicationSettingsCodePoint,
                ClientHelloExtensionKind.PostHandshakeAuthentication =>
                    (ushort)TlsExtensionType.PostHandshakeAuthentication,
                ClientHelloExtensionKind.RecordSizeLimit =>
                    (ushort)TlsExtensionType.RecordSizeLimit,
                ClientHelloExtensionKind.DelegatedCredential =>
                    (ushort)TlsExtensionType.DelegatedCredential,
                ClientHelloExtensionKind.Padding => (ushort)TlsExtensionType.Padding,
                _ => null,
            }).ToArray();

    private TlsEchGreaseConfiguration? SnapshotEchGreaseConfiguration(
        ClientHelloSpec spec)
    {
        var configuredGrease = EncryptedClientHelloGrease;
        if (configuredGrease is null && EncryptedClientHello is null &&
            spec.GreaseEncryptedClientHello)
        {
            configuredGrease = new TlsEchGreaseOptions
            {
                CipherSuites = spec.GreaseEchCipherSuites,
                PayloadLengths = spec.GreaseEchPayloadLengths.Count == 0
                    ? null
                    : spec.GreaseEchPayloadLengths.ToArray(),
            };
        }
        if (configuredGrease is null)
        {
            return null;
        }
        if (EncryptedClientHello is not null)
        {
            throw new ArgumentException(
                "Real ECH and GREASE ECH cannot be enabled on the same connection.",
                nameof(EncryptedClientHelloGrease));
        }
        if (!spec.SupportedVersions.Contains(TlsProtocolVersion.Tls13))
        {
            throw new ArgumentException(
                "GREASE ECH requires a TLS 1.3-capable ClientHello.",
                nameof(EncryptedClientHelloGrease));
        }
        if (spec.Extensions.Any(extension =>
            extension.RawExtensionType == (ushort)TlsExtensionType.EncryptedClientHello))
        {
            throw new ArgumentException(
                "GREASE ECH owns encrypted_client_hello; the profile cannot supply it.",
                nameof(EncryptedClientHelloGrease));
        }

        ArgumentNullException.ThrowIfNull(configuredGrease.CipherSuites);
        var suites = configuredGrease.CipherSuites.ToArray();
        if (suites.Length is 0 or > byte.MaxValue || suites.Distinct().Count() != suites.Length)
        {
            throw new ArgumentException(
                "GREASE ECH requires between 1 and 255 distinct HPKE suites.",
                nameof(EncryptedClientHelloGrease));
        }
        foreach (var suite in suites)
        {
            if (suite.KdfId is not (TlsHpkeKdfId.HkdfSha256 or
                TlsHpkeKdfId.HkdfSha384 or TlsHpkeKdfId.HkdfSha512) ||
                suite.AeadId is not (TlsHpkeAeadId.Aes128Gcm or
                    TlsHpkeAeadId.Aes256Gcm or TlsHpkeAeadId.ChaCha20Poly1305))
            {
                throw new NotSupportedException(
                    "GREASE ECH was configured with an unsupported HPKE suite.");
            }
            if (suite.AeadId == TlsHpkeAeadId.ChaCha20Poly1305 &&
                !ChaCha20Poly1305.IsSupported)
            {
                throw new PlatformNotSupportedException(
                    "GREASE ECH ChaCha20-Poly1305 is unavailable on this platform.");
            }
        }
        var payloadLengths = configuredGrease.PayloadLengths?.ToArray();
        if (payloadLengths is not null &&
            (payloadLengths.Length == 0 ||
             payloadLengths.Length > byte.MaxValue ||
             payloadLengths.Distinct().Count() != payloadLengths.Length ||
             payloadLengths.Any(length => length is < 1 or > ushort.MaxValue - 16)))
        {
            throw new ArgumentOutOfRangeException(
                nameof(EncryptedClientHelloGrease),
                "GREASE ECH accepts 1 to 255 distinct payload lengths that leave room for the AEAD tag.");
        }

        return new TlsEchGreaseConfiguration(suites, payloadLengths);
    }

    private Dictionary<string, byte[]> SnapshotApplicationSettings(ClientHelloSpec spec)
    {
        if (!spec.ApplicationSettingsCodePoint.HasValue)
        {
            if (ClientApplicationSettings is { Count: > 0 })
            {
                throw new ArgumentException(
                    "Client application settings require a semantic application_settings ClientHello extension.",
                    nameof(ClientApplicationSettings));
            }
            return new Dictionary<string, byte[]>(StringComparer.Ordinal);
        }

        var result = new Dictionary<string, byte[]>(StringComparer.Ordinal);
        if (ClientApplicationSettings is null)
        {
            return result;
        }
        foreach (var pair in ClientApplicationSettings)
        {
            if (pair.Key is null ||
                !spec.ApplicationSettingsProtocols.Contains(pair.Key, StringComparer.Ordinal))
            {
                throw new ArgumentException(
                    "Client application-settings keys must be advertised application protocols.",
                    nameof(ClientApplicationSettings));
            }
            ArgumentNullException.ThrowIfNull(pair.Value);
            if (pair.Value.Length > ushort.MaxValue)
            {
                throw new ArgumentOutOfRangeException(
                    nameof(ClientApplicationSettings),
                    "An application-settings payload cannot exceed 65535 bytes.");
            }
            result.Add(pair.Key, (byte[])pair.Value.Clone());
        }
        return result;
    }

    private static void ValidateTls12Offer(ClientHelloSpec spec)
    {
        var hasExtendedMasterSecret = HasRawExtension(spec, 23, []);
        var hasSecureRenegotiation = HasRawExtension(spec, 0xFF01, [0]);
        if (!hasExtendedMasterSecret || !hasSecureRenegotiation)
        {
            throw new ArgumentException(
                "TLS 1.2 ClientHello profiles must offer empty extended_master_secret and initial secure renegotiation_info.",
                nameof(ClientHello));
        }

        var hasExecutableSuite = spec.CipherSuites.Any(suite =>
        {
            try
            {
                _ = Cryptography.Tls12CipherSuiteInfo.Get(suite);
                return true;
            }
            catch (NotSupportedException)
            {
                return false;
            }
        });
        if (!hasExecutableSuite)
        {
            throw new ArgumentException(
                "TLS 1.2 ClientHello profiles must offer at least one executable ECDHE AEAD suite.",
                nameof(ClientHello));
        }
    }

    private static bool HasRawExtension(
        ClientHelloSpec spec,
        ushort type,
        ReadOnlySpan<byte> expectedBody)
    {
        foreach (var extension in spec.Extensions)
        {
            if (extension.RawExtensionType == type &&
                extension.GetRawData().AsSpan().SequenceEqual(expectedBody))
            {
                return true;
            }
        }

        return false;
    }
}

internal sealed record CustomTlsClientConfiguration(
    string? ServerName,
    ClientHelloProfile ClientHello,
    TlsRecordFragmentation HandshakeFragmentation,
    TlsRecordFragmentation ApplicationDataFragmentation,
    int ApplicationDataPaddingLength,
    TlsLimits Limits,
    CertificateValidationPolicy CertificateValidation,
    bool TcpNoDelay,
    bool SendCompatibilityChangeCipherSpec,
    bool UseInitialCompatibilityRecordVersion,
    Tls13SessionCache? SessionCache,
    int MaximumOfferedTls13PskIdentities,
    Tls12SessionCache? Tls12SessionCache,
    Tls13ExternalPskConfiguration? ExternalPsk,
    Tls13EarlyDataConfiguration? EarlyData,
    TlsEchClientConfiguration? Ech,
    TlsEchGreaseConfiguration? EchGrease,
    Dictionary<string, byte[]> ClientApplicationSettings,
    TlsClientCertificate? ClientCertificate,
    TlsClientCertificateSelector? ClientCertificateSelector,
    Action<TlsClientHelloInspection>? ClientHelloInspector,
    TlsNssKeyLogSink? DangerousNssKeyLog,
    Action<TlsHandshakeEvent>? HandshakeEventObserver) : IDisposable
{
    internal byte[] GetClientApplicationSettings(string protocol) =>
        ClientApplicationSettings.TryGetValue(protocol, out var settings)
            ? (byte[])settings.Clone()
            : [];

    public void Dispose()
    {
        ExternalPsk?.Dispose();
        EarlyData?.Dispose();
        Ech?.Dispose();
        foreach (var settings in ClientApplicationSettings.Values)
        {
            CryptographicOperations.ZeroMemory(settings);
        }
        ClientApplicationSettings.Clear();
        if (CertificateValidation.CustomTrustRoots is not { } roots)
        {
            return;
        }

        foreach (var root in roots)
        {
            root.Dispose();
        }
    }
}
