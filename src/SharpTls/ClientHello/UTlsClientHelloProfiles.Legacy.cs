using SharpTls.Protocol;

namespace SharpTls;

public static partial class ClientHelloProfiles
{
    /// <summary>Gets the pinned legacy uTLS HelloChrome_58 profile.</summary>
    public static ClientHelloProfile UTlsChrome58 { get; } = CreateUTlsChrome58();

    /// <summary>Gets uTLS HelloChrome_62, whose pinned specification equals Chrome 58.</summary>
    public static ClientHelloProfile UTlsChrome62 { get; } = UTlsChrome58;

    /// <summary>Gets the pinned uTLS HelloChrome_70 profile.</summary>
    public static ClientHelloProfile UTlsChrome70 { get; } = CreateUTlsChrome70();

    /// <summary>Gets the pinned uTLS HelloChrome_72 profile.</summary>
    public static ClientHelloProfile UTlsChrome72 { get; } = CreateUTlsChrome72();

    /// <summary>Gets the pinned legacy uTLS HelloFirefox_55 profile.</summary>
    public static ClientHelloProfile UTlsFirefox55 { get; } = CreateUTlsFirefox55();

    /// <summary>Gets uTLS HelloFirefox_56, whose pinned specification equals Firefox 55.</summary>
    public static ClientHelloProfile UTlsFirefox56 { get; } = UTlsFirefox55;

    /// <summary>Gets the pinned uTLS HelloFirefox_63 profile.</summary>
    public static ClientHelloProfile UTlsFirefox63 { get; } = CreateUTlsFirefox63();

    /// <summary>Gets uTLS HelloFirefox_65, whose pinned specification equals Firefox 63.</summary>
    public static ClientHelloProfile UTlsFirefox65 { get; } = UTlsFirefox63;

    /// <summary>Gets the pinned legacy uTLS HelloIOS_11_1 profile.</summary>
    public static ClientHelloProfile UTlsIOS11_1 { get; } = CreateUTlsIOS11_1();

    /// <summary>Gets the pinned legacy uTLS HelloIOS_12_1 profile.</summary>
    public static ClientHelloProfile UTlsIOS12_1 { get; } = CreateUTlsIOS12_1();

    /// <summary>
    /// Gets the pinned uTLS Hello360_7_5 wire profile. Its obsolete suites remain
    /// fingerprint-only and cannot be selected by the SharpTls record engine.
    /// </summary>
    public static ClientHelloProfile UTls360_7_5 { get; } = CreateUTls360_7_5();

    /// <summary>Gets the pinned uTLS Hello360_11_0 profile.</summary>
    public static ClientHelloProfile UTls360_11_0 { get; } = CreateUTls360_11_0();

    /// <summary>
    /// Gets the newest securely executable pinned 360 profile. Use
    /// <see cref="UTls360_7_5"/> explicitly for its wire-only historical image.
    /// </summary>
    public static ClientHelloProfile UTls360Auto => UTls360_11_0;

    /// <summary>Gets the pinned uTLS HelloQQ_11_1 profile.</summary>
    public static ClientHelloProfile UTlsQQ11_1 { get; } = CreateUTlsQQ11_1();

    /// <summary>Gets the upstream uTLS QQ Auto alias.</summary>
    public static ClientHelloProfile UTlsQQAuto => UTlsQQ11_1;

    private static ClientHelloProfile CreateUTlsChrome58() => Custom(builder => builder
        .WithLegacyTls12ClientHello()
        .WithGrease(CreateBoringGreasePolicy())
        .WithSecondaryGreaseExtension([])
        .WithCipherSuites(LegacyChromiumCipherSuites(includeTls13: false))
        .WithSupportedGroups(NamedGroup.X25519, NamedGroup.Secp256r1, NamedGroup.Secp384r1)
        .WithSignatureAlgorithms(ChromiumLegacySignatureAlgorithms())
        .WithAlpn("h2", "http/1.1")
        .WithBoringPadding()
        .WithExtensionLayout(
            ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.Grease),
            ClientHelloExtensionSpec.Raw(0xFF01, [0]),
            ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.ServerName),
            ClientHelloExtensionSpec.Raw(23, []),
            ClientHelloExtensionSpec.Raw(35, []),
            ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.SignatureAlgorithms),
            ClientHelloExtensionSpec.Raw(5, [1, 0, 0, 0, 0]),
            ClientHelloExtensionSpec.Raw(18, []),
            ClientHelloExtensionSpec.BuiltIn(
                ClientHelloExtensionKind.ApplicationLayerProtocolNegotiation),
            ClientHelloExtensionSpec.Raw(30032, []),
            ClientHelloExtensionSpec.Raw(11, [1, 0]),
            ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.SupportedGroups),
            ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.SecondaryGrease),
            ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.Padding)));

    private static ClientHelloProfile CreateUTlsChrome70() => Custom(builder => builder
        .WithGrease(CreateBoringGreasePolicy())
        .WithGreaseKeyShareBody([0])
        .WithSecondaryGreaseExtension([])
        .WithCipherSuites(LegacyChromiumCipherSuites(includeTls13: true))
        .WithSupportedVersions(
            TlsProtocolVersion.Tls13,
            TlsProtocolVersion.Tls12,
            TlsProtocolVersion.Tls11,
            TlsProtocolVersion.Tls10)
        .WithSupportedGroups(NamedGroup.X25519, NamedGroup.Secp256r1, NamedGroup.Secp384r1)
        .WithKeyShares(NamedGroup.X25519)
        .WithSignatureAlgorithms(ChromiumLegacySignatureAlgorithms())
        .WithAlpn("h2", "http/1.1")
        .WithBoringPadding()
        .WithExtensionLayout(
            ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.Grease),
            ClientHelloExtensionSpec.Raw(0xFF01, [0]),
            ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.ServerName),
            ClientHelloExtensionSpec.Raw(23, []),
            ClientHelloExtensionSpec.Raw(35, []),
            ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.SignatureAlgorithms),
            ClientHelloExtensionSpec.Raw(5, [1, 0, 0, 0, 0]),
            ClientHelloExtensionSpec.Raw(18, []),
            ClientHelloExtensionSpec.BuiltIn(
                ClientHelloExtensionKind.ApplicationLayerProtocolNegotiation),
            ClientHelloExtensionSpec.Raw(30032, []),
            ClientHelloExtensionSpec.Raw(11, [1, 0]),
            ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.KeyShare),
            ClientHelloExtensionSpec.Raw((ushort)TlsExtensionType.PskKeyExchangeModes, [1, 1]),
            ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.SupportedVersions),
            ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.SupportedGroups),
            ClientHelloExtensionSpec.Raw(27, [2, 0, 2]),
            ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.SecondaryGrease),
            ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.Padding),
            ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.EarlyData),
            ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.PreSharedKey)));

    private static ClientHelloProfile CreateUTlsChrome72() => Custom(builder => builder
        .WithGrease(CreateBoringGreasePolicy())
        .WithGreaseKeyShareBody([0])
        .WithSecondaryGreaseExtension([])
        .WithCipherSuites(LegacyChromiumCipherSuites(includeTls13: true))
        .WithSupportedVersions(
            TlsProtocolVersion.Tls13,
            TlsProtocolVersion.Tls12,
            TlsProtocolVersion.Tls11,
            TlsProtocolVersion.Tls10)
        .WithSupportedGroups(NamedGroup.X25519, NamedGroup.Secp256r1, NamedGroup.Secp384r1)
        .WithKeyShares(NamedGroup.X25519)
        .WithSignatureAlgorithms(ChromiumLegacySignatureAlgorithms())
        .WithAlpn("h2", "http/1.1")
        .WithBoringPadding()
        .WithExtensionLayout(
            ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.Grease),
            ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.ServerName),
            ClientHelloExtensionSpec.Raw(23, []),
            ClientHelloExtensionSpec.Raw(0xFF01, [0]),
            ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.SupportedGroups),
            ClientHelloExtensionSpec.Raw(11, [1, 0]),
            ClientHelloExtensionSpec.Raw(35, []),
            ClientHelloExtensionSpec.BuiltIn(
                ClientHelloExtensionKind.ApplicationLayerProtocolNegotiation),
            ClientHelloExtensionSpec.Raw(5, [1, 0, 0, 0, 0]),
            ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.SignatureAlgorithms),
            ClientHelloExtensionSpec.Raw(18, []),
            ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.KeyShare),
            ClientHelloExtensionSpec.Raw((ushort)TlsExtensionType.PskKeyExchangeModes, [1, 1]),
            ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.SupportedVersions),
            ClientHelloExtensionSpec.Raw(27, [2, 0, 2]),
            ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.SecondaryGrease),
            ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.Padding),
            ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.EarlyData),
            ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.PreSharedKey)));

    private static ClientHelloProfile CreateUTlsFirefox55() => Custom(builder => builder
        .WithLegacyTls12ClientHello()
        .WithSessionId([])
        .WithCipherSuites(LegacyFirefoxCipherSuites(includeTls13: false))
        .WithSupportedGroups(
            NamedGroup.X25519,
            NamedGroup.Secp256r1,
            NamedGroup.Secp384r1,
            NamedGroup.Secp521r1)
        .WithSignatureAlgorithms(FirefoxLegacySignatureAlgorithms())
        .WithAlpn("h2", "http/1.1")
        .WithBoringPadding()
        .WithExtensionLayout(
            ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.ServerName),
            ClientHelloExtensionSpec.Raw(23, []),
            ClientHelloExtensionSpec.Raw(0xFF01, [0]),
            ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.SupportedGroups),
            ClientHelloExtensionSpec.Raw(11, [1, 0]),
            ClientHelloExtensionSpec.Raw(35, []),
            ClientHelloExtensionSpec.BuiltIn(
                ClientHelloExtensionKind.ApplicationLayerProtocolNegotiation),
            ClientHelloExtensionSpec.Raw(5, [1, 0, 0, 0, 0]),
            ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.SignatureAlgorithms),
            ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.Padding)));

    private static ClientHelloProfile CreateUTlsFirefox63() => Custom(builder => builder
        .WithCipherSuites(LegacyFirefoxCipherSuites(includeTls13: true))
        .WithSupportedVersions(
            TlsProtocolVersion.Tls13,
            TlsProtocolVersion.Tls12,
            TlsProtocolVersion.Tls11,
            TlsProtocolVersion.Tls10)
        .WithSupportedGroups(
            NamedGroup.X25519,
            NamedGroup.Secp256r1,
            NamedGroup.Secp384r1,
            NamedGroup.Secp521r1,
            NamedGroup.Ffdhe2048,
            NamedGroup.Ffdhe3072)
        .WithKeyShares(NamedGroup.X25519, NamedGroup.Secp256r1)
        .WithSignatureAlgorithms(FirefoxLegacySignatureAlgorithms())
        .WithAlpn("h2", "http/1.1")
        .WithRecordSizeLimit(TlsConstants.MaxPlaintextLength + 1)
        .WithBoringPadding()
        .WithExtensionLayout(
            ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.ServerName),
            ClientHelloExtensionSpec.Raw(23, []),
            ClientHelloExtensionSpec.Raw(0xFF01, [0]),
            ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.SupportedGroups),
            ClientHelloExtensionSpec.Raw(11, [1, 0]),
            ClientHelloExtensionSpec.Raw(35, []),
            ClientHelloExtensionSpec.BuiltIn(
                ClientHelloExtensionKind.ApplicationLayerProtocolNegotiation),
            ClientHelloExtensionSpec.Raw(5, [1, 0, 0, 0, 0]),
            ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.KeyShare),
            ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.SupportedVersions),
            ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.SignatureAlgorithms),
            ClientHelloExtensionSpec.Raw((ushort)TlsExtensionType.PskKeyExchangeModes, [1, 1]),
            ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.RecordSizeLimit),
            ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.Padding),
            ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.EarlyData),
            ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.PreSharedKey)));

    private static ClientHelloProfile CreateUTlsIOS11_1() => Custom(builder => builder
        .WithLegacyTls12ClientHello()
        .WithCipherSuites(LegacyAppleCipherSuites(includeThreeDes: false))
        .WithSupportedGroups(
            NamedGroup.X25519,
            NamedGroup.Secp256r1,
            NamedGroup.Secp384r1,
            NamedGroup.Secp521r1)
        .WithSignatureAlgorithms(ChromiumLegacySignatureAlgorithms())
        .WithAlpn("h2", "h2-16", "h2-15", "h2-14", "spdy/3.1", "spdy/3", "http/1.1")
        .WithExtensionLayout(
            ClientHelloExtensionSpec.Raw(0xFF01, [0]),
            ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.ServerName),
            ClientHelloExtensionSpec.Raw(23, []),
            ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.SignatureAlgorithms),
            ClientHelloExtensionSpec.Raw(5, [1, 0, 0, 0, 0]),
            ClientHelloExtensionSpec.Raw(13172, []),
            ClientHelloExtensionSpec.Raw(18, []),
            ClientHelloExtensionSpec.BuiltIn(
                ClientHelloExtensionKind.ApplicationLayerProtocolNegotiation),
            ClientHelloExtensionSpec.Raw(11, [1, 0]),
            ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.SupportedGroups)));

    private static ClientHelloProfile CreateUTlsIOS12_1() => Custom(builder => builder
        .WithLegacyTls12ClientHello()
        .WithCipherSuites(LegacyAppleCipherSuites(includeThreeDes: true))
        .WithSupportedGroups(
            NamedGroup.X25519,
            NamedGroup.Secp256r1,
            NamedGroup.Secp384r1,
            NamedGroup.Secp521r1)
        .WithSignatureAlgorithms(
            SignatureScheme.EcdsaSecp256r1Sha256,
            SignatureScheme.RsaPssRsaeSha256,
            SignatureScheme.RsaPkcs1Sha256,
            SignatureScheme.EcdsaSecp384r1Sha384,
            SignatureScheme.EcdsaSha1,
            SignatureScheme.RsaPssRsaeSha384,
            SignatureScheme.RsaPssRsaeSha384,
            SignatureScheme.RsaPkcs1Sha384,
            SignatureScheme.RsaPssRsaeSha512,
            SignatureScheme.RsaPkcs1Sha512,
            SignatureScheme.RsaPkcs1Sha1)
        .AllowDuplicateSignatureAlgorithms()
        .WithAlpn("h2", "h2-16", "h2-15", "h2-14", "spdy/3.1", "spdy/3", "http/1.1")
        .WithExtensionLayout(
            ClientHelloExtensionSpec.Raw(0xFF01, [0]),
            ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.ServerName),
            ClientHelloExtensionSpec.Raw(23, []),
            ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.SignatureAlgorithms),
            ClientHelloExtensionSpec.Raw(5, [1, 0, 0, 0, 0]),
            ClientHelloExtensionSpec.Raw(13172, []),
            ClientHelloExtensionSpec.Raw(18, []),
            ClientHelloExtensionSpec.BuiltIn(
                ClientHelloExtensionKind.ApplicationLayerProtocolNegotiation),
            ClientHelloExtensionSpec.Raw(11, [1, 0]),
            ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.SupportedGroups)));

    private static ClientHelloProfile CreateUTls360_7_5() => Custom(builder => builder
        .WithLegacyTls12ClientHello()
        .WithCipherSuites(
            TlsCipherSuite.TlsEcdheEcdsaWithAes256CbcSha,
            TlsCipherSuite.TlsEcdheRsaWithAes256CbcSha,
            TlsCipherSuite.TlsDheRsaWithAes256CbcSha,
            TlsCipherSuite.TlsDheRsaWithAes256CbcSha256,
            TlsCipherSuite.TlsRsaWithAes256CbcSha,
            TlsCipherSuite.TlsRsaWithAes256CbcSha256,
            TlsCipherSuite.TlsEcdheEcdsaWithRc4_128Sha,
            TlsCipherSuite.TlsEcdheEcdsaWithAes128CbcSha,
            TlsCipherSuite.TlsEcdheEcdsaWithAes128CbcSha256,
            TlsCipherSuite.TlsEcdheRsaWithRc4_128Sha,
            TlsCipherSuite.TlsEcdheRsaWithAes128CbcSha,
            TlsCipherSuite.TlsEcdheRsaWithAes128CbcSha256,
            TlsCipherSuite.TlsDheRsaWithAes128CbcSha,
            TlsCipherSuite.TlsDheRsaWithAes128CbcSha256,
            TlsCipherSuite.TlsDheDssWithAes128CbcSha,
            TlsCipherSuite.TlsRsaWithRc4_128Sha,
            TlsCipherSuite.TlsRsaWithRc4_128Md5,
            TlsCipherSuite.TlsRsaWithAes128CbcSha,
            TlsCipherSuite.TlsRsaWithAes128CbcSha256,
            TlsCipherSuite.TlsRsaWith3DesEdeCbcSha)
        .WithSupportedGroups(NamedGroup.Secp256r1, NamedGroup.Secp384r1, NamedGroup.Secp521r1)
        .WithSignatureAlgorithms(
            SignatureScheme.RsaPkcs1Sha256,
            SignatureScheme.RsaPkcs1Sha384,
            SignatureScheme.RsaPkcs1Sha1,
            SignatureScheme.EcdsaSecp256r1Sha256,
            SignatureScheme.EcdsaSecp384r1Sha384,
            SignatureScheme.EcdsaSha1,
            SignatureScheme.DsaSha256,
            SignatureScheme.DsaSha1)
        .WithAlpn("spdy/2", "spdy/3", "spdy/3.1", "http/1.1")
        .WithExtensionLayout(
            ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.ServerName),
            ClientHelloExtensionSpec.Raw(0xFF01, [0]),
            ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.SupportedGroups),
            ClientHelloExtensionSpec.Raw(11, [1, 0]),
            ClientHelloExtensionSpec.Raw(35, []),
            ClientHelloExtensionSpec.Raw(13172, []),
            ClientHelloExtensionSpec.BuiltIn(
                ClientHelloExtensionKind.ApplicationLayerProtocolNegotiation),
            ClientHelloExtensionSpec.Raw(30031, []),
            ClientHelloExtensionSpec.Raw(5, [1, 0, 0, 0, 0]),
            ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.SignatureAlgorithms)));

    private static ClientHelloProfile CreateUTls360_11_0() =>
        CreateLegacyChromiumApplicationProfile(
            includeThreeDes: true,
            includeChannelId: true,
            includeApplicationSettings: false);

    private static ClientHelloProfile CreateUTlsQQ11_1() =>
        CreateLegacyChromiumApplicationProfile(
            includeThreeDes: false,
            includeChannelId: false,
            includeApplicationSettings: true);

    private static ClientHelloProfile CreateLegacyChromiumApplicationProfile(
        bool includeThreeDes,
        bool includeChannelId,
        bool includeApplicationSettings) => Custom(builder =>
    {
        var suites = LegacyChromiumCipherSuites(includeTls13: true).ToList();
        if (!includeThreeDes)
        {
            suites.Remove(TlsCipherSuite.TlsRsaWith3DesEdeCbcSha);
        }

        builder
            .WithGrease(CreateBoringGreasePolicy())
            .WithGreaseKeyShareBody([0])
            .WithSecondaryGreaseExtension([])
            .WithCipherSuites(suites.ToArray())
            .WithSupportedVersions(
                TlsProtocolVersion.Tls13,
                TlsProtocolVersion.Tls12,
                TlsProtocolVersion.Tls11,
                TlsProtocolVersion.Tls10)
            .WithSupportedGroups(
                NamedGroup.X25519,
                NamedGroup.Secp256r1,
                NamedGroup.Secp384r1)
            .WithKeyShares(NamedGroup.X25519)
            .WithSignatureAlgorithms(ChromiumLegacySignatureAlgorithms()
                .Where(scheme => scheme != SignatureScheme.RsaPkcs1Sha1 || includeChannelId)
                .ToArray())
            .WithAlpn("h2", "http/1.1")
            .WithBoringPadding();
        if (includeApplicationSettings)
        {
            builder.WithApplicationSettings(TlsApplicationSettingsCodePoint.LegacyDraft, "h2");
        }

        var layout = new List<ClientHelloExtensionSpec>
        {
            ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.Grease),
            ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.ServerName),
            ClientHelloExtensionSpec.Raw(23, []),
            ClientHelloExtensionSpec.Raw(0xFF01, [0]),
            ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.SupportedGroups),
            ClientHelloExtensionSpec.Raw(11, [1, 0]),
            ClientHelloExtensionSpec.Raw(35, []),
            ClientHelloExtensionSpec.BuiltIn(
                ClientHelloExtensionKind.ApplicationLayerProtocolNegotiation),
            ClientHelloExtensionSpec.Raw(5, [1, 0, 0, 0, 0]),
            ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.SignatureAlgorithms),
            ClientHelloExtensionSpec.Raw(18, []),
        };
        if (includeChannelId)
        {
            layout.Add(ClientHelloExtensionSpec.Raw(30032, []));
        }
        layout.AddRange(
        [
            ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.KeyShare),
            ClientHelloExtensionSpec.Raw((ushort)TlsExtensionType.PskKeyExchangeModes, [1, 1]),
            ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.SupportedVersions),
            ClientHelloExtensionSpec.Raw(27, [2, 0, 2]),
        ]);
        if (includeApplicationSettings)
        {
            layout.Add(ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.ApplicationSettings));
        }
        layout.AddRange(
        [
            ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.SecondaryGrease),
            ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.Padding),
            ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.EarlyData),
            ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.PreSharedKey),
        ]);
        builder.WithExtensionLayout(layout.ToArray());
    });

    private static TlsCipherSuite[] LegacyChromiumCipherSuites(bool includeTls13)
    {
        var suites = new List<TlsCipherSuite>();
        if (includeTls13)
        {
            suites.AddRange([
                TlsCipherSuite.TlsAes128GcmSha256,
                TlsCipherSuite.TlsAes256GcmSha384,
                TlsCipherSuite.TlsChaCha20Poly1305Sha256,
            ]);
        }
        suites.AddRange([
            TlsCipherSuite.TlsEcdheEcdsaWithAes128GcmSha256,
            TlsCipherSuite.TlsEcdheRsaWithAes128GcmSha256,
            TlsCipherSuite.TlsEcdheEcdsaWithAes256GcmSha384,
            TlsCipherSuite.TlsEcdheRsaWithAes256GcmSha384,
            TlsCipherSuite.TlsEcdheEcdsaWithChaCha20Poly1305Sha256,
            TlsCipherSuite.TlsEcdheRsaWithChaCha20Poly1305Sha256,
            TlsCipherSuite.TlsEcdheRsaWithAes128CbcSha,
            TlsCipherSuite.TlsEcdheRsaWithAes256CbcSha,
            TlsCipherSuite.TlsRsaWithAes128GcmSha256,
            TlsCipherSuite.TlsRsaWithAes256GcmSha384,
            TlsCipherSuite.TlsRsaWithAes128CbcSha,
            TlsCipherSuite.TlsRsaWithAes256CbcSha,
            TlsCipherSuite.TlsRsaWith3DesEdeCbcSha,
        ]);
        return suites.ToArray();
    }

    private static TlsCipherSuite[] LegacyFirefoxCipherSuites(bool includeTls13)
    {
        var suites = new List<TlsCipherSuite>();
        if (includeTls13)
        {
            suites.AddRange([
                TlsCipherSuite.TlsAes128GcmSha256,
                TlsCipherSuite.TlsChaCha20Poly1305Sha256,
                TlsCipherSuite.TlsAes256GcmSha384,
            ]);
        }
        suites.AddRange([
            TlsCipherSuite.TlsEcdheEcdsaWithAes128GcmSha256,
            TlsCipherSuite.TlsEcdheRsaWithAes128GcmSha256,
            TlsCipherSuite.TlsEcdheEcdsaWithChaCha20Poly1305Sha256,
            TlsCipherSuite.TlsEcdheRsaWithChaCha20Poly1305Sha256,
            TlsCipherSuite.TlsEcdheEcdsaWithAes256GcmSha384,
            TlsCipherSuite.TlsEcdheRsaWithAes256GcmSha384,
            TlsCipherSuite.TlsEcdheEcdsaWithAes256CbcSha,
            TlsCipherSuite.TlsEcdheEcdsaWithAes128CbcSha,
            TlsCipherSuite.TlsEcdheRsaWithAes128CbcSha,
            TlsCipherSuite.TlsEcdheRsaWithAes256CbcSha,
            TlsCipherSuite.TlsDheRsaWithAes128CbcSha,
            TlsCipherSuite.TlsDheRsaWithAes256CbcSha,
            TlsCipherSuite.TlsRsaWithAes128CbcSha,
            TlsCipherSuite.TlsRsaWithAes256CbcSha,
            TlsCipherSuite.TlsRsaWith3DesEdeCbcSha,
        ]);
        return suites.ToArray();
    }

    private static SignatureScheme[] ChromiumLegacySignatureAlgorithms() =>
    [
        SignatureScheme.EcdsaSecp256r1Sha256,
        SignatureScheme.RsaPssRsaeSha256,
        SignatureScheme.RsaPkcs1Sha256,
        SignatureScheme.EcdsaSecp384r1Sha384,
        SignatureScheme.RsaPssRsaeSha384,
        SignatureScheme.RsaPkcs1Sha384,
        SignatureScheme.RsaPssRsaeSha512,
        SignatureScheme.RsaPkcs1Sha512,
        SignatureScheme.RsaPkcs1Sha1,
    ];

    private static SignatureScheme[] FirefoxLegacySignatureAlgorithms() =>
    [
        SignatureScheme.EcdsaSecp256r1Sha256,
        SignatureScheme.EcdsaSecp384r1Sha384,
        SignatureScheme.EcdsaSecp521r1Sha512,
        SignatureScheme.RsaPssRsaeSha256,
        SignatureScheme.RsaPssRsaeSha384,
        SignatureScheme.RsaPssRsaeSha512,
        SignatureScheme.RsaPkcs1Sha256,
        SignatureScheme.RsaPkcs1Sha384,
        SignatureScheme.RsaPkcs1Sha512,
        SignatureScheme.EcdsaSha1,
        SignatureScheme.RsaPkcs1Sha1,
    ];

    private static TlsCipherSuite[] LegacyAppleCipherSuites(bool includeThreeDes)
    {
        var suites = new List<TlsCipherSuite>
        {
            TlsCipherSuite.TlsEcdheEcdsaWithAes256GcmSha384,
            TlsCipherSuite.TlsEcdheEcdsaWithAes128GcmSha256,
            TlsCipherSuite.TlsEcdheEcdsaWithAes256CbcSha384,
            TlsCipherSuite.TlsEcdheEcdsaWithAes128CbcSha256,
            TlsCipherSuite.TlsEcdheEcdsaWithAes256CbcSha,
            TlsCipherSuite.TlsEcdheEcdsaWithAes128CbcSha,
            TlsCipherSuite.TlsEcdheEcdsaWithChaCha20Poly1305Sha256,
            TlsCipherSuite.TlsEcdheRsaWithAes256GcmSha384,
            TlsCipherSuite.TlsEcdheRsaWithAes128GcmSha256,
            TlsCipherSuite.TlsEcdheRsaWithAes256CbcSha384,
            TlsCipherSuite.TlsEcdheRsaWithAes128CbcSha256,
            TlsCipherSuite.TlsEcdheRsaWithAes256CbcSha,
            TlsCipherSuite.TlsEcdheRsaWithAes128CbcSha,
            TlsCipherSuite.TlsEcdheRsaWithChaCha20Poly1305Sha256,
            TlsCipherSuite.TlsRsaWithAes256GcmSha384,
            TlsCipherSuite.TlsRsaWithAes128GcmSha256,
            TlsCipherSuite.TlsRsaWithAes256CbcSha256,
            TlsCipherSuite.TlsRsaWithAes128CbcSha256,
            TlsCipherSuite.TlsRsaWithAes256CbcSha,
            TlsCipherSuite.TlsRsaWithAes128CbcSha,
        };
        if (includeThreeDes)
        {
            suites.AddRange([
                TlsCipherSuite.TlsEcdheEcdsaWith3DesEdeCbcSha,
                TlsCipherSuite.TlsEcdheRsaWith3DesEdeCbcSha,
                TlsCipherSuite.TlsRsaWith3DesEdeCbcSha,
            ]);
        }
        return suites.ToArray();
    }
}
