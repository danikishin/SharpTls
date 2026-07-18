using SharpTls.Protocol;

namespace SharpTls;

public static partial class ClientHelloProfiles
{
    /// <summary>
    /// Gets the pinned uTLS HelloChrome_96 profile, including legacy ALPS code point 17513.
    /// </summary>
    public static ClientHelloProfile UTlsChrome96 { get; } =
        CreateUTlsChromiumAlpsProfile(includeLegacyVersions: true);

    /// <summary>
    /// Gets the pinned uTLS HelloChrome_100 profile, including legacy ALPS code point 17513.
    /// </summary>
    public static ClientHelloProfile UTlsChrome100 { get; } =
        CreateUTlsChromiumAlpsProfile(includeLegacyVersions: false);

    /// <summary>
    /// Gets the pinned uTLS HelloChrome_100_PSK profile. The pre_shared_key extension is
    /// emitted only when SharpTls has a valid TLS 1.3 ticket and remains last on the wire.
    /// </summary>
    public static ClientHelloProfile UTlsChrome100Psk { get; } =
        CreateUTlsChromiumAlpsProfile(
            includeLegacyVersions: false,
            includeBoringPadding: false,
            includePskSlot: true);

    /// <summary>
    /// Gets the pinned uTLS HelloChrome_112_PSK_Shuf profile with Chrome extension
    /// shuffling and a final, non-shuffled pre_shared_key extension.
    /// </summary>
    public static ClientHelloProfile UTlsChrome112PskShuffle { get; } =
        CreateUTlsChromiumAlpsProfile(
            includeLegacyVersions: false,
            shuffleExtensions: true,
            includeBoringPadding: false,
            includePskSlot: true);

    /// <summary>
    /// Gets the pinned uTLS HelloChrome_114_Padding_PSK_Shuf profile with Chrome
    /// extension shuffling, BoringSSL padding, and final pre_shared_key placement.
    /// </summary>
    public static ClientHelloProfile UTlsChrome114PaddingPskShuffle { get; } =
        CreateUTlsChromiumAlpsProfile(
            includeLegacyVersions: false,
            shuffleExtensions: true,
            includeBoringPadding: true,
            includePskSlot: true);

    /// <summary>Gets uTLS HelloChrome_102, whose pinned wire specification equals Chrome 100.</summary>
    public static ClientHelloProfile UTlsChrome102 { get; } = UTlsChrome100;

    /// <summary>
    /// Gets the pinned uTLS HelloChrome_106_Shuffle profile with Chrome-style
    /// per-connection extension shuffling.
    /// </summary>
    public static ClientHelloProfile UTlsChrome106Shuffle { get; } =
        CreateUTlsChromiumAlpsProfile(
            includeLegacyVersions: false,
            shuffleExtensions: true);

    /// <summary>
    /// Gets the pinned uTLS HelloChrome_120 profile with shuffled extensions and
    /// BoringSSL-style GREASE ECH using HKDF-SHA256/AES-128-GCM.
    /// </summary>
    public static ClientHelloProfile UTlsChrome120 { get; } =
        CreateUTlsChromiumAlpsProfile(
            includeLegacyVersions: false,
            shuffleExtensions: true,
            greaseEch: true);

    /// <summary>
    /// Gets the pinned uTLS HelloChrome_115_PQ profile using the obsolete
    /// X25519Kyber768Draft00 compatibility group.
    /// </summary>
    public static ClientHelloProfile UTlsChrome115Pq { get; } =
        CreateUTlsChromiumAlpsProfile(
            includeLegacyVersions: false,
            shuffleExtensions: true,
            hybridGroup: NamedGroup.X25519Kyber768Draft00);

    /// <summary>Gets the pinned uTLS HelloChrome_115_PQ_PSK profile.</summary>
    public static ClientHelloProfile UTlsChrome115PqPsk { get; } =
        CreateUTlsChromiumAlpsProfile(
            includeLegacyVersions: false,
            shuffleExtensions: true,
            includeBoringPadding: false,
            hybridGroup: NamedGroup.X25519Kyber768Draft00,
            includePskSlot: true);

    /// <summary>Gets the pinned uTLS HelloChrome_120_PQ profile with GREASE ECH.</summary>
    public static ClientHelloProfile UTlsChrome120Pq { get; } =
        CreateUTlsChromiumAlpsProfile(
            includeLegacyVersions: false,
            shuffleExtensions: true,
            includeBoringPadding: false,
            greaseEch: true,
            hybridGroup: NamedGroup.X25519Kyber768Draft00);

    /// <summary>Gets the pinned uTLS HelloChrome_131 profile with X25519MLKEM768.</summary>
    public static ClientHelloProfile UTlsChrome131 { get; } =
        CreateUTlsChromiumAlpsProfile(
            includeLegacyVersions: false,
            shuffleExtensions: true,
            includeBoringPadding: false,
            greaseEch: true,
            hybridGroup: NamedGroup.X25519MlKem768);

    /// <summary>
    /// Gets the pinned uTLS HelloChrome_133 profile with X25519MLKEM768 and ALPS
    /// code point 17613.
    /// </summary>
    public static ClientHelloProfile UTlsChrome133 { get; } =
        CreateUTlsChromiumAlpsProfile(
            includeLegacyVersions: false,
            shuffleExtensions: true,
            includeBoringPadding: false,
            greaseEch: true,
            hybridGroup: NamedGroup.X25519MlKem768,
            applicationSettingsCodePoint: TlsApplicationSettingsCodePoint.ChromeExperiment);

    /// <summary>Gets uTLS HelloEdge_106, whose pinned wire specification equals Chrome 100.</summary>
    public static ClientHelloProfile UTlsEdge106 { get; } = UTlsChrome100;

    /// <summary>Gets the pinned uTLS HelloFirefox_102 profile.</summary>
    public static ClientHelloProfile UTlsFirefox102 { get; } =
        CreateUTlsFirefox102Or105(includeHttp11: false);

    /// <summary>Gets the pinned uTLS HelloFirefox_105 profile.</summary>
    public static ClientHelloProfile UTlsFirefox105 { get; } =
        CreateUTlsFirefox102Or105(includeHttp11: true);

    /// <summary>
    /// Gets the pinned uTLS HelloFirefox_120 profile with semantic GREASE ECH.
    /// </summary>
    public static ClientHelloProfile UTlsFirefox120 { get; } =
        CreateUTlsFirefox102Or105(includeHttp11: true, greaseEch: true);

    /// <summary>Gets the pinned uTLS HelloFirefox_148 profile with X25519MLKEM768.</summary>
    public static ClientHelloProfile UTlsFirefox148 { get; } = CreateUTlsFirefox148();

    /// <summary>Gets the pinned uTLS HelloSafari_26_3 profile with X25519MLKEM768.</summary>
    public static ClientHelloProfile UTlsSafari263 { get; } = CreateUTlsSafari263();

    /// <summary>Gets the pinned uTLS HelloIOS_13 profile.</summary>
    public static ClientHelloProfile UTlsIOS13 { get; } = CreateUTlsIOS13();

    private static ClientHelloProfile CreateUTlsChromiumAlpsProfile(
        bool includeLegacyVersions,
        bool shuffleExtensions = false,
        bool includeBoringPadding = true,
        bool greaseEch = false,
        NamedGroup? hybridGroup = null,
        bool includePskSlot = false,
        TlsApplicationSettingsCodePoint applicationSettingsCodePoint =
            TlsApplicationSettingsCodePoint.LegacyDraft)
    {
        var versions = includeLegacyVersions
            ? new[]
            {
                TlsProtocolVersion.Tls13,
                TlsProtocolVersion.Tls12,
                TlsProtocolVersion.Tls11,
                TlsProtocolVersion.Tls10,
            }
            : new[]
            {
                TlsProtocolVersion.Tls13,
                TlsProtocolVersion.Tls12,
            };

        var boringGrease = ClientHelloGreasePolicy.CreateWithSecondaryExtension(
            cipherSuiteClass: 0,
            supportedVersionClass: 4,
            supportedGroupClass: 1,
            keyShareClass: 1,
            extensionClass: 2,
            secondaryExtensionClass: 3);

        return Custom(builder =>
        {
            builder
            .WithGrease(boringGrease)
            .WithGreaseKeyShareBody([0])
            .WithSecondaryGreaseExtension([0])
            .WithCipherSuites(
                TlsCipherSuite.TlsAes128GcmSha256,
                TlsCipherSuite.TlsAes256GcmSha384,
                TlsCipherSuite.TlsChaCha20Poly1305Sha256,
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
                TlsCipherSuite.TlsRsaWithAes256CbcSha)
            .WithSupportedVersions(versions)
            .WithSupportedGroups(hybridGroup.HasValue
                ? [
                    hybridGroup.Value,
                    NamedGroup.X25519,
                    NamedGroup.Secp256r1,
                    NamedGroup.Secp384r1,
                ]
                : [
                    NamedGroup.X25519,
                    NamedGroup.Secp256r1,
                    NamedGroup.Secp384r1,
                ])
            .WithKeyShares(hybridGroup.HasValue
                ? [hybridGroup.Value, NamedGroup.X25519]
                : [NamedGroup.X25519])
            .WithSignatureAlgorithms(
                SignatureScheme.EcdsaSecp256r1Sha256,
                SignatureScheme.RsaPssRsaeSha256,
                SignatureScheme.RsaPkcs1Sha256,
                SignatureScheme.EcdsaSecp384r1Sha384,
                SignatureScheme.RsaPssRsaeSha384,
                SignatureScheme.RsaPkcs1Sha384,
                SignatureScheme.RsaPssRsaeSha512,
                SignatureScheme.RsaPkcs1Sha512)
            .WithAlpn("h2", "http/1.1")
            .WithApplicationSettings(applicationSettingsCodePoint, "h2")
            .WithExtensionShuffling(shuffleExtensions);

            if (greaseEch)
            {
                builder.WithGreaseEncryptedClientHello(
                    [new TlsHpkeSymmetricCipherSuite(
                        TlsHpkeKdfId.HkdfSha256,
                        TlsHpkeAeadId.Aes128Gcm)],
                    128,
                    160,
                    192,
                    224);
            }

            if (includeBoringPadding)
            {
                builder.WithBoringPadding();
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
                ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.KeyShare),
                ClientHelloExtensionSpec.Raw((ushort)TlsExtensionType.PskKeyExchangeModes, [1, 1]),
                ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.SupportedVersions),
                ClientHelloExtensionSpec.Raw(27, [2, 0, 2]),
                ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.ApplicationSettings),
            };
            if (greaseEch)
            {
                layout.Add(ClientHelloExtensionSpec.BuiltIn(
                    ClientHelloExtensionKind.EncryptedClientHello));
            }
            layout.Add(ClientHelloExtensionSpec.BuiltIn(
                ClientHelloExtensionKind.SecondaryGrease));
            if (includeBoringPadding)
            {
                layout.Add(ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.Padding));
            }
            if (includePskSlot)
            {
                layout.Add(ClientHelloExtensionSpec.BuiltIn(
                    ClientHelloExtensionKind.PreSharedKey));
            }
            builder.WithExtensionLayout(layout.ToArray());
        });
    }

    private static ClientHelloProfile CreateUTlsFirefox148() => Custom(builder => builder
        .WithCipherSuites(
            TlsCipherSuite.TlsAes128GcmSha256,
            TlsCipherSuite.TlsChaCha20Poly1305Sha256,
            TlsCipherSuite.TlsAes256GcmSha384,
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
            TlsCipherSuite.TlsRsaWithAes128GcmSha256,
            TlsCipherSuite.TlsRsaWithAes256GcmSha384,
            TlsCipherSuite.TlsRsaWithAes128CbcSha,
            TlsCipherSuite.TlsRsaWithAes256CbcSha)
        .WithSupportedVersions(TlsProtocolVersion.Tls13, TlsProtocolVersion.Tls12)
        .WithSupportedGroups(
            NamedGroup.X25519MlKem768,
            NamedGroup.X25519,
            NamedGroup.Secp256r1,
            NamedGroup.Secp384r1,
            NamedGroup.Secp521r1,
            NamedGroup.Ffdhe2048,
            NamedGroup.Ffdhe3072)
        .WithKeyShares(
            NamedGroup.X25519MlKem768,
            NamedGroup.X25519,
            NamedGroup.Secp256r1)
        .WithSignatureAlgorithms(
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
            SignatureScheme.RsaPkcs1Sha1)
        .WithDelegatedCredentials(
            SignatureScheme.EcdsaSecp256r1Sha256,
            SignatureScheme.EcdsaSecp384r1Sha384,
            SignatureScheme.EcdsaSecp521r1Sha512,
            SignatureScheme.EcdsaSha1)
        .AllowUnsupportedDelegatedCredentialAlgorithmsForWireFidelity()
        .WithAlpn("h2", "http/1.1")
        .WithRecordSizeLimit(TlsConstants.MaxPlaintextLength + 1)
        .WithGreaseEncryptedClientHello(
            [
                new TlsHpkeSymmetricCipherSuite(
                    TlsHpkeKdfId.HkdfSha256,
                    TlsHpkeAeadId.Aes128Gcm),
                new TlsHpkeSymmetricCipherSuite(
                    TlsHpkeKdfId.HkdfSha256,
                    TlsHpkeAeadId.ChaCha20Poly1305),
            ],
            223)
        .WithExtensionLayout(
            ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.ServerName),
            ClientHelloExtensionSpec.Raw(23, []),
            ClientHelloExtensionSpec.Raw(0xFF01, [0]),
            ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.SupportedGroups),
            ClientHelloExtensionSpec.Raw(11, [1, 0]),
            ClientHelloExtensionSpec.BuiltIn(
                ClientHelloExtensionKind.ApplicationLayerProtocolNegotiation),
            ClientHelloExtensionSpec.Raw(5, [1, 0, 0, 0, 0]),
            ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.DelegatedCredential),
            ClientHelloExtensionSpec.Raw(18, []),
            ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.KeyShare),
            ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.SupportedVersions),
            ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.SignatureAlgorithms),
            ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.RecordSizeLimit),
            ClientHelloExtensionSpec.Raw(27, [6, 0, 1, 0, 2, 0, 3]),
            ClientHelloExtensionSpec.BuiltIn(
                ClientHelloExtensionKind.EncryptedClientHello)));

    private static ClientHelloProfile CreateUTlsSafari263() => Custom(builder => builder
        .WithGrease(CreateBoringGreasePolicy())
        .WithGreaseKeyShareBody([0])
        .WithSecondaryGreaseExtension([0])
        .WithCipherSuites(
            TlsCipherSuite.TlsAes256GcmSha384,
            TlsCipherSuite.TlsChaCha20Poly1305Sha256,
            TlsCipherSuite.TlsAes128GcmSha256,
            TlsCipherSuite.TlsEcdheEcdsaWithAes256GcmSha384,
            TlsCipherSuite.TlsEcdheEcdsaWithAes128GcmSha256,
            TlsCipherSuite.TlsEcdheEcdsaWithChaCha20Poly1305Sha256,
            TlsCipherSuite.TlsEcdheRsaWithAes256GcmSha384,
            TlsCipherSuite.TlsEcdheRsaWithAes128GcmSha256,
            TlsCipherSuite.TlsEcdheRsaWithChaCha20Poly1305Sha256,
            TlsCipherSuite.TlsEcdheEcdsaWithAes256CbcSha,
            TlsCipherSuite.TlsEcdheEcdsaWithAes128CbcSha,
            TlsCipherSuite.TlsEcdheRsaWithAes256CbcSha,
            TlsCipherSuite.TlsEcdheRsaWithAes128CbcSha,
            TlsCipherSuite.TlsRsaWithAes256GcmSha384,
            TlsCipherSuite.TlsRsaWithAes128GcmSha256,
            TlsCipherSuite.TlsRsaWithAes256CbcSha,
            TlsCipherSuite.TlsRsaWithAes128CbcSha,
            TlsCipherSuite.TlsEcdheEcdsaWith3DesEdeCbcSha,
            TlsCipherSuite.TlsEcdheRsaWith3DesEdeCbcSha,
            TlsCipherSuite.TlsRsaWith3DesEdeCbcSha)
        .WithSupportedVersions(TlsProtocolVersion.Tls13, TlsProtocolVersion.Tls12)
        .WithSupportedGroups(
            NamedGroup.X25519MlKem768,
            NamedGroup.X25519,
            NamedGroup.Secp256r1,
            NamedGroup.Secp384r1,
            NamedGroup.Secp521r1)
        .WithKeyShares(NamedGroup.X25519MlKem768, NamedGroup.X25519)
        .WithSignatureAlgorithms(
            SignatureScheme.EcdsaSecp256r1Sha256,
            SignatureScheme.RsaPssRsaeSha256,
            SignatureScheme.RsaPkcs1Sha256,
            SignatureScheme.EcdsaSecp384r1Sha384,
            SignatureScheme.RsaPssRsaeSha384,
            SignatureScheme.RsaPssRsaeSha384,
            SignatureScheme.RsaPkcs1Sha384,
            SignatureScheme.RsaPssRsaeSha512,
            SignatureScheme.RsaPkcs1Sha512,
            SignatureScheme.RsaPkcs1Sha1)
        .AllowDuplicateSignatureAlgorithms()
        .WithAlpn("h2", "http/1.1")
        .WithExtensionLayout(
            ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.Grease),
            ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.ServerName),
            ClientHelloExtensionSpec.Raw(23, []),
            ClientHelloExtensionSpec.Raw(0xFF01, [0]),
            ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.SupportedGroups),
            ClientHelloExtensionSpec.Raw(11, [1, 0]),
            ClientHelloExtensionSpec.BuiltIn(
                ClientHelloExtensionKind.ApplicationLayerProtocolNegotiation),
            ClientHelloExtensionSpec.Raw(5, [1, 0, 0, 0, 0]),
            ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.SignatureAlgorithms),
            ClientHelloExtensionSpec.Raw(18, []),
            ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.KeyShare),
            ClientHelloExtensionSpec.Raw((ushort)TlsExtensionType.PskKeyExchangeModes, [1, 1]),
            ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.SupportedVersions),
            ClientHelloExtensionSpec.Raw(27, [2, 0, 1]),
            ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.SecondaryGrease)));

    private static ClientHelloProfile CreateUTlsFirefox102Or105(
        bool includeHttp11,
        bool greaseEch = false) =>
        Custom(builder =>
        {
            builder
            .WithCipherSuites(
                TlsCipherSuite.TlsAes128GcmSha256,
                TlsCipherSuite.TlsChaCha20Poly1305Sha256,
                TlsCipherSuite.TlsAes256GcmSha384,
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
                TlsCipherSuite.TlsRsaWithAes128GcmSha256,
                TlsCipherSuite.TlsRsaWithAes256GcmSha384,
                TlsCipherSuite.TlsRsaWithAes128CbcSha,
                TlsCipherSuite.TlsRsaWithAes256CbcSha)
            .WithSupportedVersions(TlsProtocolVersion.Tls13, TlsProtocolVersion.Tls12)
            .WithSupportedGroups(
                NamedGroup.X25519,
                NamedGroup.Secp256r1,
                NamedGroup.Secp384r1,
                NamedGroup.Secp521r1,
                NamedGroup.Ffdhe2048,
                NamedGroup.Ffdhe3072)
            .WithKeyShares(NamedGroup.X25519, NamedGroup.Secp256r1)
            .WithSignatureAlgorithms(
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
                SignatureScheme.RsaPkcs1Sha1)
            .WithDelegatedCredentials(
                SignatureScheme.EcdsaSecp256r1Sha256,
                SignatureScheme.EcdsaSecp384r1Sha384,
                SignatureScheme.EcdsaSecp521r1Sha512,
                SignatureScheme.EcdsaSha1)
            .AllowUnsupportedDelegatedCredentialAlgorithmsForWireFidelity()
            .WithAlpn(includeHttp11 ? ["h2", "http/1.1"] : ["h2"])
            .WithRecordSizeLimit(TlsConstants.MaxPlaintextLength + 1);

            if (greaseEch)
            {
                builder.WithGreaseEncryptedClientHello(223);
            }
            else
            {
                builder.WithBoringPadding();
            }

            var layout = new List<ClientHelloExtensionSpec>
            {
                ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.ServerName),
                ClientHelloExtensionSpec.Raw(23, []),
                ClientHelloExtensionSpec.Raw(0xFF01, [0]),
                ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.SupportedGroups),
                ClientHelloExtensionSpec.Raw(11, [1, 0]),
                ClientHelloExtensionSpec.Raw(35, []),
                ClientHelloExtensionSpec.BuiltIn(
                    ClientHelloExtensionKind.ApplicationLayerProtocolNegotiation),
                ClientHelloExtensionSpec.Raw(5, [1, 0, 0, 0, 0]),
                ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.DelegatedCredential),
                ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.KeyShare),
                ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.SupportedVersions),
                ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.SignatureAlgorithms),
                ClientHelloExtensionSpec.Raw((ushort)TlsExtensionType.PskKeyExchangeModes, [1, 1]),
                ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.RecordSizeLimit),
            };
            if (!greaseEch)
            {
                layout.Add(ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.Padding));
            }
            layout.Add(ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.EarlyData));
            if (greaseEch)
            {
                // Before exact-slot validation, the managed encoder inserted ECH immediately
                // before final pre_shared_key. Pin that historical upstream wire position.
                layout.Add(ClientHelloExtensionSpec.BuiltIn(
                    ClientHelloExtensionKind.EncryptedClientHello));
            }
            layout.Add(ClientHelloExtensionSpec.BuiltIn(
                ClientHelloExtensionKind.PreSharedKey));
            builder.WithExtensionLayout(layout.ToArray());
        });

    private static ClientHelloProfile CreateUTlsIOS13() => Custom(builder => builder
        .WithCipherSuites(
            TlsCipherSuite.TlsAes128GcmSha256,
            TlsCipherSuite.TlsAes256GcmSha384,
            TlsCipherSuite.TlsChaCha20Poly1305Sha256,
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
            TlsCipherSuite.TlsEcdheEcdsaWith3DesEdeCbcSha,
            TlsCipherSuite.TlsEcdheRsaWith3DesEdeCbcSha,
            TlsCipherSuite.TlsRsaWith3DesEdeCbcSha)
        .WithSupportedVersions(
            TlsProtocolVersion.Tls13,
            TlsProtocolVersion.Tls12,
            TlsProtocolVersion.Tls11,
            TlsProtocolVersion.Tls10)
        .WithSupportedGroups(
            NamedGroup.X25519,
            NamedGroup.Secp256r1,
            NamedGroup.Secp384r1,
            NamedGroup.Secp521r1)
        .WithKeyShares(NamedGroup.X25519)
        .WithSignatureAlgorithms(AppleSignatureAlgorithms())
        .AllowDuplicateSignatureAlgorithms()
        .WithAlpn("h2", "http/1.1")
        .WithBoringPadding()
        .WithExtensionLayout(
            ClientHelloExtensionSpec.Raw(0xFF01, [0]),
            ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.ServerName),
            ClientHelloExtensionSpec.Raw(23, []),
            ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.SignatureAlgorithms),
            ClientHelloExtensionSpec.Raw(5, [1, 0, 0, 0, 0]),
            ClientHelloExtensionSpec.Raw(18, []),
            ClientHelloExtensionSpec.BuiltIn(
                ClientHelloExtensionKind.ApplicationLayerProtocolNegotiation),
            ClientHelloExtensionSpec.Raw(11, [1, 0]),
            ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.KeyShare),
            ClientHelloExtensionSpec.Raw((ushort)TlsExtensionType.PskKeyExchangeModes, [1, 1]),
            ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.SupportedVersions),
            ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.SupportedGroups),
            ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.Padding),
            ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.EarlyData),
            ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.PreSharedKey)));
}
