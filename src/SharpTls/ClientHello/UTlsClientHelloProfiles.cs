using SharpTls.Protocol;

namespace SharpTls;

public static partial class ClientHelloProfiles
{
    /// <summary>
    /// Gets the byte-ordered uTLS HelloChrome_83 profile sourced from uTLS commit
    /// 880e27d8b0e5daafd2a39bb3fb2e0c29211c0d40. TLS 1.3 and the safe TLS 1.2
    /// ECDHE/AEAD subset are executable; other legacy suites remain fingerprint data.
    /// </summary>
    public static ClientHelloProfile UTlsChrome83 { get; } = CreateUTlsChrome83();

    /// <summary>Gets uTLS HelloChrome_87, whose pinned wire specification equals Chrome 83.</summary>
    public static ClientHelloProfile UTlsChrome87 { get; } = UTlsChrome83;

    /// <summary>Gets uTLS HelloEdge_85, whose pinned wire specification equals Chrome 83.</summary>
    public static ClientHelloProfile UTlsEdge85 { get; } = UTlsChrome83;

    /// <summary>
    /// Gets the byte-ordered uTLS HelloFirefox_99 profile from the pinned uTLS commit.
    /// TLS 1.3 and the safe TLS 1.2 ECDHE/AEAD subset are executable; finite-field and
    /// other legacy offers remain profile data and are rejected if selected.
    /// </summary>
    public static ClientHelloProfile UTlsFirefox99 { get; } = CreateUTlsFirefox99();

    /// <summary>Gets the pinned uTLS HelloIOS_14 wire profile.</summary>
    public static ClientHelloProfile UTlsIOS14 { get; } = CreateUTlsIOS14();

    /// <summary>Gets the pinned uTLS HelloSafari_16_0 wire profile.</summary>
    public static ClientHelloProfile UTlsSafari16 { get; } = CreateUTlsSafari16();

    /// <summary>
    /// Gets the executable pinned TLS-1.2-only uTLS HelloAndroid_11_OkHttp profile.
    /// </summary>
    public static ClientHelloProfile UTlsAndroid11OkHttp { get; } = CreateUTlsAndroid11OkHttp();

    private static ClientHelloProfile CreateUTlsChrome83()
    {
        var boringGrease = ClientHelloGreasePolicy.CreateWithSecondaryExtension(
            cipherSuiteClass: 0,
            supportedVersionClass: 4,
            supportedGroupClass: 1,
            keyShareClass: 1,
            extensionClass: 2,
            secondaryExtensionClass: 3);

        return Custom(builder => builder
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
    }

    private static ClientHelloProfile CreateUTlsFirefox99() => Custom(builder => builder
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
            TlsCipherSuite.TlsRsaWithAes256CbcSha,
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
            ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.DelegatedCredential),
            ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.KeyShare),
            ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.SupportedVersions),
            ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.SignatureAlgorithms),
            ClientHelloExtensionSpec.Raw((ushort)TlsExtensionType.PskKeyExchangeModes, [1, 1]),
            ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.RecordSizeLimit),
            ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.Padding),
            ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.EarlyData),
            ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.PreSharedKey)));

    private static ClientHelloProfile CreateUTlsIOS14() => Custom(builder => builder
        .WithGrease(CreateBoringGreasePolicy())
        .WithGreaseKeyShareBody([0])
        .WithSecondaryGreaseExtension([0])
        .WithCipherSuites(
            TlsCipherSuite.TlsAes128GcmSha256,
            TlsCipherSuite.TlsAes256GcmSha384,
            TlsCipherSuite.TlsChaCha20Poly1305Sha256,
            TlsCipherSuite.TlsEcdheEcdsaWithAes256GcmSha384,
            TlsCipherSuite.TlsEcdheEcdsaWithAes128GcmSha256,
            TlsCipherSuite.TlsEcdheEcdsaWithChaCha20Poly1305Sha256,
            TlsCipherSuite.TlsEcdheRsaWithAes256GcmSha384,
            TlsCipherSuite.TlsEcdheRsaWithAes128GcmSha256,
            TlsCipherSuite.TlsEcdheRsaWithChaCha20Poly1305Sha256,
            TlsCipherSuite.TlsEcdheEcdsaWithAes256CbcSha384,
            TlsCipherSuite.TlsEcdheEcdsaWithAes128CbcSha256,
            TlsCipherSuite.TlsEcdheEcdsaWithAes256CbcSha,
            TlsCipherSuite.TlsEcdheEcdsaWithAes128CbcSha,
            TlsCipherSuite.TlsEcdheRsaWithAes256CbcSha384,
            TlsCipherSuite.TlsEcdheRsaWithAes128CbcSha256,
            TlsCipherSuite.TlsEcdheRsaWithAes256CbcSha,
            TlsCipherSuite.TlsEcdheRsaWithAes128CbcSha,
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
            ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.SecondaryGrease),
            ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.Padding),
            ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.EarlyData),
            ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.PreSharedKey)));

    private static ClientHelloProfile CreateUTlsSafari16() => Custom(builder => builder
        .WithGrease(CreateBoringGreasePolicy())
        .WithGreaseKeyShareBody([0])
        .WithSecondaryGreaseExtension([0])
        .WithCipherSuites(
            TlsCipherSuite.TlsAes128GcmSha256,
            TlsCipherSuite.TlsAes256GcmSha384,
            TlsCipherSuite.TlsChaCha20Poly1305Sha256,
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
            ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.SecondaryGrease),
            ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.Padding),
            ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.EarlyData),
            ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.PreSharedKey)));

    private static ClientHelloGreasePolicy CreateBoringGreasePolicy() =>
        ClientHelloGreasePolicy.CreateWithSecondaryExtension(0, 4, 1, 1, 2, 3);

    private static ClientHelloProfile CreateUTlsAndroid11OkHttp() => Custom(builder => builder
        .WithLegacyTls12ClientHello()
        .WithCipherSuites(
            TlsCipherSuite.TlsEcdheEcdsaWithAes128GcmSha256,
            TlsCipherSuite.TlsEcdheEcdsaWithAes256GcmSha384,
            TlsCipherSuite.TlsEcdheEcdsaWithChaCha20Poly1305Sha256,
            TlsCipherSuite.TlsEcdheRsaWithAes128GcmSha256,
            TlsCipherSuite.TlsEcdheRsaWithAes256GcmSha384,
            TlsCipherSuite.TlsEcdheRsaWithChaCha20Poly1305Sha256,
            TlsCipherSuite.TlsEcdheRsaWithAes128CbcSha,
            TlsCipherSuite.TlsEcdheRsaWithAes256CbcSha,
            TlsCipherSuite.TlsRsaWithAes128GcmSha256,
            TlsCipherSuite.TlsRsaWithAes256GcmSha384,
            TlsCipherSuite.TlsRsaWithAes128CbcSha,
            TlsCipherSuite.TlsRsaWithAes256CbcSha)
        .WithSupportedGroups(
            NamedGroup.X25519,
            NamedGroup.Secp256r1,
            NamedGroup.Secp384r1)
        .WithSignatureAlgorithms(
            SignatureScheme.EcdsaSecp256r1Sha256,
            SignatureScheme.RsaPssRsaeSha256,
            SignatureScheme.RsaPkcs1Sha256,
            SignatureScheme.EcdsaSecp384r1Sha384,
            SignatureScheme.RsaPssRsaeSha384,
            SignatureScheme.RsaPkcs1Sha384,
            SignatureScheme.RsaPssRsaeSha512,
            SignatureScheme.RsaPkcs1Sha512,
            SignatureScheme.RsaPkcs1Sha1)
        .WithExtensionLayout(
            ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.ServerName),
            ClientHelloExtensionSpec.Raw(23, []),
            ClientHelloExtensionSpec.Raw(0xFF01, [0]),
            ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.SupportedGroups),
            ClientHelloExtensionSpec.Raw(11, [1, 0]),
            ClientHelloExtensionSpec.Raw(5, [1, 0, 0, 0, 0]),
            ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.SignatureAlgorithms)));

    private static SignatureScheme[] AppleSignatureAlgorithms() =>
    [
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
        SignatureScheme.RsaPkcs1Sha1,
    ];
}
