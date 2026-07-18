using SharpTls.IO;
using SharpTls.Protocol;

namespace SharpTls.Tests.ClientHello;

public sealed class ClientHelloTests
{
    [Fact]
    public void DeterministicModeIsByteForByteStable()
    {
        var profile = ClientHelloProfiles.Custom(builder => builder
            .WithGrease()
            .WithAlpn("h2", "http/1.1")
            .WithPadding(7));

        var first = profile.BuildDeterministicForTesting("example.com", [1, 2, 3, 4]);
        var second = profile.BuildDeterministicForTesting("example.com", [1, 2, 3, 4]);
        var different = profile.BuildDeterministicForTesting("example.com", [4, 3, 2, 1]);

        Assert.Equal(first, second);
        Assert.NotEqual(first, different);
    }

    [Fact]
    public void ExplicitExtensionOrderIsPreservedExactly()
    {
        ClientHelloExtensionKind[] order =
        [
            ClientHelloExtensionKind.Padding,
            ClientHelloExtensionKind.ApplicationLayerProtocolNegotiation,
            ClientHelloExtensionKind.KeyShare,
            ClientHelloExtensionKind.SignatureAlgorithms,
            ClientHelloExtensionKind.SupportedGroups,
            ClientHelloExtensionKind.SupportedVersions,
            ClientHelloExtensionKind.ServerName,
            ClientHelloExtensionKind.Grease,
        ];
        var profile = ClientHelloProfiles.Custom(builder => builder
            .WithGrease()
            .WithAlpn("http/1.1")
            .WithPadding(3)
            .WithExtensionOrder(order));

        var encoded = profile.BuildDeterministicForTesting("example.com", [9, 9, 9]);
        var extensionTypes = ReadExtensionTypes(encoded);

        Assert.Equal((ushort)TlsExtensionType.Padding, extensionTypes[0]);
        Assert.Equal((ushort)TlsExtensionType.ApplicationLayerProtocolNegotiation, extensionTypes[1]);
        Assert.Equal((ushort)TlsExtensionType.KeyShare, extensionTypes[2]);
        Assert.Equal((ushort)TlsExtensionType.SignatureAlgorithms, extensionTypes[3]);
        Assert.Equal((ushort)TlsExtensionType.SupportedGroups, extensionTypes[4]);
        Assert.Equal((ushort)TlsExtensionType.SupportedVersions, extensionTypes[5]);
        Assert.Equal((ushort)TlsExtensionType.ServerName, extensionTypes[6]);
        Assert.True(IsGrease(extensionTypes[7]));
    }

    [Fact]
    public void SecureGenerationDoesNotReuseKeySharesAcrossConnections()
    {
        var profile = ClientHelloProfiles.ModernTls13;
        using var first = profile.BuildSecure("example.com");
        using var second = profile.BuildSecure("example.com");

        Assert.NotEqual(
            first.KeyShares.Get(NamedGroup.Secp256r1).PublicKey.ToArray(),
            second.KeyShares.Get(NamedGroup.Secp256r1).PublicKey.ToArray());
    }

    [Fact]
    public void DuplicateCipherSuitesAreRejectedBeforeNetworkIo()
    {
        Assert.Throws<ArgumentException>(() => ClientHelloProfiles.Custom(builder => builder.WithCipherSuites(
            TlsCipherSuite.TlsAes128GcmSha256,
            TlsCipherSuite.TlsAes128GcmSha256)));
    }

    [Fact]
    public void MissingExtensionInExplicitOrderIsRejected()
    {
        Assert.Throws<ArgumentException>(() => ClientHelloProfiles.Custom(builder => builder.WithExtensionOrder(
            ClientHelloExtensionKind.ServerName,
            ClientHelloExtensionKind.SupportedVersions)));
    }

    [Fact]
    public void GreaseEchIsAnExactPositionedSlotAndCannotBeSilentlyInserted()
    {
        Assert.Throws<ArgumentException>(() => ClientHelloProfiles.Custom(builder => builder
            .WithGreaseEncryptedClientHello(160)
            .WithExtensionOrder(
                ClientHelloExtensionKind.ServerName,
                ClientHelloExtensionKind.SupportedVersions,
                ClientHelloExtensionKind.SupportedGroups,
                ClientHelloExtensionKind.SignatureAlgorithms,
                ClientHelloExtensionKind.KeyShare)));

        var profile = ClientHelloProfiles.Custom(builder => builder
            .WithGreaseEncryptedClientHello(160)
            .WithExtensionOrder(
                ClientHelloExtensionKind.ServerName,
                ClientHelloExtensionKind.EncryptedClientHello,
                ClientHelloExtensionKind.SupportedVersions,
                ClientHelloExtensionKind.SupportedGroups,
                ClientHelloExtensionKind.SignatureAlgorithms,
                ClientHelloExtensionKind.KeyShare));

        Assert.Equal(
            ClientHelloExtensionKind.EncryptedClientHello,
            profile.Spec.Extensions[1].BuiltInKind);
        Assert.Equal(
            (ushort)TlsExtensionType.EncryptedClientHello,
            ReadExtensionTypes(profile.BuildDeterministicForTesting(
                "example.com",
                [9, 8, 4, 9]))[1]);
    }

    [Fact]
    public void X25519CanBeAdvertisedAndEncoded()
    {
        var profile = ClientHelloProfiles.Custom(builder => builder
            .WithSupportedGroups(NamedGroup.X25519)
            .WithKeyShares(NamedGroup.X25519));
        using var hello = profile.BuildSecure("example.com");

        Assert.Equal(new[] { NamedGroup.X25519 }, profile.Spec.SupportedGroups);
        Assert.Equal(32, hello.KeyShares.Get(NamedGroup.X25519).PublicKey.Length);
    }

    [Fact]
    public void GreasePolicyPreservesValueClassesAndRetryValues()
    {
        var policy = ClientHelloGreasePolicy.Create(7, 2, 7, 9, 2);
        var profile = ClientHelloProfiles.Custom(builder => builder
            .WithGrease(policy)
            .WithSupportedGroups(NamedGroup.Secp256r1, NamedGroup.Secp384r1)
            .WithKeyShares(NamedGroup.Secp256r1));
        using var first = profile.BuildSecure("example.com");
        var values = first.GreaseValues!.Value;

        Assert.Equal(3, profile.Spec.GreasePolicy!.DistinctValueCount);
        Assert.Equal(values.CipherSuite, values.SupportedGroup);
        Assert.Equal(values.SupportedVersion, values.Extension);
        Assert.NotEqual(values.CipherSuite, values.SupportedVersion);
        Assert.NotEqual(values.KeyShare, values.Extension);

        using var retry = ClientHelloEncoder.BuildRetry(
            first,
            NamedGroup.Secp384r1,
            cookie: null);
        Assert.Equal(first.GreaseValues, retry.GreaseValues);
    }

    [Fact]
    public void InvalidGreaseValueClassIsRejected()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() =>
            ClientHelloGreasePolicy.Create(0, 1, 2, 3, 16));
    }

    [Theory]
    [InlineData("")]
    [InlineData("é")]
    public void InvalidAlpnIsRejected(string protocol)
    {
        Assert.Throws<ArgumentException>(() => ClientHelloProfiles.Custom(builder => builder.WithAlpn(protocol)));
    }

    [Fact]
    public void CallerSessionIdIsSnapshotted()
    {
        var sessionId = new byte[] { 1, 2, 3 };
        var profile = ClientHelloProfiles.Custom(builder => builder.WithSessionId(sessionId));
        sessionId[0] = 99;

        var encoded = profile.BuildDeterministicForTesting("example.com", [7]);
        var reader = new TlsBinaryReader(encoded.AsSpan(TlsConstants.HandshakeHeaderLength));
        _ = reader.ReadUInt16();
        _ = reader.ReadBytes(32);

        Assert.True(reader.ReadVector8().SequenceEqual(new byte[] { 1, 2, 3 }));
    }

    [Fact]
    public void MixedBuiltInAndRawExtensionLayoutIsPreservedExactly()
    {
        var firstRaw = new byte[] { 1, 2, 3 };
        var profile = ClientHelloProfiles.Custom(builder => builder
            .WithAlpn("http/1.1")
            .WithExtensionLayout(
                ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.ServerName),
                ClientHelloExtensionSpec.Raw(0xFDE8, firstRaw),
                ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.SupportedVersions),
                ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.SupportedGroups),
                ClientHelloExtensionSpec.Raw(0xFDE9, [4, 5]),
                ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.SignatureAlgorithms),
                ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.KeyShare),
                ClientHelloExtensionSpec.BuiltIn(
                    ClientHelloExtensionKind.ApplicationLayerProtocolNegotiation)));
        firstRaw[0] = 99;

        var encoded = profile.BuildDeterministicForTesting("example.com", [3, 1, 4]);
        var extensions = ReadExtensions(encoded);

        Assert.Equal(
            [
                (ushort)TlsExtensionType.ServerName,
                0xFDE8,
                (ushort)TlsExtensionType.SupportedVersions,
                (ushort)TlsExtensionType.SupportedGroups,
                0xFDE9,
                (ushort)TlsExtensionType.SignatureAlgorithms,
                (ushort)TlsExtensionType.KeyShare,
                (ushort)TlsExtensionType.ApplicationLayerProtocolNegotiation,
            ],
            extensions.Select(extension => extension.Type));
        Assert.Equal(new byte[] { 1, 2, 3 }, extensions[1].Data);
        Assert.Equal(new byte[] { 4, 5 }, extensions[4].Data);
    }

    [Fact]
    public void RawExtensionSurvivesHelloRetryRequestWithCookieInsertedBeforeKeyShare()
    {
        var profile = ClientHelloProfiles.Custom(builder => builder
            .WithSupportedGroups(NamedGroup.Secp256r1)
            .WithKeyShares()
            .WithExtensionLayout(
                ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.ServerName),
                ClientHelloExtensionSpec.Raw(0xFDE8, [8, 6, 7]),
                ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.SupportedVersions),
                ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.SupportedGroups),
                ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.SignatureAlgorithms),
                ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.KeyShare)));
        using var first = profile.BuildSecure("example.com");
        using var retry = ClientHelloEncoder.BuildRetry(first, NamedGroup.Secp256r1, [9, 9]);

        var extensions = ReadExtensions(retry.EncodedHandshake);
        Assert.Equal(
            [
                (ushort)TlsExtensionType.ServerName,
                0xFDE8,
                (ushort)TlsExtensionType.SupportedVersions,
                (ushort)TlsExtensionType.SupportedGroups,
                (ushort)TlsExtensionType.SignatureAlgorithms,
                (ushort)TlsExtensionType.Cookie,
                (ushort)TlsExtensionType.KeyShare,
            ],
            extensions.Select(extension => extension.Type));
        Assert.Equal(new byte[] { 8, 6, 7 }, extensions[1].Data);
    }

    [Fact]
    public void DuplicateAndSemanticRawExtensionTypesAreRejected()
    {
        Assert.Throws<ArgumentException>(() => ClientHelloProfiles.Custom(builder => builder
            .WithExtensionLayout([
                .. DefaultLayout(),
                ClientHelloExtensionSpec.Raw(0xFDE8, []),
                ClientHelloExtensionSpec.Raw(0xFDE8, [1]),
            ])));

        Assert.Throws<ArgumentException>(() => ClientHelloProfiles.Custom(builder => builder
            .WithExtensionLayout([
                .. DefaultLayout(),
                ClientHelloExtensionSpec.Raw((ushort)TlsExtensionType.ServerName, []),
            ])));
    }

    [Fact]
    public void AggregateRawExtensionDataIsBoundedBeforeNetworkIo()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => ClientHelloProfiles.Custom(builder => builder
            .WithExtensionLayout([
                .. DefaultLayout(),
                ClientHelloExtensionSpec.Raw(0xFDE8, new byte[30 * 1024]),
                ClientHelloExtensionSpec.Raw(0xFDE9, new byte[30 * 1024]),
            ])));
    }

    [Fact]
    public void ImmutableSpecRoundTripsToEquivalentProfile()
    {
        var sessionId = new byte[] { 7, 8, 9 };
        var spec = new ClientHelloBuilder()
            .WithCipherSuites(TlsCipherSuite.TlsAes256GcmSha384)
            .WithSupportedGroups(NamedGroup.Secp384r1)
            .WithSessionId(sessionId)
            .WithAlpn("http/1.1")
            .BuildSpec();
        sessionId[0] = 99;

        var first = ClientHelloProfiles.FromSpec(spec)
            .BuildDeterministicForTesting("example.com", [4, 2]);
        var secondProfile = ClientHelloProfiles.FromSpec(
            ClientHelloProfiles.FromSpec(spec).Spec);
        var second = secondProfile.BuildDeterministicForTesting("example.com", [4, 2]);

        Assert.Equal(first, second);
        Assert.Equal(new byte[] { 7, 8, 9 }, spec.SessionId);
        Assert.Equal(TlsCipherSuite.TlsAes256GcmSha384, Assert.Single(spec.CipherSuites));
        Assert.Equal(NamedGroup.Secp384r1, Assert.Single(spec.KeyShareGroups));
    }

    [Fact]
    public void IndividualRawExtensionBodyUsesTlsVectorBound()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() =>
            ClientHelloExtensionSpec.Raw(0xFDE8, new byte[ushort.MaxValue + 1]));
    }

    [Fact]
    public void PostHandshakeAuthIsEmptyAndPreSharedKeyRemainsLast()
    {
        var profile = ClientHelloProfiles.Custom(builder => builder
            .WithSessionResumption()
            .WithPostHandshakeAuthentication()
            .WithAlpn("http/1.1"));
        var encoded = profile.BuildDeterministicForTesting("example.com", [1, 3, 3, 7]);
        var extensions = ReadExtensions(encoded);

        Assert.True(profile.Spec.SupportsPostHandshakeAuthentication);
        Assert.Empty(Assert.Single(
            extensions,
            extension => extension.Type ==
                (ushort)TlsExtensionType.PostHandshakeAuthentication).Data);
        Assert.Equal(
            ClientHelloExtensionKind.PreSharedKey,
            profile.Spec.Extensions[^1].BuiltInKind);
        Assert.DoesNotContain(
            extensions,
            extension => extension.Type == (ushort)TlsExtensionType.PreSharedKey);
    }

    [Fact]
    public void RawPostHandshakeAuthCannotBypassSemanticCapabilityTracking()
    {
        Assert.Throws<ArgumentException>(() => ClientHelloProfiles.Custom(builder => builder
            .WithExtensionLayout([
                .. DefaultLayout(),
                ClientHelloExtensionSpec.Raw(
                    (ushort)TlsExtensionType.PostHandshakeAuthentication,
                    []),
            ])));
    }

    [Fact]
    public void CertificateSignatureAlgorithmsAreEncodedIndependently()
    {
        var profile = ClientHelloProfiles.Custom(builder => builder
            .WithCertificateSignatureAlgorithms(
                SignatureScheme.EcdsaSecp384r1Sha384,
                SignatureScheme.RsaPkcs1Sha256,
                SignatureScheme.RsaPkcs1Sha1));
        var encoded = profile.BuildDeterministicForTesting("example.com", [5, 0]);
        var extension = Assert.Single(
            ReadExtensions(encoded),
            item => item.Type == (ushort)TlsExtensionType.SignatureAlgorithmsCert);

        Assert.Equal(
            new byte[] { 0, 6, 5, 3, 4, 1, 2, 1 },
            extension.Data);
        Assert.Equal(
            [SignatureScheme.EcdsaSecp384r1Sha384,
             SignatureScheme.RsaPkcs1Sha256,
             SignatureScheme.RsaPkcs1Sha1],
            profile.Spec.CertificateSignatureAlgorithms);
    }

    [Fact]
    public void CertificateSignatureAlgorithmsRejectEmptyDuplicateAndMisorderedLegacyLists()
    {
        Assert.Throws<ArgumentException>(() => ClientHelloProfiles.Custom(builder => builder
            .WithCertificateSignatureAlgorithms([])));
        Assert.Throws<ArgumentException>(() => ClientHelloProfiles.Custom(builder => builder
            .WithCertificateSignatureAlgorithms(
                SignatureScheme.RsaPkcs1Sha256,
                SignatureScheme.RsaPkcs1Sha256)));
        Assert.Throws<ArgumentException>(() => ClientHelloProfiles.Custom(builder => builder
            .WithCertificateSignatureAlgorithms(
                SignatureScheme.RsaPkcs1Sha1,
                SignatureScheme.RsaPkcs1Sha256)));
    }

    [Fact]
    public void RecordSizeLimitIsSemanticOrderedAndExactlyEncoded()
    {
        var profile = ClientHelloProfiles.Custom(builder => builder
            .WithRecordSizeLimit(513)
            .WithExtensionOrder(
                ClientHelloExtensionKind.RecordSizeLimit,
                ClientHelloExtensionKind.ServerName,
                ClientHelloExtensionKind.SupportedVersions,
                ClientHelloExtensionKind.SupportedGroups,
                ClientHelloExtensionKind.SignatureAlgorithms,
                ClientHelloExtensionKind.KeyShare));
        var extensions = ReadExtensions(
            profile.BuildDeterministicForTesting("example.com", [8, 4, 4, 9]));

        Assert.Equal((ushort)TlsExtensionType.RecordSizeLimit, extensions[0].Type);
        Assert.Equal(new byte[] { 0x02, 0x01 }, extensions[0].Data);
        Assert.Equal(513, profile.Spec.RecordSizeLimit);
    }

    [Theory]
    [InlineData(63)]
    [InlineData(16386)]
    public void RecordSizeLimitRejectsValuesOutsideTls13Range(int value)
    {
        Assert.Throws<ArgumentOutOfRangeException>(() =>
            new ClientHelloBuilder().WithRecordSizeLimit(value));
    }

    [Fact]
    public void Tls12OnlyProfileRejectsTls13MaximumRecordSizeLimit()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => new ClientHelloBuilder()
            .WithLegacyTls12ClientHello()
            .WithRecordSizeLimit(TlsConstants.MaxPlaintextLength + 1)
            .BuildSpec());
    }

    [Fact]
    public void RawRecordSizeLimitCannotBypassSemanticNegotiation()
    {
        Assert.Throws<ArgumentException>(() => ClientHelloProfiles.Custom(builder => builder
            .WithExtensionLayout([
                .. DefaultLayout(),
                ClientHelloExtensionSpec.Raw((ushort)TlsExtensionType.RecordSizeLimit, [0, 64]),
            ])));
    }

    [Fact]
    public void DelegatedCredentialAlgorithmsAreOrderedAndExactlyEncoded()
    {
        var profile = ClientHelloProfiles.Custom(builder => builder
            .WithDelegatedCredentials(
                SignatureScheme.EcdsaSecp384r1Sha384,
                SignatureScheme.EcdsaSecp256r1Sha256));
        var extension = Assert.Single(
            ReadExtensions(profile.BuildDeterministicForTesting("example.com", [9, 3, 4, 5])),
            item => item.Type == (ushort)TlsExtensionType.DelegatedCredential);

        Assert.Equal(new byte[] { 0, 4, 5, 3, 4, 3 }, extension.Data);
        Assert.Equal(
            [SignatureScheme.EcdsaSecp384r1Sha384,
             SignatureScheme.EcdsaSecp256r1Sha256],
            profile.Spec.DelegatedCredentialSignatureAlgorithms);
    }

    [Fact]
    public void DelegatedCredentialConfigurationRejectsIncoherentOffers()
    {
        Assert.Throws<ArgumentException>(() => ClientHelloProfiles.Custom(builder => builder
            .WithDelegatedCredentials([])));
        Assert.Throws<ArgumentException>(() => ClientHelloProfiles.Custom(builder => builder
            .WithDelegatedCredentials(
                SignatureScheme.EcdsaSecp256r1Sha256,
                SignatureScheme.EcdsaSecp256r1Sha256)));
        Assert.Throws<NotSupportedException>(() => ClientHelloProfiles.Custom(builder => builder
            .WithSignatureAlgorithms(SignatureScheme.RsaPssRsaeSha256)
            .WithDelegatedCredentials(SignatureScheme.EcdsaSecp256r1Sha256)));
        Assert.Throws<NotSupportedException>(() => ClientHelloProfiles.Custom(builder => builder
            .WithDelegatedCredentials(SignatureScheme.EcdsaSha1)));
        Assert.Throws<InvalidOperationException>(() => ClientHelloProfiles.Custom(builder => builder
            .WithLegacyTls12ClientHello()
            .WithDelegatedCredentials(SignatureScheme.EcdsaSecp256r1Sha256)));
    }

    [Theory]
    [InlineData(TlsApplicationSettingsCodePoint.LegacyDraft, 17513)]
    [InlineData(TlsApplicationSettingsCodePoint.ChromeExperiment, 17613)]
    public void ApplicationSettingsCodePointOrderAndProtocolVectorAreExact(
        TlsApplicationSettingsCodePoint codePoint,
        ushort expectedType)
    {
        var profile = ClientHelloProfiles.Custom(builder => builder
            .WithAlpn("h2", "http/1.1")
            .WithApplicationSettings(codePoint, "h2", "http/1.1")
            .WithExtensionOrder(
                ClientHelloExtensionKind.ApplicationSettings,
                ClientHelloExtensionKind.ApplicationLayerProtocolNegotiation,
                ClientHelloExtensionKind.ServerName,
                ClientHelloExtensionKind.SupportedVersions,
                ClientHelloExtensionKind.SupportedGroups,
                ClientHelloExtensionKind.SignatureAlgorithms,
                ClientHelloExtensionKind.KeyShare));

        var extensions = ReadExtensions(
            profile.BuildDeterministicForTesting("example.com", [1, 7, 5, 1, 3]));

        Assert.Equal(expectedType, extensions[0].Type);
        Assert.Equal(
            new byte[] { 0, 12, 2, (byte)'h', (byte)'2', 8,
                (byte)'h', (byte)'t', (byte)'t', (byte)'p', (byte)'/',
                (byte)'1', (byte)'.', (byte)'1' },
            extensions[0].Data);
        Assert.Equal(codePoint, profile.Spec.ApplicationSettingsCodePoint);
        Assert.Equal(["h2", "http/1.1"], profile.Spec.ApplicationSettingsProtocols);
    }

    [Fact]
    public void ApplicationSettingsRequiresTls13AlpnSubsetAndSemanticWireOwnership()
    {
        Assert.Throws<InvalidOperationException>(() => ClientHelloProfiles.Custom(builder => builder
            .WithApplicationSettings(TlsApplicationSettingsCodePoint.LegacyDraft, "h2")));
        Assert.Throws<ArgumentException>(() => ClientHelloProfiles.Custom(builder => builder
            .WithAlpn("h2")
            .WithApplicationSettings(
                TlsApplicationSettingsCodePoint.LegacyDraft,
                "http/1.1")));
        Assert.Throws<ArgumentException>(() => ClientHelloProfiles.Custom(builder => builder
            .WithAlpn("h2")
            .WithApplicationSettings(TlsApplicationSettingsCodePoint.LegacyDraft, "h2", "h2")));
        Assert.Throws<InvalidOperationException>(() => ClientHelloProfiles.Custom(builder => builder
            .WithLegacyTls12ClientHello()
            .WithAlpn("h2")
            .WithApplicationSettings(TlsApplicationSettingsCodePoint.LegacyDraft, "h2")));
        Assert.Throws<ArgumentException>(() => ClientHelloProfiles.Custom(builder => builder
            .WithExtensionLayout([
                .. DefaultLayout(),
                ClientHelloExtensionSpec.Raw(
                    (ushort)TlsApplicationSettingsCodePoint.ChromeExperiment,
                    [0, 0]),
            ])));
    }

    private static List<ushort> ReadExtensionTypes(byte[] encoded)
        => ReadExtensions(encoded).Select(extension => extension.Type).ToList();

    private static List<(ushort Type, byte[] Data)> ReadExtensions(byte[] encoded)
    {
        var reader = new TlsBinaryReader(encoded);
        Assert.Equal((byte)HandshakeType.ClientHello, reader.ReadUInt8());
        var body = new TlsBinaryReader(reader.ReadBytes(reader.ReadUInt24()));
        _ = body.ReadUInt16();
        _ = body.ReadBytes(32);
        _ = body.ReadVector8();
        _ = body.ReadVector16();
        _ = body.ReadVector8();
        var extensions = new TlsBinaryReader(body.ReadVector16());
        var result = new List<(ushort Type, byte[] Data)>();
        while (!extensions.End)
        {
            result.Add((extensions.ReadUInt16(), extensions.ReadVector16().ToArray()));
        }
        return result;
    }

    private static ClientHelloExtensionSpec[] DefaultLayout() =>
    [
        ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.ServerName),
        ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.SupportedVersions),
        ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.SupportedGroups),
        ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.SignatureAlgorithms),
        ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.KeyShare),
    ];

    private static bool IsGrease(ushort value) =>
        (value & 0x0F0F) == 0x0A0A && (byte)(value >> 8) == (byte)value;
}
