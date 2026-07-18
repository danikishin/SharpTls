using SharpTls.Protocol;

namespace SharpTls.Tests.ClientHello;

public sealed class ClientHelloSpecJsonTests
{
    [Fact]
    public void CurrentVersionRoundTripPreservesExecutableWireSpecification()
    {
        var original = ClientHelloProfiles.Custom(builder => builder
            .WithGrease(ClientHelloGreasePolicy.Create(0, 1, 0, 2, 1))
            .WithCipherSuites(
                TlsCipherSuite.TlsChaCha20Poly1305Sha256,
                TlsCipherSuite.TlsAes128GcmSha256)
            .WithSupportedGroups(NamedGroup.Secp384r1, NamedGroup.Secp256r1)
            .WithKeyShares(NamedGroup.Secp384r1)
            .WithCertificateSignatureAlgorithms(
                SignatureScheme.RsaPkcs1Sha384,
                SignatureScheme.EcdsaSecp384r1Sha384)
            .WithDelegatedCredentials(SignatureScheme.EcdsaSecp384r1Sha384)
            .WithAlpn("h2", "http/1.1")
            .WithApplicationSettings(TlsApplicationSettingsCodePoint.LegacyDraft, "h2")
            .WithRecordSizeLimit(1024)
            .WithPadding(7)
            .WithExtensionShuffling()
            .WithSessionId([1, 2, 3])
            .WithExtensionLayout(
                ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.Grease),
                ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.ServerName),
                ClientHelloExtensionSpec.Raw(0xFDE8, [9, 8, 7]),
                ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.SupportedGroups),
                ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.SupportedVersions),
                ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.KeyShare),
                ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.SignatureAlgorithms),
                ClientHelloExtensionSpec.BuiltIn(
                    ClientHelloExtensionKind.SignatureAlgorithmsCert),
                ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.DelegatedCredential),
                ClientHelloExtensionSpec.BuiltIn(
                    ClientHelloExtensionKind.ApplicationLayerProtocolNegotiation),
                ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.ApplicationSettings),
                ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.RecordSizeLimit),
                ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.Padding)));
        var originalBytes = original.BuildDeterministicForTesting("example.com", [1, 6, 1, 8]);

        var json = ClientHelloSpecJson.Serialize(original.Spec);
        var restoredSpec = ClientHelloSpecJson.Deserialize(json);
        var restoredBytes = ClientHelloProfiles.FromSpec(restoredSpec)
            .BuildDeterministicForTesting("example.com", [1, 6, 1, 8]);

        Assert.Equal(originalBytes, restoredBytes);
        Assert.Equal(new[] { 0, 1, 0, 2, 1 }, restoredSpec.GreasePolicy!.ValueClasses);
        Assert.Equal(1024, restoredSpec.RecordSizeLimit);
        Assert.Equal(
            [SignatureScheme.EcdsaSecp384r1Sha384],
            restoredSpec.DelegatedCredentialSignatureAlgorithms);
        Assert.Equal(
            TlsApplicationSettingsCodePoint.LegacyDraft,
            restoredSpec.ApplicationSettingsCodePoint);
        Assert.Equal(["h2"], restoredSpec.ApplicationSettingsProtocols);
        Assert.True(restoredSpec.ShuffleExtensions);
        Assert.DoesNotContain("random", json, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("secret", json, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("keyExchange", json, StringComparison.OrdinalIgnoreCase);
    }

    [Theory]
    [InlineData("{\"format\":\"sharptls-clienthello-spec\",\"format\":\"x\"}")]
    [InlineData("{\"unknown\":true}")]
    [InlineData("[]")]
    [InlineData("not-json")]
    public void MalformedDuplicateAndUnknownDocumentsAreRejected(string json)
    {
        Assert.Throws<InvalidDataException>(() => ClientHelloSpecJson.Deserialize(json));
    }

    [Fact]
    public void InvalidUtf8PropertyNameIsRejectedAtThePublicDataBoundary()
    {
        byte[] json = [(byte)'{', (byte)'"', 0xF7, (byte)'"', (byte)':', (byte)'0', (byte)'}'];

        Assert.Throws<InvalidDataException>(() => ClientHelloSpecJson.Deserialize(json));
    }

    [Fact]
    public void UnsupportedVersionIsRejected()
    {
        var json = ClientHelloSpecJson.Serialize(ClientHelloProfiles.ModernTls13.Spec)
            .Replace("\"version\":6", "\"version\":99", StringComparison.Ordinal);

        Assert.Throws<InvalidDataException>(() => ClientHelloSpecJson.Deserialize(json));
    }

    [Fact]
    public void RawExtensionCannotMasqueradeAsSemanticBuiltIn()
    {
        var profile = ClientHelloProfiles.Custom(builder => builder.WithExtensionLayout(
            ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.ServerName),
            ClientHelloExtensionSpec.Raw(0xFDE8, [1]),
            ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.SupportedVersions),
            ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.SupportedGroups),
            ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.SignatureAlgorithms),
            ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.KeyShare)));
        var json = ClientHelloSpecJson.Serialize(profile.Spec)
            .Replace("65000", "43", StringComparison.Ordinal);

        Assert.Throws<InvalidDataException>(() => ClientHelloSpecJson.Deserialize(json));
    }

    [Fact]
    public void DocumentSizeIsBoundedOnReadAndWrite()
    {
        var options = new ClientHelloSpecJsonOptions { MaximumDocumentSize = 256 };

        Assert.Throws<InvalidOperationException>(() =>
            ClientHelloSpecJson.SerializeUtf8(ClientHelloProfiles.ModernTls13.Spec, options));
        Assert.Throws<InvalidDataException>(() =>
            ClientHelloSpecJson.Deserialize(new string(' ', 257), options));
    }

    [Fact]
    public void GreaseEchSuiteCandidatesRoundTripAndRejectUnknownAlgorithms()
    {
        var profile = ClientHelloProfiles.Custom(builder => builder
            .WithGreaseEncryptedClientHello(
                [new TlsHpkeSymmetricCipherSuite(
                    TlsHpkeKdfId.HkdfSha256,
                    TlsHpkeAeadId.Aes128Gcm)],
                128,
                160));
        var json = ClientHelloSpecJson.Serialize(profile.Spec);
        var restored = ClientHelloSpecJson.Deserialize(json);

        Assert.Equal(profile.Spec.GreaseEchCipherSuites, restored.GreaseEchCipherSuites);
        Assert.Equal(profile.Spec.GreaseEchPayloadLengths, restored.GreaseEchPayloadLengths);
        Assert.Equal(
            profile.BuildDeterministicForTesting("example.com", [1, 2, 0]),
            ClientHelloProfiles.FromSpec(restored)
                .BuildDeterministicForTesting("example.com", [1, 2, 0]));

        var hostile = json.Replace(
            "\"HkdfSha256\"",
            "\"65535\"",
            StringComparison.Ordinal);
        Assert.Throws<InvalidDataException>(() => ClientHelloSpecJson.Deserialize(hostile));
    }
}
