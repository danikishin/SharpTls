using SharpTls.IO;
using SharpTls.Protocol;

namespace SharpTls.Tests.ClientHello;

public sealed class UTlsProfileTests
{
    [Fact]
    public void Chrome83SpecMatchesPinnedUTlsOrdering()
    {
        var spec = ClientHelloProfiles.UTlsChrome83.Spec;

        Assert.Equal(
            [
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
                TlsCipherSuite.TlsRsaWithAes256CbcSha,
            ],
            spec.CipherSuites);
        Assert.Equal(
            [
                TlsProtocolVersion.Tls13,
                TlsProtocolVersion.Tls12,
                TlsProtocolVersion.Tls11,
                TlsProtocolVersion.Tls10,
            ],
            spec.SupportedVersions);
        Assert.Equal(
            [NamedGroup.X25519, NamedGroup.Secp256r1, NamedGroup.Secp384r1],
            spec.SupportedGroups);
        Assert.Equal([NamedGroup.X25519], spec.KeyShareGroups);
        Assert.True(spec.UseBoringPadding);
        Assert.Equal(new byte[] { 0 }, spec.FixedGreaseKeyShareBody);
        Assert.Equal(new byte[] { 0 }, spec.SecondaryGreaseExtensionBody);
        Assert.True(spec.SupportsSessionResumption);
        Assert.True(spec.SupportsEarlyData);
        Assert.Same(ClientHelloProfiles.UTlsChrome83, ClientHelloProfiles.UTlsChrome87);
        Assert.Same(ClientHelloProfiles.UTlsChrome83, ClientHelloProfiles.UTlsEdge85);
    }

    [Fact]
    public void Firefox99SpecMatchesPinnedUTlsOrdering()
    {
        var spec = ClientHelloProfiles.UTlsFirefox99.Spec;
        var hello = ClientHelloProfiles.UTlsFirefox99.BuildDeterministicForTesting(
            "example.com",
            [9, 9]);
        var extensions = ReadExtensions(hello);

        Assert.Equal(TlsCipherSuite.TlsAes128GcmSha256, spec.CipherSuites[0]);
        Assert.True(spec.SupportsSessionResumption);
        Assert.True(spec.SupportsEarlyData);
        Assert.Equal(TlsCipherSuite.TlsChaCha20Poly1305Sha256, spec.CipherSuites[1]);
        Assert.Equal(TlsCipherSuite.TlsAes256GcmSha384, spec.CipherSuites[2]);
        Assert.Equal(
            [
                NamedGroup.X25519,
                NamedGroup.Secp256r1,
                NamedGroup.Secp384r1,
                NamedGroup.Secp521r1,
                NamedGroup.Ffdhe2048,
                NamedGroup.Ffdhe3072,
            ],
            spec.SupportedGroups);
        Assert.Equal([NamedGroup.X25519, NamedGroup.Secp256r1], spec.KeyShareGroups);
        Assert.False(spec.Grease);
        Assert.Equal(512, hello.Length);
        Assert.Equal(
            [0, 23, 0xFF01, 10, 11, 35, 16, 5, 34, 51, 43, 13, 45, 28, 21],
            extensions.Select(extension => (int)extension.Type));
        Assert.Equal(new byte[] { 0, 8, 4, 3, 5, 3, 6, 3, 2, 3 }, extensions[8].Data);
        Assert.Equal(new byte[] { 0x40, 0x01 }, extensions[13].Data);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void AppleProfilesPreserveDuplicateSignaturesGreaseAndCompression(bool safari)
    {
        var profile = safari ? ClientHelloProfiles.UTlsSafari16 : ClientHelloProfiles.UTlsIOS14;
        var spec = profile.Spec;
        var hello = profile.BuildDeterministicForTesting("example.com", [1, 4, 1, 6]);
        var extensions = ReadExtensions(hello);

        Assert.Equal(512, hello.Length);
        Assert.True(spec.AllowsDuplicateSignatureAlgorithms);
        Assert.Equal(
            2,
            spec.SignatureAlgorithms.Count(value => value == SignatureScheme.RsaPssRsaeSha384));
        Assert.Equal(new byte[] { 0 }, spec.FixedGreaseKeyShareBody);
        Assert.Equal(new byte[] { 0 }, spec.SecondaryGreaseExtensionBody);
        Assert.Equal(2, extensions.Count(extension => IsGrease(extension.Type)));
        Assert.Equal(
            safari,
            extensions.Any(extension => extension.Type == 27 &&
                extension.Data.SequenceEqual(new byte[] { 2, 0, 1 })));
    }

    [Fact]
    public void SafariProfileJsonAndCaptureRoundTripPreserveParameterizedSlots()
    {
        var seed = new byte[] { 1, 6, 0 };
        var profile = ClientHelloProfiles.UTlsSafari16;
        var jsonSpec = ClientHelloSpecJson.Deserialize(ClientHelloSpecJson.Serialize(profile.Spec));
        var captured = profile.BuildDeterministicForTesting("example.com", seed);
        var imported = ClientHelloCapture.Import(captured);

        Assert.Equal(
            captured,
            ClientHelloProfiles.FromSpec(jsonSpec)
                .BuildDeterministicForTesting("example.com", seed));
        Assert.Equal(
            captured,
            ClientHelloProfiles.FromSpec(imported.Spec)
                .BuildDeterministicForTesting("example.com", seed));
    }

    [Fact]
    public void Android11OkHttpPreservesLegacyTls12WireShape()
    {
        var profile = ClientHelloProfiles.UTlsAndroid11OkHttp;
        var spec = profile.Spec;
        var seed = new byte[] { 1, 1 };
        var hello = profile.BuildDeterministicForTesting("example.com", seed);
        var extensions = ReadExtensions(hello);

        Assert.Equal([TlsProtocolVersion.Tls12], spec.SupportedVersions);
        Assert.Empty(spec.KeyShareGroups);
        Assert.DoesNotContain(extensions, extension =>
            extension.Type is (ushort)TlsExtensionType.SupportedVersions or
                (ushort)TlsExtensionType.KeyShare);
        Assert.Equal(
            [0, 23, 0xFF01, 10, 11, 5, 13],
            extensions.Select(extension => (int)extension.Type));

        var imported = ClientHelloCapture.Import(hello);
        var jsonSpec = ClientHelloSpecJson.Deserialize(ClientHelloSpecJson.Serialize(spec));
        Assert.Equal(
            hello,
            ClientHelloProfiles.FromSpec(imported.Spec)
                .BuildDeterministicForTesting("example.com", seed));
        Assert.Equal(
            hello,
            ClientHelloProfiles.FromSpec(jsonSpec)
                .BuildDeterministicForTesting("example.com", seed));
    }

    [Fact]
    public void Chrome83WireShapeHasTwoDistinctGreaseExtensionsAndBoringPadding()
    {
        var hello = ClientHelloProfiles.UTlsChrome83.BuildDeterministicForTesting(
            "example.com",
            [8, 3]);
        var extensions = ReadExtensions(hello);

        Assert.Equal(512, hello.Length);
        Assert.Equal(17, extensions.Count);
        Assert.True(IsGrease(extensions[0].Type));
        Assert.Empty(extensions[0].Data);
        Assert.Equal((ushort)TlsExtensionType.ServerName, extensions[1].Type);
        Assert.Equal(23, extensions[2].Type);
        Assert.Equal(0xFF01, extensions[3].Type);
        Assert.Equal(new byte[] { 0 }, extensions[3].Data);
        Assert.Equal((ushort)TlsExtensionType.SupportedGroups, extensions[4].Type);
        Assert.Equal((ushort)TlsExtensionType.ApplicationLayerProtocolNegotiation, extensions[7].Type);
        Assert.Equal((ushort)TlsExtensionType.SignatureAlgorithms, extensions[9].Type);
        Assert.Equal((ushort)TlsExtensionType.KeyShare, extensions[11].Type);
        Assert.Equal((ushort)TlsExtensionType.PskKeyExchangeModes, extensions[12].Type);
        Assert.Equal((ushort)TlsExtensionType.SupportedVersions, extensions[13].Type);
        Assert.Equal(27, extensions[14].Type);
        Assert.Equal(new byte[] { 2, 0, 2 }, extensions[14].Data);
        Assert.True(IsGrease(extensions[15].Type));
        Assert.NotEqual(extensions[0].Type, extensions[15].Type);
        Assert.Equal(new byte[] { 0 }, extensions[15].Data);
        Assert.Equal((ushort)TlsExtensionType.Padding, extensions[16].Type);
        Assert.True(extensions[16].Data.Length > 0);
        Assert.True(extensions[16].Data.AsSpan().IndexOfAnyExcept((byte)0) < 0);
    }

    [Fact]
    public void Chrome83CaptureCanBeNormalizedAndRebuiltByteForByte()
    {
        var seed = new byte[] { 8, 8, 0, 2, 7 };
        var captured = ClientHelloProfiles.UTlsChrome83.BuildDeterministicForTesting(
            "example.com",
            seed);

        var imported = ClientHelloCapture.Import(captured);
        var rebuilt = ClientHelloProfiles.FromSpec(imported.Spec)
            .BuildDeterministicForTesting("example.com", seed);

        Assert.Equal(captured, rebuilt);
    }

    [Fact]
    public void SecondaryGreaseRequiresDistinctValueClasses()
    {
        Assert.Throws<InvalidOperationException>(() => ClientHelloProfiles.Custom(builder => builder
            .WithGrease()
            .WithSecondaryGreaseExtension([0])));
    }

    private static List<(ushort Type, byte[] Data)> ReadExtensions(byte[] handshake)
    {
        var reader = new TlsBinaryReader(handshake);
        Assert.Equal((byte)HandshakeType.ClientHello, reader.ReadUInt8());
        var body = new TlsBinaryReader(reader.ReadBytes(reader.ReadUInt24()));
        reader.EnsureEnd("ClientHello test framing");
        _ = body.ReadUInt16();
        _ = body.ReadBytes(TlsConstants.RandomLength);
        _ = body.ReadVector8();
        _ = body.ReadVector16();
        _ = body.ReadVector8();
        var encodedExtensions = new TlsBinaryReader(body.ReadVector16());
        body.EnsureEnd("ClientHello test body");
        var result = new List<(ushort Type, byte[] Data)>();
        while (!encodedExtensions.End)
        {
            result.Add((encodedExtensions.ReadUInt16(), encodedExtensions.ReadVector16().ToArray()));
        }
        return result;
    }

    private static bool IsGrease(ushort value) =>
        (value & 0x0F0F) == 0x0A0A && (byte)(value >> 8) == (byte)value;
}
