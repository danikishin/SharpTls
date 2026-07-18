using System.Text;
using SharpTls.Ech;
using SharpTls.IO;
using SharpTls.Protocol;

namespace SharpTls.Tests.Ech;

public sealed class TlsEchConfigListTests
{
    [Fact]
    public void CurrentConfigurationIsParsedAndDefensivelySnapshotted()
    {
        var publicKey = Enumerable.Range(0, 32).Select(value => (byte)value).ToArray();
        var encoded = EncodeList(EncodeCurrent(
            configId: 7,
            kemId: (ushort)TlsHpkeKemId.DhkemX25519HkdfSha256,
            publicKey,
            suites:
            [
                (0xFE00, 0xFE01),
                ((ushort)TlsHpkeKdfId.HkdfSha256,
                 (ushort)TlsHpkeAeadId.Aes128Gcm),
                ((ushort)TlsHpkeKdfId.HkdfSha256,
                 (ushort)TlsHpkeAeadId.ChaCha20Poly1305),
            ],
            maximumNameLength: 42,
            publicName: "public.example",
            extensions: [(0x0001, new byte[] { 9, 8 })]));

        var parsed = TlsEchConfigList.Parse(encoded);
        encoded[^1] ^= 0xFF;
        publicKey[0] ^= 0xFF;
        var config = Assert.Single(parsed.Configurations);

        Assert.Equal((byte)7, config.ConfigId);
        Assert.Equal(TlsHpkeKemId.DhkemX25519HkdfSha256, config.KemId);
        Assert.Equal(Enumerable.Range(0, 32).Select(value => (byte)value), config.GetPublicKey());
        Assert.Equal(42, config.MaximumNameLength);
        Assert.Equal("public.example", config.PublicName);
        Assert.Equal(
            [
                new TlsHpkeSymmetricCipherSuite(
                    TlsHpkeKdfId.HkdfSha256,
                    TlsHpkeAeadId.Aes128Gcm),
                new TlsHpkeSymmetricCipherSuite(
                    TlsHpkeKdfId.HkdfSha256,
                    TlsHpkeAeadId.ChaCha20Poly1305),
            ],
            config.CipherSuites);
        Assert.False(config.HasUnsupportedMandatoryExtensions);
        var extension = Assert.Single(config.Extensions);
        Assert.Equal((ushort)1, extension.Type);
        Assert.Equal(new byte[] { 9, 8 }, extension.GetData());
    }

    [Fact]
    public void UnknownVersionAndUnknownKemAreIgnoredWithoutMisparsingFollowingConfig()
    {
        var unknownVersion = EncodeConfig(0xFE0C, [1, 2, 3]);
        var unknownKem = EncodeCurrent(
            configId: 1,
            kemId: 0xFE00,
            publicKey: [1],
            suites: [((ushort)TlsHpkeKdfId.HkdfSha256,
                      (ushort)TlsHpkeAeadId.Aes128Gcm)],
            maximumNameLength: 0,
            publicName: "ignored.example");
        var supported = EncodeCurrent(
            configId: 2,
            kemId: (ushort)TlsHpkeKemId.DhkemX25519HkdfSha256,
            publicKey: new byte[32],
            suites: [((ushort)TlsHpkeKdfId.HkdfSha256,
                      (ushort)TlsHpkeAeadId.Aes128Gcm)],
            maximumNameLength: 0,
            publicName: "public.example");

        var parsed = TlsEchConfigList.Parse(EncodeList(unknownVersion, unknownKem, supported));

        Assert.Equal(1, parsed.UnknownVersionCount);
        Assert.Equal((byte)2, Assert.Single(parsed.Configurations).ConfigId);
    }

    [Fact]
    public void UnknownMandatoryExtensionMakesConfigurationIneligible()
    {
        var encoded = EncodeList(EncodeCurrent(
            configId: 3,
            kemId: (ushort)TlsHpkeKemId.DhkemX25519HkdfSha256,
            publicKey: new byte[32],
            suites: [((ushort)TlsHpkeKdfId.HkdfSha256,
                      (ushort)TlsHpkeAeadId.Aes128Gcm)],
            maximumNameLength: 0,
            publicName: "public.example",
            extensions: [(0x8001, new byte[] { 1 })]));

        Assert.True(Assert.Single(
            TlsEchConfigList.Parse(encoded).Configurations)
            .HasUnsupportedMandatoryExtensions);
    }

    [Theory]
    [InlineData("")]
    [InlineData(".example")]
    [InlineData("example.")]
    [InlineData("bad_name.example")]
    [InlineData("-bad.example")]
    [InlineData("bad-.example")]
    [InlineData("public.123")]
    [InlineData("public.0x")]
    [InlineData("public.0x7f")]
    public void InvalidOrIpv4AmbiguousPublicNamesAreRejected(string publicName)
    {
        var encoded = EncodeList(EncodeCurrent(
            configId: 1,
            kemId: (ushort)TlsHpkeKemId.DhkemX25519HkdfSha256,
            publicKey: new byte[32],
            suites: [((ushort)TlsHpkeKdfId.HkdfSha256,
                      (ushort)TlsHpkeAeadId.Aes128Gcm)],
            maximumNameLength: 0,
            publicName));

        Assert.Throws<TlsProtocolException>(() => TlsEchConfigList.Parse(encoded));
    }

    [Fact]
    public void EmptyTruncatedTrailingAndInvalidPublicKeyListsAreRejected()
    {
        Assert.Throws<TlsProtocolException>(() => TlsEchConfigList.Parse([0, 0]));

        var valid = EncodeList(EncodeCurrent(
            configId: 1,
            kemId: (ushort)TlsHpkeKemId.DhkemX25519HkdfSha256,
            publicKey: new byte[32],
            suites: [((ushort)TlsHpkeKdfId.HkdfSha256,
                      (ushort)TlsHpkeAeadId.Aes128Gcm)],
            maximumNameLength: 0,
            publicName: "public.example"));
        Assert.Throws<TlsProtocolException>(() => TlsEchConfigList.Parse(valid[..^1]));
        Assert.Throws<TlsProtocolException>(() => TlsEchConfigList.Parse([.. valid, 0]));

        var wrongKey = EncodeList(EncodeCurrent(
            configId: 1,
            kemId: (ushort)TlsHpkeKemId.DhkemX25519HkdfSha256,
            publicKey: new byte[31],
            suites: [((ushort)TlsHpkeKdfId.HkdfSha256,
                      (ushort)TlsHpkeAeadId.Aes128Gcm)],
            maximumNameLength: 0,
            publicName: "public.example"));
        Assert.Throws<TlsProtocolException>(() => TlsEchConfigList.Parse(wrongKey));
    }

    [Fact]
    public void DuplicateCipherSuitesAndExtensionsAreRejected()
    {
        var suite = ((ushort)TlsHpkeKdfId.HkdfSha256,
            (ushort)TlsHpkeAeadId.Aes128Gcm);
        Assert.Throws<TlsProtocolException>(() => TlsEchConfigList.Parse(EncodeList(
            EncodeCurrent(
                1,
                (ushort)TlsHpkeKemId.DhkemX25519HkdfSha256,
                new byte[32],
                [suite, suite],
                0,
                "public.example"))));
        Assert.Throws<TlsProtocolException>(() => TlsEchConfigList.Parse(EncodeList(
            EncodeCurrent(
                1,
                (ushort)TlsHpkeKemId.DhkemX25519HkdfSha256,
                new byte[32],
                [suite],
                0,
                "public.example",
                [(1, new byte[] { 1 }), (1, new byte[] { 2 })]))));
    }

    [Fact]
    public void SelectionUsesConfigurationAndCipherSuiteWirePreference()
    {
        var mandatory = EncodeCurrent(
            1,
            (ushort)TlsHpkeKemId.DhkemX25519HkdfSha256,
            new byte[32],
            [((ushort)TlsHpkeKdfId.HkdfSha256, (ushort)TlsHpkeAeadId.Aes128Gcm)],
            0,
            "ignored.example",
            [(0x8001, [])]);
        var selected = EncodeCurrent(
            2,
            (ushort)TlsHpkeKemId.DhkemX25519HkdfSha256,
            Enumerable.Repeat((byte)1, 32).ToArray(),
            [
                ((ushort)TlsHpkeKdfId.HkdfSha512, (ushort)TlsHpkeAeadId.Aes256Gcm),
                ((ushort)TlsHpkeKdfId.HkdfSha256, (ushort)TlsHpkeAeadId.Aes128Gcm),
            ],
            0,
            "public.example");

        var selection = TlsEchConfigList.Parse(EncodeList(mandatory, selected))
            .SelectSupportedConfiguration();

        Assert.NotNull(selection);
        Assert.Equal((byte)2, selection.Configuration.ConfigId);
        Assert.Equal(
            new TlsHpkeSymmetricCipherSuite(
                TlsHpkeKdfId.HkdfSha512,
                TlsHpkeAeadId.Aes256Gcm),
            selection.CipherSuite);
    }

    [Fact]
    public void NistConfigurationSelectionPreservesWirePreference()
    {
        if (!HpkeNistKem.IsSupported(TlsHpkeKemId.DhkemP256HkdfSha256))
        {
            return;
        }
        var p256 = EncodeCurrent(
            8,
            (ushort)TlsHpkeKemId.DhkemP256HkdfSha256,
            Convert.FromHexString(
                "04fe8c19ce0905191ebc298a9245792531f26f0cece2460639e8bc39cb7f706" +
                "a826a779b4cf969b8a0e539c7f62fb3d30ad6aa8f80e30f1d128aafd68a2ce72ea0"),
            [((ushort)TlsHpkeKdfId.HkdfSha256, (ushort)TlsHpkeAeadId.Aes128Gcm)],
            0,
            "public.example");
        var x25519 = EncodeCurrent(
            9,
            (ushort)TlsHpkeKemId.DhkemX25519HkdfSha256,
            Enumerable.Repeat((byte)7, 32).ToArray(),
            [((ushort)TlsHpkeKdfId.HkdfSha256, (ushort)TlsHpkeAeadId.Aes128Gcm)],
            0,
            "public.example");

        var selection = TlsEchConfigList.Parse(EncodeList(p256, x25519))
            .SelectSupportedConfiguration();

        Assert.NotNull(selection);
        Assert.Equal((byte)8, selection.Configuration.ConfigId);
        Assert.Equal(TlsHpkeKemId.DhkemP256HkdfSha256, selection.Configuration.KemId);
    }

    [Fact]
    public void InvalidNistPublicPointIsRejectedDuringParsing()
    {
        var invalidPoint = new byte[65];
        invalidPoint[0] = 4;
        var encoded = EncodeList(EncodeCurrent(
            1,
            (ushort)TlsHpkeKemId.DhkemP256HkdfSha256,
            invalidPoint,
            [((ushort)TlsHpkeKdfId.HkdfSha256, (ushort)TlsHpkeAeadId.Aes128Gcm)],
            0,
            "public.example"));

        Assert.Throws<TlsProtocolException>(() => TlsEchConfigList.Parse(encoded));
    }

    private static byte[] EncodeList(params byte[][] configurations)
    {
        var entries = new TlsBinaryWriter();
        foreach (var configuration in configurations)
        {
            entries.WriteBytes(configuration);
        }
        var list = new TlsBinaryWriter();
        list.WriteVector16(entries.WrittenSpan);
        return list.ToArray();
    }

    private static byte[] EncodeConfig(ushort version, ReadOnlySpan<byte> contents)
    {
        var encoded = new TlsBinaryWriter();
        encoded.WriteUInt16(version);
        encoded.WriteVector16(contents);
        return encoded.ToArray();
    }

    private static byte[] EncodeCurrent(
        byte configId,
        ushort kemId,
        ReadOnlySpan<byte> publicKey,
        (ushort Kdf, ushort Aead)[] suites,
        byte maximumNameLength,
        string publicName,
        (ushort Type, byte[] Data)[]? extensions = null)
    {
        var encodedSuites = new TlsBinaryWriter();
        foreach (var suite in suites)
        {
            encodedSuites.WriteUInt16(suite.Kdf);
            encodedSuites.WriteUInt16(suite.Aead);
        }
        var encodedExtensions = new TlsBinaryWriter();
        foreach (var extension in extensions ?? [])
        {
            encodedExtensions.WriteUInt16(extension.Type);
            encodedExtensions.WriteVector16(extension.Data);
        }
        var contents = new TlsBinaryWriter();
        contents.WriteUInt8(configId);
        contents.WriteUInt16(kemId);
        contents.WriteVector16(publicKey);
        contents.WriteVector16(encodedSuites.WrittenSpan);
        contents.WriteUInt8(maximumNameLength);
        contents.WriteVector8(Encoding.ASCII.GetBytes(publicName));
        contents.WriteVector16(encodedExtensions.WrittenSpan);
        return EncodeConfig((ushort)TlsExtensionType.EncryptedClientHello, contents.WrittenSpan);
    }
}
