using System.Security.Cryptography;
using SharpTls.Certificates;
using SharpTls.Ech;
using SharpTls.Handshake;
using SharpTls.IO;
using SharpTls.Protocol;
using SharpTls.Tests.Certificates;

namespace SharpTls.Tests.Ech;

public sealed class TlsEchServerKeyTests
{
    private static readonly byte[] X25519PrivateKey = Convert.FromHexString(
        "4612c550263fc8ad58375df3f557aac531d26850903e55a9f23f21d8534e8ac8");
    private static readonly byte[] X25519PublicKey = Convert.FromHexString(
        "3948cfe0ad1ddb695d780e59077195da6c56506b027329794ab02bca80815c4d");

    [Fact]
    public void ServerKeyRejectsMismatchedPrivateMaterial()
    {
        var config = Assert.Single(TlsEchConfigList.Parse(
            CreateConfigList(
                TlsHpkeKemId.DhkemX25519HkdfSha256,
                X25519PublicKey,
                TlsHpkeKdfId.HkdfSha256)).Configurations);

        Assert.Throws<CryptographicException>(() =>
            new TlsEchServerKey(config, Enumerable.Repeat((byte)1, 32).ToArray()));
    }

    [Theory]
    [InlineData(0x7FFF, (ushort)TlsHpkeAeadId.Aes128Gcm)]
    [InlineData((ushort)TlsHpkeKdfId.HkdfSha256, 0x7FFF)]
    public void ServerKeyRejectsConfigurationsWithoutKnownHpkeSuites(
        ushort kdfId,
        ushort aeadId)
    {
        var config = Assert.Single(TlsEchConfigList.Parse(
            CreateConfigList(
                TlsHpkeKemId.DhkemX25519HkdfSha256,
                X25519PublicKey,
                (TlsHpkeKdfId)kdfId,
                (TlsHpkeAeadId)aeadId)).Configurations);

        Assert.Throws<ArgumentException>(() =>
            new TlsEchServerKey(config, X25519PrivateKey));
    }

    [Fact]
    public void ServerOptionsRequireTls13OnlyAndUniqueConfigIds()
    {
        using var pki = TestPki.Create();
        using var credential = new TlsServerCertificate(
            pki.Leaf,
            (RSA)pki.LeafKey,
            [pki.Root]);
        var config = Assert.Single(TlsEchConfigList.Parse(
            CreateConfigList(
                TlsHpkeKemId.DhkemX25519HkdfSha256,
                X25519PublicKey,
                TlsHpkeKdfId.HkdfSha256)).Configurations);
        using var key = new TlsEchServerKey(config, X25519PrivateKey);

        Assert.Throws<ArgumentException>(() => new CustomTlsServer(
            new CustomTlsServerOptions
            {
                ServerCertificate = credential,
                EncryptedClientHelloKeys = [key],
            }));
        Assert.Throws<ArgumentException>(() => new CustomTlsServer(
            new CustomTlsServerOptions
            {
                ServerCertificate = credential,
                SupportedVersions = [TlsProtocolVersion.Tls13],
                EncryptedClientHelloKeys = [key, key],
            }));
    }

    [Fact]
    public void P256ServerKeyAcceptsRfc9180ReceiverKeyPair()
    {
        if (!HpkeNistKem.IsSupported(TlsHpkeKemId.DhkemP256HkdfSha256))
        {
            return;
        }
        var publicKey = Convert.FromHexString(
            "04fe8c19ce0905191ebc298a9245792531f26f0cece2460639e8bc39cb7f706" +
            "a826a779b4cf969b8a0e539c7f62fb3d30ad6aa8f80e30f1d128aafd68a2ce72ea0");
        var privateKey = Convert.FromHexString(
            "f3ce7fdae57e1a310d87f1ebbde6f328be0a99cdbcadf4d6589cf29de4b8ffd2");
        var config = Assert.Single(TlsEchConfigList.Parse(
            CreateConfigList(
                TlsHpkeKemId.DhkemP256HkdfSha256,
                publicKey,
                TlsHpkeKdfId.HkdfSha256)).Configurations);

        using var key = new TlsEchServerKey(config, privateKey, sendAsRetry: true);

        Assert.Same(config, key.Configuration);
        Assert.True(key.SendAsRetry);
        CryptographicOperations.ZeroMemory(privateKey);
        CryptographicOperations.ZeroMemory(publicKey);
    }

    [Fact]
    public void ReceiverRejectsTruncatedOuterExtensionBeforeHpkeSetup()
    {
        var config = Assert.Single(TlsEchConfigList.Parse(
            CreateConfigList(
                TlsHpkeKemId.DhkemX25519HkdfSha256,
                X25519PublicKey,
                TlsHpkeKdfId.HkdfSha256)).Configurations);
        using var key = new TlsEchServerKey(config, X25519PrivateKey);
        using var keySnapshot = key.Snapshot();
        using var receiver = new TlsEchServerReceiver([keySnapshot]);
        var profile = ClientHelloProfiles.Custom(builder => builder
            .WithTls13()
            .WithExtensionLayout(
                ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.ServerName),
                ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.SupportedVersions),
                ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.SupportedGroups),
                ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.SignatureAlgorithms),
                ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.KeyShare),
                ClientHelloExtensionSpec.Raw(
                    (ushort)TlsExtensionType.EncryptedClientHello,
                    [0])));
        var encoded = profile.BuildDeterministicForTesting("public.example", [9, 1, 1]);
        var message = new HandshakeMessage(
            HandshakeType.ClientHello,
            encoded[TlsConstants.HandshakeHeaderLength..],
            encoded);

        Assert.Throws<TlsProtocolException>(() =>
            receiver.ProcessInitial(message, out _));
    }

    private static byte[] CreateConfigList(
        TlsHpkeKemId kemId,
        ReadOnlySpan<byte> publicKey,
        TlsHpkeKdfId kdfId,
        TlsHpkeAeadId aeadId = TlsHpkeAeadId.Aes128Gcm)
    {
        var suites = new TlsBinaryWriter();
        suites.WriteUInt16((ushort)kdfId);
        suites.WriteUInt16((ushort)aeadId);
        var contents = new TlsBinaryWriter();
        contents.WriteUInt8(7);
        contents.WriteUInt16((ushort)kemId);
        contents.WriteVector16(publicKey);
        contents.WriteVector16(suites.WrittenSpan);
        contents.WriteUInt8(32);
        contents.WriteVector8("public.example"u8);
        contents.WriteVector16([]);
        var configuration = new TlsBinaryWriter();
        configuration.WriteUInt16((ushort)TlsExtensionType.EncryptedClientHello);
        configuration.WriteVector16(contents.WrittenSpan);
        var list = new TlsBinaryWriter();
        list.WriteVector16(configuration.WrittenSpan);
        return list.ToArray();
    }
}
