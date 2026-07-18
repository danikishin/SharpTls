using System.Security.Cryptography;
using SharpTls.Cryptography;
using SharpTls.IO;
using SharpTls.Protocol;

namespace SharpTls.Tests.Sessions;

public sealed class Tls13ExternalPskTests
{
    [Fact]
    public void ExternalPskBinderUsesExtBinderLabelAndZeroTicketAge()
    {
        var identity = "managed-external-identity"u8.ToArray();
        var key = SHA256.HashData("managed external PSK secret"u8);
        using var external = new Tls13ExternalPsk(
            identity,
            key,
            TlsCipherSuite.TlsAes128GcmSha256);
        using var configuration = external.Snapshot();
        var profile = ClientHelloProfiles.Custom(builder => builder
            .WithTls13()
            .WithCipherSuites(TlsCipherSuite.TlsAes128GcmSha256)
            .WithSupportedGroups(NamedGroup.Secp256r1)
            .WithKeyShares(NamedGroup.Secp256r1)
            .WithSessionResumption());
        using var random = new DeterministicRandomSource([8, 4, 4, 6]);
        using var hello = ClientHelloEncoder.Build(
            "example.com",
            profile.Spec.SnapshotConfiguration(),
            random,
            new KeyShareSet(KeyShareFactory.CreateDeterministicForTesting),
            retry: null,
            pskOffer: new Tls13PskOffer(configuration));

        var extension = ReadExtension(hello.EncodedHandshake, TlsExtensionType.PreSharedKey);
        var psk = new TlsBinaryReader(extension);
        var identities = new TlsBinaryReader(psk.ReadVector16());
        Assert.Equal(identity, identities.ReadVector16().ToArray());
        Assert.Equal(0u, identities.ReadUInt32());
        identities.EnsureEnd("external PSK identities");
        var binders = new TlsBinaryReader(psk.ReadVector16());
        var actualBinder = binders.ReadVector8().ToArray();
        binders.EnsureEnd("external PSK binders");
        psk.EnsureEnd("external pre_shared_key");

        var truncatedLength = hello.EncodedHandshake.Length - (2 + 1 + 32);
        var binderHash = SHA256.HashData(hello.EncodedHandshake.AsSpan(0, truncatedLength));
        using var schedule = new Tls13KeySchedule(
            CipherSuiteInfo.Get(TlsCipherSuite.TlsAes128GcmSha256),
            key);
        var expectedExternal = schedule.ComputeExternalBinder(binderHash);
        var wrongResumption = schedule.ComputeResumptionBinder(binderHash);
        try
        {
            Assert.Equal(expectedExternal, actualBinder);
            Assert.NotEqual(wrongResumption, actualBinder);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(identity);
            CryptographicOperations.ZeroMemory(key);
            CryptographicOperations.ZeroMemory(binderHash);
            CryptographicOperations.ZeroMemory(actualBinder);
            CryptographicOperations.ZeroMemory(expectedExternal);
            CryptographicOperations.ZeroMemory(wrongResumption);
        }
    }

    [Fact]
    public void ExternalPskOwnsDefensiveSecretAndIdentityCopies()
    {
        var identity = Enumerable.Repeat((byte)0x11, 24).ToArray();
        var key = Enumerable.Repeat((byte)0x22, 32).ToArray();
        using var external = new Tls13ExternalPsk(identity, key);

        identity[0] = 0xFF;
        key[0] = 0xFF;
        var first = external.Identity;
        first[1] = 0xEE;

        Assert.Equal(0x11, external.Identity[0]);
        Assert.Equal(0x11, external.Identity[1]);
        using var snapshot = external.Snapshot();
        var snapKey = snapshot.CopyKey();
        try
        {
            Assert.All(snapKey, value => Assert.Equal(0x22, value));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(snapKey);
            CryptographicOperations.ZeroMemory(identity);
            CryptographicOperations.ZeroMemory(key);
            CryptographicOperations.ZeroMemory(first);
        }
    }

    [Fact]
    public void ExternalPskRejectsWeakOrUnusableConfiguration()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() =>
            new Tls13ExternalPsk([1], new byte[15]));
        Assert.Throws<ArgumentOutOfRangeException>(() =>
            new Tls13ExternalPsk([], new byte[32]));
        Assert.Throws<NotSupportedException>(() =>
            new Tls13ExternalPsk(
                [1],
                new byte[32],
                TlsCipherSuite.TlsEcdheRsaWithAes128GcmSha256));

        using var psk = new Tls13ExternalPsk([1], new byte[32]);
        Assert.Throws<ArgumentException>(() => new CustomTlsClient(
            new CustomTlsClientOptions
            {
                ClientHello = ClientHelloProfiles.UTlsAndroid11OkHttp,
                ExternalPsk = psk,
            }));
        using var cache = new Tls13SessionCache();
        Assert.Throws<ArgumentException>(() => new CustomTlsClient(
            new CustomTlsClientOptions
            {
                ExternalPsk = psk,
                SessionCache = cache,
            }));
    }

    private static byte[] ReadExtension(
        ReadOnlySpan<byte> handshake,
        TlsExtensionType expectedType)
    {
        var reader = new TlsBinaryReader(handshake);
        Assert.Equal((byte)HandshakeType.ClientHello, reader.ReadUInt8());
        var body = new TlsBinaryReader(reader.ReadBytes(reader.ReadUInt24()));
        reader.EnsureEnd("external PSK ClientHello framing");
        _ = body.ReadUInt16();
        _ = body.ReadBytes(TlsConstants.RandomLength);
        _ = body.ReadVector8();
        _ = body.ReadVector16();
        _ = body.ReadVector8();
        var extensions = new TlsBinaryReader(body.ReadVector16());
        body.EnsureEnd("external PSK ClientHello");
        while (!extensions.End)
        {
            var type = extensions.ReadUInt16();
            var data = extensions.ReadVector16().ToArray();
            if (type == (ushort)expectedType)
            {
                Assert.True(extensions.End);
                return data;
            }
        }
        throw new Xunit.Sdk.XunitException($"Extension {expectedType} was absent.");
    }
}
