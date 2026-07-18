using SharpTls.Cryptography;
using SharpTls.Ech;
using SharpTls.IO;
using SharpTls.Protocol;

namespace SharpTls.Tests.Ech;

public sealed class EchGreaseClientHelloBuilderTests
{
    private static readonly TlsEchGreaseConfiguration Grease = new(
    [
        new TlsHpkeSymmetricCipherSuite(
            TlsHpkeKdfId.HkdfSha256,
            TlsHpkeAeadId.Aes128Gcm),
    ]);

    [Fact]
    public void BuildsPlausibleDeterministicGreaseAndFreshSeedsChangeIt()
    {
        var profile = ClientHelloProfiles.Custom(builder => builder
            .WithTls13()
            .WithSupportedGroups(NamedGroup.Secp256r1, NamedGroup.Secp384r1)
            .WithKeyShares(NamedGroup.Secp256r1));
        using var firstRandom = new DeterministicRandomSource("grease-one"u8);
        using var secondRandom = new DeterministicRandomSource("grease-two"u8);
        using var first = EchGreaseClientHelloBuilder.Build(
            "public.example",
            profile.Spec.SnapshotConfiguration(),
            Grease,
            firstRandom,
            new KeyShareSet());
        using var second = EchGreaseClientHelloBuilder.Build(
            "public.example",
            profile.Spec.SnapshotConfiguration(),
            Grease,
            secondRandom,
            new KeyShareSet());

        var firstBody = EchGreaseClientHelloBuilder.ReadExtensionBody(
            first.EncodedHandshake);
        var secondBody = EchGreaseClientHelloBuilder.ReadExtensionBody(
            second.EncodedHandshake);
        Assert.NotEqual(firstBody, secondBody);

        var reader = new TlsBinaryReader(firstBody);
        Assert.Equal(0, reader.ReadUInt8());
        Assert.Equal((ushort)TlsHpkeKdfId.HkdfSha256, reader.ReadUInt16());
        Assert.Equal((ushort)TlsHpkeAeadId.Aes128Gcm, reader.ReadUInt16());
        _ = reader.ReadUInt8();
        var encapsulatedKey = reader.ReadVector16();
        var payload = reader.ReadVector16();
        reader.EnsureEnd("GREASE ECH");
        Assert.Equal(32, encapsulatedKey.Length);
        Assert.True(encapsulatedKey.IndexOfAnyExcept((byte)0) >= 0);
        Assert.True(payload.Length > 16);
        Assert.Equal(0, (payload.Length - 16) & 31);
        Assert.True(payload.IndexOfAnyExcept((byte)0) >= 0);
    }

    [Fact]
    public void HelloRetryRequestCopiesCompleteGreaseExtensionExactly()
    {
        var profile = ClientHelloProfiles.Custom(builder => builder
            .WithTls13()
            .WithSupportedGroups(NamedGroup.Secp256r1, NamedGroup.Secp384r1)
            .WithKeyShares(NamedGroup.Secp256r1));
        using var random = new DeterministicRandomSource("grease-retry"u8);
        using var first = EchGreaseClientHelloBuilder.Build(
            "public.example",
            profile.Spec.SnapshotConfiguration(),
            Grease,
            random,
            new KeyShareSet());
        using var retry = ClientHelloEncoder.BuildRetry(
            first,
            NamedGroup.Secp384r1,
            cookie: [1, 2, 3]);

        Assert.Equal(
            EchGreaseClientHelloBuilder.ReadExtensionBody(first.EncodedHandshake),
            EchGreaseClientHelloBuilder.ReadExtensionBody(retry.EncodedHandshake));
        Assert.Equal(first.Random, retry.Random);
        Assert.Equal(first.SessionId, retry.SessionId);
    }
}
