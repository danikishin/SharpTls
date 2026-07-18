using System.Text;
using SharpTls.Cryptography;
using SharpTls.Ech;
using SharpTls.IO;
using SharpTls.Protocol;

namespace SharpTls.Tests.Ech;

public sealed class EchClientHelloBuilderTests
{
    [Fact]
    public void DeterministicInnerAndOuterHaveRfc9849StructureAndPrivacyBoundary()
    {
        var configList = TlsEchConfigList.Parse(CreateConfigList(
            maximumNameLength: 40,
            publicName: "public.example"));
        var selection = configList.SelectSupportedConfiguration();
        Assert.NotNull(selection);
        var inner = new ClientHelloBuilder()
            .WithTls13()
            .WithAlpn("h2", "http/1.1")
            .BuildConfiguration();
        var outer = new ClientHelloBuilder()
            .WithTls13()
            .BuildConfiguration();
        using var random = new DeterministicRandomSource([9, 8, 4, 9]);
        using var result = EchClientHelloBuilder.Build(
            "private.example",
            inner,
            outer,
            selection,
            random,
            new KeyShareSet(KeyShareFactory.CreateDeterministicForTesting),
            new KeyShareSet(KeyShareFactory.CreateDeterministicForTesting));

        Assert.Equal(result.Inner.SessionId, result.Outer.SessionId);
        Assert.NotEqual(result.Inner.Random, result.Outer.Random);
        Assert.Equal(0, result.EncodedInner.Length & 31);
        Assert.Equal("private.example", ReadSni(result.Inner.EncodedHandshake));
        Assert.Equal("public.example", ReadSni(result.Outer.EncodedHandshake));
        Assert.True(result.Outer.EncodedHandshake.AsSpan().IndexOf(
            "private.example"u8) < 0);

        var innerEch = ReadExtension(
            result.Inner.EncodedHandshake,
            TlsExtensionType.EncryptedClientHello);
        Assert.Equal(new byte[] { 1 }, innerEch);

        var outerEch = new TlsBinaryReader(ReadExtension(
            result.Outer.EncodedHandshake,
            TlsExtensionType.EncryptedClientHello));
        Assert.Equal(0, outerEch.ReadUInt8());
        Assert.Equal((ushort)TlsHpkeKdfId.HkdfSha256, outerEch.ReadUInt16());
        Assert.Equal((ushort)TlsHpkeAeadId.Aes128Gcm, outerEch.ReadUInt16());
        Assert.Equal(7, outerEch.ReadUInt8());
        Assert.Equal(32, outerEch.ReadVector16().Length);
        var payload = outerEch.ReadVector16();
        Assert.Equal(result.EncodedInner.Length + 16, payload.Length);
        Assert.True(payload.IndexOfAnyExcept((byte)0) >= 0);
        outerEch.EnsureEnd("test outer ECH");
    }

    [Fact]
    public void P256EchBuilderIsByteDeterministicAndUsesSec1Encapsulation()
    {
        if (!HpkeNistKem.IsSupported(TlsHpkeKemId.DhkemP256HkdfSha256))
        {
            return;
        }
        var selection = TlsEchConfigList.Parse(CreateP256ConfigList())
            .SelectSupportedConfiguration()!;
        var configuration = new ClientHelloBuilder().WithTls13().BuildConfiguration();
        using var firstRandom = new DeterministicRandomSource("p256-ech-builder"u8);
        using var secondRandom = new DeterministicRandomSource("p256-ech-builder"u8);
        using var first = EchClientHelloBuilder.Build(
            "private.example",
            configuration,
            configuration,
            selection,
            firstRandom,
            new KeyShareSet(KeyShareFactory.CreateDeterministicForTesting),
            new KeyShareSet(KeyShareFactory.CreateDeterministicForTesting));
        using var second = EchClientHelloBuilder.Build(
            "private.example",
            configuration,
            configuration,
            selection,
            secondRandom,
            new KeyShareSet(KeyShareFactory.CreateDeterministicForTesting),
            new KeyShareSet(KeyShareFactory.CreateDeterministicForTesting));

        Assert.Equal(first.Outer.EncodedHandshake, second.Outer.EncodedHandshake);
        Assert.Equal(first.EncodedInner, second.EncodedInner);
        var ech = new TlsBinaryReader(ReadExtension(
            first.Outer.EncodedHandshake,
            TlsExtensionType.EncryptedClientHello));
        Assert.Equal(0, ech.ReadUInt8());
        Assert.Equal((ushort)TlsHpkeKdfId.HkdfSha256, ech.ReadUInt16());
        Assert.Equal((ushort)TlsHpkeAeadId.Aes128Gcm, ech.ReadUInt16());
        Assert.Equal(8, ech.ReadUInt8());
        var encapsulatedKey = ech.ReadVector16();
        Assert.Equal(65, encapsulatedKey.Length);
        Assert.Equal(4, encapsulatedKey[0]);
        Assert.Equal(first.EncodedInner.Length + 16, ech.ReadVector16().Length);
        ech.EnsureEnd("P-256 ECH extension");
    }

    [Fact]
    public void ResumptionKeepsRealPskInInnerAndMirrorsRandomGreasePskInOuter()
    {
        var selection = TlsEchConfigList.Parse(CreateConfigList(40, "public.example"))
            .SelectSupportedConfiguration()!;
        var configuration = new ClientHelloBuilder()
            .WithTls13()
            .WithSupportedGroups(NamedGroup.Secp256r1, NamedGroup.Secp384r1)
            .WithKeyShares(NamedGroup.Secp256r1)
            .WithSessionResumption()
            .BuildConfiguration();
        var issuedAt = new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero);
        using var ticket = new Tls13SessionTicket(
            Tls13SessionOrigin.Create("private.example", 443),
            TlsCipherSuite.TlsAes128GcmSha256,
            negotiatedAlpn: null,
            ageAdd: 0x01020304,
            identity: "private-ticket-identity"u8,
            psk: Enumerable.Repeat((byte)0xA5, 32).ToArray(),
            issuedAt,
            issuedAt.AddHours(1),
            issuedAt.AddHours(1),
            maximumEarlyDataSize: 4096);
        var firstOffer = new Tls13PskOffer(
            ticket,
            issuedAt.AddSeconds(1),
            OfferEarlyData: true);
        using var random = new DeterministicRandomSource("ech-psk-privacy"u8);
        using var first = EchClientHelloBuilder.Build(
            "private.example",
            configuration,
            configuration,
            selection,
            random,
            new KeyShareSet(KeyShareFactory.CreateDeterministicForTesting),
            new KeyShareSet(KeyShareFactory.CreateDeterministicForTesting),
            pskOffer: firstOffer);

        var innerPsk = ParseSinglePsk(ReadExtension(
            first.Inner.EncodedHandshake,
            TlsExtensionType.PreSharedKey));
        var outerPsk = ParseSinglePsk(ReadExtension(
            first.Outer.EncodedHandshake,
            TlsExtensionType.PreSharedKey));
        Assert.Equal(ticket.Identity, innerPsk.Identity);
        Assert.Equal(32, innerPsk.Binder.Length);
        Assert.Equal(innerPsk.Identity.Length, outerPsk.Identity.Length);
        Assert.Equal(innerPsk.Binder.Length, outerPsk.Binder.Length);
        Assert.NotEqual(innerPsk.Identity, outerPsk.Identity);
        Assert.NotEqual(innerPsk.Binder, outerPsk.Binder);
        Assert.Equal(
            new byte[] { 1, 1 },
            ReadExtension(first.Outer.EncodedHandshake, TlsExtensionType.PskKeyExchangeModes));
        Assert.Empty(ReadExtension(
            first.Inner.EncodedHandshake,
            TlsExtensionType.EarlyData));
        Assert.Empty(ReadExtension(
            first.Outer.EncodedHandshake,
            TlsExtensionType.EarlyData));
        Assert.True(first.Outer.EncodedHandshake.AsSpan().IndexOf(ticket.Identity) < 0);
        Assert.Equal(1, first.Inner.OfferedPskCount);
        Assert.Equal(1, first.Outer.OfferedPskCount);

        var retryOffer = new Tls13PskOffer(
            ticket,
            issuedAt.AddSeconds(2),
            BinderTranscriptPrefix: [1, 2, 3]);
        using var retry = EchClientHelloBuilder.BuildRetry(
            first,
            NamedGroup.Secp384r1,
            cookie: [4, 5],
            random,
            new KeyShareSet(KeyShareFactory.CreateDeterministicForTesting),
            new KeyShareSet(KeyShareFactory.CreateDeterministicForTesting),
            retryOffer);
        var retryInnerPsk = ParseSinglePsk(ReadExtension(
            retry.Inner.EncodedHandshake,
            TlsExtensionType.PreSharedKey));
        var retryOuterPsk = ParseSinglePsk(ReadExtension(
            retry.Outer.EncodedHandshake,
            TlsExtensionType.PreSharedKey));
        Assert.Equal(ticket.Identity, retryInnerPsk.Identity);
        Assert.Equal(ticket.Identity.Length, retryOuterPsk.Identity.Length);
        Assert.NotEqual(ticket.Identity, retryOuterPsk.Identity);
        Assert.Null(TryReadExtension(retry.Inner.EncodedHandshake, TlsExtensionType.EarlyData));
        Assert.Null(TryReadExtension(retry.Outer.EncodedHandshake, TlsExtensionType.EarlyData));
    }

    [Fact]
    public void MultipleInnerPsksHaveLengthMatchedIndependentOuterGreaseEntries()
    {
        var selection = TlsEchConfigList.Parse(CreateConfigList(40, "public.example"))
            .SelectSupportedConfiguration()!;
        var configuration = new ClientHelloBuilder()
            .WithTls13()
            .WithCipherSuites(
                TlsCipherSuite.TlsAes128GcmSha256,
                TlsCipherSuite.TlsAes256GcmSha384)
            .WithSessionResumption()
            .BuildConfiguration();
        var issuedAt = new DateTimeOffset(2026, 7, 18, 0, 0, 0, TimeSpan.Zero);
        using var firstTicket = new Tls13SessionTicket(
            Tls13SessionOrigin.Create("private.example", 443),
            TlsCipherSuite.TlsAes128GcmSha256,
            negotiatedAlpn: null,
            ageAdd: 1,
            identity: "first-private-ticket"u8,
            psk: Enumerable.Repeat((byte)0x11, 32).ToArray(),
            issuedAt,
            issuedAt.AddHours(1),
            issuedAt.AddHours(1),
            maximumEarlyDataSize: null);
        using var secondTicket = new Tls13SessionTicket(
            Tls13SessionOrigin.Create("private.example", 443),
            TlsCipherSuite.TlsAes256GcmSha384,
            negotiatedAlpn: null,
            ageAdd: 2,
            identity: "second-longer-private-ticket"u8,
            psk: Enumerable.Repeat((byte)0x22, 48).ToArray(),
            issuedAt,
            issuedAt.AddHours(1),
            issuedAt.AddHours(1),
            maximumEarlyDataSize: null);
        using var random = new DeterministicRandomSource("ech-multiple-psks"u8);
        using var result = EchClientHelloBuilder.Build(
            "private.example",
            configuration,
            configuration,
            selection,
            random,
            new KeyShareSet(KeyShareFactory.CreateDeterministicForTesting),
            new KeyShareSet(KeyShareFactory.CreateDeterministicForTesting),
            pskOffer: new Tls13PskOffer([firstTicket, secondTicket], issuedAt));

        var inner = ParsePsks(ReadExtension(
            result.Inner.EncodedHandshake,
            TlsExtensionType.PreSharedKey));
        var outer = ParsePsks(ReadExtension(
            result.Outer.EncodedHandshake,
            TlsExtensionType.PreSharedKey));
        Assert.Equal(2, result.Inner.OfferedPskCount);
        Assert.Equal(2, result.Outer.OfferedPskCount);
        Assert.Equal(firstTicket.Identity, inner.Identities[0]);
        Assert.Equal(secondTicket.Identity, inner.Identities[1]);
        Assert.Equal([32, 48], inner.Binders.Select(value => value.Length));
        Assert.Equal(
            inner.Identities.Select(value => value.Length),
            outer.Identities.Select(value => value.Length));
        Assert.Equal(
            inner.Binders.Select(value => value.Length),
            outer.Binders.Select(value => value.Length));
        Assert.All(Enumerable.Range(0, 2), index =>
        {
            Assert.NotEqual(inner.Identities[index], outer.Identities[index]);
            Assert.NotEqual(inner.Binders[index], outer.Binders[index]);
        });
        Assert.True(result.Outer.EncodedHandshake.AsSpan().IndexOf(firstTicket.Identity) < 0);
        Assert.True(result.Outer.EncodedHandshake.AsSpan().IndexOf(secondTicket.Identity) < 0);
    }

    [Fact]
    public void OuterExtensionCompressionUsesOrderedVectorAndKeepsTrueInnerIntact()
    {
        var selection = TlsEchConfigList.Parse(CreateConfigList(40, "public.example"))
            .SelectSupportedConfiguration()!;
        var inner = new ClientHelloBuilder().WithTls13().BuildConfiguration();
        var outer = new ClientHelloBuilder().WithTls13().BuildConfiguration();
        TlsExtensionType[] compressed =
        [
            TlsExtensionType.SupportedGroups,
            TlsExtensionType.SignatureAlgorithms,
            TlsExtensionType.SupportedVersions,
        ];
        using var random = new DeterministicRandomSource("outer-compression"u8);
        using var result = EchClientHelloBuilder.Build(
            "private.example",
            inner,
            outer,
            selection,
            random,
            new KeyShareSet(KeyShareFactory.CreateDeterministicForTesting),
            new KeyShareSet(KeyShareFactory.CreateDeterministicForTesting),
            compressed);

        var reference = new TlsBinaryReader(ReadEncodedInnerExtension(
            result.EncodedInner,
            TlsExtensionType.EchOuterExtensions));
        Assert.Equal(
            new byte[] { 0, 10, 0, 13, 0, 43 },
            reference.ReadVector8().ToArray());
        reference.EnsureEnd("ech_outer_extensions");
        Assert.Null(TryReadEncodedInnerExtension(
            result.EncodedInner,
            TlsExtensionType.SupportedVersions));
        Assert.Null(TryReadEncodedInnerExtension(
            result.EncodedInner,
            TlsExtensionType.SupportedGroups));
        Assert.Null(TryReadEncodedInnerExtension(
            result.EncodedInner,
            TlsExtensionType.SignatureAlgorithms));
        Assert.NotNull(TryReadExtension(
            result.Inner.EncodedHandshake,
            TlsExtensionType.SupportedVersions));
        Assert.Equal(compressed, result.CompressedOuterExtensions);
    }

    [Fact]
    public void OuterExtensionCompressionRejectsNonContiguousAndDifferentValues()
    {
        var selection = TlsEchConfigList.Parse(CreateConfigList(0, "public.example"))
            .SelectSupportedConfiguration()!;
        var inner = new ClientHelloBuilder()
            .WithTls13()
            .WithAlpn("h2")
            .BuildConfiguration();
        var outer = new ClientHelloBuilder()
            .WithTls13()
            .WithAlpn("http/1.1")
            .BuildConfiguration();

        using var firstRandom = new DeterministicRandomSource("non-contiguous"u8);
        Assert.Throws<InvalidOperationException>(() => EchClientHelloBuilder.Build(
            "private.example",
            inner,
            outer,
            selection,
            firstRandom,
            new KeyShareSet(KeyShareFactory.CreateDeterministicForTesting),
            new KeyShareSet(KeyShareFactory.CreateDeterministicForTesting),
            [TlsExtensionType.SupportedVersions, TlsExtensionType.SignatureAlgorithms]));

        using var secondRandom = new DeterministicRandomSource("different-values"u8);
        var mismatch = Assert.Throws<InvalidOperationException>(() =>
            EchClientHelloBuilder.Build(
                "private.example",
                inner,
                outer,
                selection,
                secondRandom,
                new KeyShareSet(KeyShareFactory.CreateDeterministicForTesting),
                new KeyShareSet(KeyShareFactory.CreateDeterministicForTesting),
                [TlsExtensionType.ApplicationLayerProtocolNegotiation]));
        Assert.Contains("differs", mismatch.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void InnerTls12AndPreOwnedEchExtensionAreRejected()
    {
        var selection = TlsEchConfigList.Parse(CreateConfigList(0, "public.example"))
            .SelectSupportedConfiguration()!;
        var tls12Inner = new ClientHelloBuilder()
            .WithLegacyTls12ClientHello()
            .BuildConfiguration();
        var outer = new ClientHelloBuilder().WithTls13().BuildConfiguration();
        using var random = new DeterministicRandomSource([1]);

        Assert.Throws<ArgumentException>(() => EchClientHelloBuilder.Build(
            "private.example",
            tls12Inner,
            outer,
            selection,
            random,
            new KeyShareSet(KeyShareFactory.CreateDeterministicForTesting),
            new KeyShareSet(KeyShareFactory.CreateDeterministicForTesting)));

        var owned = new ClientHelloBuilder()
            .WithExtensionLayout(
                ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.ServerName),
                ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.SupportedVersions),
                ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.SupportedGroups),
                ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.SignatureAlgorithms),
                ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.KeyShare),
                ClientHelloExtensionSpec.Raw(
                    (ushort)TlsExtensionType.EncryptedClientHello,
                    [1]))
            .BuildConfiguration();
        Assert.Throws<ArgumentException>(() => EchClientHelloBuilder.Build(
            "private.example",
            owned,
            outer,
            selection,
            random,
            new KeyShareSet(KeyShareFactory.CreateDeterministicForTesting),
            new KeyShareSet(KeyShareFactory.CreateDeterministicForTesting)));
    }

    [Fact]
    public void RetryReusesHpkeContextAndPreservesTlsRetryFields()
    {
        var selection = TlsEchConfigList.Parse(CreateConfigList(40, "public.example"))
            .SelectSupportedConfiguration()!;
        var inner = new ClientHelloBuilder()
            .WithTls13()
            .WithSupportedGroups(NamedGroup.Secp256r1, NamedGroup.Secp384r1)
            .WithKeyShares(NamedGroup.Secp256r1)
            .BuildConfiguration();
        var outer = new ClientHelloBuilder()
            .WithTls13()
            .WithSupportedGroups(NamedGroup.Secp256r1, NamedGroup.Secp384r1)
            .WithKeyShares(NamedGroup.Secp256r1)
            .BuildConfiguration();
        using var random = new DeterministicRandomSource([9, 8, 4, 9]);
        using var first = EchClientHelloBuilder.Build(
            "private.example",
            inner,
            outer,
            selection,
            random,
            new KeyShareSet(KeyShareFactory.CreateDeterministicForTesting),
            new KeyShareSet(KeyShareFactory.CreateDeterministicForTesting));
        var firstPayload = ReadOuterEchPayload(first.Outer.EncodedHandshake);

        using var retry = EchClientHelloBuilder.BuildRetry(
            first,
            NamedGroup.Secp384r1,
            [4, 5, 6],
            random,
            new KeyShareSet(KeyShareFactory.CreateDeterministicForTesting),
            new KeyShareSet(KeyShareFactory.CreateDeterministicForTesting));

        Assert.Equal(first.Inner.Random, retry.Inner.Random);
        Assert.Equal(first.Outer.Random, retry.Outer.Random);
        Assert.Equal(first.Inner.SessionId, retry.Inner.SessionId);
        Assert.Equal(first.Outer.SessionId, retry.Outer.SessionId);
        Assert.Equal(retry.Inner.SessionId, retry.Outer.SessionId);
        Assert.Equal([NamedGroup.Secp384r1], retry.Inner.Configuration.KeyShareGroups);
        Assert.Equal([NamedGroup.Secp384r1], retry.Outer.Configuration.KeyShareGroups);
        Assert.Equal(
            new byte[] { 1 },
            ReadExtension(retry.Inner.EncodedHandshake, TlsExtensionType.EncryptedClientHello));
        Assert.Equal(
            new byte[] { 0, 3, 4, 5, 6 },
            ReadExtension(retry.Inner.EncodedHandshake, TlsExtensionType.Cookie));
        Assert.Null(TryReadExtension(retry.Outer.EncodedHandshake, TlsExtensionType.Cookie));
        Assert.Equal(0, retry.EncodedInner.Length & 31);

        var retryEch = new TlsBinaryReader(ReadExtension(
            retry.Outer.EncodedHandshake,
            TlsExtensionType.EncryptedClientHello));
        Assert.Equal(0, retryEch.ReadUInt8());
        Assert.Equal((ushort)TlsHpkeKdfId.HkdfSha256, retryEch.ReadUInt16());
        Assert.Equal((ushort)TlsHpkeAeadId.Aes128Gcm, retryEch.ReadUInt16());
        Assert.Equal(7, retryEch.ReadUInt8());
        Assert.Empty(retryEch.ReadVector16().ToArray());
        var retryPayload = retryEch.ReadVector16().ToArray();
        retryEch.EnsureEnd("test retry outer ECH");
        Assert.Equal(retry.EncodedInner.Length + 16, retryPayload.Length);
        Assert.NotEqual(firstPayload, retryPayload);

        var duplicateRetry = Assert.Throws<TlsProtocolException>(() =>
            EchClientHelloBuilder.BuildRetry(
                first,
                NamedGroup.Secp384r1,
                null,
                random,
                new KeyShareSet(KeyShareFactory.CreateDeterministicForTesting),
                new KeyShareSet(KeyShareFactory.CreateDeterministicForTesting)));
        Assert.Equal(TlsAlertDescription.UnexpectedMessage, duplicateRetry.Alert);
    }

    [Fact]
    public void RetryRejectsIllegalGroupBeforeConsumingHpkeSequence()
    {
        var selection = TlsEchConfigList.Parse(CreateConfigList(0, "public.example"))
            .SelectSupportedConfiguration()!;
        var configuration = new ClientHelloBuilder()
            .WithTls13()
            .WithSupportedGroups(NamedGroup.Secp256r1, NamedGroup.Secp384r1)
            .WithKeyShares(NamedGroup.Secp256r1)
            .BuildConfiguration();
        using var random = new DeterministicRandomSource([1, 2, 3]);
        using var first = EchClientHelloBuilder.Build(
            "private.example",
            configuration,
            configuration,
            selection,
            random,
            new KeyShareSet(KeyShareFactory.CreateDeterministicForTesting),
            new KeyShareSet(KeyShareFactory.CreateDeterministicForTesting));

        var exception = Assert.Throws<TlsProtocolException>(() =>
            EchClientHelloBuilder.BuildRetry(
                first,
                NamedGroup.Secp256r1,
                null,
                random,
                new KeyShareSet(KeyShareFactory.CreateDeterministicForTesting),
                new KeyShareSet(KeyShareFactory.CreateDeterministicForTesting)));

        Assert.Equal(TlsAlertDescription.IllegalParameter, exception.Alert);
    }

    [Fact]
    public void RejectedRetryCopiesTheOriginalOuterEchValueExactly()
    {
        var selection = TlsEchConfigList.Parse(CreateConfigList(0, "public.example"))
            .SelectSupportedConfiguration()!;
        var configuration = new ClientHelloBuilder()
            .WithTls13()
            .WithSupportedGroups(NamedGroup.Secp256r1, NamedGroup.Secp384r1)
            .WithKeyShares(NamedGroup.Secp256r1)
            .BuildConfiguration();
        using var random = new DeterministicRandomSource([8, 6, 7, 5, 3, 0, 9]);
        using var first = EchClientHelloBuilder.Build(
            "private.example",
            configuration,
            configuration,
            selection,
            random,
            new KeyShareSet(KeyShareFactory.CreateDeterministicForTesting),
            new KeyShareSet(KeyShareFactory.CreateDeterministicForTesting));
        var firstEch = ReadExtension(
            first.Outer.EncodedHandshake,
            TlsExtensionType.EncryptedClientHello);

        using var retry = EchClientHelloBuilder.BuildOuterRetryAfterRejection(
            first,
            NamedGroup.Secp384r1,
            [9, 9],
            random,
            new KeyShareSet(KeyShareFactory.CreateDeterministicForTesting));

        Assert.Equal(first.Outer.Random, retry.Random);
        Assert.Equal(first.Outer.SessionId, retry.SessionId);
        Assert.Equal(firstEch, ReadExtension(
            retry.EncodedHandshake,
            TlsExtensionType.EncryptedClientHello));
        Assert.Equal(
            new byte[] { 0, 2, 9, 9 },
            ReadExtension(retry.EncodedHandshake, TlsExtensionType.Cookie));
    }

    private static byte[] CreateConfigList(byte maximumNameLength, string publicName)
    {
        var suites = new TlsBinaryWriter();
        suites.WriteUInt16((ushort)TlsHpkeKdfId.HkdfSha256);
        suites.WriteUInt16((ushort)TlsHpkeAeadId.Aes128Gcm);
        var contents = new TlsBinaryWriter();
        contents.WriteUInt8(7);
        contents.WriteUInt16((ushort)TlsHpkeKemId.DhkemX25519HkdfSha256);
        contents.WriteVector16(Convert.FromHexString(
            "3948cfe0ad1ddb695d780e59077195da6c56506b027329794ab02bca80815c4d"));
        contents.WriteVector16(suites.WrittenSpan);
        contents.WriteUInt8(maximumNameLength);
        contents.WriteVector8(Encoding.ASCII.GetBytes(publicName));
        contents.WriteVector16([]);
        var configuration = new TlsBinaryWriter();
        configuration.WriteUInt16((ushort)TlsExtensionType.EncryptedClientHello);
        configuration.WriteVector16(contents.WrittenSpan);
        var list = new TlsBinaryWriter();
        list.WriteVector16(configuration.WrittenSpan);
        return list.ToArray();
    }

    private static byte[] CreateP256ConfigList()
    {
        var suites = new TlsBinaryWriter();
        suites.WriteUInt16((ushort)TlsHpkeKdfId.HkdfSha256);
        suites.WriteUInt16((ushort)TlsHpkeAeadId.Aes128Gcm);
        var contents = new TlsBinaryWriter();
        contents.WriteUInt8(8);
        contents.WriteUInt16((ushort)TlsHpkeKemId.DhkemP256HkdfSha256);
        contents.WriteVector16(Convert.FromHexString(
            "04fe8c19ce0905191ebc298a9245792531f26f0cece2460639e8bc39cb7f706" +
            "a826a779b4cf969b8a0e539c7f62fb3d30ad6aa8f80e30f1d128aafd68a2ce72ea0"));
        contents.WriteVector16(suites.WrittenSpan);
        contents.WriteUInt8(0);
        contents.WriteVector8("public.example"u8);
        contents.WriteVector16([]);
        var configuration = new TlsBinaryWriter();
        configuration.WriteUInt16((ushort)TlsExtensionType.EncryptedClientHello);
        configuration.WriteVector16(contents.WrittenSpan);
        var list = new TlsBinaryWriter();
        list.WriteVector16(configuration.WrittenSpan);
        return list.ToArray();
    }

    private static byte[] ReadExtension(byte[] encoded, TlsExtensionType expectedType)
    {
        return TryReadExtension(encoded, expectedType) ??
            throw new Xunit.Sdk.XunitException($"Missing extension {expectedType}.");
    }

    private static byte[]? TryReadExtension(byte[] encoded, TlsExtensionType expectedType)
    {
        var body = new TlsBinaryReader(encoded.AsSpan(TlsConstants.HandshakeHeaderLength));
        _ = body.ReadUInt16();
        _ = body.ReadBytes(TlsConstants.RandomLength);
        _ = body.ReadVector8();
        _ = body.ReadVector16();
        _ = body.ReadVector8();
        var extensions = new TlsBinaryReader(body.ReadVector16());
        while (!extensions.End)
        {
            var type = extensions.ReadUInt16();
            var data = extensions.ReadVector16();
            if (type == (ushort)expectedType)
            {
                return data.ToArray();
            }
        }
        return null;
    }

    private static byte[] ReadEncodedInnerExtension(
        ReadOnlySpan<byte> encodedInner,
        TlsExtensionType extensionType) =>
        TryReadEncodedInnerExtension(encodedInner, extensionType) ??
        throw new Xunit.Sdk.XunitException(
            $"Missing encoded inner extension {extensionType}.");

    private static byte[]? TryReadEncodedInnerExtension(
        ReadOnlySpan<byte> encodedInner,
        TlsExtensionType extensionType)
    {
        var body = new TlsBinaryReader(encodedInner);
        _ = body.ReadUInt16();
        _ = body.ReadBytes(TlsConstants.RandomLength);
        _ = body.ReadVector8(TlsConstants.MaxSessionIdLength);
        _ = body.ReadVector16();
        _ = body.ReadVector8();
        var extensions = new TlsBinaryReader(body.ReadVector16());
        while (!extensions.End)
        {
            var type = extensions.ReadUInt16();
            var data = extensions.ReadVector16();
            if (type == (ushort)extensionType)
            {
                return data.ToArray();
            }
        }
        return null;
    }

    private static byte[] ReadOuterEchPayload(byte[] encoded)
    {
        var ech = new TlsBinaryReader(ReadExtension(
            encoded,
            TlsExtensionType.EncryptedClientHello));
        Assert.Equal(0, ech.ReadUInt8());
        _ = ech.ReadUInt16();
        _ = ech.ReadUInt16();
        _ = ech.ReadUInt8();
        _ = ech.ReadVector16();
        var payload = ech.ReadVector16().ToArray();
        ech.EnsureEnd("test outer ECH payload");
        return payload;
    }

    private static string ReadSni(byte[] encoded)
    {
        var data = new TlsBinaryReader(ReadExtension(encoded, TlsExtensionType.ServerName));
        var names = new TlsBinaryReader(data.ReadVector16());
        data.EnsureEnd("test SNI extension");
        Assert.Equal(0, names.ReadUInt8());
        var name = names.ReadVector16();
        names.EnsureEnd("test SNI list");
        return Encoding.ASCII.GetString(name);
    }

    private static (byte[] Identity, uint Age, byte[] Binder) ParseSinglePsk(
        ReadOnlySpan<byte> encoded)
    {
        var reader = new TlsBinaryReader(encoded);
        var identities = new TlsBinaryReader(reader.ReadVector16());
        var identity = identities.ReadVector16().ToArray();
        var age = identities.ReadUInt32();
        identities.EnsureEnd("test PSK identities");
        var binders = new TlsBinaryReader(reader.ReadVector16());
        var binder = binders.ReadVector8().ToArray();
        binders.EnsureEnd("test PSK binders");
        reader.EnsureEnd("test OfferedPsks");
        return (identity, age, binder);
    }

    private static (byte[][] Identities, byte[][] Binders) ParsePsks(
        ReadOnlySpan<byte> encoded)
    {
        var reader = new TlsBinaryReader(encoded);
        var identitiesReader = new TlsBinaryReader(reader.ReadVector16());
        var identities = new List<byte[]>();
        while (!identitiesReader.End)
        {
            identities.Add(identitiesReader.ReadVector16().ToArray());
            _ = identitiesReader.ReadUInt32();
        }
        var bindersReader = new TlsBinaryReader(reader.ReadVector16());
        var binders = new List<byte[]>();
        while (!bindersReader.End)
        {
            binders.Add(bindersReader.ReadVector8().ToArray());
        }
        reader.EnsureEnd("test multiple OfferedPsks");
        Assert.Equal(identities.Count, binders.Count);
        return (identities.ToArray(), binders.ToArray());
    }
}
