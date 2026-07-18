using System.Security.Cryptography;
using SharpTls.Cryptography;
using SharpTls.Handshake;
using SharpTls.IO;
using SharpTls.Protocol;

namespace SharpTls.Tests.Handshake;

public sealed class ServerHelloParserTests
{
    private static readonly byte[] HrrRandom =
    [
        0xCF, 0x21, 0xAD, 0x74, 0xE5, 0x9A, 0x61, 0x11,
        0xBE, 0x1D, 0x8C, 0x02, 0x1E, 0x65, 0xB8, 0x91,
        0xC2, 0xA2, 0x11, 0x16, 0x7A, 0xBB, 0x8C, 0x5E,
        0x07, 0x9E, 0x09, 0xE2, 0xC8, 0xA8, 0x33, 0x9C,
    ];

    [Fact]
    public void ParsesValidServerHelloAndDerivesAgreement()
    {
        var profile = ClientHelloProfiles.Custom(builder => builder
            .WithSupportedGroups(NamedGroup.Secp256r1)
            .WithCipherSuites(TlsCipherSuite.TlsAes128GcmSha256));
        using var offer = profile.BuildSecure("example.com");
        using var serverShare = EcdheKeyShare.Create(NamedGroup.Secp256r1);
        var body = BuildServerHello(offer, RandomNumberGenerator.GetBytes(32), serverShare.PublicKey.Span);

        var parsed = ServerHelloParser.Parse(body, offer);
        var clientSecret = offer.KeyShares.Get(parsed.SelectedGroup)
            .DeriveSharedSecret(parsed.PeerKeyExchange!);
        var serverSecret = serverShare.DeriveSharedSecret(
            offer.KeyShares.Get(NamedGroup.Secp256r1).PublicKey.Span);
        try
        {
            Assert.False(parsed.IsHelloRetryRequest);
            Assert.Equal(clientSecret, serverSecret);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(clientSecret);
            CryptographicOperations.ZeroMemory(serverSecret);
        }
    }

    [Fact]
    public void ValidHelloRetryRequestProducesConstrainedSecondHello()
    {
        var profile = ClientHelloProfiles.Custom(builder => builder
            .WithSupportedGroups(NamedGroup.Secp256r1, NamedGroup.Secp384r1)
            .WithKeyShares(NamedGroup.Secp256r1)
            .WithCipherSuites(TlsCipherSuite.TlsAes128GcmSha256));
        using var first = profile.BuildSecure("example.com");
        var hrrBody = BuildServerHello(first, HrrRandom, [], NamedGroup.Secp384r1, [1, 2, 3]);

        var parsed = ServerHelloParser.Parse(hrrBody, first);
        using var second = ClientHelloEncoder.BuildRetry(first, parsed.SelectedGroup, parsed.Cookie);

        Assert.True(parsed.IsHelloRetryRequest);
        Assert.Equal(NamedGroup.Secp384r1, parsed.SelectedGroup);
        Assert.Equal(first.Random, second.Random);
        Assert.Equal(first.SessionId, second.SessionId);
        Assert.Equal([NamedGroup.Secp384r1], second.Configuration.KeyShareGroups);
        Assert.Equal(97, second.KeyShares.Get(NamedGroup.Secp384r1).PublicKey.Length);
    }

    [Fact]
    public void HrrCannotRequestAlreadyOfferedShare()
    {
        using var offer = ClientHelloProfiles.ModernTls13.BuildSecure("example.com");
        var body = BuildServerHello(offer, HrrRandom, [], NamedGroup.Secp256r1);

        var exception = Assert.Throws<TlsProtocolException>(() => ServerHelloParser.Parse(body, offer));
        Assert.Equal(TlsAlertDescription.IllegalParameter, exception.Alert);
    }

    [Fact]
    public void ParsesOfferedEightByteHrrEchConfirmation()
    {
        var profile = ClientHelloProfiles.Custom(builder => builder
            .WithSupportedGroups(NamedGroup.Secp256r1, NamedGroup.Secp384r1)
            .WithKeyShares(NamedGroup.Secp256r1)
            .WithExtensionLayout(
                ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.ServerName),
                ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.SupportedVersions),
                ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.SupportedGroups),
                ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.SignatureAlgorithms),
                ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.KeyShare),
                ClientHelloExtensionSpec.Raw(
                    (ushort)TlsExtensionType.EncryptedClientHello,
                    [0])));
        using var offer = profile.BuildSecure("example.com");
        byte[] confirmation = [1, 2, 3, 4, 5, 6, 7, 8];

        var parsed = ServerHelloParser.Parse(
            BuildServerHello(
                offer,
                HrrRandom,
                [],
                NamedGroup.Secp384r1,
                echConfirmation: confirmation),
            offer);

        Assert.Equal(confirmation, parsed.EchConfirmation);
        confirmation[0] = 99;
        Assert.Equal(1, parsed.EchConfirmation![0]);
    }

    [Fact]
    public void HrrEchConfirmationMustBeOfferedAndExactlyEightBytes()
    {
        using var unoffered = ClientHelloProfiles.Custom(builder => builder
            .WithSupportedGroups(NamedGroup.Secp256r1, NamedGroup.Secp384r1)
            .WithKeyShares(NamedGroup.Secp256r1))
            .BuildSecure("example.com");
        var unsolicited = Assert.Throws<TlsProtocolException>(() =>
            ServerHelloParser.Parse(
                BuildServerHello(
                    unoffered,
                    HrrRandom,
                    [],
                    NamedGroup.Secp384r1,
                    echConfirmation: new byte[8]),
                unoffered));
        Assert.Equal(TlsAlertDescription.UnsupportedExtension, unsolicited.Alert);

        var profile = ClientHelloProfiles.Custom(builder => builder
            .WithSupportedGroups(NamedGroup.Secp256r1, NamedGroup.Secp384r1)
            .WithKeyShares(NamedGroup.Secp256r1)
            .WithExtensionLayout(
                ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.ServerName),
                ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.SupportedVersions),
                ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.SupportedGroups),
                ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.SignatureAlgorithms),
                ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.KeyShare),
                ClientHelloExtensionSpec.Raw(
                    (ushort)TlsExtensionType.EncryptedClientHello,
                    [0])));
        using var offered = profile.BuildSecure("example.com");
        var malformed = Assert.Throws<TlsProtocolException>(() =>
            ServerHelloParser.Parse(
                BuildServerHello(
                    offered,
                    HrrRandom,
                    [],
                    NamedGroup.Secp384r1,
                    echConfirmation: new byte[7]),
                offered));
        Assert.Equal(TlsAlertDescription.DecodeError, malformed.Alert);
    }

    [Fact]
    public void DuplicateExtensionsAreRejected()
    {
        using var offer = ClientHelloProfiles.ModernTls13.BuildSecure("example.com");
        using var serverShare = EcdheKeyShare.Create(NamedGroup.Secp256r1);
        var body = BuildServerHello(
            offer,
            RandomNumberGenerator.GetBytes(32),
            serverShare.PublicKey.Span,
            duplicateSupportedVersion: true);

        var exception = Assert.Throws<TlsProtocolException>(() => ServerHelloParser.Parse(body, offer));
        Assert.Equal(TlsAlertDescription.IllegalParameter, exception.Alert);
    }

    [Fact]
    public void WrongSessionEchoIsRejected()
    {
        using var offer = ClientHelloProfiles.ModernTls13.BuildSecure("example.com");
        using var serverShare = EcdheKeyShare.Create(NamedGroup.Secp256r1);
        var body = BuildServerHello(offer, RandomNumberGenerator.GetBytes(32), serverShare.PublicKey.Span);
        body[35] ^= 1;

        var exception = Assert.Throws<TlsProtocolException>(() => ServerHelloParser.Parse(body, offer));
        Assert.Equal(TlsAlertDescription.IllegalParameter, exception.Alert);
    }

    [Fact]
    public void PskSelectionMustReferToAnOfferedIdentity()
    {
        var now = new DateTimeOffset(2026, 7, 17, 12, 0, 0, TimeSpan.Zero);
        using var ticket = new Tls13SessionTicket(
            Tls13SessionOrigin.Create("example.com", 443),
            TlsCipherSuite.TlsAes128GcmSha256,
            negotiatedAlpn: null,
            ageAdd: 0,
            identity: [1, 2, 3],
            psk: new byte[32],
            issuedAt: now,
            expiresAt: now.AddHours(1),
            authenticationExpiresAt: now.AddHours(1),
            maximumEarlyDataSize: null);
        using var offer = ClientHelloProfiles.ModernTls13.BuildSecure(
            "example.com",
            new Tls13PskOffer(ticket, now));
        using var serverShare = EcdheKeyShare.Create(NamedGroup.Secp256r1);

        var accepted = ServerHelloParser.Parse(
            BuildServerHello(
                offer,
                RandomNumberGenerator.GetBytes(32),
                serverShare.PublicKey.Span,
                selectedPskIdentity: 0),
            offer);
        Assert.Equal((ushort)0, accepted.SelectedPskIdentity);

        var rejected = Assert.Throws<TlsProtocolException>(() => ServerHelloParser.Parse(
            BuildServerHello(
                offer,
                RandomNumberGenerator.GetBytes(32),
                serverShare.PublicKey.Span,
                selectedPskIdentity: 1),
            offer));
        Assert.Equal(TlsAlertDescription.IllegalParameter, rejected.Alert);
    }

    [Fact]
    public void ServerCannotSelectPskWhenClientDidNotOfferOne()
    {
        using var offer = ClientHelloProfiles.ModernTls13.BuildSecure("example.com");
        using var serverShare = EcdheKeyShare.Create(NamedGroup.Secp256r1);

        var exception = Assert.Throws<TlsProtocolException>(() => ServerHelloParser.Parse(
            BuildServerHello(
                offer,
                RandomNumberGenerator.GetBytes(32),
                serverShare.PublicKey.Span,
                selectedPskIdentity: 0),
            offer));
        Assert.Equal(TlsAlertDescription.UnsupportedExtension, exception.Alert);
    }

    private static byte[] BuildServerHello(
        ClientHelloBuildResult offer,
        ReadOnlySpan<byte> random,
        ReadOnlySpan<byte> serverPublicKey,
        NamedGroup group = NamedGroup.Secp256r1,
        byte[]? cookie = null,
        bool duplicateSupportedVersion = false,
        ushort? selectedPskIdentity = null,
        byte[]? echConfirmation = null)
    {
        var isHrr = random.SequenceEqual(HrrRandom);
        var extensions = new TlsBinaryWriter();
        WriteExtension(extensions, TlsExtensionType.SupportedVersions, [3, 4]);
        if (duplicateSupportedVersion)
        {
            WriteExtension(extensions, TlsExtensionType.SupportedVersions, [3, 4]);
        }

        var keyShare = new TlsBinaryWriter();
        keyShare.WriteUInt16((ushort)group);
        if (!isHrr)
        {
            keyShare.WriteVector16(serverPublicKey);
        }
        WriteExtension(extensions, TlsExtensionType.KeyShare, keyShare.WrittenSpan);

        if (cookie is not null)
        {
            var cookieData = new TlsBinaryWriter();
            cookieData.WriteVector16(cookie);
            WriteExtension(extensions, TlsExtensionType.Cookie, cookieData.WrittenSpan);
        }
        if (selectedPskIdentity.HasValue)
        {
            var selectedPsk = new TlsBinaryWriter();
            selectedPsk.WriteUInt16(selectedPskIdentity.Value);
            WriteExtension(extensions, TlsExtensionType.PreSharedKey, selectedPsk.WrittenSpan);
        }
        if (echConfirmation is not null)
        {
            WriteExtension(
                extensions,
                TlsExtensionType.EncryptedClientHello,
                echConfirmation);
        }

        var body = new TlsBinaryWriter();
        body.WriteUInt16(TlsConstants.LegacyRecordVersion);
        body.WriteBytes(random);
        body.WriteVector8(offer.SessionId);
        body.WriteUInt16((ushort)TlsCipherSuite.TlsAes128GcmSha256);
        body.WriteUInt8(0);
        body.WriteVector16(extensions.WrittenSpan);
        return body.ToArray();
    }

    private static void WriteExtension(
        TlsBinaryWriter writer,
        TlsExtensionType type,
        ReadOnlySpan<byte> data)
    {
        writer.WriteUInt16((ushort)type);
        writer.WriteVector16(data);
    }
}
