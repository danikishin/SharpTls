using System.Security.Cryptography;
using SharpTls.Cryptography;
using SharpTls.Handshake;
using SharpTls.IO;
using SharpTls.Protocol;

namespace SharpTls.Tests.Handshake;

public sealed class Tls12ServerHelloParserTests
{
    [Fact]
    public void AndroidOfferAcceptsSecureServerHelloAndKnownExtensions()
    {
        using var offer = ClientHelloProfiles.UTlsAndroid11OkHttp.BuildSecure("example.com");
        var extensions = new TlsBinaryWriter();
        WriteExtension(extensions, TlsExtensionType.ExtendedMasterSecret, []);
        WriteExtension(extensions, TlsExtensionType.RenegotiationInfo, [0]);
        WriteExtension(extensions, TlsExtensionType.EcPointFormats, [1, 0]);
        WriteExtension(extensions, TlsExtensionType.StatusRequest, []);
        var body = BuildServerHello(
            extensions.WrittenSpan,
            TlsCipherSuite.TlsEcdheRsaWithAes128GcmSha256);

        var parsed = Tls12ServerHelloParser.Parse(body, offer);

        Assert.True(parsed.ExtendedMasterSecretNegotiated);
        Assert.True(parsed.SecureRenegotiationNegotiated);
        Assert.True(parsed.CertificateStatusExpected);
        Assert.Equal(Tls12AeadAlgorithm.AesGcm, parsed.SuiteInfo.AeadAlgorithm);
        Assert.Equal(new byte[] { 1, 2, 3 }, parsed.SessionId);
    }

    [Theory]
    [InlineData(true, false)]
    [InlineData(false, true)]
    [InlineData(false, false)]
    public void MissingRequiredSecurityExtensionsFailClosed(bool includeEms, bool includeRenegotiation)
    {
        using var offer = ClientHelloProfiles.UTlsAndroid11OkHttp.BuildSecure("example.com");
        var extensions = new TlsBinaryWriter();
        if (includeEms)
        {
            WriteExtension(extensions, TlsExtensionType.ExtendedMasterSecret, []);
        }
        if (includeRenegotiation)
        {
            WriteExtension(extensions, TlsExtensionType.RenegotiationInfo, [0]);
        }

        var exception = Assert.Throws<TlsProtocolException>(() =>
            Tls12ServerHelloParser.Parse(BuildServerHello(extensions.WrittenSpan), offer));

        Assert.Equal(TlsAlertDescription.HandshakeFailure, exception.Alert);
    }

    [Fact]
    public void DuplicateUnofferedAndMalformedExtensionsAreRejected()
    {
        using var offer = ClientHelloProfiles.UTlsAndroid11OkHttp.BuildSecure("example.com");

        var duplicate = RequiredExtensions();
        WriteExtension(duplicate, TlsExtensionType.ExtendedMasterSecret, []);
        Assert.Equal(
            TlsAlertDescription.IllegalParameter,
            Assert.Throws<TlsProtocolException>(() =>
                Tls12ServerHelloParser.Parse(BuildServerHello(duplicate.WrittenSpan), offer)).Alert);

        var unoffered = RequiredExtensions();
        WriteRawExtension(unoffered, 65000, []);
        Assert.Equal(
            TlsAlertDescription.UnsupportedExtension,
            Assert.Throws<TlsProtocolException>(() =>
                Tls12ServerHelloParser.Parse(BuildServerHello(unoffered.WrittenSpan), offer)).Alert);

        var malformed = new TlsBinaryWriter();
        WriteExtension(malformed, TlsExtensionType.ExtendedMasterSecret, []);
        WriteExtension(malformed, TlsExtensionType.RenegotiationInfo, [1, 0]);
        Assert.Equal(
            TlsAlertDescription.IllegalParameter,
            Assert.Throws<TlsProtocolException>(() =>
                Tls12ServerHelloParser.Parse(BuildServerHello(malformed.WrittenSpan), offer)).Alert);
    }

    [Fact]
    public void OfferedButNonExecutableCbcSuiteIsRejected()
    {
        using var offer = ClientHelloProfiles.UTlsAndroid11OkHttp.BuildSecure("example.com");

        var exception = Assert.Throws<TlsProtocolException>(() => Tls12ServerHelloParser.Parse(
            BuildServerHello(
                RequiredExtensions().WrittenSpan,
                TlsCipherSuite.TlsEcdheRsaWithAes128CbcSha),
            offer));

        Assert.Equal(TlsAlertDescription.HandshakeFailure, exception.Alert);
    }

    [Fact]
    public void MixedVersionOfferRejectsTls13DowngradeSentinel()
    {
        using var offer = ClientHelloProfiles.UTlsChrome83.BuildSecure("example.com");
        var random = RandomNumberGenerator.GetBytes(32);
        "DOWNGRD\x01"u8.CopyTo(random.AsSpan(24));

        var exception = Assert.Throws<TlsProtocolException>(() => Tls12ServerHelloParser.Parse(
            BuildServerHello(
                RequiredExtensions().WrittenSpan,
                TlsCipherSuite.TlsEcdheRsaWithAes128GcmSha256,
                random),
            offer));

        Assert.Equal(TlsAlertDescription.IllegalParameter, exception.Alert);
    }

    [Fact]
    public void AlpnAndSctResponsesAreParsedWithExactOfferChecks()
    {
        var profile = CreateRichTls12Profile();
        using var offer = profile.BuildSecure("example.com");
        var extensions = RequiredExtensions();
        WriteExtension(extensions, TlsExtensionType.ApplicationLayerProtocolNegotiation, [0, 9, 8, .. "http/1.1"u8]);
        WriteExtension(extensions, TlsExtensionType.SignedCertificateTimestamp, [0, 5, 0, 3, 1, 2, 3]);
        WriteExtension(extensions, TlsExtensionType.SessionTicket, []);

        var parsed = Tls12ServerHelloParser.Parse(BuildServerHello(extensions.WrittenSpan), offer);

        Assert.Equal("http/1.1", parsed.AlpnProtocol);
        Assert.True(parsed.SignedCertificateTimestampsIncluded);
        Assert.True(parsed.SessionTicketAcknowledged);
    }

    [Fact]
    public void Tls12ServerMustNotEchoSupportedVersions()
    {
        using var offer = ClientHelloProfiles.UTlsChrome83.BuildSecure("example.com");
        var extensions = RequiredExtensions();
        WriteExtension(extensions, TlsExtensionType.SupportedVersions, [3, 3]);

        var exception = Assert.Throws<TlsProtocolException>(() =>
            Tls12ServerHelloParser.Parse(BuildServerHello(extensions.WrittenSpan), offer));

        Assert.Equal(TlsAlertDescription.IllegalParameter, exception.Alert);
    }

    [Fact]
    public void Tls12RecordSizeLimitResponseIsParsed()
    {
        using var offer = CreateRecordLimitedTls12Profile().BuildSecure("example.com");
        var extensions = RequiredExtensions();
        WriteExtension(extensions, TlsExtensionType.RecordSizeLimit, [1, 0]);

        var parsed = Tls12ServerHelloParser.Parse(
            BuildServerHello(extensions.WrittenSpan),
            offer);

        Assert.Equal(256, parsed.PeerRecordSizeLimit);
    }

    [Theory]
    [InlineData(new byte[] { 0 })]
    [InlineData(new byte[] { 0, 63 })]
    [InlineData(new byte[] { 0x40, 0x01 })]
    public void Tls12RejectsMalformedOrOutOfRangeRecordSizeLimit(byte[] data)
    {
        using var offer = CreateRecordLimitedTls12Profile().BuildSecure("example.com");
        var extensions = RequiredExtensions();
        WriteExtension(extensions, TlsExtensionType.RecordSizeLimit, data);

        var exception = Assert.Throws<TlsProtocolException>(() =>
            Tls12ServerHelloParser.Parse(BuildServerHello(extensions.WrittenSpan), offer));

        Assert.True(exception.Alert is
            TlsAlertDescription.DecodeError or TlsAlertDescription.IllegalParameter);
    }

    [Fact]
    public void Tls12RejectsRecordSizeAndMaximumFragmentLengthTogether()
    {
        using var offer = CreateRecordLimitedTls12Profile().BuildSecure("example.com");
        var extensions = RequiredExtensions();
        WriteExtension(extensions, TlsExtensionType.MaximumFragmentLength, [2]);
        WriteExtension(extensions, TlsExtensionType.RecordSizeLimit, [1, 0]);

        var exception = Assert.Throws<TlsProtocolException>(() =>
            Tls12ServerHelloParser.Parse(BuildServerHello(extensions.WrittenSpan), offer));

        Assert.Equal(TlsAlertDescription.IllegalParameter, exception.Alert);
    }

    private static ClientHelloProfile CreateRecordLimitedTls12Profile() =>
        ClientHelloProfiles.Custom(builder => builder
            .WithLegacyTls12ClientHello()
            .WithCipherSuites(TlsCipherSuite.TlsEcdheRsaWithAes128GcmSha256)
            .WithSupportedGroups(NamedGroup.Secp256r1)
            .WithSignatureAlgorithms(SignatureScheme.RsaPssRsaeSha256)
            .WithRecordSizeLimit(512)
            .WithExtensionLayout(
                ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.ServerName),
                ClientHelloExtensionSpec.Raw(
                    (ushort)TlsExtensionType.MaximumFragmentLength,
                    [2]),
                ClientHelloExtensionSpec.Raw(23, []),
                ClientHelloExtensionSpec.Raw(0xFF01, [0]),
                ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.SupportedGroups),
                ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.SignatureAlgorithms),
                ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.RecordSizeLimit)));

    private static ClientHelloProfile CreateRichTls12Profile() => ClientHelloProfiles.Custom(builder => builder
        .WithLegacyTls12ClientHello()
        .WithCipherSuites(TlsCipherSuite.TlsEcdheRsaWithAes128GcmSha256)
        .WithSupportedGroups(NamedGroup.Secp256r1)
        .WithSignatureAlgorithms(SignatureScheme.RsaPssRsaeSha256)
        .WithAlpn("h2", "http/1.1")
        .WithExtensionLayout(
            ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.ServerName),
            ClientHelloExtensionSpec.Raw(23, []),
            ClientHelloExtensionSpec.Raw(0xFF01, [0]),
            ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.SupportedGroups),
            ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.SignatureAlgorithms),
            ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.ApplicationLayerProtocolNegotiation),
            ClientHelloExtensionSpec.Raw(18, []),
            ClientHelloExtensionSpec.Raw(35, [])));

    private static TlsBinaryWriter RequiredExtensions()
    {
        var extensions = new TlsBinaryWriter();
        WriteExtension(extensions, TlsExtensionType.ExtendedMasterSecret, []);
        WriteExtension(extensions, TlsExtensionType.RenegotiationInfo, [0]);
        return extensions;
    }

    private static byte[] BuildServerHello(
        ReadOnlySpan<byte> extensions,
        TlsCipherSuite cipherSuite = TlsCipherSuite.TlsEcdheRsaWithAes128GcmSha256,
        byte[]? random = null)
    {
        var body = new TlsBinaryWriter();
        body.WriteUInt16(TlsConstants.Tls12Version);
        body.WriteBytes(random ?? RandomNumberGenerator.GetBytes(32));
        body.WriteVector8([1, 2, 3]);
        body.WriteUInt16((ushort)cipherSuite);
        body.WriteUInt8(0);
        body.WriteVector16(extensions);
        return body.ToArray();
    }

    private static void WriteExtension(
        TlsBinaryWriter writer,
        TlsExtensionType type,
        ReadOnlySpan<byte> data) => WriteRawExtension(writer, (ushort)type, data);

    private static void WriteRawExtension(
        TlsBinaryWriter writer,
        ushort type,
        ReadOnlySpan<byte> data)
    {
        writer.WriteUInt16(type);
        writer.WriteVector16(data);
    }
}
