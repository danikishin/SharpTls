using SharpTls.Handshake;
using SharpTls.IO;
using SharpTls.Protocol;

namespace SharpTls.Tests.Handshake;

public sealed class EncryptedExtensionsParserTests
{
    [Fact]
    public void EmptyOfferedEarlyDataIsAccepted()
    {
        var offer = ClientHelloProfiles.ModernTls13.Spec.SnapshotConfiguration();
        var extensions = new TlsBinaryWriter();
        extensions.WriteUInt16((ushort)TlsExtensionType.EarlyData);
        extensions.WriteVector16([]);
        var body = new TlsBinaryWriter();
        body.WriteVector16(extensions.WrittenSpan);

        var parsed = EncryptedExtensionsParser.Parse(
            body.WrittenSpan,
            offer,
            offeredEarlyData: true);

        Assert.True(parsed.EarlyDataAccepted);
    }

    [Fact]
    public void UnoferredOrNonEmptyEarlyDataIsRejected()
    {
        var offer = ClientHelloProfiles.ModernTls13.Spec.SnapshotConfiguration();
        var extensions = new TlsBinaryWriter();
        extensions.WriteUInt16((ushort)TlsExtensionType.EarlyData);
        extensions.WriteVector16([]);
        var body = new TlsBinaryWriter();
        body.WriteVector16(extensions.WrittenSpan);
        Assert.Equal(
            TlsAlertDescription.UnsupportedExtension,
            Assert.Throws<TlsProtocolException>(() =>
                EncryptedExtensionsParser.Parse(body.WrittenSpan, offer)).Alert);

        var nonEmpty = new TlsBinaryWriter();
        nonEmpty.WriteUInt16((ushort)TlsExtensionType.EarlyData);
        nonEmpty.WriteVector16([0]);
        var nonEmptyBody = new TlsBinaryWriter();
        nonEmptyBody.WriteVector16(nonEmpty.WrittenSpan);
        Assert.Equal(
            TlsAlertDescription.DecodeError,
            Assert.Throws<TlsProtocolException>(() => EncryptedExtensionsParser.Parse(
                nonEmptyBody.WrittenSpan,
                offer,
                offeredEarlyData: true)).Alert);
    }
    [Fact]
    public void ParsesOfferedAlpn()
    {
        var offer = new ClientHelloBuilder().WithAlpn("h2", "http/1.1").BuildConfiguration();
        var alpnNames = new TlsBinaryWriter();
        alpnNames.WriteVector8("http/1.1"u8);
        var alpn = new TlsBinaryWriter();
        alpn.WriteVector16(alpnNames.WrittenSpan);
        var body = EncodeExtensions((TlsExtensionType.ApplicationLayerProtocolNegotiation, alpn.ToArray()));

        var result = EncryptedExtensionsParser.Parse(body, offer);

        Assert.Equal("http/1.1", result.NegotiatedAlpn);
    }

    [Fact]
    public void UnoferredAlpnIsRejected()
    {
        var offer = new ClientHelloBuilder().WithAlpn("http/1.1").BuildConfiguration();
        var alpnNames = new TlsBinaryWriter();
        alpnNames.WriteVector8("h2"u8);
        var alpn = new TlsBinaryWriter();
        alpn.WriteVector16(alpnNames.WrittenSpan);
        var body = EncodeExtensions((TlsExtensionType.ApplicationLayerProtocolNegotiation, alpn.ToArray()));

        var exception = Assert.Throws<TlsProtocolException>(() =>
            EncryptedExtensionsParser.Parse(body, offer));
        Assert.Equal(TlsAlertDescription.NoApplicationProtocol, exception.Alert);
    }

    [Fact]
    public void DuplicateExtensionsAreRejected()
    {
        var offer = new ClientHelloBuilder().BuildConfiguration();
        var body = EncodeExtensions(
            (TlsExtensionType.ServerName, []),
            (TlsExtensionType.ServerName, []));

        var exception = Assert.Throws<TlsProtocolException>(() =>
            EncryptedExtensionsParser.Parse(body, offer));
        Assert.Equal(TlsAlertDescription.IllegalParameter, exception.Alert);
    }

    [Fact]
    public void UnknownExtensionIsRejected()
    {
        var offer = new ClientHelloBuilder().BuildConfiguration();
        var extensions = new TlsBinaryWriter();
        extensions.WriteUInt16(0x1234);
        extensions.WriteVector16([]);
        var body = new TlsBinaryWriter();
        body.WriteVector16(extensions.WrittenSpan);

        var exception = Assert.Throws<TlsProtocolException>(() =>
            EncryptedExtensionsParser.Parse(body.WrittenSpan, offer));
        Assert.Equal(TlsAlertDescription.UnsupportedExtension, exception.Alert);
    }

    [Fact]
    public void ReturnedOpaqueRawExtensionFailsWithoutSemanticHandler()
    {
        var offer = new ClientHelloBuilder()
            .WithExtensionLayout([
                ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.ServerName),
                ClientHelloExtensionSpec.Raw(0xFDE8, [1]),
                ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.SupportedVersions),
                ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.SupportedGroups),
                ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.SignatureAlgorithms),
                ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.KeyShare),
            ])
            .BuildConfiguration();
        var extensions = new TlsBinaryWriter();
        extensions.WriteUInt16(0xFDE8);
        extensions.WriteVector16([2]);
        var body = new TlsBinaryWriter();
        body.WriteVector16(extensions.WrittenSpan);

        var exception = Assert.Throws<TlsProtocolException>(() =>
            EncryptedExtensionsParser.Parse(body.WrittenSpan, offer));

        Assert.Equal(TlsAlertDescription.UnsupportedExtension, exception.Alert);
        Assert.Contains("opaque raw extension", exception.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void RecordSizeLimitIsParsedAsAnAsymmetricPeerLimit()
    {
        var offer = new ClientHelloBuilder()
            .WithRecordSizeLimit(256)
            .BuildConfiguration();
        var result = EncryptedExtensionsParser.Parse(
            EncodeExtensions((TlsExtensionType.RecordSizeLimit, [0, 64])),
            offer);

        Assert.Equal(64, result.PeerRecordSizeLimit);
    }

    [Theory]
    [InlineData(new byte[] { 0 })]
    [InlineData(new byte[] { 0, 63 })]
    [InlineData(new byte[] { 0x40, 0x02 })]
    public void MalformedOrOutOfRangeRecordSizeLimitIsRejected(byte[] data)
    {
        var offer = new ClientHelloBuilder()
            .WithRecordSizeLimit(256)
            .BuildConfiguration();
        var exception = Assert.Throws<TlsProtocolException>(() =>
            EncryptedExtensionsParser.Parse(
                EncodeExtensions((TlsExtensionType.RecordSizeLimit, data)),
                offer));

        Assert.True(exception.Alert is
            TlsAlertDescription.DecodeError or TlsAlertDescription.IllegalParameter);
    }

    [Fact]
    public void UnoferredRecordSizeLimitIsRejected()
    {
        var exception = Assert.Throws<TlsProtocolException>(() =>
            EncryptedExtensionsParser.Parse(
                EncodeExtensions((TlsExtensionType.RecordSizeLimit, [0, 64])),
                new ClientHelloBuilder().BuildConfiguration()));

        Assert.Equal(TlsAlertDescription.UnsupportedExtension, exception.Alert);
    }

    [Fact]
    public void RecordSizeLimitAndDeprecatedMaximumFragmentLengthResponseConflict()
    {
        var offer = new ClientHelloBuilder()
            .WithRecordSizeLimit(256)
            .WithExtensionLayout(
                ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.ServerName),
                ClientHelloExtensionSpec.Raw(
                    (ushort)TlsExtensionType.MaximumFragmentLength,
                    [2]),
                ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.SupportedVersions),
                ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.SupportedGroups),
                ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.SignatureAlgorithms),
                ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.KeyShare),
                ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.RecordSizeLimit))
            .BuildConfiguration();
        var body = EncodeExtensions(
            (TlsExtensionType.MaximumFragmentLength, [2]),
            (TlsExtensionType.RecordSizeLimit, [0, 64]));

        var exception = Assert.Throws<TlsProtocolException>(() =>
            EncryptedExtensionsParser.Parse(body, offer));

        Assert.Equal(TlsAlertDescription.IllegalParameter, exception.Alert);
    }

    [Theory]
    [InlineData(TlsApplicationSettingsCodePoint.LegacyDraft)]
    [InlineData(TlsApplicationSettingsCodePoint.ChromeExperiment)]
    public void ApplicationSettingsAreRetainedAfterMatchingAlpnSelection(
        TlsApplicationSettingsCodePoint codePoint)
    {
        var offer = new ClientHelloBuilder()
            .WithAlpn("h2", "http/1.1")
            .WithApplicationSettings(codePoint, "h2")
            .BuildConfiguration();
        var body = EncodeRawExtensions(
            ((ushort)codePoint, new byte[] { 1, 2, 3 }),
            ((ushort)TlsExtensionType.ApplicationLayerProtocolNegotiation,
                EncodeAlpnSelection("h2")));

        var result = EncryptedExtensionsParser.Parse(body, offer);

        Assert.Equal("h2", result.NegotiatedAlpn);
        Assert.Equal(codePoint, result.ApplicationSettingsCodePoint);
        Assert.Equal(new byte[] { 1, 2, 3 }, result.PeerApplicationSettings);
    }

    [Fact]
    public void ApplicationSettingsRejectWrongCodePointOrIneligibleAlpn()
    {
        var offer = new ClientHelloBuilder()
            .WithAlpn("h2", "http/1.1")
            .WithApplicationSettings(TlsApplicationSettingsCodePoint.LegacyDraft, "h2")
            .BuildConfiguration();

        var wrongCodePoint = Assert.Throws<TlsProtocolException>(() =>
            EncryptedExtensionsParser.Parse(
                EncodeRawExtensions(
                    ((ushort)TlsApplicationSettingsCodePoint.ChromeExperiment, []),
                    ((ushort)TlsExtensionType.ApplicationLayerProtocolNegotiation,
                        EncodeAlpnSelection("h2"))),
                offer));
        Assert.Equal(TlsAlertDescription.UnsupportedExtension, wrongCodePoint.Alert);

        var ineligibleAlpn = Assert.Throws<TlsProtocolException>(() =>
            EncryptedExtensionsParser.Parse(
                EncodeRawExtensions(
                    ((ushort)TlsApplicationSettingsCodePoint.LegacyDraft, []),
                    ((ushort)TlsExtensionType.ApplicationLayerProtocolNegotiation,
                        EncodeAlpnSelection("http/1.1"))),
                offer));
        Assert.Equal(TlsAlertDescription.IllegalParameter, ineligibleAlpn.Alert);
    }

    [Fact]
    public void ApplicationSettingsRejectMissingAlpnAndAcceptedEarlyData()
    {
        var offer = new ClientHelloBuilder()
            .WithAlpn("h2")
            .WithApplicationSettings(TlsApplicationSettingsCodePoint.LegacyDraft, "h2")
            .BuildConfiguration();
        Assert.Equal(
            TlsAlertDescription.IllegalParameter,
            Assert.Throws<TlsProtocolException>(() => EncryptedExtensionsParser.Parse(
                EncodeRawExtensions(
                    ((ushort)TlsApplicationSettingsCodePoint.LegacyDraft, [9])),
                offer)).Alert);

        var earlyData = Assert.Throws<TlsProtocolException>(() =>
            EncryptedExtensionsParser.Parse(
                EncodeRawExtensions(
                    ((ushort)TlsExtensionType.ApplicationLayerProtocolNegotiation,
                        EncodeAlpnSelection("h2")),
                    ((ushort)TlsApplicationSettingsCodePoint.LegacyDraft, [9]),
                    ((ushort)TlsExtensionType.EarlyData, [])),
                offer,
                offeredEarlyData: true));
        Assert.Equal(TlsAlertDescription.IllegalParameter, earlyData.Alert);

        var ticketBound = EncryptedExtensionsParser.Parse(
            EncodeRawExtensions(
                ((ushort)TlsExtensionType.ApplicationLayerProtocolNegotiation,
                    EncodeAlpnSelection("h2")),
                ((ushort)TlsApplicationSettingsCodePoint.LegacyDraft, [9]),
                ((ushort)TlsExtensionType.EarlyData, [])),
            offer,
            offeredEarlyData: true,
            allowApplicationSettingsWithEarlyData: true);
        Assert.True(ticketBound.EarlyDataAccepted);
        Assert.Equal(new byte[] { 9 }, ticketBound.PeerApplicationSettings);
    }

    [Fact]
    public void ClientApplicationSettingsEncryptedExtensionsIsExactlyEncoded()
    {
        var encoded = Tls13ApplicationSettings.CreateClientEncryptedExtensions(
            TlsApplicationSettingsCodePoint.ChromeExperiment,
            [0xAA, 0xBB]);

        Assert.Equal(
            new byte[] { (byte)HandshakeType.EncryptedExtensions, 0, 0, 8,
                0, 6, 0x44, 0xCD, 0, 2, 0xAA, 0xBB },
            encoded);
    }

    [Fact]
    public void AuthenticatedEchRejectionParsesRetryConfigurations()
    {
        var offer = new ClientHelloBuilder()
            .WithExtensionLayout(
                ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.ServerName),
                ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.SupportedVersions),
                ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.SupportedGroups),
                ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.SignatureAlgorithms),
                ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.KeyShare),
                ClientHelloExtensionSpec.Raw(
                    (ushort)TlsExtensionType.EncryptedClientHello,
                    [0]))
            .BuildConfiguration();
        byte[] retryList = [0, 4, 0x12, 0x34, 0, 0];
        var body = EncodeRawExtensions(
            ((ushort)TlsExtensionType.EncryptedClientHello, retryList));

        var result = EncryptedExtensionsParser.Parse(
            body,
            offer,
            echWasRejected: true);

        Assert.NotNull(result.EchRetryConfigurations);
        Assert.Equal(1, result.EchRetryConfigurations.UnknownVersionCount);
        Assert.Equal(retryList, result.EchRetryConfigurations.GetEncodedList());

        var acceptedPath = Assert.Throws<TlsProtocolException>(() =>
            EncryptedExtensionsParser.Parse(body, offer));
        Assert.Equal(TlsAlertDescription.UnsupportedExtension, acceptedPath.Alert);
    }

    [Fact]
    public void MalformedEchRetryConfigurationsAreRejected()
    {
        var offer = new ClientHelloBuilder()
            .WithExtensionLayout(
                ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.ServerName),
                ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.SupportedVersions),
                ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.SupportedGroups),
                ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.SignatureAlgorithms),
                ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.KeyShare),
                ClientHelloExtensionSpec.Raw(
                    (ushort)TlsExtensionType.EncryptedClientHello,
                    [0]))
            .BuildConfiguration();

        var exception = Assert.Throws<TlsProtocolException>(() =>
            EncryptedExtensionsParser.Parse(
                EncodeRawExtensions(
                    ((ushort)TlsExtensionType.EncryptedClientHello, [0, 4, 1])),
                offer,
                echWasRejected: true));

        Assert.Equal(TlsAlertDescription.DecodeError, exception.Alert);
    }

    [Fact]
    public void EchGreaseValidatesButDoesNotRetainRetryConfigurations()
    {
        var offer = new ClientHelloBuilder()
            .WithExtensionLayout(
                ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.ServerName),
                ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.SupportedVersions),
                ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.SupportedGroups),
                ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.SignatureAlgorithms),
                ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.KeyShare),
                ClientHelloExtensionSpec.Raw(
                    (ushort)TlsExtensionType.EncryptedClientHello,
                    [0]))
            .BuildConfiguration();
        byte[] retryList = [0, 4, 0x12, 0x34, 0, 0];

        var result = EncryptedExtensionsParser.Parse(
            EncodeRawExtensions(
                ((ushort)TlsExtensionType.EncryptedClientHello, retryList)),
            offer,
            echWasGreased: true);

        Assert.Null(result.EchRetryConfigurations);
        var malformed = Assert.Throws<TlsProtocolException>(() =>
        {
            _ = EncryptedExtensionsParser.Parse(
                EncodeRawExtensions(
                    ((ushort)TlsExtensionType.EncryptedClientHello, [0, 4, 1])),
                offer,
                echWasGreased: true);
        });
        Assert.Equal(TlsAlertDescription.DecodeError, malformed.Alert);
    }

    private static byte[] EncodeExtensions(params (TlsExtensionType Type, byte[] Data)[] extensions)
    {
        var values = new TlsBinaryWriter();
        foreach (var extension in extensions)
        {
            values.WriteUInt16((ushort)extension.Type);
            values.WriteVector16(extension.Data);
        }

        var body = new TlsBinaryWriter();
        body.WriteVector16(values.WrittenSpan);
        return body.ToArray();
    }

    private static byte[] EncodeRawExtensions(params (ushort Type, byte[] Data)[] extensions)
    {
        var values = new TlsBinaryWriter();
        foreach (var extension in extensions)
        {
            values.WriteUInt16(extension.Type);
            values.WriteVector16(extension.Data);
        }
        var body = new TlsBinaryWriter();
        body.WriteVector16(values.WrittenSpan);
        return body.ToArray();
    }

    private static byte[] EncodeAlpnSelection(string protocol)
    {
        var names = new TlsBinaryWriter();
        names.WriteVector8(System.Text.Encoding.ASCII.GetBytes(protocol));
        var extension = new TlsBinaryWriter();
        extension.WriteVector16(names.WrittenSpan);
        return extension.ToArray();
    }
}
