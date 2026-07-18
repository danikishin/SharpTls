using SharpTls.Handshake;
using SharpTls.IO;
using SharpTls.Protocol;

namespace SharpTls.Tests.Handshake;

public sealed class Tls12ClientHelloParserTests
{
    [Fact]
    public void EmptyRenegotiationInfoScsvSatisfiesInitialSecureRenegotiationSignal()
    {
        var parsed = Tls12ClientHelloParser.Parse(BuildClientHello(
            includeScsv: true,
            includeRenegotiationExtension: false));

        Assert.Equal(
            [TlsCipherSuite.TlsEcdheRsaWithAes128GcmSha256],
            parsed.CipherSuites);
    }

    [Fact]
    public void MissingSecureRenegotiationExtensionAndScsvIsRejected()
    {
        var exception = Assert.Throws<TlsProtocolException>(() =>
            Tls12ClientHelloParser.Parse(BuildClientHello(
                includeScsv: false,
                includeRenegotiationExtension: false)));

        Assert.Equal(TlsAlertDescription.HandshakeFailure, exception.Alert);
    }

    private static byte[] BuildClientHello(
        bool includeScsv,
        bool includeRenegotiationExtension)
    {
        var cipherSuites = new TlsBinaryWriter();
        cipherSuites.WriteUInt16(
            (ushort)TlsCipherSuite.TlsEcdheRsaWithAes128GcmSha256);
        if (includeScsv)
        {
            cipherSuites.WriteUInt16(TlsConstants.TlsEmptyRenegotiationInfoScsv);
        }

        var extensions = new TlsBinaryWriter();
        WriteExtension(extensions, TlsExtensionType.ExtendedMasterSecret, []);
        if (includeRenegotiationExtension)
        {
            WriteExtension(extensions, TlsExtensionType.RenegotiationInfo, [0]);
        }

        var groups = new TlsBinaryWriter();
        groups.WriteVector16([0x00, (byte)NamedGroup.Secp256r1]);
        WriteExtension(extensions, TlsExtensionType.SupportedGroups, groups.WrittenSpan);

        var signatures = new TlsBinaryWriter();
        signatures.WriteVector16([0x08, 0x04]);
        WriteExtension(
            extensions,
            TlsExtensionType.SignatureAlgorithms,
            signatures.WrittenSpan);

        var body = new TlsBinaryWriter();
        body.WriteUInt16(TlsConstants.Tls12Version);
        body.WriteBytes(new byte[TlsConstants.RandomLength]);
        body.WriteVector8([]);
        body.WriteVector16(cipherSuites.WrittenSpan);
        body.WriteVector8([0]);
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
