using SharpTls.Cryptography;
using SharpTls.Handshake;
using SharpTls.IO;
using SharpTls.Protocol;

namespace SharpTls.Tests.Handshake;

public sealed class Tls12ClientHandshakeMessageTests
{
    [Fact]
    public void CertificateRequestParsesAndEmptyClientCertificateHasTls12Shape()
    {
        var body = new TlsBinaryWriter();
        body.WriteVector8([1, 64]);
        var schemes = new TlsBinaryWriter();
        schemes.WriteUInt16((ushort)SignatureScheme.RsaPssRsaeSha256);
        schemes.WriteUInt16(0xFEFE);
        body.WriteVector16(schemes.WrittenSpan);
        var authorities = new TlsBinaryWriter();
        authorities.WriteVector16([1, 2, 3]);
        body.WriteVector16(authorities.WrittenSpan);

        var parsed = Tls12CertificateRequestParser.Parse(body.WrittenSpan);
        var emptyCertificate = ClientAuthenticationMessages.CreateTls12Certificate(
            credential: null,
            TlsLimits.Default);

        Assert.Equal(new byte[] { 1, 64 }, parsed.CertificateTypes);
        Assert.Equal([SignatureScheme.RsaPssRsaeSha256], parsed.SignatureSchemes);
        Assert.Equal(1, parsed.CertificateAuthorityCount);
        Assert.Equal(new byte[] { 11, 0, 0, 3, 0, 0, 0 }, emptyCertificate);
    }

    [Theory]
    [InlineData("0000000000")]
    [InlineData("010100000000")]
    [InlineData("01010001000000")]
    public void MalformedCertificateRequestsAreRejected(string hex)
    {
        Assert.Equal(
            TlsAlertDescription.DecodeError,
            Assert.Throws<TlsProtocolException>(() =>
                Tls12CertificateRequestParser.Parse(Convert.FromHexString(hex))).Alert);
    }

    [Fact]
    public void ClientKeyExchangeUsesEcPointVector8()
    {
        var encoded = Tls12ClientKeyExchangeEncoder.Encode([4, 1, 2, 3]);

        Assert.Equal(
            new byte[] { 16, 0, 0, 5, 4, 4, 1, 2, 3 },
            encoded);
        Assert.Throws<ArgumentOutOfRangeException>(() =>
            Tls12ClientKeyExchangeEncoder.Encode([]));
    }

    [Fact]
    public void FinishedCreationAndVerificationRejectTamperingAndBadLengths()
    {
        var suite = Tls12CipherSuiteInfo.Get(
            TlsCipherSuite.TlsEcdheRsaWithAes128GcmSha256);
        using var schedule = new Tls12KeySchedule(suite);
        schedule.DeriveExtendedMasterSecret(new byte[32], new byte[32]);
        var transcriptHash = new byte[32];
        var encodedClient = Tls12FinishedProcessor.CreateClientFinished(schedule, transcriptHash);
        var serverBody = schedule.ComputeServerFinished(transcriptHash);

        Tls12FinishedProcessor.VerifyServerFinished(serverBody, schedule, transcriptHash);
        serverBody[0] ^= 1;

        Assert.Equal((byte)HandshakeType.Finished, encodedClient[0]);
        Assert.Equal(TlsConstants.Tls12FinishedLength, encodedClient.Length - 4);
        Assert.Equal(
            TlsAlertDescription.DecryptError,
            Assert.Throws<TlsProtocolException>(() =>
                Tls12FinishedProcessor.VerifyServerFinished(
                    serverBody,
                    schedule,
                    transcriptHash)).Alert);
        Assert.Equal(
            TlsAlertDescription.DecodeError,
            Assert.Throws<TlsProtocolException>(() =>
                Tls12FinishedProcessor.VerifyServerFinished(
                    new byte[11],
                    schedule,
                    transcriptHash)).Alert);
    }

    [Theory]
    [InlineData("000000000000")]
    [InlineData("000000000001AA")]
    public void NewSessionTicketParserAcceptsEmptyAndNonEmptyTickets(string hex)
    {
        Tls12NewSessionTicketParser.ParseAndDiscard(Convert.FromHexString(hex));
    }

    [Fact]
    public void ServerHelloVersionDetectorDistinguishesLegacyAndTls13()
    {
        Assert.Equal(
            TlsProtocolVersion.Tls12,
            TlsServerHelloVersionDetector.Detect(BuildServerHello([])));

        var tls13Extensions = new TlsBinaryWriter();
        tls13Extensions.WriteUInt16((ushort)TlsExtensionType.SupportedVersions);
        tls13Extensions.WriteVector16([3, 4]);
        Assert.Equal(
            TlsProtocolVersion.Tls13,
            TlsServerHelloVersionDetector.Detect(BuildServerHello(tls13Extensions.WrittenSpan)));
    }

    [Fact]
    public void VersionDetectorRejectsLegacyVersionInsideSupportedVersions()
    {
        var extensions = new TlsBinaryWriter();
        extensions.WriteUInt16((ushort)TlsExtensionType.SupportedVersions);
        extensions.WriteVector16([3, 3]);

        Assert.Equal(
            TlsAlertDescription.IllegalParameter,
            Assert.Throws<TlsProtocolException>(() =>
                TlsServerHelloVersionDetector.Detect(BuildServerHello(extensions.WrittenSpan))).Alert);
    }

    private static byte[] BuildServerHello(ReadOnlySpan<byte> extensions)
    {
        var body = new TlsBinaryWriter();
        body.WriteUInt16(TlsConstants.LegacyRecordVersion);
        body.WriteBytes(new byte[32]);
        body.WriteVector8([]);
        body.WriteUInt16((ushort)TlsCipherSuite.TlsAes128GcmSha256);
        body.WriteUInt8(0);
        body.WriteVector16(extensions);
        return body.ToArray();
    }
}
