using System.Security.Cryptography;
using SharpTls.Cryptography;
using SharpTls.Handshake;
using SharpTls.IO;
using SharpTls.Protocol;

namespace SharpTls.Tests.Handshake;

public sealed class FinishedAndCertificateRequestTests
{
    [Fact]
    public void FinishedVerificationIsConstantTimeComparedAndRejectsTampering()
    {
        var suite = CipherSuiteInfo.Get(TlsCipherSuite.TlsAes128GcmSha256);
        using var schedule = new Tls13KeySchedule(suite);
        schedule.DeriveHandshakeSecrets(new byte[32], new byte[32]);
        var transcriptHash = SHA256.HashData([1, 2, 3]);
        var expected = schedule.ComputeServerFinished(transcriptHash);

        FinishedProcessor.VerifyServerFinished(expected, schedule, transcriptHash);
        expected[0] ^= 1;
        var exception = Assert.Throws<TlsProtocolException>(() =>
            FinishedProcessor.VerifyServerFinished(expected, schedule, transcriptHash));
        Assert.Equal(TlsAlertDescription.DecryptError, exception.Alert);
    }

    [Fact]
    public void CertificateRequestRequiresSignatureAlgorithmsPerRfc9846()
    {
        var body = new TlsBinaryWriter();
        body.WriteVector8([]);
        body.WriteVector16([]);

        var exception = Assert.Throws<TlsProtocolException>(() =>
            CertificateRequestParser.ParseInitial(body.WrittenSpan));
        Assert.Equal(TlsAlertDescription.MissingExtension, exception.Alert);
    }

    [Fact]
    public void NonEmptyInitialCertificateRequestContextIsRejected()
    {
        var body = new TlsBinaryWriter();
        body.WriteVector8([1]);
        body.WriteVector16(CreateSignatureAlgorithmsExtension());

        var exception = Assert.Throws<TlsProtocolException>(() =>
            CertificateRequestParser.ParseInitial(body.WrittenSpan));
        Assert.Equal(TlsAlertDescription.IllegalParameter, exception.Alert);
    }

    [Fact]
    public void SignatureAlgorithmsAreParsedInPeerPreferenceOrder()
    {
        var body = new TlsBinaryWriter();
        body.WriteVector8([]);
        body.WriteVector16(CreateSignatureAlgorithmsExtension(
            SignatureScheme.EcdsaSecp384r1Sha384,
            SignatureScheme.RsaPssRsaeSha256));

        var request = CertificateRequestParser.ParseInitial(body.WrittenSpan);

        Assert.Empty(request.Context);
        Assert.Equal(
            [SignatureScheme.EcdsaSecp384r1Sha384, SignatureScheme.RsaPssRsaeSha256],
            request.SignatureSchemes);
    }

    [Fact]
    public void DuplicateAndKnownIllegalCertificateRequestExtensionsAreRejected()
    {
        var duplicate = new TlsBinaryWriter();
        duplicate.WriteBytes(CreateSignatureAlgorithmsExtension());
        duplicate.WriteBytes(CreateSignatureAlgorithmsExtension());
        var duplicateBody = new TlsBinaryWriter();
        duplicateBody.WriteVector8([]);
        duplicateBody.WriteVector16(duplicate.WrittenSpan);

        Assert.Equal(
            TlsAlertDescription.IllegalParameter,
            Assert.Throws<TlsProtocolException>(() =>
                CertificateRequestParser.ParseInitial(duplicateBody.WrittenSpan)).Alert);

        var illegal = new TlsBinaryWriter();
        illegal.WriteBytes(CreateSignatureAlgorithmsExtension());
        illegal.WriteUInt16((ushort)TlsExtensionType.ApplicationLayerProtocolNegotiation);
        illegal.WriteVector16([]);
        var illegalBody = new TlsBinaryWriter();
        illegalBody.WriteVector8([]);
        illegalBody.WriteVector16(illegal.WrittenSpan);

        Assert.Equal(
            TlsAlertDescription.IllegalParameter,
            Assert.Throws<TlsProtocolException>(() =>
                CertificateRequestParser.ParseInitial(illegalBody.WrittenSpan)).Alert);
    }

    [Fact]
    public void CertificateRequestParsesIndependentCertificateSignatureAlgorithms()
    {
        var extensions = new TlsBinaryWriter();
        extensions.WriteBytes(CreateSignatureAlgorithmsExtension(
            SignatureScheme.RsaPssRsaeSha256));
        extensions.WriteBytes(CreateSignatureAlgorithmsExtension(
            TlsExtensionType.SignatureAlgorithmsCert,
            SignatureScheme.RsaPkcs1Sha384,
            SignatureScheme.EcdsaSecp384r1Sha384));
        var body = new TlsBinaryWriter();
        body.WriteVector8([]);
        body.WriteVector16(extensions.WrittenSpan);

        var request = CertificateRequestParser.ParseInitial(body.WrittenSpan);

        Assert.Equal(
            [SignatureScheme.RsaPkcs1Sha384, SignatureScheme.EcdsaSecp384r1Sha384],
            request.CertificateSignatureSchemes);
    }

    [Fact]
    public void CertificateRequestParsesDelegatedCredentialAlgorithmsWithoutRequiringUse()
    {
        var extensions = new TlsBinaryWriter();
        extensions.WriteBytes(CreateSignatureAlgorithmsExtension(
            SignatureScheme.RsaPssRsaeSha256));
        extensions.WriteBytes(CreateSignatureAlgorithmsExtension(
            TlsExtensionType.DelegatedCredential,
            SignatureScheme.EcdsaSecp256r1Sha256,
            SignatureScheme.EcdsaSecp384r1Sha384));
        var body = new TlsBinaryWriter();
        body.WriteVector8([]);
        body.WriteVector16(extensions.WrittenSpan);

        var request = CertificateRequestParser.ParseInitial(body.WrittenSpan);

        Assert.Equal(
            [SignatureScheme.EcdsaSecp256r1Sha256,
             SignatureScheme.EcdsaSecp384r1Sha384],
            request.DelegatedCredentialSignatureSchemes);
    }

    private static byte[] CreateSignatureAlgorithmsExtension(
        params SignatureScheme[] schemes)
        => CreateSignatureAlgorithmsExtension(
            TlsExtensionType.SignatureAlgorithms,
            schemes);

    private static byte[] CreateSignatureAlgorithmsExtension(
        TlsExtensionType extensionType,
        params SignatureScheme[] schemes)
    {
        if (schemes.Length == 0)
        {
            schemes = [SignatureScheme.RsaPssRsaeSha256];
        }

        var list = new TlsBinaryWriter();
        foreach (var scheme in schemes)
        {
            list.WriteUInt16((ushort)scheme);
        }

        var body = new TlsBinaryWriter();
        body.WriteVector16(list.WrittenSpan);
        var extension = new TlsBinaryWriter();
        extension.WriteUInt16((ushort)extensionType);
        extension.WriteVector16(body.WrittenSpan);
        return extension.ToArray();
    }
}
