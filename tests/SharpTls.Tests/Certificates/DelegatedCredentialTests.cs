using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using SharpTls.Certificates;
using SharpTls.IO;
using SharpTls.Protocol;

namespace SharpTls.Tests.Certificates;

public sealed class DelegatedCredentialTests
{
    [Fact]
    public void ValidCredentialAuthenticatesCertificateVerifyWithDelegatedKey()
    {
        using var pki = TestPki.Create(delegationUsage: true);
        using var delegatedKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var encoded = EncodeDelegatedCredential(
            pki,
            delegatedKey,
            expiresAfter: TimeSpan.FromDays(1));
        using var certificates = ParseCertificateMessage(pki, encoded);
        var transcriptHash = SHA256.HashData("delegated transcript"u8);
        var certificateVerifyContent =
            ServerCertificateValidator.BuildCertificateVerifyContent(transcriptHash);
        var signature = delegatedKey.SignData(
            certificateVerifyContent,
            HashAlgorithmName.SHA256,
            DSASignatureFormat.Rfc3279DerSequence);
        var certificateVerify = new TlsBinaryWriter();
        certificateVerify.WriteUInt16((ushort)SignatureScheme.EcdsaSecp256r1Sha256);
        certificateVerify.WriteVector16(signature);

        ServerCertificateValidator.ValidateChainAndHostname(
            certificates,
            "example.com",
            CustomTrust(pki.Root));
        var selected = ServerCertificateValidator.ParseAndVerifyCertificateVerify(
            certificateVerify.WrittenSpan,
            certificates.Leaf,
            [SignatureScheme.EcdsaSecp256r1Sha256],
            transcriptHash,
            certificates.DelegatedCredential);

        Assert.Equal(SignatureScheme.EcdsaSecp256r1Sha256, selected);
        Assert.NotNull(certificates.DelegatedCredential);
    }

    [Fact]
    public void RsaPssDelegatedKeyAuthenticatesCertificateVerify()
    {
        using var pki = TestPki.Create(delegationUsage: true);
        using var delegated = RsaPssTestCertificate.Create(
            HashAlgorithmName.SHA256,
            serverAuthentication: true);
        var encoded = EncodeRsaPssDelegatedCredential(
            pki,
            delegated.Certificate.PublicKey.ExportSubjectPublicKeyInfo(),
            TimeSpan.FromDays(1));
        using var certificates = ParseCertificateMessage(pki, encoded, CreateRsaPssOffer());
        var transcriptHash = SHA256.HashData("delegated rsa pss transcript"u8);
        var content = ServerCertificateValidator.BuildCertificateVerifyContent(transcriptHash);
        var signature = delegated.Key.SignData(
            content,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pss);
        var certificateVerify = new TlsBinaryWriter();
        certificateVerify.WriteUInt16((ushort)SignatureScheme.RsaPssPssSha256);
        certificateVerify.WriteVector16(signature);

        var selected = ServerCertificateValidator.ParseAndVerifyCertificateVerify(
            certificateVerify.WrittenSpan,
            certificates.Leaf,
            [SignatureScheme.RsaPssPssSha256],
            transcriptHash,
            certificates.DelegatedCredential);

        Assert.Equal(SignatureScheme.RsaPssPssSha256, selected);
    }

    [Fact]
    public void RsaeSpkiCannotMasqueradeAsPssDelegatedKey()
    {
        using var pki = TestPki.Create(delegationUsage: true);
        using var rsa = RSA.Create(2048);
        var encoded = EncodeRsaPssDelegatedCredential(
            pki,
            rsa.ExportSubjectPublicKeyInfo(),
            TimeSpan.FromDays(1));

        var exception = Assert.Throws<TlsProtocolException>(() =>
            Tls13DelegatedCredentialParser.ParseAndValidate(
                encoded,
                pki.Leaf,
                CreateRsaPssOffer()));

        Assert.Equal(TlsAlertDescription.IllegalParameter, exception.Alert);
    }

    [Fact]
    public void TamperedDelegationSignatureFailsWithIllegalParameter()
    {
        using var pki = TestPki.Create(delegationUsage: true);
        using var delegatedKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var encoded = EncodeDelegatedCredential(pki, delegatedKey, TimeSpan.FromDays(1));
        encoded[^1] ^= 1;

        var exception = Assert.Throws<TlsProtocolException>(() =>
            Tls13DelegatedCredentialParser.ParseAndValidate(
                encoded,
                pki.Leaf,
                CreateOffer()));

        Assert.Equal(TlsAlertDescription.IllegalParameter, exception.Alert);
    }

    [Fact]
    public void MissingDelegationUsageAndExcessiveLifetimeFailClosed()
    {
        using var ordinaryPki = TestPki.Create();
        using var delegatedKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var ordinaryCredential = EncodeDelegatedCredential(
            ordinaryPki,
            delegatedKey,
            TimeSpan.FromDays(1));
        Assert.Equal(
            TlsAlertDescription.IllegalParameter,
            Assert.Throws<TlsProtocolException>(() =>
                Tls13DelegatedCredentialParser.ParseAndValidate(
                    ordinaryCredential,
                    ordinaryPki.Leaf,
                    CreateOffer())).Alert);

        using var enabledPki = TestPki.Create(delegationUsage: true);
        var longCredential = EncodeDelegatedCredential(
            enabledPki,
            delegatedKey,
            TimeSpan.FromDays(8));
        Assert.Equal(
            TlsAlertDescription.IllegalParameter,
            Assert.Throws<TlsProtocolException>(() =>
                Tls13DelegatedCredentialParser.ParseAndValidate(
                    longCredential,
                    enabledPki.Leaf,
                    CreateOffer())).Alert);
    }

    [Fact]
    public void CredentialOnNonLeafCertificateIsRejected()
    {
        using var pki = TestPki.Create(delegationUsage: true);
        using var delegatedKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var delegatedCredential = EncodeDelegatedCredential(
            pki,
            delegatedKey,
            TimeSpan.FromDays(1));
        var entries = new TlsBinaryWriter();
        entries.WriteVector24(pki.Leaf.RawData);
        entries.WriteVector16([]);
        entries.WriteVector24(pki.Root.RawData);
        var rootExtensions = new TlsBinaryWriter();
        rootExtensions.WriteUInt16((ushort)TlsExtensionType.DelegatedCredential);
        rootExtensions.WriteVector16(delegatedCredential);
        entries.WriteVector16(rootExtensions.WrittenSpan);
        var body = new TlsBinaryWriter();
        body.WriteVector8([]);
        body.WriteVector24(entries.WrittenSpan);

        var exception = Assert.Throws<TlsProtocolException>(() =>
            CertificateMessageParser.Parse(body.WrittenSpan, TlsLimits.Default, CreateOffer()));

        Assert.Equal(TlsAlertDescription.IllegalParameter, exception.Alert);
    }

    [Fact]
    public void UnadvertisedCredentialIsUnexpectedMessage()
    {
        using var pki = TestPki.Create(delegationUsage: true);
        using var delegatedKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var encoded = EncodeDelegatedCredential(pki, delegatedKey, TimeSpan.FromDays(1));
        var body = EncodeCertificateBody(pki.Leaf, encoded);

        var exception = Assert.Throws<TlsProtocolException>(() =>
            CertificateMessageParser.Parse(
                body,
                TlsLimits.Default,
                ClientHelloProfiles.ModernTls13.Spec.SnapshotConfiguration()));

        Assert.Equal(TlsAlertDescription.UnexpectedMessage, exception.Alert);
    }

    internal static byte[] EncodeDelegatedCredential(
        TestPki pki,
        ECDsa delegatedKey,
        TimeSpan expiresAfter)
    {
        var notBefore = new DateTimeOffset(pki.Leaf.NotBefore.ToUniversalTime());
        var expiry = DateTimeOffset.UtcNow.Add(expiresAfter);
        var validTime = checked((uint)Math.Ceiling((expiry - notBefore).TotalSeconds));
        var unsigned = new TlsBinaryWriter();
        unsigned.WriteUInt32(validTime);
        unsigned.WriteUInt16((ushort)SignatureScheme.EcdsaSecp256r1Sha256);
        unsigned.WriteVector24(delegatedKey.ExportSubjectPublicKeyInfo());
        unsigned.WriteUInt16((ushort)SignatureScheme.RsaPssRsaeSha256);
        var signedContent = Tls13DelegatedCredentialParser.BuildSignedContent(
            pki.Leaf.RawData,
            unsigned.WrittenSpan);
        var signature = ((RSA)pki.LeafKey).SignData(
            signedContent,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pss);
        var encoded = new TlsBinaryWriter();
        encoded.WriteBytes(unsigned.WrittenSpan);
        encoded.WriteVector16(signature);
        CryptographicOperations.ZeroMemory(signedContent);
        CryptographicOperations.ZeroMemory(signature);
        return encoded.ToArray();
    }

    private static byte[] EncodeRsaPssDelegatedCredential(
        TestPki pki,
        ReadOnlySpan<byte> subjectPublicKeyInfo,
        TimeSpan expiresAfter)
    {
        var notBefore = new DateTimeOffset(pki.Leaf.NotBefore.ToUniversalTime());
        var expiry = DateTimeOffset.UtcNow.Add(expiresAfter);
        var validTime = checked((uint)Math.Ceiling((expiry - notBefore).TotalSeconds));
        var unsigned = new TlsBinaryWriter();
        unsigned.WriteUInt32(validTime);
        unsigned.WriteUInt16((ushort)SignatureScheme.RsaPssPssSha256);
        unsigned.WriteVector24(subjectPublicKeyInfo);
        unsigned.WriteUInt16((ushort)SignatureScheme.RsaPssRsaeSha256);
        var signedContent = Tls13DelegatedCredentialParser.BuildSignedContent(
            pki.Leaf.RawData,
            unsigned.WrittenSpan);
        var signature = ((RSA)pki.LeafKey).SignData(
            signedContent,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pss);
        var encoded = new TlsBinaryWriter();
        encoded.WriteBytes(unsigned.WrittenSpan);
        encoded.WriteVector16(signature);
        CryptographicOperations.ZeroMemory(signedContent);
        CryptographicOperations.ZeroMemory(signature);
        return encoded.ToArray();
    }

    private static ServerCertificateMessage ParseCertificateMessage(
        TestPki pki,
        ReadOnlySpan<byte> delegatedCredential,
        ClientHelloConfiguration? offer = null) => CertificateMessageParser.Parse(
        EncodeCertificateBody(pki.Leaf, delegatedCredential),
        TlsLimits.Default,
        offer ?? CreateOffer());

    private static byte[] EncodeCertificateBody(
        X509Certificate2 leaf,
        ReadOnlySpan<byte> delegatedCredential)
    {
        var extensions = new TlsBinaryWriter();
        extensions.WriteUInt16((ushort)TlsExtensionType.DelegatedCredential);
        extensions.WriteVector16(delegatedCredential);
        var entries = new TlsBinaryWriter();
        entries.WriteVector24(leaf.RawData);
        entries.WriteVector16(extensions.WrittenSpan);
        var body = new TlsBinaryWriter();
        body.WriteVector8([]);
        body.WriteVector24(entries.WrittenSpan);
        return body.ToArray();
    }

    private static ClientHelloConfiguration CreateOffer() => new ClientHelloBuilder()
        .WithDelegatedCredentials(SignatureScheme.EcdsaSecp256r1Sha256)
        .BuildConfiguration();

    private static ClientHelloConfiguration CreateRsaPssOffer() => new ClientHelloBuilder()
        .WithDelegatedCredentials(SignatureScheme.RsaPssPssSha256)
        .BuildConfiguration();

    private static CertificateValidationPolicy CustomTrust(X509Certificate2 root) => new(
        X509RevocationMode.NoCheck,
        X509RevocationFlag.ExcludeRoot,
        DisableCertificateDownloads: true,
        TimeSpan.Zero,
        new X509Certificate2Collection(root));
}
