using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using SharpTls.Certificates;
using SharpTls.IO;
using SharpTls.Protocol;

namespace SharpTls.Tests.Certificates;

public sealed class CertificateValidationTests
{
    [Fact]
    public void CertificateVerifyContextMatchesNormativeWireString()
    {
        var content = ServerCertificateValidator.BuildCertificateVerifyContent(new byte[] { 1, 2 });
        var context = System.Text.Encoding.ASCII.GetString(content, 64, content.Length - 64 - 3);

        Assert.Equal("TLS 1.3, server CertificateVerify", context);
        Assert.Equal(0, content[^3]);
        Assert.Equal(new byte[] { 1, 2 }, content[^2..]);
    }

    [Fact]
    public void ParsesAndValidatesTrustedServerCertificate()
    {
        using var pki = TestPki.Create();
        using var message = ParseCertificateMessage(pki.Leaf, pki.Root);
        var policy = CustomTrust(pki.Root);

        ServerCertificateValidator.ValidateChainAndHostname(message, "example.com", policy);
    }

    [Fact]
    public void HostnameMismatchIsRejectedWithoutCommonNameFallback()
    {
        using var pki = TestPki.Create(dnsName: "other.example");
        using var message = ParseCertificateMessage(pki.Leaf, pki.Root);

        var exception = Assert.Throws<TlsProtocolException>(() =>
            ServerCertificateValidator.ValidateChainAndHostname(
                message,
                "example.com",
                CustomTrust(pki.Root)));
        Assert.Equal(TlsAlertDescription.BadCertificate, exception.Alert);
    }

    [Fact]
    public void UntrustedRootIsRejected()
    {
        using var pki = TestPki.Create();
        using var otherPki = TestPki.Create();
        using var message = ParseCertificateMessage(pki.Leaf, pki.Root);

        var exception = Assert.Throws<TlsProtocolException>(() =>
            ServerCertificateValidator.ValidateChainAndHostname(
                message,
                "example.com",
                CustomTrust(otherPki.Root)));
        Assert.Equal(TlsAlertDescription.UnknownCa, exception.Alert);
    }

    [Fact]
    public void DangerousBypassSkipsTrustAndHostnameButNotCertificateVerify()
    {
        using var pki = TestPki.Create(dnsName: "other.example");
        using var otherPki = TestPki.Create();
        using var message = ParseCertificateMessage(pki.Leaf, pki.Root);
        var policy = CustomTrust(otherPki.Root) with
        {
            DangerouslySkipServerCertificateValidation = true,
        };

        ServerCertificateValidator.ValidateChainAndHostname(
            message,
            "example.com",
            policy);

        var transcriptHash = SHA256.HashData([1, 2, 3]);
        var exception = Assert.Throws<TlsProtocolException>(() =>
            ServerCertificateValidator.ParseAndVerifyCertificateVerify(
                EncodeCertificateVerify(
                    SignatureScheme.RsaPssRsaeSha256,
                    new byte[pki.LeafKey.KeySize / 8]),
                pki.Leaf,
                [SignatureScheme.RsaPssRsaeSha256],
                transcriptHash));
        Assert.Equal(TlsAlertDescription.DecryptError, exception.Alert);
    }

    [Fact]
    public void RevocationSoftFailAcceptsOnlyUnavailableEvidenceStatuses()
    {
        var softFail = new CertificateValidationPolicy(
            X509RevocationMode.Online,
            X509RevocationFlag.ExcludeRoot,
            DisableCertificateDownloads: false,
            TimeSpan.FromSeconds(1),
            CustomTrustRoots: null,
            AllowUnknownRevocationStatus: true);
        var hardFail = softFail with { AllowUnknownRevocationStatus = false };
        var noCheck = softFail with { RevocationMode = X509RevocationMode.NoCheck };
        X509ChainStatus[] unavailable =
        [
            ChainStatus(X509ChainStatusFlags.RevocationStatusUnknown),
            ChainStatus(X509ChainStatusFlags.OfflineRevocation),
        ];

        Assert.True(CertificateChainBuilder.ContainsOnlyUnavailableRevocationStatus(
            unavailable));
        Assert.True(CertificateChainBuilder.ShouldRetryWithoutRevocation(
            softFail,
            unavailable));
        Assert.False(CertificateChainBuilder.ShouldRetryWithoutRevocation(
            hardFail,
            unavailable));
        Assert.False(CertificateChainBuilder.ShouldRetryWithoutRevocation(
            noCheck,
            unavailable));
        Assert.False(CertificateChainBuilder.ContainsOnlyUnavailableRevocationStatus([]));
        Assert.False(CertificateChainBuilder.ContainsOnlyUnavailableRevocationStatus(
        [
            ChainStatus(X509ChainStatusFlags.Revoked),
        ]));
        Assert.False(CertificateChainBuilder.ContainsOnlyUnavailableRevocationStatus(
        [
            ChainStatus(
                X509ChainStatusFlags.RevocationStatusUnknown |
                X509ChainStatusFlags.NotTimeValid),
        ]));
        Assert.False(CertificateChainBuilder.ContainsOnlyUnavailableRevocationStatus(
        [
            ChainStatus(X509ChainStatusFlags.UntrustedRoot),
            ChainStatus(X509ChainStatusFlags.RevocationStatusUnknown),
        ]));
    }

    [Fact]
    public void WrongExtendedKeyUsageIsRejected()
    {
        using var pki = TestPki.Create(serverAuthenticationEku: false);
        using var message = ParseCertificateMessage(pki.Leaf, pki.Root);

        var exception = Assert.Throws<TlsProtocolException>(() =>
            ServerCertificateValidator.ValidateChainAndHostname(
                message,
                "example.com",
                CustomTrust(pki.Root)));
        Assert.Equal(TlsAlertDescription.BadCertificate, exception.Alert);
    }

    [Theory]
    [InlineData(false, SignatureScheme.RsaPssRsaeSha256)]
    [InlineData(true, SignatureScheme.EcdsaSecp256r1Sha256)]
    public void CertificateVerifyAcceptsRsaPssAndEcdsa(
        bool ecdsa,
        SignatureScheme scheme)
    {
        using var pki = TestPki.Create(ecdsaLeaf: ecdsa);
        var transcriptHash = SHA256.HashData([1, 2, 3]);
        var content = ServerCertificateValidator.BuildCertificateVerifyContent(transcriptHash);
        var signature = Sign(pki.LeafKey, content, ecdsa);
        var body = EncodeCertificateVerify(scheme, signature);

        var selected = ServerCertificateValidator.ParseAndVerifyCertificateVerify(
            body,
            pki.Leaf,
            [scheme],
            transcriptHash);

        Assert.Equal(scheme, selected);
    }

    [Fact]
    public void CertificateVerifyAcceptsP521WithSha512()
    {
        using var pki = TestPki.Create(ecdsaLeaf: true, ecdsaKeySize: 521);
        var transcriptHash = SHA512.HashData([5, 2, 1]);
        var content = ServerCertificateValidator.BuildCertificateVerifyContent(transcriptHash);
        var signature = ((ECDsa)pki.LeafKey).SignData(
            content,
            HashAlgorithmName.SHA512,
            DSASignatureFormat.Rfc3279DerSequence);
        var scheme = SignatureScheme.EcdsaSecp521r1Sha512;
        var body = EncodeCertificateVerify(scheme, signature);

        var selected = ServerCertificateValidator.ParseAndVerifyCertificateVerify(
            body,
            pki.Leaf,
            [scheme],
            transcriptHash);

        Assert.Equal(scheme, selected);
    }

    [Theory]
    [InlineData(SignatureScheme.RsaPssPssSha256)]
    [InlineData(SignatureScheme.RsaPssPssSha384)]
    [InlineData(SignatureScheme.RsaPssPssSha512)]
    public void CertificateVerifyAcceptsRsaPssKeyWithMatchingParameters(
        SignatureScheme scheme)
    {
        var hash = TlsClientCertificate.GetHashAlgorithm(scheme);
        using var pki = RsaPssTestCertificate.Create(hash, serverAuthentication: true);
        var transcriptHash = SHA256.HashData([9, 8, 7]);
        var content = ServerCertificateValidator.BuildCertificateVerifyContent(transcriptHash);
        var signature = pki.Key.SignData(content, hash, RSASignaturePadding.Pss);

        var selected = ServerCertificateValidator.ParseAndVerifyCertificateVerify(
            EncodeCertificateVerify(scheme, signature),
            pki.Certificate,
            [scheme],
            transcriptHash);

        Assert.Equal(scheme, selected);
    }

    [Fact]
    public void RsaPssKeyOidAndParametersMustMatchSelectedScheme()
    {
        using var pss = RsaPssTestCertificate.Create(
            HashAlgorithmName.SHA384,
            serverAuthentication: true);
        using var rsae = TestPki.Create();
        var transcriptHash = SHA256.HashData([4, 5, 6]);
        var content = ServerCertificateValidator.BuildCertificateVerifyContent(transcriptHash);
        var pssSignature = pss.Key.SignData(
            content,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pss);
        var rsaeSignature = ((RSA)rsae.LeafKey).SignData(
            content,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pss);

        Assert.Equal(TlsAlertDescription.DecryptError, Assert.Throws<TlsProtocolException>(() =>
            ServerCertificateValidator.ParseAndVerifyCertificateVerify(
                EncodeCertificateVerify(SignatureScheme.RsaPssPssSha256, pssSignature),
                pss.Certificate,
                [SignatureScheme.RsaPssPssSha256],
                transcriptHash)).Alert);
        Assert.Equal(TlsAlertDescription.DecryptError, Assert.Throws<TlsProtocolException>(() =>
            ServerCertificateValidator.ParseAndVerifyCertificateVerify(
                EncodeCertificateVerify(SignatureScheme.RsaPssRsaeSha256, pssSignature),
                pss.Certificate,
                [SignatureScheme.RsaPssRsaeSha256],
                transcriptHash)).Alert);
        Assert.Equal(TlsAlertDescription.DecryptError, Assert.Throws<TlsProtocolException>(() =>
            ServerCertificateValidator.ParseAndVerifyCertificateVerify(
                EncodeCertificateVerify(SignatureScheme.RsaPssPssSha256, rsaeSignature),
                rsae.Leaf,
                [SignatureScheme.RsaPssPssSha256],
                transcriptHash)).Alert);
    }

    [Fact]
    public void TamperedCertificateVerifyIsRejected()
    {
        using var pki = TestPki.Create();
        var transcriptHash = SHA256.HashData([1, 2, 3]);
        var content = ServerCertificateValidator.BuildCertificateVerifyContent(transcriptHash);
        var signature = Sign(pki.LeafKey, content, ecdsa: false);
        signature[^1] ^= 1;
        var body = EncodeCertificateVerify(SignatureScheme.RsaPssRsaeSha256, signature);

        var exception = Assert.Throws<TlsProtocolException>(() =>
            ServerCertificateValidator.ParseAndVerifyCertificateVerify(
                body,
                pki.Leaf,
                [SignatureScheme.RsaPssRsaeSha256],
                transcriptHash));
        Assert.Equal(TlsAlertDescription.DecryptError, exception.Alert);
    }

    [Fact]
    public void SignatureSchemeMustMatchCertificateKey()
    {
        using var pki = TestPki.Create(ecdsaLeaf: true);
        var transcriptHash = new byte[32];
        var body = EncodeCertificateVerify(SignatureScheme.RsaPssRsaeSha256, [1, 2, 3]);

        var exception = Assert.Throws<TlsProtocolException>(() =>
            ServerCertificateValidator.ParseAndVerifyCertificateVerify(
                body,
                pki.Leaf,
                [SignatureScheme.RsaPssRsaeSha256],
                transcriptHash));
        Assert.Equal(TlsAlertDescription.DecryptError, exception.Alert);
    }

    [Fact]
    public void MalformedCertificateListLengthIsRejected()
    {
        byte[] body = [0, 0, 0, 4, 0, 0, 5, 1];
        var exception = Assert.Throws<TlsProtocolException>(() =>
            CertificateMessageParser.Parse(body, TlsLimits.Default));
        Assert.Equal(TlsAlertDescription.DecodeError, exception.Alert);
    }

    [Fact]
    public void EmptyCertificateListIsRejected()
    {
        byte[] body = [0, 0, 0, 0];
        var exception = Assert.Throws<TlsProtocolException>(() =>
            CertificateMessageParser.Parse(body, TlsLimits.Default));
        Assert.Equal(TlsAlertDescription.BadCertificate, exception.Alert);
    }

    [Fact]
    public void OfferedOcspCertificateEntryExtensionIsStrictlyParsed()
    {
        using var pki = TestPki.Create();
        var offer = ClientHelloProfiles.UTlsChrome83.Spec.SnapshotConfiguration();
        var extensions = new TlsBinaryWriter();
        extensions.WriteUInt16(5);
        extensions.WriteVector16([1, 0, 0, 3, 9, 8, 7]);
        extensions.WriteUInt16(18);
        extensions.WriteVector16([0, 5, 0, 3, 6, 5, 4]);
        var body = EncodeCertificateBody(pki.Leaf, extensions.WrittenSpan);

        using var certificates = CertificateMessageParser.Parse(
            body,
            TlsLimits.Default,
            offer);

        Assert.Equal(pki.Leaf.RawData, certificates.Leaf.RawData);
        Assert.Equal(new byte[] { 9, 8, 7 }, certificates.LeafOcspResponse);
        Assert.Equal(
            new byte[] { 6, 5, 4 },
            Assert.Single(certificates.LeafSignedCertificateTimestamps));
    }

    [Fact]
    public void MalformedOrUnofferedOcspCertificateEntryExtensionIsRejected()
    {
        using var pki = TestPki.Create();
        var malformedExtensions = new TlsBinaryWriter();
        malformedExtensions.WriteUInt16(5);
        malformedExtensions.WriteVector16([1, 0, 0, 0]);
        var malformedBody = EncodeCertificateBody(pki.Leaf, malformedExtensions.WrittenSpan);

        var malformed = Assert.Throws<TlsProtocolException>(() => CertificateMessageParser.Parse(
            malformedBody,
            TlsLimits.Default,
            ClientHelloProfiles.UTlsFirefox99.Spec.SnapshotConfiguration()));
        var unoffered = Assert.Throws<TlsProtocolException>(() => CertificateMessageParser.Parse(
            EncodeCertificateBody(pki.Leaf, [0, 5, 0, 7, 1, 0, 0, 3, 9, 8, 7]),
            TlsLimits.Default));

        Assert.Equal(TlsAlertDescription.DecodeError, malformed.Alert);
        Assert.Equal(TlsAlertDescription.UnsupportedExtension, unoffered.Alert);
    }

    private static ServerCertificateMessage ParseCertificateMessage(params X509Certificate2[] certificates)
    {
        var entries = new TlsBinaryWriter();
        foreach (var certificate in certificates)
        {
            entries.WriteVector24(certificate.RawData);
            entries.WriteVector16([]);
        }

        var body = new TlsBinaryWriter();
        body.WriteVector8([]);
        body.WriteVector24(entries.WrittenSpan);
        return CertificateMessageParser.Parse(body.WrittenSpan, TlsLimits.Default);
    }

    private static byte[] EncodeCertificateBody(
        X509Certificate2 certificate,
        ReadOnlySpan<byte> encodedExtensions)
    {
        var entries = new TlsBinaryWriter();
        entries.WriteVector24(certificate.RawData);
        entries.WriteVector16(encodedExtensions);
        var body = new TlsBinaryWriter();
        body.WriteVector8([]);
        body.WriteVector24(entries.WrittenSpan);
        return body.ToArray();
    }

    private static CertificateValidationPolicy CustomTrust(X509Certificate2 root) => new(
        X509RevocationMode.NoCheck,
        X509RevocationFlag.ExcludeRoot,
        DisableCertificateDownloads: true,
        TimeSpan.Zero,
        new X509Certificate2Collection(root));

    private static X509ChainStatus ChainStatus(X509ChainStatusFlags flags) => new()
    {
        Status = flags,
    };

    private static byte[] Sign(AsymmetricAlgorithm key, byte[] content, bool ecdsa) => ecdsa
        ? ((ECDsa)key).SignData(
            content,
            HashAlgorithmName.SHA256,
            DSASignatureFormat.Rfc3279DerSequence)
        : ((RSA)key).SignData(content, HashAlgorithmName.SHA256, RSASignaturePadding.Pss);

    private static byte[] EncodeCertificateVerify(SignatureScheme scheme, ReadOnlySpan<byte> signature)
    {
        var writer = new TlsBinaryWriter();
        writer.WriteUInt16((ushort)scheme);
        writer.WriteVector16(signature);
        return writer.ToArray();
    }
}
