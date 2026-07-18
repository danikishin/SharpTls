using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using SharpTls.Certificates;
using SharpTls.Handshake;
using SharpTls.IO;
using SharpTls.Protocol;

namespace SharpTls.Tests.Certificates;

public sealed class ClientCertificateTests
{
    [Fact]
    public void RsaCredentialCreatesTls13ChainAndPssCertificateVerify()
    {
        using var pki = TestPki.Create(serverAuthenticationEku: false);
        using var leafWithKey = pki.Leaf.CopyWithPrivateKey((RSA)pki.LeafKey);
        using var credential = new TlsClientCertificate(leafWithKey, [pki.Root]);
        var request = new Tls13CertificateRequest(
            [1, 2, 3],
            [SignatureScheme.RsaPssRsaeSha384, SignatureScheme.RsaPssRsaeSha256]);

        var scheme = credential.SelectTls13SignatureScheme(request.SignatureSchemes);
        var certificate = ClientAuthenticationMessages.CreateTls13Certificate(
            request.Context,
            credential,
            TlsLimits.Default);
        var transcriptHash = SHA256.HashData("client transcript"u8);
        var certificateVerify = ClientAuthenticationMessages.CreateTls13CertificateVerify(
            credential,
            scheme!.Value,
            transcriptHash);

        var certificateBody = new TlsBinaryReader(certificate.AsSpan(4));
        Assert.Equal(request.Context, certificateBody.ReadVector8().ToArray());
        var entries = new TlsBinaryReader(certificateBody.ReadVector24());
        Assert.Equal(pki.Leaf.RawData, entries.ReadVector24().ToArray());
        Assert.Empty(entries.ReadVector16().ToArray());
        Assert.Equal(pki.Root.RawData, entries.ReadVector24().ToArray());
        Assert.Empty(entries.ReadVector16().ToArray());
        Assert.True(entries.End);
        certificateBody.EnsureEnd("test Certificate");

        var verifyBody = new TlsBinaryReader(certificateVerify.AsSpan(4));
        Assert.Equal((ushort)SignatureScheme.RsaPssRsaeSha384, verifyBody.ReadUInt16());
        var signature = verifyBody.ReadVector16().ToArray();
        verifyBody.EnsureEnd("test CertificateVerify");
        var content = ClientAuthenticationMessages.BuildTls13ClientCertificateVerifyContent(
            transcriptHash);
        using var publicKey = pki.Leaf.GetRSAPublicKey();
        Assert.True(publicKey!.VerifyData(
            content,
            signature,
            HashAlgorithmName.SHA384,
            RSASignaturePadding.Pss));
    }

    [Fact]
    public void RsaPssCredentialSelectsOnlyPssKeySchemesAndSigns()
    {
        using var pki = RsaPssTestCertificate.Create(
            HashAlgorithmName.SHA384,
            serverAuthentication: false);
        using var credential = new TlsClientCertificate(pki.Certificate, pki.Key);

        var selected = credential.SelectTls13SignatureScheme(
            [SignatureScheme.RsaPssRsaeSha384,
             SignatureScheme.RsaPssPssSha256,
             SignatureScheme.RsaPssPssSha384]);
        var hash = SHA384.HashData("client pss key"u8);
        var signature = credential.SignHash(selected!.Value, hash);

        Assert.Equal(SignatureScheme.RsaPssPssSha384, selected);
        Assert.True(pki.Key.VerifyHash(
            hash,
            signature,
            HashAlgorithmName.SHA384,
            RSASignaturePadding.Pss));

        credential.Dispose();
        var callerOwnedSignature = pki.Key.SignData(
            "still caller owned"u8,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pss);
        Assert.NotEmpty(callerOwnedSignature);
    }

    [Theory]
    [InlineData(256, SignatureScheme.EcdsaSecp256r1Sha256)]
    [InlineData(384, SignatureScheme.EcdsaSecp384r1Sha384)]
    [InlineData(521, SignatureScheme.EcdsaSecp521r1Sha512)]
    public void EcdsaCredentialRequiresTheExactCurveScheme(
        int keySize,
        SignatureScheme expected)
    {
        using var pki = TestPki.Create(
            ecdsaLeaf: true,
            ecdsaKeySize: keySize,
            serverAuthenticationEku: false);
        using var leafWithKey = pki.Leaf.CopyWithPrivateKey((ECDsa)pki.LeafKey);
        using var credential = new TlsClientCertificate(leafWithKey);

        var selected = credential.SelectTls13SignatureScheme(
            [SignatureScheme.EcdsaSecp256r1Sha256,
             SignatureScheme.EcdsaSecp384r1Sha384,
             SignatureScheme.EcdsaSecp521r1Sha512]);

        Assert.Equal(expected, selected);
    }

    [Fact]
    public void Tls12RsaPkcs1CertificateVerifySignsTheRequestedTranscriptHash()
    {
        using var pki = TestPki.Create(serverAuthenticationEku: false);
        using var leafWithKey = pki.Leaf.CopyWithPrivateKey((RSA)pki.LeafKey);
        using var credential = new TlsClientCertificate(leafWithKey);
        var scheme = credential.SelectTls12SignatureScheme(
            [SignatureScheme.RsaPkcs1Sha512],
            [1]);
        var hash = SHA512.HashData("tls12 transcript"u8);

        var encoded = ClientAuthenticationMessages.CreateTls12CertificateVerify(
            credential,
            scheme!.Value,
            hash);

        var body = new TlsBinaryReader(encoded.AsSpan(4));
        Assert.Equal((ushort)SignatureScheme.RsaPkcs1Sha512, body.ReadUInt16());
        var signature = body.ReadVector16().ToArray();
        body.EnsureEnd("TLS 1.2 test CertificateVerify");
        using var publicKey = pki.Leaf.GetRSAPublicKey();
        Assert.True(publicKey!.VerifyHash(
            hash,
            signature,
            HashAlgorithmName.SHA512,
            RSASignaturePadding.Pkcs1));
    }

    [Fact]
    public void IncompatibleRequestProducesAnEmptyCertificateResponse()
    {
        using var pki = TestPki.Create(serverAuthenticationEku: false);
        using var leafWithKey = pki.Leaf.CopyWithPrivateKey((RSA)pki.LeafKey);
        using var credential = new TlsClientCertificate(leafWithKey);

        Assert.Null(credential.SelectTls13SignatureScheme(
            [SignatureScheme.EcdsaSecp256r1Sha256]));
        Assert.Null(credential.SelectTls12SignatureScheme(
            [SignatureScheme.RsaPssRsaeSha256],
            [64]));

        Assert.Equal(
            new byte[] { 11, 0, 0, 4, 0, 0, 0, 0 },
            ClientAuthenticationMessages.CreateTls13Certificate(
                requestContext: [],
                credential: null,
                TlsLimits.Default));
        Assert.Equal(
            new byte[] { 11, 0, 0, 3, 0, 0, 0 },
            ClientAuthenticationMessages.CreateTls12Certificate(
                credential: null,
                TlsLimits.Default));
    }

    [Fact]
    public void WrongEkuDuplicateChainExpiredAndDisposedCredentialsAreRejected()
    {
        using (var serverPki = TestPki.Create(serverAuthenticationEku: true))
        using (var serverLeafWithKey = serverPki.Leaf.CopyWithPrivateKey(
            (RSA)serverPki.LeafKey))
        {
            Assert.Throws<ArgumentException>(() =>
                new TlsClientCertificate(serverLeafWithKey));
        }

        using (var pki = TestPki.Create(serverAuthenticationEku: false))
        using (var leafWithKey = pki.Leaf.CopyWithPrivateKey((RSA)pki.LeafKey))
        {
            Assert.Throws<ArgumentException>(() =>
                new TlsClientCertificate(leafWithKey, [pki.Root, pki.Root]));

            var credential = new TlsClientCertificate(leafWithKey);
            credential.Dispose();
            Assert.Throws<ObjectDisposedException>(() =>
                credential.SelectTls13SignatureScheme(
                    [SignatureScheme.RsaPssRsaeSha256]));
        }

        using var expiredPki = TestPki.Create(
            serverAuthenticationEku: false,
            notBefore: DateTimeOffset.UtcNow.AddDays(-3),
            notAfter: DateTimeOffset.UtcNow.AddDays(-2));
        using var expiredLeafWithKey = expiredPki.Leaf.CopyWithPrivateKey(
            (RSA)expiredPki.LeafKey);
        using var expiredCredential = new TlsClientCertificate(expiredLeafWithKey);
        Assert.Equal(
            TlsAlertDescription.CertificateExpired,
            Assert.Throws<TlsProtocolException>(() =>
                expiredCredential.SelectTls13SignatureScheme(
                    [SignatureScheme.RsaPssRsaeSha256])).Alert);
    }

    [Fact]
    public void CertificateListLimitsAreEnforcedBeforeEncoding()
    {
        using var pki = TestPki.Create(serverAuthenticationEku: false);
        using var leafWithKey = pki.Leaf.CopyWithPrivateKey((RSA)pki.LeafKey);
        using var credential = new TlsClientCertificate(leafWithKey, [pki.Root]);
        var limits = new TlsLimits
        {
            MaxCertificateCount = 1,
            MaxCertificateListSize = 1024 * 1024,
            MaxHandshakeMessageSize = 2 * 1024 * 1024,
        };

        Assert.Equal(
            TlsAlertDescription.InternalError,
            Assert.Throws<TlsProtocolException>(() =>
                ClientAuthenticationMessages.CreateTls13Certificate(
                    [],
                    credential,
                    limits)).Alert);
    }

    [Fact]
    public async Task AsyncSignerIsSpkiBoundAndProducesVerifiedCertificateVerify()
    {
        using var pki = TestPki.Create(serverAuthenticationEku: false);
        var signer = new TestAsyncRsaSigner(
            (RSA)pki.LeafKey,
            [SignatureScheme.RsaPssRsaeSha256]);
        using var credential = new TlsClientCertificate(pki.Leaf, signer, [pki.Root]);
        var transcriptHash = SHA256.HashData("async signer transcript"u8);

        var encoded = await ClientAuthenticationMessages.CreateTls13CertificateVerifyAsync(
            credential,
            SignatureScheme.RsaPssRsaeSha256,
            transcriptHash,
            CancellationToken.None);

        var body = new TlsBinaryReader(encoded.AsSpan(4));
        Assert.Equal((ushort)SignatureScheme.RsaPssRsaeSha256, body.ReadUInt16());
        var signature = body.ReadVector16().ToArray();
        body.EnsureEnd("async CertificateVerify");
        var content = ClientAuthenticationMessages.BuildTls13ClientCertificateVerifyContent(
            transcriptHash);
        using var publicKey = pki.Leaf.GetRSAPublicKey();
        Assert.True(publicKey!.VerifyData(
            content,
            signature,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pss));
        Assert.Equal(1, signer.SignCount);

        using var wrongKey = RSA.Create(2048);
        Assert.Throws<ArgumentException>(() => new TlsClientCertificate(
            pki.Leaf,
            new TestAsyncRsaSigner(wrongKey)));
        CryptographicOperations.ZeroMemory(transcriptHash);
        CryptographicOperations.ZeroMemory(encoded);
        CryptographicOperations.ZeroMemory(signature);
        CryptographicOperations.ZeroMemory(content);
    }

    [Fact]
    public async Task AsyncSignerHonorsCancellationBeforePrivateKeyOperation()
    {
        using var pki = TestPki.Create(serverAuthenticationEku: false);
        var signer = new TestAsyncRsaSigner(
            (RSA)pki.LeafKey,
            [SignatureScheme.RsaPssRsaeSha256]);
        using var credential = new TlsClientCertificate(pki.Leaf, signer);
        using var cancellation = new CancellationTokenSource();
        cancellation.Cancel();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(async () =>
            await credential.SignHashAsync(
                SignatureScheme.RsaPssRsaeSha256,
                new byte[32],
                cancellation.Token));
        Assert.Equal(0, signer.SignCount);
    }

    [Fact]
    public void StaticCredentialAndDynamicSelectorAreMutuallyExclusive()
    {
        using var pki = TestPki.Create(serverAuthenticationEku: false);
        using var leafWithKey = pki.Leaf.CopyWithPrivateKey((RSA)pki.LeafKey);
        using var credential = new TlsClientCertificate(leafWithKey);

        Assert.Throws<ArgumentException>(() => new CustomTlsClient(
            new CustomTlsClientOptions
            {
                ClientCertificate = credential,
                ClientCertificateSelector = (_, _) => ValueTask.FromResult<TlsClientCertificate?>(
                    credential),
            }));
    }
}
