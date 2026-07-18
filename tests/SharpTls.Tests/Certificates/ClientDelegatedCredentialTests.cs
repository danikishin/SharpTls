using System.Security.Cryptography;
using SharpTls.Certificates;
using SharpTls.Handshake;
using SharpTls.IO;
using SharpTls.Protocol;

namespace SharpTls.Tests.Certificates;

public sealed class ClientDelegatedCredentialTests
{
    [Fact]
    public async Task ValidCredentialIsSelectedEncodedAndSignsWithDelegatedKey()
    {
        using var pki = TestPki.Create(
            serverAuthenticationEku: false,
            delegationUsage: true);
        using var delegatedKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var signer = new TestAsyncEcdsaSigner(delegatedKey);
        var encodedCredential = EncodeClientDelegatedCredential(
            pki,
            delegatedKey.ExportSubjectPublicKeyInfo(),
            TimeSpan.FromDays(1));
        using var delegatedCredential = new TlsClientDelegatedCredential(
            encodedCredential,
            signer);
        using var credential = new TlsClientCertificate(
            pki.Leaf,
            new TestAsyncRsaSigner((RSA)pki.LeafKey),
            [pki.Root]);
        credential.AttachDelegatedCredential(delegatedCredential);

        var selected = credential.SelectTls13Authentication(
            [SignatureScheme.RsaPssRsaeSha256],
            [SignatureScheme.EcdsaSecp256r1Sha256]);

        Assert.NotNull(selected);
        Assert.Equal(
            SignatureScheme.EcdsaSecp256r1Sha256,
            selected.Value.SignatureScheme);
        Assert.Same(delegatedCredential, selected.Value.DelegatedCredential);
        Assert.NotNull(delegatedCredential.ExpiresAt);

        var certificate = ClientAuthenticationMessages.CreateTls13Certificate(
            [1, 2, 3],
            credential,
            TlsLimits.Default,
            selected.Value.DelegatedCredential);
        AssertClientCertificateEncoding(
            certificate,
            [1, 2, 3],
            pki.Leaf.RawData,
            pki.Root.RawData,
            encodedCredential);

        var transcriptHash = SHA256.HashData("client delegated transcript"u8);
        var certificateVerify = await ClientAuthenticationMessages
            .CreateTls13CertificateVerifyAsync(
                credential,
                selected.Value.SignatureScheme,
                transcriptHash,
                CancellationToken.None,
                selected.Value.DelegatedCredential);
        var body = new TlsBinaryReader(certificateVerify.AsSpan(4));
        Assert.Equal(
            (ushort)SignatureScheme.EcdsaSecp256r1Sha256,
            body.ReadUInt16());
        var signature = body.ReadVector16().ToArray();
        body.EnsureEnd("delegated client CertificateVerify");
        var content = ClientAuthenticationMessages
            .BuildTls13ClientCertificateVerifyContent(transcriptHash);
        Assert.True(delegatedKey.VerifyData(
            content,
            signature,
            HashAlgorithmName.SHA256,
            DSASignatureFormat.Rfc3279DerSequence));
        Assert.Equal(1, signer.SignCount);
    }

    [Fact]
    public void CertificateRequestMustAuthorizeBothCredentialAlgorithms()
    {
        using var pki = TestPki.Create(
            serverAuthenticationEku: false,
            delegationUsage: true);
        using var delegatedKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var encoded = EncodeClientDelegatedCredential(
            pki,
            delegatedKey.ExportSubjectPublicKeyInfo(),
            TimeSpan.FromDays(1));
        using var delegated = new TlsClientDelegatedCredential(
            encoded,
            new TestAsyncEcdsaSigner(delegatedKey));
        using var credential = new TlsClientCertificate(
            pki.Leaf,
            new TestAsyncRsaSigner((RSA)pki.LeafKey));
        credential.AttachDelegatedCredential(delegated);

        var missingDelegationAlgorithm = credential.SelectTls13Authentication(
            [SignatureScheme.EcdsaSecp256r1Sha256],
            [SignatureScheme.EcdsaSecp256r1Sha256]);
        var missingCredentialAlgorithm = credential.SelectTls13Authentication(
            [SignatureScheme.RsaPssRsaeSha256],
            null);

        Assert.Null(missingDelegationAlgorithm);
        Assert.Equal(
            SignatureScheme.RsaPssRsaeSha256,
            missingCredentialAlgorithm!.Value.SignatureScheme);
        Assert.Null(missingCredentialAlgorithm.Value.DelegatedCredential);
    }

    [Fact]
    public void InvalidBindingLifetimeSignerAndDuplicateAttachmentFailClosed()
    {
        using var pki = TestPki.Create(
            serverAuthenticationEku: false,
            delegationUsage: true);
        using var delegatedKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var wrongKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var encoded = EncodeClientDelegatedCredential(
            pki,
            delegatedKey.ExportSubjectPublicKeyInfo(),
            TimeSpan.FromDays(1));

        Assert.Throws<ArgumentException>(() => new TlsClientDelegatedCredential(
            encoded,
            new TestAsyncEcdsaSigner(wrongKey)));

        var tampered = (byte[])encoded.Clone();
        tampered[^1] ^= 1;
        using (var invalid = new TlsClientDelegatedCredential(
            tampered,
            new TestAsyncEcdsaSigner(delegatedKey)))
        using (var credential = new TlsClientCertificate(
            pki.Leaf,
            new TestAsyncRsaSigner((RSA)pki.LeafKey)))
        {
            Assert.Throws<CryptographicException>(() =>
                credential.AttachDelegatedCredential(invalid));
        }

        using var ordinaryPki = TestPki.Create(serverAuthenticationEku: false);
        var ordinaryEncoded = EncodeClientDelegatedCredential(
            ordinaryPki,
            delegatedKey.ExportSubjectPublicKeyInfo(),
            TimeSpan.FromDays(1));
        using (var ordinaryDelegated = new TlsClientDelegatedCredential(
            ordinaryEncoded,
            new TestAsyncEcdsaSigner(delegatedKey)))
        using (var ordinaryCredential = new TlsClientCertificate(
            ordinaryPki.Leaf,
            new TestAsyncRsaSigner((RSA)ordinaryPki.LeafKey)))
        {
            Assert.Equal(
                TlsAlertDescription.IllegalParameter,
                Assert.Throws<TlsProtocolException>(() =>
                    ordinaryCredential.AttachDelegatedCredential(ordinaryDelegated)).Alert);
        }

        var longEncoded = EncodeClientDelegatedCredential(
            pki,
            delegatedKey.ExportSubjectPublicKeyInfo(),
            TimeSpan.FromDays(8));
        using (var tooLong = new TlsClientDelegatedCredential(
            longEncoded,
            new TestAsyncEcdsaSigner(delegatedKey)))
        using (var credential = new TlsClientCertificate(
            pki.Leaf,
            new TestAsyncRsaSigner((RSA)pki.LeafKey)))
        {
            Assert.Throws<ArgumentException>(() =>
                credential.AttachDelegatedCredential(tooLong));
        }

        using var valid = new TlsClientDelegatedCredential(
            encoded,
            new TestAsyncEcdsaSigner(delegatedKey));
        using var target = new TlsClientCertificate(
            pki.Leaf,
            new TestAsyncRsaSigner((RSA)pki.LeafKey));
        target.AttachDelegatedCredential(valid);
        Assert.Throws<InvalidOperationException>(() =>
            target.AttachDelegatedCredential(valid));
    }

    [Fact]
    public void MalformedAndCurveMismatchedCredentialsAreRejectedBeforeAttachment()
    {
        using var delegatedKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var signer = new TestAsyncEcdsaSigner(delegatedKey);
        Assert.Throws<ArgumentOutOfRangeException>(() =>
            new TlsClientDelegatedCredential([], signer));

        var truncated = new TlsBinaryWriter();
        truncated.WriteUInt32(1);
        truncated.WriteUInt16((ushort)SignatureScheme.EcdsaSecp256r1Sha256);
        Assert.Throws<ArgumentException>(() =>
            new TlsClientDelegatedCredential(truncated.WrittenSpan, signer));

        using var pki = TestPki.Create(
            serverAuthenticationEku: false,
            delegationUsage: true);
        using var p384Key = ECDsa.Create(ECCurve.NamedCurves.nistP384);
        var wrongCurve = EncodeClientDelegatedCredential(
            pki,
            p384Key.ExportSubjectPublicKeyInfo(),
            TimeSpan.FromDays(1));
        Assert.Throws<ArgumentException>(() =>
            new TlsClientDelegatedCredential(
                wrongCurve,
                new TestAsyncEcdsaSigner(
                    p384Key,
                    [SignatureScheme.EcdsaSecp256r1Sha256])));
    }

    [Fact]
    public async Task DisposedCredentialCannotBeSelectedOrUsedForSigning()
    {
        using var pki = TestPki.Create(
            serverAuthenticationEku: false,
            delegationUsage: true);
        using var delegatedKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var encoded = EncodeClientDelegatedCredential(
            pki,
            delegatedKey.ExportSubjectPublicKeyInfo(),
            TimeSpan.FromDays(1));
        var delegated = new TlsClientDelegatedCredential(
            encoded,
            new TestAsyncEcdsaSigner(delegatedKey));
        using var credential = new TlsClientCertificate(
            pki.Leaf,
            new TestAsyncRsaSigner((RSA)pki.LeafKey));
        credential.AttachDelegatedCredential(delegated);
        delegated.Dispose();

        Assert.Throws<ObjectDisposedException>(() =>
            credential.SelectTls13Authentication(
                [SignatureScheme.RsaPssRsaeSha256],
                [SignatureScheme.EcdsaSecp256r1Sha256]));
        await Assert.ThrowsAsync<ObjectDisposedException>(async () =>
            await delegated.SignHashAsync(new byte[32], CancellationToken.None));
    }

    internal static byte[] EncodeClientDelegatedCredential(
        TestPki pki,
        ReadOnlySpan<byte> subjectPublicKeyInfo,
        TimeSpan expiresAfter)
    {
        var notBefore = new DateTimeOffset(pki.Leaf.NotBefore.ToUniversalTime());
        var expiry = DateTimeOffset.UtcNow.Add(expiresAfter);
        var validTime = checked((uint)Math.Ceiling((expiry - notBefore).TotalSeconds));
        var unsigned = new TlsBinaryWriter();
        unsigned.WriteUInt32(validTime);
        unsigned.WriteUInt16((ushort)SignatureScheme.EcdsaSecp256r1Sha256);
        unsigned.WriteVector24(subjectPublicKeyInfo);
        unsigned.WriteUInt16((ushort)SignatureScheme.RsaPssRsaeSha256);
        var signedContent = Tls13DelegatedCredentialParser.BuildClientSignedContent(
            pki.Leaf.RawData,
            unsigned.WrittenSpan);
        var signature = ((RSA)pki.LeafKey).SignData(
            signedContent,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pss);
        try
        {
            var encoded = new TlsBinaryWriter();
            encoded.WriteBytes(unsigned.WrittenSpan);
            encoded.WriteVector16(signature);
            return encoded.ToArray();
        }
        finally
        {
            CryptographicOperations.ZeroMemory(signedContent);
            CryptographicOperations.ZeroMemory(signature);
        }
    }

    private static void AssertClientCertificateEncoding(
        ReadOnlySpan<byte> encoded,
        ReadOnlySpan<byte> expectedContext,
        ReadOnlySpan<byte> expectedLeaf,
        ReadOnlySpan<byte> expectedIssuer,
        ReadOnlySpan<byte> expectedDelegatedCredential)
    {
        var body = new TlsBinaryReader(encoded[4..]);
        Assert.True(body.ReadVector8().SequenceEqual(expectedContext));
        var entries = new TlsBinaryReader(body.ReadVector24());
        body.EnsureEnd("client Certificate");
        Assert.True(entries.ReadVector24().SequenceEqual(expectedLeaf));
        var leafExtensions = new TlsBinaryReader(entries.ReadVector16());
        Assert.Equal(
            (ushort)TlsExtensionType.DelegatedCredential,
            leafExtensions.ReadUInt16());
        Assert.True(leafExtensions.ReadVector16().SequenceEqual(expectedDelegatedCredential));
        leafExtensions.EnsureEnd("client leaf extensions");
        Assert.True(entries.ReadVector24().SequenceEqual(expectedIssuer));
        Assert.Empty(entries.ReadVector16().ToArray());
        Assert.True(entries.End);
    }
}
