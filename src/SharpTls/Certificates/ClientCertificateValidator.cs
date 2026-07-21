using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using SharpTls.IO;
using SharpTls.Handshake;
using SharpTls.Protocol;

namespace SharpTls.Certificates;

internal static class ClientCertificateValidator
{
    private const string ClientAuthenticationOid = "1.3.6.1.5.5.7.3.2";

    internal static void ValidateChain(
        ClientCertificateMessage message,
        CertificateValidationPolicy policy)
    {
        if (message.Leaf is null)
        {
            throw new TlsProtocolException(
                TlsAlertDescription.CertificateRequired,
                "Client certificate was required but absent.");
        }
        using var chain = new X509Chain();
        chain.ChainPolicy.RevocationMode = policy.RevocationMode;
        chain.ChainPolicy.RevocationFlag = policy.RevocationFlag;
        chain.ChainPolicy.VerificationFlags = X509VerificationFlags.NoFlag;
        chain.ChainPolicy.DisableCertificateDownloads = policy.DisableCertificateDownloads;
        chain.ChainPolicy.UrlRetrievalTimeout = policy.UrlRetrievalTimeout;
        chain.ChainPolicy.ApplicationPolicy.Add(new Oid(ClientAuthenticationOid));
        for (var index = 1; index < message.Certificates.Count; index++)
        {
            chain.ChainPolicy.ExtraStore.Add(message.Certificates[index]);
        }
        if (policy.CustomTrustRoots is { Count: > 0 } roots)
        {
            chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
            chain.ChainPolicy.CustomTrustStore.AddRange(roots);
        }
        if (!CertificateChainBuilder.Build(chain, message.Leaf, policy))
        {
            if (chain.ChainStatus.Any(status =>
                (status.Status & X509ChainStatusFlags.Revoked) != 0))
            {
                throw new TlsProtocolException(
                    TlsAlertDescription.CertificateRevoked,
                    "Client certificate is revoked.");
            }
            if (chain.ChainStatus.Any(status =>
                (status.Status & X509ChainStatusFlags.NotTimeValid) != 0))
            {
                throw new TlsProtocolException(
                    TlsAlertDescription.CertificateExpired,
                    "Client certificate is outside its validity interval.");
            }
            if (chain.ChainStatus.Any(status => (status.Status &
                (X509ChainStatusFlags.UntrustedRoot |
                 X509ChainStatusFlags.PartialChain)) != 0))
            {
                throw new TlsProtocolException(
                    TlsAlertDescription.UnknownCa,
                    "Client certificate chain is not trusted.");
            }
            throw new TlsProtocolException(
                TlsAlertDescription.BadCertificate,
                "Client certificate chain validation failed.");
        }
    }

    internal static SignatureScheme VerifyCertificateVerify(
        ReadOnlySpan<byte> body,
        X509Certificate2 leaf,
        IReadOnlyList<SignatureScheme> offeredSchemes,
        ReadOnlySpan<byte> transcriptHash)
    {
        var reader = new TlsBinaryReader(body);
        var value = reader.ReadUInt16();
        if (!Enum.IsDefined(typeof(SignatureScheme), value))
        {
            throw TlsProtocolException.Illegal(
                "Client CertificateVerify selected an unknown signature scheme.");
        }
        var scheme = (SignatureScheme)value;
        if (!offeredSchemes.Contains(scheme))
        {
            throw TlsProtocolException.Illegal(
                "Client CertificateVerify selected an unoffered signature scheme.");
        }
        var signature = reader.ReadVector16();
        if (signature.IsEmpty)
        {
            throw TlsProtocolException.Decode("Client CertificateVerify signature is empty.");
        }
        reader.EnsureEnd("client CertificateVerify");
        var content = ClientAuthenticationMessages.BuildTls13ClientCertificateVerifyContent(
            transcriptHash);
        try
        {
            var valid = scheme switch
            {
                SignatureScheme.RsaPssRsaeSha256 => VerifyRsa(
                    leaf, content, signature, HashAlgorithmName.SHA256, scheme),
                SignatureScheme.RsaPssRsaeSha384 => VerifyRsa(
                    leaf, content, signature, HashAlgorithmName.SHA384, scheme),
                SignatureScheme.RsaPssRsaeSha512 => VerifyRsa(
                    leaf, content, signature, HashAlgorithmName.SHA512, scheme),
                SignatureScheme.RsaPssPssSha256 => VerifyRsa(
                    leaf, content, signature, HashAlgorithmName.SHA256, scheme),
                SignatureScheme.RsaPssPssSha384 => VerifyRsa(
                    leaf, content, signature, HashAlgorithmName.SHA384, scheme),
                SignatureScheme.RsaPssPssSha512 => VerifyRsa(
                    leaf, content, signature, HashAlgorithmName.SHA512, scheme),
                SignatureScheme.EcdsaSecp256r1Sha256 => VerifyEcdsa(
                    leaf, content, signature, HashAlgorithmName.SHA256, 256),
                SignatureScheme.EcdsaSecp384r1Sha384 => VerifyEcdsa(
                    leaf, content, signature, HashAlgorithmName.SHA384, 384),
                SignatureScheme.EcdsaSecp521r1Sha512 => VerifyEcdsa(
                    leaf, content, signature, HashAlgorithmName.SHA512, 521),
                _ => false,
            };
            if (!valid)
            {
                throw new TlsProtocolException(
                    TlsAlertDescription.DecryptError,
                    "Client CertificateVerify signature is invalid.");
            }
            return scheme;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(content);
        }
    }

    internal static SignatureScheme VerifyTls12CertificateVerify(
        ReadOnlySpan<byte> body,
        X509Certificate2 leaf,
        IReadOnlyList<SignatureScheme> offeredSchemes,
        Func<HashAlgorithmName, byte[]> transcriptHashFactory)
    {
        var reader = new TlsBinaryReader(body);
        var value = reader.ReadUInt16();
        if (!Enum.IsDefined(typeof(SignatureScheme), value))
        {
            throw TlsProtocolException.Illegal(
                "TLS 1.2 client CertificateVerify selected an unknown scheme.");
        }
        var scheme = (SignatureScheme)value;
        if (!offeredSchemes.Contains(scheme))
        {
            throw TlsProtocolException.Illegal(
                "TLS 1.2 client CertificateVerify selected an unoffered scheme.");
        }
        var signature = reader.ReadVector16();
        if (signature.IsEmpty)
        {
            throw TlsProtocolException.Decode(
                "TLS 1.2 client CertificateVerify signature is empty.");
        }
        reader.EnsureEnd("TLS 1.2 client CertificateVerify");
        var hashAlgorithm = TlsClientCertificate.GetHashAlgorithm(scheme);
        var transcriptHash = transcriptHashFactory(hashAlgorithm);
        try
        {
            var valid = scheme switch
            {
                SignatureScheme.RsaPssRsaeSha256 or
                SignatureScheme.RsaPssRsaeSha384 or
                SignatureScheme.RsaPssRsaeSha512 or
                SignatureScheme.RsaPssPssSha256 or
                SignatureScheme.RsaPssPssSha384 or
                SignatureScheme.RsaPssPssSha512 => VerifyRsaHash(
                    leaf,
                    transcriptHash,
                    signature,
                    hashAlgorithm,
                    scheme,
                    RSASignaturePadding.Pss),
                SignatureScheme.RsaPkcs1Sha256 or
                SignatureScheme.RsaPkcs1Sha384 or
                SignatureScheme.RsaPkcs1Sha512 => VerifyRsaHash(
                    leaf,
                    transcriptHash,
                    signature,
                    hashAlgorithm,
                    scheme,
                    RSASignaturePadding.Pkcs1),
                SignatureScheme.EcdsaSecp256r1Sha256 => VerifyEcdsaHash(
                    leaf, transcriptHash, signature, 256),
                SignatureScheme.EcdsaSecp384r1Sha384 => VerifyEcdsaHash(
                    leaf, transcriptHash, signature, 384),
                SignatureScheme.EcdsaSecp521r1Sha512 => VerifyEcdsaHash(
                    leaf, transcriptHash, signature, 521),
                _ => false,
            };
            if (!valid)
            {
                throw new TlsProtocolException(
                    TlsAlertDescription.DecryptError,
                    "TLS 1.2 client CertificateVerify signature is invalid.");
            }
            return scheme;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(transcriptHash);
        }
    }

    private static bool VerifyRsa(
        X509Certificate2 certificate,
        ReadOnlySpan<byte> content,
        ReadOnlySpan<byte> signature,
        HashAlgorithmName hash,
        SignatureScheme scheme)
    {
        if (!RsaSignatureScheme.IsCompatible(certificate, scheme))
        {
            return false;
        }
        try
        {
            using var rsa = RsaSignatureScheme.CreatePublicKey(certificate);
            return rsa?.VerifyData(content, signature, hash, RSASignaturePadding.Pss) == true;
        }
        catch (CryptographicException)
        {
            return false;
        }
    }

    private static bool VerifyRsaHash(
        X509Certificate2 certificate,
        ReadOnlySpan<byte> hash,
        ReadOnlySpan<byte> signature,
        HashAlgorithmName hashAlgorithm,
        SignatureScheme scheme,
        RSASignaturePadding padding)
    {
        if (!RsaSignatureScheme.IsCompatible(certificate, scheme))
        {
            return false;
        }
        try
        {
            using var rsa = RsaSignatureScheme.CreatePublicKey(certificate);
            return rsa?.VerifyHash(hash, signature, hashAlgorithm, padding) == true;
        }
        catch (CryptographicException)
        {
            return false;
        }
    }

    private static bool VerifyEcdsaHash(
        X509Certificate2 certificate,
        ReadOnlySpan<byte> hash,
        ReadOnlySpan<byte> signature,
        int keySize)
    {
        using var ecdsa = certificate.GetECDsaPublicKey();
        return ecdsa?.KeySize == keySize && ecdsa.VerifyHash(
            hash,
            signature,
            DSASignatureFormat.Rfc3279DerSequence);
    }

    private static bool VerifyEcdsa(
        X509Certificate2 certificate,
        ReadOnlySpan<byte> content,
        ReadOnlySpan<byte> signature,
        HashAlgorithmName hash,
        int keySize)
    {
        using var ecdsa = certificate.GetECDsaPublicKey();
        return ecdsa?.KeySize == keySize && ecdsa.VerifyData(
            content,
            signature,
            hash,
            DSASignatureFormat.Rfc3279DerSequence);
    }
}
