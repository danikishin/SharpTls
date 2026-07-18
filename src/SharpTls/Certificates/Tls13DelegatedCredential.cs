using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using SharpTls.IO;
using SharpTls.Protocol;

namespace SharpTls.Certificates;

internal sealed class Tls13DelegatedCredential : IDisposable
{
    private readonly AsymmetricAlgorithm _publicKey;

    internal Tls13DelegatedCredential(
        SignatureScheme certificateVerifyAlgorithm,
        AsymmetricAlgorithm publicKey,
        DateTimeOffset expiresAt)
    {
        CertificateVerifyAlgorithm = certificateVerifyAlgorithm;
        _publicKey = publicKey;
        ExpiresAt = expiresAt;
    }

    internal SignatureScheme CertificateVerifyAlgorithm { get; }

    internal DateTimeOffset ExpiresAt { get; }

    internal bool VerifyCertificateVerify(
        ReadOnlySpan<byte> content,
        ReadOnlySpan<byte> signature) => CertificateVerifyAlgorithm switch
    {
        SignatureScheme.EcdsaSecp256r1Sha256 => VerifyEcdsa(
            content,
            signature,
            HashAlgorithmName.SHA256,
            256),
        SignatureScheme.EcdsaSecp384r1Sha384 => VerifyEcdsa(
            content,
            signature,
            HashAlgorithmName.SHA384,
            384),
        SignatureScheme.EcdsaSecp521r1Sha512 => VerifyEcdsa(
            content,
            signature,
            HashAlgorithmName.SHA512,
            521),
        SignatureScheme.RsaPssPssSha256 => VerifyRsa(
            content,
            signature,
            HashAlgorithmName.SHA256),
        SignatureScheme.RsaPssPssSha384 => VerifyRsa(
            content,
            signature,
            HashAlgorithmName.SHA384),
        SignatureScheme.RsaPssPssSha512 => VerifyRsa(
            content,
            signature,
            HashAlgorithmName.SHA512),
        _ => false,
    };

    public void Dispose() => _publicKey.Dispose();

    private bool VerifyEcdsa(
        ReadOnlySpan<byte> content,
        ReadOnlySpan<byte> signature,
        HashAlgorithmName hashAlgorithm,
        int keySize) => _publicKey is ECDsa ecdsa && ecdsa.KeySize == keySize && ecdsa.VerifyData(
        content,
        signature,
        hashAlgorithm,
        DSASignatureFormat.Rfc3279DerSequence);

    private bool VerifyRsa(
        ReadOnlySpan<byte> content,
        ReadOnlySpan<byte> signature,
        HashAlgorithmName hashAlgorithm) => _publicKey is RSA rsa && rsa.VerifyData(
        content,
        signature,
        hashAlgorithm,
        RSASignaturePadding.Pss);
}

internal static class Tls13DelegatedCredentialParser
{
    private const string DelegationUsageOid = "1.3.6.1.4.1.44363.44";
    private static readonly TimeSpan MaximumLifetime = TimeSpan.FromDays(7);

    internal static Tls13DelegatedCredential ParseAndValidate(
        ReadOnlySpan<byte> data,
        X509Certificate2 delegationCertificate,
        ClientHelloConfiguration offer,
        DateTimeOffset? validationTime = null)
    {
        ArgumentNullException.ThrowIfNull(delegationCertificate);
        ArgumentNullException.ThrowIfNull(offer);
        var acceptedAlgorithms = offer.DelegatedCredentialSignatureAlgorithms ??
            throw TlsProtocolException.Unexpected(
                "Server sent a delegated credential without client support.");

        var reader = new TlsBinaryReader(data);
        var validTime = reader.ReadUInt32();
        var certificateVerifyValue = reader.ReadUInt16();
        var subjectPublicKeyInfo = reader.ReadVector24();
        if (subjectPublicKeyInfo.IsEmpty)
        {
            throw TlsProtocolException.Decode(
                "Delegated credential SubjectPublicKeyInfo is empty.");
        }
        var delegationAlgorithmValue = reader.ReadUInt16();
        var signedFieldsLength = data.Length - reader.Remaining;
        var signature = reader.ReadVector16();
        if (signature.IsEmpty)
        {
            throw TlsProtocolException.Decode("Delegated credential signature is empty.");
        }
        reader.EnsureEnd("delegated credential");

        if (!Enum.IsDefined(typeof(SignatureScheme), certificateVerifyValue) ||
            !Enum.IsDefined(typeof(SignatureScheme), delegationAlgorithmValue))
        {
            throw TlsProtocolException.Illegal(
                "Delegated credential selected an unknown signature scheme.");
        }
        var certificateVerifyAlgorithm = (SignatureScheme)certificateVerifyValue;
        var delegationAlgorithm = (SignatureScheme)delegationAlgorithmValue;
        if (!acceptedAlgorithms.Contains(certificateVerifyAlgorithm) ||
            !IsAllowedCredentialAlgorithm(certificateVerifyAlgorithm))
        {
            throw TlsProtocolException.Illegal(
                "Delegated credential selected an unoffered or forbidden CertificateVerify algorithm.");
        }
        if (!offer.SignatureAlgorithms.Contains(delegationAlgorithm) ||
            !IsAllowedDelegationSignatureAlgorithm(delegationAlgorithm))
        {
            throw TlsProtocolException.Illegal(
                "Delegated credential signature uses an unoffered or forbidden algorithm.");
        }

        ValidateDelegationCertificate(delegationCertificate);
        var now = validationTime ?? DateTimeOffset.UtcNow;
        var notBefore = new DateTimeOffset(
            delegationCertificate.NotBefore.ToUniversalTime());
        var notAfter = new DateTimeOffset(
            delegationCertificate.NotAfter.ToUniversalTime());
        DateTimeOffset expiresAt;
        try
        {
            expiresAt = notBefore.AddSeconds(validTime);
        }
        catch (ArgumentOutOfRangeException exception)
        {
            throw new TlsProtocolException(
                TlsAlertDescription.IllegalParameter,
                "Delegated credential expiry overflows the supported time range.",
                exception);
        }
        if (now > expiresAt || expiresAt > now.Add(MaximumLifetime) || expiresAt >= notAfter)
        {
            throw TlsProtocolException.Illegal(
                "Delegated credential validity is expired, too long, or exceeds its certificate.");
        }

        var delegatedPublicKey = ImportCredentialPublicKey(
            certificateVerifyAlgorithm,
            subjectPublicKeyInfo);
        try
        {
            var signedContent = BuildSignedContent(
                delegationCertificate.RawData,
                data[..signedFieldsLength]);
            try
            {
                if (!VerifyDelegationSignature(
                    delegationCertificate,
                    delegationAlgorithm,
                    signedContent,
                    signature))
                {
                    throw TlsProtocolException.Illegal(
                        "Delegated credential signature is invalid.");
                }
            }
            finally
            {
                CryptographicOperations.ZeroMemory(signedContent);
            }
            return new Tls13DelegatedCredential(
                certificateVerifyAlgorithm,
                delegatedPublicKey,
                expiresAt);
        }
        catch
        {
            delegatedPublicKey.Dispose();
            throw;
        }
    }

    internal static byte[] BuildSignedContent(
        ReadOnlySpan<byte> certificateDer,
        ReadOnlySpan<byte> encodedCredentialAndAlgorithm)
        => BuildSignedContent(
            certificateDer,
            encodedCredentialAndAlgorithm,
            "TLS, server delegated credentials"u8);

    internal static byte[] BuildClientSignedContent(
        ReadOnlySpan<byte> certificateDer,
        ReadOnlySpan<byte> encodedCredentialAndAlgorithm)
        => BuildSignedContent(
            certificateDer,
            encodedCredentialAndAlgorithm,
            "TLS, client delegated credentials"u8);

    private static byte[] BuildSignedContent(
        ReadOnlySpan<byte> certificateDer,
        ReadOnlySpan<byte> encodedCredentialAndAlgorithm,
        ReadOnlySpan<byte> context)
    {
        var result = new byte[
            64 + context.Length + 1 + certificateDer.Length +
            encodedCredentialAndAlgorithm.Length];
        result.AsSpan(0, 64).Fill(0x20);
        var offset = 64;
        context.CopyTo(result.AsSpan(offset));
        offset += context.Length;
        result[offset++] = 0;
        certificateDer.CopyTo(result.AsSpan(offset));
        offset += certificateDer.Length;
        encodedCredentialAndAlgorithm.CopyTo(result.AsSpan(offset));
        return result;
    }

    internal static AsymmetricAlgorithm ImportCredentialPublicKey(
        SignatureScheme algorithm,
        ReadOnlySpan<byte> subjectPublicKeyInfo)
    {
        if (algorithm is SignatureScheme.RsaPssPssSha256 or
            SignatureScheme.RsaPssPssSha384 or
            SignatureScheme.RsaPssPssSha512)
        {
            return RsaSignatureScheme.ImportPssSubjectPublicKeyInfo(
                subjectPublicKeyInfo,
                algorithm) ?? throw TlsProtocolException.Illegal(
                    "Delegated RSASSA-PSS public key or parameters do not match its scheme.");
        }

        var expectedKeySize = algorithm switch
        {
            SignatureScheme.EcdsaSecp256r1Sha256 => 256,
            SignatureScheme.EcdsaSecp384r1Sha384 => 384,
            SignatureScheme.EcdsaSecp521r1Sha512 => 521,
            _ => throw TlsProtocolException.Illegal(
                "Delegated credential key algorithm is not implemented safely."),
        };

        var key = ECDsa.Create();
        try
        {
            key.ImportSubjectPublicKeyInfo(subjectPublicKeyInfo, out var bytesRead);
            if (bytesRead != subjectPublicKeyInfo.Length || key.KeySize != expectedKeySize)
            {
                throw TlsProtocolException.Illegal(
                    "Delegated credential public key does not match its signature scheme.");
            }
            return key;
        }
        catch (TlsProtocolException)
        {
            key.Dispose();
            throw;
        }
        catch (CryptographicException exception)
        {
            key.Dispose();
            throw new TlsProtocolException(
                TlsAlertDescription.IllegalParameter,
                "Delegated credential SubjectPublicKeyInfo is invalid.",
                exception);
        }
    }

    internal static void ValidateDelegationCertificate(X509Certificate2 certificate)
    {
        var delegationUsage = certificate.Extensions
            .Cast<X509Extension>()
            .SingleOrDefault(extension => extension.Oid?.Value == DelegationUsageOid);
        if (delegationUsage is null || delegationUsage.Critical ||
            !delegationUsage.RawData.AsSpan().SequenceEqual(new byte[] { 0x05, 0x00 }))
        {
            throw TlsProtocolException.Illegal(
                "Delegation certificate lacks a valid non-critical DelegationUsage extension.");
        }

        var keyUsage = certificate.Extensions
            .OfType<X509KeyUsageExtension>()
            .SingleOrDefault();
        if (keyUsage is null ||
            (keyUsage.KeyUsages & X509KeyUsageFlags.DigitalSignature) == 0)
        {
            throw TlsProtocolException.Illegal(
                "Delegation certificate does not permit digital signatures.");
        }
    }

    internal static bool VerifyDelegationSignature(
        X509Certificate2 certificate,
        SignatureScheme algorithm,
        ReadOnlySpan<byte> content,
        ReadOnlySpan<byte> signature) => algorithm switch
    {
        SignatureScheme.RsaPssRsaeSha256 => VerifyRsa(
            certificate, algorithm, content, signature, HashAlgorithmName.SHA256),
        SignatureScheme.RsaPssRsaeSha384 => VerifyRsa(
            certificate, algorithm, content, signature, HashAlgorithmName.SHA384),
        SignatureScheme.RsaPssRsaeSha512 => VerifyRsa(
            certificate, algorithm, content, signature, HashAlgorithmName.SHA512),
        SignatureScheme.RsaPssPssSha256 => VerifyRsa(
            certificate, algorithm, content, signature, HashAlgorithmName.SHA256),
        SignatureScheme.RsaPssPssSha384 => VerifyRsa(
            certificate, algorithm, content, signature, HashAlgorithmName.SHA384),
        SignatureScheme.RsaPssPssSha512 => VerifyRsa(
            certificate, algorithm, content, signature, HashAlgorithmName.SHA512),
        SignatureScheme.EcdsaSecp256r1Sha256 => VerifyEcdsa(
            certificate, content, signature, HashAlgorithmName.SHA256, 256),
        SignatureScheme.EcdsaSecp384r1Sha384 => VerifyEcdsa(
            certificate, content, signature, HashAlgorithmName.SHA384, 384),
        SignatureScheme.EcdsaSecp521r1Sha512 => VerifyEcdsa(
            certificate, content, signature, HashAlgorithmName.SHA512, 521),
        _ => false,
    };

    private static bool VerifyRsa(
        X509Certificate2 certificate,
        SignatureScheme scheme,
        ReadOnlySpan<byte> content,
        ReadOnlySpan<byte> signature,
        HashAlgorithmName hashAlgorithm)
    {
        if (!RsaSignatureScheme.IsCompatible(certificate, scheme))
        {
            return false;
        }
        using var rsa = RsaSignatureScheme.CreatePublicKey(certificate);
        return rsa?.VerifyData(content, signature, hashAlgorithm, RSASignaturePadding.Pss) == true;
    }

    private static bool VerifyEcdsa(
        X509Certificate2 certificate,
        ReadOnlySpan<byte> content,
        ReadOnlySpan<byte> signature,
        HashAlgorithmName hashAlgorithm,
        int expectedKeySize)
    {
        using var ecdsa = certificate.GetECDsaPublicKey();
        return ecdsa?.KeySize == expectedKeySize && ecdsa.VerifyData(
            content,
            signature,
            hashAlgorithm,
            DSASignatureFormat.Rfc3279DerSequence);
    }

    internal static bool IsAllowedCredentialAlgorithm(SignatureScheme algorithm) => algorithm is
        SignatureScheme.EcdsaSecp256r1Sha256 or
        SignatureScheme.EcdsaSecp384r1Sha384 or
        SignatureScheme.EcdsaSecp521r1Sha512 or
        SignatureScheme.RsaPssPssSha256 or
        SignatureScheme.RsaPssPssSha384 or
        SignatureScheme.RsaPssPssSha512;

    internal static bool IsAllowedDelegationSignatureAlgorithm(SignatureScheme algorithm) =>
        algorithm is
            SignatureScheme.RsaPssRsaeSha256 or
            SignatureScheme.RsaPssRsaeSha384 or
            SignatureScheme.RsaPssRsaeSha512 or
            SignatureScheme.RsaPssPssSha256 or
            SignatureScheme.RsaPssPssSha384 or
            SignatureScheme.RsaPssPssSha512 or
            SignatureScheme.EcdsaSecp256r1Sha256 or
            SignatureScheme.EcdsaSecp384r1Sha384 or
            SignatureScheme.EcdsaSecp521r1Sha512;
}
