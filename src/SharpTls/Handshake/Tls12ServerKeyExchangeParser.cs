using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using SharpTls.Certificates;
using SharpTls.Cryptography;
using SharpTls.IO;
using SharpTls.Protocol;

namespace SharpTls.Handshake;

internal sealed record Tls12ServerKeyExchange(
    NamedGroup SelectedGroup,
    byte[] PeerPublicKey,
    SignatureScheme SignatureScheme,
    byte[] Signature,
    byte[] SignedParameters);

internal static class Tls12ServerKeyExchangeParser
{
    private const byte NamedCurveType = 3;
    private const int MaximumSignatureLength = 16 * 1024;

    internal static Tls12ServerKeyExchange Parse(
        ReadOnlySpan<byte> body,
        ClientHelloConfiguration offer)
    {
        ArgumentNullException.ThrowIfNull(offer);
        var reader = new TlsBinaryReader(body);
        var curveType = reader.ReadUInt8();
        if (curveType != NamedCurveType)
        {
            throw TlsProtocolException.Illegal(
                $"TLS 1.2 ServerKeyExchange selected unsupported EC curve type {curveType}.");
        }

        var groupValue = reader.ReadUInt16();
        var group = ParseGroup(groupValue);
        if (!offer.SupportedGroups.Contains(group))
        {
            throw TlsProtocolException.Illegal(
                "TLS 1.2 ServerKeyExchange selected an unoffered group.");
        }

        var peerPublicKey = reader.ReadVector8().ToArray();
        ValidatePublicKeyEncoding(group, peerPublicKey);
        var signedParameters = new TlsBinaryWriter(4 + peerPublicKey.Length);
        signedParameters.WriteUInt8(curveType);
        signedParameters.WriteUInt16(groupValue);
        signedParameters.WriteVector8(peerPublicKey);

        var schemeValue = reader.ReadUInt16();
        if (!Enum.IsDefined(typeof(SignatureScheme), schemeValue))
        {
            throw TlsProtocolException.Illegal(
                $"TLS 1.2 ServerKeyExchange selected unknown signature scheme 0x{schemeValue:X4}.");
        }
        var scheme = (SignatureScheme)schemeValue;
        if (!offer.SignatureAlgorithms.Contains(scheme))
        {
            throw TlsProtocolException.Illegal(
                "TLS 1.2 ServerKeyExchange selected an unoffered signature scheme.");
        }
        EnsureSecureSignatureScheme(scheme);

        var signature = reader.ReadVector16(MaximumSignatureLength).ToArray();
        if (signature.Length == 0)
        {
            throw TlsProtocolException.Decode("TLS 1.2 ServerKeyExchange signature is empty.");
        }
        reader.EnsureEnd("TLS 1.2 ServerKeyExchange");

        return new Tls12ServerKeyExchange(
            group,
            peerPublicKey,
            scheme,
            signature,
            signedParameters.ToArray());
    }

    internal static void VerifySignature(
        Tls12ServerKeyExchange serverKeyExchange,
        X509Certificate2 leafCertificate,
        Tls12CipherSuiteInfo suite,
        ReadOnlySpan<byte> clientRandom,
        ReadOnlySpan<byte> serverRandom)
    {
        ArgumentNullException.ThrowIfNull(serverKeyExchange);
        ArgumentNullException.ThrowIfNull(leafCertificate);
        ArgumentNullException.ThrowIfNull(suite);
        if (clientRandom.Length != TlsConstants.RandomLength ||
            serverRandom.Length != TlsConstants.RandomLength)
        {
            throw new ArgumentException("TLS random values must contain exactly 32 bytes.");
        }

        var signedContent = new byte[checked(
            (2 * TlsConstants.RandomLength) + serverKeyExchange.SignedParameters.Length)];
        clientRandom.CopyTo(signedContent);
        serverRandom.CopyTo(signedContent.AsSpan(TlsConstants.RandomLength));
        serverKeyExchange.SignedParameters.CopyTo(
            signedContent,
            2 * TlsConstants.RandomLength);

        try
        {
            var valid = suite.CertificateKeyType switch
            {
                Tls12CertificateKeyType.Rsa => VerifyRsa(
                    leafCertificate,
                    serverKeyExchange.SignatureScheme,
                    signedContent,
                    serverKeyExchange.Signature),
                Tls12CertificateKeyType.Ecdsa => VerifyEcdsa(
                    leafCertificate,
                    serverKeyExchange.SignatureScheme,
                    signedContent,
                    serverKeyExchange.Signature),
                _ => throw new NotSupportedException(),
            };
            if (!valid)
            {
                throw new TlsProtocolException(
                    TlsAlertDescription.DecryptError,
                    "TLS 1.2 ServerKeyExchange signature verification failed.");
            }
        }
        catch (TlsProtocolException)
        {
            throw;
        }
        catch (CryptographicException exception)
        {
            throw new TlsProtocolException(
                TlsAlertDescription.DecryptError,
                "TLS 1.2 ServerKeyExchange signature is malformed or invalid.",
                exception);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(signedContent);
        }
    }

    private static bool VerifyRsa(
        X509Certificate2 certificate,
        SignatureScheme scheme,
        ReadOnlySpan<byte> content,
        ReadOnlySpan<byte> signature)
    {
        var (hash, padding) = scheme switch
        {
            SignatureScheme.RsaPssRsaeSha256 => (HashAlgorithmName.SHA256, RSASignaturePadding.Pss),
            SignatureScheme.RsaPssRsaeSha384 => (HashAlgorithmName.SHA384, RSASignaturePadding.Pss),
            SignatureScheme.RsaPssRsaeSha512 => (HashAlgorithmName.SHA512, RSASignaturePadding.Pss),
            SignatureScheme.RsaPssPssSha256 => (HashAlgorithmName.SHA256, RSASignaturePadding.Pss),
            SignatureScheme.RsaPssPssSha384 => (HashAlgorithmName.SHA384, RSASignaturePadding.Pss),
            SignatureScheme.RsaPssPssSha512 => (HashAlgorithmName.SHA512, RSASignaturePadding.Pss),
            SignatureScheme.RsaPkcs1Sha256 => (HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1),
            SignatureScheme.RsaPkcs1Sha384 => (HashAlgorithmName.SHA384, RSASignaturePadding.Pkcs1),
            SignatureScheme.RsaPkcs1Sha512 => (HashAlgorithmName.SHA512, RSASignaturePadding.Pkcs1),
            _ => throw TlsProtocolException.Illegal(
                "TLS 1.2 ECDHE_RSA suite selected a non-RSA signature scheme."),
        };
        if (!RsaSignatureScheme.IsCompatible(certificate, scheme))
        {
            throw new TlsProtocolException(
                TlsAlertDescription.UnsupportedCertificate,
                "The RSA leaf key OID or RSASSA-PSS parameters do not match the selected scheme.");
        }
        using var rsa = RsaSignatureScheme.CreatePublicKey(certificate) ?? throw new TlsProtocolException(
            TlsAlertDescription.UnsupportedCertificate,
            "TLS 1.2 ECDHE_RSA suite requires an RSA leaf certificate.");
        return rsa.VerifyData(content, signature, hash, padding);
    }

    private static bool VerifyEcdsa(
        X509Certificate2 certificate,
        SignatureScheme scheme,
        ReadOnlySpan<byte> content,
        ReadOnlySpan<byte> signature)
    {
        var hash = scheme switch
        {
            SignatureScheme.EcdsaSecp256r1Sha256 => HashAlgorithmName.SHA256,
            SignatureScheme.EcdsaSecp384r1Sha384 => HashAlgorithmName.SHA384,
            SignatureScheme.EcdsaSecp521r1Sha512 => HashAlgorithmName.SHA512,
            _ => throw TlsProtocolException.Illegal(
                "TLS 1.2 ECDHE_ECDSA suite selected a non-ECDSA signature scheme."),
        };
        using var ecdsa = certificate.GetECDsaPublicKey() ?? throw new TlsProtocolException(
            TlsAlertDescription.UnsupportedCertificate,
            "TLS 1.2 ECDHE_ECDSA suite requires an ECDSA leaf certificate.");
        return ecdsa.VerifyData(
            content,
            signature,
            hash,
            DSASignatureFormat.Rfc3279DerSequence);
    }

    private static NamedGroup ParseGroup(ushort value) => value switch
    {
        (ushort)NamedGroup.X25519 => NamedGroup.X25519,
        (ushort)NamedGroup.Secp256r1 => NamedGroup.Secp256r1,
        (ushort)NamedGroup.Secp384r1 => NamedGroup.Secp384r1,
        (ushort)NamedGroup.Secp521r1 => NamedGroup.Secp521r1,
        _ => throw TlsProtocolException.Illegal(
            $"TLS 1.2 ServerKeyExchange selected unsupported group 0x{value:X4}."),
    };

    private static void ValidatePublicKeyEncoding(NamedGroup group, ReadOnlySpan<byte> publicKey)
    {
        var valid = group switch
        {
            NamedGroup.X25519 => publicKey.Length == 32,
            NamedGroup.Secp256r1 => publicKey.Length == 65 && publicKey[0] == 4,
            NamedGroup.Secp384r1 => publicKey.Length == 97 && publicKey[0] == 4,
            NamedGroup.Secp521r1 => publicKey.Length == 133 && publicKey[0] == 4,
            _ => false,
        };
        if (!valid)
        {
            throw TlsProtocolException.Illegal(
                $"TLS 1.2 ServerKeyExchange contains an invalid {group} public key encoding.");
        }
    }

    private static void EnsureSecureSignatureScheme(SignatureScheme scheme)
    {
        if (scheme is SignatureScheme.RsaPkcs1Sha1 or SignatureScheme.EcdsaSha1)
        {
            throw new TlsProtocolException(
                TlsAlertDescription.HandshakeFailure,
                "SHA-1 ServerKeyExchange signatures are intentionally unsupported.");
        }
    }
}
