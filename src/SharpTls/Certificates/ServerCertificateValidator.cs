using System.Globalization;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using SharpTls.IO;
using SharpTls.Protocol;

namespace SharpTls.Certificates;

internal static class ServerCertificateValidator
{
    private const string ServerAuthenticationOid = "1.3.6.1.5.5.7.3.1";

    internal static void ValidateChainAndHostname(
        ServerCertificateMessage message,
        string serverName,
        CertificateValidationPolicy policy)
    {
        ArgumentNullException.ThrowIfNull(message);
        ArgumentException.ThrowIfNullOrWhiteSpace(serverName);
        ArgumentNullException.ThrowIfNull(policy);

        using var chain = new X509Chain();
        chain.ChainPolicy.RevocationMode = policy.RevocationMode;
        chain.ChainPolicy.RevocationFlag = policy.RevocationFlag;
        chain.ChainPolicy.VerificationFlags = X509VerificationFlags.NoFlag;
        chain.ChainPolicy.DisableCertificateDownloads = policy.DisableCertificateDownloads;
        chain.ChainPolicy.UrlRetrievalTimeout = policy.UrlRetrievalTimeout;
        chain.ChainPolicy.ApplicationPolicy.Add(new Oid(ServerAuthenticationOid));
        for (var index = 1; index < message.Certificates.Count; index++)
        {
            chain.ChainPolicy.ExtraStore.Add(message.Certificates[index]);
        }

        if (policy.CustomTrustRoots is { Count: > 0 } roots)
        {
            chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
            chain.ChainPolicy.CustomTrustStore.AddRange(roots);
        }

        if (!chain.Build(message.Leaf))
        {
            throw MapChainFailure(chain, policy.CustomTrustRoots);
        }

        var normalizedName = NormalizeReferenceIdentity(serverName);
        if (!message.Leaf.MatchesHostname(
            normalizedName,
            allowWildcards: true,
            allowCommonName: false))
        {
            throw new TlsProtocolException(
                TlsAlertDescription.BadCertificate,
                "Server certificate does not match the reference identity.");
        }
    }

    internal static SignatureScheme ParseAndVerifyCertificateVerify(
        ReadOnlySpan<byte> body,
        X509Certificate2 leaf,
        IReadOnlyList<SignatureScheme> offeredSchemes,
        ReadOnlySpan<byte> transcriptHash,
        Tls13DelegatedCredential? delegatedCredential = null)
    {
        var reader = new TlsBinaryReader(body);
        var schemeValue = reader.ReadUInt16();
        if (!Enum.IsDefined(typeof(SignatureScheme), schemeValue))
        {
            throw new TlsProtocolException(
                TlsAlertDescription.IllegalParameter,
                $"Server selected unsupported signature scheme 0x{schemeValue:X4}.");
        }

        var scheme = (SignatureScheme)schemeValue;
        if (!offeredSchemes.Contains(scheme))
        {
            throw TlsProtocolException.Illegal("Server selected an unoffered signature scheme.");
        }
        var signature = reader.ReadVector16();
        if (signature.IsEmpty)
        {
            throw TlsProtocolException.Decode("CertificateVerify signature is empty.");
        }
        reader.EnsureEnd("CertificateVerify");

        if (delegatedCredential is not null &&
            (scheme != delegatedCredential.CertificateVerifyAlgorithm ||
             DateTimeOffset.UtcNow > delegatedCredential.ExpiresAt))
        {
            throw TlsProtocolException.Illegal(
                "CertificateVerify does not match a valid delegated credential.");
        }

        var content = BuildCertificateVerifyContent(transcriptHash);
        var valid = delegatedCredential?.VerifyCertificateVerify(content, signature) ??
            (scheme switch
        {
            SignatureScheme.RsaPssRsaeSha256 => VerifyRsa(
                leaf,
                content,
                signature,
                HashAlgorithmName.SHA256,
                scheme),
            SignatureScheme.RsaPssRsaeSha384 => VerifyRsa(
                leaf,
                content,
                signature,
                HashAlgorithmName.SHA384,
                scheme),
            SignatureScheme.RsaPssRsaeSha512 => VerifyRsa(
                leaf,
                content,
                signature,
                HashAlgorithmName.SHA512,
                scheme),
            SignatureScheme.RsaPssPssSha256 => VerifyRsa(
                leaf,
                content,
                signature,
                HashAlgorithmName.SHA256,
                scheme),
            SignatureScheme.RsaPssPssSha384 => VerifyRsa(
                leaf,
                content,
                signature,
                HashAlgorithmName.SHA384,
                scheme),
            SignatureScheme.RsaPssPssSha512 => VerifyRsa(
                leaf,
                content,
                signature,
                HashAlgorithmName.SHA512,
                scheme),
            SignatureScheme.EcdsaSecp256r1Sha256 => VerifyEcdsa(
                leaf,
                content,
                signature,
                HashAlgorithmName.SHA256,
                expectedKeySize: 256),
            SignatureScheme.EcdsaSecp384r1Sha384 => VerifyEcdsa(
                leaf,
                content,
                signature,
                HashAlgorithmName.SHA384,
                expectedKeySize: 384),
            SignatureScheme.EcdsaSecp521r1Sha512 => VerifyEcdsa(
                leaf,
                content,
                signature,
                HashAlgorithmName.SHA512,
                expectedKeySize: 521),
            _ => false,
        });

        if (!valid)
        {
            throw new TlsProtocolException(
                TlsAlertDescription.DecryptError,
                "TLS 1.3 CertificateVerify signature is invalid.");
        }

        return scheme;
    }

    internal static byte[] BuildCertificateVerifyContent(ReadOnlySpan<byte> transcriptHash)
    {
        var context = "TLS 1.3, server CertificateVerify"u8;
        var result = new byte[64 + context.Length + 1 + transcriptHash.Length];
        result.AsSpan(0, 64).Fill(0x20);
        context.CopyTo(result.AsSpan(64));
        result[64 + context.Length] = 0;
        transcriptHash.CopyTo(result.AsSpan(64 + context.Length + 1));
        return result;
    }

    private static bool VerifyRsa(
        X509Certificate2 certificate,
        ReadOnlySpan<byte> content,
        ReadOnlySpan<byte> signature,
        HashAlgorithmName hashAlgorithm,
        SignatureScheme scheme)
    {
        if (!RsaSignatureScheme.IsCompatible(certificate, scheme))
        {
            return false;
        }

        try
        {
            using var rsa = RsaSignatureScheme.CreatePublicKey(certificate);
            return rsa?.VerifyData(content, signature, hashAlgorithm, RSASignaturePadding.Pss) == true;
        }
        catch (CryptographicException)
        {
            return false;
        }
    }

    private static bool VerifyEcdsa(
        X509Certificate2 certificate,
        ReadOnlySpan<byte> content,
        ReadOnlySpan<byte> signature,
        HashAlgorithmName hashAlgorithm,
        int expectedKeySize)
    {
        using var ecdsa = certificate.GetECDsaPublicKey();
        return ecdsa?.KeySize == expectedKeySize &&
               ecdsa.VerifyData(
                   content,
                   signature,
                   hashAlgorithm,
                   DSASignatureFormat.Rfc3279DerSequence);
    }

    private static TlsProtocolException MapChainFailure(
        X509Chain chain,
        X509Certificate2Collection? customTrustRoots)
    {
        var statuses = chain.ChainStatus;
        if (statuses.Any(status => (status.Status & X509ChainStatusFlags.Revoked) != 0))
        {
            return new TlsProtocolException(TlsAlertDescription.CertificateRevoked, "Certificate is revoked.");
        }
        if (statuses.Any(status => (status.Status & X509ChainStatusFlags.NotTimeValid) != 0))
        {
            return new TlsProtocolException(
                TlsAlertDescription.CertificateExpired,
                "Certificate is outside its validity interval.");
        }
        if (statuses.Any(status => (status.Status & (X509ChainStatusFlags.UntrustedRoot |
            X509ChainStatusFlags.PartialChain)) != 0))
        {
            return new TlsProtocolException(TlsAlertDescription.UnknownCa, "Certificate chain is not trusted.");
        }
        if (customTrustRoots is { Count: > 0 } &&
            !TerminatesAtCustomTrustRoot(chain, customTrustRoots))
        {
            return new TlsProtocolException(
                TlsAlertDescription.UnknownCa,
                "Certificate chain does not terminate at a configured trust root.");
        }

        var details = string.Join(
            "; ",
            statuses.Select(status => status.Status.ToString()));
        return new TlsProtocolException(
            TlsAlertDescription.BadCertificate,
            $"Certificate chain validation failed: {details}.");
    }

    private static bool TerminatesAtCustomTrustRoot(
        X509Chain chain,
        X509Certificate2Collection customTrustRoots)
    {
        if (chain.ChainElements.Count == 0)
        {
            return false;
        }

        var terminalCertificate = chain.ChainElements[^1].Certificate;
        foreach (X509Certificate2 root in customTrustRoots)
        {
            if (terminalCertificate.RawDataMemory.Span.SequenceEqual(root.RawDataMemory.Span))
            {
                return true;
            }
        }
        return false;
    }

    private static string NormalizeReferenceIdentity(string serverName)
    {
        if (System.Net.IPAddress.TryParse(serverName, out _))
        {
            return serverName;
        }

        var withoutFinalDot = serverName.EndsWith(".", StringComparison.Ordinal)
            ? serverName[..^1]
            : serverName;
        return new IdnMapping().GetAscii(withoutFinalDot);
    }
}
