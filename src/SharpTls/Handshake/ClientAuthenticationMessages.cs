using System.Security.Cryptography;
using SharpTls.Certificates;
using SharpTls.IO;
using SharpTls.Protocol;

namespace SharpTls.Handshake;

internal static class ClientAuthenticationMessages
{
    internal static byte[] CreateTls13Certificate(
        ReadOnlySpan<byte> requestContext,
        TlsClientCertificate? credential,
        TlsLimits limits,
        TlsClientDelegatedCredential? delegatedCredential = null)
    {
        ArgumentNullException.ThrowIfNull(limits);
        limits.Validate();
        if (requestContext.Length > byte.MaxValue)
        {
            throw new ArgumentOutOfRangeException(nameof(requestContext));
        }

        var certificateList = new TlsBinaryWriter();
        if (credential is not null)
        {
            var chain = credential.SnapshotCertificateChain();
            if (chain.Count > limits.MaxCertificateCount)
            {
                throw new TlsProtocolException(
                    TlsAlertDescription.InternalError,
                    "The configured client certificate chain exceeds the certificate-count limit.");
            }

            for (var index = 0; index < chain.Count; index++)
            {
                var certificate = chain[index];
                if (certificate.Length == 0)
                {
                    throw new TlsProtocolException(
                        TlsAlertDescription.InternalError,
                        "The configured client certificate chain contains an empty certificate.");
                }
                certificateList.WriteVector24(certificate);
                if (index == 0 && delegatedCredential is not null)
                {
                    var encodedDelegatedCredential = delegatedCredential.CopyEncoded();
                    try
                    {
                        var extensions = new TlsBinaryWriter();
                        extensions.WriteUInt16((ushort)TlsExtensionType.DelegatedCredential);
                        extensions.WriteVector16(encodedDelegatedCredential);
                        certificateList.WriteVector16(extensions.WrittenSpan);
                    }
                    finally
                    {
                        CryptographicOperations.ZeroMemory(encodedDelegatedCredential);
                    }
                }
                else
                {
                    certificateList.WriteVector16([]);
                }
            }
        }

        if (certificateList.Length > limits.MaxCertificateListSize)
        {
            throw new TlsProtocolException(
                TlsAlertDescription.InternalError,
                "The configured client certificate chain exceeds the certificate-list limit.");
        }

        var body = new TlsBinaryWriter();
        body.WriteVector8(requestContext);
        body.WriteVector24(certificateList.WrittenSpan);
        return HandshakeMessage.Encode(HandshakeType.Certificate, body.WrittenSpan);
    }

    internal static byte[] CreateTls13CertificateVerify(
        TlsClientCertificate credential,
        SignatureScheme scheme,
        ReadOnlySpan<byte> transcriptHash)
    {
        ArgumentNullException.ThrowIfNull(credential);
        var content = BuildTls13ClientCertificateVerifyContent(transcriptHash);
        var contentHash = Hash(TlsClientCertificate.GetHashAlgorithm(scheme), content);
        byte[]? signature = null;
        try
        {
            signature = credential.SignHash(scheme, contentHash);
            return EncodeCertificateVerify(scheme, signature);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(content);
            CryptographicOperations.ZeroMemory(contentHash);
            if (signature is not null)
            {
                CryptographicOperations.ZeroMemory(signature);
            }
        }
    }

    internal static async ValueTask<byte[]> CreateTls13CertificateVerifyAsync(
        TlsClientCertificate credential,
        SignatureScheme scheme,
        ReadOnlyMemory<byte> transcriptHash,
        CancellationToken cancellationToken,
        TlsClientDelegatedCredential? delegatedCredential = null)
    {
        ArgumentNullException.ThrowIfNull(credential);
        var content = BuildTls13ClientCertificateVerifyContent(transcriptHash.Span);
        var contentHash = Hash(TlsClientCertificate.GetHashAlgorithm(scheme), content);
        byte[]? signature = null;
        try
        {
            signature = delegatedCredential is null
                ? await credential.SignHashAsync(
                    scheme,
                    contentHash,
                    cancellationToken).ConfigureAwait(false)
                : scheme != delegatedCredential.CertificateVerifyAlgorithm
                    ? throw new InvalidOperationException(
                        "Delegated CertificateVerify used the wrong signature scheme.")
                    : await delegatedCredential.SignHashAsync(
                        contentHash,
                        cancellationToken).ConfigureAwait(false);
            return EncodeCertificateVerify(scheme, signature);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(content);
            CryptographicOperations.ZeroMemory(contentHash);
            if (signature is not null)
            {
                CryptographicOperations.ZeroMemory(signature);
            }
        }
    }

    internal static byte[] CreateTls12Certificate(
        TlsClientCertificate? credential,
        TlsLimits limits)
    {
        ArgumentNullException.ThrowIfNull(limits);
        limits.Validate();
        var certificateList = new TlsBinaryWriter();
        if (credential is not null)
        {
            var chain = credential.SnapshotCertificateChain();
            if (chain.Count > limits.MaxCertificateCount)
            {
                throw new TlsProtocolException(
                    TlsAlertDescription.InternalError,
                    "The configured client certificate chain exceeds the certificate-count limit.");
            }

            foreach (var certificate in chain)
            {
                certificateList.WriteVector24(certificate);
            }
        }

        if (certificateList.Length > limits.MaxCertificateListSize)
        {
            throw new TlsProtocolException(
                TlsAlertDescription.InternalError,
                "The configured client certificate chain exceeds the certificate-list limit.");
        }

        var body = new TlsBinaryWriter(3 + certificateList.Length);
        body.WriteVector24(certificateList.WrittenSpan);
        return HandshakeMessage.Encode(HandshakeType.Certificate, body.WrittenSpan);
    }

    internal static byte[] CreateTls12CertificateVerify(
        TlsClientCertificate credential,
        SignatureScheme scheme,
        ReadOnlySpan<byte> transcriptHash)
    {
        ArgumentNullException.ThrowIfNull(credential);
        byte[]? signature = null;
        try
        {
            signature = credential.SignHash(scheme, transcriptHash);
            return EncodeCertificateVerify(scheme, signature);
        }
        finally
        {
            if (signature is not null)
            {
                CryptographicOperations.ZeroMemory(signature);
            }
        }
    }

    internal static async ValueTask<byte[]> CreateTls12CertificateVerifyAsync(
        TlsClientCertificate credential,
        SignatureScheme scheme,
        ReadOnlyMemory<byte> transcriptHash,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(credential);
        byte[]? signature = null;
        try
        {
            signature = await credential.SignHashAsync(
                scheme,
                transcriptHash,
                cancellationToken).ConfigureAwait(false);
            return EncodeCertificateVerify(scheme, signature);
        }
        finally
        {
            if (signature is not null)
            {
                CryptographicOperations.ZeroMemory(signature);
            }
        }
    }

    internal static byte[] BuildTls13ClientCertificateVerifyContent(
        ReadOnlySpan<byte> transcriptHash)
    {
        var context = "TLS 1.3, client CertificateVerify"u8;
        var result = new byte[64 + context.Length + 1 + transcriptHash.Length];
        result.AsSpan(0, 64).Fill(0x20);
        context.CopyTo(result.AsSpan(64));
        result[64 + context.Length] = 0;
        transcriptHash.CopyTo(result.AsSpan(64 + context.Length + 1));
        return result;
    }

    private static byte[] EncodeCertificateVerify(
        SignatureScheme scheme,
        ReadOnlySpan<byte> signature)
    {
        if (signature.IsEmpty)
        {
            throw new CryptographicException("The client CertificateVerify signature is empty.");
        }

        var body = new TlsBinaryWriter(4 + signature.Length);
        body.WriteUInt16((ushort)scheme);
        body.WriteVector16(signature);
        return HandshakeMessage.Encode(HandshakeType.CertificateVerify, body.WrittenSpan);
    }

    private static byte[] Hash(HashAlgorithmName algorithm, ReadOnlySpan<byte> value) =>
        algorithm.Name switch
        {
            "SHA256" => SHA256.HashData(value),
            "SHA384" => SHA384.HashData(value),
            "SHA512" => SHA512.HashData(value),
            _ => throw new NotSupportedException(
                $"Client CertificateVerify hash {algorithm.Name} is not supported."),
        };
}
