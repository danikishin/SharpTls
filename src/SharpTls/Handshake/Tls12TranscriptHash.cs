using System.Security.Cryptography;
using SharpTls.Cryptography;
using SharpTls.Protocol;

namespace SharpTls.Handshake;

internal sealed class Tls12TranscriptHash : IDisposable
{
    private readonly Tls12CipherSuiteInfo _suite;
    private IncrementalHash? _sha256;
    private IncrementalHash? _sha384;
    private IncrementalHash? _sha512;

    internal Tls12TranscriptHash(Tls12CipherSuiteInfo suite)
    {
        _suite = suite ?? throw new ArgumentNullException(nameof(suite));
        _sha256 = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        _sha384 = IncrementalHash.CreateHash(HashAlgorithmName.SHA384);
        _sha512 = IncrementalHash.CreateHash(HashAlgorithmName.SHA512);
    }

    internal void Append(ReadOnlySpan<byte> encodedHandshake)
    {
        if (encodedHandshake.Length < TlsConstants.HandshakeHeaderLength)
        {
            throw new ArgumentException(
                "Transcript input must include a TLS handshake header.",
                nameof(encodedHandshake));
        }

        GetHash(HashAlgorithmName.SHA256).AppendData(encodedHandshake);
        GetHash(HashAlgorithmName.SHA384).AppendData(encodedHandshake);
        GetHash(HashAlgorithmName.SHA512).AppendData(encodedHandshake);
    }

    internal byte[] CurrentHash()
    {
        var output = new byte[_suite.HashLength];
        GetHash(_suite.PrfHashAlgorithm).GetCurrentHash(output);
        return output;
    }

    internal byte[] CurrentHash(HashAlgorithmName algorithm)
    {
        var length = algorithm.Name switch
        {
            "SHA256" => SHA256.HashSizeInBytes,
            "SHA384" => SHA384.HashSizeInBytes,
            "SHA512" => SHA512.HashSizeInBytes,
            _ => throw new NotSupportedException(
                $"TLS 1.2 CertificateVerify hash {algorithm.Name} is not supported."),
        };
        var output = new byte[length];
        GetHash(algorithm).GetCurrentHash(output);
        return output;
    }

    public void Dispose()
    {
        _sha256?.Dispose();
        _sha256 = null;
        _sha384?.Dispose();
        _sha384 = null;
        _sha512?.Dispose();
        _sha512 = null;
    }

    private IncrementalHash GetHash(HashAlgorithmName algorithm) => algorithm.Name switch
    {
        "SHA256" => _sha256,
        "SHA384" => _sha384,
        "SHA512" => _sha512,
        _ => throw new NotSupportedException(
            $"TLS 1.2 CertificateVerify hash {algorithm.Name} is not supported."),
    } ?? throw new ObjectDisposedException(nameof(Tls12TranscriptHash));
}
