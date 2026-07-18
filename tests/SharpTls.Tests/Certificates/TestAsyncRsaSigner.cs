using System.Security.Cryptography;
using SharpTls.Certificates;
using SharpTls.Protocol;

namespace SharpTls.Tests.Certificates;

internal sealed class TestAsyncRsaSigner(
    RSA key,
    IReadOnlyCollection<SignatureScheme>? schemes = null)
    : ITlsClientCertificateSigner
{
    private readonly RSA _key = key ?? throw new ArgumentNullException(nameof(key));
    private int _signCount;

    public IReadOnlyCollection<SignatureScheme> SupportedSignatureSchemes { get; } =
        schemes ??
        [
            SignatureScheme.RsaPssRsaeSha256,
            SignatureScheme.RsaPssRsaeSha384,
            SignatureScheme.RsaPssRsaeSha512,
            SignatureScheme.RsaPkcs1Sha256,
            SignatureScheme.RsaPkcs1Sha384,
            SignatureScheme.RsaPkcs1Sha512,
        ];

    internal int SignCount => Volatile.Read(ref _signCount);

    public byte[] ExportSubjectPublicKeyInfo() => _key.ExportSubjectPublicKeyInfo();

    public async ValueTask<byte[]> SignHashAsync(
        SignatureScheme scheme,
        ReadOnlyMemory<byte> hash,
        CancellationToken cancellationToken = default)
    {
        await Task.Yield();
        cancellationToken.ThrowIfCancellationRequested();
        Interlocked.Increment(ref _signCount);
        var algorithm = TlsClientCertificate.GetHashAlgorithm(scheme);
        var padding = scheme is
            SignatureScheme.RsaPssRsaeSha256 or
            SignatureScheme.RsaPssRsaeSha384 or
            SignatureScheme.RsaPssRsaeSha512 or
            SignatureScheme.RsaPssPssSha256 or
            SignatureScheme.RsaPssPssSha384 or
            SignatureScheme.RsaPssPssSha512
                ? RSASignaturePadding.Pss
                : RSASignaturePadding.Pkcs1;
        return _key.SignHash(hash.Span, algorithm, padding);
    }
}
