using System.Security.Cryptography;
using SharpTls.Certificates;
using SharpTls.Protocol;

namespace SharpTls.Tests.Certificates;

internal sealed class TestAsyncEcdsaSigner(
    ECDsa key,
    IReadOnlyCollection<SignatureScheme>? schemes = null)
    : ITlsClientCertificateSigner
{
    private readonly ECDsa _key = key ?? throw new ArgumentNullException(nameof(key));
    private int _signCount;

    public IReadOnlyCollection<SignatureScheme> SupportedSignatureSchemes { get; } =
        schemes ?? [SignatureScheme.EcdsaSecp256r1Sha256];

    internal int SignCount => Volatile.Read(ref _signCount);

    public byte[] ExportSubjectPublicKeyInfo() => _key.ExportSubjectPublicKeyInfo();

    public async ValueTask<byte[]> SignHashAsync(
        SignatureScheme scheme,
        ReadOnlyMemory<byte> hash,
        CancellationToken cancellationToken = default)
    {
        await Task.Yield();
        cancellationToken.ThrowIfCancellationRequested();
        if (!SupportedSignatureSchemes.Contains(scheme))
        {
            throw new NotSupportedException();
        }
        Interlocked.Increment(ref _signCount);
        return _key.SignHash(hash.Span, DSASignatureFormat.Rfc3279DerSequence);
    }
}
