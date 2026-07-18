using System.Security.Cryptography;
using SharpTls.Protocol;

namespace SharpTls.Cryptography;

internal sealed record CipherSuiteInfo(
    TlsCipherSuite Suite,
    HashAlgorithmName HashAlgorithm,
    int HashLength,
    int KeyLength,
    int IvLength)
{
    internal static CipherSuiteInfo Get(TlsCipherSuite suite) => suite switch
    {
        TlsCipherSuite.TlsAes128GcmSha256 => new(suite, HashAlgorithmName.SHA256, 32, 16, 12),
        TlsCipherSuite.TlsAes256GcmSha384 => new(suite, HashAlgorithmName.SHA384, 48, 32, 12),
        TlsCipherSuite.TlsChaCha20Poly1305Sha256 => new(suite, HashAlgorithmName.SHA256, 32, 32, 12),
        _ => throw new NotSupportedException($"Cipher suite 0x{(ushort)suite:X4} is not implemented."),
    };
}
