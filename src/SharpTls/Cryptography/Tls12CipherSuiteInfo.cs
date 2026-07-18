using System.Security.Cryptography;
using SharpTls.Protocol;

namespace SharpTls.Cryptography;

internal enum Tls12AeadAlgorithm
{
    AesGcm,
    ChaCha20Poly1305,
}

internal enum Tls12CertificateKeyType
{
    Rsa,
    Ecdsa,
}

internal sealed record Tls12CipherSuiteInfo(
    TlsCipherSuite Suite,
    HashAlgorithmName PrfHashAlgorithm,
    int HashLength,
    int KeyLength,
    int FixedIvLength,
    int ExplicitNonceLength,
    Tls12AeadAlgorithm AeadAlgorithm,
    Tls12CertificateKeyType CertificateKeyType)
{
    internal int KeyBlockLength => checked(2 * (KeyLength + FixedIvLength));

    internal static Tls12CipherSuiteInfo Get(TlsCipherSuite suite) => suite switch
    {
        TlsCipherSuite.TlsEcdheEcdsaWithAes128GcmSha256 => AesGcm(
            suite,
            HashAlgorithmName.SHA256,
            hashLength: 32,
            keyLength: 16,
            Tls12CertificateKeyType.Ecdsa),
        TlsCipherSuite.TlsEcdheRsaWithAes128GcmSha256 => AesGcm(
            suite,
            HashAlgorithmName.SHA256,
            hashLength: 32,
            keyLength: 16,
            Tls12CertificateKeyType.Rsa),
        TlsCipherSuite.TlsEcdheEcdsaWithAes256GcmSha384 => AesGcm(
            suite,
            HashAlgorithmName.SHA384,
            hashLength: 48,
            keyLength: 32,
            Tls12CertificateKeyType.Ecdsa),
        TlsCipherSuite.TlsEcdheRsaWithAes256GcmSha384 => AesGcm(
            suite,
            HashAlgorithmName.SHA384,
            hashLength: 48,
            keyLength: 32,
            Tls12CertificateKeyType.Rsa),
        TlsCipherSuite.TlsEcdheRsaWithChaCha20Poly1305Sha256 => ChaCha(
            suite,
            Tls12CertificateKeyType.Rsa),
        TlsCipherSuite.TlsEcdheEcdsaWithChaCha20Poly1305Sha256 => ChaCha(
            suite,
            Tls12CertificateKeyType.Ecdsa),
        _ => throw new NotSupportedException(
            $"TLS 1.2 cipher suite 0x{(ushort)suite:X4} is not a supported AEAD ECDHE suite."),
    };

    private static Tls12CipherSuiteInfo AesGcm(
        TlsCipherSuite suite,
        HashAlgorithmName hash,
        int hashLength,
        int keyLength,
        Tls12CertificateKeyType certificateKeyType) => new(
            suite,
            hash,
            hashLength,
            keyLength,
            FixedIvLength: 4,
            ExplicitNonceLength: 8,
            Tls12AeadAlgorithm.AesGcm,
            certificateKeyType);

    private static Tls12CipherSuiteInfo ChaCha(
        TlsCipherSuite suite,
        Tls12CertificateKeyType certificateKeyType) => new(
            suite,
            HashAlgorithmName.SHA256,
            HashLength: 32,
            KeyLength: 32,
            FixedIvLength: 12,
            ExplicitNonceLength: 0,
            Tls12AeadAlgorithm.ChaCha20Poly1305,
            certificateKeyType);
}
