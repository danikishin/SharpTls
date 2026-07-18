using System.Buffers.Binary;
using System.Security.Cryptography;
using SharpTls.Cryptography;

namespace SharpTls.Ech;

internal sealed class HpkeReceiverContext : IDisposable
{
    private const int TagLength = 16;

    private readonly byte[] _key;
    private readonly byte[] _baseNonce;
    private readonly AesGcm? _aesGcm;
    private readonly ChaCha20Poly1305? _chaCha;
    private ulong _sequenceNumber;
    private bool _sequenceExhausted;
    private bool _disposed;

    private HpkeReceiverContext(
        TlsHpkeAeadId aeadId,
        byte[] key,
        byte[] baseNonce)
    {
        _key = key;
        _baseNonce = baseNonce;
        try
        {
            switch (aeadId)
            {
                case TlsHpkeAeadId.Aes128Gcm:
                case TlsHpkeAeadId.Aes256Gcm:
                    _aesGcm = new AesGcm(_key, TagLength);
                    break;
                case TlsHpkeAeadId.ChaCha20Poly1305:
                    if (!ChaCha20Poly1305.IsSupported)
                    {
                        throw new PlatformNotSupportedException(
                            "ChaCha20-Poly1305 is unavailable on this platform.");
                    }
                    _chaCha = new ChaCha20Poly1305(_key);
                    break;
                default:
                    throw new NotSupportedException(
                        $"HPKE AEAD 0x{(ushort)aeadId:X4} is not supported.");
            }
        }
        catch
        {
            Dispose();
            throw;
        }
    }

    internal static HpkeReceiverContext SetupBaseX25519(
        TlsHpkeSymmetricCipherSuite suite,
        ReadOnlySpan<byte> receiverPrivateKey,
        ReadOnlySpan<byte> encapsulatedKey,
        ReadOnlySpan<byte> info)
    {
        if (receiverPrivateKey.Length != X25519.KeyLength)
        {
            throw new ArgumentException(
                "An X25519 HPKE receiver private key must contain 32 bytes.",
                nameof(receiverPrivateKey));
        }
        if (encapsulatedKey.Length != X25519.KeyLength)
        {
            throw new ArgumentException(
                "An X25519 HPKE encapsulated key must contain 32 bytes.",
                nameof(encapsulatedKey));
        }

        var kdfHash = HpkeSenderContext.GetKdfHash(suite.KdfId);
        var keyLength = HpkeSenderContext.GetKeyLength(suite.AeadId);
        byte[]? receiverPublicKey = null;
        byte[]? dh = null;
        byte[]? sharedSecret = null;
        byte[]? secret = null;
        byte[]? key = null;
        byte[]? baseNonce = null;
        try
        {
            receiverPublicKey = new byte[X25519.KeyLength];
            X25519.DerivePublicKey(receiverPrivateKey, receiverPublicKey);
            dh = new byte[X25519.KeyLength];
            X25519.ScalarMultiply(receiverPrivateKey, encapsulatedKey, dh);
            Span<byte> zero = stackalloc byte[X25519.KeyLength];
            zero.Clear();
            if (CryptographicOperations.FixedTimeEquals(dh, zero))
            {
                throw new CryptographicException(
                    "X25519 HPKE decapsulation produced the all-zero shared secret.");
            }

            var kemSuiteId = HpkeSenderContext.BuildKemSuiteId(
                TlsHpkeKemId.DhkemX25519HkdfSha256);
            var kemContext = new byte[encapsulatedKey.Length + receiverPublicKey.Length];
            encapsulatedKey.CopyTo(kemContext);
            receiverPublicKey.CopyTo(kemContext, encapsulatedKey.Length);
            var eaePrk = HpkeSenderContext.LabeledExtract(
                HashAlgorithmName.SHA256,
                [],
                kemSuiteId,
                "eae_prk",
                dh);
            try
            {
                sharedSecret = HpkeSenderContext.LabeledExpand(
                    HashAlgorithmName.SHA256,
                    eaePrk,
                    kemSuiteId,
                    "shared_secret",
                    kemContext,
                    32);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(eaePrk);
                CryptographicOperations.ZeroMemory(kemContext);
            }

            var suiteId = HpkeSenderContext.BuildHpkeSuiteId(
                TlsHpkeKemId.DhkemX25519HkdfSha256,
                suite);
            var pskIdHash = HpkeSenderContext.LabeledExtract(
                kdfHash,
                [],
                suiteId,
                "psk_id_hash",
                []);
            var infoHash = HpkeSenderContext.LabeledExtract(
                kdfHash,
                [],
                suiteId,
                "info_hash",
                info);
            var keyScheduleContext = new byte[1 + pskIdHash.Length + infoHash.Length];
            try
            {
                pskIdHash.CopyTo(keyScheduleContext, 1);
                infoHash.CopyTo(keyScheduleContext, 1 + pskIdHash.Length);
                secret = HpkeSenderContext.LabeledExtract(
                    kdfHash,
                    sharedSecret,
                    suiteId,
                    "secret",
                    []);
                key = HpkeSenderContext.LabeledExpand(
                    kdfHash,
                    secret,
                    suiteId,
                    "key",
                    keyScheduleContext,
                    keyLength);
                baseNonce = HpkeSenderContext.LabeledExpand(
                    kdfHash,
                    secret,
                    suiteId,
                    "base_nonce",
                    keyScheduleContext,
                    12);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(pskIdHash);
                CryptographicOperations.ZeroMemory(infoHash);
                CryptographicOperations.ZeroMemory(keyScheduleContext);
            }

            var result = new HpkeReceiverContext(suite.AeadId, key, baseNonce);
            key = null;
            baseNonce = null;
            return result;
        }
        finally
        {
            Zero(receiverPublicKey);
            Zero(dh);
            Zero(sharedSecret);
            Zero(secret);
            Zero(key);
            Zero(baseNonce);
        }
    }

    internal static HpkeReceiverContext SetupBaseNist(
        TlsHpkeKemId kemId,
        TlsHpkeSymmetricCipherSuite suite,
        ReadOnlySpan<byte> receiverPrivateKey,
        ReadOnlySpan<byte> receiverPublicKey,
        ReadOnlySpan<byte> encapsulatedKey,
        ReadOnlySpan<byte> info)
    {
        byte[]? dh = null;
        byte[]? sharedSecret = null;
        try
        {
            dh = HpkeNistKem.Decapsulate(
                kemId,
                receiverPrivateKey,
                receiverPublicKey,
                encapsulatedKey);
            sharedSecret = HpkeSenderContext.DeriveKemSharedSecret(
                kemId,
                dh,
                encapsulatedKey,
                receiverPublicKey);
            return CreateFromKemSecret(kemId, suite, info, sharedSecret);
        }
        finally
        {
            Zero(dh);
            Zero(sharedSecret);
        }
    }

    private static HpkeReceiverContext CreateFromKemSecret(
        TlsHpkeKemId kemId,
        TlsHpkeSymmetricCipherSuite suite,
        ReadOnlySpan<byte> info,
        ReadOnlySpan<byte> sharedSecret)
    {
        var kdfHash = HpkeSenderContext.GetKdfHash(suite.KdfId);
        var keyLength = HpkeSenderContext.GetKeyLength(suite.AeadId);
        var suiteId = HpkeSenderContext.BuildHpkeSuiteId(kemId, suite);
        byte[]? secret = null;
        byte[]? key = null;
        byte[]? baseNonce = null;
        var pskIdHash = HpkeSenderContext.LabeledExtract(
            kdfHash,
            [],
            suiteId,
            "psk_id_hash",
            []);
        var infoHash = HpkeSenderContext.LabeledExtract(
            kdfHash,
            [],
            suiteId,
            "info_hash",
            info);
        var keyScheduleContext = new byte[1 + pskIdHash.Length + infoHash.Length];
        try
        {
            pskIdHash.CopyTo(keyScheduleContext, 1);
            infoHash.CopyTo(keyScheduleContext, 1 + pskIdHash.Length);
            secret = HpkeSenderContext.LabeledExtract(
                kdfHash,
                sharedSecret,
                suiteId,
                "secret",
                []);
            key = HpkeSenderContext.LabeledExpand(
                kdfHash,
                secret,
                suiteId,
                "key",
                keyScheduleContext,
                keyLength);
            baseNonce = HpkeSenderContext.LabeledExpand(
                kdfHash,
                secret,
                suiteId,
                "base_nonce",
                keyScheduleContext,
                12);

            var result = new HpkeReceiverContext(suite.AeadId, key, baseNonce);
            key = null;
            baseNonce = null;
            return result;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(pskIdHash);
            CryptographicOperations.ZeroMemory(infoHash);
            CryptographicOperations.ZeroMemory(keyScheduleContext);
            Zero(secret);
            Zero(key);
            Zero(baseNonce);
        }
    }

    internal byte[] Open(
        ReadOnlySpan<byte> associatedData,
        ReadOnlySpan<byte> ciphertext)
    {
        ThrowIfUnavailable();
        if (ciphertext.Length < TagLength)
        {
            throw new CryptographicException("HPKE ciphertext is shorter than its AEAD tag.");
        }

        var plaintext = new byte[ciphertext.Length - TagLength];
        Span<byte> nonce = stackalloc byte[12];
        BuildNonce(nonce);
        try
        {
            var encrypted = ciphertext[..plaintext.Length];
            var tag = ciphertext[plaintext.Length..];
            if (_aesGcm is not null)
            {
                _aesGcm.Decrypt(nonce, encrypted, tag, plaintext, associatedData);
            }
            else
            {
                _chaCha!.Decrypt(nonce, encrypted, tag, plaintext, associatedData);
            }
            AdvanceSequence();
            return plaintext;
        }
        catch
        {
            CryptographicOperations.ZeroMemory(plaintext);
            throw;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(nonce);
        }
    }

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }
        _disposed = true;
        _aesGcm?.Dispose();
        _chaCha?.Dispose();
        CryptographicOperations.ZeroMemory(_key);
        CryptographicOperations.ZeroMemory(_baseNonce);
    }

    private void BuildNonce(Span<byte> destination)
    {
        _baseNonce.CopyTo(destination);
        Span<byte> sequence = stackalloc byte[12];
        sequence.Clear();
        BinaryPrimitives.WriteUInt64BigEndian(sequence[4..], _sequenceNumber);
        for (var index = 0; index < destination.Length; index++)
        {
            destination[index] ^= sequence[index];
        }
        CryptographicOperations.ZeroMemory(sequence);
    }

    private void AdvanceSequence()
    {
        if (_sequenceNumber == ulong.MaxValue)
        {
            _sequenceExhausted = true;
            return;
        }
        _sequenceNumber++;
    }

    private void ThrowIfUnavailable()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (_sequenceExhausted)
        {
            throw new CryptographicException("The HPKE receiver sequence number is exhausted.");
        }
    }

    private static void Zero(byte[]? value)
    {
        if (value is not null)
        {
            CryptographicOperations.ZeroMemory(value);
        }
    }
}
