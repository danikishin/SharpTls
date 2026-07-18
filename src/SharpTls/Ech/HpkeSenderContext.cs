using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using SharpTls.Cryptography;
using SharpTls.IO;
using SharpTls.Protocol;

namespace SharpTls.Ech;

/// <summary>
/// RFC 9180 base-mode sender context for the ECH-supported DHKEM families.
/// NIST-curve operations delegate to the runtime ECDH provider; X25519 uses the isolated
/// RFC 7748 implementation shared with the TLS key-share layer.
/// </summary>
internal sealed class HpkeSenderContext : IDisposable
{
    private const int TagLength = 16;
    private static ReadOnlySpan<byte> HpkeVersionLabel => "HPKE-v1"u8;

    private readonly TlsHpkeKemId _kemId;
    private readonly TlsHpkeSymmetricCipherSuite _suite;
    private readonly HashAlgorithmName _kdfHash;
    private readonly byte[] _encapsulatedKey;
    private readonly byte[] _key;
    private readonly byte[] _baseNonce;
    private readonly byte[] _exporterSecret;
    private readonly AesGcm? _aesGcm;
    private readonly ChaCha20Poly1305? _chaCha;
    private ulong _sequenceNumber;
    private bool _sequenceExhausted;
    private bool _disposed;

    private HpkeSenderContext(
        TlsHpkeKemId kemId,
        TlsHpkeSymmetricCipherSuite suite,
        HashAlgorithmName kdfHash,
        byte[] encapsulatedKey,
        byte[] key,
        byte[] baseNonce,
        byte[] exporterSecret)
    {
        _kemId = kemId;
        _suite = suite;
        _kdfHash = kdfHash;
        _encapsulatedKey = encapsulatedKey;
        _key = key;
        _baseNonce = baseNonce;
        _exporterSecret = exporterSecret;
        try
        {
            switch (suite.AeadId)
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
                        $"HPKE AEAD 0x{(ushort)suite.AeadId:X4} is not supported.");
            }
        }
        catch
        {
            Dispose();
            throw;
        }
    }

    internal byte[] EncapsulatedKey
    {
        get
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            return (byte[])_encapsulatedKey.Clone();
        }
    }

    internal static HpkeSenderContext SetupBase(
        TlsHpkeKemId kemId,
        TlsHpkeSymmetricCipherSuite suite,
        ReadOnlySpan<byte> receiverPublicKey,
        ReadOnlySpan<byte> info,
        IRandomSource randomSource) => kemId switch
    {
        TlsHpkeKemId.DhkemX25519HkdfSha256 => SetupBaseX25519(
            suite,
            receiverPublicKey,
            info,
            randomSource),
        TlsHpkeKemId.DhkemP256HkdfSha256 or
        TlsHpkeKemId.DhkemP384HkdfSha384 or
        TlsHpkeKemId.DhkemP521HkdfSha512 => SetupBaseNist(
            kemId,
            suite,
            receiverPublicKey,
            info,
            randomSource),
        _ => throw new NotSupportedException(
            $"HPKE KEM 0x{(ushort)kemId:X4} is unsupported."),
    };

    internal static HpkeSenderContext SetupBaseX25519(
        TlsHpkeSymmetricCipherSuite suite,
        ReadOnlySpan<byte> receiverPublicKey,
        ReadOnlySpan<byte> info,
        IRandomSource randomSource)
    {
        ArgumentNullException.ThrowIfNull(randomSource);
        Span<byte> ikmE = stackalloc byte[X25519.KeyLength];
        randomSource.Fill(ikmE);
        try
        {
            return SetupBaseX25519ForTesting(suite, receiverPublicKey, info, ikmE);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(ikmE);
        }
    }

    internal static HpkeSenderContext SetupBaseX25519ForTesting(
        TlsHpkeSymmetricCipherSuite suite,
        ReadOnlySpan<byte> receiverPublicKey,
        ReadOnlySpan<byte> info,
        ReadOnlySpan<byte> ikmE)
    {
        if (receiverPublicKey.Length != X25519.KeyLength)
        {
            throw new ArgumentException(
                "An X25519 HPKE receiver public key must contain 32 bytes.",
                nameof(receiverPublicKey));
        }
        if (ikmE.Length < X25519.KeyLength)
        {
            throw new ArgumentException(
                "HPKE ephemeral input key material must contain at least 32 bytes.",
                nameof(ikmE));
        }

        var kdfHash = GetKdfHash(suite.KdfId);
        var keyLength = GetKeyLength(suite.AeadId);
        byte[]? ephemeralPrivateKey = null;
        byte[]? encapsulatedKey = null;
        byte[]? dh = null;
        byte[]? sharedSecret = null;
        byte[]? secret = null;
        byte[]? key = null;
        byte[]? baseNonce = null;
        byte[]? exporterSecret = null;
        try
        {
            var kemSuiteId = BuildKemSuiteId(TlsHpkeKemId.DhkemX25519HkdfSha256);
            var dkpPrk = LabeledExtract(
                HashAlgorithmName.SHA256,
                [],
                kemSuiteId,
                "dkp_prk",
                ikmE);
            try
            {
                ephemeralPrivateKey = LabeledExpand(
                    HashAlgorithmName.SHA256,
                    dkpPrk,
                    kemSuiteId,
                    "sk",
                    [],
                    X25519.KeyLength);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(dkpPrk);
            }

            encapsulatedKey = new byte[X25519.KeyLength];
            X25519.DerivePublicKey(ephemeralPrivateKey, encapsulatedKey);
            dh = new byte[X25519.KeyLength];
            X25519.ScalarMultiply(ephemeralPrivateKey, receiverPublicKey, dh);
            Span<byte> zero = stackalloc byte[X25519.KeyLength];
            zero.Clear();
            if (CryptographicOperations.FixedTimeEquals(dh, zero))
            {
                throw new CryptographicException(
                    "X25519 HPKE encapsulation produced the all-zero shared secret.");
            }

            var kemContext = new byte[encapsulatedKey.Length + receiverPublicKey.Length];
            encapsulatedKey.CopyTo(kemContext, 0);
            receiverPublicKey.CopyTo(kemContext.AsSpan(encapsulatedKey.Length));
            var eaePrk = LabeledExtract(
                HashAlgorithmName.SHA256,
                [],
                kemSuiteId,
                "eae_prk",
                dh);
            try
            {
                sharedSecret = LabeledExpand(
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

            var suiteId = BuildHpkeSuiteId(
                TlsHpkeKemId.DhkemX25519HkdfSha256,
                suite);
            var pskIdHash = LabeledExtract(kdfHash, [], suiteId, "psk_id_hash", []);
            var infoHash = LabeledExtract(kdfHash, [], suiteId, "info_hash", info);
            var keyScheduleContext = new byte[1 + pskIdHash.Length + infoHash.Length];
            try
            {
                pskIdHash.CopyTo(keyScheduleContext, 1);
                infoHash.CopyTo(keyScheduleContext, 1 + pskIdHash.Length);
                secret = LabeledExtract(kdfHash, sharedSecret, suiteId, "secret", []);
                key = LabeledExpand(
                    kdfHash,
                    secret,
                    suiteId,
                    "key",
                    keyScheduleContext,
                    keyLength);
                baseNonce = LabeledExpand(
                    kdfHash,
                    secret,
                    suiteId,
                    "base_nonce",
                    keyScheduleContext,
                    12);
                exporterSecret = LabeledExpand(
                    kdfHash,
                    secret,
                    suiteId,
                    "exp",
                    keyScheduleContext,
                    GetHashLength(kdfHash));
            }
            finally
            {
                CryptographicOperations.ZeroMemory(pskIdHash);
                CryptographicOperations.ZeroMemory(infoHash);
                CryptographicOperations.ZeroMemory(keyScheduleContext);
            }

            var result = new HpkeSenderContext(
                TlsHpkeKemId.DhkemX25519HkdfSha256,
                suite,
                kdfHash,
                encapsulatedKey,
                key,
                baseNonce,
                exporterSecret);
            encapsulatedKey = null;
            key = null;
            baseNonce = null;
            exporterSecret = null;
            return result;
        }
        finally
        {
            Zero(ephemeralPrivateKey);
            Zero(encapsulatedKey);
            Zero(dh);
            Zero(sharedSecret);
            Zero(secret);
            Zero(key);
            Zero(baseNonce);
            Zero(exporterSecret);
        }
    }

    internal static HpkeSenderContext SetupBaseNistForTesting(
        TlsHpkeKemId kemId,
        TlsHpkeSymmetricCipherSuite suite,
        ReadOnlySpan<byte> receiverPublicKey,
        ReadOnlySpan<byte> info,
        ReadOnlySpan<byte> ephemeralPrivateKey,
        ReadOnlySpan<byte> ephemeralPublicKey)
    {
        var encapsulation = HpkeNistKem.EncapsulateForTesting(
            kemId,
            receiverPublicKey,
            ephemeralPrivateKey,
            ephemeralPublicKey);
        return CompleteNistSetup(
            kemId,
            suite,
            receiverPublicKey,
            info,
            encapsulation.EncapsulatedKey,
            encapsulation.Dh);
    }

    internal static byte[] DeriveKemSharedSecret(
        TlsHpkeKemId kemId,
        ReadOnlySpan<byte> dh,
        ReadOnlySpan<byte> encapsulatedKey,
        ReadOnlySpan<byte> receiverPublicKey)
    {
        var (hash, sharedSecretLength) = kemId switch
        {
            TlsHpkeKemId.DhkemX25519HkdfSha256 => (HashAlgorithmName.SHA256, 32),
            TlsHpkeKemId.DhkemP256HkdfSha256 => (HashAlgorithmName.SHA256, 32),
            TlsHpkeKemId.DhkemP384HkdfSha384 => (HashAlgorithmName.SHA384, 48),
            TlsHpkeKemId.DhkemP521HkdfSha512 => (HashAlgorithmName.SHA512, 64),
            _ => throw new NotSupportedException(
                $"HPKE KEM 0x{(ushort)kemId:X4} is unsupported."),
        };
        var kemSuiteId = BuildKemSuiteId(kemId);
        var kemContext = new byte[encapsulatedKey.Length + receiverPublicKey.Length];
        encapsulatedKey.CopyTo(kemContext);
        receiverPublicKey.CopyTo(kemContext.AsSpan(encapsulatedKey.Length));
        var eaePrk = LabeledExtract(hash, [], kemSuiteId, "eae_prk", dh);
        try
        {
            return LabeledExpand(
                hash,
                eaePrk,
                kemSuiteId,
                "shared_secret",
                kemContext,
                sharedSecretLength);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(eaePrk);
            CryptographicOperations.ZeroMemory(kemContext);
        }
    }

    private static HpkeSenderContext SetupBaseNist(
        TlsHpkeKemId kemId,
        TlsHpkeSymmetricCipherSuite suite,
        ReadOnlySpan<byte> receiverPublicKey,
        ReadOnlySpan<byte> info,
        IRandomSource randomSource)
    {
        var encapsulation = HpkeNistKem.Encapsulate(
            kemId,
            receiverPublicKey,
            randomSource);
        return CompleteNistSetup(
            kemId,
            suite,
            receiverPublicKey,
            info,
            encapsulation.EncapsulatedKey,
            encapsulation.Dh);
    }

    private static HpkeSenderContext CompleteNistSetup(
        TlsHpkeKemId kemId,
        TlsHpkeSymmetricCipherSuite suite,
        ReadOnlySpan<byte> receiverPublicKey,
        ReadOnlySpan<byte> info,
        byte[] encapsulatedKey,
        byte[] dh)
    {
        byte[]? sharedSecret = null;
        try
        {
            sharedSecret = DeriveKemSharedSecret(
                kemId,
                dh,
                encapsulatedKey,
                receiverPublicKey);
            return CreateFromKemSecret(
                kemId,
                suite,
                info,
                encapsulatedKey,
                sharedSecret);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(encapsulatedKey);
            CryptographicOperations.ZeroMemory(dh);
            Zero(sharedSecret);
        }
    }

    private static HpkeSenderContext CreateFromKemSecret(
        TlsHpkeKemId kemId,
        TlsHpkeSymmetricCipherSuite suite,
        ReadOnlySpan<byte> info,
        ReadOnlySpan<byte> encapsulatedKey,
        ReadOnlySpan<byte> sharedSecret)
    {
        var kdfHash = GetKdfHash(suite.KdfId);
        var keyLength = GetKeyLength(suite.AeadId);
        var suiteId = BuildHpkeSuiteId(kemId, suite);
        byte[]? secret = null;
        byte[]? key = null;
        byte[]? baseNonce = null;
        byte[]? exporterSecret = null;
        var pskIdHash = LabeledExtract(kdfHash, [], suiteId, "psk_id_hash", []);
        var infoHash = LabeledExtract(kdfHash, [], suiteId, "info_hash", info);
        var keyScheduleContext = new byte[1 + pskIdHash.Length + infoHash.Length];
        try
        {
            pskIdHash.CopyTo(keyScheduleContext, 1);
            infoHash.CopyTo(keyScheduleContext, 1 + pskIdHash.Length);
            secret = LabeledExtract(kdfHash, sharedSecret, suiteId, "secret", []);
            key = LabeledExpand(
                kdfHash,
                secret,
                suiteId,
                "key",
                keyScheduleContext,
                keyLength);
            baseNonce = LabeledExpand(
                kdfHash,
                secret,
                suiteId,
                "base_nonce",
                keyScheduleContext,
                12);
            exporterSecret = LabeledExpand(
                kdfHash,
                secret,
                suiteId,
                "exp",
                keyScheduleContext,
                GetHashLength(kdfHash));

            var result = new HpkeSenderContext(
                kemId,
                suite,
                kdfHash,
                encapsulatedKey.ToArray(),
                key,
                baseNonce,
                exporterSecret);
            key = null;
            baseNonce = null;
            exporterSecret = null;
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
            Zero(exporterSecret);
        }
    }

    internal byte[] Seal(ReadOnlySpan<byte> associatedData, ReadOnlySpan<byte> plaintext)
    {
        ThrowIfUnavailable();
        var ciphertext = new byte[checked(plaintext.Length + TagLength)];
        Span<byte> nonce = stackalloc byte[12];
        BuildNonce(nonce);
        try
        {
            var encrypted = ciphertext.AsSpan(0, plaintext.Length);
            var tag = ciphertext.AsSpan(plaintext.Length, TagLength);
            if (_aesGcm is not null)
            {
                _aesGcm.Encrypt(nonce, plaintext, encrypted, tag, associatedData);
            }
            else
            {
                _chaCha!.Encrypt(nonce, plaintext, encrypted, tag, associatedData);
            }
            AdvanceSequence();
            return ciphertext;
        }
        catch
        {
            CryptographicOperations.ZeroMemory(ciphertext);
            throw;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(nonce);
        }
    }

    internal byte[] Export(ReadOnlySpan<byte> exporterContext, int length)
    {
        ThrowIfUnavailable();
        if (length is < 0 or > ushort.MaxValue)
        {
            throw new ArgumentOutOfRangeException(nameof(length));
        }
        var suiteId = BuildHpkeSuiteId(
            _kemId,
            _suite);
        return LabeledExpand(
            _kdfHash,
            _exporterSecret,
            suiteId,
            "sec",
            exporterContext,
            length);
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
        CryptographicOperations.ZeroMemory(_encapsulatedKey);
        CryptographicOperations.ZeroMemory(_key);
        CryptographicOperations.ZeroMemory(_baseNonce);
        CryptographicOperations.ZeroMemory(_exporterSecret);
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
            throw new CryptographicException("The HPKE sender sequence number is exhausted.");
        }
    }

    internal static byte[] LabeledExtract(
        HashAlgorithmName hash,
        ReadOnlySpan<byte> salt,
        ReadOnlySpan<byte> suiteId,
        string label,
        ReadOnlySpan<byte> inputKeyMaterial)
    {
        var labeledIkm = BuildLabeledInput(suiteId, label, inputKeyMaterial, null);
        var saltCopy = salt.ToArray();
        try
        {
            return HKDF.Extract(hash, labeledIkm, saltCopy);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(labeledIkm);
            CryptographicOperations.ZeroMemory(saltCopy);
        }
    }

    internal static byte[] LabeledExpand(
        HashAlgorithmName hash,
        ReadOnlySpan<byte> pseudorandomKey,
        ReadOnlySpan<byte> suiteId,
        string label,
        ReadOnlySpan<byte> info,
        int length)
    {
        if (length is < 0 or > ushort.MaxValue)
        {
            throw new ArgumentOutOfRangeException(nameof(length));
        }
        var labeledInfo = BuildLabeledInput(suiteId, label, info, checked((ushort)length));
        var output = new byte[length];
        try
        {
            HKDF.Expand(hash, pseudorandomKey, output, labeledInfo);
            return output;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(labeledInfo);
        }
    }

    private static byte[] BuildLabeledInput(
        ReadOnlySpan<byte> suiteId,
        string label,
        ReadOnlySpan<byte> input,
        ushort? length)
    {
        var labelBytes = Encoding.ASCII.GetBytes(label);
        if (labelBytes.Length == 0 || labelBytes.Any(value => value > 0x7F))
        {
            throw new ArgumentException("HPKE label must be non-empty ASCII.", nameof(label));
        }
        var writer = new TlsBinaryWriter();
        if (length.HasValue)
        {
            writer.WriteUInt16(length.Value);
        }
        writer.WriteBytes(HpkeVersionLabel);
        writer.WriteBytes(suiteId);
        writer.WriteBytes(labelBytes);
        writer.WriteBytes(input);
        return writer.ToArray();
    }

    internal static byte[] BuildKemSuiteId(TlsHpkeKemId kemId)
    {
        var result = new byte[5];
        "KEM"u8.CopyTo(result);
        BinaryPrimitives.WriteUInt16BigEndian(result.AsSpan(3), (ushort)kemId);
        return result;
    }

    internal static byte[] BuildHpkeSuiteId(
        TlsHpkeKemId kemId,
        TlsHpkeSymmetricCipherSuite suite)
    {
        var result = new byte[10];
        "HPKE"u8.CopyTo(result);
        BinaryPrimitives.WriteUInt16BigEndian(result.AsSpan(4), (ushort)kemId);
        BinaryPrimitives.WriteUInt16BigEndian(result.AsSpan(6), (ushort)suite.KdfId);
        BinaryPrimitives.WriteUInt16BigEndian(result.AsSpan(8), (ushort)suite.AeadId);
        return result;
    }

    internal static HashAlgorithmName GetKdfHash(TlsHpkeKdfId kdfId) => kdfId switch
    {
        TlsHpkeKdfId.HkdfSha256 => HashAlgorithmName.SHA256,
        TlsHpkeKdfId.HkdfSha384 => HashAlgorithmName.SHA384,
        TlsHpkeKdfId.HkdfSha512 => HashAlgorithmName.SHA512,
        _ => throw new NotSupportedException($"HPKE KDF 0x{(ushort)kdfId:X4} is unsupported."),
    };

    internal static int GetHashLength(HashAlgorithmName hash) => hash.Name switch
    {
        "SHA256" => 32,
        "SHA384" => 48,
        "SHA512" => 64,
        _ => throw new NotSupportedException(),
    };

    internal static int GetKeyLength(TlsHpkeAeadId aeadId) => aeadId switch
    {
        TlsHpkeAeadId.Aes128Gcm => 16,
        TlsHpkeAeadId.Aes256Gcm => 32,
        TlsHpkeAeadId.ChaCha20Poly1305 => 32,
        _ => throw new NotSupportedException($"HPKE AEAD 0x{(ushort)aeadId:X4} is unsupported."),
    };

    private static void Zero(byte[]? value)
    {
        if (value is not null)
        {
            CryptographicOperations.ZeroMemory(value);
        }
    }
}
