using System.Security.Cryptography;
using SharpTls.Cryptography;
using SharpTls.IO;
using SharpTls.Protocol;

namespace SharpTls.Records;

internal sealed record TlsInnerPlaintext(
    TlsContentType ContentType,
    byte[] Content,
    int EncodedLength);

internal sealed class Tls13RecordCipher : IDisposable
{
    private readonly CipherSuiteInfo _suite;
    private readonly byte[] _key;
    private readonly byte[] _iv;
    private readonly AesGcm? _aesGcm;
    private readonly ChaCha20Poly1305? _chaCha20Poly1305;
    private readonly ulong _maximumRecords;
    private ulong _sequenceNumber;
    private ulong _recordsProcessed;
    private bool _sequenceExhausted;
    private bool _disposed;

    internal ulong RecordsRemaining
    {
        get
        {
            ThrowIfUnavailable();
            return _maximumRecords - _recordsProcessed;
        }
    }

    internal Tls13RecordCipher(
        CipherSuiteInfo suite,
        ReadOnlySpan<byte> key,
        ReadOnlySpan<byte> iv,
        ulong initialSequenceNumber = 0,
        ulong? maximumRecords = null)
    {
        _suite = suite ?? throw new ArgumentNullException(nameof(suite));
        if (key.Length != suite.KeyLength)
        {
            throw new ArgumentException("AEAD key length does not match the cipher suite.", nameof(key));
        }
        if (iv.Length != suite.IvLength)
        {
            throw new ArgumentException("AEAD IV length does not match the cipher suite.", nameof(iv));
        }

        _key = key.ToArray();
        _iv = iv.ToArray();
        _sequenceNumber = initialSequenceNumber;
        _maximumRecords = maximumRecords ?? GetConservativeRecordLimit(suite.Suite);
        if (_maximumRecords == 0)
        {
            throw new ArgumentOutOfRangeException(nameof(maximumRecords));
        }

        try
        {
            switch (suite.Suite)
            {
                case TlsCipherSuite.TlsAes128GcmSha256:
                case TlsCipherSuite.TlsAes256GcmSha384:
                    _aesGcm = new AesGcm(_key, TlsConstants.AeadTagLength);
                    break;
                case TlsCipherSuite.TlsChaCha20Poly1305Sha256:
                    if (!ChaCha20Poly1305.IsSupported)
                    {
                        throw new PlatformNotSupportedException(
                            "ChaCha20-Poly1305 is unavailable on this platform.");
                    }
                    _chaCha20Poly1305 = new ChaCha20Poly1305(_key);
                    break;
                default:
                    throw new NotSupportedException($"Cipher suite {suite.Suite} is not implemented.");
            }
        }
        catch
        {
            CryptographicOperations.ZeroMemory(_key);
            CryptographicOperations.ZeroMemory(_iv);
            throw;
        }
    }

    internal byte[] Encrypt(
        TlsContentType contentType,
        ReadOnlySpan<byte> content,
        int paddingLength = 0)
    {
        ThrowIfUnavailable();
        ValidateInnerContentType(contentType);
        if (content.Length > TlsConstants.MaxPlaintextLength)
        {
            throw new ArgumentOutOfRangeException(nameof(content));
        }
        if (paddingLength < 0)
        {
            throw new ArgumentOutOfRangeException(nameof(paddingLength));
        }

        var innerLength = checked(content.Length + 1 + paddingLength);
        if (innerLength > TlsConstants.MaxPlaintextLength + 1)
        {
            throw new ArgumentOutOfRangeException(
                nameof(paddingLength),
                "TLSInnerPlaintext exceeds the TLS 1.3 protocol limit.");
        }
        var encryptedLength = checked(innerLength + TlsConstants.AeadTagLength);
        if (encryptedLength > TlsConstants.MaxCiphertextLength)
        {
            throw new ArgumentOutOfRangeException(nameof(paddingLength), "TLSCiphertext would exceed its limit.");
        }

        var inner = new byte[innerLength];
        content.CopyTo(inner);
        inner[content.Length] = (byte)contentType;

        var encrypted = new byte[encryptedLength];
        var ciphertext = encrypted.AsSpan(0, innerLength);
        var tag = encrypted.AsSpan(innerLength, TlsConstants.AeadTagLength);
        var additionalData = BuildAdditionalData(encryptedLength);
        Span<byte> nonce = stackalloc byte[_suite.IvLength];
        BuildNonce(nonce);

        try
        {
            EncryptCore(nonce, inner, ciphertext, tag, additionalData);
            AdvanceCounters();
            return encrypted;
        }
        catch
        {
            CryptographicOperations.ZeroMemory(encrypted);
            throw;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(inner);
            CryptographicOperations.ZeroMemory(nonce);
        }
    }

    internal TlsInnerPlaintext Decrypt(ReadOnlySpan<byte> encryptedRecord)
    {
        ThrowIfUnavailable();
        if (encryptedRecord.Length is < TlsConstants.AeadTagLength + 1 or > TlsConstants.MaxCiphertextLength)
        {
            throw new TlsProtocolException(
                TlsAlertDescription.RecordOverflow,
                "TLSCiphertext has an invalid protected length.");
        }

        var plaintextLength = encryptedRecord.Length - TlsConstants.AeadTagLength;
        var plaintext = new byte[plaintextLength];
        var ciphertext = encryptedRecord[..plaintextLength];
        var tag = encryptedRecord[plaintextLength..];
        var additionalData = BuildAdditionalData(encryptedRecord.Length);
        Span<byte> nonce = stackalloc byte[_suite.IvLength];
        BuildNonce(nonce);

        try
        {
            DecryptCore(nonce, ciphertext, tag, plaintext, additionalData);
            AdvanceCounters();

            var typeIndex = plaintext.Length - 1;
            while (typeIndex >= 0 && plaintext[typeIndex] == 0)
            {
                typeIndex--;
            }
            if (typeIndex < 0)
            {
                throw TlsProtocolException.Unexpected("TLSInnerPlaintext contains only zero padding.");
            }

            var contentType = ParseInnerContentType(plaintext[typeIndex]);
            var content = plaintext.AsSpan(0, typeIndex).ToArray();
            return new TlsInnerPlaintext(contentType, content, plaintextLength);
        }
        catch (AuthenticationTagMismatchException exception)
        {
            throw new TlsProtocolException(
                TlsAlertDescription.BadRecordMac,
                "TLS record authentication failed.",
                exception);
        }
        catch (CryptographicException exception)
        {
            throw new TlsProtocolException(
                TlsAlertDescription.BadRecordMac,
                "TLS record decryption failed.",
                exception);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(plaintext);
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
        _chaCha20Poly1305?.Dispose();
        CryptographicOperations.ZeroMemory(_key);
        CryptographicOperations.ZeroMemory(_iv);
    }

    private static ulong GetConservativeRecordLimit(TlsCipherSuite suite) => suite switch
    {
        TlsCipherSuite.TlsAes128GcmSha256 or TlsCipherSuite.TlsAes256GcmSha384 => 1UL << 24,
        TlsCipherSuite.TlsChaCha20Poly1305Sha256 => 1UL << 32,
        _ => throw new NotSupportedException(),
    };

    private byte[] BuildAdditionalData(int encryptedLength)
    {
        var writer = new TlsBinaryWriter(TlsConstants.RecordHeaderLength);
        writer.WriteUInt8((byte)TlsContentType.ApplicationData);
        writer.WriteUInt16(TlsConstants.LegacyRecordVersion);
        writer.WriteUInt16((ushort)encryptedLength);
        return writer.ToArray();
    }

    private void BuildNonce(Span<byte> destination)
    {
        _iv.CopyTo(destination);
        Span<byte> paddedSequence = stackalloc byte[_suite.IvLength];
        var offset = paddedSequence.Length - sizeof(ulong);
        paddedSequence[offset] = (byte)(_sequenceNumber >> 56);
        paddedSequence[offset + 1] = (byte)(_sequenceNumber >> 48);
        paddedSequence[offset + 2] = (byte)(_sequenceNumber >> 40);
        paddedSequence[offset + 3] = (byte)(_sequenceNumber >> 32);
        paddedSequence[offset + 4] = (byte)(_sequenceNumber >> 24);
        paddedSequence[offset + 5] = (byte)(_sequenceNumber >> 16);
        paddedSequence[offset + 6] = (byte)(_sequenceNumber >> 8);
        paddedSequence[offset + 7] = (byte)_sequenceNumber;
        for (var index = 0; index < destination.Length; index++)
        {
            destination[index] ^= paddedSequence[index];
        }
    }

    private void AdvanceCounters()
    {
        _recordsProcessed++;
        if (_sequenceNumber == ulong.MaxValue)
        {
            _sequenceExhausted = true;
        }
        else
        {
            _sequenceNumber++;
        }
    }

    private void ThrowIfUnavailable()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (_sequenceExhausted)
        {
            throw new TlsProtocolException(
                TlsAlertDescription.GeneralError,
                "TLS record sequence number is exhausted.");
        }
        if (_recordsProcessed >= _maximumRecords)
        {
            throw new TlsProtocolException(
                TlsAlertDescription.GeneralError,
                "TLS AEAD key-usage limit was reached before a key update.");
        }
    }

    private void EncryptCore(
        ReadOnlySpan<byte> nonce,
        ReadOnlySpan<byte> plaintext,
        Span<byte> ciphertext,
        Span<byte> tag,
        ReadOnlySpan<byte> additionalData)
    {
        if (_aesGcm is not null)
        {
            _aesGcm.Encrypt(nonce, plaintext, ciphertext, tag, additionalData);
        }
        else
        {
            _chaCha20Poly1305!.Encrypt(nonce, plaintext, ciphertext, tag, additionalData);
        }
    }

    private void DecryptCore(
        ReadOnlySpan<byte> nonce,
        ReadOnlySpan<byte> ciphertext,
        ReadOnlySpan<byte> tag,
        Span<byte> plaintext,
        ReadOnlySpan<byte> additionalData)
    {
        if (_aesGcm is not null)
        {
            _aesGcm.Decrypt(nonce, ciphertext, tag, plaintext, additionalData);
        }
        else
        {
            _chaCha20Poly1305!.Decrypt(nonce, ciphertext, tag, plaintext, additionalData);
        }
    }

    private static void ValidateInnerContentType(TlsContentType contentType)
    {
        if (contentType is not (TlsContentType.Alert or TlsContentType.Handshake or
            TlsContentType.ApplicationData))
        {
            throw new ArgumentOutOfRangeException(nameof(contentType));
        }
    }

    private static TlsContentType ParseInnerContentType(byte value) => value switch
    {
        (byte)TlsContentType.Alert => TlsContentType.Alert,
        (byte)TlsContentType.Handshake => TlsContentType.Handshake,
        (byte)TlsContentType.ApplicationData => TlsContentType.ApplicationData,
        _ => throw TlsProtocolException.Unexpected($"Invalid TLSInnerPlaintext content type {value}."),
    };
}
