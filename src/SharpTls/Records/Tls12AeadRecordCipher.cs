using System.Security.Cryptography;
using SharpTls.Cryptography;
using SharpTls.IO;
using SharpTls.Protocol;

namespace SharpTls.Records;

internal sealed class Tls12AeadRecordCipher : IDisposable
{
    private readonly Tls12CipherSuiteInfo _suite;
    private readonly byte[] _key;
    private readonly byte[] _fixedIv;
    private readonly AesGcm? _aesGcm;
    private readonly ChaCha20Poly1305? _chaCha20Poly1305;
    private readonly ulong _maximumRecords;
    private ulong _sequenceNumber;
    private ulong _recordsProcessed;
    private bool _sequenceExhausted;
    private bool _disposed;

    internal Tls12AeadRecordCipher(
        Tls12CipherSuiteInfo suite,
        ReadOnlySpan<byte> key,
        ReadOnlySpan<byte> fixedIv,
        ulong initialSequenceNumber = 0,
        ulong? maximumRecords = null)
    {
        _suite = suite ?? throw new ArgumentNullException(nameof(suite));
        if (key.Length != suite.KeyLength)
        {
            throw new ArgumentException("AEAD key length does not match the TLS 1.2 suite.", nameof(key));
        }
        if (fixedIv.Length != suite.FixedIvLength)
        {
            throw new ArgumentException("Fixed IV length does not match the TLS 1.2 suite.", nameof(fixedIv));
        }

        _key = key.ToArray();
        _fixedIv = fixedIv.ToArray();
        _sequenceNumber = initialSequenceNumber;
        _maximumRecords = maximumRecords ?? GetConservativeRecordLimit(suite.AeadAlgorithm);
        if (_maximumRecords == 0)
        {
            throw new ArgumentOutOfRangeException(nameof(maximumRecords));
        }

        try
        {
            if (suite.AeadAlgorithm == Tls12AeadAlgorithm.AesGcm)
            {
                _aesGcm = new AesGcm(_key, TlsConstants.AeadTagLength);
            }
            else
            {
                if (!ChaCha20Poly1305.IsSupported)
                {
                    throw new PlatformNotSupportedException(
                        "ChaCha20-Poly1305 is unavailable on this platform.");
                }

                _chaCha20Poly1305 = new ChaCha20Poly1305(_key);
            }
        }
        catch
        {
            CryptographicOperations.ZeroMemory(_key);
            CryptographicOperations.ZeroMemory(_fixedIv);
            throw;
        }
    }

    internal ulong RecordsRemaining
    {
        get
        {
            ThrowIfUnavailable();
            return _maximumRecords - _recordsProcessed;
        }
    }

    internal byte[] Encrypt(
        TlsContentType contentType,
        ReadOnlySpan<byte> plaintext,
        ushort recordVersion = TlsConstants.Tls12Version)
    {
        ThrowIfUnavailable();
        ValidateContentType(contentType);
        ValidateRecordVersion(recordVersion);
        if (plaintext.Length > TlsConstants.MaxPlaintextLength)
        {
            throw new ArgumentOutOfRangeException(nameof(plaintext));
        }

        var fragmentLength = checked(
            _suite.ExplicitNonceLength + plaintext.Length + TlsConstants.AeadTagLength);
        if (fragmentLength > TlsConstants.MaxCiphertextLength)
        {
            throw new ArgumentOutOfRangeException(nameof(plaintext));
        }

        var fragment = new byte[fragmentLength];
        var explicitNonce = fragment.AsSpan(0, _suite.ExplicitNonceLength);
        var ciphertext = fragment.AsSpan(_suite.ExplicitNonceLength, plaintext.Length);
        var tag = fragment.AsSpan(
            _suite.ExplicitNonceLength + plaintext.Length,
            TlsConstants.AeadTagLength);
        Span<byte> nonce = stackalloc byte[12];
        Span<byte> additionalData = stackalloc byte[TlsConstants.Tls12AeadAdditionalDataLength];
        if (_suite.AeadAlgorithm == Tls12AeadAlgorithm.AesGcm)
        {
            WriteSequenceNumber(explicitNonce);
        }
        BuildNonce(nonce, explicitNonce);
        BuildAdditionalData(additionalData, contentType, recordVersion, plaintext.Length);

        try
        {
            EncryptCore(nonce, plaintext, ciphertext, tag, additionalData);
            AdvanceCounters();
            return fragment;
        }
        catch
        {
            CryptographicOperations.ZeroMemory(fragment);
            throw;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(nonce);
            CryptographicOperations.ZeroMemory(additionalData);
        }
    }

    internal byte[] Decrypt(
        TlsContentType contentType,
        ReadOnlySpan<byte> fragment,
        ushort recordVersion = TlsConstants.Tls12Version)
    {
        ThrowIfUnavailable();
        ValidateContentType(contentType);
        ValidateRecordVersion(recordVersion);

        var overhead = _suite.ExplicitNonceLength + TlsConstants.AeadTagLength;
        if (fragment.Length < overhead || fragment.Length > TlsConstants.MaxCiphertextLength)
        {
            throw new TlsProtocolException(
                fragment.Length > TlsConstants.MaxCiphertextLength
                    ? TlsAlertDescription.RecordOverflow
                    : TlsAlertDescription.BadRecordMac,
                "TLS 1.2 AEAD record has an invalid protected length.");
        }

        var plaintextLength = fragment.Length - overhead;
        if (plaintextLength > TlsConstants.MaxPlaintextLength)
        {
            throw new TlsProtocolException(
                TlsAlertDescription.RecordOverflow,
                "TLS 1.2 plaintext would exceed the protocol limit.");
        }

        var explicitNonce = fragment[.._suite.ExplicitNonceLength];
        var ciphertext = fragment.Slice(_suite.ExplicitNonceLength, plaintextLength);
        var tag = fragment[^TlsConstants.AeadTagLength..];
        var plaintext = new byte[plaintextLength];
        Span<byte> nonce = stackalloc byte[12];
        Span<byte> additionalData = stackalloc byte[TlsConstants.Tls12AeadAdditionalDataLength];
        BuildNonce(nonce, explicitNonce);
        BuildAdditionalData(additionalData, contentType, recordVersion, plaintextLength);

        try
        {
            DecryptCore(nonce, ciphertext, tag, plaintext, additionalData);
            AdvanceCounters();
            return plaintext;
        }
        catch (AuthenticationTagMismatchException exception)
        {
            CryptographicOperations.ZeroMemory(plaintext);
            throw new TlsProtocolException(
                TlsAlertDescription.BadRecordMac,
                "TLS 1.2 record authentication failed.",
                exception);
        }
        catch (CryptographicException exception)
        {
            CryptographicOperations.ZeroMemory(plaintext);
            throw new TlsProtocolException(
                TlsAlertDescription.BadRecordMac,
                "TLS 1.2 record decryption failed.",
                exception);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(nonce);
            CryptographicOperations.ZeroMemory(additionalData);
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
        CryptographicOperations.ZeroMemory(_fixedIv);
    }

    private void BuildNonce(Span<byte> nonce, ReadOnlySpan<byte> explicitNonce)
    {
        if (_suite.AeadAlgorithm == Tls12AeadAlgorithm.AesGcm)
        {
            _fixedIv.CopyTo(nonce);
            explicitNonce.CopyTo(nonce[_suite.FixedIvLength..]);
            return;
        }

        _fixedIv.CopyTo(nonce);
        Span<byte> paddedSequence = stackalloc byte[12];
        WriteSequenceNumber(paddedSequence[4..]);
        for (var index = 0; index < nonce.Length; index++)
        {
            nonce[index] ^= paddedSequence[index];
        }
        CryptographicOperations.ZeroMemory(paddedSequence);
    }

    private void BuildAdditionalData(
        Span<byte> destination,
        TlsContentType contentType,
        ushort recordVersion,
        int plaintextLength)
    {
        var writer = new TlsBinaryWriter(TlsConstants.Tls12AeadAdditionalDataLength);
        writer.WriteUInt64(_sequenceNumber);
        writer.WriteUInt8((byte)contentType);
        writer.WriteUInt16(recordVersion);
        writer.WriteUInt16((ushort)plaintextLength);
        writer.WrittenSpan.CopyTo(destination);
    }

    private void WriteSequenceNumber(Span<byte> destination)
    {
        if (destination.Length != sizeof(ulong))
        {
            throw new InvalidOperationException("TLS sequence-number destination must be eight bytes.");
        }

        destination[0] = (byte)(_sequenceNumber >> 56);
        destination[1] = (byte)(_sequenceNumber >> 48);
        destination[2] = (byte)(_sequenceNumber >> 40);
        destination[3] = (byte)(_sequenceNumber >> 32);
        destination[4] = (byte)(_sequenceNumber >> 24);
        destination[5] = (byte)(_sequenceNumber >> 16);
        destination[6] = (byte)(_sequenceNumber >> 8);
        destination[7] = (byte)_sequenceNumber;
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
                "TLS 1.2 record sequence number is exhausted.");
        }
        if (_recordsProcessed >= _maximumRecords)
        {
            throw new TlsProtocolException(
                TlsAlertDescription.GeneralError,
                "TLS 1.2 AEAD key-usage limit was reached; the connection must be closed.");
        }
    }

    private static ulong GetConservativeRecordLimit(Tls12AeadAlgorithm algorithm) => algorithm switch
    {
        Tls12AeadAlgorithm.AesGcm => 1UL << 24,
        Tls12AeadAlgorithm.ChaCha20Poly1305 => 1UL << 32,
        _ => throw new NotSupportedException(),
    };

    private static void ValidateRecordVersion(ushort recordVersion)
    {
        if (recordVersion != TlsConstants.Tls12Version)
        {
            throw new TlsProtocolException(
                TlsAlertDescription.ProtocolVersion,
                $"TLS 1.2 AEAD records require version 0x0303, received 0x{recordVersion:X4}.");
        }
    }

    private static void ValidateContentType(TlsContentType contentType)
    {
        if (contentType is not (TlsContentType.Alert or TlsContentType.Handshake or
            TlsContentType.ApplicationData))
        {
            throw new ArgumentOutOfRangeException(nameof(contentType));
        }
    }
}
