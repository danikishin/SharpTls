using System.Buffers;
using System.Security.Cryptography;
using SharpTls.Cryptography;
using SharpTls.Protocol;

namespace SharpTls.Handshake;

internal sealed class TranscriptHash : IDisposable
{
    private readonly CipherSuiteInfo _suite;
    private readonly int _maximumCapturedBytes;
    private readonly ArrayBufferWriter<byte>? _captured;
    private IncrementalHash? _hash;

    internal TranscriptHash(CipherSuiteInfo suite, int maximumCapturedBytes = 0)
    {
        _suite = suite;
        if (maximumCapturedBytes < 0)
        {
            throw new ArgumentOutOfRangeException(nameof(maximumCapturedBytes));
        }
        _maximumCapturedBytes = maximumCapturedBytes;
        _captured = maximumCapturedBytes == 0
            ? null
            : new ArrayBufferWriter<byte>(Math.Min(maximumCapturedBytes, 64 * 1024));
        _hash = IncrementalHash.CreateHash(suite.HashAlgorithm);
    }

    internal void Append(ReadOnlySpan<byte> encodedHandshake)
    {
        if (encodedHandshake.Length < TlsConstants.HandshakeHeaderLength)
        {
            throw new ArgumentException("Transcript input must include a handshake header.", nameof(encodedHandshake));
        }

        GetHash().AppendData(encodedHandshake);
        Capture(encodedHandshake);
    }

    internal byte[] CurrentHash()
    {
        var output = new byte[_suite.HashLength];
        GetHash().GetCurrentHash(output);
        return output;
    }

    internal void ResetForHelloRetryRequest(ReadOnlySpan<byte> firstClientHello)
    {
        var firstHash = HashData(_suite.HashAlgorithm, firstClientHello);
        var messageHash = HandshakeMessage.Encode(HandshakeType.MessageHash, firstHash);

        _hash!.Dispose();
        _hash = IncrementalHash.CreateHash(_suite.HashAlgorithm);
        _hash.AppendData(messageHash);
        if (_captured is not null)
        {
            _captured.Clear();
            Capture(messageHash);
        }

        CryptographicOperations.ZeroMemory(firstHash);
    }

    internal TranscriptHash Fork()
    {
        if (_captured is null)
        {
            throw new InvalidOperationException("Transcript capture was not enabled.");
        }

        var fork = new TranscriptHash(_suite, _maximumCapturedBytes);
        if (!_captured.WrittenSpan.IsEmpty)
        {
            fork.Append(_captured.WrittenSpan);
        }
        return fork;
    }

    public void Dispose()
    {
        _hash?.Dispose();
        _hash = null;
    }

    private IncrementalHash GetHash() => _hash ?? throw new ObjectDisposedException(nameof(TranscriptHash));

    private void Capture(ReadOnlySpan<byte> data)
    {
        if (_captured is null)
        {
            return;
        }
        if (data.Length > _maximumCapturedBytes - _captured.WrittenCount)
        {
            throw new TlsProtocolException(
                TlsAlertDescription.InternalError,
                "The TLS handshake transcript exceeds the configured capture limit.");
        }

        data.CopyTo(_captured.GetSpan(data.Length));
        _captured.Advance(data.Length);
    }

    private static byte[] HashData(HashAlgorithmName algorithm, ReadOnlySpan<byte> data) => algorithm.Name switch
    {
        "SHA256" => SHA256.HashData(data),
        "SHA384" => SHA384.HashData(data),
        _ => throw new NotSupportedException($"Hash algorithm {algorithm.Name} is not supported."),
    };
}
