namespace SharpTls.Quic;

/// <summary>
/// Bounded offset-aware CRYPTO stream reassembly. Matching retransmissions are accepted;
/// conflicting overlaps and data extending a discarded level fail closed.
/// </summary>
internal sealed class TlsQuicCryptoStreamReassembler
{
    private readonly int _maximumLength;
    private byte[] _bytes = [];
    private byte[] _received = [];
    private int _deliveredLength;
    private int _highestReceivedEnd;
    private bool _discarded;

    internal TlsQuicCryptoStreamReassembler(int maximumLength)
    {
        if (maximumLength is < 1024 or > 32 * 1024 * 1024)
        {
            throw new ArgumentOutOfRangeException(nameof(maximumLength));
        }
        _maximumLength = maximumLength;
    }

    internal int DeliveredLength => _deliveredLength;

    internal byte[] Add(ulong offset, ReadOnlySpan<byte> data)
    {
        if (offset > int.MaxValue || data.Length > _maximumLength ||
            offset > (ulong)(_maximumLength - data.Length))
        {
            throw new TlsQuicTransportException(
                TlsQuicTransportError.CryptoBufferExceeded,
                "CRYPTO stream data exceeds the configured buffer limit.");
        }
        var start = checked((int)offset);
        var end = start + data.Length;
        if (_discarded && end > _highestReceivedEnd)
        {
            throw new TlsQuicTransportException(
                TlsQuicTransportError.ProtocolViolation,
                "A discarded CRYPTO level received new data.");
        }
        EnsureCapacity(end);
        for (var index = 0; index < data.Length; index++)
        {
            var destinationIndex = start + index;
            if (_received[destinationIndex] != 0)
            {
                if (_bytes[destinationIndex] != data[index])
                {
                    throw new TlsQuicTransportException(
                        TlsQuicTransportError.ProtocolViolation,
                        "Overlapping CRYPTO data does not match the prior bytes.");
                }
                continue;
            }
            if (_discarded)
            {
                throw new TlsQuicTransportException(
                    TlsQuicTransportError.ProtocolViolation,
                    "A discarded CRYPTO level filled a previously missing range.");
            }
            _bytes[destinationIndex] = data[index];
            _received[destinationIndex] = 1;
        }
        _highestReceivedEnd = Math.Max(_highestReceivedEnd, end);

        var contiguousEnd = _deliveredLength;
        while (contiguousEnd < _highestReceivedEnd && _received[contiguousEnd] != 0)
        {
            contiguousEnd++;
        }
        if (contiguousEnd == _deliveredLength)
        {
            return [];
        }
        var result = _bytes.AsSpan(
            _deliveredLength,
            contiguousEnd - _deliveredLength).ToArray();
        _deliveredLength = contiguousEnd;
        return result;
    }

    internal void Discard()
    {
        if (_discarded)
        {
            return;
        }
        if (_deliveredLength != _highestReceivedEnd)
        {
            throw new TlsQuicTransportException(
                TlsQuicTransportError.ProtocolViolation,
                "A CRYPTO level was discarded with an undelivered gap.");
        }
        _discarded = true;
    }

    private void EnsureCapacity(int required)
    {
        if (required <= _bytes.Length)
        {
            return;
        }
        var capacity = Math.Min(
            _maximumLength,
            Math.Max(required, Math.Max(1024, _bytes.Length * 2)));
        Array.Resize(ref _bytes, capacity);
        Array.Resize(ref _received, capacity);
    }
}
