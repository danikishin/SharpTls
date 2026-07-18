using SharpTls.Protocol;

namespace SharpTls.Records;

internal sealed class TlsRecordReader
{
    private readonly Stream _stream;
    private readonly byte[] _header = new byte[TlsConstants.RecordHeaderLength];

    internal TlsRecordReader(Stream stream)
    {
        _stream = stream ?? throw new ArgumentNullException(nameof(stream));
        if (!stream.CanRead)
        {
            throw new ArgumentException("The TLS transport must be readable.", nameof(stream));
        }
    }

    internal async ValueTask<TlsRecord?> ReadAsync(CancellationToken cancellationToken)
    {
        var headerBytes = await ReadAtMostAsync(_header, cancellationToken).ConfigureAwait(false);
        if (headerBytes == 0)
        {
            return null;
        }

        if (headerBytes != _header.Length)
        {
            throw TlsProtocolException.Decode("Unexpected EOF inside a TLS record header.");
        }

        var contentType = ParseContentType(_header[0]);
        var legacyRecordVersion = (ushort)((_header[1] << 8) | _header[2]);

        var length = (_header[3] << 8) | _header[4];
        var limit = contentType == TlsContentType.ApplicationData
            ? TlsConstants.MaxCiphertextLength
            : TlsConstants.MaxPlaintextLength;

        if (length > limit)
        {
            throw new TlsProtocolException(
                TlsAlertDescription.RecordOverflow,
                $"TLS record length {length} exceeds the {limit}-byte limit.");
        }

        var payload = new byte[length];
        if (length != 0)
        {
            var payloadBytes = await ReadAtMostAsync(payload, cancellationToken).ConfigureAwait(false);
            if (payloadBytes != length)
            {
                throw TlsProtocolException.Decode("Unexpected EOF inside a TLS record fragment.");
            }
        }

        return new TlsRecord(contentType, payload, legacyRecordVersion);
    }

    private async ValueTask<int> ReadAtMostAsync(Memory<byte> destination, CancellationToken cancellationToken)
    {
        var total = 0;
        while (total < destination.Length)
        {
            var read = await _stream.ReadAsync(destination[total..], cancellationToken).ConfigureAwait(false);
            if (read == 0)
            {
                break;
            }

            total += read;
        }

        return total;
    }

    private static TlsContentType ParseContentType(byte value) => value switch
    {
        (byte)TlsContentType.ChangeCipherSpec => TlsContentType.ChangeCipherSpec,
        (byte)TlsContentType.Alert => TlsContentType.Alert,
        (byte)TlsContentType.Handshake => TlsContentType.Handshake,
        (byte)TlsContentType.ApplicationData => TlsContentType.ApplicationData,
        _ => throw TlsProtocolException.Unexpected($"Unknown TLS record content type {value}."),
    };
}
