using SharpTls.IO;
using SharpTls.Protocol;

namespace SharpTls.Records;

internal sealed class TlsRecordWriter
{
    private readonly Stream _stream;

    internal TlsRecordWriter(Stream stream)
    {
        _stream = stream ?? throw new ArgumentNullException(nameof(stream));
        if (!stream.CanWrite)
        {
            throw new ArgumentException("The TLS transport must be writable.", nameof(stream));
        }
    }

    internal async ValueTask WriteFragmentedAsync(
        TlsContentType contentType,
        ReadOnlyMemory<byte> plaintext,
        TlsRecordFragmentation fragmentation,
        CancellationToken cancellationToken,
        ushort legacyRecordVersion = TlsConstants.LegacyRecordVersion)
    {
        ArgumentNullException.ThrowIfNull(fragmentation);

        if (plaintext.IsEmpty)
        {
            await WriteRecordAsync(contentType, plaintext, cancellationToken, legacyRecordVersion)
                .ConfigureAwait(false);
            return;
        }

        var offset = 0;
        var recordIndex = 0;
        while (offset < plaintext.Length)
        {
            var length = fragmentation.GetNextSize(recordIndex++, plaintext.Length - offset);
            await WriteRecordAsync(
                    contentType,
                    plaintext.Slice(offset, length),
                    cancellationToken,
                    legacyRecordVersion)
                .ConfigureAwait(false);
            offset += length;
        }
    }

    internal async ValueTask WriteRecordAsync(
        TlsContentType contentType,
        ReadOnlyMemory<byte> fragment,
        CancellationToken cancellationToken,
        ushort legacyRecordVersion = TlsConstants.LegacyRecordVersion)
    {
        var limit = contentType == TlsContentType.ApplicationData
            ? TlsConstants.MaxCiphertextLength
            : TlsConstants.MaxPlaintextLength;
        if (fragment.Length > limit)
        {
            throw new ArgumentOutOfRangeException(nameof(fragment));
        }

        var writer = new TlsBinaryWriter(TlsConstants.RecordHeaderLength + fragment.Length);
        writer.WriteUInt8((byte)contentType);
        writer.WriteUInt16(legacyRecordVersion);
        writer.WriteUInt16((ushort)fragment.Length);
        writer.WriteBytes(fragment.Span);

        await _stream.WriteAsync(writer.ToArray(), cancellationToken).ConfigureAwait(false);
    }
}
