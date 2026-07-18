using SharpTls.Protocol;
using SharpTls.Records;

namespace SharpTls.Tests.Records;

public sealed class TlsRecordLayerTests
{
    [Fact]
    public async Task ReaderHandlesOneByteReads()
    {
        byte[] wire = [(byte)TlsContentType.Handshake, 3, 3, 0, 3, 1, 2, 3];
        await using var stream = new ChunkedReadStream(wire, 1);
        var reader = new TlsRecordReader(stream);

        var record = await reader.ReadAsync(CancellationToken.None);

        Assert.NotNull(record);
        Assert.Equal(TlsContentType.Handshake, record.ContentType);
        Assert.Equal([1, 2, 3], record.Fragment);
        Assert.Equal((ushort)0x0303, record.LegacyRecordVersion);
        Assert.Null(await reader.ReadAsync(CancellationToken.None));
    }

    [Theory]
    [InlineData(1)]
    [InlineData(2)]
    [InlineData(3)]
    [InlineData(4)]
    [InlineData(6)]
    [InlineData(7)]
    public async Task EofInsideRecordFailsClosed(int availableBytes)
    {
        byte[] complete = [(byte)TlsContentType.Handshake, 3, 3, 0, 3, 1, 2, 3];
        await using var stream = new ChunkedReadStream(complete[..availableBytes], 2);
        var reader = new TlsRecordReader(stream);

        var exception = await Assert.ThrowsAsync<TlsProtocolException>(async () =>
            await reader.ReadAsync(CancellationToken.None));
        Assert.Equal(TlsAlertDescription.DecodeError, exception.Alert);
    }

    [Fact]
    public async Task OversizedPlaintextRecordIsRejectedBeforeAllocation()
    {
        byte[] header = [(byte)TlsContentType.Handshake, 3, 3, 0x40, 0x01];
        await using var stream = new ChunkedReadStream(header, header.Length);
        var reader = new TlsRecordReader(stream);

        var exception = await Assert.ThrowsAsync<TlsProtocolException>(async () =>
            await reader.ReadAsync(CancellationToken.None));
        Assert.Equal(TlsAlertDescription.RecordOverflow, exception.Alert);
    }

    [Theory]
    [InlineData(19)]
    [InlineData(24)]
    [InlineData(255)]
    public async Task UnknownContentTypeIsRejected(byte contentType)
    {
        byte[] wire = [contentType, 3, 3, 0, 0];
        await using var stream = new ChunkedReadStream(wire, wire.Length);
        var reader = new TlsRecordReader(stream);

        var exception = await Assert.ThrowsAsync<TlsProtocolException>(async () =>
            await reader.ReadAsync(CancellationToken.None));
        Assert.Equal(TlsAlertDescription.UnexpectedMessage, exception.Alert);
    }

    [Fact]
    public async Task WriterPreservesExplicitFragmentPattern()
    {
        await using var stream = new MemoryStream();
        var writer = new TlsRecordWriter(stream);
        var policy = new TlsRecordFragmentation(4, [1, 2]);

        await writer.WriteFragmentedAsync(
            TlsContentType.Handshake,
            new byte[] { 10, 11, 12, 13, 14, 15, 16, 17 },
            policy,
            CancellationToken.None);

        Assert.Equal(
            new byte[]
            {
                22, 3, 3, 0, 1, 10,
                22, 3, 3, 0, 2, 11, 12,
                22, 3, 3, 0, 4, 13, 14, 15, 16,
                22, 3, 3, 0, 1, 17,
            },
            stream.ToArray());
    }

    [Fact]
    public async Task CancellationIsPropagated()
    {
        await using var stream = new CancelAwareStream();
        var reader = new TlsRecordReader(stream);
        using var cancellation = new CancellationTokenSource();
        cancellation.Cancel();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(async () =>
            await reader.ReadAsync(cancellation.Token));
    }

    private sealed class ChunkedReadStream(byte[] input, int chunkSize) : Stream
    {
        private int _offset;

        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length => input.Length;
        public override long Position { get => _offset; set => throw new NotSupportedException(); }
        public override void Flush() { }
        public override int Read(byte[] buffer, int offset, int count) =>
            Read(buffer.AsSpan(offset, count));

        public override int Read(Span<byte> buffer)
        {
            var length = Math.Min(Math.Min(buffer.Length, chunkSize), input.Length - _offset);
            input.AsSpan(_offset, length).CopyTo(buffer);
            _offset += length;
            return length;
        }

        public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return ValueTask.FromResult(Read(buffer.Span));
        }

        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    }

    private sealed class CancelAwareStream : Stream
    {
        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length => throw new NotSupportedException();
        public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
        public override void Flush() => throw new NotSupportedException();
        public override int Read(byte[] buffer, int offset, int count) => throw new NotSupportedException();
        public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default) =>
            ValueTask.FromCanceled<int>(cancellationToken);
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    }
}
