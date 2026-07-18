using SharpTls.Protocol;

namespace SharpTls.Tests;

public sealed class CallerOwnedTransportTests
{
    [Theory]
    [InlineData(true, false)]
    [InlineData(false, true)]
    public async Task AuthenticateFailureHonorsTransportOwnership(
        bool leaveOpen,
        bool expectDisposed)
    {
        var transport = new TrackingMemoryStream();
        await using var client = new CustomTlsClient(new CustomTlsClientOptions());

        await Assert.ThrowsAsync<TlsProtocolException>(() => client
            .AuthenticateAsync(transport, "example.com", leaveOpen)
            .AsTask());

        Assert.Equal(expectDisposed, transport.WasDisposed);
        if (leaveOpen)
        {
            transport.WriteByte(1);
            transport.Dispose();
        }
    }

    [Fact]
    public async Task ClientInstanceCannotAuthenticateTwiceAfterFailure()
    {
        await using var client = new CustomTlsClient(new CustomTlsClientOptions());
        using var first = new TrackingMemoryStream();
        using var second = new TrackingMemoryStream();
        await Assert.ThrowsAsync<TlsProtocolException>(() => client
            .AuthenticateAsync(first, "example.com", leaveOpen: true)
            .AsTask());

        await Assert.ThrowsAsync<InvalidOperationException>(() => client
            .AuthenticateAsync(second, "example.com", leaveOpen: true)
            .AsTask());
    }

    [Fact]
    public async Task LocalPlaintextProtocolFailureSendsFatalAlert()
    {
        byte[] malformedHandshakeRecord =
        [
            (byte)TlsContentType.Handshake, 3, 3, 0, 0,
        ];
        await using var transport = new ScriptedDuplexStream(malformedHandshakeRecord);
        await using var client = new CustomTlsClient(new CustomTlsClientOptions());

        var exception = await Assert.ThrowsAsync<TlsProtocolException>(() => client
            .AuthenticateAsync(transport, "example.com", leaveOpen: true)
            .AsTask());

        Assert.Equal(TlsAlertDescription.UnexpectedMessage, exception.Alert);
        Assert.True(transport.WrittenBytes.AsSpan().EndsWith(
            new byte[]
            {
                (byte)TlsContentType.Alert, 3, 3, 0, 2,
                2, (byte)TlsAlertDescription.UnexpectedMessage,
            }));
    }

    [Fact]
    public async Task PeerFatalAlertIsNotAnsweredWithAnotherAlert()
    {
        byte[] peerAlertRecord =
        [
            (byte)TlsContentType.Alert, 3, 3, 0, 2,
            2, (byte)TlsAlertDescription.HandshakeFailure,
        ];
        await using var transport = new ScriptedDuplexStream(peerAlertRecord);
        await using var client = new CustomTlsClient(new CustomTlsClientOptions());

        await Assert.ThrowsAsync<TlsProtocolException>(() => client
            .AuthenticateAsync(transport, "example.com", leaveOpen: true)
            .AsTask());

        Assert.DoesNotContain((byte)TlsContentType.Alert, ReadRecordTypes(transport.WrittenBytes));
    }

    [Fact]
    public async Task ClientHelloInspectorReceivesExactDefensiveWireSnapshot()
    {
        TlsClientHelloInspection? inspected = null;
        await using var transport = new ScriptedDuplexStream([]);
        await using var client = new CustomTlsClient(new CustomTlsClientOptions
        {
            ClientHelloInspector = value =>
            {
                inspected = value;
                var hostileCopy = value.GetEncodedHandshake();
                hostileCopy[0] ^= 0xff;
            },
        });

        await Assert.ThrowsAsync<TlsProtocolException>(() => client
            .AuthenticateAsync(transport, "example.com", leaveOpen: true)
            .AsTask());

        Assert.NotNull(inspected);
        Assert.Equal(TlsClientHelloFlight.Initial, inspected.Flight);
        Assert.Equal(TlsClientHelloWireForm.Direct, inspected.WireForm);
        var expectedHandshake = inspected.GetEncodedHandshake();
        Assert.Equal((byte)HandshakeType.ClientHello, expectedHandshake[0]);
        Assert.Equal(expectedHandshake.Length, inspected.EncodedHandshakeLength);

        var wire = transport.WrittenBytes;
        Assert.Equal((byte)TlsContentType.Handshake, wire[0]);
        var firstRecordLength = (wire[3] << 8) | wire[4];
        Assert.Equal(
            expectedHandshake,
            wire.AsSpan(TlsConstants.RecordHeaderLength, firstRecordLength).ToArray());
        Assert.True(wire.AsSpan().StartsWith(inspected.GetEncodedTlsRecords()));
        Assert.Equal([expectedHandshake.Length], inspected.RecordFragmentSizes);
        Assert.Equal(0x0301, inspected.LegacyRecordVersion);
        Assert.Equal(inspected.GetEncodedTlsRecords().Length, inspected.EncodedTlsRecordsLength);
    }

    [Fact]
    public async Task ClientHelloInspectorIncludesExactConfiguredRecordFragmentation()
    {
        TlsClientHelloInspection? inspected = null;
        await using var transport = new ScriptedDuplexStream([]);
        await using var client = new CustomTlsClient(new CustomTlsClientOptions
        {
            HandshakeFragmentation = new TlsRecordFragmentation(11, [1, 2, 3]),
            UseInitialCompatibilityRecordVersion = false,
            ClientHelloInspector = value => inspected = value,
        });

        await Assert.ThrowsAsync<TlsProtocolException>(() => client
            .AuthenticateAsync(transport, "example.com", leaveOpen: true)
            .AsTask());

        Assert.NotNull(inspected);
        Assert.Equal(0x0303, inspected.LegacyRecordVersion);
        Assert.Equal([1, 2, 3], inspected.RecordFragmentSizes.Take(3));
        Assert.All(inspected.RecordFragmentSizes.Skip(3), length => Assert.InRange(length, 1, 11));
        Assert.True(transport.WrittenBytes.AsSpan().StartsWith(inspected.GetEncodedTlsRecords()));

        var hostileCopy = inspected.GetEncodedTlsRecords();
        hostileCopy[0] ^= 0xff;
        Assert.Equal((byte)TlsContentType.Handshake, inspected.GetEncodedTlsRecords()[0]);
    }

    [Fact]
    public async Task ClientHelloInspectorFailurePreventsClientHelloWrite()
    {
        await using var transport = new ScriptedDuplexStream([]);
        await using var client = new CustomTlsClient(new CustomTlsClientOptions
        {
            ClientHelloInspector = _ => throw new InvalidOperationException("inspection rejected"),
        });

        var exception = await Assert.ThrowsAsync<InvalidOperationException>(() => client
            .AuthenticateAsync(transport, "example.com", leaveOpen: true)
            .AsTask());

        Assert.Equal("inspection rejected", exception.Message);
        Assert.Empty(transport.WrittenBytes);
    }

    [Fact]
    public async Task HandshakeEventObserverFailurePreventsClientHelloWrite()
    {
        await using var transport = new ScriptedDuplexStream([]);
        await using var client = new CustomTlsClient(new CustomTlsClientOptions
        {
            HandshakeEventObserver = value =>
            {
                Assert.Equal(TlsHandshakeEventKind.ClientHello, value.Kind);
                Assert.Equal(TlsHandshakeEventDirection.ClientToServer, value.Direction);
                Assert.Equal(TlsClientHelloFlight.Initial, value.ClientHelloFlight);
                throw new InvalidOperationException("event rejected");
            },
        });

        var exception = await Assert.ThrowsAsync<InvalidOperationException>(() => client
            .AuthenticateAsync(transport, "example.com", leaveOpen: true)
            .AsTask());

        Assert.Equal("event rejected", exception.Message);
        Assert.Empty(transport.WrittenBytes);
    }

    private static List<byte> ReadRecordTypes(byte[] wire)
    {
        var result = new List<byte>();
        var offset = 0;
        while (offset < wire.Length)
        {
            Assert.True(wire.Length - offset >= TlsConstants.RecordHeaderLength);
            result.Add(wire[offset]);
            var length = (wire[offset + 3] << 8) | wire[offset + 4];
            offset += TlsConstants.RecordHeaderLength + length;
        }

        Assert.Equal(wire.Length, offset);
        return result;
    }

    private sealed class TrackingMemoryStream : MemoryStream
    {
        internal bool WasDisposed { get; private set; }

        protected override void Dispose(bool disposing)
        {
            WasDisposed = true;
            base.Dispose(disposing);
        }
    }

    private sealed class ScriptedDuplexStream(byte[] incoming) : Stream
    {
        private readonly MemoryStream _written = new();
        private int _readOffset;

        internal byte[] WrittenBytes => _written.ToArray();

        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => true;
        public override long Length => throw new NotSupportedException();
        public override long Position
        {
            get => throw new NotSupportedException();
            set => throw new NotSupportedException();
        }

        public override void Flush()
        {
        }

        public override int Read(byte[] buffer, int offset, int count) =>
            Read(buffer.AsSpan(offset, count));

        public override int Read(Span<byte> buffer)
        {
            var count = Math.Min(buffer.Length, incoming.Length - _readOffset);
            incoming.AsSpan(_readOffset, count).CopyTo(buffer);
            _readOffset += count;
            return count;
        }

        public override ValueTask<int> ReadAsync(
            Memory<byte> buffer,
            CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return ValueTask.FromResult(Read(buffer.Span));
        }

        public override void Write(byte[] buffer, int offset, int count) =>
            _written.Write(buffer, offset, count);

        public override void Write(ReadOnlySpan<byte> buffer) => _written.Write(buffer);

        public override ValueTask WriteAsync(
            ReadOnlyMemory<byte> buffer,
            CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            _written.Write(buffer.Span);
            return ValueTask.CompletedTask;
        }

        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                _written.Dispose();
            }

            base.Dispose(disposing);
        }
    }
}
