using System.Collections.Concurrent;

namespace SharpTls.Tests;

public sealed class CustomTlsStreamTests
{
    [Fact]
    public async Task PartialReadsHideApplicationRecordBoundaries()
    {
        var transport = new FakeApplicationTransport(
            [],
            "abcdef"u8.ToArray(),
            "gh"u8.ToArray(),
            null);
        await using var stream = new CustomTlsStream(transport, leaveClientOpen: true);
        var buffer = new byte[3];

        Assert.Equal(3, await stream.ReadAsync(buffer));
        Assert.Equal("abc"u8.ToArray(), buffer);
        Assert.Equal(3, await stream.ReadAsync(buffer));
        Assert.Equal("def"u8.ToArray(), buffer);
        Assert.Equal(2, await stream.ReadAsync(buffer));
        Assert.Equal("gh"u8.ToArray(), buffer[..2]);
        Assert.Equal(0, await stream.ReadAsync(buffer));
        Assert.Equal(4, transport.ReadCalls);
    }

    [Fact]
    public async Task WritesPreserveByteSequenceAndDelegateFragmentation()
    {
        var transport = new FakeApplicationTransport();
        await using var stream = new CustomTlsStream(transport, leaveClientOpen: true);

        await stream.WriteAsync("hello"u8.ToArray());
        stream.Write(" world"u8.ToArray());

        Assert.Equal("hello world"u8.ToArray(), transport.Writes.SelectMany(value => value));
    }

    [Fact]
    public async Task DisposeHonorsClientOwnershipAndRejectsFurtherIo()
    {
        var owned = new FakeApplicationTransport();
        var ownedStream = new CustomTlsStream(owned, leaveClientOpen: false);
        await ownedStream.DisposeAsync();

        Assert.True(owned.Disposed);
        Assert.Throws<ObjectDisposedException>(ownedStream.Flush);

        var borrowed = new FakeApplicationTransport();
        await using (var borrowedStream = new CustomTlsStream(borrowed, leaveClientOpen: true))
        {
        }

        Assert.False(borrowed.Disposed);
    }

    [Fact]
    public async Task EmptyOperationsDoNotCreateTlsRecordsOrConsumeReads()
    {
        var transport = new FakeApplicationTransport("data"u8.ToArray());
        await using var stream = new CustomTlsStream(transport, leaveClientOpen: true);

        Assert.Equal(0, await stream.ReadAsync(Memory<byte>.Empty));
        await stream.WriteAsync(ReadOnlyMemory<byte>.Empty);

        Assert.Equal(0, transport.ReadCalls);
        Assert.Empty(transport.Writes);
    }

    [Fact]
    public async Task CancellationIsObservedBeforeTransportAccess()
    {
        var transport = new FakeApplicationTransport("data"u8.ToArray());
        await using var stream = new CustomTlsStream(transport, leaveClientOpen: true);
        using var cancellation = new CancellationTokenSource();
        cancellation.Cancel();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
            stream.ReadAsync(new byte[1], cancellation.Token).AsTask());
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
            stream.WriteAsync(new byte[1], cancellation.Token).AsTask());
        Assert.Equal(0, transport.ReadCalls);
        Assert.Empty(transport.Writes);
    }

    [Fact]
    public async Task OneReadAndOneWriteCanProgressConcurrently()
    {
        var transport = new BlockingApplicationTransport();
        await using var stream = new CustomTlsStream(transport, leaveClientOpen: true);
        var readBuffer = new byte[1];

        var readTask = stream.ReadAsync(readBuffer).AsTask();
        await transport.ReadStarted.Task.WaitAsync(TimeSpan.FromSeconds(1));
        var writeTask = stream.WriteAsync("w"u8.ToArray()).AsTask();
        await writeTask.WaitAsync(TimeSpan.FromSeconds(1));
        transport.CompleteRead("r"u8.ToArray());

        Assert.Equal(1, await readTask.WaitAsync(TimeSpan.FromSeconds(1)));
        Assert.Equal((byte)'r', readBuffer[0]);
        Assert.Equal("w"u8.ToArray(), Assert.Single(transport.Writes));
    }

    private sealed class FakeApplicationTransport : IApplicationDataTransport
    {
        private readonly ConcurrentQueue<byte[]?> _reads;

        internal FakeApplicationTransport(params byte[]?[] reads)
        {
            _reads = new ConcurrentQueue<byte[]?>(reads);
        }

        internal List<byte[]> Writes { get; } = [];
        internal int ReadCalls { get; private set; }
        internal bool Disposed { get; private set; }

        public ValueTask WriteApplicationDataAsync(
            ReadOnlyMemory<byte> data,
            CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Writes.Add(data.ToArray());
            return ValueTask.CompletedTask;
        }

        public ValueTask<byte[]?> ReadApplicationDataAsync(
            CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ReadCalls++;
            return ValueTask.FromResult(_reads.TryDequeue(out var value) ? value : null);
        }

        public ValueTask DisposeAsync()
        {
            Disposed = true;
            return ValueTask.CompletedTask;
        }
    }

    private sealed class BlockingApplicationTransport : IApplicationDataTransport
    {
        private readonly TaskCompletionSource<byte[]?> _read = new(
            TaskCreationOptions.RunContinuationsAsynchronously);

        internal TaskCompletionSource ReadStarted { get; } = new(
            TaskCreationOptions.RunContinuationsAsynchronously);

        internal List<byte[]> Writes { get; } = [];

        internal void CompleteRead(byte[] data) => _read.SetResult(data);

        public ValueTask WriteApplicationDataAsync(
            ReadOnlyMemory<byte> data,
            CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Writes.Add(data.ToArray());
            return ValueTask.CompletedTask;
        }

        public async ValueTask<byte[]?> ReadApplicationDataAsync(
            CancellationToken cancellationToken = default)
        {
            ReadStarted.TrySetResult();
            return await _read.Task.WaitAsync(cancellationToken);
        }

        public ValueTask DisposeAsync()
        {
            _read.TrySetCanceled();
            return ValueTask.CompletedTask;
        }
    }
}
