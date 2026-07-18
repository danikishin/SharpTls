using System.Security.Cryptography;

namespace SharpTls;

internal interface IApplicationDataTransport : IAsyncDisposable
{
    ValueTask WriteApplicationDataAsync(
        ReadOnlyMemory<byte> data,
        CancellationToken cancellationToken = default);

    ValueTask<byte[]?> ReadApplicationDataAsync(
        CancellationToken cancellationToken = default);
}

/// <summary>
/// Presents authenticated SharpTls application data as a non-seekable byte stream,
/// hiding TLS record boundaries from callers.
/// </summary>
public sealed class CustomTlsStream : Stream
{
    private readonly IApplicationDataTransport _transport;
    private readonly bool _leaveClientOpen;
    private readonly SemaphoreSlim _readLock = new(1, 1);
    private byte[]? _bufferedRead;
    private int _bufferedReadOffset;
    private int _disposed;

    internal CustomTlsStream(IApplicationDataTransport transport, bool leaveClientOpen)
    {
        _transport = transport ?? throw new ArgumentNullException(nameof(transport));
        _leaveClientOpen = leaveClientOpen;
    }

    /// <inheritdoc />
    public override bool CanRead => Volatile.Read(ref _disposed) == 0;

    /// <inheritdoc />
    public override bool CanSeek => false;

    /// <inheritdoc />
    public override bool CanWrite => Volatile.Read(ref _disposed) == 0;

    /// <inheritdoc />
    public override long Length => throw new NotSupportedException();

    /// <inheritdoc />
    public override long Position
    {
        get => throw new NotSupportedException();
        set => throw new NotSupportedException();
    }

    /// <inheritdoc />
    public override void Flush() => ThrowIfDisposed();

    /// <inheritdoc />
    public override Task FlushAsync(CancellationToken cancellationToken)
    {
        ThrowIfDisposed();
        cancellationToken.ThrowIfCancellationRequested();
        return Task.CompletedTask;
    }

    /// <inheritdoc />
    public override int Read(byte[] buffer, int offset, int count)
    {
        ValidateBufferArguments(buffer, offset, count);
        return ReadAsync(buffer.AsMemory(offset, count), CancellationToken.None)
            .AsTask()
            .GetAwaiter()
            .GetResult();
    }

    /// <inheritdoc />
    public override async ValueTask<int> ReadAsync(
        Memory<byte> buffer,
        CancellationToken cancellationToken = default)
    {
        ThrowIfDisposed();
        cancellationToken.ThrowIfCancellationRequested();
        if (buffer.IsEmpty)
        {
            return 0;
        }

        await _readLock.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            ThrowIfDisposed();
            while (_bufferedRead is null || _bufferedReadOffset == _bufferedRead.Length)
            {
                _bufferedRead = await _transport
                    .ReadApplicationDataAsync(cancellationToken)
                    .ConfigureAwait(false);
                _bufferedReadOffset = 0;
                if (_bufferedRead is null)
                {
                    return 0;
                }
                if (_bufferedRead.Length == 0)
                {
                    continue;
                }
            }

            var count = Math.Min(buffer.Length, _bufferedRead.Length - _bufferedReadOffset);
            _bufferedRead.AsMemory(_bufferedReadOffset, count).CopyTo(buffer);
            _bufferedReadOffset += count;
            if (_bufferedReadOffset == _bufferedRead.Length)
            {
                CryptographicOperations.ZeroMemory(_bufferedRead);
                _bufferedRead = null;
                _bufferedReadOffset = 0;
            }

            return count;
        }
        finally
        {
            _readLock.Release();
        }
    }

    /// <inheritdoc />
    public override void Write(byte[] buffer, int offset, int count)
    {
        ValidateBufferArguments(buffer, offset, count);
        WriteAsync(buffer.AsMemory(offset, count), CancellationToken.None)
            .AsTask()
            .GetAwaiter()
            .GetResult();
    }

    /// <inheritdoc />
    public override ValueTask WriteAsync(
        ReadOnlyMemory<byte> buffer,
        CancellationToken cancellationToken = default)
    {
        ThrowIfDisposed();
        cancellationToken.ThrowIfCancellationRequested();
        if (buffer.IsEmpty)
        {
            return ValueTask.CompletedTask;
        }

        return _transport.WriteApplicationDataAsync(buffer, cancellationToken);
    }

    /// <inheritdoc />
    public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();

    /// <inheritdoc />
    public override void SetLength(long value) => throw new NotSupportedException();

    /// <inheritdoc />
    protected override void Dispose(bool disposing)
    {
        if (!disposing || Interlocked.Exchange(ref _disposed, 1) != 0)
        {
            base.Dispose(disposing);
            return;
        }

        try
        {
            if (!_leaveClientOpen)
            {
                _transport.DisposeAsync().AsTask().GetAwaiter().GetResult();
            }
        }
        finally
        {
            ClearBufferedRead();
            base.Dispose(disposing);
        }
    }

    /// <inheritdoc />
    public override async ValueTask DisposeAsync()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0)
        {
            return;
        }

        try
        {
            if (!_leaveClientOpen)
            {
                await _transport.DisposeAsync().ConfigureAwait(false);
            }
        }
        finally
        {
            ClearBufferedRead();
            GC.SuppressFinalize(this);
        }
    }

    private void ThrowIfDisposed() => ObjectDisposedException.ThrowIf(
        Volatile.Read(ref _disposed) != 0,
        this);

    private void ClearBufferedRead()
    {
        if (_bufferedRead is not null)
        {
            CryptographicOperations.ZeroMemory(_bufferedRead);
            _bufferedRead = null;
            _bufferedReadOffset = 0;
        }
    }
}
