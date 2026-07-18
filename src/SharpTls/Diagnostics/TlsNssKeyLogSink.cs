using System.Security.Cryptography;
using System.Text;

namespace SharpTls;

/// <summary>
/// Explicitly dangerous NSS key-log sink for packet-analysis tools. Lines contain live
/// traffic secrets. The caller owns this sink and must protect its output like private keys.
/// </summary>
public sealed class TlsNssKeyLogSink : IDisposable, IAsyncDisposable
{
    private readonly Stream _output;
    private readonly bool _leaveOpen;
    private readonly SemaphoreSlim _writeLock = new(1, 1);
    private bool _disposed;

    /// <summary>
    /// Creates a serialized NSS key-log sink. Construction fails unless secret exposure is
    /// explicitly acknowledged. The stream must be writable.
    /// </summary>
    public TlsNssKeyLogSink(
        Stream output,
        bool acknowledgeSecretExposure,
        bool leaveOpen = true)
    {
        ArgumentNullException.ThrowIfNull(output);
        if (!acknowledgeSecretExposure)
        {
            throw new ArgumentException(
                "NSS key logging exposes live TLS traffic secrets and requires explicit acknowledgement.",
                nameof(acknowledgeSecretExposure));
        }
        if (!output.CanWrite)
        {
            throw new ArgumentException("The NSS key-log stream must be writable.", nameof(output));
        }

        _output = output;
        _leaveOpen = leaveOpen;
    }

    /// <inheritdoc />
    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }
        _disposed = true;
        if (!_leaveOpen)
        {
            _output.Dispose();
        }
        _writeLock.Dispose();
    }

    /// <inheritdoc />
    public async ValueTask DisposeAsync()
    {
        if (_disposed)
        {
            return;
        }
        _disposed = true;
        if (!_leaveOpen)
        {
            await _output.DisposeAsync().ConfigureAwait(false);
        }
        _writeLock.Dispose();
    }

    internal async ValueTask WriteSecretAsync(
        string label,
        ReadOnlyMemory<byte> clientRandom,
        ReadOnlyMemory<byte> secret,
        CancellationToken cancellationToken)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (string.IsNullOrEmpty(label) || label.Length > 64 ||
            label.Any(character =>
                character != '_' &&
                character is not (>= 'A' and <= 'Z') and not (>= '0' and <= '9')))
        {
            throw new ArgumentException("An NSS key-log label must use uppercase ASCII and underscores.", nameof(label));
        }
        if (clientRandom.Length != 32 || secret.IsEmpty || secret.Length > 64)
        {
            throw new ArgumentException("The NSS key-log random or secret has an invalid length.");
        }

        var labelLength = Encoding.ASCII.GetByteCount(label);
        var line = GC.AllocateUninitializedArray<byte>(
            labelLength + 1 + clientRandom.Length * 2 + 1 + secret.Length * 2 + 1);
        try
        {
            var offset = Encoding.ASCII.GetBytes(label, line);
            line[offset++] = (byte)' ';
            WriteHex(clientRandom.Span, line.AsSpan(offset));
            offset += clientRandom.Length * 2;
            line[offset++] = (byte)' ';
            WriteHex(secret.Span, line.AsSpan(offset));
            offset += secret.Length * 2;
            line[offset] = (byte)'\n';

            await _writeLock.WaitAsync(cancellationToken).ConfigureAwait(false);
            try
            {
                ObjectDisposedException.ThrowIf(_disposed, this);
                await _output.WriteAsync(line, cancellationToken).ConfigureAwait(false);
                await _output.FlushAsync(cancellationToken).ConfigureAwait(false);
            }
            finally
            {
                _writeLock.Release();
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(line);
        }
    }

    private static void WriteHex(ReadOnlySpan<byte> value, Span<byte> destination)
    {
        ReadOnlySpan<byte> alphabet = "0123456789abcdef"u8;
        for (var index = 0; index < value.Length; index++)
        {
            destination[index * 2] = alphabet[value[index] >> 4];
            destination[index * 2 + 1] = alphabet[value[index] & 0x0F];
        }
    }
}
