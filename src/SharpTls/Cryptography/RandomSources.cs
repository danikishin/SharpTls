using System.Security.Cryptography;

namespace SharpTls.Cryptography;

internal interface IRandomSource
{
    void Fill(Span<byte> destination);
}

internal sealed class SecureRandomSource : IRandomSource
{
    internal static SecureRandomSource Instance { get; } = new();

    private SecureRandomSource()
    {
    }

    public void Fill(Span<byte> destination) => RandomNumberGenerator.Fill(destination);
}

internal sealed class DeterministicRandomSource : IRandomSource, IDisposable
{
    private readonly byte[] _key;
    private uint _counter;
    private bool _disposed;

    internal DeterministicRandomSource(ReadOnlySpan<byte> seed)
    {
        if (seed.IsEmpty)
        {
            throw new ArgumentException("A deterministic test seed cannot be empty.", nameof(seed));
        }

        _key = SHA256.HashData(seed);
    }

    public void Fill(Span<byte> destination)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        var written = 0;
        Span<byte> counterBytes = stackalloc byte[4];

        while (written < destination.Length)
        {
            counterBytes[0] = (byte)(_counter >> 24);
            counterBytes[1] = (byte)(_counter >> 16);
            counterBytes[2] = (byte)(_counter >> 8);
            counterBytes[3] = (byte)_counter;
            _counter = checked(_counter + 1);

            var block = HMACSHA256.HashData(_key, counterBytes);
            var length = Math.Min(block.Length, destination.Length - written);
            block.AsSpan(0, length).CopyTo(destination[written..]);
            CryptographicOperations.ZeroMemory(block);
            written += length;
        }
    }

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;
        CryptographicOperations.ZeroMemory(_key);
    }
}
