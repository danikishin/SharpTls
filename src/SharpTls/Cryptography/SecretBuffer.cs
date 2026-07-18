using System.Security.Cryptography;

namespace SharpTls.Cryptography;

internal sealed class SecretBuffer : IDisposable
{
    private byte[]? _value;

    internal SecretBuffer(ReadOnlySpan<byte> value)
    {
        _value = value.ToArray();
    }

    internal ReadOnlySpan<byte> Span => _value ?? throw new ObjectDisposedException(nameof(SecretBuffer));

    internal byte[] Copy() => Span.ToArray();

    public void Dispose()
    {
        var value = Interlocked.Exchange(ref _value, null);
        if (value is not null)
        {
            CryptographicOperations.ZeroMemory(value);
        }
    }
}
