using System.Security.Cryptography;
using SharpTls.Protocol;

namespace SharpTls.Cryptography;

internal sealed class X25519KeyShare : IKeyShare
{
    private readonly byte[] _privateKey;
    private readonly byte[] _publicKey;
    private bool _disposed;
    private bool _agreementPerformed;

    private X25519KeyShare(byte[] privateKey)
    {
        _privateKey = privateKey;
        _publicKey = new byte[X25519.KeyLength];
        X25519.DerivePublicKey(_privateKey, _publicKey);
    }

    public NamedGroup Group => NamedGroup.X25519;

    public ReadOnlyMemory<byte> PublicKey
    {
        get
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            return _publicKey;
        }
    }

    internal static X25519KeyShare Create()
    {
        var privateKey = RandomNumberGenerator.GetBytes(X25519.KeyLength);
        return new X25519KeyShare(privateKey);
    }

    internal static X25519KeyShare CreateDeterministicForTesting()
    {
        var privateKey = new byte[X25519.KeyLength];
        for (var index = 0; index < privateKey.Length; index++)
        {
            privateKey[index] = (byte)(index + 1);
        }

        return new X25519KeyShare(privateKey);
    }

    public byte[] DeriveSharedSecret(ReadOnlySpan<byte> peerKeyExchange)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (_agreementPerformed)
        {
            throw new InvalidOperationException("A key share can perform agreement only once.");
        }
        if (peerKeyExchange.Length != X25519.KeyLength)
        {
            throw TlsProtocolException.Illegal("An X25519 peer key share must contain exactly 32 bytes.");
        }

        var secret = new byte[X25519.KeyLength];
        X25519.ScalarMultiply(_privateKey, peerKeyExchange, secret);
        Span<byte> zero = stackalloc byte[X25519.KeyLength];
        zero.Clear();
        if (CryptographicOperations.FixedTimeEquals(secret, zero))
        {
            CryptographicOperations.ZeroMemory(secret);
            throw TlsProtocolException.Illegal("The X25519 peer key share produced the all-zero shared secret.");
        }

        _agreementPerformed = true;
        return secret;
    }

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;
        CryptographicOperations.ZeroMemory(_privateKey);
        CryptographicOperations.ZeroMemory(_publicKey);
    }
}
