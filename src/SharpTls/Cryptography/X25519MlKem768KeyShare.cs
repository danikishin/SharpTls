using System.Security.Cryptography;
using SharpTls.Protocol;

namespace SharpTls.Cryptography;

/// <summary>Client-side X25519MLKEM768 hybrid key share.</summary>
internal sealed class X25519MlKem768KeyShare : IKeyShare
{
    internal const int ClientShareSize = MlKem768.EncapsulationKeySize + X25519.KeyLength;
    internal const int ServerShareSize = MlKem768.CiphertextSize + X25519.KeyLength;
    internal const int HybridSecretSize = MlKem768.SharedSecretSize + X25519.KeyLength;

    private readonly MlKem768.KeyPair _mlKemKey;
    private readonly X25519KeyShare _x25519Key;
    private readonly byte[] _publicKey;
    private bool _disposed;
    private bool _agreementPerformed;

    private X25519MlKem768KeyShare(
        MlKem768.KeyPair mlKemKey,
        X25519KeyShare x25519Key)
    {
        _mlKemKey = mlKemKey;
        _x25519Key = x25519Key;
        _publicKey = new byte[ClientShareSize];
        var mlKemPublic = mlKemKey.ExportEncapsulationKey();
        try
        {
            mlKemPublic.CopyTo(_publicKey, 0);
            x25519Key.PublicKey.Span.CopyTo(_publicKey.AsSpan(MlKem768.EncapsulationKeySize));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(mlKemPublic);
        }
    }

    public NamedGroup Group => NamedGroup.X25519MlKem768;

    public ReadOnlyMemory<byte> PublicKey
    {
        get
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            return _publicKey;
        }
    }

    internal static X25519MlKem768KeyShare Create(X25519KeyShare? x25519Key = null) =>
        new(MlKem768.GenerateKey(), x25519Key ?? X25519KeyShare.Create());

    internal static X25519MlKem768KeyShare CreateDeterministicForTesting(
        X25519KeyShare? x25519Key = null)
    {
        var seed = new byte[MlKem768.SeedSize];
        for (var index = 0; index < seed.Length; index++)
        {
            seed[index] = (byte)(index + 1);
        }
        try
        {
            return new X25519MlKem768KeyShare(
                MlKem768.GenerateKeyDeterministicForTesting(seed),
                x25519Key ?? X25519KeyShare.CreateDeterministicForTesting());
        }
        finally
        {
            CryptographicOperations.ZeroMemory(seed);
        }
    }

    public byte[] DeriveSharedSecret(ReadOnlySpan<byte> peerKeyExchange)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (_agreementPerformed)
        {
            throw new InvalidOperationException("A key share can perform agreement only once.");
        }
        if (peerKeyExchange.Length != ServerShareSize)
        {
            throw TlsProtocolException.Illegal(
                $"An X25519MLKEM768 server key share must contain exactly {ServerShareSize} bytes.");
        }

        byte[]? mlKemSecret = null;
        byte[]? x25519Secret = null;
        try
        {
            mlKemSecret = _mlKemKey.Decapsulate(peerKeyExchange[..MlKem768.CiphertextSize]);
            x25519Secret = _x25519Key.DeriveSharedSecret(
                peerKeyExchange[MlKem768.CiphertextSize..]);
            var result = new byte[HybridSecretSize];
            mlKemSecret.CopyTo(result, 0);
            x25519Secret.CopyTo(result, MlKem768.SharedSecretSize);
            _agreementPerformed = true;
            return result;
        }
        catch (TlsProtocolException)
        {
            throw;
        }
        catch (CryptographicException exception)
        {
            throw new TlsProtocolException(
                TlsAlertDescription.IllegalParameter,
                "The X25519MLKEM768 server key share is invalid.",
                exception);
        }
        finally
        {
            if (mlKemSecret is not null)
            {
                CryptographicOperations.ZeroMemory(mlKemSecret);
            }
            if (x25519Secret is not null)
            {
                CryptographicOperations.ZeroMemory(x25519Secret);
            }
        }
    }

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }
        _disposed = true;
        _mlKemKey.Dispose();
        _x25519Key.Dispose();
        CryptographicOperations.ZeroMemory(_publicKey);
    }
}
