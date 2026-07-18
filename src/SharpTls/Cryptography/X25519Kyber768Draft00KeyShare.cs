using System.Security.Cryptography;
using SharpTls.Protocol;

namespace SharpTls.Cryptography;

/// <summary>
/// Client-side compatibility implementation of the obsolete
/// X25519Kyber768Draft00 construction used by historical Chromium/uTLS profiles.
/// It intentionally differs from X25519MLKEM768 in component order and KEM output
/// derivation and must not be used as a substitute for the standardized group.
/// </summary>
internal sealed class X25519Kyber768Draft00KeyShare : IKeyShare
{
    internal const int ClientShareSize = X25519.KeyLength + MlKem768.EncapsulationKeySize;
    internal const int ServerShareSize = X25519.KeyLength + MlKem768.CiphertextSize;
    internal const int HybridSecretSize = X25519.KeyLength + MlKem768.SharedSecretSize;

    private readonly MlKem768.KeyPair _mlKemKey;
    private readonly X25519KeyShare _x25519Key;
    private readonly byte[] _publicKey;
    private bool _disposed;
    private bool _agreementPerformed;

    private X25519Kyber768Draft00KeyShare(
        MlKem768.KeyPair mlKemKey,
        X25519KeyShare x25519Key)
    {
        _mlKemKey = mlKemKey;
        _x25519Key = x25519Key;
        _publicKey = new byte[ClientShareSize];
        x25519Key.PublicKey.Span.CopyTo(_publicKey);
        var mlKemPublic = mlKemKey.ExportEncapsulationKey();
        try
        {
            mlKemPublic.CopyTo(_publicKey, X25519.KeyLength);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(mlKemPublic);
        }
    }

    public NamedGroup Group => NamedGroup.X25519Kyber768Draft00;

    public ReadOnlyMemory<byte> PublicKey
    {
        get
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            return _publicKey;
        }
    }

    internal static X25519Kyber768Draft00KeyShare Create(
        X25519KeyShare? x25519Key = null) =>
        new(MlKem768.GenerateKey(), x25519Key ?? X25519KeyShare.Create());

    internal static X25519Kyber768Draft00KeyShare CreateDeterministicForTesting(
        X25519KeyShare? x25519Key = null)
    {
        var seed = new byte[MlKem768.SeedSize];
        for (var index = 0; index < seed.Length; index++)
        {
            seed[index] = (byte)(index + 1);
        }
        try
        {
            return new X25519Kyber768Draft00KeyShare(
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
                $"An X25519Kyber768Draft00 server key share must contain exactly " +
                $"{ServerShareSize} bytes.");
        }

        byte[]? x25519Secret = null;
        byte[]? mlKemSecret = null;
        byte[]? kyberSecret = null;
        try
        {
            x25519Secret = _x25519Key.DeriveSharedSecret(
                peerKeyExchange[..X25519.KeyLength]);
            mlKemSecret = _mlKemKey.Decapsulate(peerKeyExchange[X25519.KeyLength..]);
            kyberSecret = TransformSharedSecret(
                mlKemSecret,
                peerKeyExchange[X25519.KeyLength..]);

            var result = new byte[HybridSecretSize];
            x25519Secret.CopyTo(result, 0);
            kyberSecret.CopyTo(result, X25519.KeyLength);
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
                "The X25519Kyber768Draft00 server key share is invalid.",
                exception);
        }
        finally
        {
            Zero(x25519Secret);
            Zero(mlKemSecret);
            Zero(kyberSecret);
        }
    }

    internal static byte[] TransformSharedSecret(
        ReadOnlySpan<byte> mlKemSharedSecret,
        ReadOnlySpan<byte> ciphertext)
    {
        if (mlKemSharedSecret.Length != MlKem768.SharedSecretSize ||
            ciphertext.Length != MlKem768.CiphertextSize)
        {
            throw new ArgumentException("Kyber768 compatibility inputs have invalid lengths.");
        }
        var ciphertextHash = Fips202.Sha3_256(ciphertext);
        var input = new byte[MlKem768.SharedSecretSize + ciphertextHash.Length];
        try
        {
            mlKemSharedSecret.CopyTo(input);
            ciphertextHash.CopyTo(input, MlKem768.SharedSecretSize);
            return Fips202.Shake256(input, MlKem768.SharedSecretSize);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(ciphertextHash);
            CryptographicOperations.ZeroMemory(input);
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

    private static void Zero(byte[]? value)
    {
        if (value is not null)
        {
            CryptographicOperations.ZeroMemory(value);
        }
    }
}
