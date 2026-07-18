using System.Security.Cryptography;
using SharpTls.Protocol;

namespace SharpTls.Cryptography;

/// <summary>
/// Holds the role-specific output of a TLS 1.3 server key exchange. KEM-based
/// groups cannot use the symmetric <see cref="IKeyShare"/> contract because the
/// server encapsulates to the client's public key instead of decapsulating.
/// </summary>
internal sealed class Tls13ServerKeyExchange : IDisposable
{
    private readonly byte[] _publicKey;
    private readonly byte[] _sharedSecret;
    private bool _disposed;
    private bool _secretExported;

    private Tls13ServerKeyExchange(byte[] publicKey, byte[] sharedSecret)
    {
        _publicKey = publicKey;
        _sharedSecret = sharedSecret;
    }

    internal ReadOnlyMemory<byte> PublicKey
    {
        get
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            return _publicKey;
        }
    }

    internal static Tls13ServerKeyExchange Create(
        NamedGroup group,
        ReadOnlySpan<byte> clientKeyExchange)
    {
        return group switch
        {
            NamedGroup.X25519MlKem768 => CreateX25519MlKem768(clientKeyExchange),
            NamedGroup.X25519Kyber768Draft00 =>
                CreateX25519Kyber768Draft00(clientKeyExchange),
            _ => CreateClassical(group, clientKeyExchange),
        };
    }

    private static Tls13ServerKeyExchange CreateClassical(
        NamedGroup group,
        ReadOnlySpan<byte> clientKeyExchange)
    {
        using var share = KeyShareFactory.Create(group);
        byte[]? secret = null;
        try
        {
            secret = share.DeriveSharedSecret(clientKeyExchange);
            return new Tls13ServerKeyExchange(share.PublicKey.ToArray(), secret);
        }
        catch
        {
            if (secret is not null)
            {
                CryptographicOperations.ZeroMemory(secret);
            }
            throw;
        }
    }

    private static Tls13ServerKeyExchange CreateX25519MlKem768(
        ReadOnlySpan<byte> clientKeyExchange)
    {
        if (clientKeyExchange.Length != X25519MlKem768KeyShare.ClientShareSize)
        {
            throw TlsProtocolException.Illegal(
                $"An X25519MLKEM768 client key share must contain exactly " +
                $"{X25519MlKem768KeyShare.ClientShareSize} bytes.");
        }

        MlKem768.Encapsulation encapsulation = default;
        using var x25519 = X25519KeyShare.Create();
        byte[]? x25519Secret = null;
        byte[]? publicKey = null;
        byte[]? sharedSecret = null;
        try
        {
            encapsulation = MlKem768.Encapsulate(
                clientKeyExchange[..MlKem768.EncapsulationKeySize]);
            x25519Secret = x25519.DeriveSharedSecret(
                clientKeyExchange[MlKem768.EncapsulationKeySize..]);

            publicKey = new byte[X25519MlKem768KeyShare.ServerShareSize];
            encapsulation.Ciphertext.CopyTo(publicKey, 0);
            x25519.PublicKey.Span.CopyTo(publicKey.AsSpan(MlKem768.CiphertextSize));

            sharedSecret = new byte[X25519MlKem768KeyShare.HybridSecretSize];
            encapsulation.SharedSecret.CopyTo(sharedSecret, 0);
            x25519Secret.CopyTo(sharedSecret, MlKem768.SharedSecretSize);

            var result = new Tls13ServerKeyExchange(publicKey, sharedSecret);
            publicKey = null;
            sharedSecret = null;
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
                "The X25519MLKEM768 client key share is invalid.",
                exception);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(encapsulation.SharedSecret ?? []);
            CryptographicOperations.ZeroMemory(encapsulation.Ciphertext ?? []);
            if (x25519Secret is not null)
            {
                CryptographicOperations.ZeroMemory(x25519Secret);
            }
            if (publicKey is not null)
            {
                CryptographicOperations.ZeroMemory(publicKey);
            }
            if (sharedSecret is not null)
            {
                CryptographicOperations.ZeroMemory(sharedSecret);
            }
        }
    }

    private static Tls13ServerKeyExchange CreateX25519Kyber768Draft00(
        ReadOnlySpan<byte> clientKeyExchange)
    {
        if (clientKeyExchange.Length != X25519Kyber768Draft00KeyShare.ClientShareSize)
        {
            throw TlsProtocolException.Illegal(
                $"An X25519Kyber768Draft00 client key share must contain exactly " +
                $"{X25519Kyber768Draft00KeyShare.ClientShareSize} bytes.");
        }

        MlKem768.Encapsulation encapsulation = default;
        using var x25519 = X25519KeyShare.Create();
        byte[]? x25519Secret = null;
        byte[]? kyberSecret = null;
        byte[]? publicKey = null;
        byte[]? sharedSecret = null;
        try
        {
            encapsulation = MlKem768.Encapsulate(
                clientKeyExchange[X25519.KeyLength..]);
            x25519Secret = x25519.DeriveSharedSecret(
                clientKeyExchange[..X25519.KeyLength]);
            kyberSecret = X25519Kyber768Draft00KeyShare.TransformSharedSecret(
                encapsulation.SharedSecret,
                encapsulation.Ciphertext);

            publicKey = new byte[X25519Kyber768Draft00KeyShare.ServerShareSize];
            x25519.PublicKey.Span.CopyTo(publicKey);
            encapsulation.Ciphertext.CopyTo(publicKey, X25519.KeyLength);

            sharedSecret = new byte[X25519Kyber768Draft00KeyShare.HybridSecretSize];
            x25519Secret.CopyTo(sharedSecret, 0);
            kyberSecret.CopyTo(sharedSecret, X25519.KeyLength);

            var result = new Tls13ServerKeyExchange(publicKey, sharedSecret);
            publicKey = null;
            sharedSecret = null;
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
                "The X25519Kyber768Draft00 client key share is invalid.",
                exception);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(encapsulation.SharedSecret ?? []);
            CryptographicOperations.ZeroMemory(encapsulation.Ciphertext ?? []);
            Zero(x25519Secret);
            Zero(kyberSecret);
            Zero(publicKey);
            Zero(sharedSecret);
        }
    }

    internal byte[] ExportSharedSecret()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (_secretExported)
        {
            throw new InvalidOperationException("The server key-exchange secret was already exported.");
        }
        _secretExported = true;
        return (byte[])_sharedSecret.Clone();
    }

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }
        _disposed = true;
        CryptographicOperations.ZeroMemory(_publicKey);
        CryptographicOperations.ZeroMemory(_sharedSecret);
    }

    private static void Zero(byte[]? value)
    {
        if (value is not null)
        {
            CryptographicOperations.ZeroMemory(value);
        }
    }
}
