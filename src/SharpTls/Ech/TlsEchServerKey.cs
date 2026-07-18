using System.Security.Cryptography;
using SharpTls.Cryptography;
using SharpTls.Ech;
using SharpTls.IO;
using SharpTls.Protocol;

namespace SharpTls;

/// <summary>
/// A caller-owned RFC 9849 ECH decryption key and its exact public configuration.
/// Dispose the key after every server configuration that references it has been snapshotted.
/// </summary>
public sealed class TlsEchServerKey : IDisposable
{
    private readonly byte[] _privateKey;
    private bool _disposed;

    /// <summary>
    /// Creates an ECH server key and verifies that the private key matches the public key
    /// encoded in <paramref name="configuration"/>.
    /// </summary>
    public TlsEchServerKey(
        TlsEchConfig configuration,
        ReadOnlySpan<byte> privateKey,
        bool sendAsRetry = false)
    {
        ArgumentNullException.ThrowIfNull(configuration);
        if (configuration.HasUnsupportedMandatoryExtensions)
        {
            throw new ArgumentException(
                "An ECH server key cannot use a configuration with unsupported mandatory extensions.",
                nameof(configuration));
        }
        if (configuration.CipherSuites.Count == 0)
        {
            throw new ArgumentException(
                "An ECH server configuration must contain an executable HPKE cipher suite.",
                nameof(configuration));
        }
        foreach (var suite in configuration.CipherSuites)
        {
            if (TlsEchConfigList.IsCipherSuiteExecutable(suite))
            {
                continue;
            }
            if (suite.AeadId == TlsHpkeAeadId.ChaCha20Poly1305 &&
                !ChaCha20Poly1305.IsSupported)
            {
                throw new PlatformNotSupportedException(
                    "The ECH server configuration advertises ChaCha20-Poly1305, which is unavailable on this platform.");
            }
            throw new NotSupportedException(
                "The ECH server configuration advertises an unsupported HPKE cipher suite.");
        }

        _privateKey = privateKey.ToArray();
        try
        {
            ValidateKeyPair(configuration, _privateKey);
        }
        catch
        {
            CryptographicOperations.ZeroMemory(_privateKey);
            throw;
        }
        Configuration = configuration;
        SendAsRetry = sendAsRetry;
    }

    /// <summary>Gets the immutable public ECH configuration associated with this key.</summary>
    public TlsEchConfig Configuration { get; }

    /// <summary>Gets whether the configuration is included in authenticated retry configs.</summary>
    public bool SendAsRetry { get; }

    internal TlsEchServerKeyConfiguration Snapshot()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        return new TlsEchServerKeyConfiguration(
            Configuration,
            (byte[])_privateKey.Clone(),
            SendAsRetry);
    }

    /// <inheritdoc />
    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }
        _disposed = true;
        CryptographicOperations.ZeroMemory(_privateKey);
    }

    private static void ValidateKeyPair(
        TlsEchConfig configuration,
        ReadOnlySpan<byte> privateKey)
    {
        byte[]? derivedPublicKey = null;
        byte[]? configuredPublicKey = null;
        try
        {
            configuredPublicKey = configuration.GetPublicKey();
            if (configuration.KemId == TlsHpkeKemId.DhkemX25519HkdfSha256)
            {
                if (privateKey.Length != X25519.KeyLength)
                {
                    throw new ArgumentException(
                        "An X25519 ECH private key must contain exactly 32 bytes.",
                        nameof(privateKey));
                }
                derivedPublicKey = new byte[X25519.KeyLength];
                X25519.DerivePublicKey(privateKey, derivedPublicKey);
            }
            else
            {
                derivedPublicKey = HpkeNistKem.DerivePublicKey(
                    configuration.KemId,
                    privateKey);
            }

            if (!CryptographicOperations.FixedTimeEquals(
                configuredPublicKey,
                derivedPublicKey))
            {
                throw new CryptographicException(
                    "The ECH private key does not match the configuration public key.");
            }
        }
        finally
        {
            Zero(derivedPublicKey);
            Zero(configuredPublicKey);
        }
    }

    private static void Zero(byte[]? value)
    {
        if (value is not null)
        {
            CryptographicOperations.ZeroMemory(value);
        }
    }
}

internal sealed class TlsEchServerKeyConfiguration : IDisposable
{
    private byte[]? _privateKey;

    internal TlsEchServerKeyConfiguration(
        TlsEchConfig configuration,
        byte[] privateKey,
        bool sendAsRetry)
    {
        Configuration = configuration;
        _privateKey = privateKey;
        SendAsRetry = sendAsRetry;
    }

    internal TlsEchConfig Configuration { get; }

    internal bool SendAsRetry { get; }

    internal byte[] CopyPrivateKey() => _privateKey is null
        ? throw new ObjectDisposedException(nameof(TlsEchServerKeyConfiguration))
        : (byte[])_privateKey.Clone();

    internal static byte[]? BuildRetryConfigurationList(
        IReadOnlyList<TlsEchServerKeyConfiguration> keys)
    {
        var configurations = new TlsBinaryWriter();
        foreach (var key in keys)
        {
            if (!key.SendAsRetry)
            {
                continue;
            }
            var encoded = key.Configuration.GetEncodedConfig();
            try
            {
                configurations.WriteBytes(encoded);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(encoded);
            }
        }
        if (configurations.Length == 0)
        {
            return null;
        }
        var list = new TlsBinaryWriter(configurations.Length + 2);
        list.WriteVector16(configurations.WrittenSpan);
        return list.ToArray();
    }

    public void Dispose()
    {
        if (_privateKey is null)
        {
            return;
        }
        CryptographicOperations.ZeroMemory(_privateKey);
        _privateKey = null;
    }
}
