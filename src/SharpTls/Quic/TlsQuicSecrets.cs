using System.Security.Cryptography;
using SharpTls.Cryptography;
using SharpTls.Protocol;

namespace SharpTls.Quic;

/// <summary>Caller-owned QUIC packet-protection key material derived from a TLS secret.</summary>
public sealed class TlsQuicPacketProtectionKeys : IDisposable
{
    private byte[] _key;
    private byte[] _iv;
    private byte[] _headerProtectionKey;
    private bool _disposed;

    internal TlsQuicPacketProtectionKeys(byte[] key, byte[] iv, byte[] headerProtectionKey)
    {
        _key = key;
        _iv = iv;
        _headerProtectionKey = headerProtectionKey;
    }

    /// <summary>Copies the sensitive AEAD packet-protection key.</summary>
    public byte[] CopyKey() => Copy(_key);
    /// <summary>Copies the packet-protection IV.</summary>
    public byte[] CopyIv() => Copy(_iv);
    /// <summary>Copies the sensitive header-protection key.</summary>
    public byte[] CopyHeaderProtectionKey() => Copy(_headerProtectionKey);

    /// <inheritdoc />
    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }
        _disposed = true;
        CryptographicOperations.ZeroMemory(_key);
        CryptographicOperations.ZeroMemory(_iv);
        CryptographicOperations.ZeroMemory(_headerProtectionKey);
        _key = [];
        _iv = [];
        _headerProtectionKey = [];
    }

    private byte[] Copy(byte[] value)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        return (byte[])value.Clone();
    }
}

/// <summary>
/// Caller-owned TLS traffic secret exported specifically for QUIC packet protection.
/// Dispose it after the transport has installed or derived its keys.
/// </summary>
public sealed class TlsQuicTrafficSecret : IDisposable
{
    private byte[] _secret;
    private bool _disposed;

    internal TlsQuicTrafficSecret(
        TlsQuicEncryptionLevel level,
        TlsQuicSecretDirection direction,
        TlsCipherSuite cipherSuite,
        ReadOnlySpan<byte> secret)
    {
        if (level == TlsQuicEncryptionLevel.Initial)
        {
            throw new ArgumentException(
                "Initial secrets are derived by QUIC rather than the TLS handshake.",
                nameof(level));
        }
        Level = level;
        Direction = direction;
        CipherSuite = cipherSuite;
        var suite = CipherSuiteInfo.Get(cipherSuite);
        if (secret.Length != suite.HashLength)
        {
            throw new ArgumentException(
                "QUIC traffic-secret length does not match the cipher-suite hash.",
                nameof(secret));
        }
        _secret = secret.ToArray();
    }

    /// <summary>Gets the encryption level that installs this secret.</summary>
    public TlsQuicEncryptionLevel Level { get; }
    /// <summary>Gets whether the local transport reads or writes with this secret.</summary>
    public TlsQuicSecretDirection Direction { get; }
    /// <summary>Gets the negotiated TLS cipher suite and therefore AEAD/KDF selection.</summary>
    public TlsCipherSuite CipherSuite { get; }

    /// <summary>Copies the sensitive TLS traffic secret for a QUIC transport.</summary>
    public byte[] CopySecret()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        return (byte[])_secret.Clone();
    }

    /// <summary>Derives RFC 9001 or RFC 9369 packet, IV and header-protection keys.</summary>
    public TlsQuicPacketProtectionKeys DerivePacketProtectionKeys(TlsQuicVersion version)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (!Enum.IsDefined(version))
        {
            throw new ArgumentOutOfRangeException(nameof(version));
        }
        var suite = CipherSuiteInfo.Get(CipherSuite);
        var prefix = version == TlsQuicVersion.Version2 ? "quicv2 " : "quic ";
        var key = Tls13Hkdf.ExpandLabel(
            suite.HashAlgorithm,
            _secret,
            prefix + "key",
            [],
            suite.KeyLength);
        var iv = Tls13Hkdf.ExpandLabel(
            suite.HashAlgorithm,
            _secret,
            prefix + "iv",
            [],
            12);
        var headerProtectionKey = Tls13Hkdf.ExpandLabel(
            suite.HashAlgorithm,
            _secret,
            prefix + "hp",
            [],
            suite.KeyLength);
        return new TlsQuicPacketProtectionKeys(key, iv, headerProtectionKey);
    }

    /// <inheritdoc />
    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }
        _disposed = true;
        CryptographicOperations.ZeroMemory(_secret);
        _secret = [];
    }
}

/// <summary>RFC 9001/9369 Initial secrets derived outside TLS from a destination CID.</summary>
public sealed class TlsQuicInitialSecrets : IDisposable
{
    private static ReadOnlySpan<byte> Version1Salt =>
    [0x38, 0x76, 0x2C, 0xF7, 0xF5, 0x59, 0x34, 0xB3, 0x4D, 0x17,
     0x9A, 0xE6, 0xA4, 0xC8, 0x0C, 0xAD, 0xCC, 0xBB, 0x7F, 0x0A];
    private static ReadOnlySpan<byte> Version2Salt =>
    [0x0D, 0xED, 0xE3, 0xDE, 0xF7, 0x00, 0xA6, 0xDB, 0x81, 0x93,
     0x81, 0xBE, 0x6E, 0x26, 0x9D, 0xCB, 0xF9, 0xBD, 0x2E, 0xD9];

    private byte[] _clientSecret;
    private byte[] _serverSecret;
    private bool _disposed;

    private TlsQuicInitialSecrets(byte[] clientSecret, byte[] serverSecret)
    {
        _clientSecret = clientSecret;
        _serverSecret = serverSecret;
    }

    /// <summary>Derives the two SHA-256 Initial secrets for QUIC v1 or v2.</summary>
    public static TlsQuicInitialSecrets Derive(
        TlsQuicVersion version,
        ReadOnlySpan<byte> destinationConnectionId)
    {
        if (!Enum.IsDefined(version))
        {
            throw new ArgumentOutOfRangeException(nameof(version));
        }
        if (destinationConnectionId.Length > 20)
        {
            throw new ArgumentOutOfRangeException(nameof(destinationConnectionId));
        }
        var initial = Tls13Hkdf.Extract(
            HashAlgorithmName.SHA256,
            destinationConnectionId,
            version == TlsQuicVersion.Version2 ? Version2Salt : Version1Salt);
        try
        {
            return new TlsQuicInitialSecrets(
                Tls13Hkdf.ExpandLabel(
                    HashAlgorithmName.SHA256,
                    initial,
                    "client in",
                    [],
                    32),
                Tls13Hkdf.ExpandLabel(
                    HashAlgorithmName.SHA256,
                    initial,
                    "server in",
                    [],
                    32));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(initial);
        }
    }

    /// <summary>Copies the sensitive secret used for client Initial packets.</summary>
    public byte[] CopyClientSecret() => Copy(_clientSecret);
    /// <summary>Copies the sensitive secret used for server Initial packets.</summary>
    public byte[] CopyServerSecret() => Copy(_serverSecret);

    /// <summary>Derives client Initial packet and header-protection keys.</summary>
    public TlsQuicPacketProtectionKeys DeriveClientPacketProtectionKeys(
        TlsQuicVersion version) => DeriveKeys(_clientSecret, version);

    /// <summary>Derives server Initial packet and header-protection keys.</summary>
    public TlsQuicPacketProtectionKeys DeriveServerPacketProtectionKeys(
        TlsQuicVersion version) => DeriveKeys(_serverSecret, version);

    /// <inheritdoc />
    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }
        _disposed = true;
        CryptographicOperations.ZeroMemory(_clientSecret);
        CryptographicOperations.ZeroMemory(_serverSecret);
        _clientSecret = [];
        _serverSecret = [];
    }

    private TlsQuicPacketProtectionKeys DeriveKeys(
        byte[] secret,
        TlsQuicVersion version)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        var prefix = version == TlsQuicVersion.Version2 ? "quicv2 " : "quic ";
        return new TlsQuicPacketProtectionKeys(
            Tls13Hkdf.ExpandLabel(HashAlgorithmName.SHA256, secret, prefix + "key", [], 16),
            Tls13Hkdf.ExpandLabel(HashAlgorithmName.SHA256, secret, prefix + "iv", [], 12),
            Tls13Hkdf.ExpandLabel(HashAlgorithmName.SHA256, secret, prefix + "hp", [], 16));
    }

    private byte[] Copy(byte[] value)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        return (byte[])value.Clone();
    }
}
