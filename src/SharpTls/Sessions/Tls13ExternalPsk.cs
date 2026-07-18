using System.Security.Cryptography;
using SharpTls.Cryptography;
using SharpTls.Protocol;

namespace SharpTls;

/// <summary>
/// A caller-owned TLS 1.3 external pre-shared key as defined by RFC 8446 section 2.2.
/// The identity is public protocol data; the key is copied into protected SharpTls state
/// and is never exposed through the public API.
/// </summary>
public sealed class Tls13ExternalPsk : IDisposable
{
    private byte[]? _identity;
    private byte[]? _key;

    /// <summary>
    /// Creates an external PSK. Keys shorter than 128 bits are rejected. By default the
    /// connection fails if the peer does not select this identity instead of silently
    /// falling back to certificate authentication.
    /// </summary>
    public Tls13ExternalPsk(
        byte[] identity,
        byte[] key,
        TlsCipherSuite cipherSuite = TlsCipherSuite.TlsAes128GcmSha256,
        bool requireSelection = true)
    {
        ArgumentNullException.ThrowIfNull(identity);
        ArgumentNullException.ThrowIfNull(key);
        if (identity.Length is 0 or > ushort.MaxValue)
        {
            throw new ArgumentOutOfRangeException(nameof(identity));
        }
        if (key.Length is < 16 or > 1024)
        {
            throw new ArgumentOutOfRangeException(
                nameof(key),
                "A TLS 1.3 external PSK must contain 16 to 1024 bytes.");
        }

        _ = CipherSuiteInfo.Get(cipherSuite);
        _identity = (byte[])identity.Clone();
        _key = (byte[])key.Clone();
        CipherSuite = cipherSuite;
        RequireSelection = requireSelection;
    }

    /// <summary>Gets a defensive copy of the opaque PSK identity.</summary>
    public byte[] Identity
    {
        get
        {
            ObjectDisposedException.ThrowIf(_identity is null, this);
            return (byte[])_identity.Clone();
        }
    }

    /// <summary>Gets the TLS 1.3 cipher suite whose hash is bound to this PSK.</summary>
    public TlsCipherSuite CipherSuite { get; }

    /// <summary>Gets whether failure to select this PSK aborts the handshake.</summary>
    public bool RequireSelection { get; }

    internal Tls13ExternalPskConfiguration Snapshot()
    {
        ObjectDisposedException.ThrowIf(_identity is null || _key is null, this);
        return new Tls13ExternalPskConfiguration(
            _identity,
            _key,
            CipherSuite,
            RequireSelection);
    }

    internal Tls13ExternalPsk Clone()
    {
        ObjectDisposedException.ThrowIf(_identity is null || _key is null, this);
        return new Tls13ExternalPsk(
            _identity,
            _key,
            CipherSuite,
            RequireSelection);
    }

    /// <summary>Zeroes the caller-owned SharpTls copy of the PSK.</summary>
    public void Dispose()
    {
        if (_identity is not null)
        {
            CryptographicOperations.ZeroMemory(_identity);
            _identity = null;
        }
        if (_key is not null)
        {
            CryptographicOperations.ZeroMemory(_key);
            _key = null;
        }
    }
}

internal sealed class Tls13ExternalPskConfiguration : IDisposable
{
    private byte[]? _identity;
    private byte[]? _key;

    internal Tls13ExternalPskConfiguration(
        ReadOnlySpan<byte> identity,
        ReadOnlySpan<byte> key,
        TlsCipherSuite cipherSuite,
        bool requireSelection)
    {
        _identity = identity.ToArray();
        _key = key.ToArray();
        CipherSuite = cipherSuite;
        RequireSelection = requireSelection;
    }

    internal ReadOnlySpan<byte> Identity
    {
        get
        {
            ObjectDisposedException.ThrowIf(_identity is null, this);
            return _identity;
        }
    }

    internal TlsCipherSuite CipherSuite { get; }

    internal bool RequireSelection { get; }

    internal byte[] CopyKey()
    {
        ObjectDisposedException.ThrowIf(_key is null, this);
        return (byte[])_key.Clone();
    }

    public void Dispose()
    {
        if (_identity is not null)
        {
            CryptographicOperations.ZeroMemory(_identity);
            _identity = null;
        }
        if (_key is not null)
        {
            CryptographicOperations.ZeroMemory(_key);
            _key = null;
        }
    }
}
