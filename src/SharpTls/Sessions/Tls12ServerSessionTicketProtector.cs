using System.Security.Cryptography;
using System.Text;
using SharpTls.Cryptography;
using SharpTls.IO;
using SharpTls.Protocol;

namespace SharpTls;

/// <summary>
/// Protects stateless RFC 5077 TLS 1.2 server tickets with AES-256-GCM and supports
/// overlapping decryption keys during key rotation.
/// </summary>
public sealed class Tls12ServerSessionTicketProtector : IDisposable
{
    private const int KeyLength = 32;
    private const int NonceLength = 12;
    private const int TagLength = 16;
    private const int MaximumKeyIdLength = 64;
    private const int MaximumTicketLength = 4096;
    private readonly object _sync = new();
    private readonly Dictionary<string, SecretBuffer> _keys = new(StringComparer.Ordinal);
    private readonly string _currentKeyId;
    private bool _disposed;

    /// <summary>Creates a protector from a 32-byte AES key.</summary>
    public Tls12ServerSessionTicketProtector(string currentKeyId, ReadOnlySpan<byte> currentKey)
    {
        ValidateKeyId(currentKeyId);
        ValidateKey(currentKey);
        _currentKeyId = currentKeyId;
        _keys.Add(currentKeyId, new SecretBuffer(currentKey));
    }

    /// <summary>Gets the key identifier used for new tickets.</summary>
    public string CurrentKeyId => _currentKeyId;

    /// <summary>Adds an older decryption key for a rotation overlap window.</summary>
    public void AddDecryptionKey(string keyId, ReadOnlySpan<byte> key)
    {
        ValidateKeyId(keyId);
        ValidateKey(key);
        lock (_sync)
        {
            ThrowIfDisposed();
            if (!_keys.TryAdd(keyId, new SecretBuffer(key)))
            {
                throw new ArgumentException("A TLS 1.2 ticket key with that ID already exists.", nameof(keyId));
            }
        }
    }

    /// <summary>Removes and zeroizes a non-current decryption key.</summary>
    public bool RemoveDecryptionKey(string keyId)
    {
        ArgumentNullException.ThrowIfNull(keyId);
        lock (_sync)
        {
            ThrowIfDisposed();
            if (string.Equals(keyId, _currentKeyId, StringComparison.Ordinal))
            {
                throw new InvalidOperationException("The current ticket key cannot be removed.");
            }
            if (!_keys.Remove(keyId, out var key))
            {
                return false;
            }
            key.Dispose();
            return true;
        }
    }

    internal byte[] Protect(Tls12ServerTicketState state)
    {
        ArgumentNullException.ThrowIfNull(state);
        byte[] key;
        lock (_sync)
        {
            ThrowIfDisposed();
            key = _keys[_currentKeyId].Copy();
        }
        var plaintext = state.Encode();
        var nonce = RandomNumberGenerator.GetBytes(NonceLength);
        var header = BuildHeader(_currentKeyId, nonce);
        try
        {
            var output = GC.AllocateUninitializedArray<byte>(
                checked(header.Length + plaintext.Length + TagLength));
            if (output.Length > MaximumTicketLength)
            {
                throw new InvalidOperationException("Protected TLS 1.2 ticket is too large.");
            }
            header.CopyTo(output, 0);
            using var aes = new AesGcm(key, TagLength);
            aes.Encrypt(
                nonce,
                plaintext,
                output.AsSpan(header.Length, plaintext.Length),
                output.AsSpan(header.Length + plaintext.Length, TagLength),
                header);
            return output;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(key);
            CryptographicOperations.ZeroMemory(plaintext);
            CryptographicOperations.ZeroMemory(nonce);
            CryptographicOperations.ZeroMemory(header);
        }
    }

    internal bool TryUnprotect(ReadOnlySpan<byte> ticket, out Tls12ServerTicketState? state)
    {
        state = null;
        if (ticket.Length is < 40 or > MaximumTicketLength)
        {
            return false;
        }
        string keyId;
        int headerLength;
        try
        {
            var reader = new TlsBinaryReader(ticket);
            if (!reader.ReadBytes(4).SequenceEqual("S12T"u8) || reader.ReadUInt8() != 1)
            {
                return false;
            }
            var encodedKeyId = reader.ReadVector8(MaximumKeyIdLength);
            keyId = Encoding.ASCII.GetString(encodedKeyId);
            ValidateKeyId(keyId);
            _ = reader.ReadBytes(NonceLength);
            headerLength = 6 + encodedKeyId.Length + NonceLength;
            if (ticket.Length - headerLength <= TagLength)
            {
                return false;
            }
        }
        catch (Exception exception) when (exception is TlsProtocolException or ArgumentException)
        {
            return false;
        }

        byte[]? key = null;
        lock (_sync)
        {
            ThrowIfDisposed();
            if (_keys.TryGetValue(keyId, out var stored))
            {
                key = stored.Copy();
            }
        }
        if (key is null)
        {
            return false;
        }
        var plaintextLength = ticket.Length - headerLength - TagLength;
        var plaintext = GC.AllocateUninitializedArray<byte>(plaintextLength);
        try
        {
            using var aes = new AesGcm(key, TagLength);
            aes.Decrypt(
                ticket.Slice(headerLength - NonceLength, NonceLength),
                ticket.Slice(headerLength, plaintextLength),
                ticket.Slice(headerLength + plaintextLength, TagLength),
                plaintext,
                ticket[..headerLength]);
            state = Tls12ServerTicketState.Decode(plaintext);
            return true;
        }
        catch (Exception exception) when (
            exception is CryptographicException or TlsProtocolException or
                ArgumentException or OverflowException or NotSupportedException)
        {
            state?.Dispose();
            state = null;
            return false;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(key);
            CryptographicOperations.ZeroMemory(plaintext);
        }
    }

    /// <inheritdoc />
    public void Dispose()
    {
        lock (_sync)
        {
            if (_disposed)
            {
                return;
            }
            _disposed = true;
            foreach (var key in _keys.Values)
            {
                key.Dispose();
            }
            _keys.Clear();
        }
    }

    private static byte[] BuildHeader(string keyId, ReadOnlySpan<byte> nonce)
    {
        var writer = new TlsBinaryWriter();
        writer.WriteBytes("S12T"u8);
        writer.WriteUInt8(1);
        writer.WriteVector8(Encoding.ASCII.GetBytes(keyId));
        writer.WriteBytes(nonce);
        return writer.ToArray();
    }

    private static void ValidateKeyId(string keyId)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(keyId);
        if (keyId.Length > MaximumKeyIdLength || keyId.Any(character => character is < '!' or > '~'))
        {
            throw new ArgumentException("A ticket key ID must be 1-64 printable ASCII characters.", nameof(keyId));
        }
    }

    private static void ValidateKey(ReadOnlySpan<byte> key)
    {
        if (key.Length != KeyLength)
        {
            throw new ArgumentException("A TLS 1.2 ticket key must contain exactly 32 bytes.", nameof(key));
        }
    }

    private void ThrowIfDisposed() => ObjectDisposedException.ThrowIf(_disposed, this);
}

internal sealed class Tls12ServerTicketState : IDisposable
{
    private byte[]? _masterSecret;

    internal Tls12ServerTicketState(
        long issuedAtUnixMilliseconds,
        uint lifetimeSeconds,
        TlsCipherSuite cipherSuite,
        string? serverName,
        string? alpn,
        NamedGroup group,
        ReadOnlySpan<byte> masterSecret)
    {
        _ = Tls12CipherSuiteInfo.Get(cipherSuite);
        if (lifetimeSeconds is 0 or > 604800 ||
            masterSecret.Length != TlsConstants.Tls12MasterSecretLength ||
            serverName is { Length: > 253 } || serverName?.Any(c => c > 0x7f) == true ||
            alpn is { Length: > TlsConstants.MaxAlpnProtocolLength } || alpn?.Any(c => c > 0x7f) == true)
        {
            throw new ArgumentException("TLS 1.2 server ticket state is invalid.");
        }
        IssuedAtUnixMilliseconds = issuedAtUnixMilliseconds;
        LifetimeSeconds = lifetimeSeconds;
        CipherSuite = cipherSuite;
        ServerName = serverName;
        Alpn = alpn;
        Group = group;
        _masterSecret = masterSecret.ToArray();
    }

    internal long IssuedAtUnixMilliseconds { get; }
    internal uint LifetimeSeconds { get; }
    internal TlsCipherSuite CipherSuite { get; }
    internal string? ServerName { get; }
    internal string? Alpn { get; }
    internal NamedGroup Group { get; }

    internal bool IsUsable(DateTimeOffset now) =>
        _masterSecret is not null &&
        now.ToUnixTimeMilliseconds() >= IssuedAtUnixMilliseconds &&
        now.ToUnixTimeMilliseconds() - IssuedAtUnixMilliseconds <
            checked((long)LifetimeSeconds * 1000);

    internal byte[] CopyMasterSecret()
    {
        ObjectDisposedException.ThrowIf(_masterSecret is null, this);
        return (byte[])_masterSecret.Clone();
    }

    internal byte[] Encode()
    {
        var secret = _masterSecret ?? throw new ObjectDisposedException(nameof(Tls12ServerTicketState));
        var writer = new TlsBinaryWriter();
        writer.WriteBytes("T12S"u8);
        writer.WriteUInt8(1);
        writer.WriteUInt64(checked((ulong)IssuedAtUnixMilliseconds));
        writer.WriteUInt32(LifetimeSeconds);
        writer.WriteUInt16((ushort)CipherSuite);
        writer.WriteUInt16((ushort)Group);
        writer.WriteVector16(ServerName is null ? [] : Encoding.ASCII.GetBytes(ServerName));
        writer.WriteVector8(Alpn is null ? [] : Encoding.ASCII.GetBytes(Alpn));
        writer.WriteVector8(secret);
        return writer.ToArray();
    }

    internal static Tls12ServerTicketState Decode(ReadOnlySpan<byte> encoded)
    {
        var reader = new TlsBinaryReader(encoded);
        if (!reader.ReadBytes(4).SequenceEqual("T12S"u8) || reader.ReadUInt8() != 1)
        {
            throw TlsProtocolException.Decode("TLS 1.2 server ticket state version is unsupported.");
        }
        var encodedIssued = reader.ReadUInt64();
        if (encodedIssued > long.MaxValue)
        {
            throw TlsProtocolException.Decode("TLS 1.2 server ticket issue time is out of range.");
        }
        var issued = (long)encodedIssued;
        var lifetime = reader.ReadUInt32();
        var suite = (TlsCipherSuite)reader.ReadUInt16();
        var group = (NamedGroup)reader.ReadUInt16();
        var sni = reader.ReadVector16(253);
        var alpn = reader.ReadVector8(TlsConstants.MaxAlpnProtocolLength);
        var secret = reader.ReadVector8().ToArray();
        reader.EnsureEnd("TLS 1.2 server ticket state");
        if (sni.IndexOfAnyInRange((byte)0x80, byte.MaxValue) >= 0 ||
            alpn.IndexOfAnyInRange((byte)0x80, byte.MaxValue) >= 0)
        {
            throw TlsProtocolException.Decode("TLS 1.2 ticket contains non-ASCII names.");
        }
        try
        {
            _ = Tls12CipherSuiteInfo.Get(suite);
        }
        catch (NotSupportedException exception)
        {
            throw new TlsProtocolException(
                TlsAlertDescription.DecodeError,
                "TLS 1.2 server ticket contains an unsupported cipher suite.",
                exception);
        }
        if (group is not (NamedGroup.X25519 or NamedGroup.Secp256r1 or
                NamedGroup.Secp384r1 or NamedGroup.Secp521r1) ||
            lifetime is 0 or > 604800 ||
            secret.Length != TlsConstants.Tls12MasterSecretLength)
        {
            throw TlsProtocolException.Decode(
                "TLS 1.2 server ticket contains an invalid group, lifetime, or secret length.");
        }
        try
        {
            return new Tls12ServerTicketState(
                issued,
                lifetime,
                suite,
                sni.IsEmpty ? null : Encoding.ASCII.GetString(sni),
                alpn.IsEmpty ? null : Encoding.ASCII.GetString(alpn),
                group,
                secret);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(secret);
        }
    }

    public void Dispose()
    {
        if (_masterSecret is not null)
        {
            CryptographicOperations.ZeroMemory(_masterSecret);
            _masterSecret = null;
        }
    }
}
