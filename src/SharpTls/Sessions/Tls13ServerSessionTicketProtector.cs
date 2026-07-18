using System.Security.Cryptography;
using System.Text;
using SharpTls.Cryptography;
using SharpTls.IO;
using SharpTls.Protocol;

namespace SharpTls;

/// <summary>
/// Protects stateless TLS 1.3 server tickets with AES-256-GCM and supports
/// overlapping decryption keys during key rotation. The protector is safe to
/// share across server connections and owns private copies of all key bytes.
/// </summary>
public sealed class Tls13ServerSessionTicketProtector : IDisposable
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

    /// <summary>Creates a protector whose current encryption key is a 32-byte random value.</summary>
    public Tls13ServerSessionTicketProtector(
        string currentKeyId,
        ReadOnlySpan<byte> currentKey)
    {
        ValidateKeyId(currentKeyId);
        ValidateKey(currentKey);
        _currentKeyId = currentKeyId;
        _keys.Add(currentKeyId, new SecretBuffer(currentKey));
    }

    /// <summary>Gets the key identifier used to protect newly issued tickets.</summary>
    public string CurrentKeyId => _currentKeyId;

    /// <summary>Adds an older key that may decrypt tickets during a rotation window.</summary>
    public void AddDecryptionKey(string keyId, ReadOnlySpan<byte> key)
    {
        ValidateKeyId(keyId);
        ValidateKey(key);
        lock (_sync)
        {
            ThrowIfDisposed();
            if (!_keys.TryAdd(keyId, new SecretBuffer(key)))
            {
                throw new ArgumentException(
                    "A server ticket key with that identifier already exists.",
                    nameof(keyId));
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

    internal byte[] Protect(Tls13ServerSessionTicketState state)
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
            var outputLength = checked(header.Length + plaintext.Length + TagLength);
            if (outputLength > MaximumTicketLength)
            {
                throw new InvalidOperationException("Protected TLS session ticket is too large.");
            }
            var output = GC.AllocateUninitializedArray<byte>(outputLength);
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

    internal bool TryUnprotect(
        ReadOnlySpan<byte> ticket,
        out Tls13ServerSessionTicketState? state)
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
            if (!reader.ReadBytes(4).SequenceEqual("STKT"u8) || reader.ReadUInt8() != 1)
            {
                return false;
            }
            var encodedKeyId = reader.ReadVector8(MaximumKeyIdLength);
            keyId = Encoding.ASCII.GetString(encodedKeyId);
            ValidateKeyId(keyId);
            _ = reader.ReadBytes(NonceLength);
            headerLength = 4 + 1 + 1 + encodedKeyId.Length + NonceLength;
            if (ticket.Length - headerLength <= TagLength)
            {
                return false;
            }
        }
        catch (Exception exception) when (
            exception is TlsProtocolException or ArgumentException)
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
            state = Tls13ServerSessionTicketState.Decode(plaintext);
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
        writer.WriteBytes("STKT"u8);
        writer.WriteUInt8(1);
        writer.WriteVector8(Encoding.ASCII.GetBytes(keyId));
        writer.WriteBytes(nonce);
        return writer.ToArray();
    }

    private static void ValidateKeyId(string keyId)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(keyId);
        if (keyId.Length > MaximumKeyIdLength ||
            keyId.Any(character => character is < '!' or > '~'))
        {
            throw new ArgumentException(
                "A ticket key identifier must contain 1-64 printable ASCII characters.",
                nameof(keyId));
        }
    }

    private static void ValidateKey(ReadOnlySpan<byte> key)
    {
        if (key.Length != KeyLength)
        {
            throw new ArgumentException("A server ticket key must contain exactly 32 bytes.", nameof(key));
        }
    }

    private void ThrowIfDisposed() => ObjectDisposedException.ThrowIf(_disposed, this);
}

internal sealed class Tls13ServerSessionTicketState : IDisposable
{
    private const uint MaximumLifetimeSeconds = 7 * 24 * 60 * 60;
    private bool _disposed;

    internal Tls13ServerSessionTicketState(
        long issuedAtUnixMilliseconds,
        uint lifetimeSeconds,
        uint ageAdd,
        TlsCipherSuite cipherSuite,
        string? serverName,
        string? alpn,
        ReadOnlySpan<byte> psk,
        uint? maximumEarlyDataSize = null,
        byte[]? quicTransportParameters = null)
    {
        var suite = CipherSuiteInfo.Get(cipherSuite);
        if (lifetimeSeconds is 0 or > MaximumLifetimeSeconds || psk.Length != suite.HashLength)
        {
            throw new ArgumentException("TLS server ticket state is invalid.");
        }
        if ((maximumEarlyDataSize.HasValue != (quicTransportParameters is not null)) ||
            quicTransportParameters is { Length: > ushort.MaxValue } ||
            serverName is { Length: > 253 } ||
            serverName?.Any(character => character > 0x7f) == true ||
            alpn is { Length: > TlsConstants.MaxAlpnProtocolLength } ||
            alpn?.Any(character => character > 0x7f) == true)
        {
            throw new ArgumentException("TLS server ticket names are invalid.");
        }
        IssuedAtUnixMilliseconds = issuedAtUnixMilliseconds;
        LifetimeSeconds = lifetimeSeconds;
        AgeAdd = ageAdd;
        CipherSuite = cipherSuite;
        ServerName = serverName;
        Alpn = alpn;
        Psk = psk.ToArray();
        MaximumEarlyDataSize = maximumEarlyDataSize;
        QuicTransportParameters = quicTransportParameters is null
            ? null
            : (byte[])quicTransportParameters.Clone();
    }

    internal long IssuedAtUnixMilliseconds { get; }
    internal uint LifetimeSeconds { get; }
    internal uint AgeAdd { get; }
    internal TlsCipherSuite CipherSuite { get; }
    internal string? ServerName { get; }
    internal string? Alpn { get; }
    internal byte[] Psk { get; }
    internal uint? MaximumEarlyDataSize { get; }
    internal byte[]? QuicTransportParameters { get; }

    internal byte[] Encode()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        var writer = new TlsBinaryWriter();
        writer.WriteBytes("T13S"u8);
        writer.WriteUInt8(2);
        writer.WriteUInt64(checked((ulong)IssuedAtUnixMilliseconds));
        writer.WriteUInt32(LifetimeSeconds);
        writer.WriteUInt32(AgeAdd);
        writer.WriteUInt16((ushort)CipherSuite);
        writer.WriteVector16(ServerName is null ? [] : Encoding.ASCII.GetBytes(ServerName));
        writer.WriteVector8(Alpn is null ? [] : Encoding.ASCII.GetBytes(Alpn));
        writer.WriteVector8(Psk);
        writer.WriteUInt8(MaximumEarlyDataSize.HasValue ? (byte)1 : (byte)0);
        if (MaximumEarlyDataSize is { } maximumEarlyDataSize)
        {
            writer.WriteUInt32(maximumEarlyDataSize);
            writer.WriteVector16(QuicTransportParameters!);
        }
        return writer.ToArray();
    }

    internal static Tls13ServerSessionTicketState Decode(ReadOnlySpan<byte> encoded)
    {
        var reader = new TlsBinaryReader(encoded);
        if (!reader.ReadBytes(4).SequenceEqual("T13S"u8))
        {
            throw TlsProtocolException.Decode("TLS server ticket state version is unsupported.");
        }
        var version = reader.ReadUInt8();
        if (version is not (1 or 2))
        {
            throw TlsProtocolException.Decode("TLS server ticket state version is unsupported.");
        }
        var encodedIssued = reader.ReadUInt64();
        if (encodedIssued > long.MaxValue)
        {
            throw TlsProtocolException.Decode("TLS server ticket issue time is out of range.");
        }
        var issued = (long)encodedIssued;
        var lifetime = reader.ReadUInt32();
        var ageAdd = reader.ReadUInt32();
        var suite = (TlsCipherSuite)reader.ReadUInt16();
        var serverNameBytes = reader.ReadVector16(253);
        var alpnBytes = reader.ReadVector8(TlsConstants.MaxAlpnProtocolLength);
        var psk = reader.ReadVector8().ToArray();
        uint? maximumEarlyDataSize = null;
        byte[]? quicTransportParameters = null;
        if (version >= 2)
        {
            var hasEarlyData = reader.ReadUInt8();
            if (hasEarlyData > 1)
            {
                throw TlsProtocolException.Decode("TLS server ticket has an invalid early-data flag.");
            }
            if (hasEarlyData == 1)
            {
                maximumEarlyDataSize = reader.ReadUInt32();
                quicTransportParameters = reader.ReadVector16().ToArray();
            }
        }
        reader.EnsureEnd("TLS server ticket state");
        if (serverNameBytes.IndexOfAnyInRange((byte)0x80, byte.MaxValue) >= 0 ||
            alpnBytes.IndexOfAnyInRange((byte)0x80, byte.MaxValue) >= 0)
        {
            throw TlsProtocolException.Decode("TLS server ticket contains non-ASCII names.");
        }
        CipherSuiteInfo suiteInfo;
        try
        {
            suiteInfo = CipherSuiteInfo.Get(suite);
        }
        catch (NotSupportedException exception)
        {
            throw new TlsProtocolException(
                TlsAlertDescription.DecodeError,
                "TLS server ticket contains an unsupported TLS 1.3 cipher suite.",
                exception);
        }
        if (lifetime is 0 or > MaximumLifetimeSeconds ||
            psk.Length != suiteInfo.HashLength)
        {
            throw TlsProtocolException.Decode(
                "TLS server ticket contains an invalid lifetime or PSK length.");
        }
        try
        {
            return new Tls13ServerSessionTicketState(
                issued,
                lifetime,
                ageAdd,
                suite,
                serverNameBytes.IsEmpty ? null : Encoding.ASCII.GetString(serverNameBytes),
                alpnBytes.IsEmpty ? null : Encoding.ASCII.GetString(alpnBytes),
                psk,
                maximumEarlyDataSize,
                quicTransportParameters);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(psk);
            if (quicTransportParameters is not null)
            {
                CryptographicOperations.ZeroMemory(quicTransportParameters);
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
        CryptographicOperations.ZeroMemory(Psk);
        if (QuicTransportParameters is not null)
        {
            CryptographicOperations.ZeroMemory(QuicTransportParameters);
        }
    }
}
