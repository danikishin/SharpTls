using System.Security.Cryptography;
using System.Text;
using SharpTls.Cryptography;
using SharpTls.IO;
using SharpTls.Protocol;

namespace SharpTls;

/// <summary>
/// Authenticates and encrypts persistent TLS 1.3 session-cache state with AES-256-GCM.
/// The protector owns private copies of every supplied key and zeroizes them on disposal.
/// </summary>
public sealed class Tls13SessionStateProtector : IDisposable
{
    private const int KeyLength = 32;
    private const int NonceLength = 12;
    private const int TagLength = 16;
    private const int MaximumKeyIdLength = 64;
    private const int AbsoluteMaximumStateSize = 64 * 1024 * 1024;

    private readonly object _sync = new();
    private readonly Dictionary<string, SecretBuffer> _keys = new(StringComparer.Ordinal);
    private readonly string _currentKeyId;
    private bool _disposed;

    /// <summary>
    /// Creates a protector with the current encryption key. A 32-byte random key is required.
    /// </summary>
    public Tls13SessionStateProtector(
        string currentKeyId,
        ReadOnlySpan<byte> currentKey,
        int maximumProtectedStateSize = 16 * 1024 * 1024)
    {
        ValidateKeyId(currentKeyId);
        ValidateKey(currentKey);
        if (maximumProtectedStateSize is < 256 or > AbsoluteMaximumStateSize)
        {
            throw new ArgumentOutOfRangeException(nameof(maximumProtectedStateSize));
        }

        _currentKeyId = currentKeyId;
        _keys.Add(currentKeyId, new SecretBuffer(currentKey));
        MaximumProtectedStateSize = maximumProtectedStateSize;
    }

    /// <summary>Gets the identifier written on new protected state blobs.</summary>
    public string CurrentKeyId => _currentKeyId;

    /// <summary>Gets the maximum accepted or emitted blob size.</summary>
    public int MaximumProtectedStateSize { get; }

    /// <summary>
    /// Adds an older AES-256-GCM key for decryption during rotation. New exports always use
    /// <see cref="CurrentKeyId"/>.
    /// </summary>
    public void AddDecryptionKey(string keyId, ReadOnlySpan<byte> key)
    {
        ValidateKeyId(keyId);
        ValidateKey(key);
        lock (_sync)
        {
            ThrowIfDisposed();
            if (!_keys.TryAdd(keyId, new SecretBuffer(key)))
            {
                throw new ArgumentException("A session-state key with that identifier already exists.", nameof(keyId));
            }
        }
    }

    /// <summary>Removes and zeroizes an older decryption key.</summary>
    public bool RemoveDecryptionKey(string keyId)
    {
        ArgumentNullException.ThrowIfNull(keyId);
        lock (_sync)
        {
            ThrowIfDisposed();
            if (string.Equals(keyId, _currentKeyId, StringComparison.Ordinal))
            {
                throw new InvalidOperationException("The current encryption key cannot be removed.");
            }
            if (!_keys.Remove(keyId, out var key))
            {
                return false;
            }
            key.Dispose();
            return true;
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

    internal byte[] Protect(Tls13SessionCache cache)
    {
        byte[] key;
        lock (_sync)
        {
            ThrowIfDisposed();
            key = _keys[_currentKeyId].Copy();
        }

        var nonce = RandomNumberGenerator.GetBytes(NonceLength);
        var aad = BuildHeader(_currentKeyId, nonce);
        var maximumPlaintextSize = MaximumProtectedStateSize - aad.Length - TagLength;
        byte[]? plaintext = null;
        try
        {
            plaintext = cache.ExportStatePlaintext(maximumPlaintextSize);
            var output = GC.AllocateUninitializedArray<byte>(aad.Length + plaintext.Length + TagLength);
            aad.CopyTo(output, 0);
            using var aes = new AesGcm(key, TagLength);
            aes.Encrypt(
                nonce,
                plaintext,
                output.AsSpan(aad.Length, plaintext.Length),
                output.AsSpan(aad.Length + plaintext.Length, TagLength),
                aad);
            return output;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(key);
            CryptographicOperations.ZeroMemory(nonce);
            CryptographicOperations.ZeroMemory(aad);
            if (plaintext is not null)
            {
                CryptographicOperations.ZeroMemory(plaintext);
            }
        }
    }

    internal void UnprotectInto(Tls13SessionCache cache, ReadOnlySpan<byte> protectedState)
    {
        if (protectedState.Length > MaximumProtectedStateSize)
        {
            throw new InvalidDataException("The protected TLS session state exceeds the configured size limit.");
        }

        string keyId;
        int aadLength;
        try
        {
            var reader = new TlsBinaryReader(protectedState);
            if (!reader.ReadBytes(4).SequenceEqual("STSC"u8) || reader.ReadUInt8() != 1)
            {
                throw new InvalidDataException("The protected TLS session state format is unsupported.");
            }
            var encodedKeyId = reader.ReadVector8(MaximumKeyIdLength);
            keyId = Encoding.ASCII.GetString(encodedKeyId);
            ValidateKeyId(keyId);
            _ = reader.ReadBytes(NonceLength);
            aadLength = 4 + 1 + 1 + encodedKeyId.Length + NonceLength;
            if (protectedState.Length - aadLength <= TagLength)
            {
                throw new InvalidDataException("The protected TLS session state is truncated.");
            }
        }
        catch (TlsProtocolException exception)
        {
            throw new InvalidDataException("The protected TLS session state is malformed.", exception);
        }
        catch (ArgumentException exception)
        {
            throw new InvalidDataException("The protected TLS session state has an invalid key identifier.", exception);
        }

        byte[] key;
        lock (_sync)
        {
            ThrowIfDisposed();
            if (!_keys.TryGetValue(keyId, out var storedKey))
            {
                throw new CryptographicException("The TLS session state could not be authenticated.");
            }
            key = storedKey.Copy();
        }

        var ciphertextLength = protectedState.Length - aadLength - TagLength;
        var plaintext = GC.AllocateUninitializedArray<byte>(ciphertextLength);
        try
        {
            using var aes = new AesGcm(key, TagLength);
            aes.Decrypt(
                protectedState.Slice(aadLength - NonceLength, NonceLength),
                protectedState.Slice(aadLength, ciphertextLength),
                protectedState.Slice(aadLength + ciphertextLength, TagLength),
                plaintext,
                protectedState[..aadLength]);
            cache.ImportStatePlaintext(plaintext);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(key);
            CryptographicOperations.ZeroMemory(plaintext);
        }
    }

    private static byte[] BuildHeader(string keyId, ReadOnlySpan<byte> nonce)
    {
        var writer = new TlsBinaryWriter();
        writer.WriteBytes("STSC"u8);
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
                "A session-state key identifier must contain 1-64 printable ASCII characters.",
                nameof(keyId));
        }
    }

    private static void ValidateKey(ReadOnlySpan<byte> key)
    {
        if (key.Length != KeyLength)
        {
            throw new ArgumentException("A session-state protection key must contain exactly 32 bytes.", nameof(key));
        }
    }

    private void ThrowIfDisposed() => ObjectDisposedException.ThrowIf(_disposed, this);
}
