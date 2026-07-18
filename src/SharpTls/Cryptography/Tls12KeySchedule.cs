using System.Security.Cryptography;
using SharpTls.Protocol;

namespace SharpTls.Cryptography;

internal sealed record Tls12TrafficKeys(byte[] Key, byte[] FixedIv);

internal sealed class Tls12KeySchedule : IDisposable
{
    private readonly Tls12CipherSuiteInfo _suite;
    private SecretBuffer? _masterSecret;
    private SecretBuffer? _clientWriteKey;
    private SecretBuffer? _serverWriteKey;
    private SecretBuffer? _clientWriteIv;
    private SecretBuffer? _serverWriteIv;
    private bool _disposed;

    internal Tls12KeySchedule(Tls12CipherSuiteInfo suite)
    {
        _suite = suite ?? throw new ArgumentNullException(nameof(suite));
    }

    internal void DeriveExtendedMasterSecret(
        ReadOnlySpan<byte> preMasterSecret,
        ReadOnlySpan<byte> sessionHash)
    {
        ValidateHash(sessionHash, nameof(sessionHash));
        DeriveMasterSecretCore(preMasterSecret, "extended master secret", sessionHash);
    }

    internal void DeriveLegacyMasterSecret(
        ReadOnlySpan<byte> preMasterSecret,
        ReadOnlySpan<byte> clientRandom,
        ReadOnlySpan<byte> serverRandom)
    {
        ValidateRandom(clientRandom, nameof(clientRandom));
        ValidateRandom(serverRandom, nameof(serverRandom));
        var seed = new byte[TlsConstants.RandomLength * 2];
        clientRandom.CopyTo(seed);
        serverRandom.CopyTo(seed.AsSpan(TlsConstants.RandomLength));
        try
        {
            DeriveMasterSecretCore(preMasterSecret, "master secret", seed);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(seed);
        }
    }

    internal void ImportMasterSecret(ReadOnlySpan<byte> masterSecret)
    {
        ThrowIfDisposed();
        if (masterSecret.Length != TlsConstants.Tls12MasterSecretLength)
        {
            throw new ArgumentException(
                "A TLS 1.2 master secret must contain exactly 48 bytes.",
                nameof(masterSecret));
        }
        if (_masterSecret is not null)
        {
            throw new InvalidOperationException("The TLS 1.2 master secret has already been set.");
        }
        _masterSecret = Own(masterSecret);
    }

    internal void DeriveTrafficKeys(
        ReadOnlySpan<byte> clientRandom,
        ReadOnlySpan<byte> serverRandom)
    {
        ThrowIfDisposed();
        ValidateRandom(clientRandom, nameof(clientRandom));
        ValidateRandom(serverRandom, nameof(serverRandom));
        if (_masterSecret is null)
        {
            throw new InvalidOperationException("The TLS 1.2 master secret has not been derived.");
        }
        if (_clientWriteKey is not null)
        {
            throw new InvalidOperationException("TLS 1.2 traffic keys have already been derived.");
        }

        var seed = new byte[TlsConstants.RandomLength * 2];
        serverRandom.CopyTo(seed);
        clientRandom.CopyTo(seed.AsSpan(TlsConstants.RandomLength));
        var keyBlock = Tls12Prf.Expand(
            _suite.PrfHashAlgorithm,
            _masterSecret.Span,
            "key expansion",
            seed,
            _suite.KeyBlockLength);
        try
        {
            var offset = 0;
            _clientWriteKey = Own(keyBlock.AsSpan(offset, _suite.KeyLength));
            offset += _suite.KeyLength;
            _serverWriteKey = Own(keyBlock.AsSpan(offset, _suite.KeyLength));
            offset += _suite.KeyLength;
            _clientWriteIv = Own(keyBlock.AsSpan(offset, _suite.FixedIvLength));
            offset += _suite.FixedIvLength;
            _serverWriteIv = Own(keyBlock.AsSpan(offset, _suite.FixedIvLength));
        }
        catch
        {
            DisposeTrafficKeys();
            throw;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(seed);
            CryptographicOperations.ZeroMemory(keyBlock);
        }
    }

    internal Tls12TrafficKeys GetClientWriteKeys() => GetTrafficKeys(_clientWriteKey, _clientWriteIv);

    internal Tls12TrafficKeys GetServerWriteKeys() => GetTrafficKeys(_serverWriteKey, _serverWriteIv);

    internal byte[] ComputeClientFinished(ReadOnlySpan<byte> transcriptHash) =>
        ComputeFinished("client finished", transcriptHash);

    internal byte[] ComputeServerFinished(ReadOnlySpan<byte> transcriptHash) =>
        ComputeFinished("server finished", transcriptHash);

    internal byte[] CopyMasterSecret()
    {
        ThrowIfDisposed();
        return (_masterSecret ??
            throw new InvalidOperationException("The TLS 1.2 master secret is unavailable."))
            .Copy();
    }

    internal byte[] ExportKeyingMaterial(
        string label,
        ReadOnlySpan<byte> clientRandom,
        ReadOnlySpan<byte> serverRandom,
        ReadOnlySpan<byte> context,
        int outputLength)
    {
        ThrowIfDisposed();
        ArgumentException.ThrowIfNullOrEmpty(label);
        ValidateRandom(clientRandom, nameof(clientRandom));
        ValidateRandom(serverRandom, nameof(serverRandom));
        if (context.Length > ushort.MaxValue || outputLength is < 0 or > ushort.MaxValue)
        {
            throw new ArgumentOutOfRangeException(
                context.Length > ushort.MaxValue ? nameof(context) : nameof(outputLength));
        }
        if (label.Any(character => character is < ' ' or > '~') ||
            label is "client finished" or "server finished" or
                "master secret" or "key expansion")
        {
            throw new ArgumentException("TLS 1.2 exporter label is invalid or reserved.", nameof(label));
        }
        var seed = new byte[2 * TlsConstants.RandomLength + 2 + context.Length];
        clientRandom.CopyTo(seed);
        serverRandom.CopyTo(seed.AsSpan(TlsConstants.RandomLength));
        seed[2 * TlsConstants.RandomLength] = (byte)(context.Length >> 8);
        seed[2 * TlsConstants.RandomLength + 1] = (byte)context.Length;
        context.CopyTo(seed.AsSpan(2 * TlsConstants.RandomLength + 2));
        try
        {
            return Tls12Prf.Expand(
                _suite.PrfHashAlgorithm,
                (_masterSecret ?? throw new InvalidOperationException(
                    "The TLS 1.2 master secret is unavailable.")).Span,
                label,
                seed,
                outputLength);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(seed);
        }
    }

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;
        _masterSecret?.Dispose();
        DisposeTrafficKeys();
    }

    private void DeriveMasterSecretCore(
        ReadOnlySpan<byte> preMasterSecret,
        string label,
        ReadOnlySpan<byte> seed)
    {
        ThrowIfDisposed();
        if (preMasterSecret.IsEmpty)
        {
            throw new ArgumentException("The TLS 1.2 pre-master secret must not be empty.", nameof(preMasterSecret));
        }
        if (_masterSecret is not null)
        {
            throw new InvalidOperationException("The TLS 1.2 master secret has already been derived.");
        }

        var masterSecret = Tls12Prf.Expand(
            _suite.PrfHashAlgorithm,
            preMasterSecret,
            label,
            seed,
            TlsConstants.Tls12MasterSecretLength);
        try
        {
            _masterSecret = Own(masterSecret);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(masterSecret);
        }
    }

    private byte[] ComputeFinished(string label, ReadOnlySpan<byte> transcriptHash)
    {
        ThrowIfDisposed();
        ValidateHash(transcriptHash, nameof(transcriptHash));
        if (_masterSecret is null)
        {
            throw new InvalidOperationException("The TLS 1.2 master secret has not been derived.");
        }

        return Tls12Prf.Expand(
            _suite.PrfHashAlgorithm,
            _masterSecret.Span,
            label,
            transcriptHash,
            TlsConstants.Tls12FinishedLength);
    }

    private Tls12TrafficKeys GetTrafficKeys(SecretBuffer? key, SecretBuffer? iv)
    {
        ThrowIfDisposed();
        if (key is null || iv is null)
        {
            throw new InvalidOperationException("TLS 1.2 traffic keys have not been derived.");
        }

        return new Tls12TrafficKeys(key.Copy(), iv.Copy());
    }

    private void ValidateHash(ReadOnlySpan<byte> hash, string parameterName)
    {
        if (hash.Length != _suite.HashLength)
        {
            throw new ArgumentException(
                "The transcript hash length does not match the TLS 1.2 cipher suite.",
                parameterName);
        }
    }

    private static void ValidateRandom(ReadOnlySpan<byte> random, string parameterName)
    {
        if (random.Length != TlsConstants.RandomLength)
        {
            throw new ArgumentException("TLS random values must contain exactly 32 bytes.", parameterName);
        }
    }

    private static SecretBuffer Own(ReadOnlySpan<byte> value) => new(value);

    private void DisposeTrafficKeys()
    {
        _clientWriteKey?.Dispose();
        _serverWriteKey?.Dispose();
        _clientWriteIv?.Dispose();
        _serverWriteIv?.Dispose();
        _clientWriteKey = null;
        _serverWriteKey = null;
        _clientWriteIv = null;
        _serverWriteIv = null;
    }

    private void ThrowIfDisposed() => ObjectDisposedException.ThrowIf(_disposed, this);
}
