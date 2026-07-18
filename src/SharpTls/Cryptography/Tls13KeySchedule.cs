using System.Security.Cryptography;

namespace SharpTls.Cryptography;

internal sealed class Tls13KeySchedule : IDisposable
{
    private readonly CipherSuiteInfo _suite;
    private SecretBuffer? _earlySecret;
    private SecretBuffer? _clientEarlyTrafficSecret;
    private SecretBuffer? _handshakeSecret;
    private SecretBuffer? _mainSecret;
    private SecretBuffer? _clientHandshakeTrafficSecret;
    private SecretBuffer? _serverHandshakeTrafficSecret;
    private SecretBuffer? _clientApplicationTrafficSecret;
    private SecretBuffer? _serverApplicationTrafficSecret;
    private SecretBuffer? _exporterSecret;
    private SecretBuffer? _resumptionMasterSecret;
    private bool _disposed;

    internal Tls13KeySchedule(CipherSuiteInfo suite, ReadOnlySpan<byte> psk = default)
    {
        _suite = suite;
        var zeros = new byte[suite.HashLength];
        try
        {
            _earlySecret = Own(Tls13Hkdf.Extract(
                suite.HashAlgorithm,
                psk.IsEmpty ? zeros : psk,
                zeros));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(zeros);
        }
    }

    internal void DeriveHandshakeSecrets(ReadOnlySpan<byte> sharedSecret, ReadOnlySpan<byte> helloTranscriptHash)
    {
        ThrowIfDisposed();
        if (_handshakeSecret is not null)
        {
            throw new InvalidOperationException("Handshake secrets have already been derived.");
        }
        if (helloTranscriptHash.Length != _suite.HashLength)
        {
            throw new ArgumentException("Transcript hash length does not match the cipher suite.", nameof(helloTranscriptHash));
        }

        var emptyHash = HashEmpty(_suite.HashAlgorithm);
        var derived = Tls13Hkdf.DeriveSecret(_suite, _earlySecret!.Span, "derived", emptyHash);
        var handshake = Tls13Hkdf.Extract(_suite.HashAlgorithm, sharedSecret, derived);
        _handshakeSecret = new SecretBuffer(handshake);

        _clientHandshakeTrafficSecret = Own(Tls13Hkdf.DeriveSecret(
            _suite,
            handshake,
            "c hs traffic",
            helloTranscriptHash));
        _serverHandshakeTrafficSecret = Own(Tls13Hkdf.DeriveSecret(
            _suite,
            handshake,
            "s hs traffic",
            helloTranscriptHash));

        CryptographicOperations.ZeroMemory(emptyHash);
        CryptographicOperations.ZeroMemory(derived);
        CryptographicOperations.ZeroMemory(handshake);
        _earlySecret.Dispose();
        _earlySecret = null;
    }

    internal void DeriveClientEarlyTrafficSecret(ReadOnlySpan<byte> clientHelloHash)
    {
        ThrowIfDisposed();
        if (_earlySecret is null || _handshakeSecret is not null ||
            _clientEarlyTrafficSecret is not null)
        {
            throw new InvalidOperationException("Early traffic secret derivation is out of sequence.");
        }
        if (clientHelloHash.Length != _suite.HashLength)
        {
            throw new ArgumentException(
                "ClientHello hash length does not match the cipher suite.",
                nameof(clientHelloHash));
        }

        _clientEarlyTrafficSecret = Own(Tls13Hkdf.DeriveSecret(
            _suite,
            _earlySecret.Span,
            "c e traffic",
            clientHelloHash));
    }

    internal (byte[] Key, byte[] Iv) TakeClientEarlyTrafficKeys()
    {
        var secret = GetSecret(_clientEarlyTrafficSecret);
        var keys = DeriveTrafficKeys(secret);
        _clientEarlyTrafficSecret!.Dispose();
        _clientEarlyTrafficSecret = null;
        return keys;
    }

    internal void DeriveMainSecret()
    {
        ThrowIfDisposed();
        if (_handshakeSecret is null || _mainSecret is not null)
        {
            throw new InvalidOperationException("Main secret derivation is out of sequence.");
        }

        var emptyHash = HashEmpty(_suite.HashAlgorithm);
        var derived = Tls13Hkdf.DeriveSecret(_suite, _handshakeSecret.Span, "derived", emptyHash);
        var zeros = new byte[_suite.HashLength];
        _mainSecret = Own(Tls13Hkdf.Extract(_suite.HashAlgorithm, zeros, derived));

        CryptographicOperations.ZeroMemory(emptyHash);
        CryptographicOperations.ZeroMemory(derived);
        CryptographicOperations.ZeroMemory(zeros);
        _handshakeSecret.Dispose();
        _handshakeSecret = null;
    }

    internal void DeriveApplicationTrafficSecrets(ReadOnlySpan<byte> serverFinishedTranscriptHash)
    {
        ThrowIfDisposed();
        if (_mainSecret is null || _clientApplicationTrafficSecret is not null)
        {
            throw new InvalidOperationException("Application traffic secret derivation is out of sequence.");
        }
        if (serverFinishedTranscriptHash.Length != _suite.HashLength)
        {
            throw new ArgumentException(
                "Transcript hash length does not match the cipher suite.",
                nameof(serverFinishedTranscriptHash));
        }

        _clientApplicationTrafficSecret = Own(Tls13Hkdf.DeriveSecret(
            _suite,
            _mainSecret.Span,
            "c ap traffic",
            serverFinishedTranscriptHash));
        _serverApplicationTrafficSecret = Own(Tls13Hkdf.DeriveSecret(
            _suite,
            _mainSecret.Span,
            "s ap traffic",
            serverFinishedTranscriptHash));
        _exporterSecret = Own(Tls13Hkdf.DeriveSecret(
            _suite,
            _mainSecret.Span,
            "exp master",
            serverFinishedTranscriptHash));
    }

    internal void DeriveResumptionMasterSecret(ReadOnlySpan<byte> clientFinishedTranscriptHash)
    {
        ThrowIfDisposed();
        if (_mainSecret is null || _clientApplicationTrafficSecret is null ||
            _resumptionMasterSecret is not null)
        {
            throw new InvalidOperationException(
                "Resumption master secret derivation is out of sequence.");
        }
        if (clientFinishedTranscriptHash.Length != _suite.HashLength)
        {
            throw new ArgumentException(
                "Transcript hash length does not match the cipher suite.",
                nameof(clientFinishedTranscriptHash));
        }

        _resumptionMasterSecret = Own(Tls13Hkdf.DeriveSecret(
            _suite,
            _mainSecret.Span,
            "res master",
            clientFinishedTranscriptHash));
    }

    internal byte[] DeriveResumptionPsk(ReadOnlySpan<byte> ticketNonce)
    {
        if (ticketNonce.Length > byte.MaxValue)
        {
            throw new ArgumentOutOfRangeException(nameof(ticketNonce));
        }

        return Tls13Hkdf.ExpandLabel(
            _suite.HashAlgorithm,
            GetSecret(_resumptionMasterSecret),
            "resumption",
            ticketNonce,
            _suite.HashLength);
    }

    internal byte[] ComputeResumptionBinder(ReadOnlySpan<byte> truncatedClientHelloHash)
        => ComputePskBinder(truncatedClientHelloHash, external: false);

    internal byte[] ComputeExternalBinder(ReadOnlySpan<byte> truncatedClientHelloHash)
        => ComputePskBinder(truncatedClientHelloHash, external: true);

    private byte[] ComputePskBinder(
        ReadOnlySpan<byte> truncatedClientHelloHash,
        bool external)
    {
        if (truncatedClientHelloHash.Length != _suite.HashLength)
        {
            throw new ArgumentException(
                "Binder transcript hash length does not match the cipher suite.",
                nameof(truncatedClientHelloHash));
        }

        var emptyHash = HashEmpty(_suite.HashAlgorithm);
        var binderKey = Tls13Hkdf.DeriveSecret(
            _suite,
            GetSecret(_earlySecret),
            external ? "ext binder" : "res binder",
            emptyHash);
        var finishedKey = Tls13Hkdf.ExpandLabel(
            _suite.HashAlgorithm,
            binderKey,
            "finished",
            [],
            _suite.HashLength);
        try
        {
            return _suite.HashAlgorithm.Name switch
            {
                "SHA256" => HMACSHA256.HashData(finishedKey, truncatedClientHelloHash),
                "SHA384" => HMACSHA384.HashData(finishedKey, truncatedClientHelloHash),
                _ => throw new NotSupportedException(),
            };
        }
        finally
        {
            CryptographicOperations.ZeroMemory(emptyHash);
            CryptographicOperations.ZeroMemory(binderKey);
            CryptographicOperations.ZeroMemory(finishedKey);
        }
    }

    internal byte[] ComputeServerFinished(ReadOnlySpan<byte> transcriptHash) =>
        ComputeFinished(GetSecret(_serverHandshakeTrafficSecret), transcriptHash);

    internal byte[] ComputeClientFinished(ReadOnlySpan<byte> transcriptHash) =>
        ComputeFinished(GetSecret(_clientHandshakeTrafficSecret), transcriptHash);

    internal byte[] ComputeClientApplicationFinished(ReadOnlySpan<byte> transcriptHash) =>
        ComputeFinished(GetSecret(_clientApplicationTrafficSecret), transcriptHash);

    internal byte[] CopyClientEarlyTrafficSecret() =>
        GetSecret(_clientEarlyTrafficSecret).ToArray();

    internal byte[] CopyClientHandshakeTrafficSecret() =>
        GetSecret(_clientHandshakeTrafficSecret).ToArray();

    internal byte[] CopyServerHandshakeTrafficSecret() =>
        GetSecret(_serverHandshakeTrafficSecret).ToArray();

    internal byte[] CopyClientApplicationTrafficSecret() =>
        GetSecret(_clientApplicationTrafficSecret).ToArray();

    internal byte[] CopyServerApplicationTrafficSecret() =>
        GetSecret(_serverApplicationTrafficSecret).ToArray();

    internal byte[] CopyExporterSecret() => GetSecret(_exporterSecret).ToArray();

    internal (byte[] Key, byte[] Iv) GetServerHandshakeKeys() =>
        DeriveTrafficKeys(GetSecret(_serverHandshakeTrafficSecret));

    internal (byte[] Key, byte[] Iv) GetClientHandshakeKeys() =>
        DeriveTrafficKeys(GetSecret(_clientHandshakeTrafficSecret));

    internal (byte[] Key, byte[] Iv) GetServerApplicationKeys() =>
        DeriveTrafficKeys(GetSecret(_serverApplicationTrafficSecret));

    internal (byte[] Key, byte[] Iv) GetClientApplicationKeys() =>
        DeriveTrafficKeys(GetSecret(_clientApplicationTrafficSecret));

    internal void UpdateServerApplicationTrafficSecret() =>
        UpdateApplicationTrafficSecret(ref _serverApplicationTrafficSecret);

    internal void UpdateClientApplicationTrafficSecret() =>
        UpdateApplicationTrafficSecret(ref _clientApplicationTrafficSecret);

    internal byte[] ExportKeyingMaterial(
        string label,
        ReadOnlySpan<byte> context,
        int outputLength)
    {
        ThrowIfDisposed();
        ValidateExporterLabel(label);
        var maximumLength = Math.Min(ushort.MaxValue, checked(255 * _suite.HashLength));
        if (outputLength is < 0 || outputLength > maximumLength)
        {
            throw new ArgumentOutOfRangeException(nameof(outputLength));
        }

        var emptyHash = HashEmpty(_suite.HashAlgorithm);
        var contextHash = Hash(_suite.HashAlgorithm, context);
        var derived = Tls13Hkdf.DeriveSecret(
            _suite,
            GetSecret(_exporterSecret),
            label,
            emptyHash);
        try
        {
            return Tls13Hkdf.ExpandLabel(
                _suite.HashAlgorithm,
                derived,
                "exporter",
                contextHash,
                outputLength);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(emptyHash);
            CryptographicOperations.ZeroMemory(contextHash);
            CryptographicOperations.ZeroMemory(derived);
        }
    }

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;
        _earlySecret?.Dispose();
        _clientEarlyTrafficSecret?.Dispose();
        _handshakeSecret?.Dispose();
        _mainSecret?.Dispose();
        _clientHandshakeTrafficSecret?.Dispose();
        _serverHandshakeTrafficSecret?.Dispose();
        _clientApplicationTrafficSecret?.Dispose();
        _serverApplicationTrafficSecret?.Dispose();
        _exporterSecret?.Dispose();
        _resumptionMasterSecret?.Dispose();
    }

    private byte[] ComputeFinished(ReadOnlySpan<byte> trafficSecret, ReadOnlySpan<byte> transcriptHash)
    {
        if (transcriptHash.Length != _suite.HashLength)
        {
            throw new ArgumentException("Transcript hash length does not match the suite.", nameof(transcriptHash));
        }

        var finishedKey = Tls13Hkdf.ExpandLabel(
            _suite.HashAlgorithm,
            trafficSecret,
            "finished",
            [],
            _suite.HashLength);
        try
        {
            return _suite.HashAlgorithm.Name switch
            {
                "SHA256" => HMACSHA256.HashData(finishedKey, transcriptHash),
                "SHA384" => HMACSHA384.HashData(finishedKey, transcriptHash),
                _ => throw new NotSupportedException(),
            };
        }
        finally
        {
            CryptographicOperations.ZeroMemory(finishedKey);
        }
    }

    private (byte[] Key, byte[] Iv) DeriveTrafficKeys(ReadOnlySpan<byte> trafficSecret) =>
    (
        Tls13Hkdf.ExpandLabel(_suite.HashAlgorithm, trafficSecret, "key", [], _suite.KeyLength),
        Tls13Hkdf.ExpandLabel(_suite.HashAlgorithm, trafficSecret, "iv", [], _suite.IvLength)
    );

    private void UpdateApplicationTrafficSecret(ref SecretBuffer? current)
    {
        var currentSecret = GetSecret(current);
        var nextBytes = Tls13Hkdf.ExpandLabel(
            _suite.HashAlgorithm,
            currentSecret,
            "traffic upd",
            [],
            _suite.HashLength);
        SecretBuffer next;
        try
        {
            next = new SecretBuffer(nextBytes);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(nextBytes);
        }

        current!.Dispose();
        current = next;
    }

    private static SecretBuffer Own(byte[] value)
    {
        try
        {
            return new SecretBuffer(value);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(value);
        }
    }

    private static byte[] HashEmpty(HashAlgorithmName algorithm) => algorithm.Name switch
    {
        "SHA256" => SHA256.HashData([]),
        "SHA384" => SHA384.HashData([]),
        _ => throw new NotSupportedException(),
    };

    private static byte[] Hash(HashAlgorithmName algorithm, ReadOnlySpan<byte> value) =>
        algorithm.Name switch
        {
            "SHA256" => SHA256.HashData(value),
            "SHA384" => SHA384.HashData(value),
            _ => throw new NotSupportedException(),
        };

    private static void ValidateExporterLabel(string label)
    {
        ArgumentException.ThrowIfNullOrEmpty(label);
        if (label.Length > 249 || label.Any(character => character is < ' ' or > '~'))
        {
            throw new ArgumentException(
                "TLS exporter labels must contain 1-249 printable ASCII characters.",
                nameof(label));
        }
        if (label is "client finished" or "server finished" or "master secret" or "key expansion")
        {
            throw new ArgumentException("The TLS exporter label is reserved.", nameof(label));
        }
    }

    private ReadOnlySpan<byte> GetSecret(SecretBuffer? secret)
    {
        ThrowIfDisposed();
        if (secret is null)
        {
            throw new InvalidOperationException("The requested traffic secret is unavailable.");
        }

        return secret.Span;
    }

    private void ThrowIfDisposed() => ObjectDisposedException.ThrowIf(_disposed, this);
}
