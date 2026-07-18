using System.Security.Cryptography;
using SharpTls.Protocol;

namespace SharpTls;

/// <summary>
/// Bounded, process-local TLS 1.2 server session-ID cache. The cache owns every stored
/// master secret, zeroizes evicted entries, and must be shared by accepted connections.
/// </summary>
public sealed class Tls12ServerSessionCache : IDisposable
{
    private readonly object _sync = new();
    private readonly Dictionary<string, LinkedListNode<Tls12ServerSession>> _byId =
        new(StringComparer.Ordinal);
    private readonly LinkedList<Tls12ServerSession> _lru = new();
    private readonly TimeProvider _timeProvider;
    private readonly int _capacity;
    private readonly TimeSpan _lifetime;
    private bool _disposed;

    /// <summary>Creates a bounded session-ID cache.</summary>
    public Tls12ServerSessionCache(
        int capacity = 1024,
        TimeSpan? lifetime = null)
        : this(capacity, lifetime ?? TimeSpan.FromHours(24), TimeProvider.System)
    {
    }

    internal Tls12ServerSessionCache(
        int capacity,
        TimeSpan lifetime,
        TimeProvider timeProvider)
    {
        if (capacity is < 1 or > 65536)
        {
            throw new ArgumentOutOfRangeException(nameof(capacity));
        }
        if (lifetime <= TimeSpan.Zero || lifetime > TimeSpan.FromDays(7))
        {
            throw new ArgumentOutOfRangeException(nameof(lifetime));
        }
        _capacity = capacity;
        _lifetime = lifetime;
        _timeProvider = timeProvider ?? throw new ArgumentNullException(nameof(timeProvider));
    }

    /// <summary>Gets the number of unexpired sessions.</summary>
    public int Count
    {
        get
        {
            lock (_sync)
            {
                ThrowIfDisposed();
                PurgeExpired(_timeProvider.GetUtcNow());
                return _byId.Count;
            }
        }
    }

    /// <summary>Removes all sessions and zeroizes their secrets.</summary>
    public void Clear()
    {
        lock (_sync)
        {
            ThrowIfDisposed();
            DisposeAll();
        }
    }

    internal void Add(
        ReadOnlySpan<byte> sessionId,
        TlsCipherSuite cipherSuite,
        string? serverName,
        string? negotiatedAlpn,
        NamedGroup negotiatedGroup,
        ReadOnlySpan<byte> masterSecret)
    {
        if (sessionId.Length is < 1 or > TlsConstants.MaxSessionIdLength)
        {
            throw new ArgumentOutOfRangeException(nameof(sessionId));
        }
        if (masterSecret.Length != TlsConstants.Tls12MasterSecretLength)
        {
            throw new ArgumentOutOfRangeException(nameof(masterSecret));
        }
        _ = Cryptography.Tls12CipherSuiteInfo.Get(cipherSuite);
        var entry = new Tls12ServerSession(
            sessionId,
            cipherSuite,
            serverName,
            negotiatedAlpn,
            negotiatedGroup,
            masterSecret,
            _timeProvider.GetUtcNow() + _lifetime);
        lock (_sync)
        {
            try
            {
                ThrowIfDisposed();
                PurgeExpired(_timeProvider.GetUtcNow());
                var key = Convert.ToHexString(sessionId);
                if (_byId.Remove(key, out var old))
                {
                    _lru.Remove(old);
                    old.Value.Dispose();
                }
                var node = _lru.AddFirst(entry);
                _byId.Add(key, node);
                entry = null!;
                while (_lru.Count > _capacity)
                {
                    Remove(_lru.Last!);
                }
            }
            finally
            {
                entry?.Dispose();
            }
        }
    }

    internal Tls12ServerSession? TryGet(
        ReadOnlySpan<byte> sessionId,
        IReadOnlyList<TlsCipherSuite> offeredCipherSuites,
        IReadOnlyList<TlsCipherSuite> enabledCipherSuites,
        string? serverName,
        IReadOnlyList<string> offeredAlpn)
    {
        if (sessionId.IsEmpty)
        {
            return null;
        }
        lock (_sync)
        {
            ThrowIfDisposed();
            var now = _timeProvider.GetUtcNow();
            PurgeExpired(now);
            if (!_byId.TryGetValue(Convert.ToHexString(sessionId), out var node) ||
                !node.Value.CanResume(
                    now,
                    offeredCipherSuites,
                    enabledCipherSuites,
                    serverName,
                    offeredAlpn))
            {
                return null;
            }
            _lru.Remove(node);
            _lru.AddFirst(node);
            return node.Value.Clone();
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
            DisposeAll();
        }
    }

    private void PurgeExpired(DateTimeOffset now)
    {
        for (var node = _lru.Last; node is not null;)
        {
            var previous = node.Previous;
            if (!node.Value.IsUsable(now))
            {
                Remove(node);
            }
            node = previous;
        }
    }

    private void Remove(LinkedListNode<Tls12ServerSession> node)
    {
        _byId.Remove(Convert.ToHexString(node.Value.SessionId));
        _lru.Remove(node);
        node.Value.Dispose();
    }

    private void DisposeAll()
    {
        foreach (var entry in _lru)
        {
            entry.Dispose();
        }
        _lru.Clear();
        _byId.Clear();
    }

    private void ThrowIfDisposed() => ObjectDisposedException.ThrowIf(_disposed, this);
}

internal sealed class Tls12ServerSession : IDisposable
{
    private byte[]? _masterSecret;

    internal Tls12ServerSession(
        ReadOnlySpan<byte> sessionId,
        TlsCipherSuite cipherSuite,
        string? serverName,
        string? negotiatedAlpn,
        NamedGroup negotiatedGroup,
        ReadOnlySpan<byte> masterSecret,
        DateTimeOffset expiresAt)
    {
        SessionId = sessionId.ToArray();
        CipherSuite = cipherSuite;
        ServerName = serverName;
        NegotiatedAlpn = negotiatedAlpn;
        NegotiatedGroup = negotiatedGroup;
        _masterSecret = masterSecret.ToArray();
        ExpiresAt = expiresAt;
    }

    internal byte[] SessionId { get; }
    internal TlsCipherSuite CipherSuite { get; }
    internal string? ServerName { get; }
    internal string? NegotiatedAlpn { get; }
    internal NamedGroup NegotiatedGroup { get; }
    internal DateTimeOffset ExpiresAt { get; }

    internal bool IsUsable(DateTimeOffset now) => _masterSecret is not null && ExpiresAt > now;

    internal bool CanResume(
        DateTimeOffset now,
        IReadOnlyList<TlsCipherSuite> offeredCipherSuites,
        IReadOnlyList<TlsCipherSuite> enabledCipherSuites,
        string? serverName,
        IReadOnlyList<string> offeredAlpn) =>
        IsUsable(now) &&
        offeredCipherSuites.Contains(CipherSuite) &&
        enabledCipherSuites.Contains(CipherSuite) &&
        string.Equals(ServerName, serverName, StringComparison.OrdinalIgnoreCase) &&
        (NegotiatedAlpn is null
            ? offeredAlpn.Count == 0
            : offeredAlpn.Contains(NegotiatedAlpn, StringComparer.Ordinal));

    internal byte[] CopyMasterSecret()
    {
        ObjectDisposedException.ThrowIf(_masterSecret is null, this);
        return (byte[])_masterSecret.Clone();
    }

    internal Tls12ServerSession Clone()
    {
        var secret = CopyMasterSecret();
        try
        {
            return new Tls12ServerSession(
                SessionId,
                CipherSuite,
                ServerName,
                NegotiatedAlpn,
                NegotiatedGroup,
                secret,
                ExpiresAt);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(secret);
        }
    }

    public void Dispose()
    {
        CryptographicOperations.ZeroMemory(SessionId);
        if (_masterSecret is not null)
        {
            CryptographicOperations.ZeroMemory(_masterSecret);
            _masterSecret = null;
        }
    }
}
