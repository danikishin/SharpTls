using System.Security.Cryptography;
using SharpTls.Protocol;

namespace SharpTls;

/// <summary>
/// A bounded, origin-bound in-memory cache for authenticated TLS 1.2 session-ID
/// resumptions. The cache owns and zeroizes every stored master secret.
/// </summary>
public sealed class Tls12SessionCache : IDisposable
{
    private static readonly TimeSpan MaximumAuthenticationAge = TimeSpan.FromDays(7);
    private readonly object _sync = new();
    private readonly LinkedList<Tls12Session> _sessions = new();
    private readonly TimeProvider _timeProvider;
    private readonly int _capacity;
    private readonly TimeSpan _maximumAuthenticationAge;
    private bool _disposed;

    /// <summary>Creates an in-memory TLS 1.2 session cache.</summary>
    public Tls12SessionCache(
        int capacity = 64,
        TimeSpan? maximumAuthenticationAge = null)
        : this(
            capacity,
            maximumAuthenticationAge ?? TimeSpan.FromHours(24),
            TimeProvider.System)
    {
    }

    internal Tls12SessionCache(
        int capacity,
        TimeSpan maximumAuthenticationAge,
        TimeProvider timeProvider)
    {
        if (capacity is < 1 or > 4096)
        {
            throw new ArgumentOutOfRangeException(nameof(capacity));
        }
        if (maximumAuthenticationAge <= TimeSpan.Zero ||
            maximumAuthenticationAge > MaximumAuthenticationAge)
        {
            throw new ArgumentOutOfRangeException(nameof(maximumAuthenticationAge));
        }
        ArgumentNullException.ThrowIfNull(timeProvider);
        _capacity = capacity;
        _maximumAuthenticationAge = maximumAuthenticationAge;
        _timeProvider = timeProvider;
    }

    /// <summary>Gets the number of unexpired cached sessions.</summary>
    public int Count
    {
        get
        {
            lock (_sync)
            {
                ThrowIfDisposed();
                PurgeExpired(_timeProvider.GetUtcNow());
                return _sessions.Count;
            }
        }
    }

    /// <summary>Removes all sessions and zeroizes their master secrets.</summary>
    public void Clear()
    {
        lock (_sync)
        {
            ThrowIfDisposed();
            DisposeAll();
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

    internal DateTimeOffset UtcNow
    {
        get
        {
            lock (_sync)
            {
                ThrowIfDisposed();
                return _timeProvider.GetUtcNow();
            }
        }
    }

    internal DateTimeOffset GetAuthenticationExpiry(DateTimeOffset certificateNotAfter)
    {
        lock (_sync)
        {
            ThrowIfDisposed();
            var localLimit = _timeProvider.GetUtcNow() + _maximumAuthenticationAge;
            return certificateNotAfter < localLimit ? certificateNotAfter : localLimit;
        }
    }

    internal void Add(Tls12Session session)
    {
        ArgumentNullException.ThrowIfNull(session);
        lock (_sync)
        {
            ThrowIfDisposed();
            var now = _timeProvider.GetUtcNow();
            PurgeExpired(now);
            if (!session.IsUsable(now))
            {
                session.Dispose();
                return;
            }

            for (var node = _sessions.First; node is not null;)
            {
                var next = node.Next;
                if (node.Value.Origin == session.Origin &&
                    SameIdentity(node.Value, session))
                {
                    RemoveAndDispose(node);
                }
                node = next;
            }

            _sessions.AddFirst(session);
            while (_sessions.Count > _capacity)
            {
                RemoveAndDispose(_sessions.Last!);
            }
        }
    }

    internal Tls12Session? TryGet(
        Tls13SessionOrigin origin,
        IReadOnlyList<TlsCipherSuite> offeredCipherSuites)
    {
        lock (_sync)
        {
            ThrowIfDisposed();
            var now = _timeProvider.GetUtcNow();
            PurgeExpired(now);
            for (var node = _sessions.First; node is not null; node = node.Next)
            {
                if (!node.Value.CanResume(origin, offeredCipherSuites, now))
                {
                    continue;
                }

                _sessions.Remove(node);
                _sessions.AddFirst(node);
                return node.Value.Clone();
            }
            return null;
        }
    }

    private void PurgeExpired(DateTimeOffset now)
    {
        for (var node = _sessions.First; node is not null;)
        {
            var next = node.Next;
            if (!node.Value.IsUsable(now))
            {
                RemoveAndDispose(node);
            }
            node = next;
        }
    }

    private static bool SameIdentity(Tls12Session left, Tls12Session right)
    {
        if (left.Ticket is not null || right.Ticket is not null)
        {
            return left.Ticket is not null && right.Ticket is not null &&
                CryptographicOperations.FixedTimeEquals(left.Ticket, right.Ticket);
        }
        return CryptographicOperations.FixedTimeEquals(left.SessionId, right.SessionId);
    }

    private void RemoveAndDispose(LinkedListNode<Tls12Session> node)
    {
        _sessions.Remove(node);
        node.Value.Dispose();
    }

    private void DisposeAll()
    {
        foreach (var session in _sessions)
        {
            session.Dispose();
        }
        _sessions.Clear();
    }

    private void ThrowIfDisposed() => ObjectDisposedException.ThrowIf(_disposed, this);
}

internal sealed class Tls12Session : IDisposable
{
    private byte[]? _masterSecret;

    internal Tls12Session(
        Tls13SessionOrigin origin,
        ReadOnlySpan<byte> sessionId,
        TlsCipherSuite cipherSuite,
        string? negotiatedAlpn,
        NamedGroup negotiatedGroup,
        ReadOnlySpan<byte> masterSecret,
        DateTimeOffset expiresAt,
        int? peerRecordSizeLimit,
        int? localRecordSizeLimit,
        IReadOnlyList<byte[]> peerCertificateChain,
        byte[]? stapledOcspResponse,
        IReadOnlyList<byte[]> signedCertificateTimestamps,
        byte[]? ticket = null)
    {
        if (sessionId.Length > TlsConstants.MaxSessionIdLength)
        {
            throw new ArgumentOutOfRangeException(nameof(sessionId));
        }
        if (masterSecret.Length != TlsConstants.Tls12MasterSecretLength)
        {
            throw new ArgumentOutOfRangeException(nameof(masterSecret));
        }
        _ = Cryptography.Tls12CipherSuiteInfo.Get(cipherSuite);
        if (ticket is { Length: > ushort.MaxValue } ||
            (sessionId.IsEmpty && (ticket is null || ticket.Length == 0)))
        {
            throw new ArgumentOutOfRangeException(
                nameof(ticket),
                "A TLS 1.2 session requires a session ID or a non-empty RFC 5077 ticket.");
        }
        Origin = origin;
        SessionId = sessionId.ToArray();
        CipherSuite = cipherSuite;
        NegotiatedAlpn = negotiatedAlpn;
        NegotiatedGroup = negotiatedGroup;
        _masterSecret = masterSecret.ToArray();
        ExpiresAt = expiresAt;
        PeerRecordSizeLimit = peerRecordSizeLimit;
        LocalRecordSizeLimit = localRecordSizeLimit;
        PeerCertificateChain = CloneJagged(peerCertificateChain);
        StapledOcspResponse = stapledOcspResponse is null
            ? null
            : (byte[])stapledOcspResponse.Clone();
        SignedCertificateTimestamps = CloneJagged(signedCertificateTimestamps);
        Ticket = ticket is null ? null : (byte[])ticket.Clone();
    }

    internal Tls13SessionOrigin Origin { get; }
    internal byte[] SessionId { get; }
    internal TlsCipherSuite CipherSuite { get; }
    internal string? NegotiatedAlpn { get; }
    internal NamedGroup NegotiatedGroup { get; }
    internal DateTimeOffset ExpiresAt { get; }
    internal int? PeerRecordSizeLimit { get; }
    internal int? LocalRecordSizeLimit { get; }
    internal byte[][] PeerCertificateChain { get; }
    internal byte[]? StapledOcspResponse { get; }
    internal byte[][] SignedCertificateTimestamps { get; }
    internal byte[]? Ticket { get; }

    internal bool CanResume(
        Tls13SessionOrigin origin,
        IReadOnlyList<TlsCipherSuite> offeredCipherSuites,
        DateTimeOffset now) =>
        IsUsable(now) &&
        Origin == origin &&
        offeredCipherSuites.Contains(CipherSuite);

    internal bool IsUsable(DateTimeOffset now) =>
        _masterSecret is not null && ExpiresAt > now;

    internal byte[] CopyMasterSecret()
    {
        ObjectDisposedException.ThrowIf(_masterSecret is null, this);
        return (byte[])_masterSecret.Clone();
    }

    internal Tls12Session Clone()
    {
        var secret = CopyMasterSecret();
        try
        {
            return new Tls12Session(
                Origin,
                SessionId,
                CipherSuite,
                NegotiatedAlpn,
                NegotiatedGroup,
                secret,
                ExpiresAt,
                PeerRecordSizeLimit,
                LocalRecordSizeLimit,
                PeerCertificateChain,
                StapledOcspResponse,
                SignedCertificateTimestamps,
                Ticket);
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
        CryptographicOperations.ZeroMemory(SessionId);
        foreach (var certificate in PeerCertificateChain)
        {
            CryptographicOperations.ZeroMemory(certificate);
        }
        if (StapledOcspResponse is not null)
        {
            CryptographicOperations.ZeroMemory(StapledOcspResponse);
        }
        foreach (var sct in SignedCertificateTimestamps)
        {
            CryptographicOperations.ZeroMemory(sct);
        }
        if (Ticket is not null)
        {
            CryptographicOperations.ZeroMemory(Ticket);
        }
    }

    private static byte[][] CloneJagged(IReadOnlyList<byte[]> values) =>
        values.Select(value => (byte[])value.Clone()).ToArray();
}
