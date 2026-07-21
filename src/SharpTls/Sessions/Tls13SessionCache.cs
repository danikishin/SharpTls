using System.Globalization;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using SharpTls.Cryptography;
using SharpTls.IO;
using SharpTls.Protocol;

namespace SharpTls;

/// <summary>
/// Stores bounded, origin-bound TLS 1.3 resumption tickets. The cache owns and
/// zeroizes ticket PSKs and must be shared by clients that should resume sessions.
/// </summary>
public sealed class Tls13SessionCache : IDisposable
{
    private static readonly TimeSpan MaximumTicketLifetime = TimeSpan.FromDays(7);

    private readonly object _sync = new();
    private readonly LinkedList<Tls13SessionTicket> _tickets = new();
    private readonly TimeProvider _timeProvider;
    private readonly int _capacity;
    private readonly int _maximumTicketsPerOrigin;
    private readonly TimeSpan _maximumAuthenticationAge;
    private bool _disposed;

    /// <summary>
    /// Creates a cache. Resumption authentication is never extended beyond
    /// <paramref name="maximumAuthenticationAge"/> from the original certificate handshake.
    /// </summary>
    public Tls13SessionCache(
        int capacity = 64,
        int maximumTicketsPerOrigin = 4,
        TimeSpan? maximumAuthenticationAge = null)
        : this(
            capacity,
            maximumTicketsPerOrigin,
            maximumAuthenticationAge ?? MaximumTicketLifetime,
            TimeProvider.System)
    {
    }

    internal Tls13SessionCache(
        int capacity,
        int maximumTicketsPerOrigin,
        TimeSpan maximumAuthenticationAge,
        TimeProvider timeProvider)
    {
        if (capacity is < 1 or > 4096)
        {
            throw new ArgumentOutOfRangeException(nameof(capacity));
        }
        if (maximumTicketsPerOrigin is < 1 or > 64 || maximumTicketsPerOrigin > capacity)
        {
            throw new ArgumentOutOfRangeException(nameof(maximumTicketsPerOrigin));
        }
        if (maximumAuthenticationAge <= TimeSpan.Zero ||
            maximumAuthenticationAge > MaximumTicketLifetime)
        {
            throw new ArgumentOutOfRangeException(nameof(maximumAuthenticationAge));
        }

        ArgumentNullException.ThrowIfNull(timeProvider);
        _capacity = capacity;
        _maximumTicketsPerOrigin = maximumTicketsPerOrigin;
        _maximumAuthenticationAge = maximumAuthenticationAge;
        _timeProvider = timeProvider;
    }

    /// <summary>Gets the number of currently cached tickets.</summary>
    public int Count
    {
        get
        {
            lock (_sync)
            {
                ThrowIfDisposed();
                PurgeExpired(_timeProvider.GetUtcNow());
                return _tickets.Count;
            }
        }
    }

    /// <summary>
    /// Exports every unexpired ticket as one authenticated, encrypted state blob.
    /// The returned bytes are safe to persist only while the protector key remains secret.
    /// </summary>
    public byte[] ExportEncrypted(Tls13SessionStateProtector protector)
    {
        ArgumentNullException.ThrowIfNull(protector);
        return protector.Protect(this);
    }

    /// <summary>
    /// Authenticates, decrypts, validates, and atomically imports a persisted ticket set.
    /// Existing capacity, per-origin, expiry, ALPN, ECH, and single-use policies still apply.
    /// </summary>
    public void ImportEncrypted(
        ReadOnlySpan<byte> protectedState,
        Tls13SessionStateProtector protector)
    {
        ArgumentNullException.ThrowIfNull(protector);
        protector.UnprotectInto(this, protectedState);
    }

    /// <summary>Deletes every cached ticket and zeroizes its PSK.</summary>
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

    internal DateTimeOffset GetAuthenticationExpiry(DateTimeOffset certificateNotAfter)
    {
        lock (_sync)
        {
            ThrowIfDisposed();
            var localLimit = _timeProvider.GetUtcNow() + _maximumAuthenticationAge;
            return certificateNotAfter < localLimit ? certificateNotAfter : localLimit;
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

    internal void Add(Tls13SessionTicket ticket)
    {
        ArgumentNullException.ThrowIfNull(ticket);
        lock (_sync)
        {
            ThrowIfDisposed();
            var now = _timeProvider.GetUtcNow();
            PurgeExpired(now);
            AddCore(ticket, now);
        }
    }

    internal byte[] ExportStatePlaintext(int maximumSize)
    {
        lock (_sync)
        {
            ThrowIfDisposed();
            var now = _timeProvider.GetUtcNow();
            PurgeExpired(now);

            var estimatedSize = 7;
            foreach (var ticket in _tickets)
            {
                estimatedSize = checked(estimatedSize + GetSerializedSize(ticket));
                if (estimatedSize > maximumSize)
                {
                    throw new InvalidOperationException(
                        "The encrypted TLS session state would exceed the protector's size limit.");
                }
            }

            var writer = new TlsBinaryWriter(estimatedSize);
            try
            {
                writer.WriteBytes("ST13"u8);
                writer.WriteUInt8(4);
                writer.WriteUInt16((ushort)_tickets.Count);
                foreach (var ticket in _tickets)
                {
                    WriteTicket(writer, ticket);
                }
                return writer.ToArray();
            }
            finally
            {
                // Unlike normal TLS encoders, this writer held resumption PSKs.
                writer.Clear();
            }
        }
    }

    internal void ImportStatePlaintext(ReadOnlySpan<byte> plaintext)
    {
        var imported = new List<Tls13SessionTicket?>();
        try
        {
            ParseStatePlaintext(plaintext, imported);
            lock (_sync)
            {
                ThrowIfDisposed();
                var now = _timeProvider.GetUtcNow();
                PurgeExpired(now);

                // The serialized order is newest first. Insert oldest first so the
                // cache retains the same preference order after AddFirst operations.
                for (var index = imported.Count - 1; index >= 0; index--)
                {
                    var ticket = imported[index]!;
                    imported[index] = null;
                    try
                    {
                        AddCore(ticket, now);
                    }
                    catch
                    {
                        ticket.Dispose();
                        throw;
                    }
                }
            }
        }
        finally
        {
            foreach (var ticket in imported)
            {
                ticket?.Dispose();
            }
        }
    }

    internal Tls13SessionTicket? TryTake(
        Tls13SessionOrigin origin,
        IReadOnlyList<TlsCipherSuite> offeredCipherSuites,
        IReadOnlyList<string> offeredAlpn,
        byte[]? echConfigListHash = null,
        TlsApplicationSettingsCodePoint? applicationSettingsCodePoint = null,
        IReadOnlyDictionary<string, byte[]>? clientApplicationSettings = null)
    {
        var tickets = TryTakeMany(
            origin,
            offeredCipherSuites,
            offeredAlpn,
            maximumCount: 1,
            echConfigListHash,
            applicationSettingsCodePoint,
            clientApplicationSettings);
        return tickets.Count == 0 ? null : tickets[0];
    }

    internal IReadOnlyList<Tls13SessionTicket> TryTakeMany(
        Tls13SessionOrigin origin,
        IReadOnlyList<TlsCipherSuite> offeredCipherSuites,
        IReadOnlyList<string> offeredAlpn,
        int maximumCount,
        byte[]? echConfigListHash = null,
        TlsApplicationSettingsCodePoint? applicationSettingsCodePoint = null,
        IReadOnlyDictionary<string, byte[]>? clientApplicationSettings = null)
    {
        if (maximumCount is < 1 or > 64)
        {
            throw new ArgumentOutOfRangeException(nameof(maximumCount));
        }
        lock (_sync)
        {
            ThrowIfDisposed();
            var now = _timeProvider.GetUtcNow();
            PurgeExpired(now);
            var result = new List<Tls13SessionTicket>(
                Math.Min(maximumCount, _tickets.Count));
            for (var node = _tickets.First; node is not null;)
            {
                var next = node.Next;
                if (!node.Value.CanResume(
                    origin,
                    offeredCipherSuites,
                    offeredAlpn,
                    now,
                    echConfigListHash,
                    applicationSettingsCodePoint,
                    clientApplicationSettings))
                {
                    node = next;
                    continue;
                }

                result.Add(node.Value);
                _tickets.Remove(node);
                if (result.Count == maximumCount)
                {
                    break;
                }
                node = next;
            }

            return result;
        }
    }

    private void TrimOrigin(Tls13SessionOrigin origin)
    {
        var count = 0;
        for (var node = _tickets.First; node is not null;)
        {
            var next = node.Next;
            if (node.Value.Origin == origin && ++count > _maximumTicketsPerOrigin)
            {
                RemoveAndDispose(node);
            }
            node = next;
        }
    }

    private void AddCore(Tls13SessionTicket ticket, DateTimeOffset now)
    {
        if (!ticket.IsCacheable(now))
        {
            ticket.Dispose();
            return;
        }

        for (var node = _tickets.First; node is not null;)
        {
            var next = node.Next;
            if (node.Value.Origin == ticket.Origin &&
                CryptographicOperations.FixedTimeEquals(
                    node.Value.Identity,
                    ticket.Identity))
            {
                RemoveAndDispose(node);
            }
            node = next;
        }

        _tickets.AddFirst(ticket);
        TrimOrigin(ticket.Origin);
        while (_tickets.Count > _capacity)
        {
            RemoveAndDispose(_tickets.Last!);
        }
    }

    private static int GetSerializedSize(Tls13SessionTicket ticket)
    {
        var alpnLength = ticket.NegotiatedAlpn?.Length ?? 0;
        return checked(
            2 + ticket.Origin.Host.Length +
            2 + 1 + 2 +
            1 + alpnLength +
            4 +
            2 + ticket.Identity.Length +
            1 + CipherSuiteInfo.Get(ticket.CipherSuite).HashLength +
            8 + 8 + 8 +
            1 + (ticket.MaximumEarlyDataSize.HasValue ? 4 : 0) +
            2 +
            1 + (ticket.EchConfigListHash is null ? 0 : 32) +
            1 + (ticket.ApplicationSettingsCodePoint.HasValue
                ? 2 + 2 + ticket.PeerApplicationSettings!.Length +
                  2 + ticket.ClientApplicationSettings!.Length
                : 0) +
            1 + (ticket.QuicTransportParameters is null
                ? 0
                : 2 + ticket.QuicTransportParameters.Length));
    }

    private static void WriteTicket(TlsBinaryWriter writer, Tls13SessionTicket ticket)
    {
        writer.WriteVector16(Encoding.ASCII.GetBytes(ticket.Origin.Host));
        writer.WriteUInt16((ushort)(ticket.Origin.Port ?? 0));
        writer.WriteUInt8(ticket.Origin.CertificateValidationSkipped ? (byte)1 : (byte)0);
        writer.WriteUInt16((ushort)ticket.CipherSuite);
        writer.WriteVector8(ticket.NegotiatedAlpn is null
            ? ReadOnlySpan<byte>.Empty
            : Encoding.ASCII.GetBytes(ticket.NegotiatedAlpn));
        writer.WriteUInt32(ticket.AgeAdd);
        writer.WriteVector16(ticket.Identity);

        var psk = ticket.CopyPsk();
        try
        {
            writer.WriteVector8(psk);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(psk);
        }

        writer.WriteUInt64(CheckedUnixMilliseconds(ticket.IssuedAt));
        writer.WriteUInt64(CheckedUnixMilliseconds(ticket.ExpiresAt));
        writer.WriteUInt64(CheckedUnixMilliseconds(ticket.AuthenticationExpiresAt));
        writer.WriteUInt8(ticket.MaximumEarlyDataSize.HasValue ? (byte)1 : (byte)0);
        if (ticket.MaximumEarlyDataSize is { } maximumEarlyDataSize)
        {
            writer.WriteUInt32(maximumEarlyDataSize);
        }
        writer.WriteUInt16((ushort)(ticket.PeerRecordSizeLimit ?? 0));
        writer.WriteUInt8(ticket.EchConfigListHash is null ? (byte)0 : (byte)1);
        if (ticket.EchConfigListHash is not null)
        {
            writer.WriteBytes(ticket.EchConfigListHash);
        }
        writer.WriteUInt8(ticket.ApplicationSettingsCodePoint.HasValue ? (byte)1 : (byte)0);
        if (ticket.ApplicationSettingsCodePoint is { } applicationSettingsCodePoint)
        {
            writer.WriteUInt16((ushort)applicationSettingsCodePoint);
            writer.WriteVector16(ticket.PeerApplicationSettings!);
            writer.WriteVector16(ticket.ClientApplicationSettings!);
        }
        writer.WriteUInt8(ticket.QuicTransportParameters is null ? (byte)0 : (byte)1);
        if (ticket.QuicTransportParameters is not null)
        {
            writer.WriteVector16(ticket.QuicTransportParameters);
        }
    }

    private void ParseStatePlaintext(
        ReadOnlySpan<byte> plaintext,
        List<Tls13SessionTicket?> destination)
    {
        try
        {
            var reader = new TlsBinaryReader(plaintext);
            if (!reader.ReadBytes(4).SequenceEqual("ST13"u8))
            {
                throw new InvalidDataException("The TLS session state has an invalid format marker.");
            }
            var stateVersion = reader.ReadUInt8();
            if (stateVersion is not (1 or 2 or 3 or 4))
            {
                throw new InvalidDataException("The TLS session state version is unsupported.");
            }

            var ticketCount = reader.ReadUInt16();
            if (ticketCount > 4096)
            {
                throw new InvalidDataException("The TLS session state contains too many tickets.");
            }

            var now = _timeProvider.GetUtcNow();
            for (var index = 0; index < ticketCount; index++)
            {
                var host = ReadAscii(reader.ReadVector16(255), allowEmpty: false, "origin host");
                var encodedPort = reader.ReadUInt16();
                var certificateValidationSkipped = false;
                if (stateVersion >= 4)
                {
                    var encodedValidationMode = reader.ReadUInt8();
                    if (encodedValidationMode > 1)
                    {
                        throw new InvalidDataException(
                            "The TLS session state has an invalid certificate-validation mode.");
                    }
                    certificateValidationSkipped = encodedValidationMode == 1;
                }
                var origin = Tls13SessionOrigin.Create(
                    host,
                    encodedPort == 0 ? null : encodedPort,
                    certificateValidationSkipped);
                var cipherSuite = (TlsCipherSuite)reader.ReadUInt16();
                _ = CipherSuiteInfo.Get(cipherSuite);
                var alpnBytes = reader.ReadVector8();
                var alpn = alpnBytes.IsEmpty
                    ? null
                    : ReadAscii(alpnBytes, allowEmpty: false, "ALPN protocol");
                var ageAdd = reader.ReadUInt32();
                var identity = reader.ReadVector16();
                var psk = reader.ReadVector8(64);
                var issuedAt = ReadUnixMilliseconds(reader.ReadUInt64());
                var expiresAt = ReadUnixMilliseconds(reader.ReadUInt64());
                var authenticationExpiresAt = ReadUnixMilliseconds(reader.ReadUInt64());
                ValidateImportedTimes(now, issuedAt, expiresAt, authenticationExpiresAt);

                var hasEarlyData = reader.ReadUInt8();
                if (hasEarlyData > 1)
                {
                    throw new InvalidDataException("The TLS session state has an invalid early-data flag.");
                }
                uint? maximumEarlyDataSize = hasEarlyData == 1 ? reader.ReadUInt32() : null;
                var encodedRecordSizeLimit = reader.ReadUInt16();
                int? peerRecordSizeLimit = encodedRecordSizeLimit == 0
                    ? null
                    : encodedRecordSizeLimit;
                var hasEchBinding = reader.ReadUInt8();
                if (hasEchBinding > 1)
                {
                    throw new InvalidDataException("The TLS session state has an invalid ECH-binding flag.");
                }
                var echBinding = hasEchBinding == 1
                    ? reader.ReadBytes(32).ToArray()
                    : null;
                TlsApplicationSettingsCodePoint? applicationSettingsCodePoint = null;
                byte[]? peerApplicationSettings = null;
                byte[]? clientApplicationSettings = null;
                if (stateVersion >= 2)
                {
                    var hasApplicationSettings = reader.ReadUInt8();
                    if (hasApplicationSettings > 1)
                    {
                        throw new InvalidDataException(
                            "The TLS session state has an invalid application-settings flag.");
                    }
                    if (hasApplicationSettings == 1)
                    {
                        applicationSettingsCodePoint =
                            (TlsApplicationSettingsCodePoint)reader.ReadUInt16();
                        if (!Enum.IsDefined(applicationSettingsCodePoint.Value))
                        {
                            throw new InvalidDataException(
                                "The TLS session state has an unsupported application-settings code point.");
                        }
                        peerApplicationSettings = reader.ReadVector16().ToArray();
                        clientApplicationSettings = reader.ReadVector16().ToArray();
                    }
                }
                byte[]? quicTransportParameters = null;
                if (stateVersion >= 3)
                {
                    var hasQuicParameters = reader.ReadUInt8();
                    if (hasQuicParameters > 1)
                    {
                        throw new InvalidDataException(
                            "The TLS session state has an invalid QUIC-parameter flag.");
                    }
                    if (hasQuicParameters == 1)
                    {
                        quicTransportParameters = reader.ReadVector16().ToArray();
                    }
                }

                destination.Add(new Tls13SessionTicket(
                    origin,
                    cipherSuite,
                    alpn,
                    ageAdd,
                    identity,
                    psk,
                    issuedAt,
                    expiresAt,
                    authenticationExpiresAt,
                    maximumEarlyDataSize,
                    peerRecordSizeLimit,
                    echBinding,
                    applicationSettingsCodePoint,
                    peerApplicationSettings,
                    clientApplicationSettings,
                    quicTransportParameters));
                if (echBinding is not null)
                {
                    CryptographicOperations.ZeroMemory(echBinding);
                }
                if (peerApplicationSettings is not null)
                {
                    CryptographicOperations.ZeroMemory(peerApplicationSettings);
                }
                if (clientApplicationSettings is not null)
                {
                    CryptographicOperations.ZeroMemory(clientApplicationSettings);
                }
                if (quicTransportParameters is not null)
                {
                    CryptographicOperations.ZeroMemory(quicTransportParameters);
                }
            }
            reader.EnsureEnd("TLS session state");
        }
        catch (TlsProtocolException exception)
        {
            throw new InvalidDataException("The decrypted TLS session state is malformed.", exception);
        }
        catch (NotSupportedException exception)
        {
            throw new InvalidDataException("The TLS session state uses an unsupported cipher suite.", exception);
        }
        catch (ArgumentException exception)
        {
            throw new InvalidDataException("The decrypted TLS session state contains an invalid ticket.", exception);
        }
    }

    private static string ReadAscii(
        ReadOnlySpan<byte> value,
        bool allowEmpty,
        string fieldName)
    {
        if ((!allowEmpty && value.IsEmpty) || value.ContainsAnyExceptInRange((byte)0, (byte)0x7F))
        {
            throw new InvalidDataException($"The TLS session state has an invalid {fieldName}.");
        }
        return Encoding.ASCII.GetString(value);
    }

    private static void ValidateImportedTimes(
        DateTimeOffset now,
        DateTimeOffset issuedAt,
        DateTimeOffset expiresAt,
        DateTimeOffset authenticationExpiresAt)
    {
        if (issuedAt > now + TimeSpan.FromMinutes(5) ||
            expiresAt <= issuedAt ||
            authenticationExpiresAt <= issuedAt ||
            expiresAt > authenticationExpiresAt ||
            expiresAt - issuedAt > MaximumTicketLifetime ||
            authenticationExpiresAt - issuedAt > MaximumTicketLifetime)
        {
            throw new InvalidDataException("The TLS session state has invalid ticket lifetimes.");
        }
    }

    private static ulong CheckedUnixMilliseconds(DateTimeOffset value)
    {
        var milliseconds = value.ToUnixTimeMilliseconds();
        if (milliseconds < 0)
        {
            throw new InvalidOperationException("TLS session timestamps before the Unix epoch cannot be persisted.");
        }
        return (ulong)milliseconds;
    }

    private static DateTimeOffset ReadUnixMilliseconds(ulong value)
    {
        if (value > long.MaxValue)
        {
            throw new InvalidDataException("The TLS session state has an invalid timestamp.");
        }
        try
        {
            return DateTimeOffset.FromUnixTimeMilliseconds((long)value);
        }
        catch (ArgumentOutOfRangeException exception)
        {
            throw new InvalidDataException("The TLS session state has an invalid timestamp.", exception);
        }
    }

    private void PurgeExpired(DateTimeOffset now)
    {
        for (var node = _tickets.First; node is not null;)
        {
            var next = node.Next;
            if (!node.Value.IsCacheable(now))
            {
                RemoveAndDispose(node);
            }
            node = next;
        }
    }

    private void DisposeAll()
    {
        foreach (var ticket in _tickets)
        {
            ticket.Dispose();
        }
        _tickets.Clear();
    }

    private void RemoveAndDispose(LinkedListNode<Tls13SessionTicket> node)
    {
        _tickets.Remove(node);
        node.Value.Dispose();
    }

    private void ThrowIfDisposed() => ObjectDisposedException.ThrowIf(_disposed, this);
}

internal readonly record struct Tls13SessionOrigin(
    string Host,
    int? Port,
    bool CertificateValidationSkipped)
{
    internal static Tls13SessionOrigin Create(
        string referenceIdentity,
        int? port,
        bool certificateValidationSkipped = false)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(referenceIdentity);
        if (port is < 1 or > ushort.MaxValue)
        {
            throw new ArgumentOutOfRangeException(nameof(port));
        }

        var host = referenceIdentity.EndsWith(".", StringComparison.Ordinal)
            ? referenceIdentity[..^1]
            : referenceIdentity;
        host = IPAddress.TryParse(host, out var address)
            ? address.ToString()
            : new IdnMapping().GetAscii(host).ToLowerInvariant();
        return new Tls13SessionOrigin(host, port, certificateValidationSkipped);
    }
}

internal sealed class Tls13SessionTicket : IDisposable
{
    private readonly SecretBuffer _psk;
    private bool _disposed;

    internal Tls13SessionTicket(
        Tls13SessionOrigin origin,
        TlsCipherSuite cipherSuite,
        string? negotiatedAlpn,
        uint ageAdd,
        ReadOnlySpan<byte> identity,
        ReadOnlySpan<byte> psk,
        DateTimeOffset issuedAt,
        DateTimeOffset expiresAt,
        DateTimeOffset authenticationExpiresAt,
        uint? maximumEarlyDataSize,
        int? peerRecordSizeLimit = null,
        byte[]? echConfigListHash = null,
        TlsApplicationSettingsCodePoint? applicationSettingsCodePoint = null,
        byte[]? peerApplicationSettings = null,
        byte[]? clientApplicationSettings = null,
        byte[]? quicTransportParameters = null)
    {
        if (identity.IsEmpty || identity.Length > ushort.MaxValue)
        {
            throw new ArgumentOutOfRangeException(nameof(identity));
        }

        var suite = CipherSuiteInfo.Get(cipherSuite);
        if (psk.Length != suite.HashLength)
        {
            throw new ArgumentException("Ticket PSK length does not match its cipher suite.", nameof(psk));
        }
        if (expiresAt <= issuedAt || authenticationExpiresAt <= issuedAt)
        {
            throw new ArgumentOutOfRangeException(nameof(expiresAt));
        }
        if (peerRecordSizeLimit is < 64 or > TlsConstants.MaxPlaintextLength + 1)
        {
            throw new ArgumentOutOfRangeException(nameof(peerRecordSizeLimit));
        }
        if (echConfigListHash is { Length: not 32 })
        {
            throw new ArgumentException(
                "An ECH configuration-source binding must be a SHA-256 hash.",
                nameof(echConfigListHash));
        }
        var hasApplicationSettings = applicationSettingsCodePoint.HasValue;
        if (hasApplicationSettings !=
                (peerApplicationSettings is not null && clientApplicationSettings is not null) ||
            (!hasApplicationSettings &&
             (peerApplicationSettings is not null || clientApplicationSettings is not null)) ||
            (hasApplicationSettings && negotiatedAlpn is null))
        {
            throw new ArgumentException(
                "Ticket application settings require a code point, negotiated ALPN, and both peer/client payloads.",
                nameof(applicationSettingsCodePoint));
        }
        if (peerApplicationSettings is { Length: > ushort.MaxValue } ||
            clientApplicationSettings is { Length: > ushort.MaxValue } ||
            quicTransportParameters is { Length: > ushort.MaxValue })
        {
            throw new ArgumentOutOfRangeException(nameof(peerApplicationSettings));
        }

        Origin = origin;
        CipherSuite = cipherSuite;
        NegotiatedAlpn = negotiatedAlpn;
        AgeAdd = ageAdd;
        Identity = identity.ToArray();
        _psk = new SecretBuffer(psk);
        IssuedAt = issuedAt;
        ExpiresAt = expiresAt < authenticationExpiresAt ? expiresAt : authenticationExpiresAt;
        AuthenticationExpiresAt = authenticationExpiresAt;
        MaximumEarlyDataSize = maximumEarlyDataSize;
        PeerRecordSizeLimit = peerRecordSizeLimit;
        EchConfigListHash = echConfigListHash is null
            ? null
            : (byte[])echConfigListHash.Clone();
        ApplicationSettingsCodePoint = applicationSettingsCodePoint;
        PeerApplicationSettings = peerApplicationSettings is null
            ? null
            : (byte[])peerApplicationSettings.Clone();
        ClientApplicationSettings = clientApplicationSettings is null
            ? null
            : (byte[])clientApplicationSettings.Clone();
        QuicTransportParameters = quicTransportParameters is null
            ? null
            : (byte[])quicTransportParameters.Clone();
    }

    internal Tls13SessionOrigin Origin { get; }
    internal TlsCipherSuite CipherSuite { get; }
    internal string? NegotiatedAlpn { get; }
    internal uint AgeAdd { get; }
    internal byte[] Identity { get; }
    internal DateTimeOffset IssuedAt { get; }
    internal DateTimeOffset ExpiresAt { get; }
    internal DateTimeOffset AuthenticationExpiresAt { get; }
    internal uint? MaximumEarlyDataSize { get; }
    internal int? PeerRecordSizeLimit { get; }
    internal byte[]? EchConfigListHash { get; }
    internal TlsApplicationSettingsCodePoint? ApplicationSettingsCodePoint { get; }
    internal byte[]? PeerApplicationSettings { get; }
    internal byte[]? ClientApplicationSettings { get; }
    internal byte[]? QuicTransportParameters { get; }

    internal byte[] CopyPsk()
    {
        ThrowIfDisposed();
        return _psk.Copy();
    }

    internal uint GetObfuscatedAge(DateTimeOffset now)
    {
        ThrowIfDisposed();
        var elapsed = now - IssuedAt;
        var milliseconds = elapsed <= TimeSpan.Zero
            ? 0UL
            : (ulong)Math.Min(elapsed.TotalMilliseconds, uint.MaxValue);
        return unchecked((uint)milliseconds + AgeAdd);
    }

    internal bool IsCacheable(DateTimeOffset now) =>
        !_disposed && now < ExpiresAt && now < AuthenticationExpiresAt;

    internal bool CanResume(
        Tls13SessionOrigin origin,
        IReadOnlyList<TlsCipherSuite> offeredCipherSuites,
        IReadOnlyList<string> offeredAlpn,
        DateTimeOffset now,
        byte[]? echConfigListHash = null,
        TlsApplicationSettingsCodePoint? applicationSettingsCodePoint = null,
        IReadOnlyDictionary<string, byte[]>? clientApplicationSettings = null)
    {
        if (!IsCacheable(now) || Origin != origin)
        {
            return false;
        }
        if ((EchConfigListHash is null) != (echConfigListHash is null) ||
            (EchConfigListHash is not null &&
             !CryptographicOperations.FixedTimeEquals(
                 EchConfigListHash,
                 echConfigListHash!)))
        {
            return false;
        }
        if (NegotiatedAlpn is null
            ? offeredAlpn.Count != 0
            : !offeredAlpn.Contains(NegotiatedAlpn, StringComparer.Ordinal))
        {
            return false;
        }
        if (ApplicationSettingsCodePoint.HasValue)
        {
            if (applicationSettingsCodePoint != ApplicationSettingsCodePoint ||
                NegotiatedAlpn is null ||
                clientApplicationSettings is null ||
                !clientApplicationSettings.TryGetValue(
                    NegotiatedAlpn,
                    out var configuredClientSettings) ||
                !CryptographicOperations.FixedTimeEquals(
                    ClientApplicationSettings!,
                    configuredClientSettings))
            {
                return false;
            }
        }

        var ticketHash = CipherSuiteInfo.Get(CipherSuite).HashAlgorithm.Name;
        foreach (var offered in offeredCipherSuites)
        {
            try
            {
                if (CipherSuiteInfo.Get(offered).HashAlgorithm.Name == ticketHash)
                {
                    return true;
                }
            }
            catch (NotSupportedException)
            {
                // TLS 1.2 and fingerprint-only suites cannot resume this TLS 1.3 ticket.
            }
        }

        return false;
    }

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;
        _psk.Dispose();
        CryptographicOperations.ZeroMemory(Identity);
        if (EchConfigListHash is not null)
        {
            CryptographicOperations.ZeroMemory(EchConfigListHash);
        }
        if (PeerApplicationSettings is not null)
        {
            CryptographicOperations.ZeroMemory(PeerApplicationSettings);
        }
        if (ClientApplicationSettings is not null)
        {
            CryptographicOperations.ZeroMemory(ClientApplicationSettings);
        }
        if (QuicTransportParameters is not null)
        {
            CryptographicOperations.ZeroMemory(QuicTransportParameters);
        }
    }

    private void ThrowIfDisposed() => ObjectDisposedException.ThrowIf(_disposed, this);
}

internal sealed class Tls13PskOffer
{
    private readonly Tls13SessionTicket[] _tickets;
    private readonly byte[]?[] _binderTranscriptPrefixes;

    internal Tls13PskOffer(
        Tls13SessionTicket ticket,
        DateTimeOffset offeredAt,
        byte[]? BinderTranscriptPrefix = null,
        bool OfferEarlyData = false)
        : this([ticket ?? throw new ArgumentNullException(nameof(ticket))],
            offeredAt,
            [BinderTranscriptPrefix],
            OfferEarlyData)
    {
    }

    internal Tls13PskOffer(
        IReadOnlyList<Tls13SessionTicket> tickets,
        DateTimeOffset offeredAt,
        IReadOnlyList<byte[]?>? binderTranscriptPrefixes = null,
        bool offerEarlyData = false)
    {
        ArgumentNullException.ThrowIfNull(tickets);
        if (tickets.Count is < 1 or > 64 || tickets.Any(ticket => ticket is null))
        {
            throw new ArgumentOutOfRangeException(nameof(tickets));
        }
        _tickets = tickets.ToArray();
        if (binderTranscriptPrefixes is not null &&
            binderTranscriptPrefixes.Count != tickets.Count)
        {
            throw new ArgumentException(
                "Each PSK identity requires its own hash-specific binder transcript prefix.",
                nameof(binderTranscriptPrefixes));
        }
        _binderTranscriptPrefixes = binderTranscriptPrefixes?.ToArray() ??
            new byte[]?[tickets.Count];
        OfferedAt = offeredAt;
        OfferEarlyData = offerEarlyData;
    }

    internal Tls13PskOffer(
        Tls13ExternalPskConfiguration externalPsk,
        byte[]? binderTranscriptPrefix = null)
    {
        _tickets = [];
        _binderTranscriptPrefixes = [binderTranscriptPrefix];
        ExternalPsk = externalPsk ?? throw new ArgumentNullException(nameof(externalPsk));
    }

    internal Tls13SessionTicket? Ticket => _tickets.Length == 0 ? null : _tickets[0];

    internal Tls13ExternalPskConfiguration? ExternalPsk { get; }

    internal DateTimeOffset OfferedAt { get; }

    internal byte[]? BinderTranscriptPrefix => _binderTranscriptPrefixes[0];

    internal bool OfferEarlyData { get; }

    internal bool IsExternal => ExternalPsk is not null;

    internal int Count => IsExternal ? 1 : _tickets.Length;

    internal TlsCipherSuite CipherSuite => Ticket?.CipherSuite ?? ExternalPsk!.CipherSuite;

    internal ReadOnlySpan<byte> Identity => Ticket is not null
        ? Ticket.Identity
        : ExternalPsk!.Identity;

    internal uint GetObfuscatedAge() => Ticket?.GetObfuscatedAge(OfferedAt) ?? 0;

    internal byte[] CopyPsk() => Ticket?.CopyPsk() ?? ExternalPsk!.CopyKey();

    internal Tls13SessionTicket? GetTicket(int index)
    {
        if ((uint)index >= (uint)Count)
        {
            throw new ArgumentOutOfRangeException(nameof(index));
        }
        return IsExternal ? null : _tickets[index];
    }

    internal bool IsExternalAt(int index)
    {
        _ = GetCipherSuite(index);
        return IsExternal;
    }

    internal TlsCipherSuite GetCipherSuite(int index) =>
        GetTicketOrValidateExternal(index)?.CipherSuite ?? ExternalPsk!.CipherSuite;

    internal ReadOnlySpan<byte> GetIdentity(int index) =>
        GetTicketOrValidateExternal(index)?.Identity ?? ExternalPsk!.Identity;

    internal uint GetObfuscatedAge(int index) =>
        GetTicketOrValidateExternal(index)?.GetObfuscatedAge(OfferedAt) ?? 0;

    internal byte[] CopyPsk(int index) =>
        GetTicketOrValidateExternal(index)?.CopyPsk() ?? ExternalPsk!.CopyKey();

    internal byte[]? GetBinderTranscriptPrefix(int index)
    {
        _ = GetTicketOrValidateExternal(index);
        return _binderTranscriptPrefixes[index];
    }

    private Tls13SessionTicket? GetTicketOrValidateExternal(int index)
    {
        if ((uint)index >= (uint)Count)
        {
            throw new ArgumentOutOfRangeException(nameof(index));
        }
        return IsExternal ? null : _tickets[index];
    }
}

internal readonly record struct Tls13GreasePskOffer(
    int[] IdentityLengths,
    int[] BinderLengths,
    bool OfferEarlyData,
    byte[][] ProhibitedIdentities)
{
    internal static Tls13GreasePskOffer From(Tls13PskOffer offer)
    {
        ArgumentNullException.ThrowIfNull(offer);
        return new Tls13GreasePskOffer(
            Enumerable.Range(0, offer.Count)
                .Select(index => offer.GetIdentity(index).Length)
                .ToArray(),
            Enumerable.Range(0, offer.Count)
                .Select(index => CipherSuiteInfo.Get(
                    offer.GetCipherSuite(index)).HashLength)
                .ToArray(),
            offer.OfferEarlyData,
            Enumerable.Range(0, offer.Count)
                .Select(index => offer.GetIdentity(index).ToArray())
                .ToArray());
    }
}
