using System.Net;
using SharpTls.Dns;

namespace SharpTls;

/// <summary>Classifies an RFC 9848 HTTPS/SVCB bootstrap failure.</summary>
public enum TlsEchDnsErrorKind
{
    /// <summary>The DNS message or an HTTPS/SVCB value was malformed.</summary>
    MalformedResponse,
    /// <summary>An HTTPS/SVCB RRSet was rejected and requires non-SVCB fallback.</summary>
    MalformedServiceBinding,
    /// <summary>The DNS server returned an error response code.</summary>
    DnsResponseError,
    /// <summary>No configured plaintext or protected DNS server could answer the query.</summary>
    TransportFailure,
    /// <summary>A DNSSEC-authenticated response was required but not reported by the resolver.</summary>
    AuthenticationRequired,
    /// <summary>The service binding requires ECH but no executable ECH configuration was available.</summary>
    EchRequired,
}

/// <summary>Represents a bounded RFC 9848 HTTPS/SVCB bootstrap failure.</summary>
public sealed class TlsEchDnsException : IOException
{
    internal TlsEchDnsException(
        TlsEchDnsErrorKind errorKind,
        string message,
        Exception? innerException = null)
        : base(message, innerException)
    {
        ErrorKind = errorKind;
    }

    /// <summary>Gets the failure classification.</summary>
    public TlsEchDnsErrorKind ErrorKind { get; }

    internal static TlsEchDnsException Malformed(string message) =>
        new(TlsEchDnsErrorKind.MalformedResponse, message);

    internal static TlsEchDnsException MalformedServiceBinding(string message) =>
        new(TlsEchDnsErrorKind.MalformedServiceBinding, message);
}

/// <summary>Controls whether an RFC 9848 result permits a connection without ECH.</summary>
public enum TlsEchDnsFallbackPolicy
{
    /// <summary>The resolved service set contains a legitimate non-ECH path.</summary>
    DirectConnectionAllowed,
    /// <summary>Every compatible alternative endpoint advertises ECH; direct fallback is forbidden.</summary>
    EchRequired,
}

/// <summary>
/// Configures RFC 9848 HTTPS/SVCB discovery over bounded plaintext DNS, authenticated DoT,
/// or authenticated DoH.
/// </summary>
public sealed class TlsEchDnsResolverOptions
{
    private static readonly IReadOnlyList<string> DefaultSupportedAlpn =
        Array.AsReadOnly(new[] { "http/1.1" });

    /// <summary>
    /// Gets or sets explicit recursive DNS servers. Null discovers servers from active network
    /// interfaces. Port zero is normalized to the DNS port 53.
    /// </summary>
    public IReadOnlyList<IPEndPoint>? NameServers { get; set; }

    /// <summary>
    /// Gets or sets strict authenticated DNS-over-TLS. This is mutually exclusive with
    /// <see cref="NameServers"/> and <see cref="DnsOverHttps"/>.
    /// </summary>
    public TlsEchDnsOverTlsOptions? DnsOverTls { get; set; }

    /// <summary>
    /// Gets or sets strict authenticated DNS-over-HTTPS. This is mutually exclusive with
    /// <see cref="NameServers"/> and <see cref="DnsOverTls"/>.
    /// </summary>
    public TlsEchDnsOverHttpsOptions? DnsOverHttps { get; set; }

    /// <summary>Gets or sets the timeout applied independently to each DNS endpoint attempt.</summary>
    public TimeSpan QueryTimeout { get; set; } = TimeSpan.FromSeconds(3);

    /// <summary>Gets or sets the EDNS UDP payload size. Truncated answers are retried over TCP.</summary>
    public ushort UdpPayloadSize { get; set; } = 1232;

    /// <summary>Gets or sets whether the EDNS DNSSEC OK bit is sent.</summary>
    public bool RequestDnsSec { get; set; }

    /// <summary>
    /// Gets or sets whether the recursive resolver's authenticated-data bit is required. This is
    /// meaningful only when the configured resolver and the channel to it are trusted.
    /// </summary>
    public bool RequireAuthenticatedData { get; set; }

    /// <summary>Gets or sets the maximum accepted DNS wire-message size on every transport.</summary>
    public int MaximumResponseSize { get; set; } = ushort.MaxValue;

    /// <summary>Gets or sets the maximum total resource records accepted in one response.</summary>
    public int MaximumRecords { get; set; } = 256;

    /// <summary>Gets or sets the maximum combined CNAME and SVCB AliasMode traversal depth.</summary>
    public int MaximumAliasDepth { get; set; } = 8;

    /// <summary>
    /// Gets or sets the ASCII ALPN protocol identifiers supported by the caller on TLS-over-TCP.
    /// They are used to determine RFC 9460 ServiceMode compatibility.
    /// </summary>
    public IReadOnlyList<string> SupportedAlpnProtocols { get; set; } = DefaultSupportedAlpn;

    /// <summary>Gets or sets the maximum number of cached origins when no caller cache is supplied.</summary>
    public int CacheCapacity { get; set; } = 256;

    /// <summary>Gets or sets the local upper bound applied to otherwise valid DNS TTL values.</summary>
    public TimeSpan MaximumCacheLifetime { get; set; } = TimeSpan.FromDays(1);

    /// <summary>Gets or sets a caller-owned cache shared by resolvers, or null for an internal cache.</summary>
    public TlsEchDnsCache? Cache { get; set; }

    /// <summary>
    /// Gets or sets whether transport/SERVFAIL-style DNS errors may create a direct endpoint.
    /// The secure default is false because such fallback is downgradeable by an on-path attacker.
    /// NXDOMAIN and successful NODATA answers remain ordinary direct-fallback results.
    /// </summary>
    public bool AllowDirectFallbackOnDnsError { get; set; }

    internal TlsEchDnsResolverConfiguration Snapshot()
    {
        if (QueryTimeout <= TimeSpan.Zero || QueryTimeout > TimeSpan.FromMinutes(1))
        {
            throw new ArgumentOutOfRangeException(nameof(QueryTimeout));
        }
        if (UdpPayloadSize is < 512 or > 4096)
        {
            throw new ArgumentOutOfRangeException(nameof(UdpPayloadSize));
        }
        if (MaximumResponseSize is < 512 or > ushort.MaxValue)
        {
            throw new ArgumentOutOfRangeException(nameof(MaximumResponseSize));
        }
        if (MaximumRecords is < 1 or > 4096)
        {
            throw new ArgumentOutOfRangeException(nameof(MaximumRecords));
        }
        if (MaximumAliasDepth is < 1 or > 32)
        {
            throw new ArgumentOutOfRangeException(nameof(MaximumAliasDepth));
        }
        if (CacheCapacity is < 1 or > 4096)
        {
            throw new ArgumentOutOfRangeException(nameof(CacheCapacity));
        }
        ArgumentNullException.ThrowIfNull(SupportedAlpnProtocols);
        var supportedAlpn = SupportedAlpnProtocols.ToArray();
        if (supportedAlpn.Length is 0 or > 64 ||
            supportedAlpn.Distinct(StringComparer.Ordinal).Count() != supportedAlpn.Length ||
            supportedAlpn.Any(protocol => string.IsNullOrEmpty(protocol) ||
                protocol.Length > byte.MaxValue || protocol.Any(character => character > 0x7F)))
        {
            throw new ArgumentException(
                "Supported ALPN identifiers require 1-64 distinct values of 1-255 ASCII octets.",
                nameof(SupportedAlpnProtocols));
        }
        if (MaximumCacheLifetime <= TimeSpan.Zero || MaximumCacheLifetime > TimeSpan.FromDays(30))
        {
            throw new ArgumentOutOfRangeException(nameof(MaximumCacheLifetime));
        }

        var configuredTransports = (NameServers is null ? 0 : 1) +
            (DnsOverTls is null ? 0 : 1) + (DnsOverHttps is null ? 0 : 1);
        if (configuredTransports > 1)
        {
            throw new ArgumentException(
                "Plaintext DNS, DNS-over-TLS, and DNS-over-HTTPS options are mutually exclusive.");
        }

        DnsProtectedTransportConfiguration? protectedTransport = null;
        IPEndPoint[]? nameServers = null;
        if (DnsOverTls is not null)
        {
            protectedTransport = DnsOverTls.Snapshot();
            nameServers = protectedTransport.BootstrapEndpoints;
        }
        else if (DnsOverHttps is not null)
        {
            protectedTransport = DnsOverHttps.Snapshot();
            nameServers = protectedTransport.BootstrapEndpoints;
        }
        else if (NameServers is not null)
        {
            if (NameServers.Count is 0 or > 32)
            {
                throw new ArgumentException(
                    "Explicit DNS server lists require between 1 and 32 entries.",
                    nameof(NameServers));
            }
            nameServers = NameServers.Select(server =>
            {
                ArgumentNullException.ThrowIfNull(server);
                if (server.Address.Equals(IPAddress.Any) ||
                    server.Address.Equals(IPAddress.IPv6Any) ||
                    server.Address.IsIPv6Multicast || server.Port is < 0 or > ushort.MaxValue)
                {
                    throw new ArgumentException("A configured DNS endpoint is invalid.", nameof(NameServers));
                }
                return new IPEndPoint(server.Address, server.Port == 0 ? 53 : server.Port);
            }).Distinct().ToArray();
        }

        return new TlsEchDnsResolverConfiguration(
            nameServers,
            QueryTimeout,
            UdpPayloadSize,
            RequestDnsSec,
            RequireAuthenticatedData,
            MaximumResponseSize,
            MaximumRecords,
            MaximumAliasDepth,
            supportedAlpn,
            MaximumCacheLifetime,
            Cache ?? new TlsEchDnsCache(CacheCapacity),
            AllowDirectFallbackOnDnsError,
            protectedTransport);
    }
}

/// <summary>An immutable endpoint produced by RFC 9848 HTTPS/SVCB service discovery.</summary>
public sealed class TlsEchDnsEndpoint
{
    private readonly string[] _alpnProtocols;
    private readonly IPAddress[] _ipv4Hints;
    private readonly IPAddress[] _ipv6Hints;

    internal TlsEchDnsEndpoint(
        string originName,
        string targetName,
        int port,
        ushort priority,
        IEnumerable<string> alpnProtocols,
        bool hasNoDefaultAlpn,
        IEnumerable<IPAddress> ipv4Hints,
        IEnumerable<IPAddress> ipv6Hints,
        TlsEchConfigList? echConfigList,
        bool isFallback,
        DateTimeOffset expiresAt)
    {
        OriginName = originName;
        TargetName = targetName;
        Port = port;
        Priority = priority;
        _alpnProtocols = alpnProtocols.ToArray();
        HasNoDefaultAlpn = hasNoDefaultAlpn;
        _ipv4Hints = ipv4Hints.Select(static address => new IPAddress(address.GetAddressBytes())).ToArray();
        _ipv6Hints = ipv6Hints.Select(static address => new IPAddress(address.GetAddressBytes())).ToArray();
        EchConfigList = echConfigList;
        IsFallback = isFallback;
        ExpiresAt = expiresAt;
    }

    /// <summary>Gets the certificate and ClientHelloInner reference identity.</summary>
    public string OriginName { get; }

    /// <summary>Gets the DNS name to which the TCP connection is made.</summary>
    public string TargetName { get; }

    /// <summary>Gets the selected alternative service port.</summary>
    public int Port { get; }

    /// <summary>Gets the SVCB priority. Lower nonzero values are preferred.</summary>
    public ushort Priority { get; }

    /// <summary>Gets advertised ASCII ALPN protocol identifiers in server order.</summary>
    public IReadOnlyList<string> AlpnProtocols =>
        Array.AsReadOnly((string[])_alpnProtocols.Clone());

    /// <summary>Gets whether protocols not listed by the ALPN parameter are forbidden.</summary>
    public bool HasNoDefaultAlpn { get; }

    /// <summary>Gets non-authoritative IPv4 connection hints.</summary>
    public IReadOnlyList<IPAddress> Ipv4Hints =>
        Array.AsReadOnly(_ipv4Hints.Select(static address =>
            new IPAddress(address.GetAddressBytes())).ToArray());

    /// <summary>Gets non-authoritative IPv6 connection hints.</summary>
    public IReadOnlyList<IPAddress> Ipv6Hints =>
        Array.AsReadOnly(_ipv6Hints.Select(static address =>
            new IPAddress(address.GetAddressBytes())).ToArray());

    /// <summary>Gets the exact DNS-provisioned ECHConfigList, or null for a direct endpoint.</summary>
    public TlsEchConfigList? EchConfigList { get; }

    /// <summary>Gets whether this endpoint represents ordinary A/AAAA fallback after HTTPS NODATA.</summary>
    public bool IsFallback { get; }

    /// <summary>Gets the earliest TTL expiry inherited through the alias chain.</summary>
    public DateTimeOffset ExpiresAt { get; }

    /// <summary>
    /// Applies this endpoint's origin identity and ECH configuration to client options. The caller
    /// still connects to <see cref="TargetName"/>:<see cref="Port"/> and controls ALPN/profile bytes.
    /// </summary>
    public void ConfigureClient(
        CustomTlsClientOptions options,
        ClientHelloProfile? outerClientHello = null,
        IReadOnlyList<Protocol.TlsExtensionType>? compressedOuterExtensions = null)
    {
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(options.ClientHello);
        if (!IsFallback)
        {
            var spec = options.ClientHello.Spec;
            if (!spec.IncludeSni)
            {
                throw new ArgumentException(
                    "RFC 9460 HTTPS endpoints require a ClientHello SNI slot.",
                    nameof(options));
            }
            if (!spec.AlpnProtocols.Any(protocol =>
                    _alpnProtocols.Contains(protocol, StringComparer.Ordinal)))
            {
                throw new ArgumentException(
                    "The ClientHello ALPN list has no protocol compatible with this HTTPS endpoint.",
                    nameof(options));
            }
        }
        options.ServerName = OriginName;
        if (EchConfigList is null)
        {
            options.EncryptedClientHello = null;
            return;
        }

        options.EncryptedClientHelloGrease = null;
        options.EncryptedClientHello = new TlsEchOptions
        {
            ConfigList = EchConfigList,
            OuterClientHello = outerClientHello ??
                ClientHelloProfiles.Custom(builder => builder.WithTls13()),
            CompressedOuterExtensions = compressedOuterExtensions ??
                Array.Empty<Protocol.TlsExtensionType>(),
        };
    }
}

/// <summary>An immutable RFC 9848 resolution result with downgrade policy attached.</summary>
public sealed class TlsEchDnsResolution
{
    private readonly TlsEchDnsEndpoint[] _endpoints;

    internal TlsEchDnsResolution(
        string originName,
        int originPort,
        IEnumerable<TlsEchDnsEndpoint> endpoints,
        TlsEchDnsFallbackPolicy fallbackPolicy,
        bool isMixedEchDeployment,
        bool isDnsSecAuthenticated,
        DateTimeOffset expiresAt)
    {
        OriginName = originName;
        OriginPort = originPort;
        _endpoints = endpoints.ToArray();
        FallbackPolicy = fallbackPolicy;
        IsMixedEchDeployment = isMixedEchDeployment;
        IsDnsSecAuthenticated = isDnsSecAuthenticated;
        ExpiresAt = expiresAt;
    }

    /// <summary>Gets the normalized origin identity.</summary>
    public string OriginName { get; }

    /// <summary>Gets the original service port.</summary>
    public int OriginPort { get; }

    /// <summary>Gets compatible endpoints in connection-attempt order.</summary>
    public IReadOnlyList<TlsEchDnsEndpoint> Endpoints =>
        Array.AsReadOnly((TlsEchDnsEndpoint[])_endpoints.Clone());

    /// <summary>Gets the direct-fallback policy derived from the complete compatible RRSet.</summary>
    public TlsEchDnsFallbackPolicy FallbackPolicy { get; }

    /// <summary>Gets whether the RRSet mixes ECH and non-ECH alternative endpoints.</summary>
    public bool IsMixedEchDeployment { get; }

    /// <summary>Gets whether every response in the alias chain carried the DNS AD bit.</summary>
    public bool IsDnsSecAuthenticated { get; }

    /// <summary>Gets the earliest TTL expiry inherited through the resolution chain.</summary>
    public DateTimeOffset ExpiresAt { get; }
}

/// <summary>A bounded thread-safe cache for immutable RFC 9848 discovery results.</summary>
public sealed class TlsEchDnsCache
{
    private readonly object _sync = new();
    private readonly Dictionary<TlsEchDnsCacheKey, LinkedListNode<TlsEchDnsCacheEntry>> _entries = [];
    private readonly LinkedList<TlsEchDnsCacheEntry> _lru = [];
    private readonly int _capacity;
    private readonly TimeProvider _timeProvider;

    /// <summary>Creates a cache with the specified origin capacity.</summary>
    public TlsEchDnsCache(int capacity = 256)
        : this(capacity, TimeProvider.System)
    {
    }

    internal TlsEchDnsCache(int capacity, TimeProvider timeProvider)
    {
        if (capacity is < 1 or > 4096)
        {
            throw new ArgumentOutOfRangeException(nameof(capacity));
        }
        ArgumentNullException.ThrowIfNull(timeProvider);
        _capacity = capacity;
        _timeProvider = timeProvider;
    }

    /// <summary>Gets the number of unexpired cached origins.</summary>
    public int Count
    {
        get
        {
            lock (_sync)
            {
                PurgeExpired();
                return _entries.Count;
            }
        }
    }

    /// <summary>Removes all cached discovery results.</summary>
    public void Clear()
    {
        lock (_sync)
        {
            _entries.Clear();
            _lru.Clear();
        }
    }

    internal bool TryGet(string originName, int originPort, out TlsEchDnsResolution? resolution)
    {
        lock (_sync)
        {
            PurgeExpired();
            var key = new TlsEchDnsCacheKey(originName, originPort);
            if (!_entries.TryGetValue(key, out var node))
            {
                resolution = null;
                return false;
            }

            _lru.Remove(node);
            _lru.AddFirst(node);
            resolution = node.Value.Resolution;
            return true;
        }
    }

    internal void Store(TlsEchDnsResolution resolution)
    {
        ArgumentNullException.ThrowIfNull(resolution);
        lock (_sync)
        {
            PurgeExpired();
            if (resolution.ExpiresAt <= _timeProvider.GetUtcNow())
            {
                return;
            }

            var key = new TlsEchDnsCacheKey(resolution.OriginName, resolution.OriginPort);
            if (_entries.Remove(key, out var existing))
            {
                _lru.Remove(existing);
            }
            var node = _lru.AddFirst(new TlsEchDnsCacheEntry(key, resolution));
            _entries.Add(key, node);
            while (_entries.Count > _capacity)
            {
                var last = _lru.Last!;
                _lru.RemoveLast();
                _entries.Remove(last.Value.Key);
            }
        }
    }

    private void PurgeExpired()
    {
        var now = _timeProvider.GetUtcNow();
        for (var node = _lru.Last; node is not null;)
        {
            var previous = node.Previous;
            if (node.Value.Resolution.ExpiresAt <= now)
            {
                _lru.Remove(node);
                _entries.Remove(node.Value.Key);
            }
            node = previous;
        }
    }
}

internal sealed record TlsEchDnsResolverConfiguration(
    IPEndPoint[]? NameServers,
    TimeSpan QueryTimeout,
    ushort UdpPayloadSize,
    bool RequestDnsSec,
    bool RequireAuthenticatedData,
    int MaximumResponseSize,
    int MaximumRecords,
    int MaximumAliasDepth,
    string[] SupportedAlpnProtocols,
    TimeSpan MaximumCacheLifetime,
    TlsEchDnsCache Cache,
    bool AllowDirectFallbackOnDnsError,
    DnsProtectedTransportConfiguration? ProtectedTransport = null);

internal readonly record struct TlsEchDnsCacheKey(string OriginName, int OriginPort);

internal sealed record TlsEchDnsCacheEntry(
    TlsEchDnsCacheKey Key,
    TlsEchDnsResolution Resolution);
