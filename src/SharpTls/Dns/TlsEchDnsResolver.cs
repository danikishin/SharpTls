using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using SharpTls.Dns;

namespace SharpTls.Dns
{
    internal interface IDnsRandomSource
    {
        ushort NextIdentifier();
        int NextInt32(int exclusiveMaximum);
    }

    internal sealed class SecureDnsRandomSource : IDnsRandomSource
    {
        public ushort NextIdentifier() =>
            (ushort)RandomNumberGenerator.GetInt32(ushort.MaxValue + 1);

        public int NextInt32(int exclusiveMaximum) =>
            RandomNumberGenerator.GetInt32(exclusiveMaximum);
    }
}

namespace SharpTls
{

/// <summary>
/// Resolves RFC 9848 ECH bootstrap metadata from HTTPS records using RFC 9460 AliasMode and
/// ServiceMode processing. Resolution completes before a TLS ClientHello is sent.
/// </summary>
public sealed class TlsEchDnsResolver
{
    private readonly TlsEchDnsResolverConfiguration _configuration;
    private readonly IDnsQueryTransport _transport;
    private readonly IDnsRandomSource _random;
    private readonly TimeProvider _timeProvider;
    private readonly IPEndPoint[] _nameServers;

    /// <summary>Creates a resolver with system DNS servers and secure query/order randomness.</summary>
    public TlsEchDnsResolver(TlsEchDnsResolverOptions? options = null)
        : this((options ?? new TlsEchDnsResolverOptions()).Snapshot())
    {
    }

    private TlsEchDnsResolver(TlsEchDnsResolverConfiguration configuration)
        : this(
            configuration,
            DnsQueryTransportFactory.Create(configuration),
            new SecureDnsRandomSource(),
            TimeProvider.System)
    {
    }

    internal TlsEchDnsResolver(
        TlsEchDnsResolverConfiguration configuration,
        IDnsQueryTransport transport,
        IDnsRandomSource random,
        TimeProvider timeProvider)
    {
        ArgumentNullException.ThrowIfNull(configuration);
        ArgumentNullException.ThrowIfNull(transport);
        ArgumentNullException.ThrowIfNull(random);
        ArgumentNullException.ThrowIfNull(timeProvider);
        _configuration = configuration;
        _transport = transport;
        _random = random;
        _timeProvider = timeProvider;
        _nameServers = configuration.NameServers is { Length: > 0 }
            ? configuration.NameServers.Select(server =>
                new IPEndPoint(server.Address, server.Port)).ToArray()
            : DnsNameServerDiscovery.GetSystemNameServers();
    }

    /// <summary>
    /// Resolves the origin's HTTPS binding and returns ordered endpoints with an attached ECH
    /// fallback policy. Cancellation covers the selected DNS transport and alias traversal.
    /// </summary>
    public async Task<TlsEchDnsResolution> ResolveAsync(
        string originName,
        int originPort = 443,
        CancellationToken cancellationToken = default)
    {
        var origin = DnsNames.NormalizeOrigin(originName);
        if (originPort is < 1 or > ushort.MaxValue)
        {
            throw new ArgumentOutOfRangeException(nameof(originPort));
        }

        if (_configuration.Cache.TryGet(origin, originPort, out var cached))
        {
            return cached!;
        }

        try
        {
            var result = await ResolveCoreAsync(origin, originPort, cancellationToken)
                .ConfigureAwait(false);
            _configuration.Cache.Store(result);
            return result;
        }
        catch (TlsEchDnsException exception) when (
            exception.ErrorKind == TlsEchDnsErrorKind.MalformedServiceBinding)
        {
            // RFC 9460 section 2.2 requires rejecting the complete malformed RRSet and
            // continuing with non-SVCB connection establishment.
            return CreateFallbackResolution(
                origin,
                originPort,
                origin,
                isAuthenticated: false,
                _timeProvider.GetUtcNow());
        }
        catch (TlsEchDnsException exception) when (
            _configuration.AllowDirectFallbackOnDnsError &&
            exception.ErrorKind is TlsEchDnsErrorKind.TransportFailure or
                TlsEchDnsErrorKind.DnsResponseError)
        {
            return CreateFallbackResolution(
                origin,
                originPort,
                origin,
                isAuthenticated: false,
                _timeProvider.GetUtcNow());
        }
    }

    private async Task<TlsEchDnsResolution> ResolveCoreAsync(
        string origin,
        int originPort,
        CancellationToken cancellationToken)
    {
        if (_nameServers.Length == 0)
        {
            throw new TlsEchDnsException(
                TlsEchDnsErrorKind.TransportFailure,
                "No usable DNS server was configured or discovered.");
        }

        var initialQueryName = DnsNames.GetHttpsQueryName(origin, originPort);
        var currentQueryName = initialQueryName;
        var currentDefaultTarget = origin;
        var visited = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            currentQueryName,
        };
        var traversalDepth = 0;
        var processedAliasMode = false;
        var chainTtl = GetMaximumTtlSeconds();
        var allResponsesAuthenticated = true;

        while (true)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var response = await QueryHttpsAsync(currentQueryName, cancellationToken)
                .ConfigureAwait(false);
            allResponsesAuthenticated &= response.IsAuthenticatedData;
            if (response.ResponseCode == 3) // NXDOMAIN
            {
                return CreateFallbackResolution(
                    origin,
                    originPort,
                    currentDefaultTarget,
                    allResponsesAuthenticated,
                    _timeProvider.GetUtcNow());
            }

            var owner = currentQueryName;
            var followedCname = false;
            while (true)
            {
                var cnames = response.CnameRecords.Where(record =>
                    string.Equals(record.Owner, owner, StringComparison.OrdinalIgnoreCase)).ToArray();
                if (cnames.Length == 0)
                {
                    break;
                }
                if (cnames.Length != 1 || response.HttpsRecords.Any(record =>
                        string.Equals(record.Owner, owner, StringComparison.OrdinalIgnoreCase)))
                {
                    throw TlsEchDnsException.Malformed(
                        "A DNS owner has conflicting CNAME or HTTPS answer records.");
                }

                chainTtl = Math.Min(chainTtl, cnames[0].TimeToLive);
                owner = cnames[0].CanonicalName;
                currentDefaultTarget = GetDefaultConnectionTarget(owner);
                if (!VisitAlias(owner, visited, ref traversalDepth))
                {
                    return CreateFallbackResolution(
                        origin,
                        originPort,
                        origin,
                        allResponsesAuthenticated,
                        _timeProvider.GetUtcNow());
                }
                followedCname = true;
            }

            currentQueryName = owner;
            var records = response.HttpsRecords.Where(record =>
                string.Equals(record.Owner, owner, StringComparison.OrdinalIgnoreCase)).ToArray();
            if (records.Length == 0)
            {
                if (followedCname)
                {
                    continue;
                }

                return CreateFallbackResolution(
                    origin,
                    originPort,
                    currentDefaultTarget,
                    allResponsesAuthenticated,
                    _timeProvider.GetUtcNow());
            }

            var aliases = records.Where(record => record.Priority == 0).ToArray();
            if (aliases.Length != 0)
            {
                processedAliasMode = true;
                var selectedAlias = aliases[_random.NextInt32(aliases.Length)];
                chainTtl = Math.Min(chainTtl, selectedAlias.TimeToLive);
                currentQueryName = DnsServiceBindingParser.ParseAliasTarget(selectedAlias);
                if (currentQueryName == ".")
                {
                    return CreateFallbackResolution(
                        origin,
                        originPort,
                        origin,
                        allResponsesAuthenticated,
                        _timeProvider.GetUtcNow());
                }

                currentDefaultTarget = currentQueryName;
                if (!VisitAlias(currentQueryName, visited, ref traversalDepth))
                {
                    return CreateFallbackResolution(
                        origin,
                        originPort,
                        origin,
                        allResponsesAuthenticated,
                        _timeProvider.GetUtcNow());
                }
                continue;
            }

            var bindings = records.Select(record =>
                DnsServiceBindingParser.ParseService(
                    record,
                    originPort)).ToArray();
            var compatible = bindings.Where(binding =>
                binding.IsCompatible && binding.AlpnProtocols.Any(protocol =>
                    _configuration.SupportedAlpnProtocols.Contains(
                        protocol,
                        StringComparer.Ordinal))).ToArray();
            if (compatible.Length == 0)
            {
                return CreateFallbackResolution(
                    origin,
                    originPort,
                    currentDefaultTarget,
                    allResponsesAuthenticated,
                    _timeProvider.GetUtcNow());
            }

            var allAdvertiseEch = compatible.All(binding => binding.HasEchParameter);
            var anyAdvertisesEch = compatible.Any(binding => binding.HasEchParameter);
            var anyOmitsEch = compatible.Any(binding => !binding.HasEchParameter);
            var usable = compatible.Where(binding =>
                !binding.HasEchParameter || binding.HasExecutableEch).ToArray();
            if (allAdvertiseEch && usable.Length == 0)
            {
                throw new TlsEchDnsException(
                    TlsEchDnsErrorKind.EchRequired,
                    "ECH-reliant service discovery forbids direct fallback, but no ECH configuration is executable.");
            }

            var now = _timeProvider.GetUtcNow();
            var minimumSetTtl = compatible.Aggregate(
                chainTtl,
                static (ttl, binding) => Math.Min(ttl, binding.WireRecord.TimeToLive));
            var resolutionExpiry = GetExpiry(now, minimumSetTtl);
            var endpoints = usable.Select(binding => new TlsEchDnsEndpoint(
                origin,
                binding.TargetName,
                binding.Port,
                binding.WireRecord.Priority,
                binding.AlpnProtocols,
                binding.HasNoDefaultAlpn,
                ShuffleAddresses(binding.Ipv4Hints),
                ShuffleAddresses(binding.Ipv6Hints),
                binding.HasExecutableEch ? binding.EchConfigList : null,
                isFallback: false,
                GetExpiry(now, Math.Min(chainTtl, binding.WireRecord.TimeToLive)))).ToList();
            if (processedAliasMode && !allAdvertiseEch)
            {
                endpoints.Add(new TlsEchDnsEndpoint(
                    origin,
                    currentQueryName,
                    originPort,
                    ushort.MaxValue,
                    ["http/1.1"],
                    hasNoDefaultAlpn: false,
                    [],
                    [],
                    echConfigList: null,
                    isFallback: true,
                    GetExpiry(now, chainTtl)));
            }
            var orderedEndpoints = endpoints.ToArray();
            ShuffleEqualPriority(orderedEndpoints);

            return new TlsEchDnsResolution(
                origin,
                originPort,
                orderedEndpoints,
                allAdvertiseEch
                    ? TlsEchDnsFallbackPolicy.EchRequired
                    : TlsEchDnsFallbackPolicy.DirectConnectionAllowed,
                anyAdvertisesEch && anyOmitsEch,
                allResponsesAuthenticated,
                resolutionExpiry);
        }
    }

    private async Task<DnsParsedResponse> QueryHttpsAsync(
        string queryName,
        CancellationToken cancellationToken)
    {
        var failures = new List<Exception>();
        foreach (var server in _nameServers)
        {
            // RFC 8484 section 4.1 recommends ID zero because HTTP already correlates
            // requests and responses, improving cache sharing without weakening matching.
            var identifier = _configuration.ProtectedTransport is DnsOverHttpsConfiguration
                ? (ushort)0
                : _random.NextIdentifier();
            var query = DnsMessageWriter.CreateHttpsQuery(
                identifier,
                queryName,
                _configuration.UdpPayloadSize,
                _configuration.RequestDnsSec || _configuration.RequireAuthenticatedData);
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            timeout.CancelAfter(_configuration.QueryTimeout);
            try
            {
                var transportResponse = await _transport.QueryAsync(
                    server,
                    query,
                    _configuration.MaximumResponseSize,
                    timeout.Token).ConfigureAwait(false);
                var parsed = DnsMessageParser.ParseHttpsResponse(
                    transportResponse.Message,
                    identifier,
                    queryName,
                    _configuration.MaximumResponseSize,
                    _configuration.MaximumRecords,
                    transportResponse.CacheAgeSeconds,
                    transportResponse.TtlCapSeconds);
                if (parsed.IsTruncated)
                {
                    throw TlsEchDnsException.Malformed(
                        "The DNS transport returned a truncated response after TCP fallback.");
                }
                if (_configuration.RequireAuthenticatedData && !parsed.IsAuthenticatedData)
                {
                    throw new TlsEchDnsException(
                        TlsEchDnsErrorKind.AuthenticationRequired,
                        "The DNS response did not carry the authenticated-data bit.");
                }
                if (parsed.ResponseCode is not (0 or 3))
                {
                    throw new TlsEchDnsException(
                        TlsEchDnsErrorKind.DnsResponseError,
                        $"The DNS server returned response code {parsed.ResponseCode}.");
                }
                return parsed;
            }
            catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
            {
                failures.Add(new TimeoutException(
                    $"DNS server {server} did not answer within {_configuration.QueryTimeout}."));
            }
            catch (Exception exception) when (exception is
                IOException or SocketException or TlsEchDnsException)
            {
                failures.Add(exception);
            }
        }

        cancellationToken.ThrowIfCancellationRequested();
        var decisive = failures.OfType<TlsEchDnsException>().LastOrDefault(exception =>
            exception.ErrorKind is TlsEchDnsErrorKind.MalformedResponse or
                TlsEchDnsErrorKind.MalformedServiceBinding or
                TlsEchDnsErrorKind.AuthenticationRequired or
                TlsEchDnsErrorKind.DnsResponseError);
        if (decisive is not null)
        {
            throw decisive;
        }
        throw new TlsEchDnsException(
            TlsEchDnsErrorKind.TransportFailure,
            "Every configured DNS server failed to answer the HTTPS query.",
            failures.Count == 0 ? null : new AggregateException(failures));
    }

    private bool VisitAlias(
        string name,
        HashSet<string> visited,
        ref int traversalDepth)
    {
        if (++traversalDepth > _configuration.MaximumAliasDepth || !visited.Add(name))
        {
            return false;
        }
        return true;
    }

    private void ShuffleEqualPriority(TlsEchDnsEndpoint[] endpoints)
    {
        Array.Sort(endpoints, static (left, right) => left.Priority.CompareTo(right.Priority));
        for (var groupStart = 0; groupStart < endpoints.Length;)
        {
            var groupEnd = groupStart + 1;
            while (groupEnd < endpoints.Length &&
                endpoints[groupEnd].Priority == endpoints[groupStart].Priority)
            {
                groupEnd++;
            }
            for (var index = groupEnd - 1; index > groupStart; index--)
            {
                var selected = groupStart + _random.NextInt32(index - groupStart + 1);
                (endpoints[index], endpoints[selected]) = (endpoints[selected], endpoints[index]);
            }
            groupStart = groupEnd;
        }
    }

    private IPAddress[] ShuffleAddresses(IPAddress[] addresses)
    {
        var result = (IPAddress[])addresses.Clone();
        for (var index = result.Length - 1; index > 0; index--)
        {
            var selected = _random.NextInt32(index + 1);
            (result[index], result[selected]) = (result[selected], result[index]);
        }
        return result;
    }

    private TlsEchDnsResolution CreateFallbackResolution(
        string origin,
        int originPort,
        string target,
        bool isAuthenticated,
        DateTimeOffset now)
    {
        var endpoint = new TlsEchDnsEndpoint(
            origin,
            target,
            originPort,
            ushort.MaxValue,
            [],
            hasNoDefaultAlpn: false,
            [],
            [],
            echConfigList: null,
            isFallback: true,
            now);
        return new TlsEchDnsResolution(
            origin,
            originPort,
            [endpoint],
            TlsEchDnsFallbackPolicy.DirectConnectionAllowed,
            isMixedEchDeployment: false,
            isAuthenticated,
            now);
    }

    private uint GetMaximumTtlSeconds() =>
        (uint)Math.Min(uint.MaxValue, Math.Floor(_configuration.MaximumCacheLifetime.TotalSeconds));

    private DateTimeOffset GetExpiry(DateTimeOffset now, uint ttl) =>
        now.AddSeconds(Math.Min(ttl, GetMaximumTtlSeconds()));

    private static string GetDefaultConnectionTarget(string queryName)
    {
        if (queryName.Length > 9 && queryName[0] == '_')
        {
            var firstDot = queryName.IndexOf('.');
            if (firstDot > 1 && queryName.AsSpan(firstDot + 1).StartsWith("_https."))
            {
                var portText = queryName.AsSpan(1, firstDot - 1);
                if (ushort.TryParse(portText, out var port) && port != 0)
                {
                    var target = queryName[(firstDot + "._https.".Length)..];
                    DnsNames.ValidateHostName(target, nameof(queryName));
                    return target;
                }
            }
        }

        DnsNames.ValidateHostName(queryName, nameof(queryName));
        return queryName;
    }
}
}
