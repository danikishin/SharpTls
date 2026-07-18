using System.Net;
using SharpTls.Dns;

namespace SharpTls.Tests.Dns;

public sealed class TlsEchDnsResolverTests
{
    [Fact]
    public async Task DohUsesZeroTransactionIdentifierForSharedCacheability()
    {
        var configuration = new TlsEchDnsResolverOptions
        {
            DnsOverHttps = new TlsEchDnsOverHttpsOptions
            {
                Endpoint = new Uri("https://resolver.example/dns-query"),
                BootstrapEndpoints = [new IPEndPoint(IPAddress.Loopback, 443)],
            },
        }.Snapshot();
        var clock = new ManualTimeProvider(DateTimeOffset.UtcNow);
        var resolver = new TlsEchDnsResolver(
            configuration,
            new FakeTransport((query, _) =>
            {
                Assert.Equal(0, query.Span[0]);
                Assert.Equal(0, query.Span[1]);
                return Task.FromResult(DnsTestMessages.CreateHttpsResponse(query.Span));
            }),
            new FixedRandomSource(),
            clock);

        var result = await resolver.ResolveAsync("origin.example");

        Assert.Single(result.Endpoints);
        Assert.True(result.Endpoints[0].IsFallback);
    }

    [Fact]
    public async Task AllEchEndpointsForbidDirectFallbackAndConfigureOriginIdentity()
    {
        var ech = DnsTestMessages.CreateEchConfigList();
        var resolver = CreateResolver((query, _) =>
        {
            var second = DnsTestMessages.CreateServiceRData(
                2,
                "second.example",
                (5, ech));
            var first = DnsTestMessages.CreateServiceRData(
                1,
                "first.example",
                (1, DnsTestMessages.EncodeAlpn("http/1.1")),
                (5, ech));
            var response = DnsTestMessages.CreateHttpsResponse(
                query.Span,
                (60, second),
                (60, first));
            return Task.FromResult(response);
        });

        var result = await resolver.ResolveAsync("ORIGIN.example.");

        Assert.Equal(TlsEchDnsFallbackPolicy.EchRequired, result.FallbackPolicy);
        Assert.False(result.IsMixedEchDeployment);
        Assert.Equal(new[] { "first.example", "second.example" },
            result.Endpoints.Select(endpoint => endpoint.TargetName));
        Assert.All(result.Endpoints, endpoint => Assert.NotNull(endpoint.EchConfigList));

        var options = new CustomTlsClientOptions
        {
            ClientHello = ClientHelloProfiles.Custom(builder =>
                builder.WithTls13().WithAlpn("http/1.1")),
        };
        result.Endpoints[0].ConfigureClient(options);
        Assert.Equal("origin.example", options.ServerName);
        Assert.NotNull(options.EncryptedClientHello);
        Assert.Null(options.EncryptedClientHelloGrease);
    }

    [Fact]
    public async Task MixedEchDeploymentIsReportedAndAllowsTheLegitimateDirectEndpoint()
    {
        var ech = DnsTestMessages.CreateEchConfigList();
        var resolver = CreateResolver((query, _) => Task.FromResult(
            DnsTestMessages.CreateHttpsResponse(
                query.Span,
                (60, DnsTestMessages.CreateServiceRData(1, "ech.example", (5, ech))),
                (60, DnsTestMessages.CreateServiceRData(2, "direct.example")))));

        var result = await resolver.ResolveAsync("origin.example");

        Assert.Equal(TlsEchDnsFallbackPolicy.DirectConnectionAllowed, result.FallbackPolicy);
        Assert.True(result.IsMixedEchDeployment);
        Assert.NotNull(result.Endpoints[0].EchConfigList);
        Assert.Null(result.Endpoints[1].EchConfigList);
    }

    [Fact]
    public async Task AlpnCompatibilityUsesHttpsHttp11DefaultSet()
    {
        var resolver = CreateResolver((query, _) =>
        {
            var h2Only = DnsTestMessages.CreateServiceRData(
                1,
                "h2-only.example",
                (1, DnsTestMessages.EncodeAlpn("h2")),
                (2, Array.Empty<byte>()));
            var withDefault = DnsTestMessages.CreateServiceRData(
                2,
                "default-http11.example",
                (1, DnsTestMessages.EncodeAlpn("h2")));
            var response = DnsTestMessages.CreateHttpsResponse(
                query.Span,
                (60, h2Only),
                (60, withDefault));
            return Task.FromResult(response);
        });

        var result = await resolver.ResolveAsync("origin.example");

        var endpoint = Assert.Single(result.Endpoints);
        Assert.Equal("default-http11.example", endpoint.TargetName);
        Assert.Equal(new[] { "h2", "http/1.1" }, endpoint.AlpnProtocols);
    }

    [Fact]
    public async Task EndpointConfigurationRequiresOriginSniAndCompatibleInnerAlpn()
    {
        var resolver = CreateResolver((query, _) => Task.FromResult(
            DnsTestMessages.CreateHttpsResponse(
                query.Span,
                (60, DnsTestMessages.CreateServiceRData(
                    1,
                    ".",
                    (1, DnsTestMessages.EncodeAlpn("h2")),
                    (2, Array.Empty<byte>()))))),
            supportedAlpn: ["h2"]);
        var endpoint = Assert.Single(
            (await resolver.ResolveAsync("origin.example")).Endpoints);

        Assert.Throws<ArgumentException>(() => endpoint.ConfigureClient(
            new CustomTlsClientOptions()));
        Assert.Throws<ArgumentException>(() => endpoint.ConfigureClient(
            new CustomTlsClientOptions
            {
                ClientHello = ClientHelloProfiles.Custom(builder => builder
                    .WithTls13()
                    .WithSni(false)
                    .WithAlpn("h2")),
            }));
    }

    [Fact]
    public async Task AliasModeIgnoresServiceRecordsAndInheritsTheMinimumTtl()
    {
        var clock = new ManualTimeProvider(
            new DateTimeOffset(2026, 7, 17, 12, 0, 0, TimeSpan.Zero));
        var calls = new List<string>();
        var resolver = CreateResolver((query, _) =>
        {
            var name = DnsTestMessages.ReadQueryName(query.Span);
            calls.Add(name);
            return Task.FromResult(name switch
            {
                "origin.example" => DnsTestMessages.CreateHttpsResponse(
                    query.Span,
                    (20, DnsTestMessages.CreateServiceRData(0, "alias.example", (3, new byte[] { 0, 1 }))),
                    (200, DnsTestMessages.CreateServiceRData(1, "ignored.example"))),
                "alias.example" => DnsTestMessages.CreateHttpsResponse(
                    query.Span,
                    (60, DnsTestMessages.CreateServiceRData(1, "."))),
                _ => throw new InvalidOperationException(),
            });
        }, clock);

        var result = await resolver.ResolveAsync("origin.example");

        Assert.Equal(new[] { "origin.example", "alias.example" }, calls);
        Assert.Equal(2, result.Endpoints.Count);
        Assert.All(result.Endpoints, endpoint => Assert.Equal("alias.example", endpoint.TargetName));
        Assert.False(result.Endpoints[0].IsFallback);
        Assert.True(result.Endpoints[1].IsFallback);
        Assert.Equal(clock.GetUtcNow().AddSeconds(20), result.ExpiresAt);
        Assert.All(result.Endpoints, endpoint => Assert.Equal(result.ExpiresAt, endpoint.ExpiresAt));
    }

    [Fact]
    public async Task AliasLoopFallsBackToAuthorityWithinTheConfiguredTraversalBound()
    {
        var resolver = CreateResolver((query, _) =>
        {
            var name = DnsTestMessages.ReadQueryName(query.Span);
            var target = name == "origin.example" ? "alias.example" : "origin.example";
            return Task.FromResult(DnsTestMessages.CreateHttpsResponse(
                query.Span,
                (60, DnsTestMessages.CreateServiceRData(0, target))));
        });

        var result = await resolver.ResolveAsync("origin.example");

        var endpoint = Assert.Single(result.Endpoints);
        Assert.True(endpoint.IsFallback);
        Assert.Equal("origin.example", endpoint.TargetName);
    }

    [Fact]
    public async Task MultipleAliasModeRecordsAreRandomlySelectedAndRootMeansUnavailable()
    {
        var calls = new List<string>();
        var resolver = CreateResolver((query, _) =>
        {
            var name = DnsTestMessages.ReadQueryName(query.Span);
            calls.Add(name);
            return Task.FromResult(name == "origin.example"
                ? DnsTestMessages.CreateHttpsResponse(
                    query.Span,
                    (60, DnsTestMessages.CreateServiceRData(0, "first.example")),
                    (60, DnsTestMessages.CreateServiceRData(0, "second.example")))
                : DnsTestMessages.CreateNoDataResponse(query.Span));
        });

        var selected = await resolver.ResolveAsync("origin.example");

        Assert.Equal(new[] { "origin.example", "second.example" }, calls);
        Assert.Equal("second.example", Assert.Single(selected.Endpoints).TargetName);

        var unavailable = CreateResolver((query, _) => Task.FromResult(
            DnsTestMessages.CreateHttpsResponse(
                query.Span,
                (60, DnsTestMessages.CreateServiceRData(0, ".")))));
        var fallback = Assert.Single(
            (await unavailable.ResolveAsync("origin.example")).Endpoints);
        Assert.True(fallback.IsFallback);
        Assert.Equal("origin.example", fallback.TargetName);
    }

    [Fact]
    public async Task UnsupportedAllEchSetFailsClosedInsteadOfLeakingTheOrigin()
    {
        var unsupported = DnsTestMessages.CreateEchConfigList();
        unsupported[7] = 0xFE;
        unsupported[8] = 0x00;
        var resolver = CreateResolver((query, _) => Task.FromResult(
            DnsTestMessages.CreateHttpsResponse(
                query.Span,
                (60, DnsTestMessages.CreateServiceRData(1, ".", (5, unsupported))))));

        var exception = await Assert.ThrowsAsync<TlsEchDnsException>(() =>
            resolver.ResolveAsync("origin.example"));

        Assert.Equal(TlsEchDnsErrorKind.EchRequired, exception.ErrorKind);
    }

    [Fact]
    public async Task SuccessfulNoDataUsesUncachedDirectFallbackAndPreservesNonDefaultPort()
    {
        var calls = 0;
        var resolver = CreateResolver((query, _) =>
        {
            calls++;
            Assert.Equal("_8443._https.origin.example", DnsTestMessages.ReadQueryName(query.Span));
            return Task.FromResult(DnsTestMessages.CreateNoDataResponse(query.Span));
        });

        var first = await resolver.ResolveAsync("origin.example", 8443);
        var second = await resolver.ResolveAsync("origin.example", 8443);

        Assert.Equal(2, calls);
        Assert.True(Assert.Single(first.Endpoints).IsFallback);
        Assert.Equal("origin.example", Assert.Single(second.Endpoints).TargetName);
        Assert.Equal(8443, Assert.Single(second.Endpoints).Port);
    }

    [Fact]
    public async Task PositiveResultIsTtlCachedThenRefreshed()
    {
        var clock = new ManualTimeProvider(
            new DateTimeOffset(2026, 7, 17, 12, 0, 0, TimeSpan.Zero));
        var calls = 0;
        var resolver = CreateResolver((query, _) =>
        {
            calls++;
            return Task.FromResult(DnsTestMessages.CreateHttpsResponse(
                query.Span,
                (10, DnsTestMessages.CreateServiceRData(1, "."))));
        }, clock);

        var first = await resolver.ResolveAsync("origin.example");
        var cached = await resolver.ResolveAsync("ORIGIN.example.");
        Assert.Same(first, cached);
        Assert.Equal(1, calls);

        clock.Advance(TimeSpan.FromSeconds(11));
        var refreshed = await resolver.ResolveAsync("origin.example");
        Assert.NotSame(first, refreshed);
        Assert.Equal(2, calls);
    }

    [Fact]
    public async Task AuthenticatedDataRequirementAndCallerCancellationAreEnforced()
    {
        var unauthenticated = CreateResolver(
            (query, _) => Task.FromResult(
                DnsTestMessages.CreateNoDataResponse(query.Span, authenticated: false)),
            requireAuthenticatedData: true);

        var authException = await Assert.ThrowsAsync<TlsEchDnsException>(() =>
            unauthenticated.ResolveAsync("origin.example"));
        Assert.Equal(TlsEchDnsErrorKind.AuthenticationRequired, authException.ErrorKind);

        using var cancellation = new CancellationTokenSource();
        cancellation.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
            unauthenticated.ResolveAsync("other.example", cancellationToken: cancellation.Token));
    }

    [Fact]
    public async Task DnsErrorsFailClosedUnlessTheCallerExplicitlyAllowsDirectFallback()
    {
        static Task<byte[]> ServFail(ReadOnlyMemory<byte> query, CancellationToken _) =>
            Task.FromResult(DnsTestMessages.CreateNoDataResponse(query.Span, responseCode: 2));

        var strict = CreateResolver(ServFail);
        var optedIn = CreateResolver(ServFail, allowErrorFallback: true);

        var exception = await Assert.ThrowsAsync<TlsEchDnsException>(() =>
            strict.ResolveAsync("origin.example"));
        Assert.Equal(TlsEchDnsErrorKind.DnsResponseError, exception.ErrorKind);
        Assert.True(Assert.Single(
            (await optedIn.ResolveAsync("origin.example")).Endpoints).IsFallback);
    }

    [Fact]
    public async Task MalformedServiceBindingRejectsTheRrSetAndUsesNonSvcbFallback()
    {
        var resolver = CreateResolver((query, _) =>
        {
            var response = DnsTestMessages.CreateHttpsResponse(
                query.Span,
                (60, DnsTestMessages.CreateServiceRData(
                    1,
                    ".",
                    (2, Array.Empty<byte>()),
                    (1, DnsTestMessages.EncodeAlpn("http/1.1")))));
            return Task.FromResult(response);
        });

        var result = await resolver.ResolveAsync("origin.example");

        var endpoint = Assert.Single(result.Endpoints);
        Assert.True(endpoint.IsFallback);
        Assert.Equal("origin.example", endpoint.TargetName);
    }

    [Fact]
    public void ResolverOptionsRejectUnboundedAndInvalidInputs()
    {
        Assert.Throws<ArgumentException>(() => new TlsEchDnsResolverOptions
        {
            NameServers = [],
        }.Snapshot());
        Assert.Throws<ArgumentOutOfRangeException>(() => new TlsEchDnsResolverOptions
        {
            MaximumAliasDepth = 0,
        }.Snapshot());
        Assert.Throws<ArgumentException>(() => DnsNames.NormalizeOrigin("127.0.0.1"));
        Assert.Equal("xn--bcher-kva.example", DnsNames.NormalizeOrigin("BÜCHER.example."));
    }

    private static TlsEchDnsResolver CreateResolver(
        Func<ReadOnlyMemory<byte>, CancellationToken, Task<byte[]>> handler,
        ManualTimeProvider? clock = null,
        bool requireAuthenticatedData = false,
        bool allowErrorFallback = false,
        string[]? supportedAlpn = null)
    {
        clock ??= new ManualTimeProvider(DateTimeOffset.UtcNow);
        var cache = new TlsEchDnsCache(16, clock);
        var configuration = new TlsEchDnsResolverConfiguration(
            [new IPEndPoint(IPAddress.Loopback, 53)],
            TimeSpan.FromSeconds(1),
            1232,
            RequestDnsSec: false,
            requireAuthenticatedData,
            ushort.MaxValue,
            32,
            8,
            supportedAlpn ?? ["http/1.1"],
            TimeSpan.FromDays(1),
            cache,
            allowErrorFallback);
        return new TlsEchDnsResolver(
            configuration,
            new FakeTransport(handler),
            new FixedRandomSource(),
            clock);
    }

    private sealed class FakeTransport(
        Func<ReadOnlyMemory<byte>, CancellationToken, Task<byte[]>> handler) : IDnsQueryTransport
    {
        public async Task<DnsTransportResponse> QueryAsync(
            IPEndPoint server,
            ReadOnlyMemory<byte> query,
            int maximumResponseSize,
            CancellationToken cancellationToken) => new(
                await handler(query, cancellationToken));
    }

    private sealed class FixedRandomSource : IDnsRandomSource
    {
        private ushort _identifier = 1;

        public ushort NextIdentifier() => _identifier++;

        public int NextInt32(int exclusiveMaximum) => exclusiveMaximum - 1;
    }

    private sealed class ManualTimeProvider(DateTimeOffset value) : TimeProvider
    {
        private DateTimeOffset _value = value;

        public override DateTimeOffset GetUtcNow() => _value;

        internal void Advance(TimeSpan duration) => _value += duration;
    }
}
