using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using SharpTls.Dns;
using SharpTls.Tests.Certificates;
using SharpTls.Tests.Interop;

namespace SharpTls.Tests.Dns;

public sealed class ProtectedDnsTransportTests
{
    [Fact]
    public async Task DnsOverTlsAuthenticatesResolverAndUsesRfc7858Framing()
    {
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        using var pki = TestPki.Create("resolver.example");
        var query = DnsMessageWriter.CreateHttpsQuery(0x1234, "origin.example", 1232, false);
        var dnsResponse = DnsTestMessages.CreateHttpsResponse(
            query,
            (60, DnsTestMessages.CreateServiceRData(1, ".")));
        var expectedRequest = DnsTransportIo.FrameDnsMessage(query);
        var applicationResponse = DnsTransportIo.FrameDnsMessage(dnsResponse);
        await using var server = new ManagedTls13MutualAuthServer(
            pki.Leaf,
            pki.Root,
            (RSA)pki.LeafKey,
            expectedClientLeaf: [],
            expectedApplicationRequest: expectedRequest,
            applicationResponse: applicationResponse,
            expectEmptyInitialCertificate: true);
        var options = new TlsEchDnsResolverOptions
        {
            DnsOverTls = new TlsEchDnsOverTlsOptions
            {
                ResolverName = "resolver.example",
                BootstrapEndpoints = [new IPEndPoint(IPAddress.Loopback, server.Port)],
                CertificateValidation = Trust(pki.Root),
            },
        };
        var configuration = Assert.IsType<DnsOverTlsConfiguration>(
            options.Snapshot().ProtectedTransport);
        var transport = new TlsDnsQueryTransport(configuration);

        var result = await transport.QueryAsync(
            configuration.BootstrapEndpoints[0],
            query,
            ushort.MaxValue,
            timeout.Token);
        await server.Completion;

        Assert.Equal(dnsResponse, result.Message);
        Assert.Equal(0u, result.CacheAgeSeconds);
        Assert.Null(result.TtlCapSeconds);
    }

    [Fact]
    public async Task DnsOverHttpsPostsWireMessageAndAppliesHttpCacheAge()
    {
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        using var pki = TestPki.Create("resolver.example");
        var query = DnsMessageWriter.CreateHttpsQuery(0x4321, "origin.example", 1232, false);
        var dnsResponse = DnsTestMessages.CreateHttpsResponse(
            query,
            (60, DnsTestMessages.CreateServiceRData(1, ".")));
        var endpoint = new Uri("https://resolver.example:4443/dns-query?tenant=one");
        var expectedHeader = Encoding.ASCII.GetBytes(
            "POST /dns-query?tenant=one HTTP/1.1\r\n" +
            "Host: resolver.example:4443\r\n" +
            "Accept: application/dns-message\r\n" +
            "Content-Type: application/dns-message\r\n" +
            $"Content-Length: {query.Length}\r\n" +
            "Connection: close\r\n\r\n");
        byte[] expectedRequest = [.. expectedHeader, .. query];
        var responseHeader = Encoding.ASCII.GetBytes(
            "HTTP/1.1 200 OK\r\n" +
            "Content-Type: application/dns-message\r\n" +
            $"Content-Length: {dnsResponse.Length}\r\n" +
            "Age: 7\r\n" +
            "Cache-Control: public, max-age=30\r\n\r\n");
        byte[] applicationResponse = [.. responseHeader, .. dnsResponse];
        await using var server = new ManagedTls13MutualAuthServer(
            pki.Leaf,
            pki.Root,
            (RSA)pki.LeafKey,
            expectedClientLeaf: [],
            expectedApplicationRequest: expectedRequest,
            applicationResponse: applicationResponse,
            expectEmptyInitialCertificate: true);
        var options = new TlsEchDnsResolverOptions
        {
            DnsOverHttps = new TlsEchDnsOverHttpsOptions
            {
                Endpoint = endpoint,
                BootstrapEndpoints = [new IPEndPoint(IPAddress.Loopback, server.Port)],
                CertificateValidation = Trust(pki.Root),
            },
        };
        var configuration = Assert.IsType<DnsOverHttpsConfiguration>(
            options.Snapshot().ProtectedTransport);
        var transport = new HttpsDnsQueryTransport(configuration);

        var result = await transport.QueryAsync(
            configuration.BootstrapEndpoints[0],
            query,
            ushort.MaxValue,
            timeout.Token);
        await server.Completion;

        Assert.Equal(dnsResponse, result.Message);
        Assert.Equal(7u, result.CacheAgeSeconds);
        Assert.Equal(23u, result.TtlCapSeconds);
        var parsed = DnsMessageParser.ParseHttpsResponse(
            result.Message,
            0x4321,
            "origin.example",
            ushort.MaxValue,
            8,
            result.CacheAgeSeconds,
            result.TtlCapSeconds);
        Assert.Equal(23u, Assert.Single(parsed.HttpsRecords).TimeToLive);
    }

    [Fact]
    public async Task HttpReaderAcceptsFragmentedChunkedDnsMessageAndTrailers()
    {
        var query = DnsMessageWriter.CreateHttpsQuery(7, "origin.example", 1232, false);
        var dns = DnsTestMessages.CreateNoDataResponse(query);
        var first = dns[..10];
        var second = dns[10..];
        var encoded = Encoding.ASCII.GetBytes(
            "HTTP/1.1 200 OK\r\n" +
            "Content-Type: application/dns-message\r\n" +
            "Transfer-Encoding: chunked\r\n\r\n" +
            $"{first.Length:X}\r\n")
            .Concat(first)
            .Concat(Encoding.ASCII.GetBytes($"\r\n{second.Length:X};safe=yes\r\n"))
            .Concat(second)
            .Concat("\r\n0\r\nX-Trace: none\r\n\r\n"u8.ToArray())
            .ToArray();
        await using var stream = new ChunkedReadStream(encoded, 1);

        var result = await DnsHttp11ResponseReader.ReadAsync(
            stream,
            512,
            1024,
            CancellationToken.None);

        Assert.Equal(dns, result.Message);
    }

    [Theory]
    [InlineData("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 12\r\n\r\n000000000000")]
    [InlineData("HTTP/1.1 200 OK\r\nContent-Type: application/dns-message\r\nContent-Length: 12\r\nContent-Length: 12\r\n\r\n000000000000")]
    [InlineData("HTTP/1.1 200 OK\r\nContent-Type: application/dns-message\r\nContent-Length: 12\r\nTransfer-Encoding: chunked\r\n\r\n000000000000")]
    [InlineData("HTTP/1.1 200 OK\r\nContent-Type: application/dns-message\r\n Age: 1\r\nContent-Length: 12\r\n\r\n000000000000")]
    [InlineData("HTTP/1.1 302 Found\r\nContent-Type: application/dns-message\r\nContent-Length: 12\r\n\r\n000000000000")]
    [InlineData("HTTP/1.1 200 OK\r\nContent-Type: application/dns-message\r\nAge: -1\r\nContent-Length: 12\r\n\r\n000000000000")]
    [InlineData("HTTP/1.1 200 OK\r\nContent-Type: application/dns-message\r\nCache-Control: max-age=one\r\nContent-Length: 12\r\n\r\n000000000000")]
    public async Task HttpReaderRejectsMalformedOrHostileResponses(string response)
    {
        await using var stream = new ChunkedReadStream(Encoding.ASCII.GetBytes(response), 2);

        await Assert.ThrowsAnyAsync<IOException>(() => DnsHttp11ResponseReader.ReadAsync(
            stream,
            512,
            1024,
            CancellationToken.None));
    }

    [Fact]
    public async Task ProtectedReadersEnforceBoundsAndCancellationBeforeAllocation()
    {
        await using var oversizedDns = new MemoryStream([0x02, 0x01]);
        await Assert.ThrowsAsync<TlsEchDnsException>(() =>
            DnsTransportIo.ReadFramedDnsMessageAsync(
                oversizedDns,
                512,
                CancellationToken.None));

        var oversizedHttp = Encoding.ASCII.GetBytes(
            "HTTP/1.1 200 OK\r\n" +
            "Content-Type: application/dns-message\r\n" +
            "Content-Length: 513\r\n\r\n");
        await using var httpStream = new MemoryStream(oversizedHttp);
        await Assert.ThrowsAsync<TlsEchDnsException>(() =>
            DnsHttp11ResponseReader.ReadAsync(
                httpStream,
                512,
                1024,
                CancellationToken.None));

        using var canceled = new CancellationTokenSource();
        canceled.Cancel();
        await using var incomplete = new ChunkedReadStream("HTTP/1.1"u8.ToArray(), 1);
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
            DnsHttp11ResponseReader.ReadAsync(
                incomplete,
                512,
                1024,
                canceled.Token));
    }

    [Fact]
    public void ProtectedOptionsRejectAmbiguousRecursiveAndProtocolConfigurations()
    {
        var endpoint = new IPEndPoint(IPAddress.Loopback, 0);
        Assert.Throws<ArgumentException>(() => new TlsEchDnsResolverOptions
        {
            NameServers = [endpoint],
            DnsOverTls = new TlsEchDnsOverTlsOptions
            {
                ResolverName = "resolver.example",
                BootstrapEndpoints = [endpoint],
            },
        }.Snapshot());
        Assert.Throws<ArgumentException>(() => new TlsEchDnsResolverOptions
        {
            DnsOverTls = new TlsEchDnsOverTlsOptions
            {
                ResolverName = "resolver.example",
                BootstrapEndpoints = [],
            },
        }.Snapshot());
        Assert.Throws<ArgumentException>(() => new TlsEchDnsResolverOptions
        {
            DnsOverTls = new TlsEchDnsOverTlsOptions
            {
                ResolverName = "resolver.example",
                BootstrapEndpoints = [endpoint],
                ClientHello = ClientHelloProfiles.Custom(builder =>
                    builder.WithTls13().WithAlpn("http/1.1")),
            },
        }.Snapshot());
        Assert.Throws<ArgumentException>(() => new TlsEchDnsResolverOptions
        {
            DnsOverHttps = new TlsEchDnsOverHttpsOptions
            {
                Endpoint = new Uri("http://resolver.example/dns-query"),
                BootstrapEndpoints = [endpoint],
            },
        }.Snapshot());
        Assert.Throws<ArgumentException>(() => new TlsEchDnsResolverOptions
        {
            DnsOverHttps = new TlsEchDnsOverHttpsOptions
            {
                Endpoint = new Uri("https://resolver.example/dns-query"),
                BootstrapEndpoints = [endpoint],
                ClientHello = ClientHelloProfiles.Custom(builder =>
                    builder.WithTls13().WithAlpn("h2", "http/1.1")),
            },
        }.Snapshot());

        var dot = Assert.IsType<DnsOverTlsConfiguration>(
            new TlsEchDnsResolverOptions
            {
                DnsOverTls = new TlsEchDnsOverTlsOptions
                {
                    ResolverName = "RESOLVER.example.",
                    BootstrapEndpoints = [endpoint],
                },
            }.Snapshot().ProtectedTransport);
        Assert.Equal("resolver.example", dot.ResolverName);
        Assert.Equal(853, Assert.Single(dot.BootstrapEndpoints).Port);

        var doh = Assert.IsType<DnsOverHttpsConfiguration>(
            new TlsEchDnsResolverOptions
            {
                DnsOverHttps = new TlsEchDnsOverHttpsOptions
                {
                    Endpoint = new Uri("https://resolver.example/dns-query"),
                    BootstrapEndpoints = [endpoint],
                },
            }.Snapshot().ProtectedTransport);
        Assert.Equal(443, Assert.Single(doh.BootstrapEndpoints).Port);
    }

    private static CustomTlsCertificateValidationOptions Trust(X509Certificate2 root) => new()
    {
        RevocationMode = X509RevocationMode.NoCheck,
        CustomTrustRoots = [root],
    };

    private sealed class ChunkedReadStream(byte[] input, int chunkSize) : Stream
    {
        private int _offset;

        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length => input.Length;
        public override long Position { get => _offset; set => throw new NotSupportedException(); }
        public override void Flush() { }
        public override int Read(byte[] buffer, int offset, int count) =>
            Read(buffer.AsSpan(offset, count));
        public override int Read(Span<byte> buffer)
        {
            if (_offset == input.Length)
            {
                return 0;
            }
            var count = Math.Min(Math.Min(chunkSize, buffer.Length), input.Length - _offset);
            input.AsSpan(_offset, count).CopyTo(buffer);
            _offset += count;
            return count;
        }
        public override ValueTask<int> ReadAsync(
            Memory<byte> buffer,
            CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return ValueTask.FromResult(Read(buffer.Span));
        }
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) =>
            throw new NotSupportedException();
    }
}
