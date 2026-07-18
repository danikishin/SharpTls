using System.Net;
using System.Security.Cryptography.X509Certificates;
using SharpTls.Protocol;
using SharpTls.Tests.Interop;

namespace SharpTls.Tests.Dns;

[Collection(nameof(PublicInteropCollection))]
public sealed class ProtectedDnsPublicInteropTests
{
    [InteropFact]
    [Trait("Category", "Interop")]
    public async Task GoogleDnsOverTlsResolvesHttpsServiceBinding()
    {
        using var cancellation = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        var resolver = new TlsEchDnsResolver(new TlsEchDnsResolverOptions
        {
            QueryTimeout = TimeSpan.FromSeconds(10),
            DnsOverTls = new TlsEchDnsOverTlsOptions
            {
                ResolverName = "dns.google",
                BootstrapEndpoints = [new IPEndPoint(IPAddress.Parse("8.8.8.8"), 853)],
                CertificateValidation = PublicResolverCertificatePolicy(),
            },
        });

        var resolution = await resolver.ResolveAsync(
            "example.com",
            cancellationToken: cancellation.Token);

        Assert.NotEmpty(resolution.Endpoints);
        Assert.All(resolution.Endpoints, endpoint =>
            Assert.Equal("example.com", endpoint.OriginName));
    }

    [InteropFact]
    [Trait("Category", "Interop")]
    public async Task CloudflareDnsOverHttpsHttp11ResolvesHttpsServiceBinding()
    {
        using var cancellation = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        var resolver = new TlsEchDnsResolver(new TlsEchDnsResolverOptions
        {
            QueryTimeout = TimeSpan.FromSeconds(10),
            DnsOverHttps = new TlsEchDnsOverHttpsOptions
            {
                Endpoint = new Uri("https://cloudflare-dns.com/dns-query"),
                BootstrapEndpoints = [new IPEndPoint(IPAddress.Parse("1.1.1.1"), 443)],
                CertificateValidation = PublicResolverCertificatePolicy(),
            },
        });

        var resolution = await resolver.ResolveAsync(
            "example.com",
            cancellationToken: cancellation.Token);

        Assert.NotEmpty(resolution.Endpoints);
        Assert.All(resolution.Endpoints, endpoint =>
            Assert.Equal("example.com", endpoint.OriginName));
    }

    [InteropFact]
    [Trait("Category", "Interop")]
    public async Task CloudflareDohBootstrapCompletesAcceptedPublicEchHandshake()
    {
        using var cancellation = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        var resolver = new TlsEchDnsResolver(new TlsEchDnsResolverOptions
        {
            QueryTimeout = TimeSpan.FromSeconds(10),
            DnsOverHttps = new TlsEchDnsOverHttpsOptions
            {
                Endpoint = new Uri("https://cloudflare-dns.com/dns-query"),
                BootstrapEndpoints = [new IPEndPoint(IPAddress.Parse("1.1.1.1"), 443)],
                CertificateValidation = PublicResolverCertificatePolicy(),
            },
        });
        var resolution = await resolver.ResolveAsync(
            "crypto.cloudflare.com",
            cancellationToken: cancellation.Token);
        var endpoint = resolution.Endpoints.First(candidate =>
            candidate.EchConfigList is not null && candidate.Ipv4Hints.Count != 0);
        Assert.Contains(
            endpoint.EchConfigList!.Configurations,
            configuration => configuration.PublicName == "cloudflare-ech.com");
        Assert.NotEqual(
            endpoint.OriginName,
            endpoint.EchConfigList.Configurations[0].PublicName);
        var options = new CustomTlsClientOptions
        {
            ClientHello = ClientHelloProfiles.Custom(builder =>
                builder.WithTls13().WithAlpn("http/1.1")),
            CertificateValidation = PublicResolverCertificatePolicy(),
        };
        endpoint.ConfigureClient(options);
        await using var client = new CustomTlsClient(options);

        await client.ConnectAsync(
            endpoint.Ipv4Hints[0].ToString(),
            endpoint.Port,
            cancellation.Token);

        Assert.True(client.EncryptedClientHelloAccepted);
        Assert.Equal(TlsProtocolVersion.Tls13, client.NegotiatedProtocolVersion);
        Assert.Equal("http/1.1", client.NegotiatedApplicationProtocol);
    }

    private static CustomTlsCertificateValidationOptions PublicResolverCertificatePolicy() =>
        new()
        {
            // Avoid a DNS bootstrap cycle while still requiring system PKIX and hostname checks.
            RevocationMode = X509RevocationMode.NoCheck,
            DisableCertificateDownloads = true,
        };

}
