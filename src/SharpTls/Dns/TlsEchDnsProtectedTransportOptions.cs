using System.Net;
using System.Security.Cryptography.X509Certificates;
using SharpTls.Protocol;

namespace SharpTls;

/// <summary>Configures authenticated RFC 7858 DNS-over-TLS for ECH discovery.</summary>
public sealed class TlsEchDnsOverTlsOptions
{
    /// <summary>Gets or sets the DNS name authenticated by SNI, PKIX, and hostname validation.</summary>
    public string? ResolverName { get; set; }

    /// <summary>
    /// Gets or sets preconfigured resolver IP endpoints. Port zero is normalized to 853.
    /// Explicit addresses prevent recursive plaintext DNS bootstrap.
    /// </summary>
    public IReadOnlyList<IPEndPoint>? BootstrapEndpoints { get; set; }

    /// <summary>Gets or sets the TLS 1.3 ClientHello used only for the resolver connection.</summary>
    public ClientHelloProfile ClientHello { get; set; } =
        ClientHelloProfiles.Custom(builder => builder.WithTls13());

    /// <summary>Gets or sets strict resolver-certificate validation policy.</summary>
    public CustomTlsCertificateValidationOptions CertificateValidation { get; set; } = new();

    internal DnsOverTlsConfiguration Snapshot()
    {
        var resolverName = DnsProtectedTransportValidation.NormalizeResolverName(
            ResolverName,
            nameof(ResolverName));
        var endpoints = DnsProtectedTransportValidation.SnapshotEndpoints(
            BootstrapEndpoints,
            defaultPort: 853,
            nameof(BootstrapEndpoints));
        DnsProtectedTransportValidation.ValidateTlsProfile(
            ClientHello,
            requireHttp11: false,
            nameof(ClientHello));

        return new DnsOverTlsConfiguration(
            resolverName,
            endpoints,
            ClientHello,
            DnsCertificateValidationConfiguration.Snapshot(CertificateValidation));
    }
}

/// <summary>Configures authenticated RFC 8484 DNS-over-HTTPS over HTTP/1.1.</summary>
public sealed class TlsEchDnsOverHttpsOptions
{
    /// <summary>
    /// Gets or sets the configured HTTPS POST endpoint, for example
    /// <c>https://resolver.example/dns-query</c>.
    /// </summary>
    public Uri? Endpoint { get; set; }

    /// <summary>
    /// Gets or sets preconfigured resolver IP endpoints. Port zero is normalized to the
    /// endpoint URI port. Explicit addresses prevent recursive plaintext DNS bootstrap.
    /// </summary>
    public IReadOnlyList<IPEndPoint>? BootstrapEndpoints { get; set; }

    /// <summary>
    /// Gets or sets the TLS 1.3 ClientHello used only for the resolver connection. This private
    /// resolver transport intentionally uses HTTP/1.1 and therefore requires exactly that ALPN.
    /// </summary>
    public ClientHelloProfile ClientHello { get; set; } = ClientHelloProfiles.Custom(
        builder => builder.WithTls13().WithAlpn("http/1.1"));

    /// <summary>Gets or sets strict resolver-certificate validation policy.</summary>
    public CustomTlsCertificateValidationOptions CertificateValidation { get; set; } = new();

    /// <summary>Gets or sets the maximum accepted HTTP response-header byte count.</summary>
    public int MaximumResponseHeaderSize { get; set; } = 16 * 1024;

    internal DnsOverHttpsConfiguration Snapshot()
    {
        if (Endpoint is null || !Endpoint.IsAbsoluteUri ||
            !string.Equals(Endpoint.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase) ||
            !string.IsNullOrEmpty(Endpoint.UserInfo) || !string.IsNullOrEmpty(Endpoint.Fragment) ||
            string.IsNullOrEmpty(Endpoint.IdnHost) || Endpoint.Port is < 1 or > ushort.MaxValue)
        {
            throw new ArgumentException(
                "A DoH endpoint must be an absolute HTTPS URI without user information or a fragment.",
                nameof(Endpoint));
        }
        if (IPAddress.TryParse(Endpoint.IdnHost, out _))
        {
            throw new ArgumentException(
                "The current DoH transport requires a DNS authentication name and explicit bootstrap IPs.",
                nameof(Endpoint));
        }

        var resolverName = DnsProtectedTransportValidation.NormalizeResolverName(
            Endpoint.IdnHost,
            nameof(Endpoint));
        var pathAndQuery = Endpoint.GetComponents(
            UriComponents.PathAndQuery,
            UriFormat.UriEscaped);
        if (pathAndQuery.Length == 0)
        {
            pathAndQuery = "/";
        }
        else if (pathAndQuery[0] != '/')
        {
            pathAndQuery = "/" + pathAndQuery;
        }
        if (pathAndQuery.Length > 4096 || pathAndQuery.Any(character =>
                character > 0x7F || character <= 0x20 || character == 0x7F))
        {
            throw new ArgumentException(
                "The DoH endpoint path and query must contain at most 4096 visible ASCII bytes.",
                nameof(Endpoint));
        }
        if (MaximumResponseHeaderSize is < 1024 or > 64 * 1024)
        {
            throw new ArgumentOutOfRangeException(nameof(MaximumResponseHeaderSize));
        }

        var endpoints = DnsProtectedTransportValidation.SnapshotEndpoints(
            BootstrapEndpoints,
            Endpoint.Port,
            nameof(BootstrapEndpoints));
        DnsProtectedTransportValidation.ValidateTlsProfile(
            ClientHello,
            requireHttp11: true,
            nameof(ClientHello));

        var authority = Endpoint.IsDefaultPort
            ? resolverName
            : $"{resolverName}:{Endpoint.Port}";
        return new DnsOverHttpsConfiguration(
            resolverName,
            authority,
            pathAndQuery,
            endpoints,
            ClientHello,
            DnsCertificateValidationConfiguration.Snapshot(CertificateValidation),
            MaximumResponseHeaderSize);
    }
}

internal static class DnsProtectedTransportValidation
{
    internal static string NormalizeResolverName(string? value, string parameterName)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            throw new ArgumentException(
                "A protected DNS resolver authentication name is required.",
                parameterName);
        }
        return Dns.DnsNames.NormalizeOrigin(value);
    }

    internal static IPEndPoint[] SnapshotEndpoints(
        IReadOnlyList<IPEndPoint>? endpoints,
        int defaultPort,
        string parameterName)
    {
        if (endpoints is null || endpoints.Count is 0 or > 32)
        {
            throw new ArgumentException(
                "Protected DNS requires between 1 and 32 explicit bootstrap IP endpoints.",
                parameterName);
        }

        var result = endpoints.Select(endpoint =>
        {
            ArgumentNullException.ThrowIfNull(endpoint);
            if (endpoint.Address.Equals(IPAddress.Any) ||
                endpoint.Address.Equals(IPAddress.IPv6Any) ||
                endpoint.Address.IsIPv6Multicast || endpoint.Port is < 0 or > ushort.MaxValue)
            {
                throw new ArgumentException("A protected DNS bootstrap endpoint is invalid.", parameterName);
            }
            return new IPEndPoint(
                new IPAddress(endpoint.Address.GetAddressBytes()),
                endpoint.Port == 0 ? defaultPort : endpoint.Port);
        }).Distinct().ToArray();
        if (result.Length == 0)
        {
            throw new ArgumentException("No usable protected DNS bootstrap endpoint remains.", parameterName);
        }
        return result;
    }

    internal static void ValidateTlsProfile(
        ClientHelloProfile? profile,
        bool requireHttp11,
        string parameterName)
    {
        ArgumentNullException.ThrowIfNull(profile);
        var spec = profile.Spec;
        if (spec.SupportedVersions.Count != 1 ||
            spec.SupportedVersions[0] != TlsProtocolVersion.Tls13 || !spec.IncludeSni)
        {
            throw new ArgumentException(
                "Protected DNS requires a TLS-1.3-only ClientHello with semantic SNI.",
                parameterName);
        }
        if (requireHttp11)
        {
            if (spec.AlpnProtocols.Count != 1 || spec.AlpnProtocols[0] != "http/1.1")
            {
                throw new ArgumentException(
                    "The DoH HTTP/1.1 transport requires exactly the http/1.1 ALPN offer.",
                    parameterName);
            }
        }
        else if (spec.AlpnProtocols.Count != 0)
        {
            throw new ArgumentException(
                "The RFC 7858 DoT profile must not negotiate an application protocol.",
                parameterName);
        }
    }
}

internal sealed record DnsCertificateValidationConfiguration(
    X509RevocationMode RevocationMode,
    X509RevocationFlag RevocationFlag,
    bool DisableCertificateDownloads,
    TimeSpan UrlRetrievalTimeout,
    byte[][] CustomTrustRoots)
{
    internal static DnsCertificateValidationConfiguration Snapshot(
        CustomTlsCertificateValidationOptions? options)
    {
        ArgumentNullException.ThrowIfNull(options);
        if (options.UrlRetrievalTimeout < TimeSpan.Zero)
        {
            throw new ArgumentOutOfRangeException(nameof(options.UrlRetrievalTimeout));
        }
        var roots = options.CustomTrustRoots?.Select(root =>
        {
            ArgumentNullException.ThrowIfNull(root);
            return root.RawData;
        }).ToArray() ?? [];
        return new DnsCertificateValidationConfiguration(
            options.RevocationMode,
            options.RevocationFlag,
            options.DisableCertificateDownloads,
            options.UrlRetrievalTimeout,
            roots);
    }

    internal CustomTlsCertificateValidationOptions CreateOptions(
        out X509Certificate2[] temporaryRoots)
    {
        temporaryRoots = CustomTrustRoots.Select(
            X509CertificateLoader.LoadCertificate).ToArray();
        return new CustomTlsCertificateValidationOptions
        {
            RevocationMode = RevocationMode,
            RevocationFlag = RevocationFlag,
            DisableCertificateDownloads = DisableCertificateDownloads,
            UrlRetrievalTimeout = UrlRetrievalTimeout,
            CustomTrustRoots = temporaryRoots,
        };
    }
}

internal abstract record DnsProtectedTransportConfiguration(
    string ResolverName,
    IPEndPoint[] BootstrapEndpoints,
    ClientHelloProfile ClientHello,
    DnsCertificateValidationConfiguration CertificateValidation);

internal sealed record DnsOverTlsConfiguration(
    string ResolverName,
    IPEndPoint[] BootstrapEndpoints,
    ClientHelloProfile ClientHello,
    DnsCertificateValidationConfiguration CertificateValidation)
    : DnsProtectedTransportConfiguration(
        ResolverName,
        BootstrapEndpoints,
        ClientHello,
        CertificateValidation);

internal sealed record DnsOverHttpsConfiguration(
    string ResolverName,
    string Authority,
    string PathAndQuery,
    IPEndPoint[] BootstrapEndpoints,
    ClientHelloProfile ClientHello,
    DnsCertificateValidationConfiguration CertificateValidation,
    int MaximumResponseHeaderSize)
    : DnsProtectedTransportConfiguration(
        ResolverName,
        BootstrapEndpoints,
        ClientHello,
        CertificateValidation);
