using System.Text;
using SharpTls;

var discoverEch = args.Contains("--ech-dns", StringComparer.Ordinal);
var positional = args.Where(argument => argument != "--ech-dns").ToArray();
var host = positional.Length > 0 ? positional[0] : "example.com";
var path = positional.Length > 1 ? positional[1] : "/";
if (!path.StartsWith('/'))
{
    throw new ArgumentException("The request target must start with '/'.", nameof(args));
}

var options = new CustomTlsClientOptions
{
    ServerName = host,
    ClientHello = ClientHelloProfiles.Custom(builder => builder
        .WithTls13()
        .WithAlpn("http/1.1")),
};

var connectHost = host;
var connectPort = 443;
if (discoverEch)
{
    var resolver = new TlsEchDnsResolver(new TlsEchDnsResolverOptions
    {
        SupportedAlpnProtocols = ["http/1.1"],
    });
    var resolution = await resolver.ResolveAsync(host, 443);
    var endpoint = resolution.Endpoints[0];
    endpoint.ConfigureClient(options);
    connectHost = endpoint.TargetName;
    connectPort = endpoint.Port;
}

await using var client = new CustomTlsClient(options);
await client.ConnectAsync(connectHost, connectPort);
if (client.NegotiatedApplicationProtocol is not (null or "http/1.1"))
{
    throw new InvalidOperationException(
        $"Server selected unsupported ALPN '{client.NegotiatedApplicationProtocol}'.");
}

var request = Encoding.ASCII.GetBytes(
    $"GET {path} HTTP/1.1\r\n" +
    $"Host: {host}\r\n" +
    "User-Agent: SharpTls.Http11/0.1\r\n" +
    "Accept: */*\r\n" +
    "Connection: close\r\n\r\n");
await using var tlsStream = client.OpenApplicationStream(leaveClientOpen: true);
await tlsStream.WriteAsync(request);
var responseBuffer = new byte[16 * 1024];
int bytesRead;
while ((bytesRead = await tlsStream.ReadAsync(responseBuffer)) != 0)
{
    await Console.OpenStandardOutput().WriteAsync(responseBuffer.AsMemory(0, bytesRead));
}
