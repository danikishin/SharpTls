using System.Net;
using System.Security.Cryptography;
using System.Text;
using SharpTls.Protocol;

namespace SharpTls.Tests.Interop;

public sealed class Tls13ExternalPskInteropTests
{
    [Fact]
    public async Task ExternalPskAuthenticatesFullManagedTcpHandshakeAndApplicationData()
    {
        var identity = "SharpTls-external-psk-1"u8.ToArray();
        var key = SHA256.HashData("SharpTls external PSK loopback secret"u8);
        var request = Encoding.ASCII.GetBytes(
            "HEAD /external-psk HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n");
        await using var server = new ManagedTls13ResumptionServer(
            identity,
            key,
            request,
            acceptEarlyData: false,
            expectRetransmission: false,
            externalPsk: true);
        using var external = new Tls13ExternalPsk(
            identity,
            key,
            TlsCipherSuite.TlsAes128GcmSha256,
            requireSelection: true);
        await using var client = new CustomTlsClient(new CustomTlsClientOptions
        {
            ServerName = "localhost",
            ClientHello = ClientHelloProfiles.Custom(builder => builder
                .WithTls13()
                .WithCipherSuites(TlsCipherSuite.TlsAes128GcmSha256)
                .WithSupportedGroups(NamedGroup.Secp256r1)
                .WithKeyShares(NamedGroup.Secp256r1)
                .WithSessionResumption()),
            ExternalPsk = external,
        });
        external.Dispose();
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(10));

        await client.ConnectAsync(IPAddress.Loopback.ToString(), server.Port, timeout.Token);
        await client.WriteApplicationDataAsync(request, timeout.Token);
        var response = await client.ReadApplicationDataAsync(timeout.Token);
        await server.Completion.WaitAsync(timeout.Token);

        Assert.True(client.ExternalPskWasSelected);
        Assert.False(client.SessionWasResumed);
        Assert.Equal(Tls13EarlyDataStatus.NotConfigured, client.EarlyDataStatus);
        Assert.Equal(request, server.ReceivedApplicationData);
        Assert.NotNull(response);
        Assert.StartsWith(
            "HTTP/1.1 200 ",
            Encoding.ASCII.GetString(response),
            StringComparison.Ordinal);

        var state = client.GetConnectionState();
        Assert.True(state.ExternalPskWasSelected);
        Assert.False(state.SessionWasResumed);
        Assert.Empty(state.PeerCertificateChain);

        CryptographicOperations.ZeroMemory(identity);
        CryptographicOperations.ZeroMemory(key);
        CryptographicOperations.ZeroMemory(request);
        CryptographicOperations.ZeroMemory(response);
    }
}
