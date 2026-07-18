using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using SharpTls.Certificates;
using SharpTls.Protocol;
using SharpTls.Tests.Certificates;

namespace SharpTls.Tests.Interop;

public sealed class RecordSizeLimitInteropTests
{
    [Fact]
    public async Task AsymmetricLimitsFragmentBothHandshakeAndApplicationRecords()
    {
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        using var serverPki = TestPki.Create("localhost");
        using var clientPki = TestPki.Create(
            dnsName: "client.example",
            serverAuthenticationEku: false);
        using var clientLeafWithKey = clientPki.Leaf.CopyWithPrivateKey(
            (RSA)clientPki.LeafKey);
        using var clientCredential = new TlsClientCertificate(
            clientLeafWithKey,
            [clientPki.Root]);
        var request = Enumerable.Range(0, 300).Select(value => (byte)value).ToArray();
        await using var server = new ManagedTls13MutualAuthServer(
            serverPki.Leaf,
            serverPki.Root,
            (RSA)serverPki.LeafKey,
            clientPki.Leaf.RawData,
            serverRecordSizeLimit: 64,
            expectedApplicationRequest: request);
        var profile = ClientHelloProfiles.Custom(builder => builder
            .WithRecordSizeLimit(128));
        await using var client = CreateClient(
            profile,
            clientCredential,
            serverPki.Root);

        await client.ConnectAsync("127.0.0.1", server.Port, timeout.Token);
        await client.WriteApplicationDataAsync(request, timeout.Token);
        var response = await client.ReadApplicationDataAsync(timeout.Token);
        await server.Completion;

        Assert.Equal(128, client.NegotiatedReceiveRecordSizeLimit);
        Assert.Equal(64, client.NegotiatedSendRecordSizeLimit);
        Assert.Equal("pong"u8.ToArray(), response);
        Assert.InRange(server.MaximumReceivedProtectedPlaintextLength, 1, 64);
    }

    [Fact]
    public async Task OversizedAuthenticatedPeerRecordFailsWithRecordOverflow()
    {
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        using var serverPki = TestPki.Create("localhost");
        using var clientPki = TestPki.Create(
            dnsName: "client.example",
            serverAuthenticationEku: false);
        using var clientLeafWithKey = clientPki.Leaf.CopyWithPrivateKey(
            (RSA)clientPki.LeafKey);
        using var clientCredential = new TlsClientCertificate(clientLeafWithKey);
        await using var server = new ManagedTls13MutualAuthServer(
            serverPki.Leaf,
            serverPki.Root,
            (RSA)serverPki.LeafKey,
            clientPki.Leaf.RawData,
            serverRecordSizeLimit: 64,
            applicationResponse: new byte[64],
            violateClientRecordSizeLimitAfterHandshake: true);
        var profile = ClientHelloProfiles.Custom(builder => builder
            .WithRecordSizeLimit(64));
        await using var client = CreateClient(
            profile,
            clientCredential,
            serverPki.Root);

        await client.ConnectAsync("127.0.0.1", server.Port, timeout.Token);
        await client.WriteApplicationDataAsync("ping"u8.ToArray(), timeout.Token);
        var exception = await Assert.ThrowsAsync<TlsProtocolException>(async () =>
            await client.ReadApplicationDataAsync(timeout.Token));
        await server.Completion;

        Assert.Equal(TlsAlertDescription.RecordOverflow, exception.Alert);
    }

    private static CustomTlsClient CreateClient(
        ClientHelloProfile profile,
        TlsClientCertificate clientCredential,
        X509Certificate2 trustRoot) => new(new CustomTlsClientOptions
        {
            ServerName = "localhost",
            ClientHello = profile,
            ClientCertificate = clientCredential,
            CertificateValidation = new CustomTlsCertificateValidationOptions
            {
                RevocationMode = X509RevocationMode.NoCheck,
                CustomTrustRoots = [trustRoot],
            },
        });
}
