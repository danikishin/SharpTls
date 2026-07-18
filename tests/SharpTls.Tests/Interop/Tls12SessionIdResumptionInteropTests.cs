using System.Net;
using System.Security.Cryptography;
using System.Text;
using SharpTls.Protocol;

namespace SharpTls.Tests.Interop;

public sealed class Tls12SessionIdResumptionInteropTests
{
    [Fact]
    public async Task CachedSessionIdCompletesAbbreviatedHandshakeAndApplicationTraffic()
    {
        var sessionId = SHA256.HashData("SharpTls TLS12 session id"u8);
        var masterSecret = RandomNumberGenerator.GetBytes(TlsConstants.Tls12MasterSecretLength);
        var request = Encoding.ASCII.GetBytes(
            "HEAD /tls12-resumed HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n");
        await using var server = new ManagedTls12SessionIdServer(
            sessionId,
            masterSecret,
            request);
        using var cache = new Tls12SessionCache();
        cache.Add(new Tls12Session(
            Tls13SessionOrigin.Create("localhost", server.Port),
            sessionId,
            TlsCipherSuite.TlsEcdheRsaWithAes128GcmSha256,
            negotiatedAlpn: null,
            NamedGroup.Secp256r1,
            masterSecret,
            DateTimeOffset.UtcNow.AddHours(1),
            peerRecordSizeLimit: null,
            localRecordSizeLimit: null,
            peerCertificateChain: [[0x30, 0x00]],
            stapledOcspResponse: null,
            signedCertificateTimestamps: []));
        await using var client = new CustomTlsClient(new CustomTlsClientOptions
        {
            ServerName = "localhost",
            ClientHello = ClientHelloProfiles.UTlsChrome58,
            Tls12SessionCache = cache,
        });
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(10));

        await client.ConnectAsync(IPAddress.Loopback.ToString(), server.Port, timeout.Token);
        await client.WriteApplicationDataAsync(request, timeout.Token);
        var response = await client.ReadApplicationDataAsync(timeout.Token);
        await server.Completion.WaitAsync(timeout.Token);

        Assert.True(client.SessionWasResumed);
        Assert.Equal(TlsProtocolVersion.Tls12, client.NegotiatedProtocolVersion);
        Assert.Equal(
            TlsCipherSuite.TlsEcdheRsaWithAes128GcmSha256,
            client.NegotiatedCipherSuite);
        Assert.Equal(request, server.ReceivedApplicationData);
        Assert.NotNull(response);
        Assert.StartsWith(
            "HTTP/1.1 200 ",
            Encoding.ASCII.GetString(response),
            StringComparison.Ordinal);
        var state = client.GetConnectionState();
        Assert.True(state.SessionWasResumed);
        Assert.Equal(server.TlsUnique, state.TlsUnique);
        var firstCopy = Assert.IsType<byte[]>(state.TlsUnique);
        MutateCopy(firstCopy);
        Assert.Equal(server.TlsUnique, state.TlsUnique);

        CryptographicOperations.ZeroMemory(sessionId);
        CryptographicOperations.ZeroMemory(masterSecret);
        CryptographicOperations.ZeroMemory(request);
        CryptographicOperations.ZeroMemory(response);
    }

    private static byte[] MutateCopy(byte[] value)
    {
        value[0] ^= 0xFF;
        return value;
    }

    [Fact]
    public async Task Rfc5077TicketIsOfferedRenewedAndAuthenticatedInTranscript()
    {
        var ticket = RandomNumberGenerator.GetBytes(96);
        var renewedTicket = RandomNumberGenerator.GetBytes(112);
        var masterSecret = RandomNumberGenerator.GetBytes(TlsConstants.Tls12MasterSecretLength);
        var request = "HEAD /tls12-ticket HTTP/1.1\r\nHost: localhost\r\n\r\n"u8.ToArray();
        await using var server = new ManagedTls12SessionIdServer(
            sessionId: [],
            masterSecret,
            request,
            expectedTicket: ticket,
            renewedTicket);
        var port = server.Port;
        using var cache = new Tls12SessionCache();
        cache.Add(new Tls12Session(
            Tls13SessionOrigin.Create("localhost", port),
            sessionId: [],
            TlsCipherSuite.TlsEcdheRsaWithAes128GcmSha256,
            negotiatedAlpn: null,
            NamedGroup.Secp256r1,
            masterSecret,
            DateTimeOffset.UtcNow.AddHours(2),
            peerRecordSizeLimit: null,
            localRecordSizeLimit: null,
            peerCertificateChain: [[0x30, 0x00]],
            stapledOcspResponse: null,
            signedCertificateTimestamps: [],
            ticket));
        await using var client = new CustomTlsClient(new CustomTlsClientOptions
        {
            ServerName = "localhost",
            ClientHello = ClientHelloProfiles.UTlsChrome58,
            Tls12SessionCache = cache,
        });
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(10));

        await client.ConnectAsync(IPAddress.Loopback.ToString(), port, timeout.Token);
        await client.WriteApplicationDataAsync(request, timeout.Token);
        _ = await client.ReadApplicationDataAsync(timeout.Token);
        await server.Completion.WaitAsync(timeout.Token);

        Assert.True(client.SessionWasResumed);
        Assert.Equal(request, server.ReceivedApplicationData);
        using var renewed = cache.TryGet(
            Tls13SessionOrigin.Create("localhost", port),
            [TlsCipherSuite.TlsEcdheRsaWithAes128GcmSha256]);
        Assert.NotNull(renewed);
        Assert.Equal(renewedTicket, renewed.Ticket);
        Assert.Empty(renewed.SessionId);

        CryptographicOperations.ZeroMemory(ticket);
        CryptographicOperations.ZeroMemory(renewedTicket);
        CryptographicOperations.ZeroMemory(masterSecret);
        CryptographicOperations.ZeroMemory(request);
    }
}
