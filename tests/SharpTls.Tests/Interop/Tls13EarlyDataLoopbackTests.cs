using System.Net;
using System.Security.Cryptography;
using System.Text;
using SharpTls.Protocol;

namespace SharpTls.Tests.Interop;

public sealed class Tls13EarlyDataLoopbackTests
{
    private static readonly byte[] TicketIdentity =
        Convert.FromHexString("0102030405060708090A0B0C0D0E0F10");

    [Fact]
    public async Task AcceptedEarlyDataCompletesAuthenticatedResumptionHandshake()
    {
        var request = Encoding.ASCII.GetBytes(
            "HEAD /accepted HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n");
        var psk = SHA256.HashData("SharpTls accepted 0-RTT test PSK"u8);
        await using var server = new ManagedTls13ResumptionServer(
            TicketIdentity,
            psk,
            request,
            acceptEarlyData: true,
            expectRetransmission: false);
        using var cache = CreateCache(server.Port, psk, maximumEarlyDataSize: 4096);
        await using var client = CreateClient(
            cache,
            request,
            Tls13EarlyDataRejectionPolicy.ReturnToCaller);
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(10));

        await client.ConnectAsync(IPAddress.Loopback.ToString(), server.Port, timeout.Token);
        var response = await client.ReadApplicationDataAsync(timeout.Token);
        await server.Completion.WaitAsync(timeout.Token);

        Assert.True(client.SessionWasResumed);
        Assert.Equal(Tls13EarlyDataStatus.Accepted, client.EarlyDataStatus);
        Assert.Equal(request, server.ReceivedEarlyData);
        Assert.Null(server.ReceivedApplicationData);
        Assert.NotNull(response);
        Assert.StartsWith(
            "HTTP/1.1 200 ",
            Encoding.ASCII.GetString(response),
            StringComparison.Ordinal);
        CryptographicOperations.ZeroMemory(psk);
        CryptographicOperations.ZeroMemory(request);
    }

    [Fact]
    public async Task RejectedEarlyDataIsRetransmittedOnlyByExplicitPolicy()
    {
        var request = Encoding.ASCII.GetBytes(
            "HEAD /rejected HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n");
        var psk = SHA256.HashData("SharpTls rejected 0-RTT test PSK"u8);
        await using var server = new ManagedTls13ResumptionServer(
            TicketIdentity,
            psk,
            request,
            acceptEarlyData: false,
            expectRetransmission: true);
        using var cache = CreateCache(server.Port, psk, maximumEarlyDataSize: 4096);
        await using var client = CreateClient(
            cache,
            request,
            Tls13EarlyDataRejectionPolicy.RetransmitAfterHandshake);
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(10));

        await client.ConnectAsync(IPAddress.Loopback.ToString(), server.Port, timeout.Token);
        var response = await client.ReadApplicationDataAsync(timeout.Token);
        await server.Completion.WaitAsync(timeout.Token);

        Assert.True(client.SessionWasResumed);
        Assert.Equal(Tls13EarlyDataStatus.RejectedAndRetransmitted, client.EarlyDataStatus);
        Assert.Equal(request, server.ReceivedEarlyData);
        Assert.Equal(request, server.ReceivedApplicationData);
        Assert.NotNull(response);
        Assert.StartsWith(
            "HTTP/1.1 200 ",
            Encoding.ASCII.GetString(response),
            StringComparison.Ordinal);
        CryptographicOperations.ZeroMemory(psk);
        CryptographicOperations.ZeroMemory(request);
    }

    [Fact]
    public async Task MultiplePeerKeyUpdatesRatchetWithoutAnArbitraryReceiverLimit()
    {
        var request = "HEAD /updates HTTP/1.1\r\nHost: localhost\r\n\r\n"u8.ToArray();
        var psk = SHA256.HashData("SharpTls KeyUpdate flood test PSK"u8);
        await using var server = new ManagedTls13ResumptionServer(
            TicketIdentity,
            psk,
            request,
            acceptEarlyData: true,
            expectRetransmission: false,
            keyUpdatesBeforeResponse: 3,
            requestClientKeyUpdate: true);
        using var cache = CreateCache(server.Port, psk, maximumEarlyDataSize: 4096);
        await using var client = CreateClient(
            cache,
            request,
            Tls13EarlyDataRejectionPolicy.ReturnToCaller);
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(10));

        await client.ConnectAsync(IPAddress.Loopback.ToString(), server.Port, timeout.Token);
        var response = await client.ReadApplicationDataAsync(timeout.Token);
        await server.Completion.WaitAsync(timeout.Token);

        Assert.Equal(3UL, client.ServerKeyUpdateCount);
        Assert.Equal(1UL, client.ClientKeyUpdateCount);
        Assert.Equal(1, server.ReceivedClientKeyUpdateResponses);
        Assert.NotNull(response);
        Assert.StartsWith(
            "HTTP/1.1 200 ",
            Encoding.ASCII.GetString(response),
            StringComparison.Ordinal);
        CryptographicOperations.ZeroMemory(psk);
        CryptographicOperations.ZeroMemory(request);
    }

    [Fact]
    public async Task ASecondRequestedPeerUpdateIsRejectedUntilPeerKeyUpdateArrives()
    {
        var request = "HEAD /request-update HTTP/1.1\r\nHost: localhost\r\n\r\n"u8.ToArray();
        var psk = SHA256.HashData("SharpTls outstanding KeyUpdate request PSK"u8);
        await using var server = new ManagedTls13ResumptionServer(
            TicketIdentity,
            psk,
            request,
            acceptEarlyData: true,
            expectRetransmission: false,
            expectClientRequestedKeyUpdate: true);
        using var cache = CreateCache(server.Port, psk, maximumEarlyDataSize: 4096);
        await using var client = CreateClient(
            cache,
            request,
            Tls13EarlyDataRejectionPolicy.ReturnToCaller);
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(10));

        await client.ConnectAsync(IPAddress.Loopback.ToString(), server.Port, timeout.Token);
        await client.RequestKeyUpdateAsync(requestPeerUpdate: true, timeout.Token);
        await Assert.ThrowsAsync<InvalidOperationException>(async () =>
            await client.RequestKeyUpdateAsync(requestPeerUpdate: true, timeout.Token));
        var response = await client.ReadApplicationDataAsync(timeout.Token);
        await server.Completion.WaitAsync(timeout.Token);

        Assert.Equal(1UL, client.ClientKeyUpdateCount);
        Assert.Equal(1UL, client.ServerKeyUpdateCount);
        Assert.NotNull(response);
        CryptographicOperations.ZeroMemory(psk);
        CryptographicOperations.ZeroMemory(request);
    }

    [Fact]
    public async Task EarlyDataUsesRecordLimitFromTicketProducingHandshake()
    {
        var request = Enumerable.Range(0, 200).Select(value => (byte)value).ToArray();
        var psk = SHA256.HashData("SharpTls bounded 0-RTT test PSK"u8);
        await using var server = new ManagedTls13ResumptionServer(
            TicketIdentity,
            psk,
            request,
            acceptEarlyData: true,
            expectRetransmission: false,
            maximumEarlyRecordPlaintextLength: 64);
        using var cache = CreateCache(
            server.Port,
            psk,
            maximumEarlyDataSize: 4096,
            peerRecordSizeLimit: 64);
        await using var client = CreateClient(
            cache,
            request,
            Tls13EarlyDataRejectionPolicy.ReturnToCaller);
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(10));

        await client.ConnectAsync(IPAddress.Loopback.ToString(), server.Port, timeout.Token);
        _ = await client.ReadApplicationDataAsync(timeout.Token);
        await server.Completion.WaitAsync(timeout.Token);

        Assert.Equal(request, server.ReceivedEarlyData);
        Assert.InRange(server.MaximumReceivedEarlyRecordPlaintextLength, 1, 64);
        CryptographicOperations.ZeroMemory(psk);
        CryptographicOperations.ZeroMemory(request);
    }

    [Fact]
    public async Task ServerCanSelectSecondAuthenticatedPskIdentity()
    {
        var firstIdentity = "first-resumption-ticket"u8.ToArray();
        var secondIdentity = "second-resumption-ticket"u8.ToArray();
        var firstPsk = SHA256.HashData("SharpTls first multi PSK"u8);
        var secondPsk = SHA256.HashData("SharpTls second multi PSK"u8);
        await using var server = new ManagedTls13ResumptionServer(
            firstIdentity,
            firstPsk,
            expectedRequest: "unused"u8,
            acceptEarlyData: false,
            expectRetransmission: false,
            additionalTicketIdentities: [secondIdentity],
            additionalPsks: [secondPsk],
            selectedPskIdentity: 1,
            expectEarlyDataOffer: false);
        using var cache = new Tls13SessionCache();
        var now = cache.UtcNow;
        // Add in reverse order because the cache offers the newest ticket first.
        cache.Add(new Tls13SessionTicket(
            Tls13SessionOrigin.Create("localhost", server.Port),
            TlsCipherSuite.TlsAes128GcmSha256,
            negotiatedAlpn: null,
            ageAdd: 2,
            secondIdentity,
            secondPsk,
            now,
            now.AddHours(1),
            now.AddHours(1),
            maximumEarlyDataSize: null));
        cache.Add(new Tls13SessionTicket(
            Tls13SessionOrigin.Create("localhost", server.Port),
            TlsCipherSuite.TlsAes128GcmSha256,
            negotiatedAlpn: null,
            ageAdd: 1,
            firstIdentity,
            firstPsk,
            now,
            now.AddHours(1),
            now.AddHours(1),
            maximumEarlyDataSize: null));
        await using var client = new CustomTlsClient(new CustomTlsClientOptions
        {
            ServerName = "localhost",
            ClientHello = ClientHelloProfiles.Custom(builder => builder
                .WithTls13()
                .WithCipherSuites(TlsCipherSuite.TlsAes128GcmSha256)
                .WithSupportedGroups(NamedGroup.Secp256r1)
                .WithKeyShares(NamedGroup.Secp256r1)
                .WithSessionResumption()),
            SessionCache = cache,
            MaximumOfferedTls13PskIdentities = 2,
        });
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(10));

        await client.ConnectAsync("127.0.0.1", server.Port, timeout.Token);
        var response = await client.ReadApplicationDataAsync(timeout.Token);
        await server.Completion.WaitAsync(timeout.Token);

        Assert.True(client.SessionWasResumed);
        Assert.Equal(Tls13EarlyDataStatus.NotConfigured, client.EarlyDataStatus);
        Assert.NotNull(response);
        Assert.StartsWith(
            "HTTP/1.1 200 ",
            Encoding.ASCII.GetString(response),
            StringComparison.Ordinal);
        CryptographicOperations.ZeroMemory(firstPsk);
        CryptographicOperations.ZeroMemory(secondPsk);
    }

    [Fact]
    public async Task EarlyDataCapableTicketIsPromotedToPskIdentityZero()
    {
        var earlyIdentity = "early-capable-ticket"u8.ToArray();
        var newerIdentity = "newer-one-rtt-ticket"u8.ToArray();
        var earlyPsk = SHA256.HashData("SharpTls early candidate PSK"u8);
        var newerPsk = SHA256.HashData("SharpTls newer candidate PSK"u8);
        var earlyRequest = "multi-identity early request"u8.ToArray();
        await using var server = new ManagedTls13ResumptionServer(
            earlyIdentity,
            earlyPsk,
            earlyRequest,
            acceptEarlyData: true,
            expectRetransmission: false,
            additionalTicketIdentities: [newerIdentity],
            additionalPsks: [newerPsk],
            selectedPskIdentity: 0,
            expectEarlyDataOffer: true);
        using var cache = new Tls13SessionCache();
        var now = cache.UtcNow;
        cache.Add(new Tls13SessionTicket(
            Tls13SessionOrigin.Create("localhost", server.Port),
            TlsCipherSuite.TlsAes128GcmSha256,
            negotiatedAlpn: null,
            ageAdd: 1,
            earlyIdentity,
            earlyPsk,
            now,
            now.AddHours(1),
            now.AddHours(1),
            maximumEarlyDataSize: 4096));
        cache.Add(new Tls13SessionTicket(
            Tls13SessionOrigin.Create("localhost", server.Port),
            TlsCipherSuite.TlsAes128GcmSha256,
            negotiatedAlpn: null,
            ageAdd: 2,
            newerIdentity,
            newerPsk,
            now,
            now.AddHours(1),
            now.AddHours(1),
            maximumEarlyDataSize: null));
        await using var client = new CustomTlsClient(new CustomTlsClientOptions
        {
            ServerName = "localhost",
            ClientHello = ClientHelloProfiles.Custom(builder => builder
                .WithTls13()
                .WithCipherSuites(TlsCipherSuite.TlsAes128GcmSha256)
                .WithSupportedGroups(NamedGroup.Secp256r1)
                .WithKeyShares(NamedGroup.Secp256r1)
                .WithSessionResumption()),
            SessionCache = cache,
            MaximumOfferedTls13PskIdentities = 2,
            EarlyData = new Tls13EarlyDataOptions(
                earlyRequest,
                acknowledgeReplayRisk: true),
        });
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(10));

        await client.ConnectAsync("127.0.0.1", server.Port, timeout.Token);
        _ = await client.ReadApplicationDataAsync(timeout.Token);
        await server.Completion.WaitAsync(timeout.Token);

        Assert.Equal(Tls13EarlyDataStatus.Accepted, client.EarlyDataStatus);
        Assert.Equal(earlyRequest, server.ReceivedEarlyData);
        CryptographicOperations.ZeroMemory(earlyPsk);
        CryptographicOperations.ZeroMemory(newerPsk);
        CryptographicOperations.ZeroMemory(earlyRequest);
    }

    private static Tls13SessionCache CreateCache(
        int port,
        ReadOnlySpan<byte> psk,
        uint maximumEarlyDataSize,
        int? peerRecordSizeLimit = null)
    {
        var now = DateTimeOffset.UtcNow;
        var cache = new Tls13SessionCache();
        cache.Add(new Tls13SessionTicket(
            Tls13SessionOrigin.Create("localhost", port),
            TlsCipherSuite.TlsAes128GcmSha256,
            negotiatedAlpn: null,
            ageAdd: 0xA1B2C3D4,
            TicketIdentity,
            psk,
            issuedAt: now,
            expiresAt: now.AddHours(1),
            authenticationExpiresAt: now.AddHours(1),
            maximumEarlyDataSize,
            peerRecordSizeLimit));
        return cache;
    }

    private static CustomTlsClient CreateClient(
        Tls13SessionCache cache,
        ReadOnlySpan<byte> request,
        Tls13EarlyDataRejectionPolicy rejectionPolicy) => new(new CustomTlsClientOptions
        {
            ServerName = "localhost",
            ClientHello = ClientHelloProfiles.Custom(builder => builder
                .WithCipherSuites(TlsCipherSuite.TlsAes128GcmSha256)
                .WithSupportedGroups(NamedGroup.Secp256r1)
                .WithSessionResumption()),
            SessionCache = cache,
            EarlyData = new Tls13EarlyDataOptions(
                request,
                acknowledgeReplayRisk: true,
                rejectionPolicy),
        });
}
