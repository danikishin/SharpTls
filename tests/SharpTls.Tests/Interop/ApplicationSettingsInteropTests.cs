using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using SharpTls.Certificates;
using SharpTls.Protocol;
using SharpTls.Tests.Certificates;

namespace SharpTls.Tests.Interop;

public sealed class ApplicationSettingsInteropTests
{
    private static readonly byte[] TicketIdentity =
        "alps-bound-resumption-ticket"u8.ToArray();

    [Theory]
    [InlineData(TlsApplicationSettingsCodePoint.LegacyDraft)]
    [InlineData(TlsApplicationSettingsCodePoint.ChromeExperiment)]
    public async Task ExperimentalApplicationSettingsCompleteAuthenticatedRoundTrip(
        TlsApplicationSettingsCodePoint codePoint)
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
        var serverSettings = new byte[] { 0x53, 0x01, 0x02 };
        var clientSettings = new byte[] { 0x43, 0x03, 0x04 };
        using var keyLogOutput = new MemoryStream();
        using var keyLog = new TlsNssKeyLogSink(
            keyLogOutput,
            acknowledgeSecretExposure: true);
        var handshakeEvents = new List<TlsHandshakeEvent>();
        await using var server = new ManagedTls13MutualAuthServer(
            serverPki.Leaf,
            serverPki.Root,
            (RSA)serverPki.LeafKey,
            clientPki.Leaf.RawData,
            applicationSettingsCodePoint: codePoint,
            serverApplicationSettings: serverSettings,
            expectedClientApplicationSettings: clientSettings);
        var profile = ClientHelloProfiles.Custom(builder => builder
            .WithAlpn("h2", "http/1.1")
            .WithApplicationSettings(codePoint, "h2"));
        await using var client = new CustomTlsClient(new CustomTlsClientOptions
        {
            ServerName = "localhost",
            ClientHello = profile,
            ClientCertificate = clientCredential,
            DangerousNssKeyLog = keyLog,
            HandshakeEventObserver = handshakeEvents.Add,
            ClientApplicationSettings = new Dictionary<string, byte[]>
            {
                ["h2"] = clientSettings,
            },
            CertificateValidation = new CustomTlsCertificateValidationOptions
            {
                RevocationMode = X509RevocationMode.NoCheck,
                CustomTrustRoots = [serverPki.Root],
            },
        });

        Assert.Throws<InvalidOperationException>(() => client.GetConnectionState());

        await client.ConnectAsync("127.0.0.1", server.Port, timeout.Token);
        clientSettings[0] ^= 0xFF;
        serverSettings[0] ^= 0xFF;
        await client.WriteApplicationDataAsync("ping"u8.ToArray(), timeout.Token);
        var response = await client.ReadApplicationDataAsync(timeout.Token);
        await server.Completion;

        Assert.Equal("pong"u8.ToArray(), response);
        Assert.Equal("h2", client.NegotiatedApplicationProtocol);
        Assert.Equal(codePoint, client.NegotiatedApplicationSettingsCodePoint);
        Assert.Equal(new byte[] { 0x53, 0x01, 0x02 }, client.NegotiatedPeerApplicationSettings);
        var state = client.GetConnectionState();
        Assert.Equal("localhost", state.AuthenticatedServerName);
        Assert.Equal(TlsProtocolVersion.Tls13, state.ProtocolVersion);
        Assert.Equal("h2", state.ApplicationProtocol);
        Assert.Equal(codePoint, state.ApplicationSettingsCodePoint);
        Assert.Equal(new byte[] { 0x53, 0x01, 0x02 }, state.PeerApplicationSettings);
        Assert.NotEmpty(state.PeerCertificateChain);
        Assert.Null(state.StapledOcspResponse);
        Assert.Empty(state.SignedCertificateTimestamps);
        Assert.False(state.EncryptedClientHelloOffered);
        Assert.False(state.GreaseEncryptedClientHelloOffered);

        var settingsCopy = state.PeerApplicationSettings!;
        var certificateCopy = state.PeerCertificateChain[0];
        settingsCopy[0] ^= 0xFF;
        certificateCopy[0] ^= 0xFF;
        Assert.Equal(new byte[] { 0x53, 0x01, 0x02 }, state.PeerApplicationSettings);
        Assert.NotEqual(certificateCopy, state.PeerCertificateChain[0]);
        var keyLogLines = System.Text.Encoding.ASCII.GetString(keyLogOutput.ToArray())
            .Split('\n', StringSplitOptions.RemoveEmptyEntries);
        Assert.Equal(
            new[]
            {
                "CLIENT_HANDSHAKE_TRAFFIC_SECRET",
                "SERVER_HANDSHAKE_TRAFFIC_SECRET",
                "CLIENT_TRAFFIC_SECRET_0",
                "SERVER_TRAFFIC_SECRET_0",
                "EXPORTER_SECRET",
            },
            keyLogLines.Select(line => line.Split(' ')[0]));
        Assert.Single(keyLogLines.Select(line => line.Split(' ')[1]).Distinct());
        Assert.All(keyLogLines, line => Assert.Equal(3, line.Split(' ').Length));
        Assert.Equal(
            new[]
            {
                TlsHandshakeEventKind.ClientHello,
                TlsHandshakeEventKind.ServerHello,
                TlsHandshakeEventKind.EncryptedExtensions,
                TlsHandshakeEventKind.CertificateRequest,
                TlsHandshakeEventKind.Certificate,
                TlsHandshakeEventKind.CertificateVerify,
                TlsHandshakeEventKind.Finished,
                TlsHandshakeEventKind.Finished,
                TlsHandshakeEventKind.HandshakeCompleted,
            },
            handshakeEvents.Select(value => value.Kind));
        Assert.Equal(
            Enumerable.Range(1, handshakeEvents.Count).Select(value => (long)value),
            handshakeEvents.Select(value => value.SequenceNumber));
        Assert.All(handshakeEvents.Take(handshakeEvents.Count - 1), value =>
            Assert.True(value.EncodedLength > 0));
        Assert.Equal(0, handshakeEvents[^1].EncodedLength);
        Assert.Equal(TlsProtocolVersion.Tls13, handshakeEvents[^1].ProtocolVersion);
        Assert.True(server.ClientApplicationSettingsVerified);
        Assert.True(server.ClientCertificateVerified);
    }

    [Fact]
    public async Task TicketBoundApplicationSettingsPermitAuthenticatedEarlyData()
    {
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        using var serverPki = TestPki.Create("localhost");
        var psk = SHA256.HashData("SharpTls ALPS early data PSK"u8);
        var earlyData = "early ALPS request"u8.ToArray();
        var serverSettings = new byte[] { 0x53, 0x01 };
        var clientSettings = new byte[] { 0x43, 0x02 };
        await using var server = new ManagedTls13MutualAuthServer(
            serverPki.Leaf,
            serverPki.Root,
            (RSA)serverPki.LeafKey,
            expectedClientLeaf: [],
            applicationSettingsCodePoint: TlsApplicationSettingsCodePoint.LegacyDraft,
            serverApplicationSettings: serverSettings,
            expectedClientApplicationSettings: clientSettings,
            resumptionTicketIdentity: TicketIdentity,
            resumptionPsk: psk,
            expectedEarlyData: earlyData);
        using var cache = CreateApplicationSettingsTicketCache(
            server.Port,
            psk,
            serverSettings,
            clientSettings);
        await using var client = CreateResumptionClient(cache, earlyData, clientSettings);

        await client.ConnectAsync("127.0.0.1", server.Port, timeout.Token);
        await client.WriteApplicationDataAsync("ping"u8.ToArray(), timeout.Token);
        var response = await client.ReadApplicationDataAsync(timeout.Token);
        await server.Completion.WaitAsync(timeout.Token);

        Assert.True(client.SessionWasResumed);
        Assert.Equal(Tls13EarlyDataStatus.Accepted, client.EarlyDataStatus);
        Assert.Equal("h2", client.NegotiatedApplicationProtocol);
        Assert.Equal(serverSettings, client.NegotiatedPeerApplicationSettings);
        Assert.Equal(earlyData, server.ReceivedEarlyData);
        Assert.True(server.ClientApplicationSettingsVerified);
        Assert.Equal("pong"u8.ToArray(), response);
        CryptographicOperations.ZeroMemory(psk);
        CryptographicOperations.ZeroMemory(earlyData);
    }

    [Fact]
    public async Task ResumptionRejectsChangedTicketBoundPeerApplicationSettings()
    {
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        using var serverPki = TestPki.Create("localhost");
        var psk = SHA256.HashData("SharpTls changed ALPS settings PSK"u8);
        var earlyData = "early settings-bound request"u8.ToArray();
        var ticketServerSettings = new byte[] { 0x53, 0x01 };
        var changedServerSettings = new byte[] { 0x53, 0xFF };
        var clientSettings = new byte[] { 0x43, 0x02 };
        await using var server = new ManagedTls13MutualAuthServer(
            serverPki.Leaf,
            serverPki.Root,
            (RSA)serverPki.LeafKey,
            expectedClientLeaf: [],
            applicationSettingsCodePoint: TlsApplicationSettingsCodePoint.LegacyDraft,
            serverApplicationSettings: changedServerSettings,
            expectedClientApplicationSettings: clientSettings,
            expectApplicationSettingsRejection: true,
            resumptionTicketIdentity: TicketIdentity,
            resumptionPsk: psk,
            expectedEarlyData: earlyData);
        using var cache = CreateApplicationSettingsTicketCache(
            server.Port,
            psk,
            ticketServerSettings,
            clientSettings);
        await using var client = CreateResumptionClient(cache, earlyData, clientSettings);

        var exception = await Assert.ThrowsAsync<TlsProtocolException>(async () =>
            await client.ConnectAsync("127.0.0.1", server.Port, timeout.Token));
        await server.Completion.WaitAsync(timeout.Token);

        Assert.Equal(TlsAlertDescription.IllegalParameter, exception.Alert);
        Assert.True(server.ApplicationSettingsRejectionObserved);
        CryptographicOperations.ZeroMemory(psk);
        CryptographicOperations.ZeroMemory(earlyData);
    }

    [Fact]
    public async Task NewSessionTicketPersistsAuthenticatedApplicationSettingsBindings()
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
        var serverSettings = new byte[] { 0x53, 0x11 };
        var clientSettings = new byte[] { 0x43, 0x22 };
        var issuedIdentity = "issued-alps-ticket"u8.ToArray();
        await using var server = new ManagedTls13MutualAuthServer(
            serverPki.Leaf,
            serverPki.Root,
            (RSA)serverPki.LeafKey,
            clientPki.Leaf.RawData,
            applicationSettingsCodePoint: TlsApplicationSettingsCodePoint.LegacyDraft,
            serverApplicationSettings: serverSettings,
            expectedClientApplicationSettings: clientSettings,
            newSessionTicketIdentity: issuedIdentity,
            newSessionTicketMaximumEarlyDataSize: 4096);
        var serverPort = server.Port;
        using var cache = new Tls13SessionCache();
        await using var client = new CustomTlsClient(new CustomTlsClientOptions
        {
            ServerName = "localhost",
            ClientHello = ClientHelloProfiles.Custom(builder => builder
                .WithTls13()
                .WithCipherSuites(TlsCipherSuite.TlsAes128GcmSha256)
                .WithSupportedGroups(NamedGroup.Secp256r1)
                .WithKeyShares(NamedGroup.Secp256r1)
                .WithAlpn("h2")
                .WithApplicationSettings(
                    TlsApplicationSettingsCodePoint.LegacyDraft,
                    "h2")
                .WithSessionResumption()),
            SessionCache = cache,
            ClientCertificate = clientCredential,
            ClientApplicationSettings = new Dictionary<string, byte[]>
            {
                ["h2"] = clientSettings,
            },
            CertificateValidation = new CustomTlsCertificateValidationOptions
            {
                RevocationMode = X509RevocationMode.NoCheck,
                CustomTrustRoots = [serverPki.Root],
            },
        });

        await client.ConnectAsync("127.0.0.1", serverPort, timeout.Token);
        await client.WriteApplicationDataAsync("ping"u8.ToArray(), timeout.Token);
        Assert.Equal(
            "pong"u8.ToArray(),
            await client.ReadApplicationDataAsync(timeout.Token));
        await server.Completion.WaitAsync(timeout.Token);

        using var ticket = cache.TryTake(
            Tls13SessionOrigin.Create("localhost", serverPort),
            [TlsCipherSuite.TlsAes128GcmSha256],
            ["h2"],
            applicationSettingsCodePoint: TlsApplicationSettingsCodePoint.LegacyDraft,
            clientApplicationSettings: new Dictionary<string, byte[]>
            {
                ["h2"] = clientSettings,
            });
        Assert.NotNull(ticket);
        Assert.Equal(issuedIdentity, ticket.Identity);
        Assert.Equal(4096u, ticket.MaximumEarlyDataSize);
        Assert.Equal(serverSettings, ticket.PeerApplicationSettings);
        Assert.Equal(clientSettings, ticket.ClientApplicationSettings);
    }

    private static Tls13SessionCache CreateApplicationSettingsTicketCache(
        int port,
        ReadOnlySpan<byte> psk,
        byte[] serverSettings,
        byte[] clientSettings)
    {
        var cache = new Tls13SessionCache();
        var now = cache.UtcNow;
        cache.Add(new Tls13SessionTicket(
            Tls13SessionOrigin.Create("localhost", port),
            TlsCipherSuite.TlsAes128GcmSha256,
            "h2",
            ageAdd: 0x12345678,
            TicketIdentity,
            psk,
            now,
            now.AddHours(1),
            now.AddHours(1),
            maximumEarlyDataSize: 4096,
            applicationSettingsCodePoint: TlsApplicationSettingsCodePoint.LegacyDraft,
            peerApplicationSettings: serverSettings,
            clientApplicationSettings: clientSettings));
        return cache;
    }

    private static CustomTlsClient CreateResumptionClient(
        Tls13SessionCache cache,
        ReadOnlySpan<byte> earlyData,
        byte[] clientSettings) => new(new CustomTlsClientOptions
        {
            ServerName = "localhost",
            ClientHello = ClientHelloProfiles.Custom(builder => builder
                .WithTls13()
                .WithCipherSuites(TlsCipherSuite.TlsAes128GcmSha256)
                .WithSupportedGroups(NamedGroup.Secp256r1)
                .WithKeyShares(NamedGroup.Secp256r1)
                .WithAlpn("h2")
                .WithApplicationSettings(
                    TlsApplicationSettingsCodePoint.LegacyDraft,
                    "h2")
                .WithSessionResumption()),
            SessionCache = cache,
            EarlyData = new Tls13EarlyDataOptions(
                earlyData,
                acknowledgeReplayRisk: true),
            ClientApplicationSettings = new Dictionary<string, byte[]>
            {
                ["h2"] = clientSettings,
            },
        });
}
