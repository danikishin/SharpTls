using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using SharpTls.Certificates;
using SharpTls.Cryptography;
using SharpTls.IO;
using SharpTls.Protocol;
using SharpTls.Tests.Certificates;

namespace SharpTls.Tests.Interop;

public sealed class EchInteropTests
{
    private static readonly byte[] EchPrivateKey = Convert.FromHexString(
        "4612c550263fc8ad58375df3f557aac531d26850903e55a9f23f21d8534e8ac8");

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task StandardServerAcceptsEchAndUsesInnerHandshake(
        bool forceHelloRetryRequest)
    {
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        using var pki = TestPki.Create("private.example");
        using var credential = new TlsServerCertificate(
            pki.Leaf,
            (RSA)pki.LeafKey,
            [pki.Root]);
        var configList = TlsEchConfigList.Parse(CreateEchConfigList());
        using var echKey = new TlsEchServerKey(
            Assert.Single(configList.Configurations),
            EchPrivateKey,
            sendAsRetry: true);
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        await using var server = new CustomTlsServer(new CustomTlsServerOptions
        {
            ServerCertificate = credential,
            SupportedVersions = [TlsProtocolVersion.Tls13],
            CipherSuites = [TlsCipherSuite.TlsAes128GcmSha256],
            SupportedGroups = forceHelloRetryRequest
                ? [NamedGroup.Secp384r1]
                : [NamedGroup.Secp256r1],
            EncryptedClientHelloKeys = [echKey],
        });
        var serverTask = Task.Run(async () =>
        {
            using var socket = await listener.AcceptSocketAsync(timeout.Token);
            listener.Stop();
            await server.AuthenticateAsync(socket, ownsSocket: true, timeout.Token);
            Assert.Equal("ech-ping"u8.ToArray(),
                await server.ReadApplicationDataAsync(timeout.Token));
            await server.WriteApplicationDataAsync("ech-pong"u8.ToArray(), timeout.Token);
        }, timeout.Token);
        var retryProfile = CreateHelloRetryRequestProfile();
        await using var client = new CustomTlsClient(new CustomTlsClientOptions
        {
            ServerName = "private.example",
            ClientHello = forceHelloRetryRequest
                ? retryProfile
                : ClientHelloProfiles.Custom(builder => builder
                    .WithTls13()
                    .WithCipherSuites(TlsCipherSuite.TlsAes128GcmSha256)
                    .WithSupportedGroups(NamedGroup.Secp256r1)
                    .WithKeyShares(NamedGroup.Secp256r1)),
            EncryptedClientHello = new TlsEchOptions
            {
                ConfigList = configList,
                OuterClientHello = forceHelloRetryRequest
                    ? retryProfile
                    : ClientHelloProfiles.Custom(builder => builder
                        .WithTls13()
                        .WithCipherSuites(TlsCipherSuite.TlsAes128GcmSha256)
                        .WithSupportedGroups(NamedGroup.Secp256r1)
                        .WithKeyShares(NamedGroup.Secp256r1)),
            },
            CertificateValidation = new CustomTlsCertificateValidationOptions
            {
                RevocationMode = X509RevocationMode.NoCheck,
                CustomTrustRoots = [pki.Root],
            },
        });

        await client.ConnectAsync(IPAddress.Loopback.ToString(), port, timeout.Token);
        await client.WriteApplicationDataAsync("ech-ping"u8.ToArray(), timeout.Token);
        Assert.Equal("ech-pong"u8.ToArray(),
            await client.ReadApplicationDataAsync(timeout.Token));
        await serverTask.WaitAsync(timeout.Token);

        Assert.True(client.EncryptedClientHelloAccepted);
        Assert.Equal(forceHelloRetryRequest, client.HandshakeUsedHelloRetryRequest);
        Assert.True(server.EncryptedClientHelloOffered);
        Assert.True(server.EncryptedClientHelloAccepted);
        Assert.Equal("public.example", server.EncryptedClientHelloOuterServerName);
        Assert.Equal("private.example", server.ServerName);
        Assert.Equal(forceHelloRetryRequest, server.NegotiatedGroup == NamedGroup.Secp384r1);
    }

    [Fact]
    public async Task StandardServerRejectsUnknownEchAndAuthenticatesRetryConfigurations()
    {
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        using var pki = TestPki.Create("public.example");
        using var credential = new TlsServerCertificate(
            pki.Leaf,
            (RSA)pki.LeafKey,
            [pki.Root]);
        var serverConfigBytes = CreateEchConfigList();
        var serverConfigList = TlsEchConfigList.Parse(serverConfigBytes);
        using var echKey = new TlsEchServerKey(
            Assert.Single(serverConfigList.Configurations),
            EchPrivateKey,
            sendAsRetry: true);
        var otherPrivateKey = Enumerable.Repeat((byte)0x31, X25519.KeyLength).ToArray();
        var otherPublicKey = new byte[X25519.KeyLength];
        X25519.DerivePublicKey(otherPrivateKey, otherPublicKey);
        var clientConfigList = TlsEchConfigList.Parse(
            CreateEchConfigList(configId: 9, publicKey: otherPublicKey));
        CryptographicOperations.ZeroMemory(otherPrivateKey);
        CryptographicOperations.ZeroMemory(otherPublicKey);

        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        await using var server = new CustomTlsServer(new CustomTlsServerOptions
        {
            ServerCertificate = credential,
            SupportedVersions = [TlsProtocolVersion.Tls13],
            CipherSuites = [TlsCipherSuite.TlsAes128GcmSha256],
            SupportedGroups = [NamedGroup.Secp256r1],
            EncryptedClientHelloKeys = [echKey],
        });
        var serverTask = Task.Run(async () =>
        {
            using var socket = await listener.AcceptSocketAsync(timeout.Token);
            listener.Stop();
            await server.AuthenticateAsync(socket, ownsSocket: true, timeout.Token);
            return await Record.ExceptionAsync(() =>
                server.ReadApplicationDataAsync(timeout.Token).AsTask());
        }, timeout.Token);
        await using var client = new CustomTlsClient(new CustomTlsClientOptions
        {
            ServerName = "private.example",
            EncryptedClientHello = new TlsEchOptions { ConfigList = clientConfigList },
            CertificateValidation = new CustomTlsCertificateValidationOptions
            {
                RevocationMode = X509RevocationMode.NoCheck,
                CustomTrustRoots = [pki.Root],
            },
        });

        var rejection = await Assert.ThrowsAsync<TlsEchRejectedException>(() =>
            client.ConnectAsync(IPAddress.Loopback.ToString(), port, timeout.Token).AsTask());
        var serverFailure = await serverTask.WaitAsync(timeout.Token);

        Assert.IsType<TlsProtocolException>(serverFailure);
        Assert.Equal("public.example", rejection.PublicName);
        Assert.Equal(
            serverConfigBytes,
            rejection.RetryConfigurations!.GetEncodedList());
        Assert.True(server.EncryptedClientHelloOffered);
        Assert.False(server.EncryptedClientHelloAccepted);
        Assert.Equal("public.example", server.ServerName);
        Assert.False(server.IsAuthenticated);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task StandardServerTreatsGreaseEchAsPublicHandshake(
        bool forceHelloRetryRequest)
    {
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        using var pki = TestPki.Create("public.example");
        using var credential = new TlsServerCertificate(
            pki.Leaf,
            (RSA)pki.LeafKey,
            [pki.Root]);
        var serverConfigList = TlsEchConfigList.Parse(CreateEchConfigList());
        var inspectedClientHellos = new List<TlsClientHelloInspection>();
        using var echKey = new TlsEchServerKey(
            Assert.Single(serverConfigList.Configurations),
            EchPrivateKey,
            sendAsRetry: true);
        var profile = forceHelloRetryRequest
            ? CreateHelloRetryRequestProfile()
            : ClientHelloProfiles.Custom(builder => builder
                .WithTls13()
                .WithCipherSuites(TlsCipherSuite.TlsAes128GcmSha256)
                .WithSupportedGroups(NamedGroup.Secp256r1)
                .WithKeyShares(NamedGroup.Secp256r1));
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        await using var server = new CustomTlsServer(new CustomTlsServerOptions
        {
            ServerCertificate = credential,
            SupportedVersions = [TlsProtocolVersion.Tls13],
            CipherSuites = [TlsCipherSuite.TlsAes128GcmSha256],
            SupportedGroups = forceHelloRetryRequest
                ? [NamedGroup.Secp384r1]
                : [NamedGroup.Secp256r1],
            EncryptedClientHelloKeys = [echKey],
        });
        var serverTask = Task.Run(async () =>
        {
            using var socket = await listener.AcceptSocketAsync(timeout.Token);
            listener.Stop();
            await server.AuthenticateAsync(socket, ownsSocket: true, timeout.Token);
            Assert.Equal("grease-ping"u8.ToArray(),
                await server.ReadApplicationDataAsync(timeout.Token));
            await server.WriteApplicationDataAsync(
                "grease-pong"u8.ToArray(),
                timeout.Token);
        }, timeout.Token);
        await using var client = new CustomTlsClient(new CustomTlsClientOptions
        {
            ServerName = "public.example",
            ClientHello = profile,
            EncryptedClientHelloGrease = new TlsEchGreaseOptions(),
            ClientHelloInspector = inspectedClientHellos.Add,
            CertificateValidation = new CustomTlsCertificateValidationOptions
            {
                RevocationMode = X509RevocationMode.NoCheck,
                CustomTrustRoots = [pki.Root],
            },
        });

        await client.ConnectAsync(IPAddress.Loopback.ToString(), port, timeout.Token);
        await client.WriteApplicationDataAsync("grease-ping"u8.ToArray(), timeout.Token);
        Assert.Equal("grease-pong"u8.ToArray(),
            await client.ReadApplicationDataAsync(timeout.Token));
        await serverTask.WaitAsync(timeout.Token);

        Assert.False(client.EncryptedClientHelloAccepted);
        Assert.Equal(forceHelloRetryRequest, client.HandshakeUsedHelloRetryRequest);
        Assert.True(server.EncryptedClientHelloOffered);
        Assert.False(server.EncryptedClientHelloAccepted);
        Assert.Equal("public.example", server.ServerName);
        Assert.True(server.IsAuthenticated);
        Assert.Equal(forceHelloRetryRequest ? 2 : 1, inspectedClientHellos.Count);
        Assert.All(inspectedClientHellos, inspection =>
        {
            Assert.Equal(
                TlsClientHelloWireForm.GreaseEncryptedClientHello,
                inspection.WireForm);
            Assert.Equal((byte)HandshakeType.ClientHello, inspection.GetEncodedHandshake()[0]);
        });
        Assert.Equal(TlsClientHelloFlight.Initial, inspectedClientHellos[0].Flight);
        if (forceHelloRetryRequest)
        {
            Assert.Equal(
                TlsClientHelloFlight.AfterHelloRetryRequest,
                inspectedClientHellos[1].Flight);
        }
    }

    [Fact]
    public async Task AcceptedEchUsesInnerTranscriptKeyShareAndPrivateCertificate()
    {
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        using var serverPki = TestPki.Create("private.example");
        using var clientPki = TestPki.Create(
            dnsName: "client.example",
            serverAuthenticationEku: false);
        using var clientLeafWithKey = clientPki.Leaf.CopyWithPrivateKey(
            (RSA)clientPki.LeafKey);
        using var clientCredential = new TlsClientCertificate(
            clientLeafWithKey,
            [clientPki.Root]);
        var configList = TlsEchConfigList.Parse(CreateEchConfigList());
        await using var server = new ManagedTls13MutualAuthServer(
            serverPki.Leaf,
            serverPki.Root,
            (RSA)serverPki.LeafKey,
            clientPki.Leaf.RawData,
            echConfiguration: Assert.Single(configList.Configurations),
            echPrivateKey: EchPrivateKey);
        await using var client = new CustomTlsClient(new CustomTlsClientOptions
        {
            ServerName = "private.example",
            EncryptedClientHello = new TlsEchOptions
            {
                ConfigList = configList,
                CompressedOuterExtensions =
                [
                    TlsExtensionType.SupportedGroups,
                    TlsExtensionType.SignatureAlgorithms,
                ],
            },
            ClientCertificate = clientCredential,
            CertificateValidation = new CustomTlsCertificateValidationOptions
            {
                RevocationMode = X509RevocationMode.NoCheck,
                CustomTrustRoots = [serverPki.Root],
            },
        });

        await client.ConnectAsync("127.0.0.1", server.Port, timeout.Token);
        await client.WriteApplicationDataAsync("ping"u8.ToArray(), timeout.Token);
        var response = await client.ReadApplicationDataAsync(timeout.Token);
        await server.Completion;

        Assert.True(client.EncryptedClientHelloAccepted);
        Assert.True(client.IsConnected);
        Assert.Equal("pong"u8.ToArray(), response);
        Assert.True(server.EchAccepted);
        Assert.Equal("public.example", server.EchOuterServerName);
        Assert.Equal("private.example", server.EchInnerServerName);
        Assert.True(server.ClientCertificateVerified);
    }

    [Fact]
    public async Task RejectedEchAuthenticatesPublicNameAndNeverExposesApplicationData()
    {
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        using var serverPki = TestPki.Create("public.example");
        using var clientPki = TestPki.Create(
            dnsName: "client.example",
            serverAuthenticationEku: false);
        using var clientLeafWithKey = clientPki.Leaf.CopyWithPrivateKey(
            (RSA)clientPki.LeafKey);
        using var clientCredential = new TlsClientCertificate(
            clientLeafWithKey,
            [clientPki.Root]);
        var encodedConfigList = CreateEchConfigList();
        var configList = TlsEchConfigList.Parse(encodedConfigList);
        await using var server = new ManagedTls13MutualAuthServer(
            serverPki.Leaf,
            serverPki.Root,
            (RSA)serverPki.LeafKey,
            clientPki.Leaf.RawData,
            expectEmptyInitialCertificate: true,
            expectEchRequiredAlert: true,
            echRetryConfigurations: encodedConfigList);
        await using var client = new CustomTlsClient(new CustomTlsClientOptions
        {
            ServerName = "private.example",
            EncryptedClientHello = new TlsEchOptions { ConfigList = configList },
            ClientCertificate = clientCredential,
            CertificateValidation = new CustomTlsCertificateValidationOptions
            {
                RevocationMode = X509RevocationMode.NoCheck,
                CustomTrustRoots = [serverPki.Root],
            },
        });

        var exception = await Assert.ThrowsAsync<TlsEchRejectedException>(() =>
            client.ConnectAsync("127.0.0.1", server.Port, timeout.Token).AsTask());
        await server.Completion;

        Assert.Equal("public.example", exception.PublicName);
        Assert.NotNull(exception.RetryConfigurations);
        Assert.Equal(encodedConfigList, exception.RetryConfigurations.GetEncodedList());
        Assert.False(client.IsConnected);
        Assert.False(client.EncryptedClientHelloAccepted);
        Assert.Null(client.NegotiatedProtocolVersion);
        Assert.Null(client.NegotiatedApplicationProtocol);
        Assert.True(server.EchRequiredAlertReceived);
        Assert.False(server.ClientCertificateVerified);
        Assert.Equal("public.example", server.EchOuterServerName);
    }

    [Fact]
    public async Task AcceptedEchHelloRetryRequestReusesHpkeContextAndInnerTranscript()
    {
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        using var serverPki = TestPki.Create("private.example");
        using var clientPki = TestPki.Create(
            dnsName: "client.example",
            serverAuthenticationEku: false);
        using var clientLeafWithKey = clientPki.Leaf.CopyWithPrivateKey(
            (RSA)clientPki.LeafKey);
        using var clientCredential = new TlsClientCertificate(
            clientLeafWithKey,
            [clientPki.Root]);
        var configList = TlsEchConfigList.Parse(CreateEchConfigList());
        var innerProfile = CreateHelloRetryRequestProfile();
        var outerProfile = CreateHelloRetryRequestProfile();
        var inspectedClientHellos = new List<TlsClientHelloInspection>();
        await using var server = new ManagedTls13MutualAuthServer(
            serverPki.Leaf,
            serverPki.Root,
            (RSA)serverPki.LeafKey,
            clientPki.Leaf.RawData,
            echConfiguration: Assert.Single(configList.Configurations),
            echPrivateKey: EchPrivateKey,
            useEchHelloRetryRequest: true);
        await using var client = new CustomTlsClient(new CustomTlsClientOptions
        {
            ServerName = "private.example",
            ClientHello = innerProfile,
            EncryptedClientHello = new TlsEchOptions
            {
                ConfigList = configList,
                OuterClientHello = outerProfile,
                CompressedOuterExtensions =
                [
                    TlsExtensionType.SupportedGroups,
                    TlsExtensionType.SignatureAlgorithms,
                    TlsExtensionType.SupportedVersions,
                ],
            },
            ClientCertificate = clientCredential,
            ClientHelloInspector = inspectedClientHellos.Add,
            CertificateValidation = new CustomTlsCertificateValidationOptions
            {
                RevocationMode = X509RevocationMode.NoCheck,
                CustomTrustRoots = [serverPki.Root],
            },
        });

        await client.ConnectAsync("127.0.0.1", server.Port, timeout.Token);
        await client.WriteApplicationDataAsync("ping"u8.ToArray(), timeout.Token);
        var response = await client.ReadApplicationDataAsync(timeout.Token);
        await server.Completion;

        Assert.True(client.IsConnected);
        Assert.True(client.EncryptedClientHelloAccepted);
        Assert.True(client.HandshakeUsedHelloRetryRequest);
        Assert.Equal(NamedGroup.Secp384r1, client.NegotiatedGroup);
        Assert.Equal("pong"u8.ToArray(), response);
        Assert.True(server.EchAccepted);
        Assert.True(server.EchHelloRetryRequestCompleted);
        Assert.Equal("public.example", server.EchOuterServerName);
        Assert.Equal("private.example", server.EchInnerServerName);
        Assert.True(server.ClientCertificateVerified);
        Assert.Collection(
            inspectedClientHellos,
            first =>
            {
                Assert.Equal(TlsClientHelloFlight.Initial, first.Flight);
                Assert.Equal(TlsClientHelloWireForm.EncryptedClientHelloOuter, first.WireForm);
                Assert.Equal((byte)HandshakeType.ClientHello, first.GetEncodedHandshake()[0]);
            },
            second =>
            {
                Assert.Equal(TlsClientHelloFlight.AfterHelloRetryRequest, second.Flight);
                Assert.Equal(TlsClientHelloWireForm.EncryptedClientHelloOuter, second.WireForm);
                Assert.Equal((byte)HandshakeType.ClientHello, second.GetEncodedHandshake()[0]);
            });
    }

    [Fact]
    public async Task AcceptedEchResumptionAuthenticatesInnerPskAndGreasesOuterIdentity()
    {
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        using var serverPki = TestPki.Create("private.example");
        var encodedConfigList = CreateEchConfigList();
        var configList = TlsEchConfigList.Parse(encodedConfigList);
        var ticketIdentity = "private-resumption-ticket"u8.ToArray();
        var psk = Enumerable.Repeat((byte)0x5A, 32).ToArray();
        await using var server = new ManagedTls13MutualAuthServer(
            serverPki.Leaf,
            serverPki.Root,
            (RSA)serverPki.LeafKey,
            expectedClientLeaf: [],
            echConfiguration: Assert.Single(configList.Configurations),
            echPrivateKey: EchPrivateKey,
            resumptionTicketIdentity: ticketIdentity,
            resumptionPsk: psk);
        using var cache = new Tls13SessionCache();
        var issuedAt = cache.UtcNow;
        cache.Add(new Tls13SessionTicket(
            Tls13SessionOrigin.Create("private.example", server.Port),
            TlsCipherSuite.TlsAes128GcmSha256,
            negotiatedAlpn: null,
            ageAdd: 0x12345678,
            ticketIdentity,
            psk,
            issuedAt,
            issuedAt.AddHours(1),
            issuedAt.AddHours(1),
            maximumEarlyDataSize: null,
            echConfigListHash: SHA256.HashData(encodedConfigList)));
        var resumableProfile = ClientHelloProfiles.Custom(builder => builder
            .WithTls13()
            .WithCipherSuites(TlsCipherSuite.TlsAes128GcmSha256)
            .WithSupportedGroups(NamedGroup.Secp256r1)
            .WithKeyShares(NamedGroup.Secp256r1)
            .WithSessionResumption());
        await using var client = new CustomTlsClient(new CustomTlsClientOptions
        {
            ServerName = "private.example",
            ClientHello = resumableProfile,
            SessionCache = cache,
            EncryptedClientHello = new TlsEchOptions
            {
                ConfigList = configList,
                OuterClientHello = resumableProfile,
            },
        });

        await client.ConnectAsync("127.0.0.1", server.Port, timeout.Token);
        await client.WriteApplicationDataAsync("ping"u8.ToArray(), timeout.Token);
        var response = await client.ReadApplicationDataAsync(timeout.Token);
        await server.Completion;

        Assert.True(client.IsConnected);
        Assert.True(client.EncryptedClientHelloAccepted);
        Assert.True(client.SessionWasResumed);
        Assert.Equal("pong"u8.ToArray(), response);
        Assert.True(server.EchInnerPskVerified);
        Assert.True(server.EchOuterPskWasGreased);
    }

    [Fact]
    public async Task AcceptedEchEarlyDataUsesInnerTranscriptAndSignalsOuterEarlyData()
    {
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        using var serverPki = TestPki.Create("private.example");
        var encodedConfigList = CreateEchConfigList();
        var configList = TlsEchConfigList.Parse(encodedConfigList);
        var ticketIdentity = "private-early-ticket"u8.ToArray();
        var psk = Enumerable.Repeat((byte)0xC3, 32).ToArray();
        var earlyRequest = "early-private-request"u8.ToArray();
        await using var server = new ManagedTls13MutualAuthServer(
            serverPki.Leaf,
            serverPki.Root,
            (RSA)serverPki.LeafKey,
            expectedClientLeaf: [],
            echConfiguration: Assert.Single(configList.Configurations),
            echPrivateKey: EchPrivateKey,
            resumptionTicketIdentity: ticketIdentity,
            resumptionPsk: psk,
            expectedEarlyData: earlyRequest);
        using var cache = new Tls13SessionCache();
        var issuedAt = cache.UtcNow;
        cache.Add(new Tls13SessionTicket(
            Tls13SessionOrigin.Create("private.example", server.Port),
            TlsCipherSuite.TlsAes128GcmSha256,
            negotiatedAlpn: null,
            ageAdd: 0x90ABCDEF,
            ticketIdentity,
            psk,
            issuedAt,
            issuedAt.AddHours(1),
            issuedAt.AddHours(1),
            maximumEarlyDataSize: 4096,
            echConfigListHash: SHA256.HashData(encodedConfigList)));
        var resumableProfile = ClientHelloProfiles.Custom(builder => builder
            .WithTls13()
            .WithCipherSuites(TlsCipherSuite.TlsAes128GcmSha256)
            .WithSupportedGroups(NamedGroup.Secp256r1)
            .WithKeyShares(NamedGroup.Secp256r1)
            .WithSessionResumption());
        await using var client = new CustomTlsClient(new CustomTlsClientOptions
        {
            ServerName = "private.example",
            ClientHello = resumableProfile,
            SessionCache = cache,
            EarlyData = new Tls13EarlyDataOptions(
                earlyRequest,
                acknowledgeReplayRisk: true),
            EncryptedClientHello = new TlsEchOptions
            {
                ConfigList = configList,
                OuterClientHello = resumableProfile,
            },
        });

        await client.ConnectAsync("127.0.0.1", server.Port, timeout.Token);
        await client.WriteApplicationDataAsync("ping"u8.ToArray(), timeout.Token);
        var response = await client.ReadApplicationDataAsync(timeout.Token);
        await server.Completion;

        Assert.True(client.EncryptedClientHelloAccepted);
        Assert.True(client.SessionWasResumed);
        Assert.Equal(Tls13EarlyDataStatus.Accepted, client.EarlyDataStatus);
        Assert.Equal(earlyRequest, server.ReceivedEarlyData);
        Assert.True(server.EchOuterPskWasGreased);
        Assert.Equal("pong"u8.ToArray(), response);
    }

    [Fact]
    public async Task RejectedEchCannotSelectTheOuterGreasePsk()
    {
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        using var serverPki = TestPki.Create("public.example");
        var encodedConfigList = CreateEchConfigList();
        var configList = TlsEchConfigList.Parse(encodedConfigList);
        await using var server = new ManagedTls13MutualAuthServer(
            serverPki.Leaf,
            serverPki.Root,
            (RSA)serverPki.LeafKey,
            expectedClientLeaf: [],
            selectOuterGreasePsk: true);
        using var cache = new Tls13SessionCache();
        var issuedAt = cache.UtcNow;
        cache.Add(new Tls13SessionTicket(
            Tls13SessionOrigin.Create("private.example", server.Port),
            TlsCipherSuite.TlsAes128GcmSha256,
            negotiatedAlpn: null,
            ageAdd: 1,
            identity: "never-expose-this-ticket"u8,
            psk: Enumerable.Repeat((byte)0x17, 32).ToArray(),
            issuedAt,
            issuedAt.AddHours(1),
            issuedAt.AddHours(1),
            maximumEarlyDataSize: null,
            echConfigListHash: SHA256.HashData(encodedConfigList)));
        var resumableProfile = ClientHelloProfiles.Custom(builder => builder
            .WithTls13()
            .WithCipherSuites(TlsCipherSuite.TlsAes128GcmSha256)
            .WithSupportedGroups(NamedGroup.Secp256r1)
            .WithKeyShares(NamedGroup.Secp256r1)
            .WithSessionResumption());
        await using var client = new CustomTlsClient(new CustomTlsClientOptions
        {
            ServerName = "private.example",
            ClientHello = resumableProfile,
            SessionCache = cache,
            EncryptedClientHello = new TlsEchOptions
            {
                ConfigList = configList,
                OuterClientHello = resumableProfile,
            },
        });

        var exception = await Assert.ThrowsAsync<TlsProtocolException>(() =>
            client.ConnectAsync("127.0.0.1", server.Port, timeout.Token).AsTask());
        await server.Completion;

        Assert.Equal(TlsAlertDescription.IllegalParameter, exception.Alert);
        Assert.True(server.OuterGreasePskSelectionAlertReceived);
        Assert.False(client.IsConnected);
    }

    [Fact]
    public async Task RejectedEchNeverRetransmitsPrivateEarlyDataToOuterConnection()
    {
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        using var serverPki = TestPki.Create("public.example");
        var encodedConfigList = CreateEchConfigList();
        var configList = TlsEchConfigList.Parse(encodedConfigList);
        var earlyRequest = "private-early-secret"u8.ToArray();
        await using var server = new ManagedTls13MutualAuthServer(
            serverPki.Leaf,
            serverPki.Root,
            (RSA)serverPki.LeafKey,
            expectedClientLeaf: [],
            expectEmptyInitialCertificate: true,
            expectEchRequiredAlert: true,
            ignoreRejectedEarlyDataRecord: true);
        using var cache = new Tls13SessionCache();
        var issuedAt = cache.UtcNow;
        cache.Add(new Tls13SessionTicket(
            Tls13SessionOrigin.Create("private.example", server.Port),
            TlsCipherSuite.TlsAes128GcmSha256,
            negotiatedAlpn: null,
            ageAdd: 7,
            identity: "private-early-reject-ticket"u8,
            psk: Enumerable.Repeat((byte)0x29, 32).ToArray(),
            issuedAt,
            issuedAt.AddHours(1),
            issuedAt.AddHours(1),
            maximumEarlyDataSize: 4096,
            echConfigListHash: SHA256.HashData(encodedConfigList)));
        var resumableProfile = ClientHelloProfiles.Custom(builder => builder
            .WithTls13()
            .WithCipherSuites(TlsCipherSuite.TlsAes128GcmSha256)
            .WithSupportedGroups(NamedGroup.Secp256r1)
            .WithKeyShares(NamedGroup.Secp256r1)
            .WithSessionResumption());
        await using var client = new CustomTlsClient(new CustomTlsClientOptions
        {
            ServerName = "private.example",
            ClientHello = resumableProfile,
            SessionCache = cache,
            EarlyData = new Tls13EarlyDataOptions(
                earlyRequest,
                acknowledgeReplayRisk: true,
                Tls13EarlyDataRejectionPolicy.RetransmitAfterHandshake),
            EncryptedClientHello = new TlsEchOptions
            {
                ConfigList = configList,
                OuterClientHello = resumableProfile,
            },
            CertificateValidation = new CustomTlsCertificateValidationOptions
            {
                RevocationMode = X509RevocationMode.NoCheck,
                CustomTrustRoots = [serverPki.Root],
            },
        });

        await Assert.ThrowsAsync<TlsEchRejectedException>(() =>
            client.ConnectAsync("127.0.0.1", server.Port, timeout.Token).AsTask());
        await server.Completion;

        Assert.True(server.RejectedEarlyDataRecordIgnored);
        Assert.True(server.EchRequiredAlertReceived);
        Assert.False(client.IsConnected);
    }

    [Fact]
    public async Task AcceptedEchResumptionRecomputesInnerBinderAcrossHelloRetryRequest()
    {
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        using var serverPki = TestPki.Create("private.example");
        var encodedConfigList = CreateEchConfigList();
        var configList = TlsEchConfigList.Parse(encodedConfigList);
        var ticketIdentity = "private-hrr-ticket"u8.ToArray();
        var psk = Enumerable.Repeat((byte)0x6D, 32).ToArray();
        await using var server = new ManagedTls13MutualAuthServer(
            serverPki.Leaf,
            serverPki.Root,
            (RSA)serverPki.LeafKey,
            expectedClientLeaf: [],
            echConfiguration: Assert.Single(configList.Configurations),
            echPrivateKey: EchPrivateKey,
            useEchHelloRetryRequest: true,
            resumptionTicketIdentity: ticketIdentity,
            resumptionPsk: psk);
        using var cache = new Tls13SessionCache();
        var issuedAt = cache.UtcNow;
        cache.Add(new Tls13SessionTicket(
            Tls13SessionOrigin.Create("private.example", server.Port),
            TlsCipherSuite.TlsAes128GcmSha256,
            negotiatedAlpn: null,
            ageAdd: 0x22334455,
            ticketIdentity,
            psk,
            issuedAt,
            issuedAt.AddHours(1),
            issuedAt.AddHours(1),
            maximumEarlyDataSize: null,
            echConfigListHash: SHA256.HashData(encodedConfigList)));
        var resumableProfile = ClientHelloProfiles.Custom(builder => builder
            .WithTls13()
            .WithCipherSuites(TlsCipherSuite.TlsAes128GcmSha256)
            .WithSupportedGroups(NamedGroup.Secp256r1, NamedGroup.Secp384r1)
            .WithKeyShares(NamedGroup.Secp256r1)
            .WithSessionResumption());
        await using var client = new CustomTlsClient(new CustomTlsClientOptions
        {
            ServerName = "private.example",
            ClientHello = resumableProfile,
            SessionCache = cache,
            EncryptedClientHello = new TlsEchOptions
            {
                ConfigList = configList,
                OuterClientHello = resumableProfile,
            },
        });

        await client.ConnectAsync("127.0.0.1", server.Port, timeout.Token);
        await client.WriteApplicationDataAsync("ping"u8.ToArray(), timeout.Token);
        var response = await client.ReadApplicationDataAsync(timeout.Token);
        await server.Completion;

        Assert.True(client.EncryptedClientHelloAccepted);
        Assert.True(client.SessionWasResumed);
        Assert.True(client.HandshakeUsedHelloRetryRequest);
        Assert.Equal(NamedGroup.Secp384r1, client.NegotiatedGroup);
        Assert.True(server.EchInnerPskVerified);
        Assert.True(server.EchHelloRetryRequestCompleted);
        Assert.Equal("pong"u8.ToArray(), response);
    }

    [Fact]
    public async Task AcceptedEchTicketIsCachedWithSourceBindingAndResumed()
    {
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        using var serverPki = TestPki.Create("private.example");
        var encodedConfigList = CreateEchConfigList();
        var configList = TlsEchConfigList.Parse(encodedConfigList);
        var ticketIdentity = "issued-ech-ticket"u8.ToArray();
        var profile = ClientHelloProfiles.Custom(builder => builder
            .WithTls13()
            .WithCipherSuites(TlsCipherSuite.TlsAes128GcmSha256)
            .WithSupportedGroups(NamedGroup.Secp256r1)
            .WithKeyShares(NamedGroup.Secp256r1)
            .WithSessionResumption());
        using var cache = new Tls13SessionCache();
        await using var firstServer = new ManagedTls13MutualAuthServer(
            serverPki.Leaf,
            serverPki.Root,
            (RSA)serverPki.LeafKey,
            expectedClientLeaf: [],
            echConfiguration: Assert.Single(configList.Configurations),
            echPrivateKey: EchPrivateKey,
            expectEmptyInitialCertificate: true,
            newSessionTicketIdentity: ticketIdentity);
        await using (var firstClient = CreateEchSessionClient(
            profile,
            cache,
            configList,
            serverPki.Root))
        {
            await AuthenticateLoopbackAsync(
                firstClient,
                firstServer.Port,
                timeout.Token);
            await firstClient.WriteApplicationDataAsync("ping"u8.ToArray(), timeout.Token);
            Assert.Equal(
                "pong"u8.ToArray(),
                await firstClient.ReadApplicationDataAsync(timeout.Token));
            await firstServer.Completion;
            Assert.True(firstClient.EncryptedClientHelloAccepted);
            Assert.False(firstClient.SessionWasResumed);
        }
        Assert.Equal(1, cache.Count);

        var issuedPsk = firstServer.CopyIssuedResumptionPsk();
        try
        {
            await using var secondServer = new ManagedTls13MutualAuthServer(
                serverPki.Leaf,
                serverPki.Root,
                (RSA)serverPki.LeafKey,
                expectedClientLeaf: [],
                echConfiguration: Assert.Single(configList.Configurations),
                echPrivateKey: EchPrivateKey,
                resumptionTicketIdentity: ticketIdentity,
                resumptionPsk: issuedPsk);
            await using var secondClient = CreateEchSessionClient(
                profile,
                cache,
                configList,
                serverPki.Root);
            await AuthenticateLoopbackAsync(
                secondClient,
                secondServer.Port,
                timeout.Token);
            await secondClient.WriteApplicationDataAsync("ping"u8.ToArray(), timeout.Token);
            Assert.Equal(
                "pong"u8.ToArray(),
                await secondClient.ReadApplicationDataAsync(timeout.Token));
            await secondServer.Completion;

            Assert.True(secondClient.EncryptedClientHelloAccepted);
            Assert.True(secondClient.SessionWasResumed);
            Assert.True(secondServer.EchInnerPskVerified);
            Assert.True(secondServer.EchOuterPskWasGreased);
            Assert.Equal(0, cache.Count);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(issuedPsk);
        }
    }

    [Fact]
    public async Task GreaseEchIgnoresValidatedRetryConfigsAndCompletesPublicHandshake()
    {
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        using var serverPki = TestPki.Create("public.example");
        using var clientPki = TestPki.Create(
            dnsName: "client.example",
            serverAuthenticationEku: false);
        using var clientLeafWithKey = clientPki.Leaf.CopyWithPrivateKey(
            (RSA)clientPki.LeafKey);
        using var clientCredential = new TlsClientCertificate(
            clientLeafWithKey,
            [clientPki.Root]);
        await using var server = new ManagedTls13MutualAuthServer(
            serverPki.Leaf,
            serverPki.Root,
            (RSA)serverPki.LeafKey,
            clientPki.Leaf.RawData,
            echRetryConfigurations: CreateEchConfigList());
        await using var client = new CustomTlsClient(new CustomTlsClientOptions
        {
            ServerName = "public.example",
            EncryptedClientHelloGrease = new TlsEchGreaseOptions(),
            ClientCertificate = clientCredential,
            CertificateValidation = new CustomTlsCertificateValidationOptions
            {
                RevocationMode = X509RevocationMode.NoCheck,
                CustomTrustRoots = [serverPki.Root],
            },
        });

        await client.ConnectAsync("127.0.0.1", server.Port, timeout.Token);
        await client.WriteApplicationDataAsync("ping"u8.ToArray(), timeout.Token);
        var response = await client.ReadApplicationDataAsync(timeout.Token);
        await server.Completion;

        Assert.True(client.IsConnected);
        Assert.False(client.EncryptedClientHelloAccepted);
        Assert.Equal("pong"u8.ToArray(), response);
        Assert.Equal("public.example", server.EchOuterServerName);
        Assert.True(server.ClientCertificateVerified);
        Assert.False(server.EchRequiredAlertReceived);
    }

    private static ClientHelloProfile CreateHelloRetryRequestProfile() =>
        ClientHelloProfiles.Custom(builder => builder
            .WithTls13()
            .WithSupportedGroups(NamedGroup.Secp256r1, NamedGroup.Secp384r1)
            .WithKeyShares(NamedGroup.Secp256r1));

    private static CustomTlsClient CreateEchSessionClient(
        ClientHelloProfile profile,
        Tls13SessionCache cache,
        TlsEchConfigList configList,
        X509Certificate2 trustRoot) => new(new CustomTlsClientOptions
        {
            ServerName = "private.example",
            ClientHello = profile,
            SessionCache = cache,
            EncryptedClientHello = new TlsEchOptions
            {
                ConfigList = configList,
                OuterClientHello = profile,
            },
            CertificateValidation = new CustomTlsCertificateValidationOptions
            {
                RevocationMode = X509RevocationMode.NoCheck,
                CustomTrustRoots = [trustRoot],
            },
        });

    private static async ValueTask AuthenticateLoopbackAsync(
        CustomTlsClient client,
        int port,
        CancellationToken cancellationToken)
    {
        var socket = new Socket(SocketType.Stream, ProtocolType.Tcp);
        try
        {
            await socket.ConnectAsync(IPAddress.Loopback, port, cancellationToken);
            var stream = new NetworkStream(socket, ownsSocket: true);
            socket = null!;
            await client.AuthenticateAsync(
                stream,
                "private.example",
                leaveOpen: false,
                cancellationToken);
        }
        finally
        {
            socket?.Dispose();
        }
    }

    private static byte[] CreateEchConfigList(
        byte configId = 7,
        byte[]? publicKey = null)
    {
        var suites = new TlsBinaryWriter();
        suites.WriteUInt16((ushort)TlsHpkeKdfId.HkdfSha256);
        suites.WriteUInt16((ushort)TlsHpkeAeadId.Aes128Gcm);
        var contents = new TlsBinaryWriter();
        contents.WriteUInt8(configId);
        contents.WriteUInt16((ushort)TlsHpkeKemId.DhkemX25519HkdfSha256);
        contents.WriteVector16(publicKey ?? Convert.FromHexString(
            "3948cfe0ad1ddb695d780e59077195da6c56506b027329794ab02bca80815c4d"));
        contents.WriteVector16(suites.WrittenSpan);
        contents.WriteUInt8(32);
        contents.WriteVector8(Encoding.ASCII.GetBytes("public.example"));
        contents.WriteVector16([]);
        var configuration = new TlsBinaryWriter();
        configuration.WriteUInt16((ushort)TlsExtensionType.EncryptedClientHello);
        configuration.WriteVector16(contents.WrittenSpan);
        var list = new TlsBinaryWriter();
        list.WriteVector16(configuration.WrittenSpan);
        return list.ToArray();
    }
}
