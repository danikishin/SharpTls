using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using SharpTls.Certificates;
using SharpTls.Cryptography;
using SharpTls.IO;
using SharpTls.Protocol;
using SharpTls.Quic;
using SharpTls.Tests.Certificates;

namespace SharpTls.Tests.Quic;

public sealed class CustomTlsQuicServerTests
{
    private static readonly byte[] EchPrivateKey = Convert.FromHexString(
        "4612c550263fc8ad58375df3f557aac531d26850903e55a9f23f21d8534e8ac8");

    [Theory]
    [InlineData(false, NamedGroup.Secp256r1)]
    [InlineData(true, NamedGroup.Secp384r1)]
    [InlineData(false, NamedGroup.X25519MlKem768)]
    [InlineData(true, NamedGroup.X25519MlKem768)]
    [InlineData(false, NamedGroup.X25519Kyber768Draft00)]
    [InlineData(true, NamedGroup.X25519Kyber768Draft00)]
    public async Task ClientAndServerAdaptersCompleteRecordlessHandshakeAndMatchSecrets(
        bool forceHelloRetryRequest,
        NamedGroup selectedGroup)
    {
        using var pki = TestPki.Create();
        using var credential = new TlsServerCertificate(
            pki.Leaf,
            (RSA)pki.LeafKey,
            [pki.Root]);
        var clientParameters = CreateClientParameters();
        var serverParameters = CreateServerParameters();
        var profile = ClientHelloProfiles.Custom(builder => builder
            .WithTls13()
            .WithCipherSuites(TlsCipherSuite.TlsAes128GcmSha256)
            .WithSupportedGroups(forceHelloRetryRequest
                ? [NamedGroup.Secp256r1, selectedGroup]
                : [selectedGroup])
            .WithKeyShares(forceHelloRetryRequest
                ? [NamedGroup.Secp256r1]
                : [selectedGroup])
            .WithAlpn("h3")
            .WithQuicTransportParameters(clientParameters)
            .WithExtensionOrder(
                ClientHelloExtensionKind.ServerName,
                ClientHelloExtensionKind.SupportedVersions,
                ClientHelloExtensionKind.SupportedGroups,
                ClientHelloExtensionKind.SignatureAlgorithms,
                ClientHelloExtensionKind.KeyShare,
                ClientHelloExtensionKind.ApplicationLayerProtocolNegotiation,
                ClientHelloExtensionKind.QuicTransportParameters));
        await using var client = new CustomTlsQuicClient(new CustomTlsQuicClientOptions
        {
            ServerName = "example.com",
            ClientHello = profile,
            CertificateValidation = new CustomTlsCertificateValidationOptions
            {
                CustomTrustRoots = [pki.Root],
                RevocationMode = X509RevocationMode.NoCheck,
            },
        });
        await using var server = new CustomTlsQuicServer(new CustomTlsQuicServerOptions
        {
            Tls = new CustomTlsServerOptions
            {
                ServerCertificate = credential,
                SupportedVersions = [TlsProtocolVersion.Tls13],
                CipherSuites = [TlsCipherSuite.TlsAes128GcmSha256],
                SupportedGroups = [selectedGroup],
                AlpnProtocols = ["h3"],
                RequireAlpn = true,
            },
            TransportParameters = serverParameters,
        });

        using var start = client.StartHandshake();
        var firstClientHello = Assert.Single(
            start.Events.OfType<TlsQuicCryptoDataEvent>());
        using var firstServerOutput = await server.ProcessCryptoDataAsync(
            TlsQuicEncryptionLevel.Initial,
            firstClientHello.Offset,
            firstClientHello.Data);

        TlsQuicProcessResult serverFlight;
        TlsQuicProcessResult clientHelloOutput;
        if (forceHelloRetryRequest)
        {
            var retry = Assert.Single(firstServerOutput.Events.OfType<TlsQuicCryptoDataEvent>());
            Assert.Equal(0UL, retry.Offset);
            using var retryClientOutput = await client.ProcessCryptoDataAsync(
                TlsQuicEncryptionLevel.Initial,
                retry.Offset,
                retry.Data);
            var secondClientHello = Assert.Single(
                retryClientOutput.Events.OfType<TlsQuicCryptoDataEvent>());
            Assert.Equal((ulong)firstClientHello.Data.Length, secondClientHello.Offset);
            serverFlight = await server.ProcessCryptoDataAsync(
                TlsQuicEncryptionLevel.Initial,
                secondClientHello.Offset,
                secondClientHello.Data);
            var serverHello = serverFlight.Events.OfType<TlsQuicCryptoDataEvent>()
                .Single(item => item.Level == TlsQuicEncryptionLevel.Initial);
            Assert.Equal((ulong)retry.Data.Length, serverHello.Offset);
            clientHelloOutput = await client.ProcessCryptoDataAsync(
                TlsQuicEncryptionLevel.Initial,
                serverHello.Offset,
                serverHello.Data);
        }
        else
        {
            serverFlight = firstServerOutput;
            var serverHello = serverFlight.Events.OfType<TlsQuicCryptoDataEvent>()
                .Single(item => item.Level == TlsQuicEncryptionLevel.Initial);
            clientHelloOutput = await client.ProcessCryptoDataAsync(
                TlsQuicEncryptionLevel.Initial,
                serverHello.Offset,
                serverHello.Data);
        }

        try
        {
            AssertSecretPair(
                serverFlight,
                TlsQuicEncryptionLevel.Handshake,
                TlsQuicSecretDirection.Write,
                clientHelloOutput,
                TlsQuicSecretDirection.Read);
            AssertSecretPair(
                serverFlight,
                TlsQuicEncryptionLevel.Handshake,
                TlsQuicSecretDirection.Read,
                clientHelloOutput,
                TlsQuicSecretDirection.Write);

            var handshakeFlight = serverFlight.Events.OfType<TlsQuicCryptoDataEvent>()
                .Single(item => item.Level == TlsQuicEncryptionLevel.Handshake);
            using var clientCompleted = await client.ProcessCryptoDataAsync(
                TlsQuicEncryptionLevel.Handshake,
                handshakeFlight.Offset,
                handshakeFlight.Data);
            Assert.True(client.IsHandshakeComplete);
            Assert.Equal(serverParameters.Encode(),
                Assert.Single(clientCompleted.Events
                    .OfType<TlsQuicPeerTransportParametersEvent>()).Parameters.Encode());
            AssertSecretPair(
                serverFlight,
                TlsQuicEncryptionLevel.Application,
                TlsQuicSecretDirection.Write,
                clientCompleted,
                TlsQuicSecretDirection.Read);
            AssertSecretPair(
                serverFlight,
                TlsQuicEncryptionLevel.Application,
                TlsQuicSecretDirection.Read,
                clientCompleted,
                TlsQuicSecretDirection.Write);

            var clientFinished = clientCompleted.Events.OfType<TlsQuicCryptoDataEvent>()
                .Single(item => item.Level == TlsQuicEncryptionLevel.Handshake);
            using var serverCompleted = await server.ProcessCryptoDataAsync(
                TlsQuicEncryptionLevel.Handshake,
                clientFinished.Offset,
                clientFinished.Data);
            Assert.True(server.IsHandshakeComplete);
            Assert.Equal(forceHelloRetryRequest, client.HandshakeUsedHelloRetryRequest);
            Assert.Equal(forceHelloRetryRequest, server.HandshakeUsedHelloRetryRequest);
            Assert.Equal("example.com", server.ServerName);
            Assert.Equal("h3", server.NegotiatedApplicationProtocol);
            Assert.Equal(clientParameters.Encode(),
                Assert.Single(serverCompleted.Events
                    .OfType<TlsQuicPeerTransportParametersEvent>()).Parameters.Encode());
            Assert.Contains(serverCompleted.Events.OfType<TlsQuicDiscardKeysEvent>(),
                item => item.Level == TlsQuicEncryptionLevel.Initial);
            Assert.Contains(serverCompleted.Events.OfType<TlsQuicDiscardKeysEvent>(),
                item => item.Level == TlsQuicEncryptionLevel.Handshake);
            Assert.Single(serverCompleted.Events.OfType<TlsQuicHandshakeCompletedEvent>());
        }
        finally
        {
            if (!ReferenceEquals(serverFlight, firstServerOutput))
            {
                serverFlight.Dispose();
            }
            clientHelloOutput.Dispose();
        }
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task ClientAndServerAdaptersCompleteAcceptedEchHandshake(
        bool forceHelloRetryRequest)
    {
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
        var profile = ClientHelloProfiles.Custom(builder => builder
            .WithTls13()
            .WithCipherSuites(TlsCipherSuite.TlsAes128GcmSha256)
            .WithSupportedGroups(NamedGroup.Secp256r1, NamedGroup.Secp384r1)
            .WithKeyShares(NamedGroup.Secp256r1)
            .WithAlpn("h3")
            .WithQuicTransportParameters(CreateClientParameters())
            .WithExtensionOrder(
                ClientHelloExtensionKind.ServerName,
                ClientHelloExtensionKind.SupportedVersions,
                ClientHelloExtensionKind.SupportedGroups,
                ClientHelloExtensionKind.SignatureAlgorithms,
                ClientHelloExtensionKind.KeyShare,
                ClientHelloExtensionKind.ApplicationLayerProtocolNegotiation,
                ClientHelloExtensionKind.QuicTransportParameters));
        await using var client = new CustomTlsQuicClient(new CustomTlsQuicClientOptions
        {
            ServerName = "private.example",
            ClientHello = profile,
            EncryptedClientHello = new TlsEchOptions
            {
                ConfigList = configList,
                OuterClientHello = profile,
            },
            CertificateValidation = new CustomTlsCertificateValidationOptions
            {
                CustomTrustRoots = [pki.Root],
                RevocationMode = X509RevocationMode.NoCheck,
            },
        });
        await using var server = new CustomTlsQuicServer(new CustomTlsQuicServerOptions
        {
            Tls = new CustomTlsServerOptions
            {
                ServerCertificate = credential,
                SupportedVersions = [TlsProtocolVersion.Tls13],
                CipherSuites = [TlsCipherSuite.TlsAes128GcmSha256],
                SupportedGroups = forceHelloRetryRequest
                    ? [NamedGroup.Secp384r1]
                    : [NamedGroup.Secp256r1],
                AlpnProtocols = ["h3"],
                RequireAlpn = true,
                EncryptedClientHelloKeys = [echKey],
            },
            TransportParameters = CreateServerParameters(),
        });

        using var started = client.StartHandshake();
        var firstHello = Assert.Single(started.Events.OfType<TlsQuicCryptoDataEvent>());
        using var firstServerOutput = await server.ProcessCryptoDataAsync(
            TlsQuicEncryptionLevel.Initial,
            firstHello.Offset,
            firstHello.Data);
        TlsQuicProcessResult? retryClientOutput = null;
        TlsQuicProcessResult? retriedServerFlight = null;
        TlsQuicProcessResult serverFlight = firstServerOutput;
        try
        {
            if (forceHelloRetryRequest)
            {
                var retry = Assert.Single(
                    firstServerOutput.Events.OfType<TlsQuicCryptoDataEvent>());
                retryClientOutput = await client.ProcessCryptoDataAsync(
                    TlsQuicEncryptionLevel.Initial,
                    retry.Offset,
                    retry.Data);
                var secondHello = Assert.Single(
                    retryClientOutput.Events.OfType<TlsQuicCryptoDataEvent>());
                retriedServerFlight = await server.ProcessCryptoDataAsync(
                    TlsQuicEncryptionLevel.Initial,
                    secondHello.Offset,
                    secondHello.Data);
                serverFlight = retriedServerFlight;
            }

            var serverHello = serverFlight.Events.OfType<TlsQuicCryptoDataEvent>()
                .Single(value => value.Level == TlsQuicEncryptionLevel.Initial);
            using var clientSecrets = await client.ProcessCryptoDataAsync(
                TlsQuicEncryptionLevel.Initial,
                serverHello.Offset,
                serverHello.Data);
            AssertSecretPair(
                serverFlight,
                TlsQuicEncryptionLevel.Handshake,
                TlsQuicSecretDirection.Write,
                clientSecrets,
                TlsQuicSecretDirection.Read);
            var serverHandshake = serverFlight.Events.OfType<TlsQuicCryptoDataEvent>()
                .Single(value => value.Level == TlsQuicEncryptionLevel.Handshake);
            using var clientCompleted = await client.ProcessCryptoDataAsync(
                TlsQuicEncryptionLevel.Handshake,
                serverHandshake.Offset,
                serverHandshake.Data);
            var clientFinished = Assert.Single(
                clientCompleted.Events.OfType<TlsQuicCryptoDataEvent>(),
                value => value.Level == TlsQuicEncryptionLevel.Handshake);
            using var serverCompleted = await server.ProcessCryptoDataAsync(
                TlsQuicEncryptionLevel.Handshake,
                clientFinished.Offset,
                clientFinished.Data);

            Assert.True(client.IsHandshakeComplete);
            Assert.True(server.IsHandshakeComplete);
            Assert.True(client.EncryptedClientHelloAccepted);
            Assert.True(server.EncryptedClientHelloAccepted);
            Assert.True(server.EncryptedClientHelloOffered);
            Assert.Equal("public.example", server.EncryptedClientHelloOuterServerName);
            Assert.Equal("private.example", server.ServerName);
            Assert.Equal(forceHelloRetryRequest, client.HandshakeUsedHelloRetryRequest);
            Assert.Equal(forceHelloRetryRequest, server.HandshakeUsedHelloRetryRequest);
        }
        finally
        {
            retryClientOutput?.Dispose();
            retriedServerFlight?.Dispose();
        }
    }

    [Fact]
    public async Task QuicClientAuthenticatesEchRejectionAndRetryConfigurations()
    {
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
        var profile = ClientHelloProfiles.Custom(builder => builder
            .WithTls13()
            .WithCipherSuites(TlsCipherSuite.TlsAes128GcmSha256)
            .WithSupportedGroups(NamedGroup.Secp256r1)
            .WithKeyShares(NamedGroup.Secp256r1)
            .WithAlpn("h3")
            .WithQuicTransportParameters(CreateClientParameters()));
        await using var client = new CustomTlsQuicClient(new CustomTlsQuicClientOptions
        {
            ServerName = "private.example",
            ClientHello = profile,
            EncryptedClientHello = new TlsEchOptions
            {
                ConfigList = clientConfigList,
                OuterClientHello = profile,
            },
            CertificateValidation = new CustomTlsCertificateValidationOptions
            {
                CustomTrustRoots = [pki.Root],
                RevocationMode = X509RevocationMode.NoCheck,
            },
        });
        await using var server = new CustomTlsQuicServer(new CustomTlsQuicServerOptions
        {
            Tls = new CustomTlsServerOptions
            {
                ServerCertificate = credential,
                SupportedVersions = [TlsProtocolVersion.Tls13],
                CipherSuites = [TlsCipherSuite.TlsAes128GcmSha256],
                SupportedGroups = [NamedGroup.Secp256r1],
                AlpnProtocols = ["h3"],
                RequireAlpn = true,
                EncryptedClientHelloKeys = [echKey],
            },
            TransportParameters = CreateServerParameters(),
        });

        using var started = client.StartHandshake();
        var clientHello = Assert.Single(started.Events.OfType<TlsQuicCryptoDataEvent>());
        using var serverFlight = await server.ProcessCryptoDataAsync(
            TlsQuicEncryptionLevel.Initial,
            clientHello.Offset,
            clientHello.Data);
        var serverHello = serverFlight.Events.OfType<TlsQuicCryptoDataEvent>()
            .Single(value => value.Level == TlsQuicEncryptionLevel.Initial);
        using var clientSecrets = await client.ProcessCryptoDataAsync(
            TlsQuicEncryptionLevel.Initial,
            serverHello.Offset,
            serverHello.Data);
        var serverHandshake = serverFlight.Events.OfType<TlsQuicCryptoDataEvent>()
            .Single(value => value.Level == TlsQuicEncryptionLevel.Handshake);

        var rejection = await Assert.ThrowsAsync<TlsEchRejectedException>(() =>
            client.ProcessCryptoDataAsync(
                TlsQuicEncryptionLevel.Handshake,
                serverHandshake.Offset,
                serverHandshake.Data).AsTask());

        Assert.Equal("public.example", rejection.PublicName);
        Assert.Equal(serverConfigBytes, rejection.RetryConfigurations!.GetEncodedList());
        Assert.False(client.EncryptedClientHelloAccepted);
        Assert.False(client.IsHandshakeComplete);
        Assert.True(server.EncryptedClientHelloOffered);
        Assert.False(server.EncryptedClientHelloAccepted);
        Assert.False(server.IsHandshakeComplete);
    }

    [Fact]
    public async Task AcceptedEchResumptionBinderSurvivesHelloRetryRequest()
    {
        using var pki = TestPki.Create("private.example");
        using var credential = new TlsServerCertificate(
            pki.Leaf,
            (RSA)pki.LeafKey,
            [pki.Root]);
        var configList = TlsEchConfigList.Parse(CreateEchConfigList());
        using var echKey = new TlsEchServerKey(
            Assert.Single(configList.Configurations),
            EchPrivateKey);
        var ticketKey = RandomNumberGenerator.GetBytes(32);
        using var protector = new Tls13ServerSessionTicketProtector("quic-ech", ticketKey);
        CryptographicOperations.ZeroMemory(ticketKey);
        using var cache = new Tls13SessionCache(capacity: 4);
        var profile = ClientHelloProfiles.Custom(builder => builder
            .WithTls13()
            .WithCipherSuites(TlsCipherSuite.TlsAes128GcmSha256)
            .WithSupportedGroups(NamedGroup.Secp256r1, NamedGroup.Secp384r1)
            .WithKeyShares(NamedGroup.Secp256r1)
            .WithAlpn("h3")
            .WithQuicTransportParameters(CreateClientParameters())
            .WithSessionResumption()
            .WithExtensionOrder(
                ClientHelloExtensionKind.ServerName,
                ClientHelloExtensionKind.SupportedVersions,
                ClientHelloExtensionKind.SupportedGroups,
                ClientHelloExtensionKind.SignatureAlgorithms,
                ClientHelloExtensionKind.KeyShare,
                ClientHelloExtensionKind.ApplicationLayerProtocolNegotiation,
                ClientHelloExtensionKind.QuicTransportParameters,
                ClientHelloExtensionKind.PskKeyExchangeModes,
                ClientHelloExtensionKind.PreSharedKey));

        for (var connection = 0; connection < 2; connection++)
        {
            await using var client = new CustomTlsQuicClient(new CustomTlsQuicClientOptions
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
                    CustomTrustRoots = [pki.Root],
                    RevocationMode = X509RevocationMode.NoCheck,
                },
            });
            await using var server = new CustomTlsQuicServer(new CustomTlsQuicServerOptions
            {
                Tls = new CustomTlsServerOptions
                {
                    ServerCertificate = credential,
                    SupportedVersions = [TlsProtocolVersion.Tls13],
                    CipherSuites = [TlsCipherSuite.TlsAes128GcmSha256],
                    SupportedGroups = connection == 0
                        ? [NamedGroup.Secp256r1]
                        : [NamedGroup.Secp384r1],
                    AlpnProtocols = ["h3"],
                    SessionTicketProtector = protector,
                    AutomaticSessionTicketCount = 1,
                    EncryptedClientHelloKeys = [echKey],
                },
                TransportParameters = CreateServerParameters(),
            });

            using var started = client.StartHandshake();
            var firstHello = Assert.Single(started.Events.OfType<TlsQuicCryptoDataEvent>());
            using var firstServerOutput = await server.ProcessCryptoDataAsync(
                TlsQuicEncryptionLevel.Initial,
                firstHello.Offset,
                firstHello.Data);
            TlsQuicProcessResult? retryClientOutput = null;
            TlsQuicProcessResult? retriedServerFlight = null;
            TlsQuicProcessResult serverFlight = firstServerOutput;
            try
            {
                if (connection == 1)
                {
                    var retry = Assert.Single(
                        firstServerOutput.Events.OfType<TlsQuicCryptoDataEvent>());
                    retryClientOutput = await client.ProcessCryptoDataAsync(
                        TlsQuicEncryptionLevel.Initial,
                        retry.Offset,
                        retry.Data);
                    var secondHello = Assert.Single(
                        retryClientOutput.Events.OfType<TlsQuicCryptoDataEvent>());
                    retriedServerFlight = await server.ProcessCryptoDataAsync(
                        TlsQuicEncryptionLevel.Initial,
                        secondHello.Offset,
                        secondHello.Data);
                    serverFlight = retriedServerFlight;
                }

                var serverHello = serverFlight.Events.OfType<TlsQuicCryptoDataEvent>()
                    .Single(value => value.Level == TlsQuicEncryptionLevel.Initial);
                using var clientSecrets = await client.ProcessCryptoDataAsync(
                    TlsQuicEncryptionLevel.Initial,
                    serverHello.Offset,
                    serverHello.Data);
                var serverHandshake = serverFlight.Events.OfType<TlsQuicCryptoDataEvent>()
                    .Single(value => value.Level == TlsQuicEncryptionLevel.Handshake);
                using var clientCompleted = await client.ProcessCryptoDataAsync(
                    TlsQuicEncryptionLevel.Handshake,
                    serverHandshake.Offset,
                    serverHandshake.Data);
                var clientFinished = Assert.Single(
                    clientCompleted.Events.OfType<TlsQuicCryptoDataEvent>(),
                    value => value.Level == TlsQuicEncryptionLevel.Handshake);
                using var serverCompleted = await server.ProcessCryptoDataAsync(
                    TlsQuicEncryptionLevel.Handshake,
                    clientFinished.Offset,
                    clientFinished.Data);

                Assert.True(client.EncryptedClientHelloAccepted);
                Assert.True(server.EncryptedClientHelloAccepted);
                Assert.Equal(connection == 1, client.SessionWasResumed);
                Assert.Equal(connection == 1, server.SessionWasResumed);
                Assert.Equal(connection == 1, client.HandshakeUsedHelloRetryRequest);
                foreach (var ticket in serverCompleted.Events
                    .OfType<TlsQuicCryptoDataEvent>()
                    .Where(value => value.Level == TlsQuicEncryptionLevel.Application))
                {
                    using var processed = await client.ProcessCryptoDataAsync(
                        ticket.Level,
                        ticket.Offset,
                        ticket.Data);
                }
            }
            finally
            {
                retryClientOutput?.Dispose();
                retriedServerFlight?.Dispose();
            }
        }
    }

    [Fact]
    public async Task AcceptedEchResumptionProducesMatchingZeroRttSecrets()
    {
        using var pki = TestPki.Create("private.example");
        using var credential = new TlsServerCertificate(
            pki.Leaf,
            (RSA)pki.LeafKey,
            [pki.Root]);
        var configList = TlsEchConfigList.Parse(CreateEchConfigList());
        using var echKey = new TlsEchServerKey(
            Assert.Single(configList.Configurations),
            EchPrivateKey);
        var ticketKey = RandomNumberGenerator.GetBytes(32);
        using var protector = new Tls13ServerSessionTicketProtector(
            "quic-ech-early-data",
            ticketKey);
        CryptographicOperations.ZeroMemory(ticketKey);
        using var cache = new Tls13SessionCache(capacity: 4);
        var profile = ClientHelloProfiles.Custom(builder => builder
            .WithTls13()
            .WithCipherSuites(TlsCipherSuite.TlsAes128GcmSha256)
            .WithSupportedGroups(NamedGroup.Secp256r1)
            .WithKeyShares(NamedGroup.Secp256r1)
            .WithAlpn("h3")
            .WithQuicTransportParameters(CreateClientParameters())
            .WithSessionResumption()
            .WithExtensionOrder(
                ClientHelloExtensionKind.ServerName,
                ClientHelloExtensionKind.SupportedVersions,
                ClientHelloExtensionKind.SupportedGroups,
                ClientHelloExtensionKind.SignatureAlgorithms,
                ClientHelloExtensionKind.KeyShare,
                ClientHelloExtensionKind.ApplicationLayerProtocolNegotiation,
                ClientHelloExtensionKind.QuicTransportParameters,
                ClientHelloExtensionKind.PskKeyExchangeModes,
                ClientHelloExtensionKind.EarlyData,
                ClientHelloExtensionKind.PreSharedKey));

        for (var connection = 0; connection < 2; connection++)
        {
            await using var client = new CustomTlsQuicClient(new CustomTlsQuicClientOptions
            {
                ServerName = "private.example",
                ClientHello = profile,
                SessionCache = cache,
                EarlyData = connection == 1
                    ? new TlsQuicEarlyDataOptions(acknowledgeReplayRisk: true)
                    : null,
                EncryptedClientHello = new TlsEchOptions
                {
                    ConfigList = configList,
                    OuterClientHello = profile,
                },
                CertificateValidation = new CustomTlsCertificateValidationOptions
                {
                    CustomTrustRoots = [pki.Root],
                    RevocationMode = X509RevocationMode.NoCheck,
                },
            });
            await using var server = new CustomTlsQuicServer(new CustomTlsQuicServerOptions
            {
                Tls = new CustomTlsServerOptions
                {
                    ServerCertificate = credential,
                    SupportedVersions = [TlsProtocolVersion.Tls13],
                    CipherSuites = [TlsCipherSuite.TlsAes128GcmSha256],
                    SupportedGroups = [NamedGroup.Secp256r1],
                    AlpnProtocols = ["h3"],
                    SessionTicketProtector = protector,
                    AutomaticSessionTicketCount = 1,
                    EncryptedClientHelloKeys = [echKey],
                },
                TransportParameters = CreateServerParameters(),
                EnableEarlyData = true,
                EarlyDataReplayValidator = (_, _) => ValueTask.FromResult(true),
            });

            using var started = client.StartHandshake();
            if (connection == 1)
            {
                Assert.Single(started.Events.OfType<TlsQuicEarlyDataReadyEvent>());
            }
            var clientHello = Assert.Single(
                started.Events.OfType<TlsQuicCryptoDataEvent>());
            using var serverFlight = await server.ProcessCryptoDataAsync(
                TlsQuicEncryptionLevel.Initial,
                clientHello.Offset,
                clientHello.Data);
            if (connection == 1)
            {
                AssertSecretPair(
                    started,
                    TlsQuicEncryptionLevel.EarlyData,
                    TlsQuicSecretDirection.Write,
                    serverFlight,
                    TlsQuicSecretDirection.Read);
                Assert.True(server.EarlyDataAccepted);
            }
            var serverHello = serverFlight.Events.OfType<TlsQuicCryptoDataEvent>()
                .Single(value => value.Level == TlsQuicEncryptionLevel.Initial);
            using var clientSecrets = await client.ProcessCryptoDataAsync(
                TlsQuicEncryptionLevel.Initial,
                serverHello.Offset,
                serverHello.Data);
            var serverHandshake = serverFlight.Events.OfType<TlsQuicCryptoDataEvent>()
                .Single(value => value.Level == TlsQuicEncryptionLevel.Handshake);
            using var clientCompleted = await client.ProcessCryptoDataAsync(
                TlsQuicEncryptionLevel.Handshake,
                serverHandshake.Offset,
                serverHandshake.Data);
            var clientFinished = Assert.Single(
                clientCompleted.Events.OfType<TlsQuicCryptoDataEvent>(),
                value => value.Level == TlsQuicEncryptionLevel.Handshake);
            using var serverCompleted = await server.ProcessCryptoDataAsync(
                TlsQuicEncryptionLevel.Handshake,
                clientFinished.Offset,
                clientFinished.Data);

            Assert.True(client.EncryptedClientHelloAccepted);
            Assert.True(server.EncryptedClientHelloAccepted);
            Assert.Equal(connection == 1, client.SessionWasResumed);
            Assert.Equal(connection == 1, server.SessionWasResumed);
            Assert.Equal(
                connection == 1
                    ? Tls13EarlyDataStatus.Accepted
                    : Tls13EarlyDataStatus.NotConfigured,
                client.EarlyDataStatus);
            foreach (var ticket in serverCompleted.Events
                .OfType<TlsQuicCryptoDataEvent>()
                .Where(value => value.Level == TlsQuicEncryptionLevel.Application))
            {
                using var processed = await client.ProcessCryptoDataAsync(
                    ticket.Level,
                    ticket.Offset,
                    ticket.Data);
            }
        }
    }

    [Fact]
    public async Task ClientServerOnlyTransportParameterFailsClosed()
    {
        using var pki = TestPki.Create();
        using var credential = new TlsServerCertificate(
            pki.Leaf,
            (RSA)pki.LeafKey,
            [pki.Root]);
        var hostileClientParameters = new TlsQuicTransportParameters(
        [
            new TlsQuicTransportParameter(0x21, new byte[16]),
        ]);
        var profile = ClientHelloProfiles.Custom(builder => builder
            .WithTls13()
            .WithAlpn("h3")
            .WithQuicTransportParameters(hostileClientParameters));
        await using var client = new CustomTlsQuicClient(new CustomTlsQuicClientOptions
        {
            ServerName = "example.com",
            ClientHello = profile,
            CertificateValidation = new CustomTlsCertificateValidationOptions
            {
                CustomTrustRoots = [pki.Root],
                RevocationMode = X509RevocationMode.NoCheck,
            },
        });
        await using var server = new CustomTlsQuicServer(new CustomTlsQuicServerOptions
        {
            Tls = new CustomTlsServerOptions
            {
                ServerCertificate = credential,
                AlpnProtocols = ["h3"],
            },
            TransportParameters = CreateServerParameters(),
        });
        using var start = client.StartHandshake();
        var hello = Assert.Single(start.Events.OfType<TlsQuicCryptoDataEvent>());
        var hostileHello = hello.Data;
        var marker = hostileClientParameters.Encode();
        var markerOffset = hostileHello.AsSpan().IndexOf(marker);
        Assert.True(markerOffset >= 0);
        Assert.Equal(0x21, hostileHello[markerOffset]);
        hostileHello[markerOffset] = (byte)TlsQuicTransportParameterId.StatelessResetToken;

        var failure = await Assert.ThrowsAsync<TlsQuicTransportException>(async () =>
            await server.ProcessCryptoDataAsync(
                TlsQuicEncryptionLevel.Initial,
                hello.Offset,
                hostileHello));
        Assert.Equal(TlsQuicTransportError.TransportParameterError, failure.Error);
    }

    [Fact]
    public async Task RequiredClientCertificateIsAuthenticatedRecordlessly()
    {
        using var serverPki = TestPki.Create();
        using var clientPki = TestPki.Create(
            dnsName: "client.invalid",
            serverAuthenticationEku: false);
        using var serverCredential = new TlsServerCertificate(
            serverPki.Leaf,
            (RSA)serverPki.LeafKey,
            [serverPki.Root]);
        using var clientCredential = new TlsClientCertificate(
            clientPki.Leaf,
            (RSA)clientPki.LeafKey,
            [clientPki.Root]);
        var profile = ClientHelloProfiles.Custom(builder => builder
            .WithTls13()
            .WithCipherSuites(TlsCipherSuite.TlsAes128GcmSha256)
            .WithSupportedGroups(NamedGroup.Secp256r1)
            .WithAlpn("h3")
            .WithQuicTransportParameters(CreateClientParameters()));
        await using var client = new CustomTlsQuicClient(new CustomTlsQuicClientOptions
        {
            ServerName = "example.com",
            ClientHello = profile,
            ClientCertificate = clientCredential,
            CertificateValidation = new CustomTlsCertificateValidationOptions
            {
                CustomTrustRoots = [serverPki.Root],
                RevocationMode = X509RevocationMode.NoCheck,
            },
        });
        await using var server = new CustomTlsQuicServer(new CustomTlsQuicServerOptions
        {
            Tls = new CustomTlsServerOptions
            {
                ServerCertificate = serverCredential,
                CipherSuites = [TlsCipherSuite.TlsAes128GcmSha256],
                SupportedGroups = [NamedGroup.Secp256r1],
                AlpnProtocols = ["h3"],
                ClientAuthentication = TlsServerClientAuthenticationMode.Require,
                ClientCertificateValidation = new CustomTlsCertificateValidationOptions
                {
                    CustomTrustRoots = [clientPki.Root],
                    RevocationMode = X509RevocationMode.NoCheck,
                },
            },
            TransportParameters = CreateServerParameters(),
        });

        using var start = client.StartHandshake();
        var clientHello = Assert.Single(start.Events.OfType<TlsQuicCryptoDataEvent>());
        using var serverFlight = await server.ProcessCryptoDataAsync(
            TlsQuicEncryptionLevel.Initial,
            clientHello.Offset,
            clientHello.Data);
        var serverHello = serverFlight.Events.OfType<TlsQuicCryptoDataEvent>()
            .Single(item => item.Level == TlsQuicEncryptionLevel.Initial);
        using var clientHelloOutput = await client.ProcessCryptoDataAsync(
            TlsQuicEncryptionLevel.Initial,
            serverHello.Offset,
            serverHello.Data);
        var serverHandshake = serverFlight.Events.OfType<TlsQuicCryptoDataEvent>()
            .Single(item => item.Level == TlsQuicEncryptionLevel.Handshake);
        using var clientFlight = await client.ProcessCryptoDataAsync(
            TlsQuicEncryptionLevel.Handshake,
            serverHandshake.Offset,
            serverHandshake.Data);

        var clientMessages = clientFlight.Events.OfType<TlsQuicCryptoDataEvent>()
            .Where(item => item.Level == TlsQuicEncryptionLevel.Handshake)
            .OrderBy(item => item.Offset)
            .ToArray();
        Assert.Equal(3, clientMessages.Length);
        foreach (var clientMessage in clientMessages)
        {
            using var output = await server.ProcessCryptoDataAsync(
                TlsQuicEncryptionLevel.Handshake,
                clientMessage.Offset,
                clientMessage.Data);
        }

        Assert.True(server.IsHandshakeComplete);
        Assert.Equal(clientPki.Leaf.RawData, Assert.Single(
            server.PeerCertificateChain.Take(1)));
    }

    [Fact]
    public async Task ClientAndServerResumeRecordlesslyAndProcessApplicationLevelTickets()
    {
        using var pki = TestPki.Create();
        using var credential = new TlsServerCertificate(
            pki.Leaf,
            (RSA)pki.LeafKey,
            [pki.Root]);
        var ticketKey = RandomNumberGenerator.GetBytes(32);
        using var protector = new Tls13ServerSessionTicketProtector("quic", ticketKey);
        CryptographicOperations.ZeroMemory(ticketKey);
        using var cache = new Tls13SessionCache(capacity: 8);
        var profile = ClientHelloProfiles.Custom(builder => builder
            .WithTls13()
            .WithCipherSuites(TlsCipherSuite.TlsAes128GcmSha256)
            .WithSupportedGroups(NamedGroup.Secp256r1)
            .WithKeyShares(NamedGroup.Secp256r1)
            .WithAlpn("h3")
            .WithQuicTransportParameters(CreateClientParameters())
            .WithSessionResumption()
            .WithExtensionOrder(
                ClientHelloExtensionKind.ServerName,
                ClientHelloExtensionKind.SupportedVersions,
                ClientHelloExtensionKind.SupportedGroups,
                ClientHelloExtensionKind.SignatureAlgorithms,
                ClientHelloExtensionKind.KeyShare,
                ClientHelloExtensionKind.ApplicationLayerProtocolNegotiation,
                ClientHelloExtensionKind.QuicTransportParameters,
                ClientHelloExtensionKind.PskKeyExchangeModes,
                ClientHelloExtensionKind.EarlyData,
                ClientHelloExtensionKind.PreSharedKey));
        var replayedTicketIdentities = new HashSet<string>(StringComparer.Ordinal);

        for (var connection = 0; connection < 4; connection++)
        {
            await using var client = new CustomTlsQuicClient(new CustomTlsQuicClientOptions
            {
                ServerName = "example.com",
                ServerPort = 443,
                ClientHello = profile,
                SessionCache = cache,
                EarlyData = connection > 0
                    ? new TlsQuicEarlyDataOptions(acknowledgeReplayRisk: true)
                    : null,
                CertificateValidation = new CustomTlsCertificateValidationOptions
                {
                    CustomTrustRoots = [pki.Root],
                    RevocationMode = X509RevocationMode.NoCheck,
                },
            });
            await using var server = new CustomTlsQuicServer(new CustomTlsQuicServerOptions
            {
                Tls = new CustomTlsServerOptions
                {
                    ServerCertificate = credential,
                    CipherSuites = [TlsCipherSuite.TlsAes128GcmSha256],
                    SupportedGroups = [NamedGroup.Secp256r1],
                    AlpnProtocols = ["h3"],
                    SessionTicketProtector = protector,
                    AutomaticSessionTicketCount = 2,
                },
                TransportParameters = CreateServerParameters(
                    activeConnectionIdLimit: connection == 3 ? 2UL : 4UL),
                EnableEarlyData = true,
                EarlyDataReplayValidator = (context, _) =>
                {
                    var identity = context.TicketIdentity;
                    try
                    {
                        if (connection == 2)
                        {
                            return ValueTask.FromResult(false);
                        }
                        return ValueTask.FromResult(
                            replayedTicketIdentities.Add(Convert.ToHexString(identity)));
                    }
                    finally
                    {
                        CryptographicOperations.ZeroMemory(identity);
                    }
                },
            });

            using var started = client.StartHandshake();
            if (connection > 0)
            {
                Assert.Single(started.Events.OfType<TlsQuicEarlyDataReadyEvent>());
                Assert.Single(started.Events.OfType<TlsQuicTrafficSecretEvent>(),
                    item => item.Secret.Level == TlsQuicEncryptionLevel.EarlyData &&
                        item.Secret.Direction == TlsQuicSecretDirection.Write);
            }
            var clientHello = Assert.Single(started.Events.OfType<TlsQuicCryptoDataEvent>());
            using var serverFlight = await server.ProcessCryptoDataAsync(
                TlsQuicEncryptionLevel.Initial,
                clientHello.Offset,
                clientHello.Data);
            if (connection == 1)
            {
                AssertSecretPair(
                    started,
                    TlsQuicEncryptionLevel.EarlyData,
                    TlsQuicSecretDirection.Write,
                    serverFlight,
                    TlsQuicSecretDirection.Read);
                Assert.True(server.EarlyDataAccepted);
            }
            else if (connection >= 2)
            {
                Assert.False(server.EarlyDataAccepted);
                Assert.DoesNotContain(
                    serverFlight.Events.OfType<TlsQuicTrafficSecretEvent>(),
                    item => item.Secret.Level == TlsQuicEncryptionLevel.EarlyData);
            }
            var serverHello = serverFlight.Events.OfType<TlsQuicCryptoDataEvent>()
                .Single(item => item.Level == TlsQuicEncryptionLevel.Initial);
            using var clientSecrets = await client.ProcessCryptoDataAsync(
                TlsQuicEncryptionLevel.Initial,
                serverHello.Offset,
                serverHello.Data);
            var serverHandshake = serverFlight.Events.OfType<TlsQuicCryptoDataEvent>()
                .Single(item => item.Level == TlsQuicEncryptionLevel.Handshake);
            using var clientCompleted = await client.ProcessCryptoDataAsync(
                TlsQuicEncryptionLevel.Handshake,
                serverHandshake.Offset,
                serverHandshake.Data);
            var clientFinished = Assert.Single(
                clientCompleted.Events.OfType<TlsQuicCryptoDataEvent>(),
                item => item.Level == TlsQuicEncryptionLevel.Handshake);
            using var serverCompleted = await server.ProcessCryptoDataAsync(
                TlsQuicEncryptionLevel.Handshake,
                clientFinished.Offset,
                clientFinished.Data);

            Assert.Equal(connection > 0, client.SessionWasResumed);
            Assert.Equal(connection > 0, server.SessionWasResumed);
            Assert.Equal(
                connection switch
                {
                    0 => Tls13EarlyDataStatus.NotConfigured,
                    1 => Tls13EarlyDataStatus.Accepted,
                    _ => Tls13EarlyDataStatus.Rejected,
                },
                client.EarlyDataStatus);
            Assert.Equal(2, server.IssuedSessionTicketCount);
            foreach (var ticket in serverCompleted.Events
                .OfType<TlsQuicCryptoDataEvent>()
                .Where(item => item.Level == TlsQuicEncryptionLevel.Application)
                .OrderBy(item => item.Offset))
            {
                using var processed = await client.ProcessCryptoDataAsync(
                    ticket.Level,
                    ticket.Offset,
                    ticket.Data);
                Assert.Empty(processed.Events);
            }
            Assert.True(cache.Count > 0);
        }
    }

    [Fact]
    public async Task ResumptionBinderSurvivesHelloRetryRequestTranscriptRewrite()
    {
        using var pki = TestPki.Create();
        using var credential = new TlsServerCertificate(
            pki.Leaf,
            (RSA)pki.LeafKey,
            [pki.Root]);
        var ticketKey = RandomNumberGenerator.GetBytes(32);
        using var protector = new Tls13ServerSessionTicketProtector("quic-hrr", ticketKey);
        CryptographicOperations.ZeroMemory(ticketKey);
        using var cache = new Tls13SessionCache(capacity: 4);
        var profile = ClientHelloProfiles.Custom(builder => builder
            .WithTls13()
            .WithCipherSuites(TlsCipherSuite.TlsAes128GcmSha256)
            .WithSupportedGroups(NamedGroup.Secp256r1, NamedGroup.Secp384r1)
            .WithKeyShares(NamedGroup.Secp256r1)
            .WithAlpn("h3")
            .WithQuicTransportParameters(CreateClientParameters())
            .WithSessionResumption()
            .WithExtensionOrder(
                ClientHelloExtensionKind.ServerName,
                ClientHelloExtensionKind.SupportedVersions,
                ClientHelloExtensionKind.SupportedGroups,
                ClientHelloExtensionKind.SignatureAlgorithms,
                ClientHelloExtensionKind.KeyShare,
                ClientHelloExtensionKind.ApplicationLayerProtocolNegotiation,
                ClientHelloExtensionKind.QuicTransportParameters,
                ClientHelloExtensionKind.PskKeyExchangeModes,
                ClientHelloExtensionKind.PreSharedKey));

        for (var connection = 0; connection < 2; connection++)
        {
            await using var client = new CustomTlsQuicClient(new CustomTlsQuicClientOptions
            {
                ServerName = "example.com",
                ServerPort = 443,
                ClientHello = profile,
                SessionCache = cache,
                CertificateValidation = new CustomTlsCertificateValidationOptions
                {
                    CustomTrustRoots = [pki.Root],
                    RevocationMode = X509RevocationMode.NoCheck,
                },
            });
            await using var server = new CustomTlsQuicServer(new CustomTlsQuicServerOptions
            {
                Tls = new CustomTlsServerOptions
                {
                    ServerCertificate = credential,
                    CipherSuites = [TlsCipherSuite.TlsAes128GcmSha256],
                    SupportedGroups = connection == 0
                        ? [NamedGroup.Secp256r1]
                        : [NamedGroup.Secp384r1],
                    AlpnProtocols = ["h3"],
                    SessionTicketProtector = protector,
                    AutomaticSessionTicketCount = 1,
                },
                TransportParameters = CreateServerParameters(),
            });

            using var started = client.StartHandshake();
            var firstHello = Assert.Single(started.Events.OfType<TlsQuicCryptoDataEvent>());
            using var firstServerOutput = await server.ProcessCryptoDataAsync(
                TlsQuicEncryptionLevel.Initial,
                firstHello.Offset,
                firstHello.Data);
            TlsQuicProcessResult? retryClientOutput = null;
            TlsQuicProcessResult? retriedServerFlight = null;
            TlsQuicProcessResult serverFlight = firstServerOutput;
            try
            {
                if (connection == 1)
                {
                    var retry = Assert.Single(
                        firstServerOutput.Events.OfType<TlsQuicCryptoDataEvent>());
                    retryClientOutput = await client.ProcessCryptoDataAsync(
                        TlsQuicEncryptionLevel.Initial,
                        retry.Offset,
                        retry.Data);
                    var secondHello = Assert.Single(
                        retryClientOutput.Events.OfType<TlsQuicCryptoDataEvent>());
                    retriedServerFlight = await server.ProcessCryptoDataAsync(
                        TlsQuicEncryptionLevel.Initial,
                        secondHello.Offset,
                        secondHello.Data);
                    serverFlight = retriedServerFlight;
                }

                var serverHello = serverFlight.Events.OfType<TlsQuicCryptoDataEvent>()
                    .Single(value => value.Level == TlsQuicEncryptionLevel.Initial);
                using var clientSecrets = await client.ProcessCryptoDataAsync(
                    TlsQuicEncryptionLevel.Initial,
                    serverHello.Offset,
                    serverHello.Data);
                var serverHandshake = serverFlight.Events.OfType<TlsQuicCryptoDataEvent>()
                    .Single(value => value.Level == TlsQuicEncryptionLevel.Handshake);
                using var clientCompleted = await client.ProcessCryptoDataAsync(
                    TlsQuicEncryptionLevel.Handshake,
                    serverHandshake.Offset,
                    serverHandshake.Data);
                var clientFinished = Assert.Single(
                    clientCompleted.Events.OfType<TlsQuicCryptoDataEvent>(),
                    value => value.Level == TlsQuicEncryptionLevel.Handshake);
                using var serverCompleted = await server.ProcessCryptoDataAsync(
                    TlsQuicEncryptionLevel.Handshake,
                    clientFinished.Offset,
                    clientFinished.Data);

                Assert.True(client.IsHandshakeComplete);
                Assert.True(server.IsHandshakeComplete);
                Assert.Equal(connection == 1, client.SessionWasResumed);
                Assert.Equal(connection == 1, server.SessionWasResumed);
                Assert.Equal(connection == 1, client.HandshakeUsedHelloRetryRequest);
                Assert.Equal(connection == 1, server.HandshakeUsedHelloRetryRequest);
                Assert.Equal(
                    connection == 0 ? NamedGroup.Secp256r1 : NamedGroup.Secp384r1,
                    client.NegotiatedGroup);
                foreach (var ticket in serverCompleted.Events
                    .OfType<TlsQuicCryptoDataEvent>()
                    .Where(value => value.Level == TlsQuicEncryptionLevel.Application))
                {
                    using var processed = await client.ProcessCryptoDataAsync(
                        ticket.Level,
                        ticket.Offset,
                        ticket.Data);
                }
            }
            finally
            {
                retryClientOutput?.Dispose();
                retriedServerFlight?.Dispose();
            }
        }
    }

    private static void AssertSecretPair(
        TlsQuicProcessResult first,
        TlsQuicEncryptionLevel level,
        TlsQuicSecretDirection firstDirection,
        TlsQuicProcessResult second,
        TlsQuicSecretDirection secondDirection)
    {
        var firstSecret = first.Events.OfType<TlsQuicTrafficSecretEvent>()
            .Single(item => item.Secret.Level == level &&
                item.Secret.Direction == firstDirection).Secret.CopySecret();
        var secondSecret = second.Events.OfType<TlsQuicTrafficSecretEvent>()
            .Single(item => item.Secret.Level == level &&
                item.Secret.Direction == secondDirection).Secret.CopySecret();
        try
        {
            Assert.Equal(firstSecret, secondSecret);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(firstSecret);
            CryptographicOperations.ZeroMemory(secondSecret);
        }
    }

    private static TlsQuicTransportParameters CreateClientParameters() => new(
    [
        new TlsQuicTransportParameter(
            (ulong)TlsQuicTransportParameterId.InitialSourceConnectionId,
            [1, 2, 3, 4]),
        TlsQuicTransportParameter.VariableInteger(
            TlsQuicTransportParameterId.MaxUdpPayloadSize,
            1400),
        TlsQuicTransportParameter.VariableInteger(
            TlsQuicTransportParameterId.ActiveConnectionIdLimit,
            2),
    ]);

    private static TlsQuicTransportParameters CreateServerParameters(
        ulong activeConnectionIdLimit = 4) => new(
    [
        new TlsQuicTransportParameter(
            (ulong)TlsQuicTransportParameterId.OriginalDestinationConnectionId,
            [0xA0, 0xA1, 0xA2]),
        new TlsQuicTransportParameter(
            (ulong)TlsQuicTransportParameterId.InitialSourceConnectionId,
            [0xB0, 0xB1, 0xB2]),
        TlsQuicTransportParameter.VariableInteger(
            TlsQuicTransportParameterId.ActiveConnectionIdLimit,
            activeConnectionIdLimit),
    ]);

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
