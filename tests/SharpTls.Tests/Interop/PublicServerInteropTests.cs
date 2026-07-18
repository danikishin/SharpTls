using System.Text;
using System.Net.Sockets;
using System.Reflection;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using SharpTls.Protocol;
using SharpTls.Tests.ClientHello;

namespace SharpTls.Tests.Interop;

[Collection(nameof(PublicInteropCollection))]
public sealed class PublicServerInteropTests
{
    [InteropFact]
    [Trait("Category", "Interop")]
    public async Task EverySecurelyExecutablePinnedProfileAuthenticatesAgainstTwoIndependentDeployments()
    {
        string[] hosts = ["example.com", "www.cloudflare.com"];
        foreach (var propertyName in UTlsUpstreamCoverageTests.PinnedPropertyNames)
        {
            // The exact 360/7.5 capture predates Extended Master Secret and is retained
            // only as a deterministic wire specification. SharpTls never weakens its
            // TLS 1.2 policy to execute that unsafe legacy image.
            if (propertyName == "UTls360_7_5")
            {
                continue;
            }
            var property = typeof(ClientHelloProfiles).GetProperty(
                propertyName,
                BindingFlags.Public | BindingFlags.Static);
            var profile = Assert.IsType<ClientHelloProfile>(property?.GetValue(null));
            foreach (var host in hosts)
            {
                try
                {
                    await using var client = await ConnectAsync(
                        profile,
                        host,
                        disableRevocationForEndpoint: host == "www.cloudflare.com");
                    Assert.True(client.IsConnected, $"{propertyName} did not authenticate {host}.");
                    Assert.Contains(
                        client.NegotiatedProtocolVersion!.Value,
                        profile.Spec.SupportedVersions);
                    Assert.Contains(
                        client.NegotiatedCipherSuite!.Value,
                        profile.Spec.CipherSuites);
                }
                catch (Exception exception)
                {
                    throw new InvalidOperationException(
                        $"Pinned profile {propertyName} failed against {host}.",
                        exception);
                }
            }
        }
    }

    [InteropFact]
    [Trait("Category", "Interop")]
    public async Task Aes128P256HandshakeAndHttp11()
    {
        var client = await ConnectAsync(ClientHelloProfiles.Custom(builder => builder
            .WithCipherSuites(TlsCipherSuite.TlsAes128GcmSha256)
            .WithSupportedGroups(NamedGroup.Secp256r1)));
        await using (client)
        {
            Assert.Equal(TlsCipherSuite.TlsAes128GcmSha256, client.NegotiatedCipherSuite);
            Assert.Equal(NamedGroup.Secp256r1, client.NegotiatedGroup);
            await AssertHttpResponseAsync(client);
        }
    }

    [InteropFact]
    [Trait("Category", "Interop")]
    public async Task Aes256P384HandshakeAndHttp11()
    {
        var client = await ConnectAsync(ClientHelloProfiles.Custom(builder => builder
            .WithCipherSuites(TlsCipherSuite.TlsAes256GcmSha384)
            .WithSupportedGroups(NamedGroup.Secp384r1)));
        await using (client)
        {
            Assert.Equal(TlsCipherSuite.TlsAes256GcmSha384, client.NegotiatedCipherSuite);
            Assert.Equal(NamedGroup.Secp384r1, client.NegotiatedGroup);
            await AssertHttpResponseAsync(client);
        }
    }

    [InteropFact]
    [Trait("Category", "Interop")]
    public async Task Aes128X25519HandshakeAndHttp11()
    {
        var client = await ConnectAsync(ClientHelloProfiles.Custom(builder => builder
            .WithCipherSuites(TlsCipherSuite.TlsAes128GcmSha256)
            .WithSupportedGroups(NamedGroup.X25519)));
        await using (client)
        {
            Assert.Equal(TlsCipherSuite.TlsAes128GcmSha256, client.NegotiatedCipherSuite);
            Assert.Equal(NamedGroup.X25519, client.NegotiatedGroup);
            await AssertHttpResponseAsync(client);
        }
    }

    [InteropFact]
    [Trait("Category", "Interop")]
    public async Task UTlsChrome83ProfileCompletesTls13Handshake()
    {
        await using var client = await ConnectAsync(ClientHelloProfiles.UTlsChrome83);

        Assert.Equal(NamedGroup.X25519, client.NegotiatedGroup);
        Assert.True(client.NegotiatedCipherSuite.HasValue);
        Assert.Contains(
            client.NegotiatedCipherSuite.Value,
            new[]
            {
                TlsCipherSuite.TlsAes128GcmSha256,
                TlsCipherSuite.TlsAes256GcmSha384,
                TlsCipherSuite.TlsChaCha20Poly1305Sha256,
            });
    }

    [InteropFact]
    [Trait("Category", "Interop")]
    public async Task UTlsFirefox99ProfileCompletesTls13Handshake()
    {
        await using var client = await ConnectAsync(ClientHelloProfiles.UTlsFirefox99);

        Assert.Contains(
            client.NegotiatedGroup,
            new NamedGroup?[] { NamedGroup.X25519, NamedGroup.Secp256r1 });
    }

    [InteropFact]
    [Trait("Category", "Interop")]
    public async Task UTlsSafari16ProfileCompletesTls13Handshake()
    {
        await using var client = await ConnectAsync(ClientHelloProfiles.UTlsSafari16);

        Assert.Equal(NamedGroup.X25519, client.NegotiatedGroup);
    }

    [InteropFact]
    [Trait("Category", "Interop")]
    public async Task UTlsIOS14ProfileCompletesTls13Handshake()
    {
        await using var client = await ConnectAsync(ClientHelloProfiles.UTlsIOS14);

        Assert.Equal(NamedGroup.X25519, client.NegotiatedGroup);
    }

    [InteropFact]
    [Trait("Category", "Interop")]
    public async Task AdditionalPinnedUTlsProfilesCompleteTls13Handshake()
    {
        var profiles = new (string Name, ClientHelloProfile Profile)[]
        {
            ("Chrome 70", ClientHelloProfiles.UTlsChrome70),
            ("Chrome 72", ClientHelloProfiles.UTlsChrome72),
            ("Chrome 96", ClientHelloProfiles.UTlsChrome96),
            ("Chrome 100", ClientHelloProfiles.UTlsChrome100),
            ("Chrome 106 Shuffle", ClientHelloProfiles.UTlsChrome106Shuffle),
            ("Firefox 63", ClientHelloProfiles.UTlsFirefox63),
            ("Firefox 102", ClientHelloProfiles.UTlsFirefox102),
            ("Firefox 105", ClientHelloProfiles.UTlsFirefox105),
            ("Firefox 120", ClientHelloProfiles.UTlsFirefox120),
            ("iOS 13", ClientHelloProfiles.UTlsIOS13),
            ("360 11.0", ClientHelloProfiles.UTls360_11_0),
            ("QQ 11.1", ClientHelloProfiles.UTlsQQ11_1),
        };

        foreach (var (name, profile) in profiles)
        {
            await using var client = await ConnectAsync(profile);

            Assert.True(
                client.NegotiatedProtocolVersion == TlsProtocolVersion.Tls13,
                name);
            Assert.Contains(
                client.NegotiatedGroup,
                new NamedGroup?[] { NamedGroup.X25519, NamedGroup.Secp256r1 });
        }
    }

    [InteropFact]
    [Trait("Category", "Interop")]
    public async Task LegacyPinnedUTlsProfilesCompleteRestrictedTls12Handshake()
    {
        var profiles = new (string Name, ClientHelloProfile Profile)[]
        {
            ("Chrome 58", ClientHelloProfiles.UTlsChrome58),
            ("Firefox 55", ClientHelloProfiles.UTlsFirefox55),
            ("iOS 11.1", ClientHelloProfiles.UTlsIOS11_1),
            ("iOS 12.1", ClientHelloProfiles.UTlsIOS12_1),
        };

        foreach (var (name, profile) in profiles)
        {
            await using var client = await ConnectAsync(profile);
            Assert.True(client.NegotiatedProtocolVersion == TlsProtocolVersion.Tls12, name);
        }
    }

    [InteropFact]
    [Trait("Category", "Interop")]
    public async Task UTlsAndroid11OkHttpCompletesTls12HandshakeAndHttp11()
    {
        await using var client = await ConnectAsync(ClientHelloProfiles.UTlsAndroid11OkHttp);

        Assert.Equal(TlsProtocolVersion.Tls12, client.NegotiatedProtocolVersion);
        Assert.Contains(
            client.NegotiatedCipherSuite,
            new TlsCipherSuite?[]
            {
                TlsCipherSuite.TlsEcdheEcdsaWithAes128GcmSha256,
                TlsCipherSuite.TlsEcdheEcdsaWithAes256GcmSha384,
                TlsCipherSuite.TlsEcdheEcdsaWithChaCha20Poly1305Sha256,
                TlsCipherSuite.TlsEcdheRsaWithAes128GcmSha256,
                TlsCipherSuite.TlsEcdheRsaWithAes256GcmSha384,
                TlsCipherSuite.TlsEcdheRsaWithChaCha20Poly1305Sha256,
            });
        Assert.Contains(
            client.NegotiatedGroup,
            new NamedGroup?[] { NamedGroup.X25519, NamedGroup.Secp256r1, NamedGroup.Secp384r1 });
        await AssertHttpResponseAsync(client);
    }

    [InteropFact]
    [Trait("Category", "Interop")]
    public async Task Aes128P521HandshakeAndHttp11()
    {
        var client = await ConnectAsync(ClientHelloProfiles.Custom(builder => builder
            .WithCipherSuites(TlsCipherSuite.TlsAes128GcmSha256)
            .WithSupportedGroups(NamedGroup.Secp521r1)));
        await using (client)
        {
            Assert.Equal(TlsCipherSuite.TlsAes128GcmSha256, client.NegotiatedCipherSuite);
            Assert.Equal(NamedGroup.Secp521r1, client.NegotiatedGroup);
            await AssertHttpResponseAsync(client);
        }
    }

    [InteropFact(requiresChaCha: true)]
    [Trait("Category", "Interop")]
    public async Task ChaCha20P256HandshakeAndHttp11()
    {
        var client = await ConnectAsync(ClientHelloProfiles.Custom(builder => builder
            .WithCipherSuites(TlsCipherSuite.TlsChaCha20Poly1305Sha256)
            .WithSupportedGroups(NamedGroup.Secp256r1)));
        await using (client)
        {
            Assert.Equal(TlsCipherSuite.TlsChaCha20Poly1305Sha256, client.NegotiatedCipherSuite);
            await AssertHttpResponseAsync(client);
        }
    }

    [InteropFact]
    [Trait("Category", "Interop")]
    public async Task EmptyKeyShareForcesHelloRetryRequest()
    {
        var client = await ConnectAsync(ClientHelloProfiles.Custom(builder => builder
            .WithCipherSuites(TlsCipherSuite.TlsAes128GcmSha256)
            .WithSupportedGroups(NamedGroup.Secp256r1)
            .WithKeyShares()));
        await using (client)
        {
            Assert.True(client.HandshakeUsedHelloRetryRequest);
            Assert.Equal(NamedGroup.Secp256r1, client.NegotiatedGroup);
            await AssertHttpResponseAsync(client);
        }
    }

    [InteropFact]
    [Trait("Category", "Interop")]
    public async Task IndependentGoogleEndpointCompletesHttp11()
    {
        const string host = "www.google.com";
        var client = await ConnectAsync(
            ClientHelloProfiles.Custom(builder => builder.WithAlpn("http/1.1")),
            host);
        await using (client)
        {
            Assert.Equal("http/1.1", client.NegotiatedApplicationProtocol);
            await AssertHttpResponseAsync(client, host);
        }
    }

    [InteropFact]
    [Trait("Category", "Interop")]
    public async Task PrivateUseRawExtensionIsIgnoredByPublicServer()
    {
        var client = await ConnectAsync(ClientHelloProfiles.Custom(builder => builder
            .WithExtensionLayout(
                ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.ServerName),
                ClientHelloExtensionSpec.Raw(0xFDE8, [1, 3, 3, 7]),
                ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.SupportedVersions),
                ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.SupportedGroups),
                ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.SignatureAlgorithms),
                ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.KeyShare))));
        await using (client)
        {
            await AssertHttpResponseAsync(client);
        }
    }

    [InteropFact]
    [Trait("Category", "Interop")]
    public async Task CallerOwnedTransportAndStreamCompleteHttp11()
    {
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        using var socket = new Socket(SocketType.Stream, ProtocolType.Tcp);
        await socket.ConnectAsync("example.com", 443, timeout.Token);
        await using var transport = new NetworkStream(socket, ownsSocket: false);
        await using var client = new CustomTlsClient(new CustomTlsClientOptions
        {
            ServerName = "example.com",
            ClientHello = ClientHelloProfiles.Custom(builder => builder.WithAlpn("http/1.1")),
        });

        await client.AuthenticateAsync(
            transport,
            "example.com",
            leaveOpen: true,
            timeout.Token);
        await using var stream = client.OpenApplicationStream(leaveClientOpen: true);
        await stream.WriteAsync(
            "HEAD / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n"u8.ToArray(),
            timeout.Token);
        var response = new byte[128];
        var read = await stream.ReadAsync(response, timeout.Token);

        Assert.True(read > 0);
        Assert.StartsWith(
            "HTTP/1.1 ",
            Encoding.ASCII.GetString(response, 0, read),
            StringComparison.Ordinal);
    }

    [InteropFact]
    [Trait("Category", "Interop")]
    public async Task SecureRandomizedProfileCompletesHttp11()
    {
        var profile = ClientHelloProfileRandomizer.CreateSecure(
            new ClientHelloRandomizationOptions
            {
                AlpnVariants = [new ClientHelloAlpnVariant(1, "http/1.1")],
            });
        var client = await ConnectAsync(profile);
        await using (client)
        {
            Assert.Equal("http/1.1", client.NegotiatedApplicationProtocol);
            await AssertHttpResponseAsync(client);
        }
    }

    [InteropFact]
    [Trait("Category", "Interop")]
    public async Task RollerCachesAuthenticatedPublicServerProfile()
    {
        var roller = new ClientHelloProfileRoller(new ClientHelloRollerOptions
        {
            InitialRetryDelay = TimeSpan.Zero,
            MaximumRetryDelay = TimeSpan.Zero,
            // This assertion writes HTTP/1.1 bytes. The default pinned uTLS family pool
            // intentionally offers h2 first, so use the HTTP/1.1-only randomized member.
            CandidateProfiles = [],
            Randomization = new ClientHelloRandomizationOptions
            {
                AlpnVariants = [new ClientHelloAlpnVariant(1, "http/1.1")],
            },
        });
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        var client = await roller.ConnectAsync(
            new CustomTlsClientOptions { ServerName = "example.com" },
            "example.com",
            443,
            timeout.Token);
        await using (client)
        {
            Assert.Equal(1, roller.CachedOriginCount);
            await AssertHttpResponseAsync(client);
        }
    }

    [InteropFact]
    [Trait("Category", "Interop")]
    public async Task ClientAndRequestedServerKeyUpdatePreserveHttp11Traffic()
    {
        var client = await ConnectAsync(ClientHelloProfiles.Custom(builder =>
            builder.WithAlpn("http/1.1")));
        await using (client)
        {
            using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(20));
            var beforeUpdate = client.ExportKeyingMaterial(
                "EXPORTER-SharpTls-interop",
                "example.com"u8,
                32);
            await client.RequestKeyUpdateAsync(requestPeerUpdate: true, timeout.Token);
            await AssertHttpResponseAsync(client);

            Assert.Equal(1UL, client.ClientKeyUpdateCount);
            Assert.True(client.ServerKeyUpdateCount >= 1UL);
            Assert.Equal(
                beforeUpdate,
                client.ExportKeyingMaterial(
                    "EXPORTER-SharpTls-interop",
                    "example.com"u8,
                    32));
            CryptographicOperations.ZeroMemory(beforeUpdate);
        }
    }

    [InteropFact]
    [Trait("Category", "Interop")]
    public async Task SessionTicketResumesASecondAuthenticatedConnection()
    {
        using var cache = new Tls13SessionCache();
        await using (var first = await ConnectAsync(
            ClientHelloProfiles.ModernTls13,
            sessionCache: cache))
        {
            Assert.False(first.SessionWasResumed);
            await AssertHttpResponseAsync(first);
            Assert.True(cache.Count > 0);
        }

        await using var second = await ConnectAsync(
            ClientHelloProfiles.ModernTls13,
            sessionCache: cache);
        Assert.True(second.SessionWasResumed);
        await AssertHttpResponseAsync(second);
    }

    [InteropFact]
    [Trait("Category", "Interop")]
    public async Task SessionTicketResumptionSurvivesHelloRetryRequest()
    {
        using var cache = new Tls13SessionCache();
        var profile = ClientHelloProfiles.Custom(builder => builder
            .WithCipherSuites(TlsCipherSuite.TlsAes128GcmSha256)
            .WithSupportedGroups(NamedGroup.Secp256r1)
            .WithKeyShares()
            .WithSessionResumption());

        await using (var first = await ConnectAsync(profile, sessionCache: cache))
        {
            Assert.True(first.HandshakeUsedHelloRetryRequest);
            await AssertHttpResponseAsync(first);
            Assert.True(cache.Count > 0);
        }

        await using var second = await ConnectAsync(profile, sessionCache: cache);
        Assert.True(second.HandshakeUsedHelloRetryRequest);
        Assert.True(second.SessionWasResumed);
        await AssertHttpResponseAsync(second);
    }

    [InteropFact]
    [Trait("Category", "Interop")]
    public async Task SessionTicketResumesAtIndependentGoogleEndpoint()
    {
        const string host = "www.google.com";
        using var cache = new Tls13SessionCache();
        await using (var first = await ConnectAsync(
            ClientHelloProfiles.ModernTls13,
            host,
            sessionCache: cache))
        {
            await AssertHttpResponseAsync(first, host);
            Assert.True(cache.Count > 0);
        }

        await using var second = await ConnectAsync(
            ClientHelloProfiles.ModernTls13,
            host,
            sessionCache: cache);
        Assert.True(second.SessionWasResumed);
        await AssertHttpResponseAsync(second, host);
    }

    [InteropFact(requiresEarlyDataEndpoint: true)]
    [Trait("Category", "Interop")]
    public async Task ReplayAcknowledgedEarlyHttpRequestIsAccepted()
    {
        var host = Environment.GetEnvironmentVariable("SHARPTLS_EARLY_DATA_HOST")!;
        using var cache = new Tls13SessionCache();
        await using (var first = await ConnectAsync(
            ClientHelloProfiles.ModernTls13,
            host,
            sessionCache: cache,
            disableRevocationForEndpoint: true))
        {
            await AssertHttpResponseAsync(first, host);
            Assert.True(cache.Count > 0);
        }

        var request = Encoding.ASCII.GetBytes(
            $"HEAD / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n");
        var earlyData = new Tls13EarlyDataOptions(
            request,
            acknowledgeReplayRisk: true,
            Tls13EarlyDataRejectionPolicy.RetransmitAfterHandshake);
        await using var second = await ConnectAsync(
            ClientHelloProfiles.ModernTls13,
            host,
            sessionCache: cache,
            earlyData: earlyData,
            disableRevocationForEndpoint: true);

        Assert.Equal(Tls13EarlyDataStatus.Accepted, second.EarlyDataStatus);
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        var response = await second.ReadApplicationDataAsync(timeout.Token);
        Assert.NotNull(response);
        Assert.StartsWith(
            "HTTP/1.1 ",
            Encoding.ASCII.GetString(response),
            StringComparison.Ordinal);
    }

    private static async Task<CustomTlsClient> ConnectAsync(
        ClientHelloProfile profile,
        string host = "example.com",
        int port = 443,
        Tls13SessionCache? sessionCache = null,
        Tls13EarlyDataOptions? earlyData = null,
        bool disableRevocationForEndpoint = false)
    {
        var client = new CustomTlsClient(new CustomTlsClientOptions
        {
            ServerName = host,
            ClientHello = profile,
            SessionCache = sessionCache,
            EarlyData = earlyData,
            CertificateValidation = new CustomTlsCertificateValidationOptions
            {
                // Cloudflare's test endpoint does not always expose a reachable
                // revocation responder. Keep this exception local to the smoke test.
                RevocationMode = disableRevocationForEndpoint
                    ? X509RevocationMode.NoCheck
                    : X509RevocationMode.Online,
            },
        });
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        await client.ConnectAsync(host, port, timeout.Token);
        return client;
    }

    private static async Task AssertHttpResponseAsync(
        CustomTlsClient client,
        string host = "example.com")
    {
        var request = Encoding.ASCII.GetBytes(
            $"HEAD / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n");
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        await client.WriteApplicationDataAsync(request, timeout.Token);
        var first = await client.ReadApplicationDataAsync(timeout.Token);
        Assert.NotNull(first);
        Assert.StartsWith("HTTP/1.1 ", Encoding.ASCII.GetString(first), StringComparison.Ordinal);
    }
}

[CollectionDefinition(nameof(PublicInteropCollection), DisableParallelization = true)]
public sealed class PublicInteropCollection;

public sealed class InteropFactAttribute : FactAttribute
{
    public InteropFactAttribute(
        bool requiresChaCha = false,
        bool requiresEarlyDataEndpoint = false)
    {
        if (!string.Equals(
            Environment.GetEnvironmentVariable("SHARPTLS_RUN_INTEROP"),
            "1",
            StringComparison.Ordinal))
        {
            Skip = "Set SHARPTLS_RUN_INTEROP=1 to enable public-network interoperability tests.";
        }
        else if (requiresChaCha && !System.Security.Cryptography.ChaCha20Poly1305.IsSupported)
        {
            Skip = "ChaCha20-Poly1305 is unavailable on this runtime.";
        }
        else if (requiresEarlyDataEndpoint && string.IsNullOrWhiteSpace(
            Environment.GetEnvironmentVariable("SHARPTLS_EARLY_DATA_HOST")))
        {
            Skip = "Set SHARPTLS_EARLY_DATA_HOST to an endpoint that advertises TLS 1.3 early data.";
        }
    }
}
