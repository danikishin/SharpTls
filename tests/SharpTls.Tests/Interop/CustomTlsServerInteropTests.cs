using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using SharpTls.Certificates;
using SharpTls.Handshake;
using SharpTls.Protocol;
using SharpTls.Tests.Certificates;
using TlsCipherSuite = SharpTls.Protocol.TlsCipherSuite;

namespace SharpTls.Tests.Interop;

public sealed class CustomTlsServerInteropTests
{
    [NonAppleTlsTheory]
    [InlineData(SslProtocols.Tls13, TlsProtocolVersion.Tls13)]
    [InlineData(SslProtocols.Tls12, TlsProtocolVersion.Tls12)]
    public async Task PlatformSslStreamClientAuthenticatesSharpTlsServerAndExchangesTraffic(
        SslProtocols platformProtocol,
        TlsProtocolVersion expectedVersion)
    {
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        using var pki = TestPki.Create();
        using var credential = new TlsServerCertificate(
            pki.Leaf,
            (RSA)pki.LeafKey,
            [pki.Root]);
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start(1);
        var port = ((IPEndPoint)listener.LocalEndpoint).Port;

        var serverTask = Task.Run(async () =>
        {
            using var socket = await listener.AcceptSocketAsync(timeout.Token);
            await using var server = new CustomTlsServer(new CustomTlsServerOptions
            {
                ServerCertificate = credential,
                SupportedVersions = [expectedVersion],
                CipherSuites = [TlsCipherSuite.TlsAes128GcmSha256],
                Tls12CipherSuites =
                    [TlsCipherSuite.TlsEcdheRsaWithAes128GcmSha256],
                SupportedGroups =
                    [NamedGroup.X25519, NamedGroup.Secp256r1, NamedGroup.Secp384r1],
                AlpnProtocols = ["http/1.1"],
                RequireAlpn = true,
            });
            await server.AuthenticateAsync(socket, ownsSocket: true, timeout.Token);
            Assert.Equal(expectedVersion, server.NegotiatedProtocolVersion);
            Assert.Equal("example.com", server.ServerName);
            Assert.Equal("http/1.1", server.NegotiatedApplicationProtocol);
            Assert.Equal(
                "platform-ping"u8.ToArray(),
                await server.ReadApplicationDataAsync(timeout.Token));
            await server.WriteApplicationDataAsync(
                    "sharptls-pong"u8.ToArray(),
                    timeout.Token);
        }, timeout.Token);

        using var tcpClient = new TcpClient(AddressFamily.InterNetwork);
        await tcpClient.ConnectAsync(IPAddress.Loopback, port, timeout.Token);
        await using var platformClient = new SslStream(
            tcpClient.GetStream(),
            leaveInnerStreamOpen: false,
            (_, certificate, _, _) => certificate is not null &&
                certificate.GetRawCertData().AsSpan().SequenceEqual(pki.Leaf.RawData));
        try
        {
            await platformClient.AuthenticateAsClientAsync(
                new SslClientAuthenticationOptions
                {
                    TargetHost = "example.com",
                    EnabledSslProtocols = platformProtocol,
                    CertificateRevocationCheckMode = X509RevocationMode.NoCheck,
                    ApplicationProtocols = [SslApplicationProtocol.Http11],
                },
                timeout.Token);
        }
        catch (Exception clientException)
        {
            try
            {
                await serverTask.WaitAsync(timeout.Token);
            }
            catch (Exception serverException)
            {
                throw new AggregateException(clientException, serverException);
            }
            throw;
        }

        Assert.Equal(platformProtocol, platformClient.SslProtocol);
        Assert.Equal(SslApplicationProtocol.Http11, platformClient.NegotiatedApplicationProtocol);
        await platformClient.WriteAsync("platform-ping"u8.ToArray(), timeout.Token);
        await platformClient.FlushAsync(timeout.Token);
        var response = new byte["sharptls-pong"u8.Length];
        await platformClient.ReadExactlyAsync(response, timeout.Token);
        Assert.Equal("sharptls-pong"u8.ToArray(), response);
        await serverTask.WaitAsync(timeout.Token);
    }

    [Fact]
    public async Task TlsListenerAcceptsAndAuthenticatesIndependentConnection()
    {
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        using var pki = TestPki.Create();
        using var credential = new TlsServerCertificate(
            pki.Leaf,
            (RSA)pki.LeafKey,
            [pki.Root]);
        await using var listener = new CustomTlsListener(
            new IPEndPoint(IPAddress.Loopback, 0),
            () => new CustomTlsServerOptions
            {
                ServerCertificate = credential,
                CipherSuites = [TlsCipherSuite.TlsAes128GcmSha256],
                SupportedGroups = [NamedGroup.Secp256r1],
                AlpnProtocols = ["http/1.1"],
            });
        listener.Start();
        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        var accepted = listener.AcceptConnectionAsync(timeout.Token).AsTask();

        await using var client = new CustomTlsClient(new CustomTlsClientOptions
        {
            ServerName = "example.com",
            ClientHello = ClientHelloProfiles.Custom(builder => builder
                .WithTls13()
                .WithCipherSuites(TlsCipherSuite.TlsAes128GcmSha256)
                .WithSupportedGroups(NamedGroup.Secp256r1)
                .WithKeyShares(NamedGroup.Secp256r1)
                .WithAlpn("http/1.1")),
            CertificateValidation = new CustomTlsCertificateValidationOptions
            {
                CustomTrustRoots = [pki.Root],
                RevocationMode = X509RevocationMode.NoCheck,
            },
        });
        await client.ConnectAsync(IPAddress.Loopback.ToString(), port, timeout.Token);
        await using var server = await accepted.WaitAsync(timeout.Token);
        Assert.True(server.IsAuthenticated);
        Assert.Equal("http/1.1", server.NegotiatedApplicationProtocol);
        Assert.Null(client.GetConnectionState().TlsUnique);
        await client.WriteApplicationDataAsync("ping"u8.ToArray(), timeout.Token);
        Assert.Equal("ping"u8.ToArray(),
            await server.ReadApplicationDataAsync(timeout.Token));
    }

    [Theory]
    [InlineData(TlsProtocolVersion.Tls13)]
    [InlineData(TlsProtocolVersion.Tls12)]
    public async Task DangerousCertificateBypassCompletesOtherwiseUntrustedHandshake(
        TlsProtocolVersion version)
    {
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        using var pki = TestPki.Create(dnsName: "certificate.example");
        using var credential = new TlsServerCertificate(
            pki.Leaf,
            (RSA)pki.LeafKey,
            [pki.Root]);
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start(1);
        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        var serverTask = Task.Run(async () =>
        {
            using var socket = await listener.AcceptSocketAsync(timeout.Token);
            await using var server = new CustomTlsServer(new CustomTlsServerOptions
            {
                ServerCertificate = credential,
                SupportedVersions = [version],
                CipherSuites = [TlsCipherSuite.TlsAes128GcmSha256],
                Tls12CipherSuites = [TlsCipherSuite.TlsEcdheRsaWithAes128GcmSha256],
                SupportedGroups = [NamedGroup.Secp256r1],
            });
            await server.AuthenticateAsync(socket, ownsSocket: true, timeout.Token);
            Assert.Equal(
                "dangerous-mode-ping"u8.ToArray(),
                await server.ReadApplicationDataAsync(timeout.Token));
        }, timeout.Token);

        var profile = version == TlsProtocolVersion.Tls13
            ? ClientHelloProfiles.Custom(builder => builder
                .WithTls13()
                .WithCipherSuites(TlsCipherSuite.TlsAes128GcmSha256)
                .WithSupportedGroups(NamedGroup.Secp256r1)
                .WithKeyShares(NamedGroup.Secp256r1))
            : ClientHelloProfiles.Custom(builder => builder
                .WithLegacyTls12ClientHello()
                .WithCipherSuites(TlsCipherSuite.TlsEcdheRsaWithAes128GcmSha256)
                .WithSupportedGroups(NamedGroup.Secp256r1)
                .WithSignatureAlgorithms(
                    SignatureScheme.RsaPssRsaeSha256,
                    SignatureScheme.RsaPkcs1Sha256)
                .WithExtensionLayout(
                    ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.ServerName),
                    ClientHelloExtensionSpec.Raw(
                        (ushort)TlsExtensionType.ExtendedMasterSecret,
                        []),
                    ClientHelloExtensionSpec.Raw(
                        (ushort)TlsExtensionType.RenegotiationInfo,
                        [0]),
                    ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.SupportedGroups),
                    ClientHelloExtensionSpec.Raw(
                        (ushort)TlsExtensionType.EcPointFormats,
                        [1, 0]),
                    ClientHelloExtensionSpec.BuiltIn(
                        ClientHelloExtensionKind.SignatureAlgorithms)));
        await using var client = new CustomTlsClient(new CustomTlsClientOptions
        {
            ServerName = "wrong.example",
            ClientHello = profile,
            CertificateValidation = new CustomTlsCertificateValidationOptions
            {
                DangerouslySkipServerCertificateValidation = true,
            },
        });

        await client.ConnectAsync(IPAddress.Loopback.ToString(), port, timeout.Token);
        Assert.Equal(version, client.NegotiatedProtocolVersion);
        Assert.True(client.GetConnectionState().ServerCertificateValidationSkipped);
        await client.WriteApplicationDataAsync(
            "dangerous-mode-ping"u8.ToArray(),
            timeout.Token);
        await serverTask.WaitAsync(timeout.Token);
    }

    [Theory]
    [InlineData(TlsProtocolVersion.Tls13)]
    [InlineData(TlsProtocolVersion.Tls12)]
    public async Task ServerStapledOcspAndSctsAreAuthenticatedWhenRequested(
        TlsProtocolVersion version)
    {
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        using var pki = TestPki.Create();
        byte[] ocsp = [0x30, 0x03, 0x0A, 0x01, 0x00];
        byte[][] scts = [[1, 2, 3], [4, 5, 6, 7]];
        var presentation = new TlsServerCertificatePresentation(ocsp, scts);
        using var credential = new TlsServerCertificate(
            pki.Leaf,
            (RSA)pki.LeafKey,
            [pki.Root],
            presentation);
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        var serverTask = Task.Run(async () =>
        {
            using var socket = await listener.AcceptSocketAsync(timeout.Token);
            listener.Stop();
            await using var server = new CustomTlsServer(new CustomTlsServerOptions
            {
                ServerCertificate = credential,
                SupportedVersions = [version],
                CipherSuites = [TlsCipherSuite.TlsAes128GcmSha256],
                Tls12CipherSuites = [TlsCipherSuite.TlsEcdheRsaWithAes128GcmSha256],
                SupportedGroups = [NamedGroup.Secp256r1],
            });
            await server.AuthenticateAsync(socket, ownsSocket: true, timeout.Token);
        }, timeout.Token);

        var profile = version == TlsProtocolVersion.Tls13
            ? ClientHelloProfiles.Custom(builder => builder
                .WithTls13()
                .WithCipherSuites(TlsCipherSuite.TlsAes128GcmSha256)
                .WithSupportedGroups(NamedGroup.Secp256r1)
                .WithKeyShares(NamedGroup.Secp256r1)
                .WithExtensionLayout(
                    ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.ServerName),
                    ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.SupportedVersions),
                    ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.SupportedGroups),
                    ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.SignatureAlgorithms),
                    ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.KeyShare),
                    ClientHelloExtensionSpec.Raw((ushort)TlsExtensionType.StatusRequest,
                        [1, 0, 0, 0, 0]),
                    ClientHelloExtensionSpec.Raw(
                        (ushort)TlsExtensionType.SignedCertificateTimestamp, [])))
            : ClientHelloProfiles.Custom(builder => builder
                .WithLegacyTls12ClientHello()
                .WithCipherSuites(TlsCipherSuite.TlsEcdheRsaWithAes128GcmSha256)
                .WithSupportedGroups(NamedGroup.Secp256r1)
                .WithSignatureAlgorithms(
                    SignatureScheme.RsaPssRsaeSha256,
                    SignatureScheme.RsaPkcs1Sha256)
                .WithExtensionLayout(
                    ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.ServerName),
                    ClientHelloExtensionSpec.Raw(
                        (ushort)TlsExtensionType.ExtendedMasterSecret, []),
                    ClientHelloExtensionSpec.Raw(
                        (ushort)TlsExtensionType.RenegotiationInfo, [0]),
                    ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.SupportedGroups),
                    ClientHelloExtensionSpec.Raw(
                        (ushort)TlsExtensionType.EcPointFormats, [1, 0]),
                    ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.SignatureAlgorithms),
                    ClientHelloExtensionSpec.Raw((ushort)TlsExtensionType.StatusRequest,
                        [1, 0, 0, 0, 0]),
                    ClientHelloExtensionSpec.Raw(
                        (ushort)TlsExtensionType.SignedCertificateTimestamp, [])));
        await using var client = new CustomTlsClient(new CustomTlsClientOptions
        {
            ServerName = "example.com",
            ClientHello = profile,
            CertificateValidation = new CustomTlsCertificateValidationOptions
            {
                CustomTrustRoots = [pki.Root],
                RevocationMode = X509RevocationMode.NoCheck,
            },
        });
        await client.ConnectAsync(IPAddress.Loopback.ToString(), port, timeout.Token);
        await serverTask.WaitAsync(timeout.Token);
        var state = client.GetConnectionState();
        Assert.Equal(ocsp, state.StapledOcspResponse);
        Assert.Equal(scts, state.SignedCertificateTimestamps);
    }

    [Theory]
    [InlineData(TlsCertificateCompressionAlgorithm.Zlib)]
    [InlineData(TlsCertificateCompressionAlgorithm.Brotli)]
    public async Task ServerNegotiatesAndAuthenticatesCompressedCertificate(
        TlsCertificateCompressionAlgorithm algorithm)
    {
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        using var pki = TestPki.Create();
        using var credential = new TlsServerCertificate(
            pki.Leaf,
            (RSA)pki.LeafKey,
            [pki.Root]);
        var expectedLength = Tls13ServerHandshakeMessages.BuildCompressedCertificate(
            credential,
            TlsLimits.Default,
            algorithm).Length;
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        var serverTask = Task.Run(async () =>
        {
            using var socket = await listener.AcceptSocketAsync(timeout.Token);
            listener.Stop();
            await using var server = new CustomTlsServer(new CustomTlsServerOptions
            {
                ServerCertificate = credential,
                SupportedVersions = [TlsProtocolVersion.Tls13],
                CipherSuites = [TlsCipherSuite.TlsAes128GcmSha256],
                SupportedGroups = [NamedGroup.Secp256r1],
                CertificateCompressionAlgorithms = [algorithm],
            });
            await server.AuthenticateAsync(socket, ownsSocket: true, timeout.Token);
        }, timeout.Token);
        var events = new List<TlsHandshakeEvent>();
        var profile = ClientHelloProfiles.Custom(builder => builder
            .WithTls13()
            .WithCipherSuites(TlsCipherSuite.TlsAes128GcmSha256)
            .WithSupportedGroups(NamedGroup.Secp256r1)
            .WithKeyShares(NamedGroup.Secp256r1)
            .WithExtensionLayout(
                ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.ServerName),
                ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.SupportedVersions),
                ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.SupportedGroups),
                ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.SignatureAlgorithms),
                ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.KeyShare),
                ClientHelloExtensionSpec.Raw(
                    (ushort)TlsExtensionType.CompressCertificate,
                    [2, 0, (byte)algorithm])));
        await using var client = new CustomTlsClient(new CustomTlsClientOptions
        {
            ServerName = "example.com",
            ClientHello = profile,
            HandshakeEventObserver = events.Add,
            CertificateValidation = new CustomTlsCertificateValidationOptions
            {
                CustomTrustRoots = [pki.Root],
                RevocationMode = X509RevocationMode.NoCheck,
            },
        });

        await client.ConnectAsync(IPAddress.Loopback.ToString(), port, timeout.Token);
        await serverTask.WaitAsync(timeout.Token);

        Assert.Equal(
            expectedLength,
            Assert.Single(events, value => value.Kind == TlsHandshakeEventKind.Certificate)
                .EncodedLength);
        Assert.NotEmpty(client.GetConnectionState().PeerCertificateChain);
    }


    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task SharpTlsClientCompletesServerHandshakeAndApplicationTraffic(
        bool forceHelloRetryRequest)
    {
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        using var pki = TestPki.Create();
        using var credential = new TlsServerCertificate(
            pki.Leaf,
            (RSA)pki.LeafKey,
            [pki.Root]);
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        string? selectedServerName = null;
        string? selectedAlpn = null;
        NamedGroup? selectedGroup = null;
        var inspectedClientHellos = new List<TlsClientHelloInspection>();

        var serverTask = Task.Run(async () =>
        {
            using var socket = await listener.AcceptSocketAsync(timeout.Token);
            listener.Stop();
            await using var server = new CustomTlsServer(new CustomTlsServerOptions
            {
                ServerCertificate = credential,
                CipherSuites = [TlsCipherSuite.TlsAes128GcmSha256],
                SupportedGroups = forceHelloRetryRequest
                    ? [NamedGroup.Secp384r1]
                    : [NamedGroup.Secp256r1],
                AlpnProtocols = ["http/1.1"],
                RequireAlpn = true,
            });
            await server.AuthenticateAsync(socket, ownsSocket: true, timeout.Token);
            selectedServerName = server.ServerName;
            selectedAlpn = server.NegotiatedApplicationProtocol;
            selectedGroup = server.NegotiatedGroup;
            Assert.True(server.IsAuthenticated);
            Assert.Equal("ping"u8.ToArray(),
                await server.ReadApplicationDataAsync(timeout.Token));
            await server.WriteApplicationDataAsync("pong"u8.ToArray(), timeout.Token);
        }, timeout.Token);

        var profile = ClientHelloProfiles.Custom(builder =>
        {
            builder
                .WithTls13()
                .WithCipherSuites(TlsCipherSuite.TlsAes128GcmSha256)
                .WithSupportedGroups(NamedGroup.Secp256r1, NamedGroup.Secp384r1)
                .WithAlpn("http/1.1");
            if (forceHelloRetryRequest)
            {
                builder.WithKeyShares(NamedGroup.Secp256r1);
            }
        });
        await using var client = new CustomTlsClient(new CustomTlsClientOptions
        {
            ServerName = "example.com",
            ClientHello = profile,
            ClientHelloInspector = inspectedClientHellos.Add,
            CertificateValidation = new CustomTlsCertificateValidationOptions
            {
                CustomTrustRoots = [pki.Root],
                RevocationMode = X509RevocationMode.NoCheck,
            },
        });
        await client.ConnectAsync(IPAddress.Loopback.ToString(), port, timeout.Token);
        Assert.Equal("http/1.1", client.NegotiatedApplicationProtocol);
        Assert.Equal(forceHelloRetryRequest, client.HandshakeUsedHelloRetryRequest);
        await client.WriteApplicationDataAsync("ping"u8.ToArray(), timeout.Token);
        Assert.Equal("pong"u8.ToArray(),
            await client.ReadApplicationDataAsync(timeout.Token));

        await serverTask.WaitAsync(timeout.Token);
        Assert.Equal("example.com", selectedServerName);
        Assert.Equal("http/1.1", selectedAlpn);
        Assert.Equal(
            forceHelloRetryRequest ? NamedGroup.Secp384r1 : NamedGroup.Secp256r1,
            selectedGroup);
        Assert.Equal(forceHelloRetryRequest ? 2 : 1, inspectedClientHellos.Count);
        Assert.Equal(TlsClientHelloFlight.Initial, inspectedClientHellos[0].Flight);
        Assert.Equal(TlsClientHelloWireForm.Direct, inspectedClientHellos[0].WireForm);
        if (forceHelloRetryRequest)
        {
            Assert.Equal(
                TlsClientHelloFlight.AfterHelloRetryRequest,
                inspectedClientHellos[1].Flight);
        }
        Assert.All(inspectedClientHellos, inspection =>
        {
            Assert.Equal((byte)TlsContentType.Handshake, inspection.GetEncodedTlsRecords()[0]);
            Assert.Equal((byte)HandshakeType.ClientHello, inspection.GetEncodedHandshake()[0]);
        });
    }

    [Theory]
    [InlineData(NamedGroup.X25519MlKem768, false)]
    [InlineData(NamedGroup.X25519MlKem768, true)]
    [InlineData(NamedGroup.X25519Kyber768Draft00, false)]
    [InlineData(NamedGroup.X25519Kyber768Draft00, true)]
    public async Task SharpTlsClientAndServerCompleteHybridHandshake(
        NamedGroup hybridGroup,
        bool forceHelloRetryRequest)
    {
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        using var pki = TestPki.Create();
        using var credential = new TlsServerCertificate(
            pki.Leaf,
            (RSA)pki.LeafKey,
            [pki.Root]);
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var port = ((IPEndPoint)listener.LocalEndpoint).Port;

        var serverTask = Task.Run(async () =>
        {
            using var socket = await listener.AcceptSocketAsync(timeout.Token);
            listener.Stop();
            await using var server = new CustomTlsServer(new CustomTlsServerOptions
            {
                ServerCertificate = credential,
                SupportedVersions = [TlsProtocolVersion.Tls13],
                CipherSuites = [TlsCipherSuite.TlsAes128GcmSha256],
                SupportedGroups = [hybridGroup],
            });
            await server.AuthenticateAsync(socket, ownsSocket: true, timeout.Token);
            Assert.Equal(hybridGroup, server.NegotiatedGroup);
            Assert.Equal("hybrid-ping"u8.ToArray(),
                await server.ReadApplicationDataAsync(timeout.Token));
            await server.WriteApplicationDataAsync("hybrid-pong"u8.ToArray(), timeout.Token);
        }, timeout.Token);

        await using var client = new CustomTlsClient(new CustomTlsClientOptions
        {
            ServerName = "example.com",
            ClientHello = ClientHelloProfiles.Custom(builder => builder
                .WithTls13()
                .WithCipherSuites(TlsCipherSuite.TlsAes128GcmSha256)
                .WithSupportedGroups(hybridGroup, NamedGroup.X25519)
                .WithKeyShares(forceHelloRetryRequest
                    ? [NamedGroup.X25519]
                    : [hybridGroup, NamedGroup.X25519])),
            CertificateValidation = new CustomTlsCertificateValidationOptions
            {
                CustomTrustRoots = [pki.Root],
                RevocationMode = X509RevocationMode.NoCheck,
            },
        });

        try
        {
            await client.ConnectAsync(IPAddress.Loopback.ToString(), port, timeout.Token);
        }
        catch (Exception clientException)
        {
            try
            {
                await serverTask.WaitAsync(timeout.Token);
            }
            catch (Exception serverException)
            {
                throw new AggregateException(clientException, serverException);
            }
            throw;
        }
        Assert.Equal(hybridGroup, client.NegotiatedGroup);
        Assert.Equal(forceHelloRetryRequest, client.HandshakeUsedHelloRetryRequest);
        await client.WriteApplicationDataAsync("hybrid-ping"u8.ToArray(), timeout.Token);
        Assert.Equal("hybrid-pong"u8.ToArray(),
            await client.ReadApplicationDataAsync(timeout.Token));
        await serverTask.WaitAsync(timeout.Token);
    }

    [Fact]
    public async Task AsyncCertificateSelectorReceivesSniAndCanRejectIt()
    {
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        using var pki = TestPki.Create();
        using var credential = new TlsServerCertificate(
            pki.Leaf,
            (RSA)pki.LeafKey,
            [pki.Root]);
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        TlsServerCertificateSelectionContext? observed = null;
        var serverTask = Task.Run(async () =>
        {
            using var socket = await listener.AcceptSocketAsync(timeout.Token);
            listener.Stop();
            await using var server = new CustomTlsServer(new CustomTlsServerOptions
            {
                ServerCertificateSelector = (context, _) =>
                {
                    observed = context;
                    return ValueTask.FromResult<TlsServerCertificate?>(
                        context.ServerName == "example.com" ? credential : null);
                },
                AlpnProtocols = ["http/1.1"],
                RequireAlpn = true,
            });
            await server.AuthenticateAsync(socket, ownsSocket: true, timeout.Token);
        }, timeout.Token);

        await using var client = new CustomTlsClient(new CustomTlsClientOptions
        {
            ServerName = "example.com",
            ClientHello = ClientHelloProfiles.Custom(builder => builder
                .WithTls13()
                .WithAlpn("http/1.1")),
            CertificateValidation = new CustomTlsCertificateValidationOptions
            {
                CustomTrustRoots = [pki.Root],
                RevocationMode = X509RevocationMode.NoCheck,
            },
        });
        await client.ConnectAsync(IPAddress.Loopback.ToString(), port, timeout.Token);
        await serverTask.WaitAsync(timeout.Token);
        Assert.Equal("example.com", observed!.ServerName);
        Assert.Contains("http/1.1", observed.AlpnProtocols);
        Assert.Contains(SignatureScheme.RsaPssRsaeSha256, observed.SignatureAlgorithms);
    }

    [Theory]
    [InlineData(TlsServerClientAuthenticationMode.Request, false)]
    [InlineData(TlsServerClientAuthenticationMode.Require, true)]
    public async Task ServerClientAuthenticationHandlesEmptyAndRsaCertificatePaths(
        TlsServerClientAuthenticationMode mode,
        bool provideCertificate)
    {
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        using var serverPki = TestPki.Create();
        using var clientPki = TestPki.Create(
            dnsName: "unused.example",
            serverAuthenticationEku: false);
        using var serverCredential = new TlsServerCertificate(
            serverPki.Leaf,
            (RSA)serverPki.LeafKey,
            [serverPki.Root]);
        using var clientCredential = new TlsClientCertificate(
            clientPki.Leaf,
            (RSA)clientPki.LeafKey,
            [clientPki.Root]);
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        byte[][]? peerChain = null;

        var serverTask = Task.Run(async () =>
        {
            using var socket = await listener.AcceptSocketAsync(timeout.Token);
            listener.Stop();
            await using var server = new CustomTlsServer(new CustomTlsServerOptions
            {
                ServerCertificate = serverCredential,
                ClientAuthentication = mode,
                ClientCertificateValidation = new CustomTlsCertificateValidationOptions
                {
                    CustomTrustRoots = [clientPki.Root],
                    RevocationMode = X509RevocationMode.NoCheck,
                },
            });
            await server.AuthenticateAsync(socket, ownsSocket: true, timeout.Token);
            peerChain = server.PeerCertificateChain.ToArray();
        }, timeout.Token);

        await using var client = new CustomTlsClient(new CustomTlsClientOptions
        {
            ServerName = "example.com",
            ClientHello = ClientHelloProfiles.Custom(builder => builder.WithTls13()),
            CertificateValidation = new CustomTlsCertificateValidationOptions
            {
                CustomTrustRoots = [serverPki.Root],
                RevocationMode = X509RevocationMode.NoCheck,
            },
            ClientCertificate = provideCertificate ? clientCredential : null,
        });
        await client.ConnectAsync(IPAddress.Loopback.ToString(), port, timeout.Token);
        await serverTask.WaitAsync(timeout.Token);

        if (provideCertificate)
        {
            Assert.NotNull(peerChain);
            Assert.Equal(clientPki.Leaf.RawData, peerChain![0]);
        }
        else
        {
            Assert.Empty(peerChain!);
        }
    }

    [Fact]
    public async Task CrossedKeyUpdateAndExporterRemainSynchronized()
    {
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        using var pki = TestPki.Create();
        using var credential = new TlsServerCertificate(
            pki.Leaf,
            (RSA)pki.LeafKey,
            [pki.Root]);
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        byte[]? serverExporter = null;
        ulong serverSendUpdates = 0;
        ulong clientSendUpdates = 0;

        var serverTask = Task.Run(async () =>
        {
            using var socket = await listener.AcceptSocketAsync(timeout.Token);
            listener.Stop();
            await using var server = new CustomTlsServer(new CustomTlsServerOptions
            {
                ServerCertificate = credential,
            });
            await server.AuthenticateAsync(socket, ownsSocket: true, timeout.Token);
            serverExporter = server.ExportKeyingMaterial("test exporter", [1, 2, 3], 32);
            Assert.Equal("ping"u8.ToArray(),
                await server.ReadApplicationDataAsync(timeout.Token));
            await server.WriteApplicationDataAsync("pong"u8.ToArray(), timeout.Token);
            serverSendUpdates = server.ServerKeyUpdateCount;
            clientSendUpdates = server.ClientKeyUpdateCount;
        }, timeout.Token);

        await using var client = new CustomTlsClient(new CustomTlsClientOptions
        {
            ServerName = "example.com",
            ClientHello = ClientHelloProfiles.Custom(builder => builder.WithTls13()),
            CertificateValidation = new CustomTlsCertificateValidationOptions
            {
                CustomTrustRoots = [pki.Root],
                RevocationMode = X509RevocationMode.NoCheck,
            },
        });
        await client.ConnectAsync(IPAddress.Loopback.ToString(), port, timeout.Token);
        var clientExporter = client.ExportKeyingMaterial("test exporter", [1, 2, 3], 32);
        await client.RequestKeyUpdateAsync(requestPeerUpdate: true, timeout.Token);
        await client.WriteApplicationDataAsync("ping"u8.ToArray(), timeout.Token);
        Assert.Equal("pong"u8.ToArray(),
            await client.ReadApplicationDataAsync(timeout.Token));
        await serverTask.WaitAsync(timeout.Token);

        try
        {
            Assert.Equal(clientExporter, serverExporter);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(clientExporter);
            if (serverExporter is not null)
            {
                CryptographicOperations.ZeroMemory(serverExporter);
            }
        }
        Assert.Equal(1UL, client.ClientKeyUpdateCount);
        Assert.Equal(1UL, client.ServerKeyUpdateCount);
        Assert.Equal(1UL, serverSendUpdates);
        Assert.Equal(1UL, clientSendUpdates);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task StatelessTicketResumptionAuthenticatesBinderAndSkipsCertificateFlight(
        bool forceHelloRetryRequest)
    {
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        using var pki = TestPki.Create();
        using var credential = new TlsServerCertificate(
            pki.Leaf,
            (RSA)pki.LeafKey,
            [pki.Root]);
        var ticketKey = RandomNumberGenerator.GetBytes(32);
        using var ticketProtector = new Tls13ServerSessionTicketProtector("current", ticketKey);
        CryptographicOperations.ZeroMemory(ticketKey);
        using var cache = new Tls13SessionCache();
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        var serverResumption = new bool[2];

        var serverTask = Task.Run(async () =>
        {
            for (var connection = 0; connection < 2; connection++)
            {
                using var socket = await listener.AcceptSocketAsync(timeout.Token);
                await using var server = new CustomTlsServer(new CustomTlsServerOptions
                {
                    ServerCertificate = credential,
                    CipherSuites = [TlsCipherSuite.TlsAes128GcmSha256],
                    SupportedGroups = forceHelloRetryRequest
                        ? [NamedGroup.Secp384r1]
                        : [NamedGroup.Secp256r1],
                    AlpnProtocols = ["http/1.1"],
                    RequireAlpn = true,
                    SessionTicketProtector = ticketProtector,
                    AutomaticSessionTicketCount = 1,
                });
                await server.AuthenticateAsync(socket, ownsSocket: true, timeout.Token);
                serverResumption[connection] = server.SessionWasResumed;
                Assert.Equal(1, server.IssuedSessionTicketCount);
                Assert.Equal("ping"u8.ToArray(),
                    await server.ReadApplicationDataAsync(timeout.Token));
                await server.WriteApplicationDataAsync("pong"u8.ToArray(), timeout.Token);
            }
            listener.Stop();
        }, timeout.Token);

        var profile = ClientHelloProfiles.Custom(builder => builder
            .WithTls13()
            .WithCipherSuites(TlsCipherSuite.TlsAes128GcmSha256)
            .WithSupportedGroups(NamedGroup.Secp256r1, NamedGroup.Secp384r1)
            .WithKeyShares(NamedGroup.Secp256r1)
            .WithAlpn("http/1.1")
            .WithSessionResumption());
        for (var connection = 0; connection < 2; connection++)
        {
            await using var client = new CustomTlsClient(new CustomTlsClientOptions
            {
                ServerName = "example.com",
                ClientHello = profile,
                SessionCache = cache,
                CertificateValidation = new CustomTlsCertificateValidationOptions
                {
                    CustomTrustRoots = [pki.Root],
                    RevocationMode = X509RevocationMode.NoCheck,
                },
            });
            await client.ConnectAsync(IPAddress.Loopback.ToString(), port, timeout.Token);
            Assert.Equal(connection == 1, client.SessionWasResumed);
            await client.WriteApplicationDataAsync("ping"u8.ToArray(), timeout.Token);
            Assert.Equal("pong"u8.ToArray(),
                await client.ReadApplicationDataAsync(timeout.Token));
            Assert.True(cache.Count > 0);
        }

        await serverTask.WaitAsync(timeout.Token);
        Assert.Equal([false, true], serverResumption);
    }

    [Theory]
    [InlineData(TlsCipherSuite.TlsEcdheRsaWithAes128GcmSha256, false)]
    [InlineData(TlsCipherSuite.TlsEcdheRsaWithAes256GcmSha384, false)]
    [InlineData(TlsCipherSuite.TlsEcdheRsaWithChaCha20Poly1305Sha256, false)]
    [InlineData(TlsCipherSuite.TlsEcdheEcdsaWithAes128GcmSha256, true)]
    [InlineData(TlsCipherSuite.TlsEcdheEcdsaWithAes256GcmSha384, true)]
    [InlineData(TlsCipherSuite.TlsEcdheEcdsaWithChaCha20Poly1305Sha256, true)]
    public async Task SecureTls12ServerCompletesEcdheAeadHandshakeAndTraffic(
        TlsCipherSuite cipherSuite,
        bool ecdsaCertificate)
    {
        if (cipherSuite == TlsCipherSuite.TlsEcdheRsaWithChaCha20Poly1305Sha256 &&
            !ChaCha20Poly1305.IsSupported)
        {
            return;
        }
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        using var pki = TestPki.Create(ecdsaLeaf: ecdsaCertificate);
        using var credential = ecdsaCertificate
            ? new TlsServerCertificate(pki.Leaf, (ECDsa)pki.LeafKey, [pki.Root])
            : new TlsServerCertificate(pki.Leaf, (RSA)pki.LeafKey, [pki.Root]);
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        byte[]? serverExporter = null;
        byte[]? serverTlsUnique = null;
        var serverTask = Task.Run(async () =>
        {
            using var socket = await listener.AcceptSocketAsync(timeout.Token);
            listener.Stop();
            await using var server = new CustomTlsServer(new CustomTlsServerOptions
            {
                ServerCertificate = credential,
                SupportedVersions = [TlsProtocolVersion.Tls12],
                Tls12CipherSuites = [cipherSuite],
                SupportedGroups = [NamedGroup.Secp256r1],
            });
            await server.AuthenticateAsync(socket, ownsSocket: true, timeout.Token);
            Assert.Equal(TlsProtocolVersion.Tls12, server.NegotiatedProtocolVersion);
            Assert.Equal(cipherSuite, server.NegotiatedCipherSuite);
            serverTlsUnique = server.TlsUnique;
            serverExporter = server.ExportKeyingMaterial("SharpTls TLS 1.2 test", [1, 2, 3], 48);
            Assert.Equal("ping"u8.ToArray(),
                await server.ReadApplicationDataAsync(timeout.Token));
            await server.WriteApplicationDataAsync("pong"u8.ToArray(), timeout.Token);
        }, timeout.Token);

        await using var client = new CustomTlsClient(new CustomTlsClientOptions
        {
            ServerName = "example.com",
            ClientHello = ClientHelloProfiles.UTlsAndroid11OkHttp,
            CertificateValidation = new CustomTlsCertificateValidationOptions
            {
                CustomTrustRoots = [pki.Root],
                RevocationMode = X509RevocationMode.NoCheck,
            },
        });
        await client.ConnectAsync(IPAddress.Loopback.ToString(), port, timeout.Token);
        Assert.Equal(TlsProtocolVersion.Tls12, client.NegotiatedProtocolVersion);
        Assert.Equal(cipherSuite, client.NegotiatedCipherSuite);
        Assert.Equal(TlsConstants.Tls12FinishedLength, client.GetConnectionState().TlsUnique?.Length);
        var clientExporter = client.ExportKeyingMaterial(
            "SharpTls TLS 1.2 test",
            [1, 2, 3],
            48);
        await client.WriteApplicationDataAsync("ping"u8.ToArray(), timeout.Token);
        Assert.Equal("pong"u8.ToArray(),
            await client.ReadApplicationDataAsync(timeout.Token));
        await serverTask.WaitAsync(timeout.Token);
        Assert.Equal(serverExporter, clientExporter);
        Assert.Equal(serverTlsUnique, client.GetConnectionState().TlsUnique);
        CryptographicOperations.ZeroMemory(clientExporter);
        CryptographicOperations.ZeroMemory(serverExporter!);
        CryptographicOperations.ZeroMemory(serverTlsUnique!);
    }

    [Fact]
    public async Task SecureTls12ClientAndServerCompleteP521HandshakeAndTraffic()
    {
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        using var pki = TestPki.Create();
        using var credential = new TlsServerCertificate(
            pki.Leaf,
            (RSA)pki.LeafKey,
            [pki.Root]);
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        var serverTask = Task.Run(async () =>
        {
            using var socket = await listener.AcceptSocketAsync(timeout.Token);
            await using var server = new CustomTlsServer(new CustomTlsServerOptions
            {
                ServerCertificate = credential,
                SupportedVersions = [TlsProtocolVersion.Tls12],
                Tls12CipherSuites = [TlsCipherSuite.TlsEcdheRsaWithAes128GcmSha256],
                SupportedGroups = [NamedGroup.Secp521r1],
            });
            await server.AuthenticateAsync(socket, ownsSocket: true, timeout.Token);
            Assert.Equal(NamedGroup.Secp521r1, server.NegotiatedGroup);
            Assert.Equal("p521-ping"u8.ToArray(),
                await server.ReadApplicationDataAsync(timeout.Token));
            await server.WriteApplicationDataAsync("p521-pong"u8.ToArray(), timeout.Token);
        }, timeout.Token);

        var profile = ClientHelloProfiles.Custom(builder => builder
            .WithLegacyTls12ClientHello()
            .WithCipherSuites(TlsCipherSuite.TlsEcdheRsaWithAes128GcmSha256)
            .WithSupportedGroups(NamedGroup.Secp521r1)
            .WithSignatureAlgorithms(SignatureScheme.RsaPssRsaeSha256)
            .WithExtensionLayout(
                ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.ServerName),
                ClientHelloExtensionSpec.Raw(
                    (ushort)TlsExtensionType.ExtendedMasterSecret, []),
                ClientHelloExtensionSpec.Raw(
                    (ushort)TlsExtensionType.RenegotiationInfo, [0]),
                ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.SupportedGroups),
                ClientHelloExtensionSpec.Raw(
                    (ushort)TlsExtensionType.EcPointFormats, [1, 0]),
                ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.SignatureAlgorithms)));
        await using var client = new CustomTlsClient(new CustomTlsClientOptions
        {
            ServerName = "example.com",
            ClientHello = profile,
            CertificateValidation = new CustomTlsCertificateValidationOptions
            {
                CustomTrustRoots = [pki.Root],
                RevocationMode = X509RevocationMode.NoCheck,
            },
        });
        await client.ConnectAsync(IPAddress.Loopback.ToString(), port, timeout.Token);
        Assert.Equal(NamedGroup.Secp521r1, client.NegotiatedGroup);
        await client.WriteApplicationDataAsync("p521-ping"u8.ToArray(), timeout.Token);
        Assert.Equal("p521-pong"u8.ToArray(),
            await client.ReadApplicationDataAsync(timeout.Token));
        await serverTask.WaitAsync(timeout.Token);
    }

    [Theory]
    [InlineData(TlsServerClientAuthenticationMode.Request, false)]
    [InlineData(TlsServerClientAuthenticationMode.Require, true)]
    public async Task Tls12ServerAuthenticatesEmptyAndRsaClientCertificatePaths(
        TlsServerClientAuthenticationMode mode,
        bool provideCertificate)
    {
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        using var serverPki = TestPki.Create();
        using var clientPki = TestPki.Create(
            dnsName: "unused.example",
            serverAuthenticationEku: false);
        using var serverCredential = new TlsServerCertificate(
            serverPki.Leaf,
            (RSA)serverPki.LeafKey,
            [serverPki.Root]);
        using var clientCredential = new TlsClientCertificate(
            clientPki.Leaf,
            (RSA)clientPki.LeafKey,
            [clientPki.Root]);
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        byte[][]? peerChain = null;

        var serverTask = Task.Run(async () =>
        {
            using var socket = await listener.AcceptSocketAsync(timeout.Token);
            listener.Stop();
            await using var server = new CustomTlsServer(new CustomTlsServerOptions
            {
                ServerCertificate = serverCredential,
                SupportedVersions = [TlsProtocolVersion.Tls12],
                Tls12CipherSuites = [TlsCipherSuite.TlsEcdheRsaWithAes128GcmSha256],
                SupportedGroups = [NamedGroup.Secp256r1],
                ClientAuthentication = mode,
                ClientCertificateValidation = new CustomTlsCertificateValidationOptions
                {
                    CustomTrustRoots = [clientPki.Root],
                    RevocationMode = X509RevocationMode.NoCheck,
                },
            });
            await server.AuthenticateAsync(socket, ownsSocket: true, timeout.Token);
            peerChain = server.PeerCertificateChain.ToArray();
        }, timeout.Token);

        await using var client = new CustomTlsClient(new CustomTlsClientOptions
        {
            ServerName = "example.com",
            ClientHello = ClientHelloProfiles.UTlsAndroid11OkHttp,
            CertificateValidation = new CustomTlsCertificateValidationOptions
            {
                CustomTrustRoots = [serverPki.Root],
                RevocationMode = X509RevocationMode.NoCheck,
            },
            ClientCertificate = provideCertificate ? clientCredential : null,
        });
        await client.ConnectAsync(IPAddress.Loopback.ToString(), port, timeout.Token);
        await serverTask.WaitAsync(timeout.Token);

        if (provideCertificate)
        {
            Assert.Equal(clientPki.Leaf.RawData, peerChain![0]);
        }
        else
        {
            Assert.Empty(peerChain!);
        }
    }

    [Fact]
    public async Task Tls12ServerAndClientResumeWithSharedSessionIdCaches()
    {
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        using var pki = TestPki.Create();
        using var credential = new TlsServerCertificate(
            pki.Leaf,
            (RSA)pki.LeafKey,
            [pki.Root]);
        using var serverCache = new Tls12ServerSessionCache(capacity: 8);
        using var clientCache = new Tls12SessionCache(capacity: 8);
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        var serverResumption = new List<bool>();
        var serverTask = Task.Run(async () =>
        {
            for (var connection = 0; connection < 2; connection++)
            {
                using var socket = await listener.AcceptSocketAsync(timeout.Token);
                await using var server = new CustomTlsServer(new CustomTlsServerOptions
                {
                    ServerCertificate = credential,
                    SupportedVersions = [TlsProtocolVersion.Tls12],
                    Tls12CipherSuites =
                        [TlsCipherSuite.TlsEcdheRsaWithAes128GcmSha256],
                    SupportedGroups = [NamedGroup.Secp256r1],
                    Tls12SessionCache = serverCache,
                });
                await server.AuthenticateAsync(socket, ownsSocket: true, timeout.Token);
                serverResumption.Add(server.SessionWasResumed);
                Assert.Equal("ping"u8.ToArray(),
                    await server.ReadApplicationDataAsync(timeout.Token));
                await server.WriteApplicationDataAsync("pong"u8.ToArray(), timeout.Token);
            }
            listener.Stop();
        }, timeout.Token);

        for (var connection = 0; connection < 2; connection++)
        {
            await using var client = new CustomTlsClient(new CustomTlsClientOptions
            {
                ServerName = "example.com",
                ClientHello = ClientHelloProfiles.UTlsAndroid11OkHttp,
                Tls12SessionCache = clientCache,
                CertificateValidation = new CustomTlsCertificateValidationOptions
                {
                    CustomTrustRoots = [pki.Root],
                    RevocationMode = X509RevocationMode.NoCheck,
                },
            });
            await client.ConnectAsync(IPAddress.Loopback.ToString(), port, timeout.Token);
            Assert.Equal(connection == 1, client.SessionWasResumed);
            await client.WriteApplicationDataAsync("ping"u8.ToArray(), timeout.Token);
            Assert.Equal("pong"u8.ToArray(),
                await client.ReadApplicationDataAsync(timeout.Token));
        }

        await serverTask.WaitAsync(timeout.Token);
        Assert.Equal([false, true], serverResumption);
        Assert.Equal(1, serverCache.Count);
        Assert.Equal(1, clientCache.Count);
    }

    [Fact]
    public async Task Tls12ServerAndClientResumeWithStatelessRfc5077Tickets()
    {
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        using var pki = TestPki.Create();
        using var credential = new TlsServerCertificate(
            pki.Leaf,
            (RSA)pki.LeafKey,
            [pki.Root]);
        var ticketKey = RandomNumberGenerator.GetBytes(32);
        using var protector = new Tls12ServerSessionTicketProtector("active", ticketKey);
        CryptographicOperations.ZeroMemory(ticketKey);
        using var clientCache = new Tls12SessionCache(capacity: 8);
        var profile = ClientHelloProfiles.Custom(builder => builder
            .WithLegacyTls12ClientHello()
            .WithCipherSuites(TlsCipherSuite.TlsEcdheRsaWithAes128GcmSha256)
            .WithSupportedGroups(NamedGroup.Secp256r1)
            .WithSignatureAlgorithms(
                SignatureScheme.RsaPssRsaeSha256,
                SignatureScheme.RsaPkcs1Sha256)
            .WithExtensionLayout(
                ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.ServerName),
                ClientHelloExtensionSpec.Raw((ushort)TlsExtensionType.ExtendedMasterSecret, []),
                ClientHelloExtensionSpec.Raw((ushort)TlsExtensionType.RenegotiationInfo, [0]),
                ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.SupportedGroups),
                ClientHelloExtensionSpec.Raw((ushort)TlsExtensionType.EcPointFormats, [1, 0]),
                ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.SignatureAlgorithms),
                ClientHelloExtensionSpec.Raw((ushort)TlsExtensionType.SessionTicket, [])));
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        var serverResumption = new List<bool>();
        var issuedTickets = new List<int>();
        var serverTask = Task.Run(async () =>
        {
            for (var connection = 0; connection < 2; connection++)
            {
                using var socket = await listener.AcceptSocketAsync(timeout.Token);
                await using var server = new CustomTlsServer(new CustomTlsServerOptions
                {
                    ServerCertificate = credential,
                    SupportedVersions = [TlsProtocolVersion.Tls12],
                    Tls12CipherSuites =
                        [TlsCipherSuite.TlsEcdheRsaWithAes128GcmSha256],
                    SupportedGroups = [NamedGroup.Secp256r1],
                    Tls12SessionTicketProtector = protector,
                });
                await server.AuthenticateAsync(socket, ownsSocket: true, timeout.Token);
                serverResumption.Add(server.SessionWasResumed);
                issuedTickets.Add(server.IssuedSessionTicketCount);
                Assert.Equal("ping"u8.ToArray(),
                    await server.ReadApplicationDataAsync(timeout.Token));
                await server.WriteApplicationDataAsync("pong"u8.ToArray(), timeout.Token);
            }
            listener.Stop();
        }, timeout.Token);

        for (var connection = 0; connection < 2; connection++)
        {
            await using var client = new CustomTlsClient(new CustomTlsClientOptions
            {
                ServerName = "example.com",
                ClientHello = profile,
                Tls12SessionCache = clientCache,
                CertificateValidation = new CustomTlsCertificateValidationOptions
                {
                    CustomTrustRoots = [pki.Root],
                    RevocationMode = X509RevocationMode.NoCheck,
                },
            });
            await client.ConnectAsync(IPAddress.Loopback.ToString(), port, timeout.Token);
            Assert.Equal(connection == 1, client.SessionWasResumed);
            await client.WriteApplicationDataAsync("ping"u8.ToArray(), timeout.Token);
            Assert.Equal("pong"u8.ToArray(),
                await client.ReadApplicationDataAsync(timeout.Token));
        }

        await serverTask.WaitAsync(timeout.Token);
        Assert.Equal([false, true], serverResumption);
        Assert.Equal([1, 1], issuedTickets);
        Assert.InRange(clientCache.Count, 1, 2);
    }
}

public sealed class NonAppleTlsTheoryAttribute : TheoryAttribute
{
    public NonAppleTlsTheoryAttribute()
    {
        // The .NET 9 Apple TLS provider neither exposes TLS 1.3 through SslStream
        // nor emits both mandatory EMS and secure-renegotiation signals as a TLS
        // 1.2 client. Linux and Windows CI execute both rows. SharpTls must not
        // weaken its TLS 1.2 server policy merely to accommodate that provider.
        if (OperatingSystem.IsMacOS())
        {
            Skip = "The .NET 9 Apple SslStream client provider cannot satisfy this interop matrix.";
        }
    }
}
