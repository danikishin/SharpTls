using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using SharpTls.Certificates;
using SharpTls.Protocol;
using SharpTls.Tests.Certificates;

namespace SharpTls.Tests.Interop;

public sealed class ClientCertificateInteropTests
{
    [Fact]
    public async Task Tls13MutualAuthenticationCompletesAgainstManagedServer()
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
        await using var server = new ManagedTls13MutualAuthServer(
            serverPki.Leaf,
            serverPki.Root,
            (RSA)serverPki.LeafKey,
            clientPki.Leaf.RawData);
        await using var client = new CustomTlsClient(new CustomTlsClientOptions
        {
            ServerName = "localhost",
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

        Assert.Equal(TlsProtocolVersion.Tls13, client.NegotiatedProtocolVersion);
        Assert.Equal("pong"u8.ToArray(), response);
        Assert.True(server.ClientCertificateVerified);
    }

    [Fact]
    public async Task DynamicSelectorAndAsyncSignerCompleteMutualAuthentication()
    {
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        using var serverPki = TestPki.Create("localhost");
        using var clientPki = TestPki.Create(
            dnsName: "client.example",
            serverAuthenticationEku: false);
        var signer = new TestAsyncRsaSigner(
            (RSA)clientPki.LeafKey,
            [SignatureScheme.RsaPssRsaeSha256]);
        using var clientCredential = new TlsClientCertificate(
            clientPki.Leaf,
            signer,
            [clientPki.Root]);
        await using var server = new ManagedTls13MutualAuthServer(
            serverPki.Leaf,
            serverPki.Root,
            (RSA)serverPki.LeafKey,
            clientPki.Leaf.RawData);
        TlsClientCertificateSelectionContext? observedContext = null;
        await using var client = new CustomTlsClient(new CustomTlsClientOptions
        {
            ServerName = "localhost",
            ClientCertificateSelector = async (context, cancellationToken) =>
            {
                await Task.Yield();
                cancellationToken.ThrowIfCancellationRequested();
                observedContext = context;
                return clientCredential;
            },
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

        Assert.Equal("pong"u8.ToArray(), response);
        Assert.True(server.ClientCertificateVerified);
        Assert.Equal(1, signer.SignCount);
        Assert.NotNull(observedContext);
        Assert.Equal("localhost", observedContext.ServerName);
        Assert.Equal(TlsProtocolVersion.Tls13, observedContext.ProtocolVersion);
        Assert.False(observedContext.IsPostHandshake);
        Assert.Contains(
            SignatureScheme.RsaPssRsaeSha256,
            observedContext.SignatureSchemes);
        Assert.Empty(observedContext.CertificateTypes);
    }

    [Fact]
    public async Task Tls13PostHandshakeAuthenticationUsesApplicationTrafficSecret()
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
        await using var server = new ManagedTls13MutualAuthServer(
            serverPki.Leaf,
            serverPki.Root,
            (RSA)serverPki.LeafKey,
            clientPki.Leaf.RawData,
            requestPostHandshakeAuthentication: true);
        var profile = ClientHelloProfiles.Custom(builder => builder
            .WithSessionResumption()
            .WithPostHandshakeAuthentication());
        await using var client = new CustomTlsClient(new CustomTlsClientOptions
        {
            ServerName = "localhost",
            ClientHello = profile,
            ClientCertificate = clientCredential,
            CertificateValidation = new CustomTlsCertificateValidationOptions
            {
                RevocationMode = X509RevocationMode.NoCheck,
                CustomTrustRoots = [serverPki.Root],
            },
        });

        await client.ConnectAsync("127.0.0.1", server.Port, timeout.Token);
        var response = await client.ReadApplicationDataAsync(timeout.Token);
        await server.Completion;

        Assert.Equal("pong"u8.ToArray(), response);
        Assert.Equal(1, client.PostHandshakeAuthenticationCount);
        Assert.True(server.ClientCertificateVerified);
    }

    [Fact]
    public async Task UnadvertisedPostHandshakeAuthenticationIsRejectedWithFatalAlert()
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
            requestPostHandshakeAuthentication: true,
            expectPostHandshakeRejection: true);
        await using var client = new CustomTlsClient(new CustomTlsClientOptions
        {
            ServerName = "localhost",
            ClientCertificate = clientCredential,
            CertificateValidation = new CustomTlsCertificateValidationOptions
            {
                RevocationMode = X509RevocationMode.NoCheck,
                CustomTrustRoots = [serverPki.Root],
            },
        });

        await client.ConnectAsync("127.0.0.1", server.Port, timeout.Token);
        var exception = await Assert.ThrowsAsync<TlsProtocolException>(async () =>
            await client.ReadApplicationDataAsync(timeout.Token));
        await server.Completion;

        Assert.Equal(TlsAlertDescription.UnexpectedMessage, exception.Alert);
        Assert.True(server.PostHandshakeRequestWasRejected);
    }

    [Fact]
    public async Task ReusedPostHandshakeRequestContextIsRejected()
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
            requestPostHandshakeAuthentication: true,
            repeatPostHandshakeContext: true);
        var profile = ClientHelloProfiles.Custom(builder => builder
            .WithPostHandshakeAuthentication());
        await using var client = new CustomTlsClient(new CustomTlsClientOptions
        {
            ServerName = "localhost",
            ClientHello = profile,
            ClientCertificate = clientCredential,
            CertificateValidation = new CustomTlsCertificateValidationOptions
            {
                RevocationMode = X509RevocationMode.NoCheck,
                CustomTrustRoots = [serverPki.Root],
            },
        });

        await client.ConnectAsync("127.0.0.1", server.Port, timeout.Token);
        var exception = await Assert.ThrowsAsync<TlsProtocolException>(async () =>
            await client.ReadApplicationDataAsync(timeout.Token));
        await server.Completion;

        Assert.Equal(TlsAlertDescription.IllegalParameter, exception.Alert);
        Assert.Equal(1, client.PostHandshakeAuthenticationCount);
        Assert.True(server.PostHandshakeRequestWasRejected);
    }

    [Fact]
    public async Task IncompatiblePostHandshakeRequestSendsEmptyCertificateAndFinished()
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
            requestPostHandshakeAuthentication: true,
            expectEmptyPostHandshakeCertificate: true);
        var profile = ClientHelloProfiles.Custom(builder => builder
            .WithPostHandshakeAuthentication());
        await using var client = new CustomTlsClient(new CustomTlsClientOptions
        {
            ServerName = "localhost",
            ClientHello = profile,
            ClientCertificate = clientCredential,
            CertificateValidation = new CustomTlsCertificateValidationOptions
            {
                RevocationMode = X509RevocationMode.NoCheck,
                CustomTrustRoots = [serverPki.Root],
            },
        });

        await client.ConnectAsync("127.0.0.1", server.Port, timeout.Token);
        var response = await client.ReadApplicationDataAsync(timeout.Token);
        await server.Completion;

        Assert.Equal("pong"u8.ToArray(), response);
        Assert.Equal(1, client.PostHandshakeAuthenticationCount);
    }

    [Fact]
    public async Task Tls12MutualAuthenticationInteroperatesWithPlatformServer()
    {
        var tls12Profile = ClientHelloProfiles.Custom(builder => builder
            .WithLegacyTls12ClientHello()
            .WithCipherSuites(
                SharpTls.Protocol.TlsCipherSuite.TlsEcdheRsaWithAes128GcmSha256,
                SharpTls.Protocol.TlsCipherSuite.TlsEcdheRsaWithAes256GcmSha384)
            .WithSupportedGroups(NamedGroup.Secp256r1, NamedGroup.Secp384r1)
            .WithSignatureAlgorithms(
                SignatureScheme.RsaPssRsaeSha256,
                SignatureScheme.RsaPssRsaeSha384,
                SignatureScheme.RsaPkcs1Sha256,
                SignatureScheme.RsaPkcs1Sha384)
            .WithExtensionLayout(
                ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.ServerName),
                ClientHelloExtensionSpec.Raw(
                    (ushort)TlsExtensionType.ExtendedMasterSecret,
                    []),
                ClientHelloExtensionSpec.Raw(
                    (ushort)TlsExtensionType.RenegotiationInfo,
                    [0]),
                ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.SupportedGroups),
                ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.SignatureAlgorithms)));

        await RunMutualAuthenticationAsync(
            SslProtocols.Tls12,
            tls12Profile);
    }

    private static async Task RunMutualAuthenticationAsync(
        SslProtocols protocol,
        ClientHelloProfile profile)
    {
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        using var serverPki = TestPki.Create("localhost");
        using var clientPki = TestPki.Create(
            dnsName: "client.example",
            serverAuthenticationEku: false);
        using var serverLeafWithKey = serverPki.Leaf.CopyWithPrivateKey(
            (RSA)serverPki.LeafKey);
        using var clientLeafWithKey = clientPki.Leaf.CopyWithPrivateKey(
            (RSA)clientPki.LeafKey);
        using var clientCredential = new TlsClientCertificate(
            clientLeafWithKey,
            [clientPki.Root]);
        var serverContext = SslStreamCertificateContext.Create(
            serverLeafWithKey,
            [serverPki.Root],
            offline: true);
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start(1);
        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        X509Certificate2? observedClientCertificate = null;

        var serverTask = Task.Run(async () =>
        {
            using var socket = await listener.AcceptSocketAsync(timeout.Token).ConfigureAwait(false);
            await using var network = new NetworkStream(socket, ownsSocket: true);
            await using var tls = new SslStream(
                network,
                leaveInnerStreamOpen: false,
                (_, certificate, _, _) =>
                {
                    observedClientCertificate?.Dispose();
                    observedClientCertificate = certificate is null
                        ? null
                        : X509CertificateLoader.LoadCertificate(certificate.GetRawCertData());
                    return certificate is not null &&
                        certificate.GetRawCertData().AsSpan().SequenceEqual(clientPki.Leaf.RawData);
                });
            await tls.AuthenticateAsServerAsync(
                new SslServerAuthenticationOptions
                {
                    ServerCertificateContext = serverContext,
                    ClientCertificateRequired = true,
                    EnabledSslProtocols = protocol,
                    CertificateRevocationCheckMode = X509RevocationMode.NoCheck,
                },
                timeout.Token).ConfigureAwait(false);

            var request = new byte[4];
            await tls.ReadExactlyAsync(request, timeout.Token).ConfigureAwait(false);
            Assert.Equal("ping"u8.ToArray(), request);
            await tls.WriteAsync("pong"u8.ToArray(), timeout.Token).ConfigureAwait(false);
            await tls.FlushAsync(timeout.Token).ConfigureAwait(false);
        }, timeout.Token);

        try
        {
            await using var client = new CustomTlsClient(new CustomTlsClientOptions
            {
                ServerName = "localhost",
                ClientHello = profile,
                ClientCertificate = clientCredential,
                CertificateValidation = new CustomTlsCertificateValidationOptions
                {
                    RevocationMode = X509RevocationMode.NoCheck,
                    CustomTrustRoots = [serverPki.Root],
                },
            });
            await client.ConnectAsync("127.0.0.1", port, timeout.Token).ConfigureAwait(false);
            await client.WriteApplicationDataAsync("ping"u8.ToArray(), timeout.Token)
                .ConfigureAwait(false);
            var response = await client.ReadApplicationDataAsync(timeout.Token).ConfigureAwait(false);

            Assert.Equal(protocol == SslProtocols.Tls13
                ? TlsProtocolVersion.Tls13
                : TlsProtocolVersion.Tls12, client.NegotiatedProtocolVersion);
            Assert.Equal("pong"u8.ToArray(), response);
            await serverTask.ConfigureAwait(false);
            Assert.NotNull(observedClientCertificate);
            Assert.Equal(clientPki.Leaf.RawData, observedClientCertificate.RawData);
        }
        finally
        {
            listener.Stop();
            observedClientCertificate?.Dispose();
            await IgnoreCancellationAsync(serverTask).ConfigureAwait(false);
        }
    }

    private static async Task IgnoreCancellationAsync(Task task)
    {
        try
        {
            await task.ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
        }
        catch (SocketException)
        {
        }
    }
}
