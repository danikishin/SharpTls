using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using SharpTls.Certificates;
using SharpTls.Protocol;
using SharpTls.Tests.Certificates;

namespace SharpTls.Tests.Interop;

public sealed class DelegatedCredentialInteropTests
{
    [Fact]
    public async Task ManagedServerAuthenticatesClientDelegatedCredential()
    {
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        using var serverPki = TestPki.Create("localhost");
        using var clientPki = TestPki.Create(
            dnsName: "client.example",
            serverAuthenticationEku: false,
            delegationUsage: true);
        using var delegatedKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var delegatedSigner = new TestAsyncEcdsaSigner(delegatedKey);
        var encodedDelegatedCredential = ClientDelegatedCredentialTests
            .EncodeClientDelegatedCredential(
                clientPki,
                delegatedKey.ExportSubjectPublicKeyInfo(),
                TimeSpan.FromDays(1));
        using var delegatedCredential = new TlsClientDelegatedCredential(
            encodedDelegatedCredential,
            delegatedSigner);
        using var clientCredential = new TlsClientCertificate(
            clientPki.Leaf,
            new TestAsyncRsaSigner((RSA)clientPki.LeafKey),
            [clientPki.Root]);
        clientCredential.AttachDelegatedCredential(delegatedCredential);
        await using var server = new ManagedTls13MutualAuthServer(
            serverPki.Leaf,
            serverPki.Root,
            (RSA)serverPki.LeafKey,
            clientPki.Leaf.RawData,
            requestClientDelegatedCredential: true);
        TlsClientCertificateSelectionContext? observedContext = null;
        await using var client = new CustomTlsClient(new CustomTlsClientOptions
        {
            ServerName = "localhost",
            ClientCertificateSelector = (context, _) =>
            {
                observedContext = context;
                return ValueTask.FromResult<TlsClientCertificate?>(clientCredential);
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
        Assert.True(server.ClientDelegatedCredentialVerified);
        Assert.Equal(1, delegatedSigner.SignCount);
        Assert.NotNull(observedContext);
        Assert.Equal(
            [SignatureScheme.EcdsaSecp256r1Sha256],
            observedContext.DelegatedCredentialSignatureSchemes);
    }

    [Fact]
    public async Task ClientDelegatedCredentialSupportsPostHandshakeAuthentication()
    {
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        using var serverPki = TestPki.Create("localhost");
        using var clientPki = TestPki.Create(
            dnsName: "client.example",
            serverAuthenticationEku: false,
            delegationUsage: true);
        using var delegatedKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var delegatedSigner = new TestAsyncEcdsaSigner(delegatedKey);
        var encodedDelegatedCredential = ClientDelegatedCredentialTests
            .EncodeClientDelegatedCredential(
                clientPki,
                delegatedKey.ExportSubjectPublicKeyInfo(),
                TimeSpan.FromDays(1));
        using var delegatedCredential = new TlsClientDelegatedCredential(
            encodedDelegatedCredential,
            delegatedSigner);
        using var clientCredential = new TlsClientCertificate(
            clientPki.Leaf,
            new TestAsyncRsaSigner((RSA)clientPki.LeafKey));
        clientCredential.AttachDelegatedCredential(delegatedCredential);
        await using var server = new ManagedTls13MutualAuthServer(
            serverPki.Leaf,
            serverPki.Root,
            (RSA)serverPki.LeafKey,
            clientPki.Leaf.RawData,
            requestPostHandshakeAuthentication: true,
            requestClientDelegatedCredential: true);
        var profile = ClientHelloProfiles.Custom(builder => builder
            .WithPostHandshakeAuthentication());
        await using var client = CreateClient(
            serverPki.Root,
            clientCredential,
            profile);

        await client.ConnectAsync("127.0.0.1", server.Port, timeout.Token);
        var response = await client.ReadApplicationDataAsync(timeout.Token);
        await server.Completion;

        Assert.Equal("pong"u8.ToArray(), response);
        Assert.True(server.ClientDelegatedCredentialVerified);
        Assert.Equal(2, delegatedSigner.SignCount);
        Assert.Equal(1, client.PostHandshakeAuthenticationCount);
    }

    [Fact]
    public async Task ManagedServerAuthenticatesWithRsaSignedEcdsaDelegatedCredential()
    {
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        using var serverPki = TestPki.Create("localhost", delegationUsage: true);
        using var clientPki = TestPki.Create(
            dnsName: "client.example",
            serverAuthenticationEku: false);
        using var clientLeafWithKey = clientPki.Leaf.CopyWithPrivateKey(
            (RSA)clientPki.LeafKey);
        using var clientCredential = new TlsClientCertificate(
            clientLeafWithKey,
            [clientPki.Root]);
        using var delegatedKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        await using var server = new ManagedTls13MutualAuthServer(
            serverPki.Leaf,
            serverPki.Root,
            (RSA)serverPki.LeafKey,
            clientPki.Leaf.RawData,
            serverDelegatedCredentialKey: delegatedKey);
        await using var client = CreateClient(
            serverPki.Root,
            clientCredential,
            OfferDelegatedCredentials());

        await client.ConnectAsync("127.0.0.1", server.Port, timeout.Token);
        await client.WriteApplicationDataAsync("ping"u8.ToArray(), timeout.Token);
        var response = await client.ReadApplicationDataAsync(timeout.Token);
        await server.Completion;

        Assert.Equal("pong"u8.ToArray(), response);
        Assert.True(server.ClientCertificateVerified);
        Assert.True(client.ServerUsedDelegatedCredential);
        Assert.NotNull(client.ServerDelegatedCredentialExpiresAt);
    }

    [Fact]
    public async Task InvalidDelegationSignatureProducesFatalIllegalParameter()
    {
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        using var serverPki = TestPki.Create("localhost", delegationUsage: true);
        using var clientPki = TestPki.Create(
            dnsName: "client.example",
            serverAuthenticationEku: false);
        using var clientLeafWithKey = clientPki.Leaf.CopyWithPrivateKey(
            (RSA)clientPki.LeafKey);
        using var clientCredential = new TlsClientCertificate(clientLeafWithKey);
        using var delegatedKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        await using var server = new ManagedTls13MutualAuthServer(
            serverPki.Leaf,
            serverPki.Root,
            (RSA)serverPki.LeafKey,
            clientPki.Leaf.RawData,
            serverDelegatedCredentialKey: delegatedKey,
            tamperDelegatedCredential: true,
            expectDelegatedCredentialRejection: true);
        await using var client = CreateClient(
            serverPki.Root,
            clientCredential,
            OfferDelegatedCredentials());

        var exception = await Assert.ThrowsAsync<TlsProtocolException>(async () =>
            await client.ConnectAsync("127.0.0.1", server.Port, timeout.Token));
        await server.Completion;

        Assert.Equal(TlsAlertDescription.IllegalParameter, exception.Alert);
        Assert.True(server.DelegatedCredentialRejectionObserved);
    }

    [Fact]
    public async Task ManagedServerAuthenticatesWithRsaPssDelegatedCredential()
    {
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        using var serverPki = TestPki.Create("localhost", delegationUsage: true);
        using var delegated = RsaPssTestCertificate.Create(
            HashAlgorithmName.SHA256,
            serverAuthentication: true);
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
            serverRsaDelegatedCredentialKey: delegated.Key,
            serverRsaDelegatedCredentialSpki:
                delegated.Certificate.PublicKey.ExportSubjectPublicKeyInfo());
        await using var client = CreateClient(
            serverPki.Root,
            clientCredential,
            ClientHelloProfiles.Custom(builder => builder
                .WithCipherSuites(TlsCipherSuite.TlsAes128GcmSha256)
                .WithSupportedGroups(NamedGroup.Secp256r1)
                .WithDelegatedCredentials(SignatureScheme.RsaPssPssSha256)));

        await client.ConnectAsync("127.0.0.1", server.Port, timeout.Token);
        await client.WriteApplicationDataAsync("ping"u8.ToArray(), timeout.Token);
        var response = await client.ReadApplicationDataAsync(timeout.Token);
        await server.Completion;

        Assert.Equal("pong"u8.ToArray(), response);
        Assert.True(client.ServerUsedDelegatedCredential);
    }

    private static ClientHelloProfile OfferDelegatedCredentials() =>
        ClientHelloProfiles.Custom(builder => builder
            .WithCipherSuites(TlsCipherSuite.TlsAes128GcmSha256)
            .WithSupportedGroups(NamedGroup.Secp256r1)
            .WithDelegatedCredentials(SignatureScheme.EcdsaSecp256r1Sha256));

    private static CustomTlsClient CreateClient(
        X509Certificate2 trustRoot,
        TlsClientCertificate clientCredential,
        ClientHelloProfile profile) => new(new CustomTlsClientOptions
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
