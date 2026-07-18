using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using SharpTls.Certificates;
using SharpTls.Protocol;
using SharpTls.Tests.Certificates;

namespace SharpTls.Tests.Interop;

public sealed class CertificateEvidenceInteropTests
{
    [Fact]
    public async Task AdditionalOcspAndSctPolicyCompletesAfterSystemValidation()
    {
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        using var serverPki = TestPki.Create("localhost");
        using var clientPki = TestPki.Create(
            dnsName: "client.example",
            serverAuthenticationEku: false);
        using var clientLeafWithKey = clientPki.Leaf.CopyWithPrivateKey(
            (RSA)clientPki.LeafKey);
        using var clientCredential = new TlsClientCertificate(clientLeafWithKey);
        byte[] ocsp = [1, 2, 3, 4];
        byte[][] scts = [[5, 6, 7]];
        await using var server = new ManagedTls13MutualAuthServer(
            serverPki.Leaf,
            serverPki.Root,
            (RSA)serverPki.LeafKey,
            clientPki.Leaf.RawData,
            serverOcspResponse: ocsp,
            serverSignedCertificateTimestamps: scts);
        var callbackCount = 0;
        await using var client = CreateClient(
            serverPki.Root,
            clientCredential,
            async (evidence, cancellationToken) =>
            {
                await Task.Yield();
                cancellationToken.ThrowIfCancellationRequested();
                Interlocked.Increment(ref callbackCount);
                Assert.Equal("localhost", evidence.ServerName);
                Assert.Equal(TlsProtocolVersion.Tls13, evidence.ProtocolVersion);
                Assert.Equal(serverPki.Leaf.RawData, evidence.CertificateChain[0]);
                Assert.Equal(ocsp, evidence.StapledOcspResponse);
                Assert.Equal(scts[0], Assert.Single(evidence.SignedCertificateTimestamps));

                var mutated = evidence.StapledOcspResponse!;
                mutated[0] ^= 0xFF;
                Assert.Equal(ocsp, evidence.StapledOcspResponse);
                return new TlsServerCertificateEvidenceValidationResult(
                    TlsStapledOcspValidationStatus.Good,
                    validSignedCertificateTimestampCount: 1);
            });

        await client.ConnectAsync("127.0.0.1", server.Port, timeout.Token);
        await client.WriteApplicationDataAsync("ping"u8.ToArray(), timeout.Token);
        var response = await client.ReadApplicationDataAsync(timeout.Token);
        await server.Completion;

        Assert.Equal("pong"u8.ToArray(), response);
        Assert.Equal(1, callbackCount);
        Assert.True(server.ClientCertificateVerified);
    }

    [Fact]
    public async Task InvalidStapleFailsWithDedicatedFatalAlert()
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
            serverOcspResponse: [0xFF],
            serverSignedCertificateTimestamps: [[1]],
            expectCertificateEvidenceRejection: true);
        await using var client = CreateClient(
            serverPki.Root,
            clientCredential,
            (_, _) => ValueTask.FromResult(
                new TlsServerCertificateEvidenceValidationResult(
                    TlsStapledOcspValidationStatus.Invalid,
                    validSignedCertificateTimestampCount: 0)));

        var exception = await Assert.ThrowsAsync<TlsProtocolException>(async () =>
            await client.ConnectAsync("127.0.0.1", server.Port, timeout.Token));
        await server.Completion;

        Assert.Equal(TlsAlertDescription.BadCertificateStatusResponse, exception.Alert);
        Assert.True(server.CertificateEvidenceRejectionObserved);
    }

    private static CustomTlsClient CreateClient(
        X509Certificate2 trustRoot,
        TlsClientCertificate clientCredential,
        TlsServerCertificateEvidenceValidator validator)
    {
        var profile = ClientHelloProfiles.Custom(builder => builder
            .WithCipherSuites(TlsCipherSuite.TlsAes128GcmSha256)
            .WithSupportedGroups(NamedGroup.Secp256r1)
            .WithExtensionLayout(
                ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.ServerName),
                ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.SupportedVersions),
                ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.SupportedGroups),
                ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.SignatureAlgorithms),
                ClientHelloExtensionSpec.Raw(
                    (ushort)TlsExtensionType.StatusRequest,
                    [1, 0, 0, 0, 0]),
                ClientHelloExtensionSpec.Raw(
                    (ushort)TlsExtensionType.SignedCertificateTimestamp,
                    []),
                ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.KeyShare)));
        return new CustomTlsClient(new CustomTlsClientOptions
        {
            ServerName = "localhost",
            ClientHello = profile,
            ClientCertificate = clientCredential,
            CertificateValidation = new CustomTlsCertificateValidationOptions
            {
                RevocationMode = X509RevocationMode.NoCheck,
                CustomTrustRoots = [trustRoot],
                EvidenceValidator = validator,
                RequireValidStapledOcspResponse = true,
                MinimumValidSignedCertificateTimestamps = 1,
            },
        });
    }
}
