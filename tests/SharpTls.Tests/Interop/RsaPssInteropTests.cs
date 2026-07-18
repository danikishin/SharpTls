using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using SharpTls.Certificates;
using SharpTls.Protocol;
using SharpTls.Tests.Certificates;

namespace SharpTls.Tests.Interop;

public sealed class RsaPssInteropTests
{
    [Fact]
    public async Task RsaPssSubjectPublicKeyCompletesAuthenticatedTls13AndApplicationTraffic()
    {
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        using var serverPki = RsaPssTestCertificate.Create(
            HashAlgorithmName.SHA256,
            serverAuthentication: true);
        using var clientPki = TestPki.Create(
            dnsName: "client.example",
            serverAuthenticationEku: false);
        using var clientLeafWithKey = clientPki.Leaf.CopyWithPrivateKey(
            (RSA)clientPki.LeafKey);
        using var clientCredential = new TlsClientCertificate(clientLeafWithKey);
        await using var server = new ManagedTls13MutualAuthServer(
            serverPki.Certificate,
            serverPki.Issuer,
            serverPki.Key,
            clientPki.Leaf.RawData,
            serverSignatureScheme: SignatureScheme.RsaPssPssSha256);
        var options = new CustomTlsClientOptions
        {
            ServerName = "example.com",
            ClientHello = ClientHelloProfiles.Custom(builder => builder
                .WithTls13()
                .WithSignatureAlgorithms(
                    SignatureScheme.RsaPssPssSha256,
                    SignatureScheme.RsaPssRsaeSha256)),
            ClientCertificate = clientCredential,
            CertificateValidation = new CustomTlsCertificateValidationOptions
            {
                RevocationMode = X509RevocationMode.NoCheck,
                CustomTrustRoots = [serverPki.Issuer],
            },
        };
        await using var client = new CustomTlsClient(options);

        await client.ConnectAsync("127.0.0.1", server.Port, timeout.Token);
        await client.WriteApplicationDataAsync("ping"u8.ToArray(), timeout.Token);
        var response = await client.ReadApplicationDataAsync(timeout.Token);
        await server.Completion;

        Assert.Equal("pong"u8.ToArray(), response);
        Assert.Equal(TlsProtocolVersion.Tls13, client.NegotiatedProtocolVersion);
    }
}
