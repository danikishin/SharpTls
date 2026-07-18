using System.Security.Cryptography;
using SharpTls.Cryptography;
using SharpTls.Protocol;

namespace SharpTls.Tests.Cryptography;

public sealed class X25519MlKem768Tests
{
    [Fact]
    public void ClientAndServerDeriveTheSameHybridSecret()
    {
        using var client = X25519MlKem768KeyShare.Create();
        using var server = Tls13ServerKeyExchange.Create(
            NamedGroup.X25519MlKem768,
            client.PublicKey.Span);
        var clientSecret = client.DeriveSharedSecret(server.PublicKey.Span);
        var serverSecret = server.ExportSharedSecret();
        try
        {
            Assert.Equal(X25519MlKem768KeyShare.ClientShareSize, client.PublicKey.Length);
            Assert.Equal(X25519MlKem768KeyShare.ServerShareSize, server.PublicKey.Length);
            Assert.Equal(X25519MlKem768KeyShare.HybridSecretSize, clientSecret.Length);
            Assert.Equal(clientSecret, serverSecret);
            Assert.Throws<InvalidOperationException>(() => server.ExportSharedSecret());
        }
        finally
        {
            CryptographicOperations.ZeroMemory(clientSecret);
            CryptographicOperations.ZeroMemory(serverSecret);
        }
    }

    [Fact]
    public void HybridShareRejectsMalformedAndLowOrderInputs()
    {
        using var client = X25519MlKem768KeyShare.Create();
        var malformedServer = Assert.Throws<TlsProtocolException>(() =>
            client.DeriveSharedSecret(
                new byte[X25519MlKem768KeyShare.ServerShareSize - 1]));
        Assert.Equal(TlsAlertDescription.IllegalParameter, malformedServer.Alert);

        var lowOrderServer = new byte[X25519MlKem768KeyShare.ServerShareSize];
        var lowOrder = Assert.Throws<TlsProtocolException>(() =>
            client.DeriveSharedSecret(lowOrderServer));
        Assert.Equal(TlsAlertDescription.IllegalParameter, lowOrder.Alert);

        var malformedClient = Assert.Throws<TlsProtocolException>(() =>
            Tls13ServerKeyExchange.Create(
                NamedGroup.X25519MlKem768,
                new byte[X25519MlKem768KeyShare.ClientShareSize - 1]));
        Assert.Equal(TlsAlertDescription.IllegalParameter, malformedClient.Alert);

        var invalidClient = new byte[X25519MlKem768KeyShare.ClientShareSize];
        invalidClient[0] = 0xFF;
        invalidClient[1] = 0x0F;
        var nonCanonical = Assert.Throws<TlsProtocolException>(() =>
            Tls13ServerKeyExchange.Create(NamedGroup.X25519MlKem768, invalidClient));
        Assert.Equal(TlsAlertDescription.IllegalParameter, nonCanonical.Alert);
    }

    [Fact]
    public void HybridAndClassicalEntriesReuseTheX25519Component()
    {
        using var shares = new KeyShareSet(deterministicForTesting: true);
        shares.Generate([NamedGroup.X25519MlKem768, NamedGroup.X25519]);

        var hybrid = shares.Get(NamedGroup.X25519MlKem768).PublicKey.Span;
        var classical = shares.Get(NamedGroup.X25519).PublicKey.Span;
        Assert.True(hybrid[^X25519.KeyLength..].SequenceEqual(classical));
    }

    [Fact]
    public void KyberDraftCompatibilityTransformMatchesIndependentVector()
    {
        var secret = Enumerable.Range(0, 32).Select(value => (byte)value).ToArray();
        var ciphertext = Enumerable.Range(0, MlKem768.CiphertextSize)
            .Select(value => (byte)(value * 7 + 3))
            .ToArray();
        var transformed = X25519Kyber768Draft00KeyShare.TransformSharedSecret(
            secret,
            ciphertext);
        try
        {
            Assert.Equal(
                "97D8474A686144353542D191117BB930B3EAAA5C807F1B0B1928B8CB05FEC58C",
                Convert.ToHexString(transformed));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(secret);
            CryptographicOperations.ZeroMemory(ciphertext);
            CryptographicOperations.ZeroMemory(transformed);
        }
    }

    [Fact]
    public void KyberDraftClientAndServerAgreeWithDraftComponentOrdering()
    {
        using var client = X25519Kyber768Draft00KeyShare.Create();
        using var server = Tls13ServerKeyExchange.Create(
            NamedGroup.X25519Kyber768Draft00,
            client.PublicKey.Span);
        var clientSecret = client.DeriveSharedSecret(server.PublicKey.Span);
        var serverSecret = server.ExportSharedSecret();
        try
        {
            Assert.Equal(X25519Kyber768Draft00KeyShare.ClientShareSize, client.PublicKey.Length);
            Assert.Equal(X25519Kyber768Draft00KeyShare.ServerShareSize, server.PublicKey.Length);
            Assert.Equal(clientSecret, serverSecret);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(clientSecret);
            CryptographicOperations.ZeroMemory(serverSecret);
        }
    }

    [Fact]
    public void KyberDraftAndClassicalEntriesReuseTheLeadingX25519Component()
    {
        using var shares = new KeyShareSet(deterministicForTesting: true);
        shares.Generate([NamedGroup.X25519Kyber768Draft00, NamedGroup.X25519]);

        var hybrid = shares.Get(NamedGroup.X25519Kyber768Draft00).PublicKey.Span;
        var classical = shares.Get(NamedGroup.X25519).PublicKey.Span;
        Assert.True(hybrid[..X25519.KeyLength].SequenceEqual(classical));
    }
}
