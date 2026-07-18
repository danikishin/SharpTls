using System.Security.Cryptography;
using SharpTls.Cryptography;
using SharpTls.Protocol;

namespace SharpTls.Tests.Cryptography;

public sealed class X25519Tests
{
    [Theory]
    [InlineData(
        "a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4",
        "e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c",
        "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552")]
    [InlineData(
        "4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d",
        "e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493",
        "95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957")]
    public void Rfc7748ScalarMultiplicationVectors(string scalarHex, string uHex, string expectedHex)
    {
        var result = new byte[X25519.KeyLength];
        X25519.ScalarMultiply(Convert.FromHexString(scalarHex), Convert.FromHexString(uHex), result);

        Assert.Equal(Convert.FromHexString(expectedHex), result);
    }

    [Fact]
    public void Rfc7748DiffieHellmanVector()
    {
        var alicePrivate = Convert.FromHexString(
            "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
        var bobPrivate = Convert.FromHexString(
            "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb");
        var alicePublic = new byte[X25519.KeyLength];
        var bobPublic = new byte[X25519.KeyLength];
        var aliceSecret = new byte[X25519.KeyLength];
        var bobSecret = new byte[X25519.KeyLength];
        try
        {
            X25519.DerivePublicKey(alicePrivate, alicePublic);
            X25519.DerivePublicKey(bobPrivate, bobPublic);
            X25519.ScalarMultiply(alicePrivate, bobPublic, aliceSecret);
            X25519.ScalarMultiply(bobPrivate, alicePublic, bobSecret);

            Assert.Equal(
                Convert.FromHexString("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"),
                alicePublic);
            Assert.Equal(
                Convert.FromHexString("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f"),
                bobPublic);
            Assert.Equal(
                Convert.FromHexString("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742"),
                aliceSecret);
            Assert.Equal(aliceSecret, bobSecret);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(alicePrivate);
            CryptographicOperations.ZeroMemory(bobPrivate);
            CryptographicOperations.ZeroMemory(aliceSecret);
            CryptographicOperations.ZeroMemory(bobSecret);
        }
    }

    [Fact]
    public void Rfc7748OneThousandIterationVector()
    {
        var k = new byte[X25519.KeyLength];
        var u = new byte[X25519.KeyLength];
        k[0] = 9;
        u[0] = 9;

        for (var iteration = 0; iteration < 1_000; iteration++)
        {
            var oldK = k;
            var result = new byte[X25519.KeyLength];
            X25519.ScalarMultiply(k, u, result);
            k = result;
            u = oldK;
        }

        Assert.Equal(
            Convert.FromHexString("684cf59ba83309552800ef566f2f4d3c1c3887c49360e3875f2eb94d99532c51"),
            k);
    }

    [Fact]
    public void KeyShareRejectsAllZeroAndMalformedPeerInputs()
    {
        using var share = X25519KeyShare.Create();

        var malformed = Assert.Throws<TlsProtocolException>(() => share.DeriveSharedSecret(new byte[31]));
        Assert.Equal(TlsAlertDescription.IllegalParameter, malformed.Alert);

        var lowOrder = Assert.Throws<TlsProtocolException>(() => share.DeriveSharedSecret(new byte[32]));
        Assert.Equal(TlsAlertDescription.IllegalParameter, lowOrder.Alert);
    }

    [Fact]
    public void KeySharesAgreeAndAreSingleUse()
    {
        using var alice = X25519KeyShare.Create();
        using var bob = X25519KeyShare.Create();
        var aliceSecret = alice.DeriveSharedSecret(bob.PublicKey.Span);
        var bobSecret = bob.DeriveSharedSecret(alice.PublicKey.Span);
        try
        {
            Assert.Equal(X25519.KeyLength, alice.PublicKey.Length);
            Assert.Equal(aliceSecret, bobSecret);
            Assert.Throws<InvalidOperationException>(() => alice.DeriveSharedSecret(bob.PublicKey.Span));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(aliceSecret);
            CryptographicOperations.ZeroMemory(bobSecret);
        }
    }

    [Fact]
    public void DisposeZerosOwnedKeyMaterialAndBlocksUse()
    {
        var share = X25519KeyShare.Create();
        var publicKey = share.PublicKey;
        share.Dispose();

        Assert.True(publicKey.Span.IndexOfAnyExcept((byte)0) < 0);
        Assert.Throws<ObjectDisposedException>(() => _ = share.PublicKey);
    }
}
