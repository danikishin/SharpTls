using System.Security.Cryptography;
using SharpTls.Cryptography;
using SharpTls.Protocol;

namespace SharpTls.Tests.Cryptography;

public sealed class EcdheKeyShareTests
{
    [Theory]
    [InlineData(NamedGroup.Secp256r1, 65)]
    [InlineData(NamedGroup.Secp384r1, 97)]
    [InlineData(NamedGroup.Secp521r1, 133)]
    public void TwoPartiesDeriveSameCanonicalSecret(NamedGroup group, int publicLength)
    {
        using var alice = EcdheKeyShare.Create(group);
        using var bob = EcdheKeyShare.Create(group);

        Assert.Equal(publicLength, alice.PublicKey.Length);
        Assert.Equal(4, alice.PublicKey.Span[0]);

        var aliceSecret = alice.DeriveSharedSecret(bob.PublicKey.Span);
        var bobSecret = bob.DeriveSharedSecret(alice.PublicKey.Span);
        try
        {
            var expectedSecretLength = group switch
            {
                NamedGroup.Secp256r1 => 32,
                NamedGroup.Secp384r1 => 48,
                NamedGroup.Secp521r1 => 66,
                _ => throw new InvalidOperationException(),
            };
            Assert.Equal(expectedSecretLength, aliceSecret.Length);
            Assert.Equal(aliceSecret, bobSecret);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(aliceSecret);
            CryptographicOperations.ZeroMemory(bobSecret);
        }
    }

    [Fact]
    public void TruncatedPointIsRejected()
    {
        using var share = EcdheKeyShare.Create(NamedGroup.Secp256r1);
        var exception = Assert.Throws<TlsProtocolException>(() => share.DeriveSharedSecret(new byte[64]));
        Assert.Equal(TlsAlertDescription.IllegalParameter, exception.Alert);
    }

    [Fact]
    public void OffCurvePointIsRejectedByRuntimeProvider()
    {
        using var share = EcdheKeyShare.Create(NamedGroup.Secp256r1);
        var hostile = new byte[65];
        hostile[0] = 4;

        var exception = Assert.Throws<TlsProtocolException>(() => share.DeriveSharedSecret(hostile));
        Assert.Equal(TlsAlertDescription.IllegalParameter, exception.Alert);
    }

    [Fact]
    public void AgreementIsSingleUse()
    {
        using var alice = EcdheKeyShare.Create(NamedGroup.Secp256r1);
        using var bob = EcdheKeyShare.Create(NamedGroup.Secp256r1);
        var secret = alice.DeriveSharedSecret(bob.PublicKey.Span);
        CryptographicOperations.ZeroMemory(secret);

        Assert.Throws<InvalidOperationException>(() => alice.DeriveSharedSecret(bob.PublicKey.Span));
    }

    [Fact]
    public void DisposeZerosOwnedPublicBufferAndBlocksUse()
    {
        var share = EcdheKeyShare.Create(NamedGroup.Secp256r1);
        var publicMemory = share.PublicKey;
        share.Dispose();

        Assert.True(publicMemory.Span.IndexOfAnyExcept((byte)0) < 0);
        Assert.Throws<ObjectDisposedException>(() => _ = share.PublicKey);
    }
}
