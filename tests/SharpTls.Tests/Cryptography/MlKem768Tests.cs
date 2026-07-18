using System.Security.Cryptography;
using SharpTls.Cryptography;

namespace SharpTls.Tests.Cryptography;

public sealed class MlKem768Tests
{
    [Fact]
    public void GoFips203AccumulatedVectorMatchesForOneHundredCases()
    {
        Assert.True(MlKem768.IsSupported);
        using var input = Fips202.CreateShake128();
        using var output = Fips202.CreateShake128();
        var seed = new byte[MlKem768.SeedSize];
        var message = new byte[MlKem768.SharedSecretSize];
        var invalidCiphertext = new byte[MlKem768.CiphertextSize];

        try
        {
            for (var index = 0; index < 100; index++)
            {
                input.Read(seed);
                using var key = MlKem768.GenerateKeyDeterministicForTesting(seed);
                var publicKey = key.ExportEncapsulationKey();
                output.AppendData(publicKey);

                input.Read(message);
                var encapsulation = MlKem768.EncapsulateDeterministicForTesting(
                    publicKey,
                    message);
                output.AppendData(encapsulation.Ciphertext);
                output.AppendData(encapsulation.SharedSecret);

                var decapsulated = key.Decapsulate(encapsulation.Ciphertext);
                Assert.Equal(encapsulation.SharedSecret, decapsulated);

                input.Read(invalidCiphertext);
                var implicitlyRejected = key.Decapsulate(invalidCiphertext);
                output.AppendData(implicitlyRejected);

                CryptographicOperations.ZeroMemory(publicKey);
                CryptographicOperations.ZeroMemory(encapsulation.Ciphertext);
                CryptographicOperations.ZeroMemory(encapsulation.SharedSecret);
                CryptographicOperations.ZeroMemory(decapsulated);
                CryptographicOperations.ZeroMemory(implicitlyRejected);
            }

            var digest = output.GetCurrentHash(32);
            Assert.Equal(
                "1114B1B6699ED191734FA339376AFA7E285C9E6ACF6FF0177D346696CE564415",
                Convert.ToHexString(digest));
            CryptographicOperations.ZeroMemory(digest);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(seed);
            CryptographicOperations.ZeroMemory(message);
            CryptographicOperations.ZeroMemory(invalidCiphertext);
        }
    }

    [Fact]
    public void GeneratedKeyRoundTripsAndTamperingUsesImplicitRejection()
    {
        using var key = MlKem768.GenerateKey();
        var publicKey = key.ExportEncapsulationKey();
        var encapsulation = MlKem768.Encapsulate(publicKey);
        var decapsulated = key.Decapsulate(encapsulation.Ciphertext);
        var tampered = (byte[])encapsulation.Ciphertext.Clone();
        tampered[17] ^= 0x80;
        var rejected = key.Decapsulate(tampered);

        Assert.Equal(MlKem768.EncapsulationKeySize, publicKey.Length);
        Assert.Equal(MlKem768.CiphertextSize, encapsulation.Ciphertext.Length);
        Assert.Equal(MlKem768.SharedSecretSize, encapsulation.SharedSecret.Length);
        Assert.Equal(encapsulation.SharedSecret, decapsulated);
        Assert.NotEqual(encapsulation.SharedSecret, rejected);

        CryptographicOperations.ZeroMemory(publicKey);
        CryptographicOperations.ZeroMemory(encapsulation.Ciphertext);
        CryptographicOperations.ZeroMemory(encapsulation.SharedSecret);
        CryptographicOperations.ZeroMemory(decapsulated);
        CryptographicOperations.ZeroMemory(tampered);
        CryptographicOperations.ZeroMemory(rejected);
    }

    [Fact]
    public void MalformedLengthsAndNonCanonicalPublicKeyAreRejected()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() =>
            MlKem768.GenerateKeyDeterministicForTesting(new byte[MlKem768.SeedSize - 1]));
        Assert.Throws<CryptographicException>(() =>
            MlKem768.Encapsulate(new byte[MlKem768.EncapsulationKeySize - 1]));

        var nonCanonical = new byte[MlKem768.EncapsulationKeySize];
        nonCanonical[0] = 0xFF;
        nonCanonical[1] = 0x0F;
        Assert.Throws<CryptographicException>(() => MlKem768.Encapsulate(nonCanonical));

        using var key = MlKem768.GenerateKey();
        Assert.Throws<CryptographicException>(() =>
            key.Decapsulate(new byte[MlKem768.CiphertextSize - 1]));
    }

    [Fact]
    public void DisposedKeyRejectsFurtherUse()
    {
        var key = MlKem768.GenerateKey();
        key.Dispose();

        Assert.Throws<ObjectDisposedException>(() => key.ExportEncapsulationKey());
        Assert.Throws<ObjectDisposedException>(() =>
            key.Decapsulate(new byte[MlKem768.CiphertextSize]));
    }
}
