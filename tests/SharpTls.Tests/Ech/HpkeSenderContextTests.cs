using System.Security.Cryptography;
using SharpTls.Cryptography;
using SharpTls.Ech;

namespace SharpTls.Tests.Ech;

public sealed class HpkeSenderContextTests
{
    private static readonly byte[] Info = Hex(
        "4f6465206f6e2061204772656369616e2055726e");
    private static readonly byte[] Plaintext = Hex(
        "4265617574792069732074727574682c20747275746820626561757479");

    [Fact]
    public void Rfc9180AppendixA3P256BaseVectorMatchesSenderAndReceiver()
    {
        if (!HpkeNistKem.IsSupported(TlsHpkeKemId.DhkemP256HkdfSha256))
        {
            return;
        }
        var suite = new TlsHpkeSymmetricCipherSuite(
            TlsHpkeKdfId.HkdfSha256,
            TlsHpkeAeadId.Aes128Gcm);
        var ephemeralPublicKey = Hex(
            "04a92719c6195d5085104f469a8b9814d5838ff72b60501e2c4466e5e67b325" +
            "ac98536d7b61a1af4b78e5b7f951c0900be863c403ce65c9bfcb9382657222d18c4");
        var receiverPublicKey = Hex(
            "04fe8c19ce0905191ebc298a9245792531f26f0cece2460639e8bc39cb7f706" +
            "a826a779b4cf969b8a0e539c7f62fb3d30ad6aa8f80e30f1d128aafd68a2ce72ea0");
        var receiverPrivateKey = Hex(
            "f3ce7fdae57e1a310d87f1ebbde6f328be0a99cdbcadf4d6589cf29de4b8ffd2");
        using var sender = HpkeSenderContext.SetupBaseNistForTesting(
            TlsHpkeKemId.DhkemP256HkdfSha256,
            suite,
            receiverPublicKey,
            Info,
            Hex("4995788ef4b9d6132b249ce59a77281493eb39af373d236a1fe415cb0c2d7beb"),
            ephemeralPublicKey);

        Assert.Equal(ephemeralPublicKey, sender.EncapsulatedKey);
        var ciphertext = sender.Seal("Count-0"u8, Plaintext);
        Assert.Equal(
            Hex("5ad590bb8baa577f8619db35a36311226a896e7342a6d836d8b7bcd2f20b6c7f" +
                "9076ac232e3ab2523f39513434"),
            ciphertext);
        Assert.Equal(
            Hex("5e9bc3d236e1911d95e65b576a8a86d478fb827e8bdfe77b741b289890490d4d"),
            sender.Export([], 32));

        using var receiver = HpkeReceiverContext.SetupBaseNist(
            TlsHpkeKemId.DhkemP256HkdfSha256,
            suite,
            receiverPrivateKey,
            receiverPublicKey,
            ephemeralPublicKey,
            Info);
        Assert.Equal(Plaintext, receiver.Open("Count-0"u8, ciphertext));
    }

    [Fact]
    public void Rfc9180AppendixA6P521BaseVectorMatchesSenderAndReceiver()
    {
        if (!HpkeNistKem.IsSupported(TlsHpkeKemId.DhkemP521HkdfSha512))
        {
            return;
        }
        var suite = new TlsHpkeSymmetricCipherSuite(
            TlsHpkeKdfId.HkdfSha512,
            TlsHpkeAeadId.Aes256Gcm);
        var ephemeralPublicKey = Hex(
            "040138b385ca16bb0d5fa0c0665fbbd7e69e3ee29f63991d3e9b5fa740aab890" +
            "0aaeed46ed73a49055758425a0ce36507c54b29cc5b85a5cee6bae0cf1c21f2731" +
            "ece2013dc3fb7c8d21654bb161b463962ca19e8c654ff24c94dd2898de12051f1e" +
            "d0692237fb02b2f8d1dc1c73e9b366b529eb436e98a996ee522aef863dd5739d2f29b0");
        var receiverPublicKey = Hex(
            "0401b45498c1714e2dce167d3caf162e45e0642afc7ed435df7902ccae0e84ba0f" +
            "7d373f646b7738bbbdca11ed91bdeae3cdcba3301f2457be452f271fa6837580e6" +
            "61012af49583a62e48d44bed350c7118c0d8dc861c238c72a2bda17f64704f464" +
            "b57338e7f40b60959480c0e58e6559b190d81663ed816e523b6b6a418f66d2451ec64");
        var receiverPrivateKey = Hex(
            "01462680369ae375e4b3791070a7458ed527842f6a98a79ff5e0d4cbde83c27196" +
            "a3916956655523a6a2556a7af62c5cadabe2ef9da3760bb21e005202f7b2462847");
        using var sender = HpkeSenderContext.SetupBaseNistForTesting(
            TlsHpkeKemId.DhkemP521HkdfSha512,
            suite,
            receiverPublicKey,
            Info,
            Hex(
                "014784c692da35df6ecde98ee43ac425dbdd0969c0c72b42f2e708ab9d535415a8" +
                "569bdacfcc0a114c85b8e3f26acf4d68115f8c91a66178cdbd03b7bcc5291e374b"),
            ephemeralPublicKey);

        Assert.Equal(ephemeralPublicKey, sender.EncapsulatedKey);
        var ciphertext = sender.Seal("Count-0"u8, Plaintext);
        Assert.Equal(
            Hex("170f8beddfe949b75ef9c387e201baf4132fa7374593dfafa90768788b7b2b200" +
                "aafcc6d80ea4c795a7c5b841a"),
            ciphertext);
        Assert.Equal(
            Hex("05e2e5bd9f0c30832b80a279ff211cc65eceb0d97001524085d609ead60d0412"),
            sender.Export([], 32));

        using var receiver = HpkeReceiverContext.SetupBaseNist(
            TlsHpkeKemId.DhkemP521HkdfSha512,
            suite,
            receiverPrivateKey,
            receiverPublicKey,
            ephemeralPublicKey,
            Info);
        Assert.Equal(Plaintext, receiver.Open("Count-0"u8, ciphertext));
    }

    [Fact]
    public void P384RoundTripUsesDeterministicRfc9180KeyDerivation()
    {
        if (!HpkeNistKem.IsSupported(TlsHpkeKemId.DhkemP384HkdfSha384))
        {
            return;
        }
        using var recipient = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP384);
        var recipientParameters = recipient.ExportParameters(includePrivateParameters: true);
        var receiverPublicKey = SerializePublicKey(recipientParameters, 48);
        var receiverPrivateKey = Assert.IsType<byte[]>(recipientParameters.D);
        var suite = new TlsHpkeSymmetricCipherSuite(
            TlsHpkeKdfId.HkdfSha384,
            TlsHpkeAeadId.Aes128Gcm);
        using var firstRandom = new DeterministicRandomSource("p384-hpke-test"u8);
        using var secondRandom = new DeterministicRandomSource("p384-hpke-test"u8);
        using var first = HpkeSenderContext.SetupBase(
            TlsHpkeKemId.DhkemP384HkdfSha384,
            suite,
            receiverPublicKey,
            Info,
            firstRandom);
        using var second = HpkeSenderContext.SetupBase(
            TlsHpkeKemId.DhkemP384HkdfSha384,
            suite,
            receiverPublicKey,
            Info,
            secondRandom);

        Assert.Equal(first.EncapsulatedKey, second.EncapsulatedKey);
        var firstCiphertext = first.Seal("deterministic"u8, Plaintext);
        Assert.Equal(firstCiphertext, second.Seal("deterministic"u8, Plaintext));

        using var receiver = HpkeReceiverContext.SetupBaseNist(
            TlsHpkeKemId.DhkemP384HkdfSha384,
            suite,
            receiverPrivateKey,
            receiverPublicKey,
            first.EncapsulatedKey,
            Info);
        Assert.Equal(Plaintext, receiver.Open("deterministic"u8, firstCiphertext));
    }

    [Fact]
    public void Rfc9180AppendixA1BaseAes128GcmVectorMatches()
    {
        var ikmE = Hex("7268600d403fce431561aef583ee1613527cff655c1343f29812e66706df3234");
        var receiverPublicKey = Hex(
            "3948cfe0ad1ddb695d780e59077195da6c56506b027329794ab02bca80815c4d");
        using var context = HpkeSenderContext.SetupBaseX25519ForTesting(
            new TlsHpkeSymmetricCipherSuite(
                TlsHpkeKdfId.HkdfSha256,
                TlsHpkeAeadId.Aes128Gcm),
            receiverPublicKey,
            Info,
            ikmE);

        Assert.Equal(
            Hex("37fda3567bdbd628e88668c3c8d7e97d1d1253b6d4ea6d44c150f741f1bf4431"),
            context.EncapsulatedKey);
        Assert.Equal(
            Hex("f938558b5d72f1a23810b4be2ab4f84331acc02fc97babc53a52ae8218a355a96d8770ac83d07bea87e13c512a"),
            context.Seal("Count-0"u8, Plaintext));
        Assert.Equal(
            Hex("af2d7e9ac9ae7e270f46ba1f975be53c09f8d875bdc8535458c2494e8a6eab251c03d0c22a56b8ca42c2063b84"),
            context.Seal("Count-1"u8, Plaintext));
        Assert.Equal(
            Hex("3853fe2b4035195a573ffc53856e77058e15d9ea064de3e59f4961d0095250ee"),
            context.Export([], 32));
        Assert.Equal(
            Hex("2e8f0b54673c7029649d4eb9d5e33bf1872cf76d623ff164ac185da9e88c21a5"),
            context.Export([0], 32));
    }

    [Fact]
    public void Rfc9180AppendixA2BaseChaCha20Poly1305VectorMatches()
    {
        if (!System.Security.Cryptography.ChaCha20Poly1305.IsSupported)
        {
            return;
        }
        var ikmE = Hex("909a9b35d3dc4713a5e72a4da274b55d3d3821a37e5d099e74a647db583a904b");
        var receiverPublicKey = Hex(
            "4310ee97d88cc1f088a5576c77ab0cf5c3ac797f3d95139c6c84b5429c59662a");
        using var context = HpkeSenderContext.SetupBaseX25519ForTesting(
            new TlsHpkeSymmetricCipherSuite(
                TlsHpkeKdfId.HkdfSha256,
                TlsHpkeAeadId.ChaCha20Poly1305),
            receiverPublicKey,
            Info,
            ikmE);

        Assert.Equal(
            Hex("1afa08d3dec047a643885163f1180476fa7ddb54c6a8029ea33f95796bf2ac4a"),
            context.EncapsulatedKey);
        Assert.Equal(
            Hex("1c5250d8034ec2b784ba2cfd69dbdb8af406cfe3ff938e131f0def8c8b60b4db21993c62ce81883d2dd1b51a28"),
            context.Seal("Count-0"u8, Plaintext));
        Assert.Equal(
            Hex("6b53c051e4199c518de79594e1c4ab18b96f081549d45ce015be002090bb119e85285337cc95ba5f59992dc98c"),
            context.Seal("Count-1"u8, Plaintext));
        Assert.Equal(
            Hex("4bbd6243b8bb54cec311fac9df81841b6fd61f56538a775e7c80a9f40160606e"),
            context.Export([], 32));
    }

    [Fact]
    public void AllZeroReceiverKeyAndDisposedContextFailClosed()
    {
        var suite = new TlsHpkeSymmetricCipherSuite(
            TlsHpkeKdfId.HkdfSha256,
            TlsHpkeAeadId.Aes128Gcm);
        Assert.Throws<System.Security.Cryptography.CryptographicException>(() =>
            HpkeSenderContext.SetupBaseX25519ForTesting(
                suite,
                new byte[32],
                [],
                new byte[32]));

        using var context = HpkeSenderContext.SetupBaseX25519ForTesting(
            suite,
            Hex("3948cfe0ad1ddb695d780e59077195da6c56506b027329794ab02bca80815c4d"),
            Info,
            Hex("7268600d403fce431561aef583ee1613527cff655c1343f29812e66706df3234"));
        context.Dispose();
        Assert.Throws<ObjectDisposedException>(() => context.Seal([], []));
        Assert.Throws<ObjectDisposedException>(() => context.Export([], 1));
    }

    [Fact]
    public void Rfc9180ReceiverOpensSequentialAes128GcmVectors()
    {
        var receiverPrivateKey = Hex(
            "4612c550263fc8ad58375df3f557aac531d26850903e55a9f23f21d8534e8ac8");
        var encapsulatedKey = Hex(
            "37fda3567bdbd628e88668c3c8d7e97d1d1253b6d4ea6d44c150f741f1bf4431");
        using var context = HpkeReceiverContext.SetupBaseX25519(
            new TlsHpkeSymmetricCipherSuite(
                TlsHpkeKdfId.HkdfSha256,
                TlsHpkeAeadId.Aes128Gcm),
            receiverPrivateKey,
            encapsulatedKey,
            Info);

        var first = context.Open(
            "Count-0"u8,
            Hex("f938558b5d72f1a23810b4be2ab4f84331acc02fc97babc53a52ae8218a355a96d8770ac83d07bea87e13c512a"));
        Assert.Equal(Plaintext, first);

        var secondCiphertext = Hex(
            "af2d7e9ac9ae7e270f46ba1f975be53c09f8d875bdc8535458c2494e8a6eab251c03d0c22a56b8ca42c2063b84");
        var tampered = (byte[])secondCiphertext.Clone();
        tampered[^1] ^= 1;
        Assert.Throws<System.Security.Cryptography.AuthenticationTagMismatchException>(() =>
            context.Open("Count-1"u8, tampered));
        Assert.Equal(Plaintext, context.Open("Count-1"u8, secondCiphertext));
    }

    private static byte[] Hex(string value) => Convert.FromHexString(value);

    private static byte[] SerializePublicKey(ECParameters parameters, int coordinateLength)
    {
        var x = Assert.IsType<byte[]>(parameters.Q.X);
        var y = Assert.IsType<byte[]>(parameters.Q.Y);
        var result = new byte[1 + (2 * coordinateLength)];
        result[0] = 4;
        x.CopyTo(result.AsSpan(1 + coordinateLength - x.Length));
        y.CopyTo(result.AsSpan(1 + (2 * coordinateLength) - y.Length));
        return result;
    }
}
