using System.Security.Cryptography;
using SharpTls.Cryptography;
using SharpTls.Handshake;
using SharpTls.Protocol;

namespace SharpTls.Tests.Cryptography;

public sealed class Tls12PrfAndKeyScheduleTests
{
    [Fact]
    public void Sha256PrfMatchesFixedVectorAcrossMultipleBlocks()
    {
        var secret = Enumerable.Range(0, 32).Select(value => (byte)value).ToArray();
        var seed = Enumerable.Range(0xA0, 64).Select(value => (byte)value).ToArray();
        var expected = Hex(
            "9aea2cea5444d372ae653247065e3f388645153b820d99a190630787b25c530fb" +
            "8d30b46748ce330e01f7a133180a2e8b762e82773f2d37d94fa0efd6ea5ba187" +
            "54b2ed9467d4db28fe5d2c14d825fbeccf63bea599dc680b8b76a32e251199fa" +
            "064c273");

        var actual = Tls12Prf.Expand(
            HashAlgorithmName.SHA256,
            secret,
            "test label",
            seed,
            expected.Length);

        Assert.Equal(expected, actual);
    }

    [Fact]
    public void Sha384PrfMatchesFixedVectorAcrossMultipleBlocks()
    {
        var secret = Enumerable.Range(0, 32).Select(value => (byte)value).ToArray();
        var seed = Enumerable.Range(0xA0, 64).Select(value => (byte)value).ToArray();
        var expected = Hex(
            "9a5a4b162539bf0e82ae769042d58645d96b0c822b243280f47b1799f0fdc507" +
            "1dc873c3a9958e3db0f96e19627aadc400b812d3605dd5c7a8027b38a3df373b" +
            "d869767793f658e09be189d9e7023af1cdf80988507ff3de6dad4a2579335350a" +
            "68e8ec5");

        var actual = Tls12Prf.Expand(
            HashAlgorithmName.SHA384,
            secret,
            "test label",
            seed,
            expected.Length);

        Assert.Equal(expected, actual);
    }

    [Fact]
    public void ExtendedMasterSecretSha256KeysAndFinishedMatchFixedVectors()
    {
        var suite = Tls12CipherSuiteInfo.Get(
            TlsCipherSuite.TlsEcdheRsaWithAes128GcmSha256);
        var preMasterSecret = Range(1, 32);
        var sessionHash = Range(0x80, 32);
        var clientRandom = Range(0, 32);
        var serverRandom = Range(32, 32);
        var finishedHash = Range(0x40, 32);
        var expectedKeyBlock = Hex(
            "293103b545a1ab3fa340c8c27bfab47c" +
            "0bb6af34a3515dd9a357faec747f4928" +
            "d51e1a1bf3af19cd");
        using var schedule = new Tls12KeySchedule(suite);

        schedule.DeriveExtendedMasterSecret(preMasterSecret, sessionHash);
        schedule.DeriveTrafficKeys(clientRandom, serverRandom);
        var client = schedule.GetClientWriteKeys();
        var server = schedule.GetServerWriteKeys();

        Assert.Equal(expectedKeyBlock.AsSpan(0, 16).ToArray(), client.Key);
        Assert.Equal(expectedKeyBlock.AsSpan(16, 16).ToArray(), server.Key);
        Assert.Equal(expectedKeyBlock.AsSpan(32, 4).ToArray(), client.FixedIv);
        Assert.Equal(expectedKeyBlock.AsSpan(36, 4).ToArray(), server.FixedIv);
        Assert.Equal(Hex("1fa8d6bfb588f17cfce2491d"), schedule.ComputeClientFinished(finishedHash));
        Assert.Equal(Hex("9a73e7d1eb80760a0fa3ce08"), schedule.ComputeServerFinished(finishedHash));
    }

    [Fact]
    public void ExtendedMasterSecretSha384KeysAndFinishedMatchFixedVectors()
    {
        var suite = Tls12CipherSuiteInfo.Get(
            TlsCipherSuite.TlsEcdheEcdsaWithAes256GcmSha384);
        var preMasterSecret = Range(1, 48);
        var sessionHash = Range(0x80, 48);
        var clientRandom = Range(0, 32);
        var serverRandom = Range(32, 32);
        var finishedHash = Range(0x40, 48);
        var expectedKeyBlock = Hex(
            "4b192421e9a0a74a95518f93e965a43936dd6af9255b0544fbc2e3103e8a26cd" +
            "ce6cc3972b6c10e7860a28925c38bd8de5341e33756c3f0a20695f57fe966b95" +
            "e0790872cac16a0a");
        using var schedule = new Tls12KeySchedule(suite);

        schedule.DeriveExtendedMasterSecret(preMasterSecret, sessionHash);
        schedule.DeriveTrafficKeys(clientRandom, serverRandom);
        var client = schedule.GetClientWriteKeys();
        var server = schedule.GetServerWriteKeys();

        Assert.Equal(expectedKeyBlock.AsSpan(0, 32).ToArray(), client.Key);
        Assert.Equal(expectedKeyBlock.AsSpan(32, 32).ToArray(), server.Key);
        Assert.Equal(expectedKeyBlock.AsSpan(64, 4).ToArray(), client.FixedIv);
        Assert.Equal(expectedKeyBlock.AsSpan(68, 4).ToArray(), server.FixedIv);
        Assert.Equal(Hex("d03f35a2d10fcab6283531f5"), schedule.ComputeClientFinished(finishedHash));
        Assert.Equal(Hex("b3dcfb9899eecf49e7b7cba8"), schedule.ComputeServerFinished(finishedHash));
    }

    [Theory]
    [InlineData(TlsCipherSuite.TlsEcdheEcdsaWithAes128GcmSha256, 32, 16, 4, 8)]
    [InlineData(TlsCipherSuite.TlsEcdheRsaWithAes128GcmSha256, 32, 16, 4, 8)]
    [InlineData(TlsCipherSuite.TlsEcdheEcdsaWithAes256GcmSha384, 48, 32, 4, 8)]
    [InlineData(TlsCipherSuite.TlsEcdheRsaWithAes256GcmSha384, 48, 32, 4, 8)]
    [InlineData(TlsCipherSuite.TlsEcdheRsaWithChaCha20Poly1305Sha256, 32, 32, 12, 0)]
    [InlineData(TlsCipherSuite.TlsEcdheEcdsaWithChaCha20Poly1305Sha256, 32, 32, 12, 0)]
    public void SafeEcdheAeadSuiteMetadataIsExact(
        TlsCipherSuite cipherSuite,
        int hashLength,
        int keyLength,
        int fixedIvLength,
        int explicitNonceLength)
    {
        var suite = Tls12CipherSuiteInfo.Get(cipherSuite);

        Assert.Equal(hashLength, suite.HashLength);
        Assert.Equal(keyLength, suite.KeyLength);
        Assert.Equal(fixedIvLength, suite.FixedIvLength);
        Assert.Equal(explicitNonceLength, suite.ExplicitNonceLength);
        Assert.Equal(2 * (keyLength + fixedIvLength), suite.KeyBlockLength);
    }

    [Theory]
    [InlineData(TlsCipherSuite.TlsAes128GcmSha256)]
    [InlineData(TlsCipherSuite.TlsEcdheRsaWithAes128CbcSha)]
    [InlineData(TlsCipherSuite.TlsRsaWithAes128GcmSha256)]
    public void Tls13CbcAndStaticRsaSuitesAreNotExecutableTls12Suites(TlsCipherSuite cipherSuite)
    {
        Assert.Throws<NotSupportedException>(() => Tls12CipherSuiteInfo.Get(cipherSuite));
    }

    [Fact]
    public void KeyScheduleRejectsIllegalOrderAndWrongHashLengths()
    {
        var suite = Tls12CipherSuiteInfo.Get(
            TlsCipherSuite.TlsEcdheRsaWithAes128GcmSha256);
        using var schedule = new Tls12KeySchedule(suite);

        Assert.Throws<InvalidOperationException>(() =>
            schedule.DeriveTrafficKeys(new byte[32], new byte[32]));
        Assert.Throws<ArgumentException>(() =>
            schedule.DeriveExtendedMasterSecret(new byte[32], new byte[31]));

        schedule.DeriveExtendedMasterSecret(new byte[32], new byte[32]);
        Assert.Throws<InvalidOperationException>(() =>
            schedule.DeriveExtendedMasterSecret(new byte[32], new byte[32]));
        Assert.Throws<ArgumentException>(() => schedule.ComputeClientFinished(new byte[31]));
    }

    [Fact]
    public void TranscriptHashIncludesFullEncodedHandshakeMessages()
    {
        var suite = Tls12CipherSuiteInfo.Get(
            TlsCipherSuite.TlsEcdheRsaWithAes128GcmSha256);
        var first = HandshakeMessage.Encode(HandshakeType.ClientHello, [1, 2, 3]);
        var second = HandshakeMessage.Encode(HandshakeType.ServerHello, [4, 5]);
        using var transcript = new Tls12TranscriptHash(suite);

        transcript.Append(first);
        transcript.Append(second);
        byte[] combined = [.. first, .. second];

        Assert.Equal(SHA256.HashData(combined), transcript.CurrentHash());
        Assert.Throws<ArgumentException>(() => transcript.Append([1, 2, 3]));
    }

    [Fact]
    public void PrfRejectsNonAsciiLabelsAndUnboundedOutputs()
    {
        Assert.Throws<ArgumentException>(() =>
            Tls12Prf.Expand(HashAlgorithmName.SHA256, [], "etiket-ı", [], 32));
        Assert.Throws<ArgumentOutOfRangeException>(() =>
            Tls12Prf.Expand(HashAlgorithmName.SHA256, [], "label", [], (1 << 20) + 1));
    }

    private static byte[] Range(int start, int count) =>
        Enumerable.Range(start, count).Select(value => (byte)value).ToArray();

    private static byte[] Hex(string value) => Convert.FromHexString(value);
}
