using System.Security.Cryptography;
using SharpTls.Cryptography;
using SharpTls.Handshake;
using SharpTls.Protocol;

namespace SharpTls.Tests.Cryptography;

public sealed class HkdfAndTranscriptTests
{
    [Fact]
    public void Rfc8448SimpleHandshakeKeyScheduleMatches()
    {
        var suite = CipherSuiteInfo.Get(TlsCipherSuite.TlsAes128GcmSha256);
        var zeros = new byte[32];
        var emptyHash = SHA256.HashData([]);
        var sharedSecret = Hex("8bd4054fb55b9d63fdfbacf9f04b9f0d35e6d63f537563efd46272900f89492d");
        var helloHash = Hex("860c06edc07858ee8e78f0e7428c58edd6b43f2ca3e6e95f02ed063cf0e1cad8");

        var early = Tls13Hkdf.Extract(HashAlgorithmName.SHA256, zeros, zeros);
        var derived = Tls13Hkdf.DeriveSecret(suite, early, "derived", emptyHash);
        var handshake = Tls13Hkdf.Extract(HashAlgorithmName.SHA256, sharedSecret, derived);
        var clientTraffic = Tls13Hkdf.DeriveSecret(suite, handshake, "c hs traffic", helloHash);
        var serverTraffic = Tls13Hkdf.DeriveSecret(suite, handshake, "s hs traffic", helloHash);
        var mainDerived = Tls13Hkdf.DeriveSecret(suite, handshake, "derived", emptyHash);
        var main = Tls13Hkdf.Extract(HashAlgorithmName.SHA256, zeros, mainDerived);
        var serverKey = Tls13Hkdf.ExpandLabel(HashAlgorithmName.SHA256, serverTraffic, "key", [], 16);
        var serverIv = Tls13Hkdf.ExpandLabel(HashAlgorithmName.SHA256, serverTraffic, "iv", [], 12);

        Assert.Equal(Hex("33ad0a1c607ec03b09e6cd9893680ce210adf300aa1f2660e1b22e10f170f92a"), early);
        Assert.Equal(Hex("6f2615a108c702c5678f54fc9dbab69716c076189c48250cebeac3576c3611ba"), derived);
        Assert.Equal(Hex("1dc826e93606aa6fdc0aadc12f741b01046aa6b99f691ed221a9f0ca043fbeac"), handshake);
        Assert.Equal(Hex("b3eddb126e067f35a780b3abf45e2d8f3b1a950738f52e9600746a0e27a55a21"), clientTraffic);
        Assert.Equal(Hex("b67b7d690cc16c4e75e54213cb2d37b4e9c912bcded9105d42befd59d391ad38"), serverTraffic);
        Assert.Equal(Hex("43de77e0c77713859a944db9db2590b53190a65b3ee2e4f12dd7a0bb7ce254b4"), mainDerived);
        Assert.Equal(Hex("18df06843d13a08bf2a449844c5f8a478001bc4d4c627984d5a41da8d0402919"), main);
        Assert.Equal(Hex("3fce516009c21727d0f2e4e86ee403bc"), serverKey);
        Assert.Equal(Hex("5d313eb2671276ee13000b30"), serverIv);
    }

    [Fact]
    public void Rfc5869Sha256TestCaseOneMatches()
    {
        var ikm = Enumerable.Repeat((byte)0x0B, 22).ToArray();
        var salt = Convert.FromHexString("000102030405060708090A0B0C");
        var info = Convert.FromHexString("F0F1F2F3F4F5F6F7F8F9");
        var expectedPrk = Convert.FromHexString(
            "077709362C2E32DF0DDC3F0DC47BBA6390B6C73BB50F9C3122EC844AD7C2B3E5");
        var expectedOkm = Convert.FromHexString(
            "3CB25F25FAACD57A90434F64D0362F2A2D2D0A90CF1A5A4C5DB02D56ECC4C5BF34007208D5B887185865");

        var prk = Tls13Hkdf.Extract(HashAlgorithmName.SHA256, ikm, salt);
        var okm = Tls13Hkdf.Expand(HashAlgorithmName.SHA256, prk, info, 42);
        try
        {
            Assert.Equal(expectedPrk, prk);
            Assert.Equal(expectedOkm, okm);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(prk);
            CryptographicOperations.ZeroMemory(okm);
        }
    }

    [Fact]
    public void ExpandLabelUsesTls13PrefixAndWireStructure()
    {
        var secret = new byte[32];
        var actual = Tls13Hkdf.ExpandLabel(HashAlgorithmName.SHA256, secret, "key", [], 16);

        byte[] expectedInfo =
        [
            0, 16,
            9, (byte)'t', (byte)'l', (byte)'s', (byte)'1', (byte)'3', (byte)' ', (byte)'k', (byte)'e', (byte)'y',
            0,
        ];
        var expected = Tls13Hkdf.Expand(HashAlgorithmName.SHA256, secret, expectedInfo, 16);
        Assert.Equal(expected, actual);
    }

    [Fact]
    public void ExpandLabelSha384MatchesFixedVector()
    {
        var secret = Enumerable.Range(0, 48).Select(value => (byte)value).ToArray();
        var context = Enumerable.Range(0, 32).Select(value => (byte)value).ToArray();
        var expected = Hex(
            "74e8392409b646f7c6e1b03a3e9284b00d360633b274903fa149f1b84ab65243" +
            "d3a2d69e1ab1e9e23730d8f434ba836e");

        var actual = Tls13Hkdf.ExpandLabel(
            HashAlgorithmName.SHA384,
            secret,
            "test",
            context,
            48);

        Assert.Equal(expected, actual);
    }

    [Fact]
    public void HelloRetryRequestTranscriptUsesSyntheticMessageHash()
    {
        var suite = CipherSuiteInfo.Get(TlsCipherSuite.TlsAes128GcmSha256);
        var firstHello = HandshakeMessage.Encode(HandshakeType.ClientHello, [1, 2, 3]);
        var retry = HandshakeMessage.Encode(HandshakeType.ServerHello, [4, 5, 6]);
        using var transcript = new TranscriptHash(suite);

        transcript.ResetForHelloRetryRequest(firstHello);
        transcript.Append(retry);

        var firstHash = SHA256.HashData(firstHello);
        var synthetic = HandshakeMessage.Encode(HandshakeType.MessageHash, firstHash);
        byte[] combined = [.. synthetic, .. retry];
        var expected = SHA256.HashData(combined);
        Assert.Equal(expected, transcript.CurrentHash());
    }

    [Fact]
    public void CapturedTranscriptForksFromTheInitialHandshakeBase()
    {
        var suite = CipherSuiteInfo.Get(TlsCipherSuite.TlsAes128GcmSha256);
        var hello = HandshakeMessage.Encode(HandshakeType.ClientHello, [1]);
        var finished = HandshakeMessage.Encode(HandshakeType.Finished, new byte[32]);
        var certificateRequest = HandshakeMessage.Encode(
            HandshakeType.CertificateRequest,
            [0, 0, 0]);
        using var transcript = new TranscriptHash(suite, maximumCapturedBytes: 1024);
        transcript.Append(hello);
        transcript.Append(finished);

        using var firstFork = transcript.Fork();
        firstFork.Append(certificateRequest);
        using var secondFork = transcript.Fork();

        byte[] firstInput = [.. hello, .. finished, .. certificateRequest];
        byte[] baseInput = [.. hello, .. finished];
        Assert.Equal(SHA256.HashData(firstInput), firstFork.CurrentHash());
        Assert.Equal(SHA256.HashData(baseInput), secondFork.CurrentHash());
    }

    [Fact]
    public void CapturedTranscriptIsStrictlyBounded()
    {
        var suite = CipherSuiteInfo.Get(TlsCipherSuite.TlsAes128GcmSha256);
        using var transcript = new TranscriptHash(suite, maximumCapturedBytes: 5);
        transcript.Append(HandshakeMessage.Encode(HandshakeType.ClientHello, [1]));

        Assert.Equal(
            TlsAlertDescription.InternalError,
            Assert.Throws<TlsProtocolException>(() =>
                transcript.Append(HandshakeMessage.Encode(
                    HandshakeType.ServerHello,
                    []))).Alert);
    }

    [Fact]
    public void KeyScheduleRejectsOutOfOrderApplicationDerivation()
    {
        using var schedule = new Tls13KeySchedule(
            CipherSuiteInfo.Get(TlsCipherSuite.TlsAes128GcmSha256));

        Assert.Throws<InvalidOperationException>(() => schedule.DeriveApplicationTrafficSecrets(new byte[32]));
        Assert.Throws<InvalidOperationException>(() => schedule.GetClientHandshakeKeys());
    }

    [Fact]
    public void Sha384KeyScheduleRejectsWrongTranscriptHashLength()
    {
        using var schedule = new Tls13KeySchedule(
            CipherSuiteInfo.Get(TlsCipherSuite.TlsAes256GcmSha384));
        schedule.DeriveHandshakeSecrets(new byte[48], new byte[48]);
        schedule.DeriveMainSecret();

        Assert.Throws<ArgumentException>(() => schedule.DeriveApplicationTrafficSecrets(new byte[32]));
    }

    [Theory]
    [InlineData(TlsCipherSuite.TlsAes128GcmSha256)]
    [InlineData(TlsCipherSuite.TlsAes256GcmSha384)]
    public void ApplicationTrafficSecretUpdateRatchetsBothDirections(TlsCipherSuite cipherSuite)
    {
        var suite = CipherSuiteInfo.Get(cipherSuite);
        using var schedule = new Tls13KeySchedule(suite);
        schedule.DeriveHandshakeSecrets(
            new byte[suite.HashLength],
            new byte[suite.HashLength]);
        schedule.DeriveMainSecret();
        schedule.DeriveApplicationTrafficSecrets(new byte[suite.HashLength]);
        var oldClient = schedule.GetClientApplicationKeys();
        var oldServer = schedule.GetServerApplicationKeys();

        schedule.UpdateClientApplicationTrafficSecret();
        schedule.UpdateServerApplicationTrafficSecret();
        var nextClient = schedule.GetClientApplicationKeys();
        var nextServer = schedule.GetServerApplicationKeys();
        try
        {
            Assert.NotEqual(oldClient.Key, nextClient.Key);
            Assert.NotEqual(oldClient.Iv, nextClient.Iv);
            Assert.NotEqual(oldServer.Key, nextServer.Key);
            Assert.NotEqual(oldServer.Iv, nextServer.Iv);
            Assert.NotEqual(nextClient.Key, nextServer.Key);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(oldClient.Key);
            CryptographicOperations.ZeroMemory(oldClient.Iv);
            CryptographicOperations.ZeroMemory(oldServer.Key);
            CryptographicOperations.ZeroMemory(oldServer.Iv);
            CryptographicOperations.ZeroMemory(nextClient.Key);
            CryptographicOperations.ZeroMemory(nextClient.Iv);
            CryptographicOperations.ZeroMemory(nextServer.Key);
            CryptographicOperations.ZeroMemory(nextServer.Iv);
        }
    }

    [Fact]
    public void Tls13ExporterMatchesRfcConstructionAndSurvivesKeyUpdates()
    {
        var suite = CipherSuiteInfo.Get(TlsCipherSuite.TlsAes128GcmSha256);
        var sharedSecret = Enumerable.Range(1, suite.HashLength)
            .Select(value => (byte)value)
            .ToArray();
        var helloHash = SHA256.HashData("hello"u8);
        var serverFinishedHash = SHA256.HashData("server-finished"u8);
        using var schedule = new Tls13KeySchedule(suite);
        schedule.DeriveHandshakeSecrets(sharedSecret, helloHash);
        schedule.DeriveMainSecret();
        schedule.DeriveApplicationTrafficSecrets(serverFinishedHash);

        var expected = ComputeExporterIndependently(
            suite,
            sharedSecret,
            helloHash,
            serverFinishedHash,
            "EXPORTER-SharpTls-test",
            "context"u8,
            42);
        var actual = schedule.ExportKeyingMaterial(
            "EXPORTER-SharpTls-test",
            "context"u8,
            42);
        schedule.UpdateClientApplicationTrafficSecret();
        schedule.UpdateServerApplicationTrafficSecret();
        var afterUpdate = schedule.ExportKeyingMaterial(
            "EXPORTER-SharpTls-test",
            "context"u8,
            42);

        Assert.Equal(expected, actual);
        Assert.Equal(actual, afterUpdate);
        Assert.NotEqual(
            actual,
            schedule.ExportKeyingMaterial("EXPORTER-SharpTls-test", "other"u8, 42));
    }

    [Theory]
    [InlineData("")]
    [InlineData("client finished")]
    [InlineData("contains\nnewline")]
    public void ExporterRejectsInvalidOrReservedLabels(string label)
    {
        var suite = CipherSuiteInfo.Get(TlsCipherSuite.TlsAes128GcmSha256);
        using var schedule = new Tls13KeySchedule(suite);
        schedule.DeriveHandshakeSecrets(new byte[32], new byte[32]);
        schedule.DeriveMainSecret();
        schedule.DeriveApplicationTrafficSecrets(new byte[32]);

        Assert.Throws<ArgumentException>(() =>
            schedule.ExportKeyingMaterial(label, [], 32));
    }

    private static byte[] ComputeExporterIndependently(
        CipherSuiteInfo suite,
        ReadOnlySpan<byte> sharedSecret,
        ReadOnlySpan<byte> helloHash,
        ReadOnlySpan<byte> serverFinishedHash,
        string label,
        ReadOnlySpan<byte> context,
        int length)
    {
        var zeros = new byte[suite.HashLength];
        var emptyHash = SHA256.HashData([]);
        var early = Tls13Hkdf.Extract(suite.HashAlgorithm, zeros, zeros);
        var earlyDerived = Tls13Hkdf.DeriveSecret(suite, early, "derived", emptyHash);
        var handshake = Tls13Hkdf.Extract(suite.HashAlgorithm, sharedSecret, earlyDerived);
        var mainDerived = Tls13Hkdf.DeriveSecret(suite, handshake, "derived", emptyHash);
        var main = Tls13Hkdf.Extract(suite.HashAlgorithm, zeros, mainDerived);
        var exporter = Tls13Hkdf.DeriveSecret(suite, main, "exp master", serverFinishedHash);
        var derived = Tls13Hkdf.DeriveSecret(suite, exporter, label, emptyHash);
        var contextHash = SHA256.HashData(context);
        return Tls13Hkdf.ExpandLabel(suite.HashAlgorithm, derived, "exporter", contextHash, length);
    }

    private static byte[] Hex(string value) => Convert.FromHexString(value);
}
