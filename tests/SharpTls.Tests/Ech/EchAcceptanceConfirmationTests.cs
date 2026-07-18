using SharpTls.Ech;
using SharpTls.Protocol;

namespace SharpTls.Tests.Ech;

public sealed class EchAcceptanceConfirmationTests
{
    private const string FirstClientHelloHex =
        "010000220303000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
    private const string SecondClientHelloHex =
        "010000230303000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f01";
    private const string ServerHelloSha256Hex =
        "020000280303202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f001301000000";
    private const string HelloRetryRequestHex =
        "020000340303cf21ad74e59a6111be1d8c021e65b891c2a211167abb8c5e079e09e2c8a8339c00130100000cfe0d00080000000000000000";

    [Fact]
    public void ServerHelloSha256MatchesIndependentVector()
    {
        var clientHello = Convert.FromHexString(FirstClientHelloHex);
        var serverHello = Convert.FromHexString(ServerHelloSha256Hex);
        var original = (byte[])serverHello.Clone();

        var confirmation = EchAcceptanceConfirmation.ComputeForServerHello(
            TlsCipherSuite.TlsAes128GcmSha256,
            clientHello,
            serverHello);

        Assert.Equal("7B220E9D75187FE8", Convert.ToHexString(confirmation));
        Assert.Equal(original, serverHello);
        confirmation.CopyTo(serverHello, 30);
        Assert.True(EchAcceptanceConfirmation.VerifyServerHello(
            TlsCipherSuite.TlsAes128GcmSha256,
            clientHello,
            serverHello));

        serverHello[37] ^= 1;
        Assert.False(EchAcceptanceConfirmation.VerifyServerHello(
            TlsCipherSuite.TlsAes128GcmSha256,
            clientHello,
            serverHello));
    }

    [Fact]
    public void ServerHelloSha384MatchesIndependentVector()
    {
        var clientHello = Convert.FromHexString(FirstClientHelloHex);
        var serverHello = Convert.FromHexString(ServerHelloSha256Hex);
        serverHello[39] = 0x13;
        serverHello[40] = 0x02;

        var confirmation = EchAcceptanceConfirmation.ComputeForServerHello(
            TlsCipherSuite.TlsAes256GcmSha384,
            clientHello,
            serverHello);

        Assert.Equal("4E2A63A47ED51DCB", Convert.ToHexString(confirmation));
        Assert.Equal(
            TlsCipherSuite.TlsAes256GcmSha384,
            EchAcceptanceConfirmation.ReadCipherSuite(serverHello));
    }

    [Fact]
    public void HelloRetryRequestUsesSyntheticMessageHashTranscript()
    {
        var clientHello = Convert.FromHexString(FirstClientHelloHex);
        var helloRetryRequest = Convert.FromHexString(HelloRetryRequestHex);

        var confirmation = EchAcceptanceConfirmation.ComputeForHelloRetryRequest(
            TlsCipherSuite.TlsAes128GcmSha256,
            clientHello,
            helloRetryRequest);

        Assert.Equal("6094FB132E23FBDC", Convert.ToHexString(confirmation));
        confirmation.CopyTo(helloRetryRequest, helloRetryRequest.Length - 8);
        Assert.True(EchAcceptanceConfirmation.VerifyHelloRetryRequest(
            TlsCipherSuite.TlsAes128GcmSha256,
            clientHello,
            helloRetryRequest));

        helloRetryRequest[^1] ^= 1;
        Assert.False(EchAcceptanceConfirmation.VerifyHelloRetryRequest(
            TlsCipherSuite.TlsAes128GcmSha256,
            clientHello,
            helloRetryRequest));
    }

    [Fact]
    public void PostHrrServerHelloBindsBothInnerHellosAndAcceptedHrr()
    {
        var firstClientHello = Convert.FromHexString(FirstClientHelloHex);
        var secondClientHello = Convert.FromHexString(SecondClientHelloHex);
        var helloRetryRequest = Convert.FromHexString(HelloRetryRequestHex);
        Convert.FromHexString("6094FB132E23FBDC")
            .CopyTo(helloRetryRequest, helloRetryRequest.Length - 8);
        var serverHello = Convert.FromHexString(ServerHelloSha256Hex);

        var confirmation =
            EchAcceptanceConfirmation.ComputeForServerHelloAfterHelloRetryRequest(
                TlsCipherSuite.TlsAes128GcmSha256,
                firstClientHello,
                helloRetryRequest,
                secondClientHello,
                serverHello);

        Assert.Equal("E6F28BDE6E0A3898", Convert.ToHexString(confirmation));
        confirmation.CopyTo(serverHello, 30);
        Assert.True(
            EchAcceptanceConfirmation.VerifyServerHelloAfterHelloRetryRequest(
                TlsCipherSuite.TlsAes128GcmSha256,
                firstClientHello,
                helloRetryRequest,
                secondClientHello,
                serverHello));

        secondClientHello[^1] ^= 1;
        Assert.False(
            EchAcceptanceConfirmation.VerifyServerHelloAfterHelloRetryRequest(
                TlsCipherSuite.TlsAes128GcmSha256,
                firstClientHello,
                helloRetryRequest,
                secondClientHello,
                serverHello));
    }

    [Fact]
    public void MissingHrrConfirmationMeansEchRejection()
    {
        var clientHello = Convert.FromHexString(FirstClientHelloHex);
        var helloRetryRequest = Convert.FromHexString(HelloRetryRequestHex);
        Array.Resize(ref helloRetryRequest, helloRetryRequest.Length - 12);
        helloRetryRequest[3] -= 12;
        helloRetryRequest[^2] = 0;
        helloRetryRequest[^1] = 0;

        Assert.False(EchAcceptanceConfirmation.VerifyHelloRetryRequest(
            TlsCipherSuite.TlsAes128GcmSha256,
            clientHello,
            helloRetryRequest));
        var exception = Assert.Throws<TlsProtocolException>(() =>
            EchAcceptanceConfirmation.ComputeForHelloRetryRequest(
                TlsCipherSuite.TlsAes128GcmSha256,
                clientHello,
                helloRetryRequest));
        Assert.Equal(TlsAlertDescription.MissingExtension, exception.Alert);
    }

    [Fact]
    public void MalformedConfirmationAndTranscriptInputsAreRejected()
    {
        var clientHello = Convert.FromHexString(FirstClientHelloHex);
        var helloRetryRequest = Convert.FromHexString(HelloRetryRequestHex);
        helloRetryRequest[^10] = 0;
        helloRetryRequest[^9] = 7;

        var badLength = Assert.Throws<TlsProtocolException>(() =>
            EchAcceptanceConfirmation.VerifyHelloRetryRequest(
                TlsCipherSuite.TlsAes128GcmSha256,
                clientHello,
                helloRetryRequest));
        Assert.Equal(TlsAlertDescription.DecodeError, badLength.Alert);

        var serverHello = Convert.FromHexString(ServerHelloSha256Hex);
        var wrongSuite = Assert.Throws<TlsProtocolException>(() =>
            EchAcceptanceConfirmation.ComputeForServerHello(
                TlsCipherSuite.TlsAes256GcmSha384,
                clientHello,
                serverHello));
        Assert.Equal(TlsAlertDescription.IllegalParameter, wrongSuite.Alert);

        clientHello[3]--;
        var badHandshake = Assert.Throws<TlsProtocolException>(() =>
            EchAcceptanceConfirmation.ComputeForServerHello(
                TlsCipherSuite.TlsAes128GcmSha256,
                clientHello,
                serverHello));
        Assert.Equal(TlsAlertDescription.DecodeError, badHandshake.Alert);
    }

    [Fact]
    public void UnsupportedServerCipherSuiteIsAProtocolFailure()
    {
        var serverHello = Convert.FromHexString(ServerHelloSha256Hex);
        serverHello[39] = 0x13;
        serverHello[40] = 0x04;

        var exception = Assert.Throws<TlsProtocolException>(() =>
            EchAcceptanceConfirmation.ReadCipherSuite(serverHello));

        Assert.Equal(TlsAlertDescription.IllegalParameter, exception.Alert);
        Assert.IsType<NotSupportedException>(exception.InnerException);
    }
}
