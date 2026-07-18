using SharpTls.Handshake;
using SharpTls.Protocol;

namespace SharpTls.Tests.Handshake;

public sealed class Tls13ClientStateMachineTests
{
    [Fact]
    public void FullAuthenticatedHandshakeUsesOnlyLegalTransitions()
    {
        var state = new Tls13ClientStateMachine();
        state.TransportConnected();
        state.ClientHelloSent();
        state.ServerHelloReceived();
        state.EncryptedExtensionsReceived();
        state.CertificateReceived();
        state.CertificateVerifyReceived();
        state.ServerFinishedReceived();
        state.ClientFinishedSent();

        Assert.Equal(Tls13ClientState.Connected, state.State);
    }

    [Fact]
    public void HelloRetryRequestCanOccurOnlyOnce()
    {
        var state = new Tls13ClientStateMachine();
        state.TransportConnected();
        state.ClientHelloSent();
        state.HelloRetryRequestReceived();
        state.SecondClientHelloSent();

        var exception = Assert.Throws<TlsProtocolException>(state.HelloRetryRequestReceived);
        Assert.Equal(TlsAlertDescription.UnexpectedMessage, exception.Alert);
    }

    [Fact]
    public void CertificateBeforeEncryptedExtensionsIsRejected()
    {
        var state = new Tls13ClientStateMachine();
        state.TransportConnected();
        state.ClientHelloSent();
        state.ServerHelloReceived();

        var exception = Assert.Throws<TlsProtocolException>(state.CertificateReceived);
        Assert.Equal(TlsAlertDescription.UnexpectedMessage, exception.Alert);
    }

    [Fact]
    public void ApplicationStateCannotBeReachedBySkippingAuthentication()
    {
        var state = new Tls13ClientStateMachine();
        state.TransportConnected();
        state.ClientHelloSent();

        var exception = Assert.Throws<TlsProtocolException>(state.ClientFinishedSent);
        Assert.Equal(TlsAlertDescription.UnexpectedMessage, exception.Alert);
        Assert.NotEqual(Tls13ClientState.Connected, state.State);
    }

    [Fact]
    public void ResumptionPskAuthenticatesFinishedWithoutCertificateMessages()
    {
        var state = new Tls13ClientStateMachine();
        state.TransportConnected();
        state.ClientHelloSent();
        state.ServerHelloReceived();
        state.EncryptedExtensionsReceived();
        state.ServerFinishedReceived(resumed: true);
        state.ClientFinishedSent();

        Assert.Equal(Tls13ClientState.Connected, state.State);
    }

    [Fact]
    public void RequestedNonEmptyClientCertificateRequiresCertificateVerify()
    {
        var state = new Tls13ClientStateMachine();
        state.TransportConnected();
        state.ClientHelloSent();
        state.ServerHelloReceived();
        state.EncryptedExtensionsReceived();
        state.CertificateRequestReceived();
        state.CertificateReceived();
        state.CertificateVerifyReceived();
        state.ServerFinishedReceived();
        state.ClientCertificateSent(hasCertificate: true);

        Assert.Throws<TlsProtocolException>(state.ClientFinishedSent);
        state.ClientCertificateVerifySent();
        state.ClientFinishedSent();

        Assert.Equal(Tls13ClientState.Connected, state.State);
    }

    [Fact]
    public void ClientApplicationSettingsCanBeSentOnceAfterServerFinished()
    {
        var state = new Tls13ClientStateMachine();
        state.TransportConnected();
        state.ClientHelloSent();
        state.ServerHelloReceived();
        state.EncryptedExtensionsReceived();
        state.CertificateReceived();
        state.CertificateVerifyReceived();

        Assert.Throws<TlsProtocolException>(state.ClientApplicationSettingsSent);
        state.ServerFinishedReceived();
        state.ClientApplicationSettingsSent();
        Assert.Throws<TlsProtocolException>(state.ClientApplicationSettingsSent);
        state.ClientFinishedSent();

        Assert.Equal(Tls13ClientState.Connected, state.State);
    }
}
