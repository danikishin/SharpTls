using SharpTls.Handshake;
using SharpTls.Protocol;

namespace SharpTls.Tests.Handshake;

public sealed class Tls12ClientStateMachineTests
{
    [Fact]
    public void FullHandshakeWithoutOptionalMessagesUsesLegalTransitions()
    {
        var state = StartServerFlight();
        state.ServerKeyExchangeReceived();
        state.ServerHelloDoneReceived();
        state.ClientKeyExchangeSent();
        state.ClientChangeCipherSpecSent();
        state.ClientFinishedSent();
        state.ServerChangeCipherSpecReceived();
        state.ServerFinishedReceived();

        Assert.Equal(Tls12ClientState.Connected, state.State);
    }

    [Fact]
    public void CertificateStatusClientCertificateRequestAndTicketAreOrderedStrictly()
    {
        var state = StartServerFlight();
        state.CertificateStatusReceived();
        state.ServerKeyExchangeReceived();
        state.CertificateRequestReceived();
        state.ServerHelloDoneReceived();
        state.ClientCertificateSent(hasCertificate: false);
        state.ClientKeyExchangeSent();
        state.ClientChangeCipherSpecSent();
        state.ClientFinishedSent();
        state.NewSessionTicketReceived();
        state.ServerChangeCipherSpecReceived();
        state.ServerFinishedReceived();

        Assert.Equal(Tls12ClientState.Connected, state.State);
    }

    [Fact]
    public void ClientKeyExchangeCannotSkipRequestedEmptyCertificate()
    {
        var state = StartServerFlight();
        state.ServerKeyExchangeReceived();
        state.CertificateRequestReceived();
        state.ServerHelloDoneReceived();

        var exception = Assert.Throws<TlsProtocolException>(state.ClientKeyExchangeSent);

        Assert.Equal(TlsAlertDescription.UnexpectedMessage, exception.Alert);
    }

    [Fact]
    public void NonEmptyClientCertificateRequiresCertificateVerifyBeforeCcs()
    {
        var state = StartServerFlight();
        state.ServerKeyExchangeReceived();
        state.CertificateRequestReceived();
        state.ServerHelloDoneReceived();
        state.ClientCertificateSent(hasCertificate: true);
        state.ClientKeyExchangeSent();

        Assert.Throws<TlsProtocolException>(state.ClientChangeCipherSpecSent);
        state.ClientCertificateVerifySent();
        state.ClientChangeCipherSpecSent();
    }

    [Fact]
    public void ServerFinishedBeforeChangeCipherSpecIsRejected()
    {
        var state = StartServerFlight();
        state.ServerKeyExchangeReceived();
        state.ServerHelloDoneReceived();
        state.ClientKeyExchangeSent();
        state.ClientChangeCipherSpecSent();
        state.ClientFinishedSent();

        var exception = Assert.Throws<TlsProtocolException>(state.ServerFinishedReceived);

        Assert.Equal(TlsAlertDescription.UnexpectedMessage, exception.Alert);
        Assert.NotEqual(Tls12ClientState.Connected, state.State);
    }

    [Fact]
    public void DuplicateOptionalMessagesAreRejected()
    {
        var state = StartServerFlight();
        state.CertificateStatusReceived();

        Assert.Throws<TlsProtocolException>(state.CertificateStatusReceived);
        state.ServerKeyExchangeReceived();
        state.CertificateRequestReceived();
        Assert.Throws<TlsProtocolException>(state.CertificateRequestReceived);
    }

    [Fact]
    public void AbbreviatedHandshakeUsesServerThenClientFinishedOrdering()
    {
        var state = new Tls12ClientStateMachine();
        state.TransportConnected();
        state.ClientHelloSent();
        state.ServerHelloReceived(resumed: true);
        state.AbbreviatedServerChangeCipherSpecReceived();
        state.AbbreviatedServerFinishedReceived();
        state.AbbreviatedClientChangeCipherSpecSent();
        state.AbbreviatedClientFinishedSent();

        Assert.Equal(Tls12ClientState.Connected, state.State);
    }

    [Fact]
    public void AbbreviatedHandshakeRejectsFullHandshakeMessagesAndReorderedFinished()
    {
        var state = new Tls12ClientStateMachine();
        state.TransportConnected();
        state.ClientHelloSent();
        state.ServerHelloReceived(resumed: true);

        Assert.Throws<TlsProtocolException>(state.CertificateReceived);
        Assert.Throws<TlsProtocolException>(state.AbbreviatedServerFinishedReceived);
        Assert.Throws<TlsProtocolException>(state.AbbreviatedClientChangeCipherSpecSent);
    }

    private static Tls12ClientStateMachine StartServerFlight()
    {
        var state = new Tls12ClientStateMachine();
        state.TransportConnected();
        state.ClientHelloSent();
        state.ServerHelloReceived();
        state.CertificateReceived();
        return state;
    }
}
