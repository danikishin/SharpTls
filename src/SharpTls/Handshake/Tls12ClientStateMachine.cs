using SharpTls.Protocol;

namespace SharpTls.Handshake;

internal enum Tls12ClientState
{
    Created,
    TransportConnected,
    AwaitingServerHello,
    AwaitingAbbreviatedServerChangeCipherSpec,
    AwaitingAbbreviatedServerFinished,
    SendingAbbreviatedClientChangeCipherSpec,
    SendingAbbreviatedClientFinished,
    AwaitingCertificate,
    AwaitingCertificateStatusOrServerKeyExchange,
    AwaitingServerKeyExchange,
    AwaitingCertificateRequestOrServerHelloDone,
    SendingClientFlight,
    SendingClientCertificateVerify,
    SendingClientChangeCipherSpec,
    SendingClientFinished,
    AwaitingNewSessionTicketOrServerChangeCipherSpec,
    AwaitingServerChangeCipherSpec,
    AwaitingServerFinished,
    Connected,
    Closing,
    Closed,
    Failed,
}

internal sealed class Tls12ClientStateMachine
{
    private bool _certificateRequestReceived;
    private bool _clientCertificateSent;
    private bool _clientCertificateVerifyRequired;

    internal Tls12ClientState State { get; private set; } = Tls12ClientState.Created;

    internal void TransportConnected() => Transition(
        Tls12ClientState.Created,
        Tls12ClientState.TransportConnected,
        "transport connection");

    internal void ClientHelloSent() => Transition(
        Tls12ClientState.TransportConnected,
        Tls12ClientState.AwaitingServerHello,
        "ClientHello");

    internal void ServerHelloReceived(bool resumed = false) => Transition(
        Tls12ClientState.AwaitingServerHello,
        resumed
            ? Tls12ClientState.AwaitingAbbreviatedServerChangeCipherSpec
            : Tls12ClientState.AwaitingCertificate,
        "ServerHello");

    internal void AbbreviatedServerChangeCipherSpecReceived() => Transition(
        Tls12ClientState.AwaitingAbbreviatedServerChangeCipherSpec,
        Tls12ClientState.AwaitingAbbreviatedServerFinished,
        "abbreviated server ChangeCipherSpec");

    internal void AbbreviatedServerFinishedReceived() => Transition(
        Tls12ClientState.AwaitingAbbreviatedServerFinished,
        Tls12ClientState.SendingAbbreviatedClientChangeCipherSpec,
        "abbreviated server Finished");

    internal void AbbreviatedClientChangeCipherSpecSent() => Transition(
        Tls12ClientState.SendingAbbreviatedClientChangeCipherSpec,
        Tls12ClientState.SendingAbbreviatedClientFinished,
        "abbreviated client ChangeCipherSpec");

    internal void AbbreviatedClientFinishedSent() => Transition(
        Tls12ClientState.SendingAbbreviatedClientFinished,
        Tls12ClientState.Connected,
        "abbreviated client Finished");

    internal void CertificateReceived() => Transition(
        Tls12ClientState.AwaitingCertificate,
        Tls12ClientState.AwaitingCertificateStatusOrServerKeyExchange,
        "Certificate");

    internal void CertificateStatusReceived() => Transition(
        Tls12ClientState.AwaitingCertificateStatusOrServerKeyExchange,
        Tls12ClientState.AwaitingServerKeyExchange,
        "CertificateStatus");

    internal void ServerKeyExchangeReceived()
    {
        if (State is not (Tls12ClientState.AwaitingCertificateStatusOrServerKeyExchange or
            Tls12ClientState.AwaitingServerKeyExchange))
        {
            ThrowIllegal("ServerKeyExchange");
        }

        State = Tls12ClientState.AwaitingCertificateRequestOrServerHelloDone;
    }

    internal void CertificateRequestReceived()
    {
        if (State != Tls12ClientState.AwaitingCertificateRequestOrServerHelloDone ||
            _certificateRequestReceived)
        {
            ThrowIllegal("CertificateRequest");
        }

        _certificateRequestReceived = true;
    }

    internal void ServerHelloDoneReceived() => Transition(
        Tls12ClientState.AwaitingCertificateRequestOrServerHelloDone,
        Tls12ClientState.SendingClientFlight,
        "ServerHelloDone");

    internal void ClientCertificateSent(bool hasCertificate)
    {
        if (State != Tls12ClientState.SendingClientFlight ||
            !_certificateRequestReceived ||
            _clientCertificateSent)
        {
            ThrowIllegal("empty client Certificate");
        }

        _clientCertificateSent = true;
        _clientCertificateVerifyRequired = hasCertificate;
    }

    internal void ClientKeyExchangeSent()
    {
        if (State != Tls12ClientState.SendingClientFlight ||
            (_certificateRequestReceived && !_clientCertificateSent))
        {
            ThrowIllegal("ClientKeyExchange");
        }

        State = _clientCertificateVerifyRequired
            ? Tls12ClientState.SendingClientCertificateVerify
            : Tls12ClientState.SendingClientChangeCipherSpec;
    }

    internal void ClientCertificateVerifySent() => Transition(
        Tls12ClientState.SendingClientCertificateVerify,
        Tls12ClientState.SendingClientChangeCipherSpec,
        "client CertificateVerify");

    internal void ClientChangeCipherSpecSent() => Transition(
        Tls12ClientState.SendingClientChangeCipherSpec,
        Tls12ClientState.SendingClientFinished,
        "client ChangeCipherSpec");

    internal void ClientFinishedSent() => Transition(
        Tls12ClientState.SendingClientFinished,
        Tls12ClientState.AwaitingNewSessionTicketOrServerChangeCipherSpec,
        "client Finished");

    internal void NewSessionTicketReceived() => Transition(
        Tls12ClientState.AwaitingNewSessionTicketOrServerChangeCipherSpec,
        Tls12ClientState.AwaitingServerChangeCipherSpec,
        "NewSessionTicket");

    internal void ServerChangeCipherSpecReceived()
    {
        if (State is not (Tls12ClientState.AwaitingNewSessionTicketOrServerChangeCipherSpec or
            Tls12ClientState.AwaitingServerChangeCipherSpec))
        {
            ThrowIllegal("server ChangeCipherSpec");
        }

        State = Tls12ClientState.AwaitingServerFinished;
    }

    internal void ServerFinishedReceived() => Transition(
        Tls12ClientState.AwaitingServerFinished,
        Tls12ClientState.Connected,
        "server Finished");

    internal void BeginClose()
    {
        if (State is not (Tls12ClientState.Connected or Tls12ClientState.Failed))
        {
            ThrowIllegal("close_notify");
        }

        State = Tls12ClientState.Closing;
    }

    internal void Closed()
    {
        if (State is not (Tls12ClientState.Closing or Tls12ClientState.Failed))
        {
            ThrowIllegal("transport close");
        }

        State = Tls12ClientState.Closed;
    }

    internal void Fail() => State = Tls12ClientState.Failed;

    private void Transition(Tls12ClientState expected, Tls12ClientState next, string action)
    {
        if (State != expected)
        {
            ThrowIllegal(action);
        }

        State = next;
    }

    private void ThrowIllegal(string action) =>
        throw TlsProtocolException.Unexpected(
            $"Illegal TLS 1.2 state transition: cannot process {action} while in {State}.");
}
