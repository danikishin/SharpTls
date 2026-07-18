using SharpTls.Protocol;

namespace SharpTls.Handshake;

internal enum Tls13ClientState
{
    Created,
    TransportConnected,
    AwaitingServerHello,
    AwaitingSecondServerHello,
    AwaitingEncryptedExtensions,
    AwaitingCertificateOrRequest,
    AwaitingCertificateVerify,
    AwaitingServerFinished,
    SendingClientFinished,
    Connected,
    Closing,
    Closed,
    Failed,
}

internal sealed class Tls13ClientStateMachine
{
    private bool _certificateRequestReceived;
    private bool _clientCertificateSent;
    private bool _clientCertificateVerifyRequired;
    private bool _clientCertificateVerifySent;
    private bool _clientApplicationSettingsSent;

    internal Tls13ClientState State { get; private set; } = Tls13ClientState.Created;

    internal void TransportConnected() =>
        Transition(Tls13ClientState.Created, Tls13ClientState.TransportConnected, "transport connection");

    internal void ClientHelloSent() =>
        Transition(Tls13ClientState.TransportConnected, Tls13ClientState.AwaitingServerHello, "ClientHello");

    internal void HelloRetryRequestReceived() =>
        Transition(Tls13ClientState.AwaitingServerHello, Tls13ClientState.TransportConnected, "HelloRetryRequest");

    internal void SecondClientHelloSent()
    {
        if (State != Tls13ClientState.TransportConnected)
        {
            ThrowIllegal("second ClientHello");
        }

        State = Tls13ClientState.AwaitingSecondServerHello;
    }

    internal void ServerHelloReceived()
    {
        if (State is not (Tls13ClientState.AwaitingServerHello or Tls13ClientState.AwaitingSecondServerHello))
        {
            ThrowIllegal("ServerHello");
        }

        State = Tls13ClientState.AwaitingEncryptedExtensions;
    }

    internal void EncryptedExtensionsReceived() => Transition(
        Tls13ClientState.AwaitingEncryptedExtensions,
        Tls13ClientState.AwaitingCertificateOrRequest,
        "EncryptedExtensions");

    internal void CertificateRequestReceived()
    {
        if (State != Tls13ClientState.AwaitingCertificateOrRequest)
        {
            ThrowIllegal("CertificateRequest");
        }

        if (_certificateRequestReceived)
        {
            ThrowIllegal("duplicate CertificateRequest");
        }

        _certificateRequestReceived = true;
    }

    internal void CertificateReceived() => Transition(
        Tls13ClientState.AwaitingCertificateOrRequest,
        Tls13ClientState.AwaitingCertificateVerify,
        "Certificate");

    internal void CertificateVerifyReceived() => Transition(
        Tls13ClientState.AwaitingCertificateVerify,
        Tls13ClientState.AwaitingServerFinished,
        "CertificateVerify");

    internal void ServerFinishedReceived(bool resumed = false)
    {
        var expected = resumed
            ? Tls13ClientState.AwaitingCertificateOrRequest
            : Tls13ClientState.AwaitingServerFinished;
        Transition(expected, Tls13ClientState.SendingClientFinished, "server Finished");
    }

    internal void ClientCertificateSent(bool hasCertificate)
    {
        if (State != Tls13ClientState.SendingClientFinished ||
            !_certificateRequestReceived || _clientCertificateSent)
        {
            ThrowIllegal("client Certificate");
        }

        _clientCertificateSent = true;
        _clientCertificateVerifyRequired = hasCertificate;
    }

    internal void ClientApplicationSettingsSent()
    {
        if (State != Tls13ClientState.SendingClientFinished ||
            _clientApplicationSettingsSent)
        {
            ThrowIllegal("client EncryptedExtensions");
        }

        _clientApplicationSettingsSent = true;
    }

    internal void ClientCertificateVerifySent()
    {
        if (State != Tls13ClientState.SendingClientFinished ||
            !_clientCertificateVerifyRequired || _clientCertificateVerifySent)
        {
            ThrowIllegal("client CertificateVerify");
        }

        _clientCertificateVerifySent = true;
    }

    internal void ClientFinishedSent()
    {
        if (State != Tls13ClientState.SendingClientFinished ||
            (_certificateRequestReceived && !_clientCertificateSent) ||
            (_clientCertificateVerifyRequired && !_clientCertificateVerifySent))
        {
            ThrowIllegal("client Finished");
        }

        State = Tls13ClientState.Connected;
    }

    internal void BeginClose()
    {
        if (State is not (Tls13ClientState.Connected or Tls13ClientState.Failed))
        {
            ThrowIllegal("close_notify");
        }

        State = Tls13ClientState.Closing;
    }

    internal void Closed()
    {
        if (State is not (Tls13ClientState.Closing or Tls13ClientState.Failed))
        {
            ThrowIllegal("transport close");
        }

        State = Tls13ClientState.Closed;
    }

    internal void Fail() => State = Tls13ClientState.Failed;

    private void Transition(Tls13ClientState expected, Tls13ClientState next, string action)
    {
        if (State != expected)
        {
            ThrowIllegal(action);
        }

        State = next;
    }

    private void ThrowIllegal(string action) =>
        throw TlsProtocolException.Unexpected(
            $"Illegal TLS state transition: cannot process {action} while in {State}.");
}
