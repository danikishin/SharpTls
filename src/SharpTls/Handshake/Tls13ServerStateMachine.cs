using SharpTls.Protocol;

namespace SharpTls.Handshake;

internal enum Tls13ServerState
{
    Created,
    AwaitingClientHello,
    AwaitingSecondClientHello,
    SendingServerFlight,
    AwaitingClientFinished,
    Connected,
    Closing,
    Closed,
    Failed,
}

internal sealed class Tls13ServerStateMachine
{
    internal Tls13ServerState State { get; private set; } = Tls13ServerState.Created;

    internal void TransportAccepted() => Transition(
        Tls13ServerState.Created,
        Tls13ServerState.AwaitingClientHello,
        "transport acceptance");

    internal void HelloRetryRequestSent() => Transition(
        Tls13ServerState.AwaitingClientHello,
        Tls13ServerState.AwaitingSecondClientHello,
        "HelloRetryRequest");

    internal void ClientHelloAccepted()
    {
        if (State is not (
            Tls13ServerState.AwaitingClientHello or
            Tls13ServerState.AwaitingSecondClientHello))
        {
            ThrowIllegal("ClientHello");
        }
        State = Tls13ServerState.SendingServerFlight;
    }

    internal void ServerFlightSent() => Transition(
        Tls13ServerState.SendingServerFlight,
        Tls13ServerState.AwaitingClientFinished,
        "server flight");

    internal void ClientFinishedReceived() => Transition(
        Tls13ServerState.AwaitingClientFinished,
        Tls13ServerState.Connected,
        "client Finished");

    internal void BeginClose()
    {
        if (State is not (Tls13ServerState.Connected or Tls13ServerState.Failed))
        {
            ThrowIllegal("close_notify");
        }
        State = Tls13ServerState.Closing;
    }

    internal void Closed()
    {
        if (State is not (Tls13ServerState.Closing or Tls13ServerState.Failed))
        {
            ThrowIllegal("transport close");
        }
        State = Tls13ServerState.Closed;
    }

    internal void Fail() => State = Tls13ServerState.Failed;

    private void Transition(Tls13ServerState expected, Tls13ServerState next, string action)
    {
        if (State != expected)
        {
            ThrowIllegal(action);
        }
        State = next;
    }

    private void ThrowIllegal(string action) => throw TlsProtocolException.Unexpected(
        $"Illegal TLS server state transition: cannot process {action} while in {State}.");
}
