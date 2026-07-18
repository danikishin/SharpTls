using SharpTls.Protocol;

namespace SharpTls.Handshake;

internal static class KeyUpdateProcessor
{
    internal const ulong MaximumSendingEpoch = (1UL << 48) - 1;

    internal static bool CanAdvanceSendingEpoch(ulong currentEpoch) =>
        currentEpoch < MaximumSendingEpoch;

    internal static bool ParseRequestUpdate(ReadOnlySpan<byte> body)
    {
        if (body.Length != 1)
        {
            throw TlsProtocolException.Decode("KeyUpdate must contain exactly one request byte.");
        }

        return body[0] switch
        {
            0 => false,
            1 => true,
            _ => throw TlsProtocolException.Illegal("KeyUpdate request_update is not a defined value."),
        };
    }

    internal static byte[] Encode(bool requestPeerUpdate) => HandshakeMessage.Encode(
        HandshakeType.KeyUpdate,
        new byte[] { requestPeerUpdate ? (byte)1 : (byte)0 });
}
