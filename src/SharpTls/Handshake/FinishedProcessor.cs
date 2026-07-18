using System.Security.Cryptography;
using SharpTls.Cryptography;
using SharpTls.Protocol;

namespace SharpTls.Handshake;

internal static class FinishedProcessor
{
    internal static void VerifyServerFinished(
        ReadOnlySpan<byte> body,
        Tls13KeySchedule keySchedule,
        ReadOnlySpan<byte> transcriptHash)
    {
        var expected = keySchedule.ComputeServerFinished(transcriptHash);
        try
        {
            if (body.Length != expected.Length ||
                !CryptographicOperations.FixedTimeEquals(body, expected))
            {
                throw new TlsProtocolException(
                    TlsAlertDescription.DecryptError,
                    "Server Finished verification failed.");
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(expected);
        }
    }

    internal static byte[] CreateClientFinished(
        Tls13KeySchedule keySchedule,
        ReadOnlySpan<byte> transcriptHash)
    {
        var verifyData = keySchedule.ComputeClientFinished(transcriptHash);
        try
        {
            return HandshakeMessage.Encode(HandshakeType.Finished, verifyData);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(verifyData);
        }
    }
}
