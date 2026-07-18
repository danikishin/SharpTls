using System.Security.Cryptography;
using SharpTls.Cryptography;
using SharpTls.IO;
using SharpTls.Protocol;

namespace SharpTls.Handshake;

internal sealed record Tls12CertificateRequest(
    byte[] CertificateTypes,
    SignatureScheme[] SignatureSchemes,
    int CertificateAuthorityCount);

internal static class Tls12CertificateRequestParser
{
    internal static Tls12CertificateRequest Parse(ReadOnlySpan<byte> body)
    {
        var reader = new TlsBinaryReader(body);
        var certificateTypes = reader.ReadVector8().ToArray();
        if (certificateTypes.Length == 0)
        {
            throw TlsProtocolException.Decode(
                "TLS 1.2 CertificateRequest certificate_types is empty.");
        }

        var encodedSchemes = new TlsBinaryReader(reader.ReadVector16());
        if (encodedSchemes.End || (encodedSchemes.Remaining & 1) != 0)
        {
            throw TlsProtocolException.Decode(
                "TLS 1.2 CertificateRequest signature_algorithms is empty or odd-sized.");
        }
        var schemes = new List<SignatureScheme>();
        while (!encodedSchemes.End)
        {
            var value = encodedSchemes.ReadUInt16();
            if (Enum.IsDefined(typeof(SignatureScheme), value))
            {
                schemes.Add((SignatureScheme)value);
            }
        }

        var encodedAuthorities = new TlsBinaryReader(reader.ReadVector16());
        reader.EnsureEnd("TLS 1.2 CertificateRequest");
        var authorityCount = 0;
        while (!encodedAuthorities.End)
        {
            _ = encodedAuthorities.ReadVector16();
            authorityCount++;
        }

        return new Tls12CertificateRequest(certificateTypes, [.. schemes], authorityCount);
    }

}

internal static class Tls12ClientKeyExchangeEncoder
{
    internal static byte[] Encode(ReadOnlySpan<byte> publicKey)
    {
        if (publicKey.IsEmpty || publicKey.Length > byte.MaxValue)
        {
            throw new ArgumentOutOfRangeException(nameof(publicKey));
        }

        var body = new TlsBinaryWriter(1 + publicKey.Length);
        body.WriteVector8(publicKey);
        return HandshakeMessage.Encode(HandshakeType.ClientKeyExchange, body.WrittenSpan);
    }
}

internal static class Tls12FinishedProcessor
{
    internal static byte[] CreateClientFinished(
        Tls12KeySchedule keySchedule,
        ReadOnlySpan<byte> transcriptHash)
    {
        ArgumentNullException.ThrowIfNull(keySchedule);
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

    internal static void VerifyServerFinished(
        ReadOnlySpan<byte> body,
        Tls12KeySchedule keySchedule,
        ReadOnlySpan<byte> transcriptHash)
    {
        ArgumentNullException.ThrowIfNull(keySchedule);
        if (body.Length != TlsConstants.Tls12FinishedLength)
        {
            throw TlsProtocolException.Decode("TLS 1.2 Finished verify_data has an invalid length.");
        }

        var expected = keySchedule.ComputeServerFinished(transcriptHash);
        try
        {
            if (!CryptographicOperations.FixedTimeEquals(expected, body))
            {
                throw new TlsProtocolException(
                    TlsAlertDescription.DecryptError,
                    "TLS 1.2 server Finished verification failed.");
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(expected);
        }
    }
}

internal static class Tls12NewSessionTicketParser
{
    internal static Tls12NewSessionTicket Parse(ReadOnlySpan<byte> body)
    {
        var reader = new TlsBinaryReader(body);
        var lifetimeHint = reader.ReadUInt32();
        var ticket = reader.ReadVector16().ToArray();
        reader.EnsureEnd("TLS 1.2 NewSessionTicket");
        return new Tls12NewSessionTicket(lifetimeHint, ticket);
    }

    internal static void ParseAndDiscard(ReadOnlySpan<byte> body)
    {
        using var ticket = Parse(body);
    }
}

internal sealed record Tls12NewSessionTicket(uint LifetimeHintSeconds, byte[] Ticket) : IDisposable
{
    public void Dispose() => CryptographicOperations.ZeroMemory(Ticket);
}
