using System.Security.Cryptography;
using SharpTls.Certificates;
using SharpTls.Cryptography;
using SharpTls.IO;
using SharpTls.Protocol;

namespace SharpTls.Handshake;

internal static class Tls12ServerHandshakeMessages
{
    internal static byte[] BuildServerHello(
        ReadOnlySpan<byte> serverRandom,
        ReadOnlySpan<byte> sessionId,
        TlsCipherSuite cipherSuite,
        bool acknowledgeSni,
        bool acknowledgeEcPointFormats,
        bool acknowledgeSessionTicket,
        bool acknowledgeStatusRequest,
        IReadOnlyList<byte[]>? signedCertificateTimestamps,
        string? alpn)
    {
        var extensions = new TlsBinaryWriter();
        if (acknowledgeSni)
        {
            extensions.WriteUInt16((ushort)TlsExtensionType.ServerName);
            extensions.WriteVector16([]);
        }
        extensions.WriteUInt16((ushort)TlsExtensionType.ExtendedMasterSecret);
        extensions.WriteVector16([]);
        extensions.WriteUInt16((ushort)TlsExtensionType.RenegotiationInfo);
        extensions.WriteVector16([0]);
        if (acknowledgeSessionTicket)
        {
            extensions.WriteUInt16((ushort)TlsExtensionType.SessionTicket);
            extensions.WriteVector16([]);
        }
        if (acknowledgeStatusRequest)
        {
            extensions.WriteUInt16((ushort)TlsExtensionType.StatusRequest);
            extensions.WriteVector16([]);
        }
        if (signedCertificateTimestamps is { Count: > 0 })
        {
            extensions.WriteUInt16((ushort)TlsExtensionType.SignedCertificateTimestamp);
            extensions.WriteVector16(
                Tls13ServerHandshakeMessages.EncodeSignedCertificateTimestamps(
                    signedCertificateTimestamps));
        }
        if (acknowledgeEcPointFormats)
        {
            extensions.WriteUInt16((ushort)TlsExtensionType.EcPointFormats);
            extensions.WriteVector16([1, 0]);
        }
        if (alpn is not null)
        {
            var names = new TlsBinaryWriter();
            names.WriteVector8(System.Text.Encoding.ASCII.GetBytes(alpn));
            var selected = new TlsBinaryWriter();
            selected.WriteVector16(names.WrittenSpan);
            extensions.WriteUInt16((ushort)TlsExtensionType.ApplicationLayerProtocolNegotiation);
            extensions.WriteVector16(selected.WrittenSpan);
        }

        var body = new TlsBinaryWriter();
        body.WriteUInt16(TlsConstants.Tls12Version);
        body.WriteBytes(serverRandom);
        body.WriteVector8(sessionId);
        body.WriteUInt16((ushort)cipherSuite);
        body.WriteUInt8(0);
        body.WriteVector16(extensions.WrittenSpan);
        return HandshakeMessage.Encode(HandshakeType.ServerHello, body.WrittenSpan);
    }

    internal static byte[] BuildCertificate(
        TlsServerCertificate credential,
        TlsLimits limits)
    {
        var entries = new TlsBinaryWriter();
        var chain = credential.SnapshotCertificateChain();
        if (chain.Count > limits.MaxCertificateCount)
        {
            throw new TlsProtocolException(
                TlsAlertDescription.InternalError,
                "TLS 1.2 server certificate count exceeds the configured limit.");
        }
        foreach (var certificate in chain)
        {
            entries.WriteVector24(certificate);
        }
        if (entries.Length > limits.MaxCertificateListSize)
        {
            throw new TlsProtocolException(
                TlsAlertDescription.InternalError,
                "TLS 1.2 server certificate list exceeds the configured limit.");
        }
        var body = new TlsBinaryWriter();
        body.WriteVector24(entries.WrittenSpan);
        return HandshakeMessage.Encode(HandshakeType.Certificate, body.WrittenSpan);
    }

    internal static byte[] BuildServerKeyExchange(
        NamedGroup group,
        ReadOnlySpan<byte> publicKey,
        SignatureScheme signatureScheme,
        Tls12CertificateKeyType certificateKeyType,
        TlsServerCertificate credential,
        ReadOnlySpan<byte> clientRandom,
        ReadOnlySpan<byte> serverRandom)
    {
        if (publicKey.IsEmpty || publicKey.Length > byte.MaxValue)
        {
            throw new ArgumentOutOfRangeException(nameof(publicKey));
        }
        var parameters = new TlsBinaryWriter();
        parameters.WriteUInt8(3);
        parameters.WriteUInt16((ushort)group);
        parameters.WriteVector8(publicKey);
        var signedContent = new byte[
            2 * TlsConstants.RandomLength + parameters.Length];
        clientRandom.CopyTo(signedContent);
        serverRandom.CopyTo(signedContent.AsSpan(TlsConstants.RandomLength));
        parameters.WrittenSpan.CopyTo(
            signedContent.AsSpan(2 * TlsConstants.RandomLength));
        byte[]? signature = null;
        try
        {
            signature = credential.SignTls12ServerKeyExchange(
                signatureScheme,
                certificateKeyType,
                signedContent);
            var body = new TlsBinaryWriter();
            body.WriteBytes(parameters.WrittenSpan);
            body.WriteUInt16((ushort)signatureScheme);
            body.WriteVector16(signature);
            return HandshakeMessage.Encode(
                HandshakeType.ServerKeyExchange,
                body.WrittenSpan);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(signedContent);
            if (signature is not null)
            {
                CryptographicOperations.ZeroMemory(signature);
            }
        }
    }

    internal static byte[] BuildCertificateRequest(
        IReadOnlyList<SignatureScheme> signatureAlgorithms)
    {
        var algorithms = new TlsBinaryWriter();
        foreach (var algorithm in signatureAlgorithms)
        {
            algorithms.WriteUInt16((ushort)algorithm);
        }
        var body = new TlsBinaryWriter();
        body.WriteVector8([1, 64]);
        body.WriteVector16(algorithms.WrittenSpan);
        body.WriteVector16([]);
        return HandshakeMessage.Encode(HandshakeType.CertificateRequest, body.WrittenSpan);
    }

    internal static byte[] BuildServerHelloDone() =>
        HandshakeMessage.Encode(HandshakeType.ServerHelloDone, []);

    internal static byte[]? BuildCertificateStatus(TlsServerCertificate credential)
    {
        var ocsp = credential.CopyStapledOcspResponse();
        if (ocsp is null)
        {
            return null;
        }
        var body = new TlsBinaryWriter();
        body.WriteUInt8(1);
        body.WriteVector24(ocsp);
        return HandshakeMessage.Encode(HandshakeType.CertificateStatus, body.WrittenSpan);
    }

    internal static byte[] BuildNewSessionTicket(uint lifetimeHintSeconds, ReadOnlySpan<byte> ticket)
    {
        if (ticket.IsEmpty || ticket.Length > ushort.MaxValue)
        {
            throw new ArgumentOutOfRangeException(nameof(ticket));
        }
        var body = new TlsBinaryWriter();
        body.WriteUInt32(lifetimeHintSeconds);
        body.WriteVector16(ticket);
        return HandshakeMessage.Encode(HandshakeType.NewSessionTicket, body.WrittenSpan);
    }
}
