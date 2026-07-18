using System.Security.Cryptography;
using System.IO.Compression;
using SharpTls.Certificates;
using SharpTls.IO;
using SharpTls.Protocol;
using SharpTls.Quic;

namespace SharpTls.Handshake;

internal static class Tls13ServerHandshakeMessages
{
    internal static byte[] BuildServerHello(
        ReadOnlySpan<byte> sessionId,
        TlsCipherSuite suite,
        NamedGroup group,
        ReadOnlySpan<byte> keyExchange,
        int? selectedPskIdentity = null)
    {
        var extensions = new TlsBinaryWriter();
        var version = new TlsBinaryWriter();
        version.WriteUInt16(TlsConstants.Tls13Version);
        extensions.WriteUInt16((ushort)TlsExtensionType.SupportedVersions);
        extensions.WriteVector16(version.WrittenSpan);
        var keyShare = new TlsBinaryWriter();
        keyShare.WriteUInt16((ushort)group);
        keyShare.WriteVector16(keyExchange);
        extensions.WriteUInt16((ushort)TlsExtensionType.KeyShare);
        extensions.WriteVector16(keyShare.WrittenSpan);
        if (selectedPskIdentity.HasValue)
        {
            var selectedIdentity = new TlsBinaryWriter();
            selectedIdentity.WriteUInt16(checked((ushort)selectedPskIdentity.Value));
            extensions.WriteUInt16((ushort)TlsExtensionType.PreSharedKey);
            extensions.WriteVector16(selectedIdentity.WrittenSpan);
        }
        var body = new TlsBinaryWriter();
        body.WriteUInt16(TlsConstants.LegacyRecordVersion);
        body.WriteBytes(RandomNumberGenerator.GetBytes(TlsConstants.RandomLength));
        body.WriteVector8(sessionId);
        body.WriteUInt16((ushort)suite);
        body.WriteUInt8(0);
        body.WriteVector16(extensions.WrittenSpan);
        return HandshakeMessage.Encode(HandshakeType.ServerHello, body.WrittenSpan);
    }

    internal static byte[] BuildHelloRetryRequest(
        ReadOnlySpan<byte> sessionId,
        TlsCipherSuite suite,
        NamedGroup group,
        bool includeEchAcceptanceConfirmation = false)
    {
        ReadOnlySpan<byte> random =
        [
            0xCF, 0x21, 0xAD, 0x74, 0xE5, 0x9A, 0x61, 0x11,
            0xBE, 0x1D, 0x8C, 0x02, 0x1E, 0x65, 0xB8, 0x91,
            0xC2, 0xA2, 0x11, 0x16, 0x7A, 0xBB, 0x8C, 0x5E,
            0x07, 0x9E, 0x09, 0xE2, 0xC8, 0xA8, 0x33, 0x9C,
        ];
        var extensions = new TlsBinaryWriter();
        var version = new TlsBinaryWriter();
        version.WriteUInt16(TlsConstants.Tls13Version);
        extensions.WriteUInt16((ushort)TlsExtensionType.SupportedVersions);
        extensions.WriteVector16(version.WrittenSpan);
        var keyShare = new TlsBinaryWriter();
        keyShare.WriteUInt16((ushort)group);
        extensions.WriteUInt16((ushort)TlsExtensionType.KeyShare);
        extensions.WriteVector16(keyShare.WrittenSpan);
        if (includeEchAcceptanceConfirmation)
        {
            extensions.WriteUInt16((ushort)TlsExtensionType.EncryptedClientHello);
            extensions.WriteVector16(new byte[Ech.EchAcceptanceConfirmation.ConfirmationLength]);
        }
        var body = new TlsBinaryWriter();
        body.WriteUInt16(TlsConstants.LegacyRecordVersion);
        body.WriteBytes(random);
        body.WriteVector8(sessionId);
        body.WriteUInt16((ushort)suite);
        body.WriteUInt8(0);
        body.WriteVector16(extensions.WrittenSpan);
        return HandshakeMessage.Encode(HandshakeType.ServerHello, body.WrittenSpan);
    }

    internal static byte[] BuildEncryptedExtensions(
        bool acknowledgeSni,
        string? alpn,
        TlsQuicTransportParameters? quicTransportParameters = null,
        bool acknowledgeEarlyData = false,
        ReadOnlySpan<byte> echRetryConfigurations = default)
    {
        var extensions = new TlsBinaryWriter();
        if (acknowledgeSni)
        {
            extensions.WriteUInt16((ushort)TlsExtensionType.ServerName);
            extensions.WriteVector16([]);
        }
        if (alpn is not null)
        {
            var names = new TlsBinaryWriter();
            names.WriteVector8(System.Text.Encoding.ASCII.GetBytes(alpn));
            var encoded = new TlsBinaryWriter();
            encoded.WriteVector16(names.WrittenSpan);
            extensions.WriteUInt16((ushort)TlsExtensionType.ApplicationLayerProtocolNegotiation);
            extensions.WriteVector16(encoded.WrittenSpan);
        }
        if (quicTransportParameters is not null)
        {
            extensions.WriteUInt16((ushort)TlsExtensionType.QuicTransportParameters);
            extensions.WriteVector16(quicTransportParameters.Encode());
        }
        if (acknowledgeEarlyData)
        {
            extensions.WriteUInt16((ushort)TlsExtensionType.EarlyData);
            extensions.WriteVector16([]);
        }
        if (!echRetryConfigurations.IsEmpty)
        {
            extensions.WriteUInt16((ushort)TlsExtensionType.EncryptedClientHello);
            extensions.WriteVector16(echRetryConfigurations);
        }
        var body = new TlsBinaryWriter();
        body.WriteVector16(extensions.WrittenSpan);
        return HandshakeMessage.Encode(HandshakeType.EncryptedExtensions, body.WrittenSpan);
    }

    internal static byte[] BuildCertificateRequest(
        IReadOnlyList<SignatureScheme> signatureAlgorithms)
    {
        var algorithms = new TlsBinaryWriter();
        foreach (var algorithm in signatureAlgorithms)
        {
            algorithms.WriteUInt16((ushort)algorithm);
        }
        var algorithmList = new TlsBinaryWriter();
        algorithmList.WriteVector16(algorithms.WrittenSpan);
        var extensions = new TlsBinaryWriter();
        extensions.WriteUInt16((ushort)TlsExtensionType.SignatureAlgorithms);
        extensions.WriteVector16(algorithmList.WrittenSpan);
        var body = new TlsBinaryWriter();
        body.WriteVector8([]);
        body.WriteVector16(extensions.WrittenSpan);
        return HandshakeMessage.Encode(HandshakeType.CertificateRequest, body.WrittenSpan);
    }

    internal static byte[] BuildCertificate(
        TlsServerCertificate credential,
        TlsLimits limits,
        bool includeOcspResponse = false,
        bool includeSignedCertificateTimestamps = false)
    {
        var body = BuildCertificateBody(
            credential,
            limits,
            includeOcspResponse,
            includeSignedCertificateTimestamps);
        return HandshakeMessage.Encode(HandshakeType.Certificate, body);
    }

    internal static byte[] BuildCompressedCertificate(
        TlsServerCertificate credential,
        TlsLimits limits,
        TlsCertificateCompressionAlgorithm algorithm,
        bool includeOcspResponse = false,
        bool includeSignedCertificateTimestamps = false)
    {
        if (algorithm is not (TlsCertificateCompressionAlgorithm.Zlib or
            TlsCertificateCompressionAlgorithm.Brotli))
        {
            throw new ArgumentOutOfRangeException(nameof(algorithm));
        }

        var certificateBody = BuildCertificateBody(
            credential,
            limits,
            includeOcspResponse,
            includeSignedCertificateTimestamps);
        using var output = new MemoryStream();
        using (Stream compressor = algorithm switch
        {
            TlsCertificateCompressionAlgorithm.Zlib =>
                new ZLibStream(output, CompressionLevel.SmallestSize, leaveOpen: true),
            TlsCertificateCompressionAlgorithm.Brotli =>
                new BrotliStream(output, CompressionLevel.SmallestSize, leaveOpen: true),
            _ => throw new InvalidOperationException(
                "Certificate compression selection invariant failed."),
        })
        {
            compressor.Write(certificateBody);
        }

        var compressed = output.ToArray();
        if (compressed.Length == 0 || compressed.Length > limits.MaxHandshakeMessageSize)
        {
            throw new TlsProtocolException(
                TlsAlertDescription.InternalError,
                "Compressed server Certificate exceeds the configured handshake limit.");
        }
        var body = new TlsBinaryWriter();
        body.WriteUInt16((ushort)algorithm);
        body.WriteUInt24(certificateBody.Length);
        body.WriteVector24(compressed);
        if (body.Length > limits.MaxHandshakeMessageSize)
        {
            throw new TlsProtocolException(
                TlsAlertDescription.InternalError,
                "CompressedCertificate exceeds the configured handshake limit.");
        }
        return HandshakeMessage.Encode(HandshakeType.CompressedCertificate, body.WrittenSpan);
    }

    private static byte[] BuildCertificateBody(
        TlsServerCertificate credential,
        TlsLimits limits,
        bool includeOcspResponse,
        bool includeSignedCertificateTimestamps)
    {
        var entries = new TlsBinaryWriter();
        var chain = credential.SnapshotCertificateChain();
        if (chain.Count > limits.MaxCertificateCount)
        {
            throw new TlsProtocolException(
                TlsAlertDescription.InternalError,
                "Server certificate chain exceeds the configured certificate-count limit.");
        }
        var ocsp = includeOcspResponse ? credential.CopyStapledOcspResponse() : null;
        var scts = includeSignedCertificateTimestamps
            ? credential.CopySignedCertificateTimestamps()
            : [];
        for (var index = 0; index < chain.Count; index++)
        {
            entries.WriteVector24(chain[index]);
            var extensions = new TlsBinaryWriter();
            if (index == 0 && ocsp is not null)
            {
                var status = new TlsBinaryWriter();
                status.WriteUInt8(1);
                status.WriteVector24(ocsp);
                extensions.WriteUInt16((ushort)TlsExtensionType.StatusRequest);
                extensions.WriteVector16(status.WrittenSpan);
            }
            if (index == 0 && scts.Length != 0)
            {
                var list = EncodeSignedCertificateTimestamps(scts);
                extensions.WriteUInt16((ushort)TlsExtensionType.SignedCertificateTimestamp);
                extensions.WriteVector16(list);
            }
            entries.WriteVector16(extensions.WrittenSpan);
        }
        if (entries.Length > limits.MaxCertificateListSize)
        {
            throw new TlsProtocolException(
                TlsAlertDescription.InternalError,
                "Server certificate chain exceeds the configured list-size limit.");
        }
        var body = new TlsBinaryWriter();
        body.WriteVector8([]);
        body.WriteVector24(entries.WrittenSpan);
        if (body.Length > limits.MaxHandshakeMessageSize)
        {
            throw new TlsProtocolException(
                TlsAlertDescription.InternalError,
                "Server Certificate exceeds the configured handshake limit.");
        }
        return body.ToArray();
    }

    internal static byte[] EncodeSignedCertificateTimestamps(IReadOnlyList<byte[]> scts)
    {
        var entries = new TlsBinaryWriter();
        foreach (var sct in scts)
        {
            entries.WriteVector16(sct);
        }
        var list = new TlsBinaryWriter();
        list.WriteVector16(entries.WrittenSpan);
        return list.ToArray();
    }

    internal static byte[] BuildCertificateVerify(
        TlsServerCertificate credential,
        SignatureScheme scheme,
        ReadOnlySpan<byte> transcriptHash)
    {
        var signature = credential.SignTls13CertificateVerify(scheme, transcriptHash);
        try
        {
            var body = new TlsBinaryWriter();
            body.WriteUInt16((ushort)scheme);
            body.WriteVector16(signature);
            return HandshakeMessage.Encode(HandshakeType.CertificateVerify, body.WrittenSpan);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(signature);
        }
    }
}
