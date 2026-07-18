using System.Text;
using SharpTls.Cryptography;
using SharpTls.IO;
using SharpTls.Protocol;

namespace SharpTls.Handshake;

internal sealed record Tls12ServerHelloResult(
    byte[] Random,
    byte[] SessionId,
    TlsCipherSuite CipherSuite,
    Tls12CipherSuiteInfo SuiteInfo,
    bool ExtendedMasterSecretNegotiated,
    bool SecureRenegotiationNegotiated,
    bool CertificateStatusExpected,
    bool SessionTicketAcknowledged,
    byte[][] SignedCertificateTimestamps,
    string? AlpnProtocol,
    int? PeerRecordSizeLimit)
{
    internal bool SignedCertificateTimestampsIncluded => SignedCertificateTimestamps.Length != 0;
}

internal sealed record Tls12ServerHelloSecurityPolicy(
    bool RequireExtendedMasterSecret = true,
    bool RequireSecureRenegotiation = true)
{
    internal static Tls12ServerHelloSecurityPolicy Default { get; } = new();
}

internal static class Tls12ServerHelloParser
{
    private static ReadOnlySpan<byte> Tls12DowngradeSentinel => "DOWNGRD\x01"u8;
    private static ReadOnlySpan<byte> LegacyDowngradeSentinel => "DOWNGRD\x00"u8;

    internal static Tls12ServerHelloResult Parse(
        ReadOnlySpan<byte> body,
        ClientHelloBuildResult offer,
        Tls12ServerHelloSecurityPolicy? securityPolicy = null)
    {
        ArgumentNullException.ThrowIfNull(offer);
        securityPolicy ??= Tls12ServerHelloSecurityPolicy.Default;
        var reader = new TlsBinaryReader(body);
        if (reader.ReadUInt16() != TlsConstants.Tls12Version)
        {
            throw new TlsProtocolException(
                TlsAlertDescription.ProtocolVersion,
                "TLS 1.2 ServerHello version is not 0x0303.");
        }

        var random = reader.ReadBytes(TlsConstants.RandomLength).ToArray();
        ValidateDowngradeSentinel(random, offer.Configuration);
        var sessionId = reader.ReadVector8(TlsConstants.MaxSessionIdLength).ToArray();

        var suiteValue = reader.ReadUInt16();
        if (!offer.Configuration.CipherSuites.Any(suite => (ushort)suite == suiteValue))
        {
            throw TlsProtocolException.Illegal("TLS 1.2 ServerHello selected an unoffered cipher suite.");
        }

        TlsCipherSuite selectedSuite;
        Tls12CipherSuiteInfo suiteInfo;
        try
        {
            selectedSuite = (TlsCipherSuite)suiteValue;
            suiteInfo = Tls12CipherSuiteInfo.Get(selectedSuite);
        }
        catch (NotSupportedException exception)
        {
            throw new TlsProtocolException(
                TlsAlertDescription.HandshakeFailure,
                $"Server selected TLS 1.2 suite 0x{suiteValue:X4}, which has no secure executable implementation.",
                exception);
        }

        if (reader.ReadUInt8() != 0)
        {
            throw TlsProtocolException.Illegal("TLS 1.2 ServerHello selected legacy compression.");
        }

        var extensionBytes = reader.End ? ReadOnlySpan<byte>.Empty : reader.ReadVector16();
        reader.EnsureEnd("TLS 1.2 ServerHello");
        var extensions = new TlsBinaryReader(extensionBytes);
        var seen = new HashSet<ushort>();
        var hasEms = false;
        var hasSecureRenegotiation = false;
        var certificateStatusExpected = false;
        var sessionTicketAcknowledged = false;
        byte[][] signedCertificateTimestamps = [];
        string? selectedAlpn = null;
        int? peerRecordSizeLimit = null;
        var maximumFragmentLengthReturned = false;

        while (!extensions.End)
        {
            var type = extensions.ReadUInt16();
            var data = extensions.ReadVector16();
            if (!seen.Add(type))
            {
                throw TlsProtocolException.Illegal(
                    $"TLS 1.2 ServerHello contains duplicate extension 0x{type:X4}.");
            }
            if (!WasExtensionOffered(type, offer.Configuration))
            {
                throw new TlsProtocolException(
                    TlsAlertDescription.UnsupportedExtension,
                    $"TLS 1.2 ServerHello contains unoffered extension 0x{type:X4}.");
            }

            switch ((TlsExtensionType)type)
            {
                case TlsExtensionType.ServerName:
                    RequireEmpty(data, "server_name");
                    break;

                case TlsExtensionType.StatusRequest:
                    RequireEmpty(data, "status_request");
                    certificateStatusExpected = true;
                    break;

                case TlsExtensionType.EcPointFormats:
                    ParsePointFormats(data);
                    break;

                case TlsExtensionType.ApplicationLayerProtocolNegotiation:
                    selectedAlpn = ParseAlpn(data, offer.Configuration.AlpnProtocols);
                    break;

                case TlsExtensionType.SignedCertificateTimestamp:
                    signedCertificateTimestamps = ParseSignedCertificateTimestamps(data);
                    break;

                case TlsExtensionType.ExtendedMasterSecret:
                    RequireEmpty(data, "extended_master_secret");
                    hasEms = true;
                    break;

                case TlsExtensionType.SessionTicket:
                    RequireEmpty(data, "session_ticket");
                    sessionTicketAcknowledged = true;
                    break;

                case TlsExtensionType.RenegotiationInfo:
                    if (!data.SequenceEqual(new byte[] { 0 }))
                    {
                        throw TlsProtocolException.Illegal(
                            "Initial TLS 1.2 renegotiation_info must contain an empty renegotiated_connection vector.");
                    }
                    hasSecureRenegotiation = true;
                    break;

                case TlsExtensionType.RecordSizeLimit:
                    peerRecordSizeLimit = ParseRecordSizeLimit(data);
                    break;

                case TlsExtensionType.MaximumFragmentLength:
                    maximumFragmentLengthReturned = true;
                    break;

                case TlsExtensionType.SupportedVersions:
                    throw TlsProtocolException.Illegal(
                        "A server negotiating TLS 1.2 must not send supported_versions in ServerHello.");

                default:
                    throw new TlsProtocolException(
                        TlsAlertDescription.UnsupportedExtension,
                        $"TLS 1.2 ServerHello extension 0x{type:X4} has no implemented response semantics.");
            }
        }

        if (maximumFragmentLengthReturned)
        {
            if (peerRecordSizeLimit.HasValue)
            {
                throw TlsProtocolException.Illegal(
                    "TLS 1.2 ServerHello returned both maximum_fragment_length and record_size_limit.");
            }
            throw new TlsProtocolException(
                TlsAlertDescription.UnsupportedExtension,
                "TLS 1.2 selected opaque maximum_fragment_length semantics.");
        }

        if (securityPolicy.RequireExtendedMasterSecret && !hasEms)
        {
            throw new TlsProtocolException(
                TlsAlertDescription.HandshakeFailure,
                "TLS 1.2 ServerHello did not negotiate extended_master_secret.");
        }
        if (securityPolicy.RequireSecureRenegotiation && !hasSecureRenegotiation)
        {
            throw new TlsProtocolException(
                TlsAlertDescription.HandshakeFailure,
                "TLS 1.2 ServerHello did not acknowledge secure renegotiation.");
        }

        return new Tls12ServerHelloResult(
            random,
            sessionId,
            selectedSuite,
            suiteInfo,
            hasEms,
            hasSecureRenegotiation,
            certificateStatusExpected,
            sessionTicketAcknowledged,
            signedCertificateTimestamps,
            selectedAlpn,
            peerRecordSizeLimit);
    }

    private static void ValidateDowngradeSentinel(
        ReadOnlySpan<byte> random,
        ClientHelloConfiguration offer)
    {
        if (!offer.SupportedVersions.Contains(TlsProtocolVersion.Tls13))
        {
            return;
        }

        var suffix = random[^8..];
        if (suffix.SequenceEqual(Tls12DowngradeSentinel) ||
            suffix.SequenceEqual(LegacyDowngradeSentinel))
        {
            throw TlsProtocolException.Illegal(
                "TLS 1.2 ServerHello contains an RFC 8446 downgrade sentinel.");
        }
    }

    private static bool WasExtensionOffered(ushort type, ClientHelloConfiguration offer)
    {
        foreach (var extension in offer.ExtensionLayout)
        {
            if (extension.RawExtensionType == type)
            {
                return true;
            }
            if (extension.BuiltInKind is { } kind && TryGetWireType(kind) == type)
            {
                return true;
            }
        }

        return false;
    }

    private static ushort? TryGetWireType(ClientHelloExtensionKind kind) => kind switch
    {
        ClientHelloExtensionKind.ServerName => (ushort)TlsExtensionType.ServerName,
        ClientHelloExtensionKind.SupportedVersions => (ushort)TlsExtensionType.SupportedVersions,
        ClientHelloExtensionKind.Cookie => (ushort)TlsExtensionType.Cookie,
        ClientHelloExtensionKind.SupportedGroups => (ushort)TlsExtensionType.SupportedGroups,
        ClientHelloExtensionKind.SignatureAlgorithms => (ushort)TlsExtensionType.SignatureAlgorithms,
        ClientHelloExtensionKind.SignatureAlgorithmsCert =>
            (ushort)TlsExtensionType.SignatureAlgorithmsCert,
        ClientHelloExtensionKind.KeyShare => (ushort)TlsExtensionType.KeyShare,
        ClientHelloExtensionKind.PskKeyExchangeModes =>
            (ushort)TlsExtensionType.PskKeyExchangeModes,
        ClientHelloExtensionKind.EarlyData => (ushort)TlsExtensionType.EarlyData,
        ClientHelloExtensionKind.PreSharedKey => (ushort)TlsExtensionType.PreSharedKey,
        ClientHelloExtensionKind.ApplicationLayerProtocolNegotiation =>
            (ushort)TlsExtensionType.ApplicationLayerProtocolNegotiation,
        ClientHelloExtensionKind.PostHandshakeAuthentication =>
            (ushort)TlsExtensionType.PostHandshakeAuthentication,
        ClientHelloExtensionKind.RecordSizeLimit => (ushort)TlsExtensionType.RecordSizeLimit,
        ClientHelloExtensionKind.Padding => (ushort)TlsExtensionType.Padding,
        ClientHelloExtensionKind.Grease or ClientHelloExtensionKind.SecondaryGrease => null,
        _ => null,
    };

    private static int ParseRecordSizeLimit(ReadOnlySpan<byte> data)
    {
        var reader = new TlsBinaryReader(data);
        var value = reader.ReadUInt16();
        reader.EnsureEnd("TLS 1.2 record_size_limit");
        if (value is < 64 or > TlsConstants.MaxPlaintextLength)
        {
            throw TlsProtocolException.Illegal(
                "TLS 1.2 record_size_limit is outside the negotiated protocol range.");
        }

        return value;
    }

    private static void ParsePointFormats(ReadOnlySpan<byte> data)
    {
        var reader = new TlsBinaryReader(data);
        var formats = reader.ReadVector8();
        reader.EnsureEnd("ec_point_formats");
        if (formats.IsEmpty || !formats.Contains((byte)0))
        {
            throw TlsProtocolException.Illegal(
                "TLS 1.2 ServerHello ec_point_formats omitted uncompressed points.");
        }
    }

    private static string ParseAlpn(ReadOnlySpan<byte> data, IReadOnlyList<string> offeredProtocols)
    {
        var reader = new TlsBinaryReader(data);
        var protocolList = new TlsBinaryReader(reader.ReadVector16());
        reader.EnsureEnd("ALPN extension");
        var protocolBytes = protocolList.ReadVector8(TlsConstants.MaxAlpnProtocolLength);
        if (protocolBytes.IsEmpty)
        {
            throw TlsProtocolException.Decode("TLS 1.2 ServerHello selected an empty ALPN protocol.");
        }
        protocolList.EnsureEnd("TLS 1.2 ServerHello ALPN protocol list");

        var selected = Encoding.ASCII.GetString(protocolBytes);
        if (!offeredProtocols.Contains(selected, StringComparer.Ordinal))
        {
            throw TlsProtocolException.Illegal("TLS 1.2 ServerHello selected an unoffered ALPN protocol.");
        }

        return selected;
    }

    private static byte[][] ParseSignedCertificateTimestamps(ReadOnlySpan<byte> data)
    {
        var reader = new TlsBinaryReader(data);
        var list = new TlsBinaryReader(reader.ReadVector16());
        reader.EnsureEnd("signed_certificate_timestamp");
        if (list.End)
        {
            throw TlsProtocolException.Decode("TLS 1.2 ServerHello SCT list is empty.");
        }
        var result = new List<byte[]>();
        while (!list.End)
        {
            var encodedSct = list.ReadVector16().ToArray();
            if (encodedSct.Length == 0)
            {
                throw TlsProtocolException.Decode("TLS 1.2 ServerHello SCT entry is empty.");
            }
            result.Add(encodedSct);
        }
        return result.ToArray();
    }

    private static void RequireEmpty(ReadOnlySpan<byte> data, string name)
    {
        if (!data.IsEmpty)
        {
            throw TlsProtocolException.Illegal($"TLS 1.2 ServerHello {name} response must be empty.");
        }
    }
}
