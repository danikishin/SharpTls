using System.Text;
using SharpTls.IO;
using SharpTls.Protocol;
using SharpTls.Quic;

namespace SharpTls.Handshake;

internal sealed record EncryptedExtensionsResult(
    string? NegotiatedAlpn,
    bool EarlyDataAccepted,
    int? PeerRecordSizeLimit,
    TlsApplicationSettingsCodePoint? ApplicationSettingsCodePoint,
    byte[]? PeerApplicationSettings,
    TlsEchConfigList? EchRetryConfigurations,
    TlsQuicTransportParameters? PeerQuicTransportParameters);

internal static class EncryptedExtensionsParser
{
    internal static EncryptedExtensionsResult Parse(
        ReadOnlySpan<byte> body,
        ClientHelloConfiguration offer,
        bool offeredEarlyData = false,
        bool allowApplicationSettingsWithEarlyData = false,
        bool echWasRejected = false,
        bool echWasGreased = false)
    {
        var reader = new TlsBinaryReader(body);
        var extensions = new TlsBinaryReader(reader.ReadVector16());
        reader.EnsureEnd("EncryptedExtensions");
        var seen = new HashSet<ushort>();
        string? negotiatedAlpn = null;
        var earlyDataAccepted = false;
        int? peerRecordSizeLimit = null;
        TlsApplicationSettingsCodePoint? applicationSettingsCodePoint = null;
        byte[]? peerApplicationSettings = null;
        TlsEchConfigList? echRetryConfigurations = null;
        TlsQuicTransportParameters? peerQuicTransportParameters = null;
        var maximumFragmentLengthReturned = false;

        while (!extensions.End)
        {
            var type = extensions.ReadUInt16();
            var data = extensions.ReadVector16();
            if (!seen.Add(type))
            {
                throw TlsProtocolException.Illegal(
                    $"EncryptedExtensions contains duplicate extension 0x{type:X4}.");
            }


            if (offer.ApplicationSettingsCodePoint is { } offeredCodePoint &&
                type == (ushort)offeredCodePoint)
            {
                applicationSettingsCodePoint = offeredCodePoint;
                peerApplicationSettings = data.ToArray();
                continue;
            }
            if (type is (ushort)TlsApplicationSettingsCodePoint.LegacyDraft or
                (ushort)TlsApplicationSettingsCodePoint.ChromeExperiment)
            {
                throw new TlsProtocolException(
                    TlsAlertDescription.UnsupportedExtension,
                    "The server selected an application_settings code point that the client did not offer.");
            }
            if (type == (ushort)TlsExtensionType.EncryptedClientHello &&
                (echWasRejected || echWasGreased))
            {
                var parsedRetryConfigurations = TlsEchConfigList.Parse(data);
                if (echWasRejected)
                {
                    echRetryConfigurations = parsedRetryConfigurations;
                }
                continue;
            }

            switch ((TlsExtensionType)type)
            {
                case TlsExtensionType.ServerName when offer.IncludeSni:
                    if (!data.IsEmpty)
                    {
                        throw TlsProtocolException.Decode("EncryptedExtensions server_name is not empty.");
                    }
                    break;

                case TlsExtensionType.ApplicationLayerProtocolNegotiation
                    when offer.AlpnProtocols.Length != 0:
                    negotiatedAlpn = ParseAlpn(data, offer.AlpnProtocols);
                    break;

                case TlsExtensionType.SupportedGroups:
                    ParseServerSupportedGroups(data);
                    break;

                case TlsExtensionType.EarlyData when offeredEarlyData:
                    if (!data.IsEmpty)
                    {
                        throw TlsProtocolException.Decode(
                            "EncryptedExtensions early_data is not empty.");
                    }
                    earlyDataAccepted = true;
                    break;

                case TlsExtensionType.RecordSizeLimit when offer.RecordSizeLimit.HasValue:
                    peerRecordSizeLimit = ParseRecordSizeLimit(data);
                    break;

                case TlsExtensionType.QuicTransportParameters
                    when offer.QuicTransportParameters is not null:
                    peerQuicTransportParameters = TlsQuicTransportParameters.Parse(data);
                    peerQuicTransportParameters.ValidatePeer(TlsQuicEndpointRole.Server);
                    break;

                case TlsExtensionType.MaximumFragmentLength when offer.ExtensionLayout.Any(
                    extension => extension.RawExtensionType ==
                        (ushort)TlsExtensionType.MaximumFragmentLength):
                    maximumFragmentLengthReturned = true;
                    break;

                default:
                    if (offer.ExtensionLayout.Any(extension =>
                        extension.RawExtensionType == type))
                    {
                        throw new TlsProtocolException(
                            TlsAlertDescription.UnsupportedExtension,
                            $"Peer returned opaque raw extension 0x{type:X4}, which has no response handler.");
                    }

                    throw new TlsProtocolException(
                        TlsAlertDescription.UnsupportedExtension,
                        $"EncryptedExtensions contains unoffered extension 0x{type:X4}.");
            }
        }

        if (maximumFragmentLengthReturned)
        {
            if (peerRecordSizeLimit.HasValue)
            {
                throw TlsProtocolException.Illegal(
                    "The server returned both maximum_fragment_length and record_size_limit.");
            }
            throw new TlsProtocolException(
                TlsAlertDescription.UnsupportedExtension,
                "The server selected opaque maximum_fragment_length semantics.");
        }

        if (applicationSettingsCodePoint.HasValue)
        {
            if (negotiatedAlpn is null ||
                !offer.ApplicationSettingsProtocols.Contains(
                    negotiatedAlpn,
                    StringComparer.Ordinal))
            {
                throw TlsProtocolException.Illegal(
                    "The server returned application_settings without selecting an advertised settings-capable ALPN protocol.");
            }
            if (earlyDataAccepted && !allowApplicationSettingsWithEarlyData)
            {
                throw TlsProtocolException.Illegal(
                    "The server returned application_settings with early data that was not bound to the selected ticket.");
            }
        }

        return new EncryptedExtensionsResult(
            negotiatedAlpn,
            earlyDataAccepted,
            peerRecordSizeLimit,
            applicationSettingsCodePoint,
            peerApplicationSettings,
            echRetryConfigurations,
            peerQuicTransportParameters);
    }

    private static int ParseRecordSizeLimit(ReadOnlySpan<byte> data)
    {
        var reader = new TlsBinaryReader(data);
        var value = reader.ReadUInt16();
        reader.EnsureEnd("record_size_limit");
        if (value is < 64 or > TlsConstants.MaxPlaintextLength + 1)
        {
            throw TlsProtocolException.Illegal(
                "EncryptedExtensions record_size_limit is outside the TLS 1.3 range.");
        }

        return value;
    }

    private static string ParseAlpn(ReadOnlySpan<byte> data, IReadOnlyList<string> offered)
    {
        var reader = new TlsBinaryReader(data);
        var protocols = new TlsBinaryReader(reader.ReadVector16());
        reader.EnsureEnd("ALPN extension");
        var selected = protocols.ReadVector8(TlsConstants.MaxAlpnProtocolLength);
        if (selected.IsEmpty)
        {
            throw TlsProtocolException.Decode("Server selected an empty ALPN protocol.");
        }
        protocols.EnsureEnd("server ALPN list");

        var selectedName = Encoding.ASCII.GetString(selected);
        if (!offered.Contains(selectedName, StringComparer.Ordinal))
        {
            throw new TlsProtocolException(
                TlsAlertDescription.NoApplicationProtocol,
                "Server selected an ALPN protocol that the client did not offer.");
        }

        return selectedName;
    }

    private static void ParseServerSupportedGroups(ReadOnlySpan<byte> data)
    {
        var reader = new TlsBinaryReader(data);
        var groups = reader.ReadVector16();
        reader.EnsureEnd("server supported_groups");
        if (groups.Length < 2 || (groups.Length & 1) != 0)
        {
            throw TlsProtocolException.Decode("Server supported_groups has an invalid vector length.");
        }

        var values = new TlsBinaryReader(groups);
        var seen = new HashSet<ushort>();
        while (!values.End)
        {
            if (!seen.Add(values.ReadUInt16()))
            {
                throw TlsProtocolException.Illegal("Server supported_groups contains a duplicate group.");
            }
        }
    }
}
