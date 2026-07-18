using System.Text;
using SharpTls.IO;
using SharpTls.Protocol;

namespace SharpTls.Handshake;

internal sealed record Tls12ParsedClientHello(
    byte[] Random,
    byte[] SessionId,
    TlsCipherSuite[] CipherSuites,
    NamedGroup[] SupportedGroups,
    SignatureScheme[] SignatureAlgorithms,
    string[] AlpnProtocols,
    string? ServerName,
    byte[]? SessionTicket,
    IReadOnlyDictionary<ushort, byte[]> ExtensionBodies);

internal static class TlsClientHelloVersionOfferParser
{
    internal static TlsProtocolVersion[] Parse(ReadOnlySpan<byte> body)
    {
        var reader = new TlsBinaryReader(body);
        var legacyVersion = reader.ReadUInt16();
        _ = reader.ReadBytes(TlsConstants.RandomLength);
        _ = reader.ReadVector8(TlsConstants.MaxSessionIdLength);
        _ = reader.ReadVector16();
        _ = reader.ReadVector8();
        if (reader.End)
        {
            return legacyVersion >= TlsConstants.Tls12Version
                ? [TlsProtocolVersion.Tls12]
                : [];
        }
        var extensions = new TlsBinaryReader(reader.ReadVector16());
        reader.EnsureEnd("ClientHello");
        var seen = new HashSet<ushort>();
        while (!extensions.End)
        {
            var type = extensions.ReadUInt16();
            var data = extensions.ReadVector16();
            if (!seen.Add(type))
            {
                throw TlsProtocolException.Illegal(
                    $"ClientHello contains duplicate extension 0x{type:X4}.");
            }
            if (type != (ushort)TlsExtensionType.SupportedVersions)
            {
                continue;
            }
            var versionReader = new TlsBinaryReader(data);
            var encoded = new TlsBinaryReader(versionReader.ReadVector8());
            versionReader.EnsureEnd("supported_versions");
            if (encoded.Remaining < 2 || (encoded.Remaining & 1) != 0)
            {
                throw TlsProtocolException.Decode(
                    "ClientHello supported_versions has an invalid length.");
            }
            var result = new List<TlsProtocolVersion>();
            var values = new HashSet<ushort>();
            while (!encoded.End)
            {
                var value = encoded.ReadUInt16();
                if (!values.Add(value))
                {
                    throw TlsProtocolException.Illegal(
                        "ClientHello supported_versions contains a duplicate.");
                }
                if (value is TlsConstants.Tls13Version or TlsConstants.Tls12Version)
                {
                    result.Add((TlsProtocolVersion)value);
                }
            }
            return [.. result];
        }
        return legacyVersion >= TlsConstants.Tls12Version
            ? [TlsProtocolVersion.Tls12]
            : [];
    }
}

internal static class Tls12ClientHelloParser
{
    internal static Tls12ParsedClientHello Parse(ReadOnlySpan<byte> body)
    {
        var reader = new TlsBinaryReader(body);
        if (reader.ReadUInt16() != TlsConstants.Tls12Version)
        {
            throw new TlsProtocolException(
                TlsAlertDescription.ProtocolVersion,
                "TLS 1.2 ClientHello legacy_version is not 0x0303.");
        }
        var random = reader.ReadBytes(TlsConstants.RandomLength).ToArray();
        var sessionId = reader.ReadVector8(TlsConstants.MaxSessionIdLength).ToArray();
        var cipherSuites = ParseCipherSuites(
            reader.ReadVector16(),
            out var hasSecureRenegotiationScsv);
        var compression = reader.ReadVector8();
        if (!compression.Contains((byte)0))
        {
            throw TlsProtocolException.Illegal(
                "TLS 1.2 ClientHello does not offer null compression.");
        }

        var extensionBytes = reader.End ? ReadOnlySpan<byte>.Empty : reader.ReadVector16();
        reader.EnsureEnd("TLS 1.2 ClientHello");
        var extensions = new TlsBinaryReader(extensionBytes);
        var bodies = new Dictionary<ushort, byte[]>();
        NamedGroup[]? groups = null;
        SignatureScheme[]? signatures = null;
        string[] alpn = [];
        string? serverName = null;
        byte[]? sessionTicket = null;
        var hasEms = false;
        var hasSecureRenegotiation = hasSecureRenegotiationScsv;
        while (!extensions.End)
        {
            var type = extensions.ReadUInt16();
            var data = extensions.ReadVector16();
            if (!bodies.TryAdd(type, data.ToArray()))
            {
                throw TlsProtocolException.Illegal(
                    $"TLS 1.2 ClientHello contains duplicate extension 0x{type:X4}.");
            }
            switch ((TlsExtensionType)type)
            {
                case TlsExtensionType.SupportedGroups:
                    groups = ParseGroups(data);
                    break;
                case TlsExtensionType.SignatureAlgorithms:
                    signatures = ParseSignatures(data);
                    break;
                case TlsExtensionType.ApplicationLayerProtocolNegotiation:
                    alpn = ParseAlpn(data);
                    break;
                case TlsExtensionType.ServerName:
                    serverName = ParseServerName(data);
                    break;
                case TlsExtensionType.SessionTicket:
                    sessionTicket = data.ToArray();
                    break;
                case TlsExtensionType.ExtendedMasterSecret:
                    if (!data.IsEmpty)
                    {
                        throw TlsProtocolException.Illegal(
                            "extended_master_secret must be empty.");
                    }
                    hasEms = true;
                    break;
                case TlsExtensionType.RenegotiationInfo:
                    if (!data.SequenceEqual(new byte[] { 0 }))
                    {
                        throw TlsProtocolException.Illegal(
                            "Initial renegotiation_info is not empty.");
                    }
                    hasSecureRenegotiation = true;
                    break;
            }
        }
        if (!hasEms || !hasSecureRenegotiation)
        {
            throw new TlsProtocolException(
                TlsAlertDescription.HandshakeFailure,
                "TLS 1.2 requires extended master secret and secure renegotiation signaling.");
        }
        if (groups is null || groups.Length == 0 || signatures is null || signatures.Length == 0)
        {
            throw new TlsProtocolException(
                TlsAlertDescription.MissingExtension,
                "TLS 1.2 ECDHE requires supported_groups and signature_algorithms.");
        }
        return new Tls12ParsedClientHello(
            random,
            sessionId,
            cipherSuites,
            groups,
            signatures,
            alpn,
            serverName,
            sessionTicket,
            bodies);
    }

    private static TlsCipherSuite[] ParseCipherSuites(
        ReadOnlySpan<byte> encoded,
        out bool hasSecureRenegotiationScsv)
    {
        if (encoded.Length < 2 || (encoded.Length & 1) != 0)
        {
            throw TlsProtocolException.Decode("TLS 1.2 cipher_suites has an invalid length.");
        }
        var reader = new TlsBinaryReader(encoded);
        var result = new List<TlsCipherSuite>();
        var seen = new HashSet<ushort>();
        hasSecureRenegotiationScsv = false;
        while (!reader.End)
        {
            var value = reader.ReadUInt16();
            if (!seen.Add(value))
            {
                throw TlsProtocolException.Illegal("TLS 1.2 cipher_suites contains a duplicate.");
            }
            if (value == TlsConstants.TlsEmptyRenegotiationInfoScsv)
            {
                hasSecureRenegotiationScsv = true;
                continue;
            }
            if (Enum.IsDefined(typeof(TlsCipherSuite), value))
            {
                result.Add((TlsCipherSuite)value);
            }
        }
        return [.. result];
    }

    private static NamedGroup[] ParseGroups(ReadOnlySpan<byte> data)
    {
        var reader = new TlsBinaryReader(data);
        var values = new TlsBinaryReader(reader.ReadVector16());
        reader.EnsureEnd("supported_groups");
        if (values.Remaining < 2 || (values.Remaining & 1) != 0)
        {
            throw TlsProtocolException.Decode("supported_groups has an invalid length.");
        }
        var result = new List<NamedGroup>();
        var seen = new HashSet<ushort>();
        while (!values.End)
        {
            var value = values.ReadUInt16();
            if (!seen.Add(value))
            {
                throw TlsProtocolException.Illegal("supported_groups contains a duplicate.");
            }
            if (value is (ushort)NamedGroup.X25519 or
                (ushort)NamedGroup.Secp256r1 or
                (ushort)NamedGroup.Secp384r1 or
                (ushort)NamedGroup.Secp521r1)
            {
                result.Add((NamedGroup)value);
            }
        }
        return [.. result];
    }

    private static SignatureScheme[] ParseSignatures(ReadOnlySpan<byte> data)
    {
        var reader = new TlsBinaryReader(data);
        var values = new TlsBinaryReader(reader.ReadVector16());
        reader.EnsureEnd("signature_algorithms");
        if (values.Remaining < 2 || (values.Remaining & 1) != 0)
        {
            throw TlsProtocolException.Decode("signature_algorithms has an invalid length.");
        }
        var result = new List<SignatureScheme>();
        var seen = new HashSet<ushort>();
        while (!values.End)
        {
            var value = values.ReadUInt16();
            if (!seen.Add(value))
            {
                throw TlsProtocolException.Illegal("signature_algorithms contains a duplicate.");
            }
            if (Enum.IsDefined(typeof(SignatureScheme), value))
            {
                result.Add((SignatureScheme)value);
            }
        }
        return [.. result];
    }

    private static string[] ParseAlpn(ReadOnlySpan<byte> data)
    {
        var reader = new TlsBinaryReader(data);
        var values = new TlsBinaryReader(reader.ReadVector16());
        reader.EnsureEnd("ALPN");
        var result = new List<string>();
        while (!values.End)
        {
            var value = values.ReadVector8(TlsConstants.MaxAlpnProtocolLength);
            if (value.IsEmpty || value.IndexOfAnyInRange((byte)0x80, byte.MaxValue) >= 0)
            {
                throw TlsProtocolException.Illegal("ALPN contains an invalid protocol.");
            }
            result.Add(Encoding.ASCII.GetString(value));
        }
        if (result.Count == 0 || result.Distinct(StringComparer.Ordinal).Count() != result.Count)
        {
            throw TlsProtocolException.Illegal("ALPN is empty or contains duplicates.");
        }
        return [.. result];
    }

    private static string ParseServerName(ReadOnlySpan<byte> data)
    {
        var reader = new TlsBinaryReader(data);
        var names = new TlsBinaryReader(reader.ReadVector16());
        reader.EnsureEnd("server_name");
        string? result = null;
        while (!names.End)
        {
            var type = names.ReadUInt8();
            var value = names.ReadVector16();
            if (type != 0)
            {
                continue;
            }
            if (result is not null || value.IsEmpty || value.Contains((byte)0) ||
                value.IndexOfAnyInRange((byte)0x80, byte.MaxValue) >= 0)
            {
                throw TlsProtocolException.Illegal("server_name contains an invalid host_name.");
            }
            result = Encoding.ASCII.GetString(value);
        }
        return result ?? throw TlsProtocolException.Illegal(
            "server_name contains no supported host_name.");
    }
}
