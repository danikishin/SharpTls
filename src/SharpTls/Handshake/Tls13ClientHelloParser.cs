using System.Text;
using SharpTls.IO;
using SharpTls.Protocol;

namespace SharpTls.Handshake;

internal sealed record Tls13ParsedClientHello(
    byte[] Random,
    byte[] SessionId,
    TlsCipherSuite[] CipherSuites,
    TlsProtocolVersion[] SupportedVersions,
    NamedGroup[] SupportedGroups,
    SignatureScheme[] SignatureAlgorithms,
    IReadOnlyDictionary<NamedGroup, byte[]> KeyShares,
    string[] AlpnProtocols,
    string? ServerName,
    byte[] PskKeyExchangeModes,
    Tls13OfferedPreSharedKey? OfferedPreSharedKey,
    bool OfferedEarlyData,
    TlsCertificateCompressionAlgorithm[] CertificateCompressionAlgorithms,
    ushort[] ExtensionTypes,
    IReadOnlyDictionary<ushort, byte[]> ExtensionBodies);

internal sealed record Tls13OfferedPskIdentity(
    byte[] Identity,
    uint ObfuscatedTicketAge);

internal sealed record Tls13OfferedPreSharedKey(
    Tls13OfferedPskIdentity[] Identities,
    byte[][] Binders,
    int TruncatedBodyLength);

internal static class Tls13ClientHelloParser
{
    internal static Tls13ParsedClientHello Parse(ReadOnlySpan<byte> body)
    {
        var reader = new TlsBinaryReader(body);
        if (reader.ReadUInt16() != TlsConstants.LegacyRecordVersion)
        {
            throw new TlsProtocolException(
                TlsAlertDescription.ProtocolVersion,
                "ClientHello legacy_version is not 0x0303.");
        }
        var random = reader.ReadBytes(TlsConstants.RandomLength).ToArray();
        var sessionId = reader.ReadVector8(TlsConstants.MaxSessionIdLength).ToArray();
        var cipherSuites = ParseCipherSuites(reader.ReadVector16());
        var compression = reader.ReadVector8();
        if (!compression.SequenceEqual(new byte[] { 0 }))
        {
            throw TlsProtocolException.Illegal(
                "TLS 1.3 ClientHello legacy_compression_methods must contain only null compression.");
        }

        var extensions = new TlsBinaryReader(reader.ReadVector16());
        reader.EnsureEnd("ClientHello");
        var extensionTypes = new List<ushort>();
        var extensionBodies = new Dictionary<ushort, byte[]>();
        TlsProtocolVersion[]? supportedVersions = null;
        NamedGroup[]? supportedGroups = null;
        SignatureScheme[]? signatureAlgorithms = null;
        Dictionary<NamedGroup, byte[]>? keyShares = null;
        string[] alpn = [];
        string? serverName = null;
        byte[] pskKeyExchangeModes = [];
        Tls13OfferedPreSharedKey? offeredPreSharedKey = null;
        var offeredEarlyData = false;
        TlsCertificateCompressionAlgorithm[] certificateCompressionAlgorithms = [];

        while (!extensions.End)
        {
            var type = extensions.ReadUInt16();
            var data = extensions.ReadVector16();
            if (!extensionBodies.TryAdd(type, data.ToArray()))
            {
                throw TlsProtocolException.Illegal(
                    $"ClientHello contains duplicate extension 0x{type:X4}.");
            }
            extensionTypes.Add(type);
            switch ((TlsExtensionType)type)
            {
                case TlsExtensionType.SupportedVersions:
                    supportedVersions = ParseSupportedVersions(data);
                    break;
                case TlsExtensionType.SupportedGroups:
                    supportedGroups = ParseSupportedGroups(data);
                    break;
                case TlsExtensionType.SignatureAlgorithms:
                    signatureAlgorithms = ParseSignatureAlgorithms(data);
                    break;
                case TlsExtensionType.KeyShare:
                    keyShares = ParseKeyShares(data);
                    break;
                case TlsExtensionType.ApplicationLayerProtocolNegotiation:
                    alpn = ParseAlpn(data);
                    break;
                case TlsExtensionType.ServerName:
                    serverName = ParseServerName(data);
                    break;
                case TlsExtensionType.PskKeyExchangeModes:
                    pskKeyExchangeModes = ParsePskKeyExchangeModes(data);
                    break;
                case TlsExtensionType.EarlyData:
                    if (!data.IsEmpty)
                    {
                        throw TlsProtocolException.Decode(
                            "ClientHello early_data extension is not empty.");
                    }
                    offeredEarlyData = true;
                    break;
                case TlsExtensionType.CompressCertificate:
                    certificateCompressionAlgorithms =
                        ParseCertificateCompressionAlgorithms(data);
                    break;
                case TlsExtensionType.PreSharedKey:
                    if (!extensions.End)
                    {
                        throw TlsProtocolException.Illegal(
                            "ClientHello pre_shared_key is not the final extension.");
                    }
                    offeredPreSharedKey = ParsePreSharedKey(data, body.Length);
                    break;
            }
        }

        if (supportedVersions is null ||
            !supportedVersions.Contains(TlsProtocolVersion.Tls13))
        {
            throw new TlsProtocolException(
                TlsAlertDescription.ProtocolVersion,
                "ClientHello does not offer TLS 1.3 in supported_versions.");
        }
        if (supportedGroups is null)
        {
            throw new TlsProtocolException(
                TlsAlertDescription.MissingExtension,
                "TLS 1.3 ClientHello omitted supported_groups.");
        }
        if (signatureAlgorithms is null)
        {
            throw new TlsProtocolException(
                TlsAlertDescription.MissingExtension,
                "TLS 1.3 ClientHello omitted signature_algorithms.");
        }
        keyShares ??= [];
        if (keyShares.Keys.Any(group => !supportedGroups.Contains(group)))
        {
            throw TlsProtocolException.Illegal(
                "ClientHello key_share contains a group absent from supported_groups.");
        }
        if (offeredPreSharedKey is not null && pskKeyExchangeModes.Length == 0)
        {
            throw new TlsProtocolException(
                TlsAlertDescription.MissingExtension,
                "ClientHello offered pre_shared_key without psk_key_exchange_modes.");
        }
        if (offeredEarlyData && offeredPreSharedKey is null)
        {
            throw TlsProtocolException.Illegal(
                "ClientHello offered early_data without pre_shared_key.");
        }

        return new Tls13ParsedClientHello(
            random,
            sessionId,
            cipherSuites,
            supportedVersions,
            supportedGroups,
            signatureAlgorithms,
            keyShares,
            alpn,
            serverName,
            pskKeyExchangeModes,
            offeredPreSharedKey,
            offeredEarlyData,
            certificateCompressionAlgorithms,
            [.. extensionTypes],
            extensionBodies);
    }

    internal static void ValidateRetry(
        Tls13ParsedClientHello first,
        Tls13ParsedClientHello second,
        NamedGroup requestedGroup)
    {
        if (!first.Random.AsSpan().SequenceEqual(second.Random) ||
            !first.SessionId.AsSpan().SequenceEqual(second.SessionId) ||
            !first.CipherSuites.SequenceEqual(second.CipherSuites) ||
            !first.SupportedVersions.SequenceEqual(second.SupportedVersions) ||
            !first.SupportedGroups.SequenceEqual(second.SupportedGroups) ||
            !first.SignatureAlgorithms.SequenceEqual(second.SignatureAlgorithms) ||
            !first.AlpnProtocols.SequenceEqual(second.AlpnProtocols, StringComparer.Ordinal) ||
            !string.Equals(first.ServerName, second.ServerName, StringComparison.Ordinal) ||
            second.KeyShares.Count != 1 || !second.KeyShares.ContainsKey(requestedGroup))
        {
            throw TlsProtocolException.Illegal(
                "Second ClientHello changed fields forbidden by HelloRetryRequest.");
        }

        var ignored = new HashSet<ushort>
        {
            (ushort)TlsExtensionType.KeyShare,
            (ushort)TlsExtensionType.Cookie,
            (ushort)TlsExtensionType.Padding,
            (ushort)TlsExtensionType.PreSharedKey,
            (ushort)TlsExtensionType.EarlyData,
        };
        foreach (var pair in first.ExtensionBodies)
        {
            if (ignored.Contains(pair.Key))
            {
                continue;
            }
            if (!second.ExtensionBodies.TryGetValue(pair.Key, out var secondBody) ||
                !pair.Value.AsSpan().SequenceEqual(secondBody))
            {
                throw TlsProtocolException.Illegal(
                    $"Second ClientHello changed extension 0x{pair.Key:X4}.");
            }
        }
        if (second.ExtensionBodies.Keys.Any(type =>
            !ignored.Contains(type) && !first.ExtensionBodies.ContainsKey(type)))
        {
            throw TlsProtocolException.Illegal(
                "Second ClientHello added an extension not permitted by HelloRetryRequest.");
        }
        if (second.ExtensionBodies.ContainsKey((ushort)TlsExtensionType.EarlyData))
        {
            throw TlsProtocolException.Illegal(
                "Second ClientHello retained early_data after HelloRetryRequest.");
        }
    }

    private static TlsCipherSuite[] ParseCipherSuites(ReadOnlySpan<byte> data)
    {
        if (data.Length < 2 || (data.Length & 1) != 0)
        {
            throw TlsProtocolException.Decode("ClientHello cipher_suites has an invalid length.");
        }
        var reader = new TlsBinaryReader(data);
        var result = new List<TlsCipherSuite>();
        var seen = new HashSet<ushort>();
        while (!reader.End)
        {
            var value = reader.ReadUInt16();
            if (!seen.Add(value))
            {
                throw TlsProtocolException.Illegal("ClientHello contains a duplicate cipher suite.");
            }
            if (Enum.IsDefined(typeof(TlsCipherSuite), value))
            {
                result.Add((TlsCipherSuite)value);
            }
        }
        return [.. result];
    }

    private static TlsProtocolVersion[] ParseSupportedVersions(ReadOnlySpan<byte> data)
    {
        var reader = new TlsBinaryReader(data);
        var values = new TlsBinaryReader(reader.ReadVector8());
        reader.EnsureEnd("supported_versions");
        if (values.Remaining < 2 || (values.Remaining & 1) != 0)
        {
            throw TlsProtocolException.Decode("supported_versions has an invalid length.");
        }
        var result = new List<TlsProtocolVersion>();
        var seen = new HashSet<ushort>();
        while (!values.End)
        {
            var value = values.ReadUInt16();
            if (!seen.Add(value))
            {
                throw TlsProtocolException.Illegal("supported_versions contains a duplicate.");
            }
            if (Enum.IsDefined(typeof(TlsProtocolVersion), value))
            {
                result.Add((TlsProtocolVersion)value);
            }
        }
        return [.. result];
    }

    private static NamedGroup[] ParseSupportedGroups(ReadOnlySpan<byte> data)
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
            if (Enum.IsDefined(typeof(NamedGroup), value))
            {
                result.Add((NamedGroup)value);
            }
        }
        return [.. result];
    }

    private static SignatureScheme[] ParseSignatureAlgorithms(ReadOnlySpan<byte> data)
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
                throw TlsProtocolException.Illegal(
                    "signature_algorithms contains a duplicate.");
            }
            if (Enum.IsDefined(typeof(SignatureScheme), value))
            {
                result.Add((SignatureScheme)value);
            }
        }
        return [.. result];
    }

    private static byte[] ParsePskKeyExchangeModes(ReadOnlySpan<byte> data)
    {
        var reader = new TlsBinaryReader(data);
        var modes = reader.ReadVector8();
        reader.EnsureEnd("psk_key_exchange_modes");
        var result = modes.ToArray();
        if (result.Length is 0 or > 2 || result.Distinct().Count() != result.Length ||
            result.Any(mode => mode is not (0 or 1)))
        {
            throw TlsProtocolException.Illegal(
                "psk_key_exchange_modes is empty, duplicate, or unsupported.");
        }
        return result;
    }

    private static TlsCertificateCompressionAlgorithm[]
        ParseCertificateCompressionAlgorithms(ReadOnlySpan<byte> data)
    {
        var reader = new TlsBinaryReader(data);
        var values = new TlsBinaryReader(reader.ReadVector8());
        reader.EnsureEnd("compress_certificate");
        if (values.Remaining < 2 || (values.Remaining & 1) != 0)
        {
            throw TlsProtocolException.Decode(
                "compress_certificate has an invalid algorithm vector.");
        }

        var result = new List<TlsCertificateCompressionAlgorithm>();
        var seen = new HashSet<ushort>();
        while (!values.End)
        {
            var value = values.ReadUInt16();
            if (!seen.Add(value))
            {
                throw TlsProtocolException.Illegal(
                    "compress_certificate contains a duplicate algorithm.");
            }
            if (value is (ushort)TlsCertificateCompressionAlgorithm.Zlib or
                (ushort)TlsCertificateCompressionAlgorithm.Brotli)
            {
                result.Add((TlsCertificateCompressionAlgorithm)value);
            }
        }
        return [.. result];
    }

    private static Tls13OfferedPreSharedKey ParsePreSharedKey(
        ReadOnlySpan<byte> data,
        int clientHelloBodyLength)
    {
        var reader = new TlsBinaryReader(data);
        var encodedIdentities = reader.ReadVector16();
        var identitiesReader = new TlsBinaryReader(encodedIdentities);
        var identities = new List<Tls13OfferedPskIdentity>();
        while (!identitiesReader.End)
        {
            var identity = identitiesReader.ReadVector16().ToArray();
            var age = identitiesReader.ReadUInt32();
            if (identity.Length == 0 || identities.Count == 64)
            {
                throw TlsProtocolException.Illegal(
                    "pre_shared_key contains an empty identity or too many identities.");
            }
            identities.Add(new Tls13OfferedPskIdentity(identity, age));
        }

        var encodedBinders = reader.ReadVector16();
        var bindersReader = new TlsBinaryReader(encodedBinders);
        var binders = new List<byte[]>();
        while (!bindersReader.End)
        {
            var binder = bindersReader.ReadVector8().ToArray();
            if (binder.Length is < 32 or > 48 || binders.Count == 64)
            {
                throw TlsProtocolException.Illegal(
                    "pre_shared_key contains an invalid binder length or too many binders.");
            }
            binders.Add(binder);
        }
        reader.EnsureEnd("pre_shared_key");
        if (identities.Count == 0 || identities.Count != binders.Count)
        {
            throw TlsProtocolException.Illegal(
                "pre_shared_key identity and binder counts do not match.");
        }

        var encodedBinderVectorLength = checked(2 + encodedBinders.Length);
        var truncatedBodyLength = clientHelloBodyLength - encodedBinderVectorLength;
        if (truncatedBodyLength < 0)
        {
            throw TlsProtocolException.Decode("pre_shared_key binder vector is truncated.");
        }
        return new Tls13OfferedPreSharedKey(
            [.. identities],
            [.. binders],
            truncatedBodyLength);
    }

    private static Dictionary<NamedGroup, byte[]> ParseKeyShares(ReadOnlySpan<byte> data)
    {
        var reader = new TlsBinaryReader(data);
        var entries = new TlsBinaryReader(reader.ReadVector16());
        reader.EnsureEnd("key_share");
        var result = new Dictionary<NamedGroup, byte[]>();
        var seen = new HashSet<ushort>();
        while (!entries.End)
        {
            var value = entries.ReadUInt16();
            var exchange = entries.ReadVector16().ToArray();
            if (exchange.Length == 0 || !seen.Add(value))
            {
                throw TlsProtocolException.Illegal(
                    "key_share contains an empty or duplicate entry.");
            }
            if (Enum.IsDefined(typeof(NamedGroup), value))
            {
                result.Add((NamedGroup)value, exchange);
            }
        }
        return result;
    }

    private static string[] ParseAlpn(ReadOnlySpan<byte> data)
    {
        var reader = new TlsBinaryReader(data);
        var names = new TlsBinaryReader(reader.ReadVector16());
        reader.EnsureEnd("ALPN");
        var result = new List<string>();
        while (!names.End)
        {
            var value = names.ReadVector8(TlsConstants.MaxAlpnProtocolLength);
            if (value.IsEmpty || value.IndexOfAnyInRange((byte)0x80, byte.MaxValue) >= 0)
            {
                throw TlsProtocolException.Illegal("ALPN contains an empty or non-ASCII value.");
            }
            result.Add(Encoding.ASCII.GetString(value));
        }
        if (result.Count == 0 || result.Distinct(StringComparer.Ordinal).Count() != result.Count)
        {
            throw TlsProtocolException.Illegal("ALPN list is empty or contains duplicates.");
        }
        return [.. result];
    }

    private static string ParseServerName(ReadOnlySpan<byte> data)
    {
        var reader = new TlsBinaryReader(data);
        var names = new TlsBinaryReader(reader.ReadVector16());
        reader.EnsureEnd("server_name");
        string? host = null;
        while (!names.End)
        {
            var type = names.ReadUInt8();
            var value = names.ReadVector16();
            if (type != 0)
            {
                continue;
            }
            if (host is not null || value.IsEmpty ||
                value.IndexOfAnyInRange((byte)0x80, byte.MaxValue) >= 0 ||
                value.Contains((byte)0))
            {
                throw TlsProtocolException.Illegal("server_name contains an invalid host_name.");
            }
            host = Encoding.ASCII.GetString(value);
        }
        return host ?? throw TlsProtocolException.Illegal(
            "server_name contains no supported host_name.");
    }
}
