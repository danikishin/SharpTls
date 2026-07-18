using System.Buffers.Binary;
using System.Net;
using System.Text;
using SharpTls.Protocol;

namespace SharpTls.Dns;

internal enum DnsSvcParameterKey : ushort
{
    Mandatory = 0,
    Alpn = 1,
    NoDefaultAlpn = 2,
    Port = 3,
    Ipv4Hint = 4,
    Ech = 5,
    Ipv6Hint = 6,
}

internal sealed record DnsServiceBinding(
    DnsHttpsRecord WireRecord,
    bool IsCompatible,
    string TargetName,
    int Port,
    byte[][] AlpnProtocolIds,
    string[] AlpnProtocols,
    bool HasNoDefaultAlpn,
    IPAddress[] Ipv4Hints,
    IPAddress[] Ipv6Hints,
    TlsEchConfigList? EchConfigList,
    bool HasEchParameter,
    bool HasExecutableEch);

internal static class DnsServiceBindingParser
{
    private static readonly HashSet<ushort> SupportedKeys =
    [
        (ushort)DnsSvcParameterKey.Mandatory,
        (ushort)DnsSvcParameterKey.Alpn,
        (ushort)DnsSvcParameterKey.NoDefaultAlpn,
        (ushort)DnsSvcParameterKey.Port,
        (ushort)DnsSvcParameterKey.Ipv4Hint,
        (ushort)DnsSvcParameterKey.Ech,
        (ushort)DnsSvcParameterKey.Ipv6Hint,
    ];

    internal static string ParseAliasTarget(DnsHttpsRecord record)
    {
        if (record.Priority != 0)
        {
            throw new ArgumentException("The HTTPS record is not in AliasMode.", nameof(record));
        }
        if (record.TargetName != ".")
        {
            ValidateTarget(record.TargetName);
        }
        return record.TargetName;
    }

    internal static DnsServiceBinding ParseService(
        DnsHttpsRecord record,
        int defaultPort)
    {
        if (record.Priority == 0)
        {
            throw new ArgumentException("The HTTPS record is not in ServiceMode.", nameof(record));
        }

        var parameters = record.Parameters.ToDictionary(parameter => parameter.Key);
        var mandatoryKeys = ParseMandatory(parameters);
        var compatible = mandatoryKeys.All(SupportedKeys.Contains);

        var targetName = record.TargetName == "." ? record.Owner : record.TargetName;
        ValidateTarget(targetName, allowHttpsPortPrefix: record.TargetName == ".");
        var port = defaultPort;
        var alpnProtocolIds = Array.Empty<byte[]>();
        var noDefaultAlpn = false;
        var ipv4Hints = Array.Empty<IPAddress>();
        var ipv6Hints = Array.Empty<IPAddress>();
        TlsEchConfigList? echConfigList = null;
        var hasEchParameter = false;

        foreach (var parameter in record.Parameters)
        {
            switch ((DnsSvcParameterKey)parameter.Key)
            {
                case DnsSvcParameterKey.Mandatory:
                    break;
                case DnsSvcParameterKey.Alpn:
                    alpnProtocolIds = ParseAlpn(parameter.Value);
                    break;
                case DnsSvcParameterKey.NoDefaultAlpn:
                    if (parameter.Value.Length != 0)
                    {
                        throw TlsEchDnsException.MalformedServiceBinding(
                            "The no-default-alpn SVCB parameter must have an empty value.");
                    }
                    noDefaultAlpn = true;
                    break;
                case DnsSvcParameterKey.Port:
                    if (parameter.Value.Length != 2)
                    {
                        throw TlsEchDnsException.MalformedServiceBinding(
                            "The port SVCB parameter must contain exactly two octets.");
                    }
                    port = BinaryPrimitives.ReadUInt16BigEndian(parameter.Value);
                    if (port == 0)
                    {
                        // Zero is a valid wire value, but no TCP connection can succeed on it.
                        // HTTPS declares port automatically mandatory, so the RR is incompatible.
                        compatible = false;
                    }
                    break;
                case DnsSvcParameterKey.Ipv4Hint:
                    ipv4Hints = ParseAddressHints(parameter.Value, 4, System.Net.Sockets.AddressFamily.InterNetwork);
                    break;
                case DnsSvcParameterKey.Ech:
                    hasEchParameter = true;
                    try
                    {
                        echConfigList = TlsEchConfigList.Parse(parameter.Value);
                    }
                    catch (TlsProtocolException exception)
                    {
                        throw new TlsEchDnsException(
                            TlsEchDnsErrorKind.MalformedServiceBinding,
                            "The ech SVCB parameter is not a valid ECHConfigList.",
                            exception);
                    }
                    break;
                case DnsSvcParameterKey.Ipv6Hint:
                    ipv6Hints = ParseAddressHints(parameter.Value, 16, System.Net.Sockets.AddressFamily.InterNetworkV6);
                    break;
                default:
                    // Unknown optional keys are ignored. Unknown mandatory keys made the RR incompatible above.
                    break;
            }
        }

        if (noDefaultAlpn && !parameters.ContainsKey((ushort)DnsSvcParameterKey.Alpn))
        {
            compatible = false;
        }

        if (!noDefaultAlpn && !alpnProtocolIds.Any(protocol =>
                protocol.AsSpan().SequenceEqual("http/1.1"u8)))
        {
            alpnProtocolIds = [.. alpnProtocolIds, "http/1.1"u8.ToArray()];
        }
        var alpnProtocols = alpnProtocolIds
            .Where(protocol => protocol.All(value => value <= 0x7F))
            .Select(Encoding.ASCII.GetString)
            .ToArray();

        var hasExecutableEch = echConfigList?.SelectSupportedConfiguration() is not null;
        if (hasEchParameter &&
            mandatoryKeys.Contains((ushort)DnsSvcParameterKey.Ech) &&
            !hasExecutableEch)
        {
            compatible = false;
        }

        return new DnsServiceBinding(
            record,
            compatible,
            targetName,
            port,
            alpnProtocolIds,
            alpnProtocols,
            noDefaultAlpn,
            ipv4Hints,
            ipv6Hints,
            echConfigList,
            hasEchParameter,
            hasExecutableEch);
    }

    private static HashSet<ushort> ParseMandatory(
        IReadOnlyDictionary<ushort, DnsSvcParameter> parameters)
    {
        if (!parameters.TryGetValue((ushort)DnsSvcParameterKey.Mandatory, out var mandatory))
        {
            return [];
        }
        if (mandatory.Value.Length == 0 || (mandatory.Value.Length & 1) != 0)
        {
            throw TlsEchDnsException.MalformedServiceBinding(
                "The mandatory SVCB parameter must contain a non-empty uint16 list.");
        }

        var result = new HashSet<ushort>();
        var previous = -1;
        for (var offset = 0; offset < mandatory.Value.Length; offset += 2)
        {
            var key = BinaryPrimitives.ReadUInt16BigEndian(mandatory.Value.AsSpan(offset, 2));
            if (key == (ushort)DnsSvcParameterKey.Mandatory || key <= previous ||
                !parameters.ContainsKey(key))
            {
                throw TlsEchDnsException.MalformedServiceBinding(
                    "The mandatory SVCB list is unsorted, self-referential, or names an absent key.");
            }
            result.Add(key);
            previous = key;
        }
        return result;
    }

    private static byte[][] ParseAlpn(byte[] value)
    {
        if (value.Length == 0)
        {
            throw TlsEchDnsException.MalformedServiceBinding(
                "The alpn SVCB parameter cannot be empty.");
        }

        var protocols = new List<byte[]>();
        var encodedProtocols = new HashSet<string>(StringComparer.Ordinal);
        for (var offset = 0; offset < value.Length;)
        {
            var length = value[offset++];
            if (length == 0 || value.Length - offset < length)
            {
                throw TlsEchDnsException.MalformedServiceBinding(
                    "The alpn SVCB parameter contains an empty or truncated protocol identifier.");
            }

            var protocolBytes = value.AsSpan(offset, length);
            var encoded = Convert.ToHexString(protocolBytes);
            if (encodedProtocols.Add(encoded))
            {
                protocols.Add(protocolBytes.ToArray());
            }
            offset += length;
        }
        return protocols.ToArray();
    }

    private static IPAddress[] ParseAddressHints(
        byte[] value,
        int addressLength,
        System.Net.Sockets.AddressFamily family)
    {
        if (value.Length == 0 || value.Length % addressLength != 0)
        {
            throw TlsEchDnsException.MalformedServiceBinding(
                "An IP hint SVCB parameter has an invalid vector length.");
        }

        var result = new List<IPAddress>();
        for (var offset = 0; offset < value.Length; offset += addressLength)
        {
            var address = new IPAddress(value.AsSpan(offset, addressLength));
            if (address.AddressFamily != family)
            {
                throw TlsEchDnsException.MalformedServiceBinding(
                    "An IP hint SVCB parameter contains an invalid address.");
            }
            result.Add(address);
        }
        return result.ToArray();
    }

    private static void ValidateTarget(
        string targetName,
        bool allowHttpsPortPrefix = false)
    {
        try
        {
            DnsNames.ValidateHostName(targetName, nameof(targetName));
        }
        catch (ArgumentException exception)
        {
            if (allowHttpsPortPrefix && IsHttpsPortPrefixedName(targetName))
            {
                return;
            }
            throw new TlsEchDnsException(
                TlsEchDnsErrorKind.MalformedServiceBinding,
                "An HTTPS/SVCB target is not a valid hostname.",
                exception);
        }
    }

    private static bool IsHttpsPortPrefixedName(string name)
    {
        var labels = name.Split('.');
        if (labels.Length < 4 || labels[0].Length < 2 || labels[0][0] != '_' ||
            !ushort.TryParse(labels[0].AsSpan(1), out var port) || port == 0 ||
            !string.Equals(labels[1], "_https", StringComparison.Ordinal))
        {
            return false;
        }

        try
        {
            DnsNames.ValidateHostName(string.Join('.', labels[2..]), nameof(name));
            return true;
        }
        catch (ArgumentException)
        {
            return false;
        }
    }
}
