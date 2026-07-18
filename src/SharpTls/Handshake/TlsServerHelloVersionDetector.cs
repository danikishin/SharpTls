using SharpTls.IO;
using SharpTls.Protocol;

namespace SharpTls.Handshake;

internal static class TlsServerHelloVersionDetector
{
    internal static TlsProtocolVersion Detect(ReadOnlySpan<byte> body)
    {
        var reader = new TlsBinaryReader(body);
        if (reader.ReadUInt16() != TlsConstants.LegacyRecordVersion)
        {
            throw new TlsProtocolException(
                TlsAlertDescription.ProtocolVersion,
                "ServerHello legacy version is not TLS 1.2.");
        }

        _ = reader.ReadBytes(TlsConstants.RandomLength);
        _ = reader.ReadVector8(TlsConstants.MaxSessionIdLength);
        _ = reader.ReadUInt16();
        _ = reader.ReadUInt8();
        if (reader.End)
        {
            return TlsProtocolVersion.Tls12;
        }

        var extensions = new TlsBinaryReader(reader.ReadVector16());
        reader.EnsureEnd("ServerHello");
        var seen = new HashSet<ushort>();
        while (!extensions.End)
        {
            var type = extensions.ReadUInt16();
            var data = extensions.ReadVector16();
            if (!seen.Add(type))
            {
                throw TlsProtocolException.Illegal(
                    $"ServerHello contains duplicate extension 0x{type:X4}.");
            }
            if (type != (ushort)TlsExtensionType.SupportedVersions)
            {
                continue;
            }

            var version = new TlsBinaryReader(data);
            var selected = version.ReadUInt16();
            version.EnsureEnd("ServerHello supported_versions");
            if (selected != TlsConstants.Tls13Version)
            {
                throw TlsProtocolException.Illegal(
                    "A pre-TLS-1.3 ServerHello must not contain supported_versions.");
            }

            return TlsProtocolVersion.Tls13;
        }

        return TlsProtocolVersion.Tls12;
    }
}
