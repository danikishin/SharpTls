using SharpTls.IO;
using SharpTls.Protocol;

namespace SharpTls.Sessions;

internal sealed record Tls13NewSessionTicketMessage(
    uint LifetimeSeconds,
    uint AgeAdd,
    byte[] Nonce,
    byte[] Identity,
    uint? MaximumEarlyDataSize);

internal static class Tls13NewSessionTicketParser
{
    internal const uint MaximumLifetimeSeconds = 7 * 24 * 60 * 60;

    internal static Tls13NewSessionTicketMessage Parse(ReadOnlySpan<byte> body)
    {
        var reader = new TlsBinaryReader(body);
        var lifetime = reader.ReadUInt32();
        var ageAdd = reader.ReadUInt32();
        var nonce = reader.ReadVector8().ToArray();
        var identity = reader.ReadVector16().ToArray();
        if (identity.Length == 0)
        {
            throw TlsProtocolException.Decode("NewSessionTicket ticket identity is empty.");
        }

        var extensions = new TlsBinaryReader(reader.ReadVector16());
        reader.EnsureEnd("NewSessionTicket");
        var seen = new HashSet<ushort>();
        uint? maximumEarlyDataSize = null;
        while (!extensions.End)
        {
            var type = extensions.ReadUInt16();
            var data = extensions.ReadVector16();
            if (!seen.Add(type))
            {
                throw TlsProtocolException.Illegal(
                    $"NewSessionTicket contains duplicate extension 0x{type:X4}.");
            }

            if (type != (ushort)TlsExtensionType.EarlyData)
            {
                continue;
            }

            var earlyData = new TlsBinaryReader(data);
            maximumEarlyDataSize = earlyData.ReadUInt32();
            earlyData.EnsureEnd("NewSessionTicket early_data");
        }

        return new Tls13NewSessionTicketMessage(
            lifetime,
            ageAdd,
            nonce,
            identity,
            maximumEarlyDataSize);
    }
}
