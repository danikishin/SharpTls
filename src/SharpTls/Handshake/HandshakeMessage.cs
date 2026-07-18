using SharpTls.IO;
using SharpTls.Protocol;

namespace SharpTls.Handshake;

internal sealed record HandshakeMessage(HandshakeType Type, byte[] Body, byte[] Encoded)
{
    internal static byte[] Encode(HandshakeType type, ReadOnlySpan<byte> body)
    {
        if (body.Length > 0xFFFFFF)
        {
            throw new ArgumentOutOfRangeException(nameof(body));
        }

        var writer = new TlsBinaryWriter(TlsConstants.HandshakeHeaderLength + body.Length);
        writer.WriteUInt8((byte)type);
        writer.WriteUInt24(body.Length);
        writer.WriteBytes(body);
        return writer.ToArray();
    }
}
