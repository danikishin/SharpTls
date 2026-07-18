using SharpTls.IO;
using SharpTls.Protocol;

namespace SharpTls.Handshake;

internal static class Tls13ApplicationSettings
{
    internal static byte[] CreateClientEncryptedExtensions(
        TlsApplicationSettingsCodePoint codePoint,
        ReadOnlySpan<byte> settings)
    {
        var extensions = new TlsBinaryWriter();
        extensions.WriteUInt16((ushort)codePoint);
        extensions.WriteVector16(settings);

        var body = new TlsBinaryWriter();
        body.WriteVector16(extensions.WrittenSpan);
        return HandshakeMessage.Encode(HandshakeType.EncryptedExtensions, body.WrittenSpan);
    }
}
