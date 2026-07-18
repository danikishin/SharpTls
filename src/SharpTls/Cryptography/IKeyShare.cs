using SharpTls.Protocol;

namespace SharpTls.Cryptography;

internal interface IKeyShare : IDisposable
{
    NamedGroup Group { get; }

    ReadOnlyMemory<byte> PublicKey { get; }

    byte[] DeriveSharedSecret(ReadOnlySpan<byte> peerKeyExchange);
}
