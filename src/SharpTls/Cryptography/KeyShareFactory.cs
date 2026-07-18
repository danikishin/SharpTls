using SharpTls.Protocol;

namespace SharpTls.Cryptography;

internal static class KeyShareFactory
{
    internal static IKeyShare Create(NamedGroup group) => group switch
    {
        NamedGroup.X25519 => X25519KeyShare.Create(),
        NamedGroup.X25519MlKem768 => X25519MlKem768KeyShare.Create(),
        NamedGroup.X25519Kyber768Draft00 => X25519Kyber768Draft00KeyShare.Create(),
        _ => EcdheKeyShare.Create(group),
    };

    internal static IKeyShare CreateDeterministicForTesting(NamedGroup group) => group switch
    {
        NamedGroup.X25519 => X25519KeyShare.CreateDeterministicForTesting(),
        NamedGroup.X25519MlKem768 => X25519MlKem768KeyShare.CreateDeterministicForTesting(),
        NamedGroup.X25519Kyber768Draft00 =>
            X25519Kyber768Draft00KeyShare.CreateDeterministicForTesting(),
        _ => EcdheKeyShare.CreateDeterministicForTesting(group),
    };
}
