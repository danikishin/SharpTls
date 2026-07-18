using System.Security.Cryptography;
using System.Text;
using SharpTls.IO;
using SharpTls.Protocol;

namespace SharpTls.Cryptography;

internal static class Tls13Hkdf
{
    private static ReadOnlySpan<byte> LabelPrefix => "tls13 "u8;

    internal static byte[] Extract(
        HashAlgorithmName hashAlgorithm,
        ReadOnlySpan<byte> inputKeyMaterial,
        ReadOnlySpan<byte> salt)
    {
        var inputCopy = inputKeyMaterial.ToArray();
        var saltCopy = salt.ToArray();
        try
        {
            return HKDF.Extract(hashAlgorithm, inputCopy, saltCopy);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(inputCopy);
            CryptographicOperations.ZeroMemory(saltCopy);
        }
    }

    internal static byte[] ExpandLabel(
        HashAlgorithmName hashAlgorithm,
        ReadOnlySpan<byte> secret,
        string label,
        ReadOnlySpan<byte> context,
        int outputLength)
    {
        ArgumentException.ThrowIfNullOrEmpty(label);
        if (outputLength is < 0 or > ushort.MaxValue)
        {
            throw new ArgumentOutOfRangeException(nameof(outputLength));
        }

        var labelBytes = Encoding.ASCII.GetBytes(label);
        if (labelBytes.Any(value => value > 0x7F) ||
            labelBytes.Length + LabelPrefix.Length > byte.MaxValue ||
            context.Length > byte.MaxValue)
        {
            throw new ArgumentOutOfRangeException(nameof(label));
        }

        var fullLabel = new byte[LabelPrefix.Length + labelBytes.Length];
        LabelPrefix.CopyTo(fullLabel);
        labelBytes.CopyTo(fullLabel.AsSpan(LabelPrefix.Length));

        var info = new TlsBinaryWriter();
        info.WriteUInt16((ushort)outputLength);
        info.WriteVector8(fullLabel);
        info.WriteVector8(context);

        var output = new byte[outputLength];
        HKDF.Expand(hashAlgorithm, secret, output, info.WrittenSpan);
        return output;
    }

    internal static byte[] Expand(
        HashAlgorithmName hashAlgorithm,
        ReadOnlySpan<byte> pseudorandomKey,
        ReadOnlySpan<byte> info,
        int outputLength)
    {
        if (outputLength < 0)
        {
            throw new ArgumentOutOfRangeException(nameof(outputLength));
        }

        var output = new byte[outputLength];
        HKDF.Expand(hashAlgorithm, pseudorandomKey, output, info);
        return output;
    }

    internal static byte[] DeriveSecret(
        CipherSuiteInfo suite,
        ReadOnlySpan<byte> secret,
        string label,
        ReadOnlySpan<byte> transcriptHash) =>
        ExpandLabel(suite.HashAlgorithm, secret, label, transcriptHash, suite.HashLength);
}
