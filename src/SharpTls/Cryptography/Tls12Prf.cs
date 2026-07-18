using System.Security.Cryptography;
using System.Text;

namespace SharpTls.Cryptography;

internal static class Tls12Prf
{
    private const int MaximumOutputLength = 1 << 20;

    internal static byte[] Expand(
        HashAlgorithmName hashAlgorithm,
        ReadOnlySpan<byte> secret,
        string label,
        ReadOnlySpan<byte> seed,
        int outputLength)
    {
        ArgumentNullException.ThrowIfNull(label);
        if (label.Any(character => character > 0x7F))
        {
            throw new ArgumentException("TLS PRF labels must contain only ASCII characters.", nameof(label));
        }
        if (outputLength is < 0 or > MaximumOutputLength)
        {
            throw new ArgumentOutOfRangeException(nameof(outputLength));
        }
        if (outputLength == 0)
        {
            return [];
        }

        var labelBytes = Encoding.ASCII.GetBytes(label);
        var labelAndSeed = new byte[checked(labelBytes.Length + seed.Length)];
        labelBytes.CopyTo(labelAndSeed, 0);
        seed.CopyTo(labelAndSeed.AsSpan(labelBytes.Length));
        try
        {
            return ExpandCore(hashAlgorithm, secret, labelAndSeed, outputLength);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(labelBytes);
            CryptographicOperations.ZeroMemory(labelAndSeed);
        }
    }

    private static byte[] ExpandCore(
        HashAlgorithmName hashAlgorithm,
        ReadOnlySpan<byte> secret,
        ReadOnlySpan<byte> seed,
        int outputLength)
    {
        var output = new byte[outputLength];
        var a = Hmac(hashAlgorithm, secret, seed);
        var roundInput = new byte[checked(a.Length + seed.Length)];
        var written = 0;
        try
        {
            while (written < output.Length)
            {
                a.CopyTo(roundInput, 0);
                seed.CopyTo(roundInput.AsSpan(a.Length));
                var block = Hmac(hashAlgorithm, secret, roundInput);
                try
                {
                    var copyLength = Math.Min(block.Length, output.Length - written);
                    block.AsSpan(0, copyLength).CopyTo(output.AsSpan(written));
                    written += copyLength;
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(block);
                }

                if (written < output.Length)
                {
                    var nextA = Hmac(hashAlgorithm, secret, a);
                    CryptographicOperations.ZeroMemory(a);
                    a = nextA;
                }
            }

            return output;
        }
        catch
        {
            CryptographicOperations.ZeroMemory(output);
            throw;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(a);
            CryptographicOperations.ZeroMemory(roundInput);
        }
    }

    private static byte[] Hmac(
        HashAlgorithmName hashAlgorithm,
        ReadOnlySpan<byte> key,
        ReadOnlySpan<byte> data) => hashAlgorithm.Name switch
        {
            "SHA256" => HMACSHA256.HashData(key, data),
            "SHA384" => HMACSHA384.HashData(key, data),
            _ => throw new NotSupportedException(
                $"TLS 1.2 PRF hash {hashAlgorithm.Name ?? "<unnamed>"} is not supported."),
        };
}
