using System.Security.Cryptography;
using System.Formats.Asn1;
using SharpTls.Cryptography;

namespace SharpTls.Ech;

internal readonly record struct HpkeNistKemParameters(
    ECCurve Curve,
    int CoordinateLength,
    HashAlgorithmName Hash,
    int SharedSecretLength);

internal static class HpkeNistKem
{
    internal static bool IsSupported(TlsHpkeKemId kemId)
    {
        try
        {
            using var key = ECDiffieHellman.Create(GetParameters(kemId).Curve);
            return key.KeySize > 0;
        }
        catch (Exception exception) when (exception is
            CryptographicException or PlatformNotSupportedException)
        {
            return false;
        }
    }

    internal static (byte[] EncapsulatedKey, byte[] Dh) Encapsulate(
        TlsHpkeKemId kemId,
        ReadOnlySpan<byte> receiverPublicKey,
        IRandomSource randomSource)
    {
        ArgumentNullException.ThrowIfNull(randomSource);
        var parameters = GetParameters(kemId);
        Span<byte> ikm = parameters.CoordinateLength <= 128
            ? stackalloc byte[parameters.CoordinateLength]
            : new byte[parameters.CoordinateLength];
        randomSource.Fill(ikm);
        try
        {
            using var ephemeral = DeriveKeyPair(kemId, ikm);
            return EncapsulateCore(kemId, receiverPublicKey, ephemeral);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(ikm);
        }
    }

    internal static (byte[] EncapsulatedKey, byte[] Dh) EncapsulateForTesting(
        TlsHpkeKemId kemId,
        ReadOnlySpan<byte> receiverPublicKey,
        ReadOnlySpan<byte> ephemeralPrivateKey,
        ReadOnlySpan<byte> ephemeralPublicKey)
    {
        var parameters = GetParameters(kemId);
        if (ephemeralPrivateKey.Length != parameters.CoordinateLength)
        {
            throw new ArgumentException(
                "The deterministic NIST HPKE private key has an invalid length.",
                nameof(ephemeralPrivateKey));
        }

        var point = ParsePublicKey(ephemeralPublicKey, parameters);
        var privateCopy = ephemeralPrivateKey.ToArray();
        try
        {
            using var ephemeral = ECDiffieHellman.Create(new ECParameters
            {
                Curve = parameters.Curve,
                D = privateCopy,
                Q = point,
            });
            var actualPublicKey = SerializePublicKey(
                ephemeral.ExportParameters(includePrivateParameters: false),
                parameters.CoordinateLength);
            try
            {
                if (!actualPublicKey.AsSpan().SequenceEqual(ephemeralPublicKey))
                {
                    throw new CryptographicException(
                        "The deterministic NIST HPKE private and public keys do not match.");
                }
            }
            finally
            {
                CryptographicOperations.ZeroMemory(actualPublicKey);
            }
            return EncapsulateCore(kemId, receiverPublicKey, ephemeral);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(privateCopy);
            ZeroPoint(point);
        }
    }

    internal static byte[] Decapsulate(
        TlsHpkeKemId kemId,
        ReadOnlySpan<byte> receiverPrivateKey,
        ReadOnlySpan<byte> receiverPublicKey,
        ReadOnlySpan<byte> encapsulatedKey)
    {
        var parameters = GetParameters(kemId);
        if (receiverPrivateKey.Length != parameters.CoordinateLength)
        {
            throw new ArgumentException(
                "The NIST HPKE receiver private key has an invalid length.",
                nameof(receiverPrivateKey));
        }

        var receiverPoint = ParsePublicKey(receiverPublicKey, parameters);
        var ephemeralPoint = ParsePublicKey(encapsulatedKey, parameters);
        var privateCopy = receiverPrivateKey.ToArray();
        try
        {
            using var receiver = ECDiffieHellman.Create(new ECParameters
            {
                Curve = parameters.Curve,
                D = privateCopy,
                Q = receiverPoint,
            });
            using var ephemeral = ECDiffieHellman.Create(new ECParameters
            {
                Curve = parameters.Curve,
                Q = ephemeralPoint,
            });
            return DeriveRawSecret(receiver, ephemeral.PublicKey, parameters.CoordinateLength);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(privateCopy);
            ZeroPoint(receiverPoint);
            ZeroPoint(ephemeralPoint);
        }
    }

    internal static void ValidatePublicKey(
        TlsHpkeKemId kemId,
        ReadOnlySpan<byte> encoded)
    {
        var parameters = GetParameters(kemId);
        var point = ParsePublicKey(encoded, parameters);
        try
        {
            using var key = ECDiffieHellman.Create(new ECParameters
            {
                Curve = parameters.Curve,
                Q = point,
            });
            _ = key.KeySize;
        }
        finally
        {
            ZeroPoint(point);
        }
    }

    internal static byte[] DerivePublicKey(
        TlsHpkeKemId kemId,
        ReadOnlySpan<byte> privateScalar)
    {
        var parameters = GetParameters(kemId);
        if (privateScalar.Length != parameters.CoordinateLength)
        {
            throw new ArgumentException(
                "The NIST HPKE receiver private key has an invalid length.",
                nameof(privateScalar));
        }
        using var key = ImportPrivateScalar(parameters.Curve, privateScalar);
        return SerializePublicKey(
            key.ExportParameters(includePrivateParameters: false),
            parameters.CoordinateLength);
    }

    internal static HpkeNistKemParameters GetParameters(TlsHpkeKemId kemId) => kemId switch
    {
        TlsHpkeKemId.DhkemP256HkdfSha256 => new(
            ECCurve.NamedCurves.nistP256,
            32,
            HashAlgorithmName.SHA256,
            32),
        TlsHpkeKemId.DhkemP384HkdfSha384 => new(
            ECCurve.NamedCurves.nistP384,
            48,
            HashAlgorithmName.SHA384,
            48),
        TlsHpkeKemId.DhkemP521HkdfSha512 => new(
            ECCurve.NamedCurves.nistP521,
            66,
            HashAlgorithmName.SHA512,
            64),
        _ => throw new NotSupportedException(
            $"HPKE KEM 0x{(ushort)kemId:X4} is not a supported NIST curve."),
    };

    private static ECDiffieHellman DeriveKeyPair(
        TlsHpkeKemId kemId,
        ReadOnlySpan<byte> inputKeyMaterial)
    {
        var parameters = GetParameters(kemId);
        var suiteId = HpkeSenderContext.BuildKemSuiteId(kemId);
        var dkpPrk = HpkeSenderContext.LabeledExtract(
            parameters.Hash,
            [],
            suiteId,
            "dkp_prk",
            inputKeyMaterial);
        var order = GetOrder(kemId);
        var candidate = new byte[parameters.CoordinateLength];
        try
        {
            for (var counter = 0; counter <= byte.MaxValue; counter++)
            {
                var expanded = HpkeSenderContext.LabeledExpand(
                    parameters.Hash,
                    dkpPrk,
                    suiteId,
                    "candidate",
                    [(byte)counter],
                    candidate.Length);
                expanded.CopyTo(candidate, 0);
                CryptographicOperations.ZeroMemory(expanded);

                if (kemId == TlsHpkeKemId.DhkemP521HkdfSha512)
                {
                    candidate[0] &= 0x01;
                }
                if (!IsValidScalar(candidate, order))
                {
                    continue;
                }

                return ImportPrivateScalar(parameters.Curve, candidate);
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(dkpPrk);
            CryptographicOperations.ZeroMemory(candidate);
        }

        throw new CryptographicException(
            "RFC 9180 DeriveKeyPair could not produce a valid NIST private scalar.");
    }

    private static ECDiffieHellman ImportPrivateScalar(
        ECCurve curve,
        ReadOnlySpan<byte> privateScalar)
    {
        if (curve.Oid.Value is null)
        {
            throw new CryptographicException("The NIST curve has no named-curve OID.");
        }

        var writer = new AsnWriter(AsnEncodingRules.DER);
        writer.PushSequence();
        writer.WriteInteger(1);
        writer.WriteOctetString(privateScalar);
        var parametersTag = new Asn1Tag(
            TagClass.ContextSpecific,
            0,
            isConstructed: true);
        writer.PushSequence(parametersTag);
        writer.WriteObjectIdentifier(curve.Oid.Value);
        writer.PopSequence(parametersTag);
        writer.PopSequence();

        var encoded = writer.Encode();
        try
        {
            var key = ECDiffieHellman.Create();
            try
            {
                key.ImportECPrivateKey(encoded, out var bytesRead);
                if (bytesRead != encoded.Length)
                {
                    throw new CryptographicException(
                        "The NIST ECDH provider did not consume the complete private key.");
                }
                return key;
            }
            catch
            {
                key.Dispose();
                throw;
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(encoded);
        }
    }

    private static bool IsValidScalar(
        ReadOnlySpan<byte> candidate,
        ReadOnlySpan<byte> order)
    {
        var nonZero = 0;
        foreach (var value in candidate)
        {
            nonZero |= value;
        }
        if (nonZero == 0 || candidate.Length != order.Length)
        {
            return false;
        }

        for (var index = 0; index < candidate.Length; index++)
        {
            if (candidate[index] < order[index])
            {
                return true;
            }
            if (candidate[index] > order[index])
            {
                return false;
            }
        }
        return false;
    }

    private static byte[] GetOrder(TlsHpkeKemId kemId) => kemId switch
    {
        TlsHpkeKemId.DhkemP256HkdfSha256 => Convert.FromHexString(
            "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551"),
        TlsHpkeKemId.DhkemP384HkdfSha384 => Convert.FromHexString(
            "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC7634D81F4372DDF" +
            "581A0DB248B0A77AECEC196ACCC52973"),
        TlsHpkeKemId.DhkemP521HkdfSha512 => Convert.FromHexString(
            "01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF" +
            "FA51868783BF2F966B7FCC0148F709A5D03BB5C9B8899C47AEBB6FB71E91386409"),
        _ => throw new NotSupportedException(
            $"HPKE KEM 0x{(ushort)kemId:X4} is not a supported NIST curve."),
    };

    private static (byte[] EncapsulatedKey, byte[] Dh) EncapsulateCore(
        TlsHpkeKemId kemId,
        ReadOnlySpan<byte> receiverPublicKey,
        ECDiffieHellman ephemeral)
    {
        var parameters = GetParameters(kemId);
        var receiverPoint = ParsePublicKey(receiverPublicKey, parameters);
        try
        {
            using var receiver = ECDiffieHellman.Create(new ECParameters
            {
                Curve = parameters.Curve,
                Q = receiverPoint,
            });
            var encapsulatedKey = SerializePublicKey(
                ephemeral.ExportParameters(includePrivateParameters: false),
                parameters.CoordinateLength);
            byte[]? dh = null;
            try
            {
                dh = DeriveRawSecret(
                    ephemeral,
                    receiver.PublicKey,
                    parameters.CoordinateLength);
                var result = (encapsulatedKey, dh);
                encapsulatedKey = null!;
                dh = null;
                return result;
            }
            finally
            {
                if (encapsulatedKey is not null)
                {
                    CryptographicOperations.ZeroMemory(encapsulatedKey);
                }
                if (dh is not null)
                {
                    CryptographicOperations.ZeroMemory(dh);
                }
            }
        }
        finally
        {
            ZeroPoint(receiverPoint);
        }
    }

    private static byte[] DeriveRawSecret(
        ECDiffieHellman local,
        ECDiffieHellmanPublicKey peer,
        int expectedLength)
    {
        var secret = local.DeriveRawSecretAgreement(peer);
        if (secret.Length != expectedLength)
        {
            CryptographicOperations.ZeroMemory(secret);
            throw new CryptographicException(
                "The NIST ECDH provider returned a non-canonical shared secret length.");
        }
        return secret;
    }

    private static ECPoint ParsePublicKey(
        ReadOnlySpan<byte> encoded,
        HpkeNistKemParameters parameters)
    {
        if (encoded.Length != 1 + (2 * parameters.CoordinateLength) || encoded[0] != 4)
        {
            throw new CryptographicException(
                "The NIST HPKE public key is not an uncompressed SEC1 point.");
        }
        return new ECPoint
        {
            X = encoded.Slice(1, parameters.CoordinateLength).ToArray(),
            Y = encoded.Slice(1 + parameters.CoordinateLength, parameters.CoordinateLength).ToArray(),
        };
    }

    private static byte[] SerializePublicKey(ECParameters parameters, int coordinateLength)
    {
        if (parameters.Q.X is null || parameters.Q.Y is null ||
            parameters.Q.X.Length > coordinateLength || parameters.Q.Y.Length > coordinateLength)
        {
            throw new CryptographicException(
                "The NIST ECDH provider returned an invalid public point.");
        }

        var result = new byte[1 + (2 * coordinateLength)];
        result[0] = 4;
        parameters.Q.X.CopyTo(result.AsSpan(1 + coordinateLength - parameters.Q.X.Length));
        parameters.Q.Y.CopyTo(result.AsSpan(
            1 + (2 * coordinateLength) - parameters.Q.Y.Length));
        return result;
    }

    private static void ZeroPoint(ECPoint point)
    {
        if (point.X is not null)
        {
            CryptographicOperations.ZeroMemory(point.X);
        }
        if (point.Y is not null)
        {
            CryptographicOperations.ZeroMemory(point.Y);
        }
    }
}
