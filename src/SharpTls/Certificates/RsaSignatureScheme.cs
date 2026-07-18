using System.Formats.Asn1;
using System.Numerics;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace SharpTls.Certificates;

/// <summary>Applies the RSA SubjectPublicKeyInfo constraints attached to TLS schemes.</summary>
internal static class RsaSignatureScheme
{
    internal const string RsaEncryptionOid = "1.2.840.113549.1.1.1";
    internal const string RsaPssOid = "1.2.840.113549.1.1.10";

    private const string Mgf1Oid = "1.2.840.113549.1.1.8";
    private const string Sha1Oid = "1.3.14.3.2.26";
    private const string Sha256Oid = "2.16.840.1.101.3.4.2.1";
    private const string Sha384Oid = "2.16.840.1.101.3.4.2.2";
    private const string Sha512Oid = "2.16.840.1.101.3.4.2.3";

    internal static bool IsCompatible(
        X509Certificate2 certificate,
        Protocol.SignatureScheme scheme)
    {
        var oid = certificate.PublicKey.Oid?.Value;
        return scheme switch
        {
            Protocol.SignatureScheme.RsaPssRsaeSha256 or
            Protocol.SignatureScheme.RsaPssRsaeSha384 or
            Protocol.SignatureScheme.RsaPssRsaeSha512 or
            Protocol.SignatureScheme.RsaPkcs1Sha256 or
            Protocol.SignatureScheme.RsaPkcs1Sha384 or
            Protocol.SignatureScheme.RsaPkcs1Sha512 => oid == RsaEncryptionOid,
            Protocol.SignatureScheme.RsaPssPssSha256 =>
                oid == RsaPssOid && ParametersPermit(
                    certificate.PublicKey.EncodedParameters.RawData, Sha256Oid, 32),
            Protocol.SignatureScheme.RsaPssPssSha384 =>
                oid == RsaPssOid && ParametersPermit(
                    certificate.PublicKey.EncodedParameters.RawData, Sha384Oid, 48),
            Protocol.SignatureScheme.RsaPssPssSha512 =>
                oid == RsaPssOid && ParametersPermit(
                    certificate.PublicKey.EncodedParameters.RawData, Sha512Oid, 64),
            _ => false,
        };
    }

    internal static bool ParametersPermit(
        X509Certificate2 certificate,
        HashAlgorithmName hashAlgorithm) => hashAlgorithm.Name switch
    {
        "SHA256" => ParametersPermit(
            certificate.PublicKey.EncodedParameters.RawData, Sha256Oid, 32),
        "SHA384" => ParametersPermit(
            certificate.PublicKey.EncodedParameters.RawData, Sha384Oid, 48),
        "SHA512" => ParametersPermit(
            certificate.PublicKey.EncodedParameters.RawData, Sha512Oid, 64),
        _ => false,
    };

    internal static RSA? CreatePublicKey(X509Certificate2 certificate)
    {
        if (certificate.PublicKey.Oid?.Value != RsaPssOid)
        {
            return certificate.GetRSAPublicKey();
        }

        try
        {
            return CreatePkcs1PublicKey(certificate.PublicKey.EncodedKeyValue.RawData);
        }
        catch (Exception exception) when (exception is AsnContentException or CryptographicException)
        {
            return null;
        }
    }

    internal static RSA? ImportPssSubjectPublicKeyInfo(
        ReadOnlySpan<byte> subjectPublicKeyInfo,
        Protocol.SignatureScheme scheme)
    {
        try
        {
            var reader = new AsnReader(subjectPublicKeyInfo.ToArray(), AsnEncodingRules.DER);
            var sequence = reader.ReadSequence();
            reader.ThrowIfNotEmpty();
            var algorithm = sequence.ReadSequence();
            if (algorithm.ReadObjectIdentifier() != RsaPssOid)
            {
                return null;
            }
            var parameters = algorithm.HasData
                ? algorithm.ReadEncodedValue()
                : ReadOnlyMemory<byte>.Empty;
            algorithm.ThrowIfNotEmpty();
            var keyValue = sequence.ReadBitString(out var unusedBitCount);
            sequence.ThrowIfNotEmpty();
            if (unusedBitCount != 0 || !ParametersPermit(parameters, scheme))
            {
                return null;
            }
            return CreatePkcs1PublicKey(keyValue);
        }
        catch (Exception exception) when (exception is AsnContentException or CryptographicException)
        {
            return null;
        }
    }

    private static bool ParametersPermit(
        ReadOnlyMemory<byte> encoded,
        Protocol.SignatureScheme scheme) => scheme switch
    {
        Protocol.SignatureScheme.RsaPssPssSha256 =>
            ParametersPermit(encoded, Sha256Oid, 32),
        Protocol.SignatureScheme.RsaPssPssSha384 =>
            ParametersPermit(encoded, Sha384Oid, 48),
        Protocol.SignatureScheme.RsaPssPssSha512 =>
            ParametersPermit(encoded, Sha512Oid, 64),
        _ => false,
    };

    private static bool ParametersPermit(
        ReadOnlyMemory<byte> encoded,
        string requiredHashOid,
        int tlsSaltLength)
    {
        if (encoded.Length == 0)
        {
            // RFC 4055 section 3.3: absent key parameters impose no restrictions.
            return true;
        }

        try
        {
            var reader = new AsnReader(encoded, AsnEncodingRules.DER);
            var sequence = reader.ReadSequence();
            reader.ThrowIfNotEmpty();

            var hashOid = Sha1Oid;
            var maskHashOid = Sha1Oid;
            var minimumSaltLength = 20;
            var trailerField = 1;
            var previousField = -1;
            while (sequence.HasData)
            {
                var tag = sequence.PeekTag();
                if (tag.TagClass != TagClass.ContextSpecific || !tag.IsConstructed ||
                    tag.TagValue is < 0 or > 3 || tag.TagValue <= previousField)
                {
                    return false;
                }
                previousField = tag.TagValue;
                switch (tag.TagValue)
                {
                    case 0:
                        hashOid = ReadHashAlgorithm(sequence, 0);
                        break;
                    case 1:
                        maskHashOid = ReadMaskGenerationAlgorithm(sequence);
                        break;
                    case 2:
                        var saltReader = sequence.ReadSequence(ContextTag(2));
                        if (!saltReader.TryReadInt32(out minimumSaltLength) || saltReader.HasData ||
                            minimumSaltLength < 0)
                        {
                            return false;
                        }
                        break;
                    case 3:
                        var trailerReader = sequence.ReadSequence(ContextTag(3));
                        if (!trailerReader.TryReadInt32(out trailerField) || trailerReader.HasData)
                        {
                            return false;
                        }
                        break;
                }
            }

            return hashOid == requiredHashOid && maskHashOid == requiredHashOid &&
                minimumSaltLength <= tlsSaltLength && trailerField == 1;
        }
        catch (AsnContentException)
        {
            return false;
        }
    }

    private static RSA? CreatePkcs1PublicKey(ReadOnlyMemory<byte> encoded)
    {
        var reader = new AsnReader(encoded, AsnEncodingRules.DER);
        var sequence = reader.ReadSequence();
        reader.ThrowIfNotEmpty();
        var modulus = sequence.ReadInteger();
        var exponent = sequence.ReadInteger();
        sequence.ThrowIfNotEmpty();
        if (modulus.Sign <= 0 || exponent.Sign <= 0 || exponent > uint.MaxValue)
        {
            return null;
        }

        var rsa = RSA.Create();
        try
        {
            rsa.ImportParameters(new RSAParameters
            {
                Modulus = modulus.ToByteArray(isUnsigned: true, isBigEndian: true),
                Exponent = exponent.ToByteArray(isUnsigned: true, isBigEndian: true),
            });
            return rsa;
        }
        catch
        {
            rsa.Dispose();
            throw;
        }
    }

    private static string ReadMaskGenerationAlgorithm(AsnReader sequence)
    {
        var explicitValue = sequence.ReadSequence(ContextTag(1));
        var algorithm = explicitValue.ReadSequence();
        if (algorithm.ReadObjectIdentifier() != Mgf1Oid || !algorithm.HasData)
        {
            throw new AsnContentException();
        }
        var hashAlgorithm = algorithm.ReadSequence();
        algorithm.ThrowIfNotEmpty();
        var result = ReadHashAlgorithm(hashAlgorithm);
        hashAlgorithm.ThrowIfNotEmpty();
        explicitValue.ThrowIfNotEmpty();
        return result;
    }

    private static string ReadHashAlgorithm(AsnReader sequence, int tagValue)
    {
        var explicitValue = sequence.ReadSequence(ContextTag(tagValue));
        var algorithm = explicitValue.ReadSequence();
        explicitValue.ThrowIfNotEmpty();
        return ReadHashAlgorithm(algorithm);
    }

    private static string ReadHashAlgorithm(AsnReader algorithm)
    {
        var oid = algorithm.ReadObjectIdentifier();
        if (algorithm.HasData)
        {
            algorithm.ReadNull();
        }
        algorithm.ThrowIfNotEmpty();
        return oid;
    }

    private static Asn1Tag ContextTag(int value) =>
        new(TagClass.ContextSpecific, value, isConstructed: true);
}
