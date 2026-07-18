using System.Formats.Asn1;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using SharpTls.Certificates;

namespace SharpTls.Tests.Certificates;

internal sealed class RsaPssTestCertificate : IDisposable
{
    private RsaPssTestCertificate(
        X509Certificate2 certificate,
        X509Certificate2 issuer,
        RSA key)
    {
        Certificate = certificate;
        Issuer = issuer;
        Key = key;
    }

    internal X509Certificate2 Certificate { get; }
    internal X509Certificate2 Issuer { get; }
    internal RSA Key { get; }

    internal static RsaPssTestCertificate Create(
        HashAlgorithmName constrainedHash,
        bool serverAuthentication)
    {
        using var issuerPki = TestPki.Create();
        var key = RSA.Create(2048);
        try
        {
            var publicKey = new PublicKey(
                new Oid(RsaSignatureScheme.RsaPssOid),
                new AsnEncodedData(EncodePssParameters(constrainedHash)),
                new AsnEncodedData(EncodeRsaPublicKey(key)));
            var request = new CertificateRequest(
                new X500DistinguishedName("CN=ignored.example"),
                publicKey,
                HashAlgorithmName.SHA256);
            request.CertificateExtensions.Add(
                new X509BasicConstraintsExtension(false, false, 0, critical: true));
            request.CertificateExtensions.Add(new X509KeyUsageExtension(
                X509KeyUsageFlags.DigitalSignature,
                critical: true));
            var eku = new OidCollection
            {
                new(serverAuthentication
                    ? "1.3.6.1.5.5.7.3.1"
                    : "1.3.6.1.5.5.7.3.2"),
            };
            request.CertificateExtensions.Add(
                new X509EnhancedKeyUsageExtension(eku, critical: true));
            var san = new SubjectAlternativeNameBuilder();
            san.AddDnsName("example.com");
            request.CertificateExtensions.Add(san.Build());

            using var issuerKey = issuerPki.Root.GetRSAPrivateKey()!;
            var generator = X509SignatureGenerator.CreateForRSA(
                issuerKey,
                RSASignaturePadding.Pkcs1);
            var certificate = request.Create(
                issuerPki.Root.SubjectName,
                generator,
                DateTimeOffset.UtcNow.AddDays(-1),
                DateTimeOffset.UtcNow.AddDays(7),
                RandomNumberGenerator.GetBytes(16));
            var issuer = X509CertificateLoader.LoadCertificate(issuerPki.Root.RawData);
            return new RsaPssTestCertificate(certificate, issuer, key);
        }
        catch
        {
            key.Dispose();
            throw;
        }
    }

    public void Dispose()
    {
        Certificate.Dispose();
        Issuer.Dispose();
        Key.Dispose();
    }

    private static byte[] EncodeRsaPublicKey(RSA rsa)
    {
        var parameters = rsa.ExportParameters(includePrivateParameters: false);
        var writer = new AsnWriter(AsnEncodingRules.DER);
        writer.PushSequence();
        writer.WriteIntegerUnsigned(parameters.Modulus!);
        writer.WriteIntegerUnsigned(parameters.Exponent!);
        writer.PopSequence();
        return writer.Encode();
    }

    private static byte[] EncodePssParameters(HashAlgorithmName hash)
    {
        var (hashOid, saltLength) = hash.Name switch
        {
            "SHA256" => ("2.16.840.1.101.3.4.2.1", 32),
            "SHA384" => ("2.16.840.1.101.3.4.2.2", 48),
            "SHA512" => ("2.16.840.1.101.3.4.2.3", 64),
            _ => throw new ArgumentOutOfRangeException(nameof(hash)),
        };
        var writer = new AsnWriter(AsnEncodingRules.DER);
        writer.PushSequence();
        WriteExplicitHash(writer, 0, hashOid);

        var maskTag = new Asn1Tag(TagClass.ContextSpecific, 1, isConstructed: true);
        writer.PushSequence(maskTag);
        writer.PushSequence();
        writer.WriteObjectIdentifier("1.2.840.113549.1.1.8");
        WriteHashAlgorithm(writer, hashOid);
        writer.PopSequence();
        writer.PopSequence(maskTag);

        var saltTag = new Asn1Tag(TagClass.ContextSpecific, 2, isConstructed: true);
        writer.PushSequence(saltTag);
        writer.WriteInteger(saltLength);
        writer.PopSequence(saltTag);
        writer.PopSequence();
        return writer.Encode();
    }

    private static void WriteExplicitHash(AsnWriter writer, int tagValue, string hashOid)
    {
        var tag = new Asn1Tag(TagClass.ContextSpecific, tagValue, isConstructed: true);
        writer.PushSequence(tag);
        WriteHashAlgorithm(writer, hashOid);
        writer.PopSequence(tag);
    }

    private static void WriteHashAlgorithm(AsnWriter writer, string hashOid)
    {
        writer.PushSequence();
        writer.WriteObjectIdentifier(hashOid);
        writer.WriteNull();
        writer.PopSequence();
    }
}
