using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace SharpTls.Tests.Certificates;

internal sealed class TestPki : IDisposable
{
    private TestPki(
        X509Certificate2 root,
        X509Certificate2 leaf,
        AsymmetricAlgorithm leafKey)
    {
        Root = root;
        Leaf = leaf;
        LeafKey = leafKey;
    }

    internal X509Certificate2 Root { get; }
    internal X509Certificate2 Leaf { get; }
    internal AsymmetricAlgorithm LeafKey { get; }

    internal static TestPki Create(
        string dnsName = "example.com",
        bool ecdsaLeaf = false,
        int ecdsaKeySize = 256,
        bool serverAuthenticationEku = true,
        bool delegationUsage = false,
        DateTimeOffset? notBefore = null,
        DateTimeOffset? notAfter = null)
    {
        var rootKey = RSA.Create(2048);
        var rootRequest = new CertificateRequest(
            "CN=SharpTls Test Root",
            rootKey,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1);
        rootRequest.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        rootRequest.CertificateExtensions.Add(new X509KeyUsageExtension(
            X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign,
            true));
        rootRequest.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(rootRequest.PublicKey, false));
        var root = rootRequest.CreateSelfSigned(
            DateTimeOffset.UtcNow.AddDays(-2),
            DateTimeOffset.UtcNow.AddYears(2));
        rootKey.Dispose();

        AsymmetricAlgorithm leafKey;
        CertificateRequest leafRequest;
        if (ecdsaLeaf)
        {
            var curve = ecdsaKeySize switch
            {
                256 => ECCurve.NamedCurves.nistP256,
                384 => ECCurve.NamedCurves.nistP384,
                521 => ECCurve.NamedCurves.nistP521,
                _ => throw new ArgumentOutOfRangeException(nameof(ecdsaKeySize)),
            };
            var ecdsa = ECDsa.Create(curve);
            leafKey = ecdsa;
            var hashAlgorithm = ecdsaKeySize switch
            {
                256 => HashAlgorithmName.SHA256,
                384 => HashAlgorithmName.SHA384,
                521 => HashAlgorithmName.SHA512,
                _ => throw new InvalidOperationException(),
            };
            leafRequest = new CertificateRequest("CN=ignored.example", ecdsa, hashAlgorithm);
        }
        else
        {
            var rsa = RSA.Create(2048);
            leafKey = rsa;
            leafRequest = new CertificateRequest(
                "CN=ignored.example",
                rsa,
                HashAlgorithmName.SHA256,
                RSASignaturePadding.Pkcs1);
        }

        leafRequest.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
        leafRequest.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, true));
        if (delegationUsage)
        {
            leafRequest.CertificateExtensions.Add(new X509Extension(
                new Oid("1.3.6.1.4.1.44363.44"),
                [0x05, 0x00],
                critical: false));
        }
        var eku = new OidCollection();
        eku.Add(new Oid(serverAuthenticationEku
            ? "1.3.6.1.5.5.7.3.1"
            : "1.3.6.1.5.5.7.3.2"));
        leafRequest.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(eku, true));
        var san = new SubjectAlternativeNameBuilder();
        san.AddDnsName(dnsName);
        leafRequest.CertificateExtensions.Add(san.Build());
        leafRequest.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(leafRequest.PublicKey, false));

        using var issuerKey = root.GetRSAPrivateKey() ??
            throw new InvalidOperationException("Test root has no private key.");
        var signatureGenerator = X509SignatureGenerator.CreateForRSA(
            issuerKey,
            RSASignaturePadding.Pkcs1);
        var leaf = leafRequest.Create(
            root.SubjectName,
            signatureGenerator,
            notBefore ?? DateTimeOffset.UtcNow.AddDays(-1),
            notAfter ?? DateTimeOffset.UtcNow.AddDays(30),
            RandomNumberGenerator.GetBytes(16));
        return new TestPki(root, leaf, leafKey);
    }

    public void Dispose()
    {
        Leaf.Dispose();
        Root.Dispose();
        LeafKey.Dispose();
    }
}
