using SharpTls.Certificates;

namespace SharpTls.Tests.Certificates;

public sealed class TlsServerCertificatePresentationTests
{
    [Fact]
    public void EmptyEvidenceValuesAreRejected()
    {
        Assert.Throws<ArgumentException>(() =>
            new TlsServerCertificatePresentation(ReadOnlyMemory<byte>.Empty));
        Assert.Throws<ArgumentException>(() =>
            new TlsServerCertificatePresentation(
                signedCertificateTimestamps: [Array.Empty<byte>()]));
    }

    [Fact]
    public void CredentialOwnsDefensiveEvidenceSnapshots()
    {
        using var pki = TestPki.Create();
        byte[] ocsp = [1, 2, 3];
        byte[] sct = [4, 5, 6];
        var presentation = new TlsServerCertificatePresentation(ocsp, [sct]);
        using var credential = new TlsServerCertificate(
            pki.Leaf,
            (System.Security.Cryptography.RSA)pki.LeafKey,
            [pki.Root],
            presentation);
        ocsp[0] = 0xFF;
        sct[0] = 0xFF;

        Assert.Equal(new byte[] { 1, 2, 3 }, credential.CopyStapledOcspResponse());
        Assert.Equal(new byte[] { 4, 5, 6 },
            Assert.Single(credential.CopySignedCertificateTimestamps()));
        Assert.True(credential.HasStapledOcspResponse);
        Assert.True(credential.HasSignedCertificateTimestamps);
    }
}
