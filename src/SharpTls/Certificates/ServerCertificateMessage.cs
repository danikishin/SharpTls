using System.Security.Cryptography.X509Certificates;

namespace SharpTls.Certificates;

internal sealed class ServerCertificateMessage : IDisposable
{
    internal ServerCertificateMessage(
        IReadOnlyList<X509Certificate2> certificates,
        Tls13DelegatedCredential? delegatedCredential = null,
        IReadOnlyList<ServerCertificateEntryMetadata>? entries = null)
    {
        Certificates = certificates;
        DelegatedCredential = delegatedCredential;
        Entries = entries ?? certificates.Select(_ => ServerCertificateEntryMetadata.Empty).ToArray();
        if (Entries.Count != Certificates.Count)
        {
            throw new ArgumentException("Certificate metadata must match the certificate chain.", nameof(entries));
        }
    }

    internal IReadOnlyList<X509Certificate2> Certificates { get; }

    internal X509Certificate2 Leaf => Certificates[0];

    internal Tls13DelegatedCredential? DelegatedCredential { get; }

    internal IReadOnlyList<ServerCertificateEntryMetadata> Entries { get; }

    internal byte[]? LeafOcspResponse => Entries[0].OcspResponse;

    internal IReadOnlyList<byte[]> LeafSignedCertificateTimestamps =>
        Entries[0].SignedCertificateTimestamps;

    public void Dispose()
    {
        DelegatedCredential?.Dispose();
        foreach (var certificate in Certificates)
        {
            certificate.Dispose();
        }
    }
}

internal sealed record ServerCertificateEntryMetadata(
    byte[]? OcspResponse,
    IReadOnlyList<byte[]> SignedCertificateTimestamps)
{
    internal static ServerCertificateEntryMetadata Empty { get; } = new(null, Array.Empty<byte[]>());
}
