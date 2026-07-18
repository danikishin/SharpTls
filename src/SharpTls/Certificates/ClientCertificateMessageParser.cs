using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using SharpTls.IO;
using SharpTls.Protocol;

namespace SharpTls.Certificates;

internal sealed class ClientCertificateMessage : IDisposable
{
    internal ClientCertificateMessage(IReadOnlyList<X509Certificate2> certificates)
    {
        Certificates = certificates;
    }

    internal IReadOnlyList<X509Certificate2> Certificates { get; }
    internal X509Certificate2? Leaf => Certificates.Count == 0 ? null : Certificates[0];

    public void Dispose()
    {
        foreach (var certificate in Certificates)
        {
            certificate.Dispose();
        }
    }
}

internal static class ClientCertificateMessageParser
{
    internal static ClientCertificateMessage ParseTls12(
        ReadOnlySpan<byte> body,
        TlsLimits limits)
    {
        var reader = new TlsBinaryReader(body);
        var list = reader.ReadVector24(limits.MaxCertificateListSize);
        reader.EnsureEnd("TLS 1.2 client Certificate");
        var certificates = new List<X509Certificate2>();
        try
        {
            var entries = new TlsBinaryReader(list);
            while (!entries.End)
            {
                if (certificates.Count == limits.MaxCertificateCount)
                {
                    throw new TlsProtocolException(
                        TlsAlertDescription.BadCertificate,
                        "TLS 1.2 client certificate count exceeds the configured limit.");
                }
                var der = entries.ReadVector24(limits.MaxCertificateListSize);
                if (der.IsEmpty)
                {
                    throw new TlsProtocolException(
                        TlsAlertDescription.BadCertificate,
                        "TLS 1.2 client certificate contains empty DER.");
                }
                try
                {
                    certificates.Add(X509CertificateLoader.LoadCertificate(der));
                }
                catch (CryptographicException exception)
                {
                    throw new TlsProtocolException(
                        TlsAlertDescription.BadCertificate,
                        "TLS 1.2 client certificate contains invalid DER X.509.",
                        exception);
                }
            }
            return new ClientCertificateMessage(certificates);
        }
        catch
        {
            foreach (var certificate in certificates)
            {
                certificate.Dispose();
            }
            throw;
        }
    }

    internal static ClientCertificateMessage Parse(
        ReadOnlySpan<byte> body,
        TlsLimits limits)
    {
        var reader = new TlsBinaryReader(body);
        var context = reader.ReadVector8();
        if (!context.IsEmpty)
        {
            throw TlsProtocolException.Illegal(
                "Initial client Certificate context must be empty.");
        }
        var list = reader.ReadVector24(limits.MaxCertificateListSize);
        reader.EnsureEnd("client Certificate");
        var certificates = new List<X509Certificate2>();
        try
        {
            var entries = new TlsBinaryReader(list);
            while (!entries.End)
            {
                if (certificates.Count == limits.MaxCertificateCount)
                {
                    throw new TlsProtocolException(
                        TlsAlertDescription.BadCertificate,
                        "Client certificate count exceeds the configured limit.");
                }
                var der = entries.ReadVector24(limits.MaxCertificateListSize);
                if (der.IsEmpty)
                {
                    throw new TlsProtocolException(
                        TlsAlertDescription.BadCertificate,
                        "Client certificate entry contains empty DER.");
                }
                try
                {
                    certificates.Add(X509CertificateLoader.LoadCertificate(der));
                }
                catch (CryptographicException exception)
                {
                    throw new TlsProtocolException(
                        TlsAlertDescription.BadCertificate,
                        "Client certificate entry is invalid DER X.509.",
                        exception);
                }
                var extensions = new TlsBinaryReader(entries.ReadVector16());
                if (!extensions.End)
                {
                    throw new TlsProtocolException(
                        TlsAlertDescription.UnsupportedExtension,
                        "Client CertificateEntry extensions were not requested.");
                }
            }
            return new ClientCertificateMessage(certificates);
        }
        catch
        {
            foreach (var certificate in certificates)
            {
                certificate.Dispose();
            }
            throw;
        }
    }
}
