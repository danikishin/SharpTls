using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using SharpTls.IO;
using SharpTls.Protocol;

namespace SharpTls.Certificates;

internal static class Tls12CertificateMessageParser
{
    internal static ServerCertificateMessage Parse(ReadOnlySpan<byte> body, TlsLimits limits)
    {
        ArgumentNullException.ThrowIfNull(limits);
        limits.Validate();
        var reader = new TlsBinaryReader(body);
        var certificateList = reader.ReadVector24(limits.MaxCertificateListSize);
        reader.EnsureEnd("TLS 1.2 Certificate message");
        if (certificateList.IsEmpty)
        {
            throw new TlsProtocolException(
                TlsAlertDescription.BadCertificate,
                "TLS 1.2 server Certificate list is empty.");
        }

        var certificates = new List<X509Certificate2>();
        try
        {
            var entries = new TlsBinaryReader(certificateList);
            while (!entries.End)
            {
                if (certificates.Count >= limits.MaxCertificateCount)
                {
                    throw new TlsProtocolException(
                        TlsAlertDescription.BadCertificate,
                        "TLS 1.2 server sent too many certificates.");
                }

                var der = entries.ReadVector24(limits.MaxCertificateListSize);
                if (der.IsEmpty)
                {
                    throw new TlsProtocolException(
                        TlsAlertDescription.BadCertificate,
                        "TLS 1.2 Certificate entry contains empty DER data.");
                }

                try
                {
                    certificates.Add(X509CertificateLoader.LoadCertificate(der));
                }
                catch (CryptographicException exception)
                {
                    throw new TlsProtocolException(
                        TlsAlertDescription.BadCertificate,
                        "TLS 1.2 Certificate entry is not valid DER X.509 data.",
                        exception);
                }
            }

            return new ServerCertificateMessage(certificates);
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
