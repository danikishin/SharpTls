using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using SharpTls.IO;
using SharpTls.Protocol;

namespace SharpTls.Certificates;

internal static class CertificateMessageParser
{
    internal static ServerCertificateMessage Parse(
        ReadOnlySpan<byte> body,
        TlsLimits limits,
        ClientHelloConfiguration? offer = null)
    {
        ArgumentNullException.ThrowIfNull(limits);
        limits.Validate();
        var reader = new TlsBinaryReader(body);
        var requestContext = reader.ReadVector8();
        if (!requestContext.IsEmpty)
        {
            throw TlsProtocolException.Illegal("Initial server Certificate context must be empty.");
        }

        var certificateList = reader.ReadVector24(limits.MaxCertificateListSize);
        reader.EnsureEnd("Certificate message");
        if (certificateList.IsEmpty)
        {
            throw new TlsProtocolException(
                TlsAlertDescription.BadCertificate,
                "Server Certificate list is empty.");
        }

        var certificates = new List<X509Certificate2>();
        var metadata = new List<ServerCertificateEntryMetadata>();
        Tls13DelegatedCredential? delegatedCredential = null;
        try
        {
            var entries = new TlsBinaryReader(certificateList);
            while (!entries.End)
            {
                if (certificates.Count >= limits.MaxCertificateCount)
                {
                    throw new TlsProtocolException(
                        TlsAlertDescription.BadCertificate,
                        "Server sent too many certificates.");
                }

                var der = entries.ReadVector24(limits.MaxCertificateListSize);
                if (der.IsEmpty)
                {
                    throw new TlsProtocolException(
                        TlsAlertDescription.BadCertificate,
                        "Certificate entry contains empty DER data.");
                }

                try
                {
                    certificates.Add(X509CertificateLoader.LoadCertificate(der));
                }
                catch (CryptographicException exception)
                {
                    throw new TlsProtocolException(
                        TlsAlertDescription.BadCertificate,
                        "Certificate entry is not valid DER X.509 data.",
                        exception);
                }
                var certificateIndex = certificates.Count - 1;

                var certificateExtensions = new TlsBinaryReader(entries.ReadVector16());
                var seenExtensions = new HashSet<ushort>();
                byte[]? ocspResponse = null;
                var signedCertificateTimestamps = new List<byte[]>();
                while (!certificateExtensions.End)
                {
                    var type = certificateExtensions.ReadUInt16();
                    var extensionData = certificateExtensions.ReadVector16();
                    if (!seenExtensions.Add(type))
                    {
                        throw TlsProtocolException.Illegal(
                            $"Certificate entry contains duplicate extension 0x{type:X4}.");
                    }

                    if (!IsExtensionOffered(type, offer))
                    {
                        if (type == (ushort)TlsExtensionType.DelegatedCredential)
                        {
                            throw TlsProtocolException.Unexpected(
                                "Server sent a delegated credential without ClientHello support.");
                        }
                        throw new TlsProtocolException(
                            TlsAlertDescription.UnsupportedExtension,
                            $"Certificate entry contains unoffered extension 0x{type:X4}.");
                    }
                    if (type == (ushort)TlsExtensionType.DelegatedCredential)
                    {
                        if (certificateIndex != 0)
                        {
                            throw TlsProtocolException.Illegal(
                                "A delegated credential appeared on a non-leaf certificate.");
                        }
                        delegatedCredential = Tls13DelegatedCredentialParser.ParseAndValidate(
                            extensionData,
                            certificates[certificateIndex],
                            offer!);
                    }
                    else
                    {
                        ParseCertificateEntryExtension(
                            type,
                            extensionData,
                            ref ocspResponse,
                            signedCertificateTimestamps);
                    }
                }
                metadata.Add(new ServerCertificateEntryMetadata(
                    ocspResponse,
                    signedCertificateTimestamps.AsReadOnly()));
            }

            var result = new ServerCertificateMessage(certificates, delegatedCredential, metadata);
            delegatedCredential = null;
            return result;
        }
        catch
        {
            delegatedCredential?.Dispose();
            foreach (var certificate in certificates)
            {
                certificate.Dispose();
            }
            throw;
        }
    }

    private static bool IsExtensionOffered(ushort type, ClientHelloConfiguration? offer) =>
        offer is not null &&
        (type == (ushort)TlsExtensionType.DelegatedCredential
            ? offer.DelegatedCredentialSignatureAlgorithms is not null
            : offer.ExtensionLayout.Any(extension => extension.RawExtensionType == type));

    private static void ParseCertificateEntryExtension(
        ushort type,
        ReadOnlySpan<byte> data,
        ref byte[]? ocspResponse,
        List<byte[]> signedCertificateTimestamps)
    {
        switch (type)
        {
            case 5: // status_request
                var status = new TlsBinaryReader(data);
                if (status.ReadUInt8() != 1)
                {
                    throw TlsProtocolException.Decode(
                        "Certificate status_request does not contain a non-empty OCSP response.");
                }
                ocspResponse = status.ReadVector24().ToArray();
                if (ocspResponse.Length == 0)
                {
                    throw TlsProtocolException.Decode(
                        "Certificate status_request does not contain a non-empty OCSP response.");
                }
                status.EnsureEnd("Certificate status_request");
                break;

            case 18: // signed_certificate_timestamp
                var sct = new TlsBinaryReader(data);
                var entries = new TlsBinaryReader(sct.ReadVector16());
                sct.EnsureEnd("Certificate SCT extension");
                if (entries.End)
                {
                    throw TlsProtocolException.Decode("Certificate SCT list is empty.");
                }
                while (!entries.End)
                {
                    var encodedSct = entries.ReadVector16().ToArray();
                    if (encodedSct.Length == 0)
                    {
                        throw TlsProtocolException.Decode("Certificate SCT entry is empty.");
                    }
                    signedCertificateTimestamps.Add(encodedSct);
                }
                break;

            default:
                throw new TlsProtocolException(
                    TlsAlertDescription.UnsupportedExtension,
                    $"Certificate entry extension 0x{type:X4} has no implemented semantics.");
        }
    }
}
