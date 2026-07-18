using SharpTls.IO;
using SharpTls.Protocol;

namespace SharpTls.Handshake;

internal static class Tls12CertificateStatusParser
{
    private const byte OcspStatusType = 1;

    internal static byte[] ParseOcspResponse(ReadOnlySpan<byte> body, TlsLimits limits)
    {
        ArgumentNullException.ThrowIfNull(limits);
        limits.Validate();
        var reader = new TlsBinaryReader(body);
        if (reader.ReadUInt8() != OcspStatusType)
        {
            throw new TlsProtocolException(
                TlsAlertDescription.UnsupportedExtension,
                "TLS 1.2 CertificateStatus uses an unsupported status type.");
        }

        var response = reader.ReadVector24(limits.MaxCertificateListSize).ToArray();
        if (response.Length == 0)
        {
            throw TlsProtocolException.Decode("TLS 1.2 CertificateStatus OCSP response is empty.");
        }
        reader.EnsureEnd("TLS 1.2 CertificateStatus");
        return response;
    }
}

internal static class Tls12ServerHelloDoneParser
{
    internal static void Parse(ReadOnlySpan<byte> body)
    {
        if (!body.IsEmpty)
        {
            throw TlsProtocolException.Decode("TLS 1.2 ServerHelloDone must have an empty body.");
        }
    }
}
