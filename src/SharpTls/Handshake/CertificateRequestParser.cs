using SharpTls.IO;
using SharpTls.Protocol;

namespace SharpTls.Handshake;

internal sealed record Tls13CertificateRequest(
    byte[] Context,
    SignatureScheme[] SignatureSchemes,
    SignatureScheme[]? CertificateSignatureSchemes = null,
    SignatureScheme[]? DelegatedCredentialSignatureSchemes = null);

internal static class CertificateRequestParser
{
    internal static Tls13CertificateRequest ParseInitial(ReadOnlySpan<byte> body)
    {
        var request = Parse(body);
        if (request.Context.Length != 0)
        {
            throw TlsProtocolException.Illegal(
                "Initial-handshake CertificateRequest context must be empty.");
        }

        return request;
    }

    internal static Tls13CertificateRequest ParsePostHandshake(ReadOnlySpan<byte> body) =>
        Parse(body);

    private static Tls13CertificateRequest Parse(ReadOnlySpan<byte> body)
    {
        var reader = new TlsBinaryReader(body);
        var context = reader.ReadVector8().ToArray();

        var extensions = new TlsBinaryReader(reader.ReadVector16());
        reader.EnsureEnd("CertificateRequest");
        var seen = new HashSet<ushort>();
        SignatureScheme[]? signatureSchemes = null;
        SignatureScheme[]? certificateSignatureSchemes = null;
        SignatureScheme[]? delegatedCredentialSignatureSchemes = null;
        while (!extensions.End)
        {
            var type = extensions.ReadUInt16();
            var data = extensions.ReadVector16();
            if (!seen.Add(type))
            {
                throw TlsProtocolException.Illegal(
                    $"CertificateRequest contains duplicate extension 0x{type:X4}.");
            }

            if (type == (ushort)TlsExtensionType.SignatureAlgorithms)
            {
                signatureSchemes = ParseSignatureSchemeList(
                    data,
                    "signature_algorithms");
            }
            else if (type == (ushort)TlsExtensionType.SignatureAlgorithmsCert)
            {
                certificateSignatureSchemes = ParseSignatureSchemeList(
                    data,
                    "signature_algorithms_cert");
            }
            else if (type == (ushort)TlsExtensionType.DelegatedCredential)
            {
                delegatedCredentialSignatureSchemes = ParseSignatureSchemeList(
                    data,
                    "delegated_credential");
            }
            else if (Enum.IsDefined(typeof(TlsExtensionType), type) &&
                     !IsAllowedCertificateRequestExtension(type))
            {
                throw TlsProtocolException.Illegal(
                    $"Extension 0x{type:X4} is not allowed in CertificateRequest.");
            }
            // RFC 9846 requires clients to ignore unrecognized CertificateRequest extensions.
        }

        if (signatureSchemes is null)
        {
            throw new TlsProtocolException(
                TlsAlertDescription.MissingExtension,
                "CertificateRequest omitted the required signature_algorithms extension.");
        }

        return new Tls13CertificateRequest(
            context,
            signatureSchemes,
            certificateSignatureSchemes,
            delegatedCredentialSignatureSchemes);
    }

    private static bool IsAllowedCertificateRequestExtension(ushort type) => type is
        (ushort)TlsExtensionType.ServerName or
        (ushort)TlsExtensionType.StatusRequest or
        (ushort)TlsExtensionType.SignatureAlgorithms or
        (ushort)TlsExtensionType.SignatureAlgorithmsCert or
        (ushort)TlsExtensionType.DelegatedCredential;

    private static SignatureScheme[] ParseSignatureSchemeList(
        ReadOnlySpan<byte> data,
        string extensionName)
    {
        var extension = new TlsBinaryReader(data);
        var algorithms = new TlsBinaryReader(extension.ReadVector16());
        extension.EnsureEnd($"CertificateRequest {extensionName}");
        if (algorithms.End || (algorithms.Remaining & 1) != 0)
        {
            throw TlsProtocolException.Decode(
                $"CertificateRequest {extensionName} has an invalid length.");
        }

        var parsed = new List<SignatureScheme>();
        while (!algorithms.End)
        {
            var value = algorithms.ReadUInt16();
            if (Enum.IsDefined(typeof(SignatureScheme), value))
            {
                parsed.Add((SignatureScheme)value);
            }
        }
        return [.. parsed];
    }
}
