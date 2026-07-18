using SharpTls.Protocol;

namespace SharpTls.Certificates;

/// <summary>
/// Signs pre-hashed TLS CertificateVerify inputs using a runtime, HSM, smart-card,
/// remote KMS, or other caller-owned private-key provider.
/// </summary>
public interface ITlsClientCertificateSigner
{
    /// <summary>Gets the exact TLS signature schemes this signer can execute.</summary>
    IReadOnlyCollection<SignatureScheme> SupportedSignatureSchemes { get; }

    /// <summary>
    /// Exports only the public SubjectPublicKeyInfo DER used to bind this signer to
    /// the configured leaf certificate. Private key material must never be returned.
    /// </summary>
    byte[] ExportSubjectPublicKeyInfo();

    /// <summary>
    /// Signs an already-hashed CertificateVerify input. The returned signature uses
    /// RFC 3279 DER encoding for ECDSA and the scheme-selected padding for RSA.
    /// </summary>
    ValueTask<byte[]> SignHashAsync(
        SignatureScheme scheme,
        ReadOnlyMemory<byte> hash,
        CancellationToken cancellationToken = default);
}

/// <summary>Immutable input for dynamic client-certificate selection.</summary>
public sealed class TlsClientCertificateSelectionContext
{
    private readonly SignatureScheme[] _signatureSchemes;
    private readonly SignatureScheme[] _delegatedCredentialSignatureSchemes;
    private readonly byte[] _certificateTypes;

    internal TlsClientCertificateSelectionContext(
        string serverName,
        TlsProtocolVersion protocolVersion,
        bool isPostHandshake,
        IReadOnlyList<SignatureScheme> signatureSchemes,
        IReadOnlyList<SignatureScheme>? delegatedCredentialSignatureSchemes,
        ReadOnlySpan<byte> certificateTypes)
    {
        ServerName = serverName;
        ProtocolVersion = protocolVersion;
        IsPostHandshake = isPostHandshake;
        _signatureSchemes = signatureSchemes.ToArray();
        _delegatedCredentialSignatureSchemes =
            delegatedCredentialSignatureSchemes?.ToArray() ?? [];
        _certificateTypes = certificateTypes.ToArray();
    }

    /// <summary>Gets the authenticated reference identity for this connection.</summary>
    public string ServerName { get; }

    /// <summary>Gets the active TLS protocol version.</summary>
    public TlsProtocolVersion ProtocolVersion { get; }

    /// <summary>Gets whether this is a TLS 1.3 post-handshake request.</summary>
    public bool IsPostHandshake { get; }

    /// <summary>Gets the peer's exact signature-scheme preference order.</summary>
    public IReadOnlyList<SignatureScheme> SignatureSchemes =>
        Array.AsReadOnly((SignatureScheme[])_signatureSchemes.Clone());

    /// <summary>
    /// Gets the RFC 9345 delegated-key algorithms advertised by a TLS 1.3
    /// CertificateRequest, or an empty list when delegated credentials are unavailable.
    /// </summary>
    public IReadOnlyList<SignatureScheme> DelegatedCredentialSignatureSchemes =>
        Array.AsReadOnly(
            (SignatureScheme[])_delegatedCredentialSignatureSchemes.Clone());

    /// <summary>Gets TLS 1.2 certificate_type values, or an empty list for TLS 1.3.</summary>
    public IReadOnlyList<byte> CertificateTypes =>
        Array.AsReadOnly((byte[])_certificateTypes.Clone());
}

/// <summary>Selects a caller-owned client credential for one certificate request.</summary>
public delegate ValueTask<TlsClientCertificate?> TlsClientCertificateSelector(
    TlsClientCertificateSelectionContext context,
    CancellationToken cancellationToken);
