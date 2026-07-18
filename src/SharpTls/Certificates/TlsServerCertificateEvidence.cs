using SharpTls.Protocol;

namespace SharpTls.Certificates;

/// <summary>Result of caller-supplied validation of authenticated certificate evidence.</summary>
public enum TlsStapledOcspValidationStatus
{
    /// <summary>The validator did not evaluate a staple.</summary>
    NotChecked,
    /// <summary>The staple cryptographically proves a current good status.</summary>
    Good,
    /// <summary>The staple cryptographically proves revocation.</summary>
    Revoked,
    /// <summary>The responder returned an authenticated unknown status.</summary>
    Unknown,
    /// <summary>The response was malformed, stale, mismatched, or cryptographically invalid.</summary>
    Invalid,
}

/// <summary>
/// Immutable defensive input for an additional OCSP/Certificate Transparency policy.
/// Normal chain and hostname validation has already succeeded and cannot be bypassed.
/// </summary>
public sealed class TlsServerCertificateEvidence
{
    private readonly byte[][] _certificateChain;
    private readonly byte[]? _stapledOcspResponse;
    private readonly byte[][] _signedCertificateTimestamps;

    internal TlsServerCertificateEvidence(
        string serverName,
        TlsProtocolVersion protocolVersion,
        IReadOnlyList<byte[]> certificateChain,
        byte[]? stapledOcspResponse,
        IReadOnlyList<byte[]> signedCertificateTimestamps)
    {
        ServerName = serverName;
        ProtocolVersion = protocolVersion;
        _certificateChain = CloneJagged(certificateChain);
        _stapledOcspResponse = stapledOcspResponse is null
            ? null
            : (byte[])stapledOcspResponse.Clone();
        _signedCertificateTimestamps = CloneJagged(signedCertificateTimestamps);
    }

    /// <summary>Gets the certificate reference identity that was already hostname-validated.</summary>
    public string ServerName { get; }

    /// <summary>Gets the negotiated TLS version.</summary>
    public TlsProtocolVersion ProtocolVersion { get; }

    /// <summary>Gets leaf-to-root defensive DER certificate copies.</summary>
    public IReadOnlyList<byte[]> CertificateChain => Array.AsReadOnly(
        CloneJagged(_certificateChain));

    /// <summary>Gets a defensive copy of the stapled OCSP response, or null.</summary>
    public byte[]? StapledOcspResponse => _stapledOcspResponse is null
        ? null
        : (byte[])_stapledOcspResponse.Clone();

    /// <summary>Gets defensive copies of handshake-delivered SCT encodings.</summary>
    public IReadOnlyList<byte[]> SignedCertificateTimestamps => Array.AsReadOnly(
        CloneJagged(_signedCertificateTimestamps));

    private static byte[][] CloneJagged(IReadOnlyList<byte[]> values) => values
        .Select(value => (byte[])value.Clone())
        .ToArray();
}

/// <summary>Validated OCSP and SCT policy output. Counts refer only to supplied SCT entries.</summary>
public sealed record TlsServerCertificateEvidenceValidationResult
{
    /// <summary>Creates a bounded validation result.</summary>
    public TlsServerCertificateEvidenceValidationResult(
        TlsStapledOcspValidationStatus stapledOcspStatus,
        int validSignedCertificateTimestampCount)
    {
        if (!Enum.IsDefined(stapledOcspStatus))
        {
            throw new ArgumentOutOfRangeException(nameof(stapledOcspStatus));
        }
        if (validSignedCertificateTimestampCount < 0)
        {
            throw new ArgumentOutOfRangeException(
                nameof(validSignedCertificateTimestampCount));
        }
        StapledOcspStatus = stapledOcspStatus;
        ValidSignedCertificateTimestampCount = validSignedCertificateTimestampCount;
    }

    /// <summary>Gets the cryptographically determined OCSP status.</summary>
    public TlsStapledOcspValidationStatus StapledOcspStatus { get; }

    /// <summary>Gets the number of supplied SCT entries whose log signatures and policy passed.</summary>
    public int ValidSignedCertificateTimestampCount { get; }
}

/// <summary>
/// Adds deployment-specific OCSP and CT validation after mandatory system X.509 and
/// hostname validation. Completion never overrides a system validation failure.
/// </summary>
public delegate ValueTask<TlsServerCertificateEvidenceValidationResult>
    TlsServerCertificateEvidenceValidator(
        TlsServerCertificateEvidence evidence,
        CancellationToken cancellationToken);
