using System.Security.Cryptography.X509Certificates;
using SharpTls.Certificates;

namespace SharpTls;

/// <summary>Controls server X.509 chain and reference-identity validation.</summary>
public sealed class CustomTlsCertificateValidationOptions
{
    /// <summary>
    /// Gets or sets whether server certificate chain and hostname validation are bypassed.
    /// The default is false. Enabling this permits active man-in-the-middle attacks and is
    /// intended only for controlled testing. TLS CertificateVerify and handshake authentication
    /// are still required and validated.
    /// </summary>
    public bool DangerouslySkipServerCertificateValidation { get; set; }

    /// <summary>Gets or sets revocation checking. The secure default is online checking.</summary>
    public X509RevocationMode RevocationMode { get; set; } = X509RevocationMode.Online;

    /// <summary>Gets or sets which certificates are checked for revocation.</summary>
    public X509RevocationFlag RevocationFlag { get; set; } = X509RevocationFlag.ExcludeRoot;

    /// <summary>
    /// Gets or sets whether unavailable revocation evidence may soft-fail after a second
    /// chain build validates every non-revocation requirement. The default is true.
    /// A certificate reported as revoked is never accepted.
    /// </summary>
    public bool AllowUnknownRevocationStatus { get; set; } = true;

    /// <summary>Gets or sets whether Authority Information Access downloads are disabled.</summary>
    public bool DisableCertificateDownloads { get; set; }

    /// <summary>Gets or sets the system chain engine network retrieval timeout.</summary>
    public TimeSpan UrlRetrievalTimeout { get; set; } = TimeSpan.FromSeconds(15);

    /// <summary>
    /// Gets or sets optional trust roots which replace the system root store.
    /// Certificates are cloned when the client is constructed.
    /// </summary>
    public IReadOnlyCollection<X509Certificate2>? CustomTrustRoots { get; set; }

    /// <summary>
    /// Gets or sets an additional async validator for stapled OCSP and handshake-delivered
    /// SCT evidence. It normally runs after chain and hostname validation and cannot override
    /// a validation failure. It remains active when the dangerous built-in bypass is explicit.
    /// </summary>
    public TlsServerCertificateEvidenceValidator? EvidenceValidator { get; set; }

    /// <summary>
    /// Gets or sets whether a cryptographically validated good stapled OCSP response is
    /// mandatory on every full certificate-authenticated handshake.
    /// </summary>
    public bool RequireValidStapledOcspResponse { get; set; }

    /// <summary>
    /// Gets or sets the minimum number of supplied SCT entries the evidence validator must
    /// authenticate against the caller's current CT log policy. Zero disables this requirement.
    /// </summary>
    public int MinimumValidSignedCertificateTimestamps { get; set; }
}
