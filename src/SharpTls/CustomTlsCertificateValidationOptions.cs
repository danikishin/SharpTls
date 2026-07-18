using System.Security.Cryptography.X509Certificates;
using SharpTls.Certificates;

namespace SharpTls;

/// <summary>Controls system X.509 chain validation without allowing validation bypass.</summary>
public sealed class CustomTlsCertificateValidationOptions
{
    /// <summary>Gets or sets revocation checking. The secure default is online checking.</summary>
    public X509RevocationMode RevocationMode { get; set; } = X509RevocationMode.Online;

    /// <summary>Gets or sets which certificates are checked for revocation.</summary>
    public X509RevocationFlag RevocationFlag { get; set; } = X509RevocationFlag.ExcludeRoot;

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
    /// SCT evidence. It runs only after normal chain and hostname validation succeeds and
    /// therefore cannot bypass trust validation.
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
