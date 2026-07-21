using System.Security.Cryptography.X509Certificates;

namespace SharpTls.Certificates;

internal sealed record CertificateValidationPolicy(
    X509RevocationMode RevocationMode,
    X509RevocationFlag RevocationFlag,
    bool DisableCertificateDownloads,
    TimeSpan UrlRetrievalTimeout,
    X509Certificate2Collection? CustomTrustRoots,
    TlsServerCertificateEvidenceValidator? EvidenceValidator = null,
    bool RequireValidStapledOcspResponse = false,
    int MinimumValidSignedCertificateTimestamps = 0,
    bool AllowUnknownRevocationStatus = true,
    bool DangerouslySkipServerCertificateValidation = false)
{
    internal static CertificateValidationPolicy SystemDefault { get; } = new(
        X509RevocationMode.Online,
        X509RevocationFlag.ExcludeRoot,
        DisableCertificateDownloads: false,
        TimeSpan.FromSeconds(15),
        CustomTrustRoots: null,
        EvidenceValidator: null,
        RequireValidStapledOcspResponse: false,
        MinimumValidSignedCertificateTimestamps: 0,
        AllowUnknownRevocationStatus: true,
        DangerouslySkipServerCertificateValidation: false);
}
