using System.Security.Cryptography.X509Certificates;

namespace SharpTls.Certificates;

internal static class CertificateChainBuilder
{
    private const X509ChainStatusFlags UnavailableRevocationFlags =
        X509ChainStatusFlags.RevocationStatusUnknown |
        X509ChainStatusFlags.OfflineRevocation;

    internal static bool Build(
        X509Chain chain,
        X509Certificate2 certificate,
        CertificateValidationPolicy policy)
    {
        if (chain.Build(certificate))
        {
            return true;
        }

        if (!ShouldRetryWithoutRevocation(policy, chain.ChainStatus))
        {
            return false;
        }

        // The first build performed the configured online/offline lookup. Rebuild without
        // revocation only when every reported failure says that evidence was unavailable.
        // All trust, time, EKU, constraints and signature checks remain enabled.
        chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
        return chain.Build(certificate);
    }

    internal static bool ShouldRetryWithoutRevocation(
        CertificateValidationPolicy policy,
        ReadOnlySpan<X509ChainStatus> statuses) =>
        policy.AllowUnknownRevocationStatus &&
        policy.RevocationMode != X509RevocationMode.NoCheck &&
        ContainsOnlyUnavailableRevocationStatus(statuses);

    internal static bool ContainsOnlyUnavailableRevocationStatus(
        ReadOnlySpan<X509ChainStatus> statuses)
    {
        var foundUnavailableStatus = false;
        foreach (var status in statuses)
        {
            if (status.Status == X509ChainStatusFlags.NoError)
            {
                continue;
            }
            if ((status.Status & ~UnavailableRevocationFlags) != 0)
            {
                return false;
            }
            foundUnavailableStatus = true;
        }
        return foundUnavailableStatus;
    }
}
