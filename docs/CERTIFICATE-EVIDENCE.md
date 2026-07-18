# OCSP and certificate-transparency policy

SharpTls always performs normal X.509 chain, server-auth EKU, revocation-mode and
hostname validation. An evidence callback is an additional fail-closed policy gate; it
cannot accept a chain or identity that the system validator rejected.

TLS 1.3 `status_request` and RFC 6962 SCT values are parsed from the leaf
CertificateEntry. TLS 1.2 CertificateStatus and ServerHello SCT values are parsed in
their version-specific positions. Framing is bounded and malformed, duplicate,
unoffered, empty or context-invalid values abort the handshake.

Deployments that maintain an OCSP responder policy or Certificate Transparency log
list can validate the authenticated raw evidence asynchronously:

```csharp
var validation = new CustomTlsCertificateValidationOptions
{
    EvidenceValidator = async (evidence, cancellationToken) =>
    {
        var ocsp = await ocspPolicy.ValidateAsync(
            evidence.CertificateChain,
            evidence.StapledOcspResponse,
            cancellationToken);
        var validScts = ctPolicy.Validate(
            evidence.CertificateChain,
            evidence.SignedCertificateTimestamps);

        return new TlsServerCertificateEvidenceValidationResult(ocsp, validScts);
    },
    RequireValidStapledOcspResponse = true,
    MinimumValidSignedCertificateTimestamps = 2,
};
```

The ClientHello profile must offer `status_request` and/or
`signed_certificate_timestamp` when the corresponding requirement is enabled. A
requirement without a validator is rejected before network I/O. Inputs are defensive
copies, cancellation is propagated, callback exceptions fail with `certificate_unknown`,
revocation fails with `certificate_revoked`, and an invalid/unknown/required-missing
staple fails with `bad_certificate_status_response`. A validator cannot report more
valid SCTs than the peer supplied.

The callback must perform real ASN.1, CertID, responder authorization, signature and
freshness checks for OCSP, and current log-ID/key, timestamp, signature and operator
policy checks for CT. SharpTls never treats mere presence as cryptographic validity.
The secure system chain engine remains active independently, including its configured
online/offline revocation behavior.

RFC 9162 CT v2 `transparency_info` is structurally different from the legacy RFC 6962
SCT extension and is tracked separately in the roadmap. Until its semantic parser is
complete, callers must not encode extension 52 as an opaque ClientHello extension and
expect SharpTls to process a server response.
