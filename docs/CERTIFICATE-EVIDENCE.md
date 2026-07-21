# OCSP and certificate-transparency policy

SharpTls performs normal X.509 chain, server-auth EKU, revocation-mode and hostname
validation by default. An evidence callback is an additional policy gate; it cannot
override a failure from the built-in validator.

## Explicit trust and hostname bypass

Controlled TLS laboratories, local interception endpoints and protocol tests sometimes
need encryption without PKI or reference-identity authentication. This requires a
deliberately named opt-in:

```csharp
var options = new CustomTlsClientOptions
{
    CertificateValidation = new CustomTlsCertificateValidationOptions
    {
        DangerouslySkipServerCertificateValidation = true,
    },
};
```

This setting bypasses certificate-chain, EKU, validity, revocation and hostname checks.
It permits active man-in-the-middle attacks and must not be enabled for normal traffic.
Certificate parsing, TLS 1.3 CertificateVerify or TLS 1.2 server-key signature validation,
the transcript, Finished and record authentication remain mandatory. Optional OCSP/CT
evidence validation also remains active when configured. TLS 1.2 and TLS 1.3 resumption
entries are partitioned by validation mode, so a ticket learned with this option cannot
authenticate a later connection using the default validated mode.
`TlsConnectionState.ServerCertificateValidationSkipped` and the corresponding live
client/QUIC property expose the effective mode to diagnostics.

## Revocation responder availability

The default policy requests online revocation information. Platform chain engines often
return `RevocationStatusUnknown` or `OfflineRevocation` when a certificate has no usable
responder, a responder is temporarily unreachable, or the platform cannot obtain fresh
evidence. SharpTls soft-fails only that availability condition by default: it first runs
the requested revocation build, verifies that no other status was reported, then rebuilds
with revocation disabled while retaining trust, time, EKU, constraints and signature
validation. Hostname is mandatory unless the dangerous bypass above is explicit, while
TLS CertificateVerify remains an independent mandatory gate in both modes.
An explicit `Revoked` status is never ignored.

Deployments that require revocation evidence to be available on every connection can opt
into hard failure:

```csharp
var validation = new CustomTlsCertificateValidationOptions
{
    RevocationMode = X509RevocationMode.Online,
    AllowUnknownRevocationStatus = false,
};
```

`X509RevocationMode.NoCheck` skips the initial revocation attempt and should be selected
only when the deployment has a deliberate alternative. Requiring a cryptographically
validated stapled OCSP response through the evidence policy below is a separate,
stronger availability requirement.

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
The system chain engine remains active independently, including its configured
online/offline lookup and revocation-availability policy, unless the caller explicitly
enables the dangerous bypass above.

RFC 9162 CT v2 `transparency_info` is structurally different from the legacy RFC 6962
SCT extension and is tracked separately in the roadmap. Until its semantic parser is
complete, callers must not encode extension 52 as an opaque ClientHello extension and
expect SharpTls to process a server response.
