# Delegated credentials

SharpTls implements both RFC 9345 directions used by a TLS client: validating a server
delegated credential and presenting a caller-issued delegated credential for TLS 1.3
client authentication. The client can advertise server delegated-key algorithms in an
exact ClientHello position:

```csharp
var profile = ClientHelloProfiles.Custom(builder => builder
    .WithDelegatedCredentials(
        SignatureScheme.EcdsaSecp256r1Sha256,
        SignatureScheme.EcdsaSecp384r1Sha384));
```

The list is encoded as extension 34 and survives capture import and versioned JSON
round trips. Executable delegated keys are P-256/P-384/P-521 ECDSA and constrained
RSA-PSS-PSS SHA-256/384/512. RSAE public keys are forbidden for the delegated key by
RFC 9345. PSS SubjectPublicKeyInfo parameters are DER-checked before modulus/exponent
are imported into the runtime RSA provider. EdDSA remains unadvertised because .NET 9
does not expose a portable primitive.

The pinned historical Firefox profile retains its legacy ECDSA/SHA-1 list member only
under the explicit wire-fidelity flag. SharpTls will never accept that member if a
server selects it.

## Validation

Normal certificate-chain, EKU, revocation-policy, and hostname checks still apply to
the delegation certificate. A server credential is additionally rejected unless:

- it appears exactly once on the leaf CertificateEntry and was advertised;
- the leaf has the non-critical DelegationUsage OID `1.3.6.1.4.1.44363.44` encoded as
  ASN.1 NULL and permits `digitalSignature`;
- expiry is after the current time, no more than seven days ahead, and strictly before
  the leaf certificate expiry;
- the delegated DER SubjectPublicKeyInfo matches its advertised algorithm and curve;
- the credential's signing algorithm was offered in `signature_algorithms`, and the
  delegated-key algorithm was offered in the delegated-credential list;
- the leaf certificate key verifies the RFC 9345 server-context delegation signature.

After these checks, server CertificateVerify must use the credential's exact algorithm
and is verified with the delegated public key. The connection exposes
`ServerUsedDelegatedCredential` and `ServerDelegatedCredentialExpiresAt`. Session
tickets produced by that authentication are capped to the delegated credential expiry,
so resumption cannot silently outlive the short-lived credential.

Malformed, duplicated, unadvertised, non-leaf, expired, overlong, mismatched, or
cryptographically invalid credentials fail closed.

## Client authentication

SharpTls deliberately does not issue delegated credentials. Supply a pre-issued RFC
9345 extension body and a caller-owned signer whose public SPKI is exactly the delegated
SPKI. Attach it to the client delegation certificate before connecting:

```csharp
var delegated = new TlsClientDelegatedCredential(encodedCredential, delegatedSigner);
var clientCertificate = new TlsClientCertificate(
    delegationCertificate,
    delegationCertificateSigner,
    issuerCertificates);
clientCertificate.AttachDelegatedCredential(delegated);
```

`delegatedSigner` implements `ITlsClientCertificateSigner`; its private key can remain
inside a runtime provider, HSM, smart card, or remote KMS. The delegated credential and
both signers remain caller-owned and must outlive every client using them.

Attachment validates the DelegationUsage/key-usage extensions, seven-day and certificate
lifetime, exact delegated SPKI and curve or constrained PSS parameters, certificate
binding, and the RFC 9345 `TLS, client delegated credentials` delegation signature.
Selection occurs only if CertificateRequest authorizes both independent algorithms:
the delegation signature algorithm must appear in `signature_algorithms`, and the
delegated key's CertificateVerify algorithm must appear in extension 34. Otherwise the
normal certificate key is used when compatible, or SharpTls sends an empty Certificate.

When selected, extension 34 is encoded only on the leaf CertificateEntry and
CertificateVerify is produced asynchronously with the delegated signer. The same rules
apply to post-handshake authentication. Duplicate attachment, disposed credentials,
wrong signer SPKI, malformed encoding, wrong curves/PSS parameters, invalid signatures,
and expired or overlong credentials fail before unauthenticated application traffic.
