# Client authentication

SharpTls supports static caller-owned RSA and ECDSA client credentials in TLS 1.3 and
the executable TLS 1.2 subset. The private key remains inside the .NET `RSA` or `ECDsa`
object obtained from `X509Certificate2`; SharpTls compares its public key to the leaf,
but never exports private key bytes.

```csharp
using var credential = new TlsClientCertificate(
    leafCertificateWithPrivateKey,
    issuerCertificatesInLeafToRootOrder);

var profile = ClientHelloProfiles.Custom(builder => builder
    .WithSessionResumption()
    .WithPostHandshakeAuthentication());

await using var client = new CustomTlsClient(new CustomTlsClientOptions
{
    ServerName = "service.example",
    ClientHello = profile,
    ClientCertificate = credential,
});

await client.ConnectAsync("service.example", 443, cancellationToken);
```

The credential snapshots the public DER chain at construction and owns the private-key
handle returned by the certificate. Dispose every client before disposing the credential.
One credential may be shared by concurrent clients; signing and disposal are serialized.
The leaf must permit digital signatures and, when EKU is present, client authentication.
Its private key must match the leaf and the certificate must be time-valid when selected.

Some platforms cannot attach a private `RSA` object to an X.509 certificate whose
SubjectPublicKeyInfo OID is RSASSA-PSS. Use the separate-key overload in that case:

```csharp
using var credential = new TlsClientCertificate(
    rsaPssLeafCertificate,
    callerOwnedRsaPrivateKey,
    issuerCertificatesInLeafToRootOrder);
```

This overload compares modulus and exponent without exporting private values. The `RSA`
object stays caller-owned and must remain alive until the credential is disposed.

## Dynamic selection and external signers

Set `CustomTlsClientOptions.ClientCertificateSelector` when credentials depend on the
server identity, TLS version, peer signature list, TLS 1.2 certificate types, or whether
the request is post-handshake. The callback is asynchronous, receives the connection
cancellation token, and runs once for each CertificateRequest. It is mutually exclusive
with the static `ClientCertificate` option. Returning null (or an incompatible credential)
sends the protocol-mandated empty Certificate response.

Hardware tokens, smart cards, remote KMS services and runtime key providers implement
`ITlsClientCertificateSigner`. A signer publishes its executable TLS signature schemes,
exports only its public SubjectPublicKeyInfo, and asynchronously signs a pre-hashed
CertificateVerify input. `TlsClientCertificate` requires the signer SPKI to match the leaf
certificate exactly before accepting the credential, filters requests through both the
leaf key constraints and signer capabilities, serializes shared signer calls, validates
hash/signature lengths, propagates cancellation, and never requests private key bytes.
The signer remains caller-owned and must outlive every credential using it.

The selection context also exposes the exact RFC 9345
`DelegatedCredentialSignatureSchemes` list from a TLS 1.3 CertificateRequest. This list
is empty for TLS 1.2 and when the server did not request a delegated credential.

For TLS 1.3, RSAE and RSASSA-PSS keys use their distinct RSA-PSS SHA-256/384/512 schemes;
constrained PSS parameters must permit the selected hash, MGF1, salt length, and trailer.
ECDSA keys require the exact P-256/SHA-256, P-384/SHA-384 or P-521/SHA-512 pairing.
TLS 1.2 also permits RSA-PKCS#1 with SHA-256/384/512. SHA-1 CertificateVerify is never
generated. The peer's preference order is preserved when selecting a compatible scheme.

If a server requests authentication and no credential is configured or no offered scheme
matches, SharpTls sends the required empty Certificate message and omits CertificateVerify;
it does not fake authentication or select an unoffered algorithm.

## Post-handshake authentication

PHA is disabled unless the ClientHello profile explicitly calls
`WithPostHandshakeAuthentication()`. An unadvertised request is rejected with a fatal
`unexpected_message`. Request contexts must be unique on the connection; reuse is an
`illegal_parameter` failure. Each response uses a fresh fork of the original transcript
through client Finished plus only the current CertificateRequest and response block.
Its Finished MAC uses the current client application traffic-secret epoch.

`PostHandshakeAuthenticationCount` reports completed responses. The server may still
decide not to treat the client as authenticated; applications requiring that assurance
need an application-layer acknowledgement, as described by RFC 9846 Appendix F.1.2.

Client-certificate compression is not claimed. RFC 9345 client delegated credentials
are supported for initial authentication and PHA, but SharpTls does not issue them: the
caller must supply a pre-issued credential and its separate signer as documented in
[Delegated credentials](DELEGATED-CREDENTIALS.md).
