namespace SharpTls.Protocol;

/// <summary>Supported TLS cipher-suite identifiers.</summary>
public enum TlsCipherSuite : ushort
{
    /// <summary>TLS_AES_128_GCM_SHA256.</summary>
    TlsAes128GcmSha256 = 0x1301,

    /// <summary>TLS_AES_256_GCM_SHA384.</summary>
    TlsAes256GcmSha384 = 0x1302,

    /// <summary>TLS_CHACHA20_POLY1305_SHA256.</summary>
    TlsChaCha20Poly1305Sha256 = 0x1303,

    /// <summary>TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256.</summary>
    TlsEcdheEcdsaWithAes128GcmSha256 = 0xC02B,
    /// <summary>TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384.</summary>
    TlsEcdheEcdsaWithAes256GcmSha384 = 0xC02C,
    /// <summary>TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256.</summary>
    TlsEcdheRsaWithAes128GcmSha256 = 0xC02F,
    /// <summary>TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384.</summary>
    TlsEcdheRsaWithAes256GcmSha384 = 0xC030,
    /// <summary>TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256.</summary>
    TlsEcdheRsaWithChaCha20Poly1305Sha256 = 0xCCA8,
    /// <summary>TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256.</summary>
    TlsEcdheEcdsaWithChaCha20Poly1305Sha256 = 0xCCA9,
    /// <summary>TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA.</summary>
    TlsEcdheEcdsaWithAes128CbcSha = 0xC009,
    /// <summary>TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA.</summary>
    TlsEcdheEcdsaWithAes256CbcSha = 0xC00A,
    /// <summary>TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256.</summary>
    TlsEcdheEcdsaWithAes128CbcSha256 = 0xC023,
    /// <summary>TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384.</summary>
    TlsEcdheEcdsaWithAes256CbcSha384 = 0xC024,
    /// <summary>TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA.</summary>
    TlsEcdheEcdsaWith3DesEdeCbcSha = 0xC008,
    /// <summary>TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA.</summary>
    TlsEcdheRsaWithAes128CbcSha = 0xC013,
    /// <summary>TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA.</summary>
    TlsEcdheRsaWithAes256CbcSha = 0xC014,
    /// <summary>TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256.</summary>
    TlsEcdheRsaWithAes128CbcSha256 = 0xC027,
    /// <summary>TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384.</summary>
    TlsEcdheRsaWithAes256CbcSha384 = 0xC028,
    /// <summary>TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA.</summary>
    TlsEcdheRsaWith3DesEdeCbcSha = 0xC012,
    /// <summary>TLS_RSA_WITH_AES_128_GCM_SHA256.</summary>
    TlsRsaWithAes128GcmSha256 = 0x009C,
    /// <summary>TLS_RSA_WITH_AES_256_GCM_SHA384.</summary>
    TlsRsaWithAes256GcmSha384 = 0x009D,
    /// <summary>TLS_RSA_WITH_AES_128_CBC_SHA.</summary>
    TlsRsaWithAes128CbcSha = 0x002F,
    /// <summary>TLS_RSA_WITH_AES_256_CBC_SHA.</summary>
    TlsRsaWithAes256CbcSha = 0x0035,
    /// <summary>TLS_RSA_WITH_AES_128_CBC_SHA256.</summary>
    TlsRsaWithAes128CbcSha256 = 0x003C,
    /// <summary>TLS_RSA_WITH_AES_256_CBC_SHA256.</summary>
    TlsRsaWithAes256CbcSha256 = 0x003D,
    /// <summary>TLS_RSA_WITH_3DES_EDE_CBC_SHA.</summary>
    TlsRsaWith3DesEdeCbcSha = 0x000A,

    // Historical wire-fidelity values. SharpTls never negotiates or implements these
    // weak suites; they exist only so pinned legacy ClientHello profiles can encode them.
    /// <summary>Fingerprint-only TLS_DHE_DSS_WITH_AES_128_CBC_SHA.</summary>
    TlsDheDssWithAes128CbcSha = 0x0032,
    /// <summary>Fingerprint-only TLS_DHE_RSA_WITH_AES_128_CBC_SHA.</summary>
    TlsDheRsaWithAes128CbcSha = 0x0033,
    /// <summary>Fingerprint-only TLS_DHE_RSA_WITH_AES_256_CBC_SHA.</summary>
    TlsDheRsaWithAes256CbcSha = 0x0039,
    /// <summary>Fingerprint-only TLS_DHE_RSA_WITH_AES_128_CBC_SHA256.</summary>
    TlsDheRsaWithAes128CbcSha256 = 0x0067,
    /// <summary>Fingerprint-only TLS_DHE_RSA_WITH_AES_256_CBC_SHA256.</summary>
    TlsDheRsaWithAes256CbcSha256 = 0x006B,
    /// <summary>Fingerprint-only TLS_RSA_WITH_RC4_128_MD5.</summary>
    TlsRsaWithRc4_128Md5 = 0x0004,
    /// <summary>Fingerprint-only TLS_RSA_WITH_RC4_128_SHA.</summary>
    TlsRsaWithRc4_128Sha = 0x0005,
    /// <summary>Fingerprint-only TLS_ECDHE_ECDSA_WITH_RC4_128_SHA.</summary>
    TlsEcdheEcdsaWithRc4_128Sha = 0xC007,
    /// <summary>Fingerprint-only TLS_ECDHE_RSA_WITH_RC4_128_SHA.</summary>
    TlsEcdheRsaWithRc4_128Sha = 0xC011,
}

/// <summary>TLS protocol version identifiers used in supported_versions.</summary>
public enum TlsProtocolVersion : ushort
{
    /// <summary>TLS 1.0.</summary>
    Tls10 = 0x0301,
    /// <summary>TLS 1.1.</summary>
    Tls11 = 0x0302,
    /// <summary>TLS 1.2.</summary>
    Tls12 = 0x0303,
    /// <summary>TLS 1.3.</summary>
    Tls13 = 0x0304,
}

/// <summary>TLS supported-group identifiers.</summary>
public enum NamedGroup : ushort
{
    /// <summary>NIST P-256 / secp256r1.</summary>
    Secp256r1 = 0x0017,

    /// <summary>NIST P-384 / secp384r1.</summary>
    Secp384r1 = 0x0018,

    /// <summary>NIST P-521 / secp521r1.</summary>
    Secp521r1 = 0x0019,

    /// <summary>X25519 as specified by RFC 7748.</summary>
    X25519 = 0x001D,

    /// <summary>X25519 combined with FIPS 203 ML-KEM-768 (IANA value 4588).</summary>
    X25519MlKem768 = 0x11EC,

    /// <summary>
    /// Obsolete pre-standard X25519+Kyber768 draft group retained only for exact
    /// interoperability with historical uTLS Chrome profiles.
    /// </summary>
    X25519Kyber768Draft00 = 0x6399,

    /// <summary>Finite-field ffdhe2048 profile identifier.</summary>
    Ffdhe2048 = 0x0100,

    /// <summary>Finite-field ffdhe3072 profile identifier.</summary>
    Ffdhe3072 = 0x0101,
}

/// <summary>TLS signature-scheme identifiers used by TLS 1.3.</summary>
public enum SignatureScheme : ushort
{
    /// <summary>RSA PKCS #1 v1.5 with SHA-1.</summary>
    RsaPkcs1Sha1 = 0x0201,

    /// <summary>Fingerprint-only DSA with SHA-1.</summary>
    DsaSha1 = 0x0202,

    /// <summary>ECDSA with SHA-1.</summary>
    EcdsaSha1 = 0x0203,

    /// <summary>RSA PKCS #1 v1.5 with SHA-256.</summary>
    RsaPkcs1Sha256 = 0x0401,

    /// <summary>Fingerprint-only DSA with SHA-256.</summary>
    DsaSha256 = 0x0402,

    /// <summary>RSA PKCS #1 v1.5 with SHA-384.</summary>
    RsaPkcs1Sha384 = 0x0501,

    /// <summary>RSA PKCS #1 v1.5 with SHA-512.</summary>
    RsaPkcs1Sha512 = 0x0601,

    /// <summary>ECDSA P-256 with SHA-256.</summary>
    EcdsaSecp256r1Sha256 = 0x0403,

    /// <summary>ECDSA P-384 with SHA-384.</summary>
    EcdsaSecp384r1Sha384 = 0x0503,

    /// <summary>ECDSA P-521 with SHA-512.</summary>
    EcdsaSecp521r1Sha512 = 0x0603,

    /// <summary>RSA-PSS using an RSAE key and SHA-256.</summary>
    RsaPssRsaeSha256 = 0x0804,

    /// <summary>RSA-PSS using an RSAE key and SHA-384.</summary>
    RsaPssRsaeSha384 = 0x0805,

    /// <summary>RSA-PSS using an RSAE key and SHA-512.</summary>
    RsaPssRsaeSha512 = 0x0806,

    /// <summary>RSA-PSS using an RSASSA-PSS key and SHA-256.</summary>
    RsaPssPssSha256 = 0x0809,

    /// <summary>RSA-PSS using an RSASSA-PSS key and SHA-384.</summary>
    RsaPssPssSha384 = 0x080A,

    /// <summary>RSA-PSS using an RSASSA-PSS key and SHA-512.</summary>
    RsaPssPssSha512 = 0x080B,
}

/// <summary>Known TLS extension identifiers.</summary>
public enum TlsExtensionType : ushort
{
    /// <summary>Server Name Indication.</summary>
    ServerName = 0,

    /// <summary>Deprecated maximum_fragment_length negotiation.</summary>
    MaximumFragmentLength = 1,

    /// <summary>OCSP status_request.</summary>
    StatusRequest = 5,

    /// <summary>Supported Groups.</summary>
    SupportedGroups = 10,

    /// <summary>Supported EC point formats.</summary>
    EcPointFormats = 11,

    /// <summary>Signature Algorithms.</summary>
    SignatureAlgorithms = 13,

    /// <summary>Application-Layer Protocol Negotiation.</summary>
    ApplicationLayerProtocolNegotiation = 16,

    /// <summary>Signed Certificate Timestamp delivery.</summary>
    SignedCertificateTimestamp = 18,

    /// <summary>ClientHello padding.</summary>
    Padding = 21,

    /// <summary>TLS 1.2 extended master secret.</summary>
    ExtendedMasterSecret = 23,

    /// <summary>RFC 8879 TLS certificate compression algorithms.</summary>
    CompressCertificate = 27,

    /// <summary>RFC 8449 protected-record plaintext limit.</summary>
    RecordSizeLimit = 28,

    /// <summary>RFC 9345 delegated credentials.</summary>
    DelegatedCredential = 34,

    /// <summary>TLS session-ticket signaling.</summary>
    SessionTicket = 35,

    /// <summary>TLS 1.3 pre-shared-key selection and identities.</summary>
    PreSharedKey = 41,

    /// <summary>TLS 1.3 early-data indication.</summary>
    EarlyData = 42,

    /// <summary>Supported TLS versions.</summary>
    SupportedVersions = 43,

    /// <summary>HelloRetryRequest cookie.</summary>
    Cookie = 44,

    /// <summary>PSK key-exchange modes.</summary>
    PskKeyExchangeModes = 45,

    /// <summary>TLS 1.3 post-handshake client authentication capability.</summary>
    PostHandshakeAuthentication = 49,

    /// <summary>Certificate-chain signature algorithms.</summary>
    SignatureAlgorithmsCert = 50,

    /// <summary>ECDHE key shares.</summary>
    KeyShare = 51,

    /// <summary>RFC 9001 QUIC transport parameters.</summary>
    QuicTransportParameters = 57,

    /// <summary>RFC 9849 inner-ClientHello outer-extension reference list.</summary>
    EchOuterExtensions = 0xFD00,

    /// <summary>RFC 9849 Encrypted ClientHello.</summary>
    EncryptedClientHello = 0xFE0D,

    /// <summary>RFC 5746 secure renegotiation indication.</summary>
    RenegotiationInfo = 0xFF01,
}

/// <summary>TLS alert descriptions exposed for protocol failures.</summary>
public enum TlsAlertDescription : byte
{
    /// <summary>Peer requested an orderly shutdown.</summary>
    CloseNotify = 0,
    /// <summary>Unexpected protocol message.</summary>
    UnexpectedMessage = 10,
    /// <summary>Authentication tag or Finished verification failed.</summary>
    BadRecordMac = 20,
    /// <summary>Record exceeded protocol limits.</summary>
    RecordOverflow = 22,
    /// <summary>Handshake could not be completed.</summary>
    HandshakeFailure = 40,
    /// <summary>Certificate could not be parsed or verified.</summary>
    BadCertificate = 42,
    /// <summary>Certificate type or public-key algorithm is unsupported.</summary>
    UnsupportedCertificate = 43,
    /// <summary>Certificate has been revoked.</summary>
    CertificateRevoked = 44,
    /// <summary>Certificate is outside its validity interval.</summary>
    CertificateExpired = 45,
    /// <summary>Certificate validation failed for an unspecified reason.</summary>
    CertificateUnknown = 46,
    /// <summary>A field or negotiation result was illegal.</summary>
    IllegalParameter = 47,
    /// <summary>Certificate issuer is not trusted.</summary>
    UnknownCa = 48,
    /// <summary>Input was malformed or truncated.</summary>
    DecodeError = 50,
    /// <summary>A cryptographic operation failed.</summary>
    DecryptError = 51,
    /// <summary>Negotiated protocol version is unsupported.</summary>
    ProtocolVersion = 70,
    /// <summary>Required extension was missing.</summary>
    MissingExtension = 109,
    /// <summary>Peer sent an extension that was not offered or is not supported in context.</summary>
    UnsupportedExtension = 110,
    /// <summary>SNI name was not recognized by the endpoint.</summary>
    UnrecognizedName = 112,
    /// <summary>A stapled OCSP response was missing, invalid, or unacceptable.</summary>
    BadCertificateStatusResponse = 113,
    /// <summary>A mandatory client certificate was not supplied.</summary>
    CertificateRequired = 116,
    /// <summary>No offered application protocol matched.</summary>
    NoApplicationProtocol = 120,
    /// <summary>RFC 9849 ECH was required but not accepted.</summary>
    EchRequired = 121,
    /// <summary>Internal invariant failed.</summary>
    InternalError = 80,
    /// <summary>Generic protocol failure without a more specific alert.</summary>
    GeneralError = 117,
}

internal enum TlsContentType : byte
{
    ChangeCipherSpec = 20,
    Alert = 21,
    Handshake = 22,
    ApplicationData = 23,
}

internal enum HandshakeType : byte
{
    HelloRequest = 0,
    ClientHello = 1,
    ServerHello = 2,
    NewSessionTicket = 4,
    EndOfEarlyData = 5,
    EncryptedExtensions = 8,
    Certificate = 11,
    ServerKeyExchange = 12,
    CertificateRequest = 13,
    ServerHelloDone = 14,
    CertificateVerify = 15,
    ClientKeyExchange = 16,
    Finished = 20,
    CertificateStatus = 22,
    CompressedCertificate = 25,
    KeyUpdate = 24,
    MessageHash = 254,
}
