namespace SharpTls;

/// <summary>Identifies built-in ClientHello extensions for exact ordering.</summary>
public enum ClientHelloExtensionKind
{
    /// <summary>RFC 8701 GREASE extension.</summary>
    Grease,
    /// <summary>A second RFC 8701 GREASE extension with an independently generated type.</summary>
    SecondaryGrease,
    /// <summary>Server Name Indication.</summary>
    ServerName,
    /// <summary>Supported TLS versions.</summary>
    SupportedVersions,
    /// <summary>A server-provided HelloRetryRequest cookie; not configurable in the initial ClientHello.</summary>
    Cookie,
    /// <summary>Supported key-exchange groups.</summary>
    SupportedGroups,
    /// <summary>CertificateVerify signature schemes.</summary>
    SignatureAlgorithms,
    /// <summary>Signature schemes accepted on X.509 certificate chains.</summary>
    SignatureAlgorithmsCert,
    /// <summary>ECDHE key shares.</summary>
    KeyShare,
    /// <summary>PSK key-exchange modes; SharpTls emits only forward-secret psk_dhe_ke.</summary>
    PskKeyExchangeModes,
    /// <summary>Conditional empty TLS 1.3 early_data indication.</summary>
    EarlyData,
    /// <summary>Conditional TLS 1.3 PSK identities and binders; must be the final ClientHello extension.</summary>
    PreSharedKey,
    /// <summary>Application-Layer Protocol Negotiation.</summary>
    ApplicationLayerProtocolNegotiation,
    /// <summary>Experimental ALPS/application_settings protocol list.</summary>
    ApplicationSettings,
    /// <summary>Empty TLS 1.3 post_handshake_auth capability indication.</summary>
    PostHandshakeAuthentication,
    /// <summary>Maximum protected-record plaintext the client is willing to receive.</summary>
    RecordSizeLimit,
    /// <summary>Signature schemes accepted for RFC 9345 delegated credential keys.</summary>
    DelegatedCredential,
    /// <summary>RFC 9001 QUIC transport parameters.</summary>
    QuicTransportParameters,
    /// <summary>
    /// Managed encrypted_client_hello slot. The ECH builder replaces this slot with the
    /// generated extension body, preserving its exact profile position.
    /// </summary>
    EncryptedClientHello,
    /// <summary>ClientHello padding.</summary>
    Padding,
}
