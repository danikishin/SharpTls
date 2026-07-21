using SharpTls.Protocol;

namespace SharpTls;

/// <summary>
/// Immutable, redacted snapshot of one completed TLS connection. It contains public
/// negotiation/authentication results and certificate material, but no traffic secrets,
/// private keys, PSKs, transcript state, sequence numbers, or mutable cipher state.
/// </summary>
public sealed class TlsConnectionState
{
    private readonly byte[]? _peerApplicationSettings;
    private readonly byte[][] _peerCertificateChain;
    private readonly byte[]? _stapledOcspResponse;
    private readonly byte[][] _signedCertificateTimestamps;
    private readonly byte[]? _tlsUnique;

    internal TlsConnectionState(
        string authenticatedServerName,
        TlsProtocolVersion protocolVersion,
        TlsCipherSuite cipherSuite,
        string? applicationProtocol,
        NamedGroup group,
        bool usedHelloRetryRequest,
        bool sessionWasResumed,
        bool externalPskWasSelected,
        bool serverCertificateValidationSkipped,
        Tls13EarlyDataStatus earlyDataStatus,
        bool encryptedClientHelloOffered,
        bool encryptedClientHelloAccepted,
        bool greaseEncryptedClientHelloOffered,
        TlsApplicationSettingsCodePoint? applicationSettingsCodePoint,
        byte[]? peerApplicationSettings,
        int? receiveRecordSizeLimit,
        int? sendRecordSizeLimit,
        bool serverUsedDelegatedCredential,
        DateTimeOffset? serverDelegatedCredentialExpiresAt,
        ulong clientKeyUpdateCount,
        ulong serverKeyUpdateCount,
        int postHandshakeAuthenticationCount,
        byte[]? tlsUnique,
        byte[][] peerCertificateChain,
        byte[]? stapledOcspResponse,
        byte[][] signedCertificateTimestamps,
        bool localClosed,
        bool peerClosed)
    {
        AuthenticatedServerName = authenticatedServerName;
        ProtocolVersion = protocolVersion;
        CipherSuite = cipherSuite;
        ApplicationProtocol = applicationProtocol;
        Group = group;
        UsedHelloRetryRequest = usedHelloRetryRequest;
        SessionWasResumed = sessionWasResumed;
        ExternalPskWasSelected = externalPskWasSelected;
        ServerCertificateValidationSkipped = serverCertificateValidationSkipped;
        EarlyDataStatus = earlyDataStatus;
        EncryptedClientHelloOffered = encryptedClientHelloOffered;
        EncryptedClientHelloAccepted = encryptedClientHelloAccepted;
        GreaseEncryptedClientHelloOffered = greaseEncryptedClientHelloOffered;
        ApplicationSettingsCodePoint = applicationSettingsCodePoint;
        _peerApplicationSettings = peerApplicationSettings is null ? null : (byte[])peerApplicationSettings.Clone();
        ReceiveRecordSizeLimit = receiveRecordSizeLimit;
        SendRecordSizeLimit = sendRecordSizeLimit;
        ServerUsedDelegatedCredential = serverUsedDelegatedCredential;
        ServerDelegatedCredentialExpiresAt = serverDelegatedCredentialExpiresAt;
        ClientKeyUpdateCount = clientKeyUpdateCount;
        ServerKeyUpdateCount = serverKeyUpdateCount;
        PostHandshakeAuthenticationCount = postHandshakeAuthenticationCount;
        _tlsUnique = tlsUnique is null ? null : (byte[])tlsUnique.Clone();
        _peerCertificateChain = CloneJagged(peerCertificateChain);
        _stapledOcspResponse = stapledOcspResponse is null ? null : (byte[])stapledOcspResponse.Clone();
        _signedCertificateTimestamps = CloneJagged(signedCertificateTimestamps);
        LocalClosed = localClosed;
        PeerClosed = peerClosed;
    }

    /// <summary>
    /// Gets the normalized reference identity. It is certificate-authenticated unless
    /// <see cref="ServerCertificateValidationSkipped"/> is true.
    /// </summary>
    public string AuthenticatedServerName { get; }
    /// <summary>Gets the negotiated TLS version.</summary>
    public TlsProtocolVersion ProtocolVersion { get; }
    /// <summary>Gets the negotiated cipher suite.</summary>
    public TlsCipherSuite CipherSuite { get; }
    /// <summary>Gets the negotiated ALPN protocol, or null.</summary>
    public string? ApplicationProtocol { get; }
    /// <summary>Gets the negotiated ECDHE group.</summary>
    public NamedGroup Group { get; }
    /// <summary>Gets whether the handshake used HelloRetryRequest.</summary>
    public bool UsedHelloRetryRequest { get; }
    /// <summary>Gets whether TLS 1.3 ticket or TLS 1.2 session-ID resumption authenticated the connection.</summary>
    public bool SessionWasResumed { get; }
    /// <summary>Gets whether an explicitly configured external PSK authenticated the peer.</summary>
    public bool ExternalPskWasSelected { get; }
    /// <summary>Gets whether the explicit dangerous option bypassed server PKI/name validation.</summary>
    public bool ServerCertificateValidationSkipped { get; }
    /// <summary>Gets the final early-data outcome.</summary>
    public Tls13EarlyDataStatus EarlyDataStatus { get; }
    /// <summary>Gets whether real ECH was offered.</summary>
    public bool EncryptedClientHelloOffered { get; }
    /// <summary>Gets whether real ECH was authenticated as accepted.</summary>
    public bool EncryptedClientHelloAccepted { get; }
    /// <summary>Gets whether the ClientHello carried GREASE ECH.</summary>
    public bool GreaseEncryptedClientHelloOffered { get; }
    /// <summary>Gets the negotiated experimental application-settings code point.</summary>
    public TlsApplicationSettingsCodePoint? ApplicationSettingsCodePoint { get; }
    /// <summary>Gets a copy of authenticated peer application settings, or null.</summary>
    public byte[]? PeerApplicationSettings =>
        _peerApplicationSettings is null ? null : (byte[])_peerApplicationSettings.Clone();
    /// <summary>Gets the negotiated inbound record size limit, or null.</summary>
    public int? ReceiveRecordSizeLimit { get; }
    /// <summary>Gets the negotiated outbound record size limit, or null.</summary>
    public int? SendRecordSizeLimit { get; }
    /// <summary>Gets whether the server authenticated with a delegated credential.</summary>
    public bool ServerUsedDelegatedCredential { get; }
    /// <summary>Gets the delegated-credential expiry, or null.</summary>
    public DateTimeOffset? ServerDelegatedCredentialExpiresAt { get; }
    /// <summary>Gets the completed client sending-key update count at snapshot time.</summary>
    public ulong ClientKeyUpdateCount { get; }
    /// <summary>Gets the authenticated server receiving-key update count at snapshot time.</summary>
    public ulong ServerKeyUpdateCount { get; }
    /// <summary>Gets the completed post-handshake authentication response count.</summary>
    public int PostHandshakeAuthenticationCount { get; }
    /// <summary>
    /// Gets a defensive copy of the RFC 5929 tls-unique channel binding for TLS 1.2,
    /// or null for TLS 1.3 where that binding is not defined.
    /// </summary>
    public byte[]? TlsUnique => _tlsUnique is null ? null : (byte[])_tlsUnique.Clone();
    /// <summary>Gets defensive DER copies of the peer certificate chain.</summary>
    public IReadOnlyList<byte[]> PeerCertificateChain => Array.AsReadOnly(CloneJagged(_peerCertificateChain));
    /// <summary>Gets a copy of the stapled OCSP response, or null.</summary>
    public byte[]? StapledOcspResponse =>
        _stapledOcspResponse is null ? null : (byte[])_stapledOcspResponse.Clone();
    /// <summary>Gets defensive copies of authenticated SCT encodings.</summary>
    public IReadOnlyList<byte[]> SignedCertificateTimestamps =>
        Array.AsReadOnly(CloneJagged(_signedCertificateTimestamps));
    /// <summary>Gets whether the local close state was set at snapshot time.</summary>
    public bool LocalClosed { get; }
    /// <summary>Gets whether the peer close state was set at snapshot time.</summary>
    public bool PeerClosed { get; }

    private static byte[][] CloneJagged(IReadOnlyList<byte[]> values) =>
        values.Select(value => (byte[])value.Clone()).ToArray();
}
