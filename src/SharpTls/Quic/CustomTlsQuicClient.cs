using System.Security.Cryptography;
using SharpTls.Certificates;
using SharpTls.Cryptography;
using SharpTls.Ech;
using SharpTls.Handshake;
using SharpTls.Protocol;
using SharpTls.Sessions;

namespace SharpTls.Quic;

/// <summary>
/// A recordless TLS 1.3 client state machine for QUIC. The caller owns QUIC packets,
/// CRYPTO frames, loss recovery and packet protection; this type owns only TLS Handshake bytes.
/// </summary>
public sealed class CustomTlsQuicClient : IAsyncDisposable
{
    private readonly CustomTlsQuicClientConfiguration _configuration;
    private readonly Tls13ClientStateMachine _state = new();
    private readonly HandshakeDeframer _initialDeframer;
    private readonly HandshakeDeframer _handshakeDeframer;
    private readonly HandshakeDeframer _applicationDeframer;
    private readonly TlsQuicCryptoStreamReassembler _initialReassembler;
    private readonly TlsQuicCryptoStreamReassembler _handshakeReassembler;
    private readonly TlsQuicCryptoStreamReassembler _applicationReassembler;
    private readonly SemaphoreSlim _gate = new(1, 1);
    private readonly bool _echGreased;

    private ClientHelloBuildResult? _offer;
    private EchClientHelloBuildResult? _firstEchOffer;
    private EchClientHelloRetryBuildResult? _retryEchOffer;
    private TranscriptHash? _transcript;
    private Tls13KeySchedule? _keySchedule;
    private Tls13KeySchedule? _earlyKeySchedule;
    private CipherSuiteInfo? _suite;
    private ServerHelloResult? _serverHello;
    private ServerCertificateMessage? _certificates;
    private Tls13CertificateRequest? _certificateRequest;
    private TlsQuicTransportParameters? _peerTransportParameters;
    private Tls13SessionTicket? _offeredTicket;
    private DateTimeOffset? _authenticationExpiresAt;
    private byte[][] _peerCertificateChain = [];
    private readonly HashSet<string> _receivedTicketNonces = new(StringComparer.Ordinal);
    private ulong _initialWriteOffset;
    private ulong _handshakeWriteOffset;
    private TlsCipherSuite? _helloRetryRequestSuite;
    private NamedGroup? _helloRetryRequestGroup;
    private byte[]? _helloRetryRequestEncoded;
    private TlsEchConfigList? _echRetryConfigurations;
    private bool _echRejected;
    private bool _started;
    private bool _failed;
    private bool _disposed;
    private bool _initialKeysDiscarded;
    private bool _handshakeConfirmed;
    private bool _attemptedEarlyData;
    private int _receivedSessionTickets;

    /// <summary>Creates a snapshotted, reusable recordless TLS client.</summary>
    public CustomTlsQuicClient(CustomTlsQuicClientOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);
        _configuration = options.Snapshot();
        _initialDeframer = new HandshakeDeframer(_configuration.Shared.Limits.MaxHandshakeMessageSize);
        _handshakeDeframer = new HandshakeDeframer(_configuration.Shared.Limits.MaxHandshakeMessageSize);
        _applicationDeframer = new HandshakeDeframer(_configuration.Shared.Limits.MaxHandshakeMessageSize);
        _initialReassembler = new TlsQuicCryptoStreamReassembler(
            _configuration.MaximumCryptoStreamLength);
        _handshakeReassembler = new TlsQuicCryptoStreamReassembler(
            _configuration.MaximumCryptoStreamLength);
        _applicationReassembler = new TlsQuicCryptoStreamReassembler(
            _configuration.MaximumCryptoStreamLength);
        _echGreased = _configuration.Shared.EchGrease is not null ||
            _configuration.ClientHello.Spec.GreaseEncryptedClientHello;
    }

    /// <summary>Gets whether server Finished and the local client Finished were completed.</summary>
    public bool IsHandshakeComplete => !_disposed && _state.State == Tls13ClientState.Connected;

    /// <summary>Gets the negotiated cipher suite after handshake completion.</summary>
    public TlsCipherSuite? NegotiatedCipherSuite { get; private set; }

    /// <summary>Gets the negotiated ECDHE group after handshake completion.</summary>
    public NamedGroup? NegotiatedGroup { get; private set; }

    /// <summary>Gets the mandatory negotiated ALPN identifier after authentication.</summary>
    public string? NegotiatedApplicationProtocol { get; private set; }

    /// <summary>Gets whether the server selected an authenticated resumption ticket.</summary>
    public bool SessionWasResumed { get; private set; }

    /// <summary>Gets whether this handshake authenticated a HelloRetryRequest path.</summary>
    public bool HandshakeUsedHelloRetryRequest => _helloRetryRequestSuite.HasValue;

    /// <summary>Gets whether RFC 9849 ECH was authenticated as accepted.</summary>
    public bool EncryptedClientHelloAccepted { get; private set; }

    /// <summary>Gets the outcome of explicitly enabled replayable QUIC 0-RTT.</summary>
    public Tls13EarlyDataStatus EarlyDataStatus { get; private set; }

    /// <summary>Gets defensive DER copies of the authenticated server chain.</summary>
    public IReadOnlyList<byte[]> PeerCertificateChain => Array.AsReadOnly(
        _peerCertificateChain.Select(value => (byte[])value.Clone()).ToArray());

    /// <summary>
    /// Starts exactly one handshake and returns the Initial-level ClientHello CRYPTO bytes.
    /// </summary>
    public TlsQuicProcessResult StartHandshake()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (_started || _failed)
        {
            throw new InvalidOperationException("The QUIC TLS handshake has already been started.");
        }

        try
        {
            _started = true;
            _state.TransportConnected();
            Tls13PskOffer? pskOffer = null;
            if (_configuration.Shared.SessionCache is { } cache)
            {
                _offeredTicket = cache.TryTake(
                    Tls13SessionOrigin.Create(
                        _configuration.ServerName,
                        _configuration.ServerPort),
                    _configuration.ClientHello.Spec.CipherSuites,
                    _configuration.ClientHello.Spec.AlpnProtocols,
                    _configuration.Shared.Ech?.ConfigListHash);
                if (_offeredTicket is not null)
                {
                    pskOffer = new Tls13PskOffer(_offeredTicket, cache.UtcNow);
                }
            }
            var executablePskOffer = pskOffer is null
                ? null
                : new Tls13PskOffer(
                    _offeredTicket!,
                    _configuration.Shared.SessionCache!.UtcNow,
                    OfferEarlyData: _configuration.EnableEarlyData &&
                        _offeredTicket!.MaximumEarlyDataSize == uint.MaxValue &&
                        _offeredTicket.QuicTransportParameters is not null);
            ClientHelloBuildResult wireOffer;
            if (_configuration.Shared.Ech is { } ech)
            {
                _firstEchOffer = EchClientHelloBuilder.Build(
                    _configuration.ServerName,
                    _configuration.ClientHello.Spec.SnapshotConfiguration(),
                    ech.OuterClientHello.Spec.SnapshotConfiguration(),
                    ech.Selection,
                    SecureRandomSource.Instance,
                    new KeyShareSet(),
                    new KeyShareSet(),
                    ech.CompressedOuterExtensions,
                    executablePskOffer);
                _offer = _firstEchOffer.Inner;
                wireOffer = _firstEchOffer.Outer;
            }
            else if (_configuration.Shared.EchGrease is { } echGrease)
            {
                _offer = EchGreaseClientHelloBuilder.Build(
                    _configuration.ServerName,
                    _configuration.ClientHello.Spec.SnapshotConfiguration(),
                    echGrease,
                    SecureRandomSource.Instance,
                    new KeyShareSet(),
                    executablePskOffer);
                wireOffer = _offer;
            }
            else
            {
                _offer = _configuration.ClientHello.BuildSecure(
                    _configuration.ServerName,
                    executablePskOffer);
                wireOffer = _offer;
            }
            var output = CreateCryptoEvent(
                TlsQuicEncryptionLevel.Initial,
                ref _initialWriteOffset,
                wireOffer.EncodedHandshake);
            var events = new List<TlsQuicEvent> { output };
            EarlyDataStatus = _configuration.EnableEarlyData
                ? Tls13EarlyDataStatus.Unavailable
                : Tls13EarlyDataStatus.NotConfigured;
            if (_configuration.EnableEarlyData &&
                _offeredTicket is
                {
                    MaximumEarlyDataSize: uint.MaxValue,
                    QuicTransportParameters: not null,
                })
            {
                _attemptedEarlyData = true;
                EarlyDataStatus = Tls13EarlyDataStatus.Rejected;
                var earlySuite = CipherSuiteInfo.Get(_offeredTicket.CipherSuite);
                var psk = _offeredTicket.CopyPsk();
                var clientHelloHash = HashHandshake(earlySuite, _offer.EncodedHandshake);
                try
                {
                    _earlyKeySchedule = new Tls13KeySchedule(earlySuite, psk);
                    _earlyKeySchedule.DeriveClientEarlyTrafficSecret(clientHelloHash);
                    AddTrafficSecret(
                        events,
                        TlsQuicEncryptionLevel.EarlyData,
                        TlsQuicSecretDirection.Write,
                        earlySuite.Suite,
                        _earlyKeySchedule.CopyClientEarlyTrafficSecret());
                    events.Add(new TlsQuicEarlyDataReadyEvent(
                        TlsQuicTransportParameters.Parse(
                            _offeredTicket.QuicTransportParameters)));
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(psk);
                    CryptographicOperations.ZeroMemory(clientHelloHash);
                }
            }
            _state.ClientHelloSent();
            return new TlsQuicProcessResult(events);
        }
        catch
        {
            Fail();
            throw;
        }
    }

    /// <summary>
    /// Supplies an arbitrary, possibly overlapping CRYPTO frame. Matching retransmissions and
    /// gaps are handled internally; newly contiguous Handshake messages are processed atomically.
    /// </summary>
    public async ValueTask<TlsQuicProcessResult> ProcessCryptoDataAsync(
        TlsQuicEncryptionLevel level,
        ulong offset,
        ReadOnlyMemory<byte> data,
        CancellationToken cancellationToken = default)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (!_started || _failed)
        {
            throw new InvalidOperationException("The QUIC TLS handshake is not active.");
        }
        if (!Enum.IsDefined(level) || level == TlsQuicEncryptionLevel.EarlyData)
        {
            throw new TlsQuicTransportException(
                TlsQuicTransportError.ProtocolViolation,
                "QUIC CRYPTO frames cannot use the 0-RTT encryption level.");
        }

        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        var events = new List<TlsQuicEvent>();
        try
        {
            cancellationToken.ThrowIfCancellationRequested();
            var contiguous = GetReassembler(level).Add(offset, data.Span);
            if (contiguous.Length == 0)
            {
                return new TlsQuicProcessResult(events);
            }

            var deframer = GetDeframer(level);
            deframer.Append(contiguous);
            while (deframer.TryRead(out var message))
            {
                cancellationToken.ThrowIfCancellationRequested();
                switch (level)
                {
                    case TlsQuicEncryptionLevel.Initial:
                        ProcessInitialMessage(message!, events);
                        break;
                    case TlsQuicEncryptionLevel.Handshake:
                        await ProcessHandshakeMessageAsync(
                            message!,
                            events,
                            cancellationToken).ConfigureAwait(false);
                        break;
                    case TlsQuicEncryptionLevel.Application:
                        ProcessApplicationMessage(message!);
                        break;
                    default:
                        throw new TlsQuicTransportException(
                            TlsQuicTransportError.ProtocolViolation,
                            "Unsupported CRYPTO encryption level.");
                }
            }
            return new TlsQuicProcessResult(events);
        }
        catch
        {
            foreach (var item in events.OfType<IDisposable>())
            {
                item.Dispose();
            }
            Fail();
            throw;
        }
        finally
        {
            _gate.Release();
        }
    }

    /// <summary>
    /// Notifies TLS that the client has sent its first Handshake packet. RFC 9001 then permits
    /// client Initial-key disposal. The notification is idempotent after the transition.
    /// </summary>
    public TlsQuicProcessResult NotifyHandshakePacketSent()
    {
        EnsureActive();
        if (_initialKeysDiscarded)
        {
            return new TlsQuicProcessResult([]);
        }
        if (_serverHello is null)
        {
            throw new InvalidOperationException(
                "Handshake packet notification cannot precede the final ServerHello.");
        }
        _initialReassembler.Discard();
        _initialKeysDiscarded = true;
        return new TlsQuicProcessResult(
            [new TlsQuicDiscardKeysEvent(TlsQuicEncryptionLevel.Initial)]);
    }

    /// <summary>
    /// Marks receipt of QUIC HANDSHAKE_DONE. Only a client calls this; it releases Handshake keys.
    /// </summary>
    public TlsQuicProcessResult ConfirmHandshake()
    {
        EnsureActive();
        if (!IsHandshakeComplete)
        {
            throw new InvalidOperationException("TLS has not completed the handshake.");
        }
        if (_handshakeConfirmed)
        {
            return new TlsQuicProcessResult([]);
        }
        _handshakeReassembler.Discard();
        _handshakeConfirmed = true;
        return new TlsQuicProcessResult(
            [new TlsQuicDiscardKeysEvent(TlsQuicEncryptionLevel.Handshake)]);
    }

    private void ProcessInitialMessage(HandshakeMessage message, List<TlsQuicEvent> events)
    {
        if (message.Type != HandshakeType.ServerHello)
        {
            throw TlsProtocolException.Unexpected(
                "QUIC Initial CRYPTO contained a message other than ServerHello or HelloRetryRequest.");
        }
        if (_serverHello is not null)
        {
            throw TlsProtocolException.Unexpected("QUIC received another ServerHello.");
        }

        var offer = _offer ?? throw new InvalidOperationException("ClientHello is unavailable.");
        if (_firstEchOffer is not null && !_helloRetryRequestSuite.HasValue)
        {
            var selectedSuite = EchAcceptanceConfirmation.ReadCipherSuite(message.Encoded);
            EncryptedClientHelloAccepted = EchAcceptanceConfirmation.IsHelloRetryRequest(
                message.Encoded)
                ? EchAcceptanceConfirmation.VerifyHelloRetryRequest(
                    selectedSuite,
                    _firstEchOffer.Inner.EncodedHandshake,
                    message.Encoded)
                : EchAcceptanceConfirmation.VerifyServerHello(
                    selectedSuite,
                    _firstEchOffer.Inner.EncodedHandshake,
                    message.Encoded);
            _echRejected = !EncryptedClientHelloAccepted;
            _offer = EncryptedClientHelloAccepted
                ? _firstEchOffer.Inner
                : _firstEchOffer.Outer;
            offer = _offer;
        }
        var parsed = ServerHelloParser.Parse(
            message.Body,
            offer,
            _helloRetryRequestSuite,
            _helloRetryRequestGroup);
        var suite = CipherSuiteInfo.Get(parsed.CipherSuite);
        if (parsed.IsHelloRetryRequest)
        {
            if (_helloRetryRequestSuite.HasValue)
            {
                throw TlsProtocolException.Unexpected("A second HelloRetryRequest is forbidden.");
            }
            _transcript = new TranscriptHash(suite);
            _transcript.ResetForHelloRetryRequest(offer.EncodedHandshake);
            _transcript.Append(message.Encoded);
            _state.HelloRetryRequestReceived();
            _helloRetryRequestSuite = parsed.CipherSuite;
            _helloRetryRequestGroup = parsed.SelectedGroup;
            _helloRetryRequestEncoded = (byte[])message.Encoded.Clone();
            _earlyKeySchedule?.Dispose();
            _earlyKeySchedule = null;

            Tls13PskOffer? retryPskOffer = null;
            if (_offeredTicket is not null)
            {
                var binderPrefix = CreateHelloRetryRequestBinderPrefix(
                    _offeredTicket.CipherSuite,
                    offer.EncodedHandshake,
                    message.Encoded);
                retryPskOffer = new Tls13PskOffer(
                    _offeredTicket,
                    _configuration.Shared.SessionCache!.UtcNow,
                    binderPrefix);
            }
            ClientHelloBuildResult wireRetryOffer;
            if (_firstEchOffer is not null && EncryptedClientHelloAccepted)
            {
                _retryEchOffer = EchClientHelloBuilder.BuildRetry(
                    _firstEchOffer,
                    parsed.SelectedGroup,
                    parsed.Cookie,
                    SecureRandomSource.Instance,
                    new KeyShareSet(),
                    new KeyShareSet(),
                    retryPskOffer);
                _offer = _retryEchOffer.Inner;
                wireRetryOffer = _retryEchOffer.Outer;
            }
            else if (_firstEchOffer is not null)
            {
                _offer = EchClientHelloBuilder.BuildOuterRetryAfterRejection(
                    _firstEchOffer,
                    parsed.SelectedGroup,
                    parsed.Cookie,
                    SecureRandomSource.Instance,
                    new KeyShareSet(),
                    retryPskOffer);
                wireRetryOffer = _offer;
            }
            else
            {
                var retryOffer = ClientHelloEncoder.BuildRetry(
                    offer,
                    parsed.SelectedGroup,
                    parsed.Cookie,
                    retryPskOffer);
                offer.Dispose();
                _offer = retryOffer;
                wireRetryOffer = retryOffer;
            }
            _transcript.Append(_offer.EncodedHandshake);
            events.Add(CreateCryptoEvent(
                TlsQuicEncryptionLevel.Initial,
                ref _initialWriteOffset,
                wireRetryOffer.EncodedHandshake));
            _state.SecondClientHelloSent();
            return;
        }

        if (_initialDeframer.BufferedBytes != 0)
        {
            throw TlsProtocolException.Unexpected(
                "ServerHello was not aligned to the QUIC Initial encryption-level transition.");
        }
        _transcript ??= new TranscriptHash(suite);
        if (_firstEchOffer is not null && EncryptedClientHelloAccepted &&
            _helloRetryRequestSuite.HasValue &&
            !EchAcceptanceConfirmation.VerifyServerHelloAfterHelloRetryRequest(
                suite.Suite,
                _firstEchOffer.Inner.EncodedHandshake,
                _helloRetryRequestEncoded!,
                _retryEchOffer!.Inner.EncodedHandshake,
                message.Encoded))
        {
            throw TlsProtocolException.Illegal(
                "QUIC server accepted ECH in HelloRetryRequest but not in ServerHello.");
        }
        if (!_helloRetryRequestSuite.HasValue)
        {
            _transcript.Append(offer.EncodedHandshake);
        }
        _transcript.Append(message.Encoded);
        _state.ServerHelloReceived();
        _serverHello = parsed;
        _suite = suite;

        if (_echRejected && parsed.SelectedPskIdentity.HasValue)
        {
            throw TlsProtocolException.Illegal(
                "An ECH-rejecting QUIC server selected ClientHelloOuter GREASE PSK.");
        }

        if (parsed.SelectedPskIdentity.HasValue)
        {
            if (parsed.SelectedPskIdentity.Value != 0 || _offeredTicket is null)
            {
                throw TlsProtocolException.Illegal(
                    "QUIC ServerHello selected an unavailable PSK identity.");
            }
            var ticketHash = CipherSuiteInfo.Get(_offeredTicket.CipherSuite).HashAlgorithm.Name;
            if (!string.Equals(ticketHash, suite.HashAlgorithm.Name, StringComparison.Ordinal))
            {
                throw TlsProtocolException.Illegal(
                    "QUIC ServerHello selected a cipher suite incompatible with the ticket PSK.");
            }
            SessionWasResumed = true;
        }

        var sharedSecret = offer.KeyShares.Get(parsed.SelectedGroup)
            .DeriveSharedSecret(parsed.PeerKeyExchange!);
        byte[]? psk = null;
        try
        {
            if (SessionWasResumed)
            {
                psk = _offeredTicket!.CopyPsk();
            }
            if (SessionWasResumed && _earlyKeySchedule is not null &&
                _offeredTicket!.CipherSuite == suite.Suite)
            {
                _keySchedule = _earlyKeySchedule;
                _earlyKeySchedule = null;
            }
            else
            {
                _earlyKeySchedule?.Dispose();
                _earlyKeySchedule = null;
                _keySchedule = new Tls13KeySchedule(
                    suite,
                    psk is null ? default : psk);
            }
            _keySchedule.DeriveHandshakeSecrets(sharedSecret, _transcript.CurrentHash());
            _keySchedule.DeriveMainSecret();
            AddTrafficSecret(
                events,
                TlsQuicEncryptionLevel.Handshake,
                TlsQuicSecretDirection.Read,
                parsed.CipherSuite,
                _keySchedule.CopyServerHandshakeTrafficSecret());
            AddTrafficSecret(
                events,
                TlsQuicEncryptionLevel.Handshake,
                TlsQuicSecretDirection.Write,
                parsed.CipherSuite,
                _keySchedule.CopyClientHandshakeTrafficSecret());
        }
        finally
        {
            CryptographicOperations.ZeroMemory(sharedSecret);
            if (psk is not null)
            {
                CryptographicOperations.ZeroMemory(psk);
            }
        }
    }

    private async ValueTask ProcessHandshakeMessageAsync(
        HandshakeMessage message,
        List<TlsQuicEvent> events,
        CancellationToken cancellationToken)
    {
        if (_serverHello is null || _suite is null ||
            _keySchedule is null || _transcript is null || _offer is null)
        {
            throw TlsProtocolException.Unexpected(
                "Handshake-level CRYPTO arrived before the final ServerHello.");
        }
        if (IsHandshakeComplete)
        {
            throw TlsProtocolException.Unexpected(
                "New Handshake-level TLS data arrived after client Finished.");
        }

        switch (message.Type)
        {
            case HandshakeType.EncryptedExtensions:
                var encryptedExtensions = EncryptedExtensionsParser.Parse(
                    message.Body,
                    _offer.Configuration,
                    offeredEarlyData: _attemptedEarlyData,
                    echWasRejected: _echRejected,
                    echWasGreased: _echGreased);
                _echRetryConfigurations = encryptedExtensions.EchRetryConfigurations;
                if (encryptedExtensions.NegotiatedAlpn is null)
                {
                    throw new TlsProtocolException(
                        TlsAlertDescription.MissingExtension,
                        "A QUIC server must select ALPN in EncryptedExtensions.");
                }
                if (encryptedExtensions.PeerQuicTransportParameters is null)
                {
                    throw new TlsProtocolException(
                        TlsAlertDescription.MissingExtension,
                        "A QUIC server omitted quic_transport_parameters.");
                }
                NegotiatedApplicationProtocol = encryptedExtensions.NegotiatedAlpn;
                _peerTransportParameters = encryptedExtensions.PeerQuicTransportParameters;
                if (encryptedExtensions.EarlyDataAccepted)
                {
                    if (!SessionWasResumed || _helloRetryRequestSuite.HasValue)
                    {
                        throw TlsProtocolException.Illegal(
                            "QUIC server accepted early_data without eligible resumption.");
                    }
                    EarlyDataStatus = Tls13EarlyDataStatus.Accepted;
                }
                _transcript.Append(message.Encoded);
                _state.EncryptedExtensionsReceived();
                break;

            case HandshakeType.CertificateRequest:
                if (SessionWasResumed)
                {
                    throw TlsProtocolException.Unexpected(
                        "A PSK-resumed QUIC handshake sent CertificateRequest.");
                }
                if (_certificateRequest is not null)
                {
                    throw TlsProtocolException.Unexpected(
                        "Server sent multiple initial CertificateRequest messages.");
                }
                _certificateRequest = CertificateRequestParser.ParseInitial(message.Body);
                _transcript.Append(message.Encoded);
                _state.CertificateRequestReceived();
                break;

            case HandshakeType.Certificate:
                if (SessionWasResumed)
                {
                    throw TlsProtocolException.Unexpected(
                        "A PSK-resumed QUIC handshake sent Certificate.");
                }
                await ProcessCertificateAsync(
                    CertificateMessageParser.Parse(
                        message.Body,
                        _configuration.Shared.Limits,
                        _offer.Configuration),
                    message,
                    cancellationToken).ConfigureAwait(false);
                break;

            case HandshakeType.CompressedCertificate:
                if (SessionWasResumed)
                {
                    throw TlsProtocolException.Unexpected(
                        "A PSK-resumed QUIC handshake sent CompressedCertificate.");
                }
                var decompressed = CompressedCertificateParser.Decompress(
                    message.Body,
                    _offer.Configuration,
                    _configuration.Shared.Limits);
                await ProcessCertificateAsync(
                    CertificateMessageParser.Parse(
                        decompressed,
                        _configuration.Shared.Limits,
                        _offer.Configuration),
                    message,
                    cancellationToken).ConfigureAwait(false);
                break;

            case HandshakeType.CertificateVerify:
                if (SessionWasResumed)
                {
                    throw TlsProtocolException.Unexpected(
                        "A PSK-resumed QUIC handshake sent CertificateVerify.");
                }
                if (_certificates is null)
                {
                    throw TlsProtocolException.Unexpected(
                        "CertificateVerify arrived before Certificate.");
                }
                _ = ServerCertificateValidator.ParseAndVerifyCertificateVerify(
                    message.Body,
                    _certificates.Leaf,
                    _offer.Configuration.SignatureAlgorithms,
                    _transcript.CurrentHash(),
                    _certificates.DelegatedCredential);
                _transcript.Append(message.Encoded);
                _state.CertificateVerifyReceived();
                break;

            case HandshakeType.Finished:
                await ProcessServerFinishedAsync(
                    message,
                    events,
                    cancellationToken).ConfigureAwait(false);
                break;

            case HandshakeType.EndOfEarlyData:
            case HandshakeType.KeyUpdate:
                throw TlsProtocolException.Unexpected(
                    $"QUIC forbids TLS {message.Type} messages.");

            default:
                throw TlsProtocolException.Unexpected(
                    $"Unexpected QUIC handshake message {message.Type}.");
        }
    }

    private async ValueTask ProcessCertificateAsync(
        ServerCertificateMessage certificates,
        HandshakeMessage wireMessage,
        CancellationToken cancellationToken)
    {
        if (_certificates is not null)
        {
            certificates.Dispose();
            throw TlsProtocolException.Unexpected("Server sent multiple Certificate messages.");
        }
        _certificates = certificates;
        var authenticatedName = _echRejected
            ? _configuration.Shared.Ech!.Selection.Configuration.PublicName
            : _configuration.ServerName;
        ServerCertificateValidator.ValidateChainAndHostname(
            certificates,
            authenticatedName,
            _configuration.Shared.CertificateValidation);
        _peerCertificateChain = certificates.Certificates
            .Select(certificate => certificate.RawData)
            .ToArray();
        if (_configuration.Shared.SessionCache is { } cache)
        {
            _authenticationExpiresAt = cache.GetAuthenticationExpiry(
                new DateTimeOffset(certificates.Leaf.NotAfter.ToUniversalTime()));
        }
        await ValidateCertificateEvidenceAsync(certificates, cancellationToken).ConfigureAwait(false);
        cancellationToken.ThrowIfCancellationRequested();
        _transcript!.Append(wireMessage.Encoded);
        _state.CertificateReceived();
    }

    private async ValueTask ProcessServerFinishedAsync(
        HandshakeMessage message,
        List<TlsQuicEvent> events,
        CancellationToken cancellationToken)
    {
        var keySchedule = _keySchedule ??
            throw new InvalidOperationException("TLS key schedule is unavailable.");
        var transcript = _transcript ??
            throw new InvalidOperationException("TLS transcript is unavailable.");
        FinishedProcessor.VerifyServerFinished(
            message.Body,
            keySchedule,
            transcript.CurrentHash());
        transcript.Append(message.Encoded);
        _state.ServerFinishedReceived(SessionWasResumed);
        if (_handshakeDeframer.BufferedBytes != 0)
        {
            throw TlsProtocolException.Unexpected(
                "Server Finished was not aligned to the QUIC application encryption-level transition.");
        }

        if (_echRejected)
        {
            NegotiatedApplicationProtocol = null;
            _peerTransportParameters = null;
            throw new TlsEchRejectedException(
                _configuration.Shared.Ech!.Selection.Configuration.PublicName,
                _echRetryConfigurations);
        }

        keySchedule.DeriveApplicationTrafficSecrets(transcript.CurrentHash());
        AddTrafficSecret(
            events,
            TlsQuicEncryptionLevel.Application,
            TlsQuicSecretDirection.Read,
            _suite!.Suite,
            keySchedule.CopyServerApplicationTrafficSecret());
        AddTrafficSecret(
            events,
            TlsQuicEncryptionLevel.Application,
            TlsQuicSecretDirection.Write,
            _suite.Suite,
            keySchedule.CopyClientApplicationTrafficSecret());

        if (_peerTransportParameters is null || NegotiatedApplicationProtocol is null)
        {
            throw TlsProtocolException.Unexpected(
                "Authenticated QUIC handshake state is incomplete.");
        }
        events.Add(new TlsQuicPeerTransportParametersEvent(_peerTransportParameters));

        if (_certificateRequest is not null)
        {
            await AddClientAuthenticationAsync(events, cancellationToken).ConfigureAwait(false);
        }

        var clientFinished = FinishedProcessor.CreateClientFinished(
            keySchedule,
            transcript.CurrentHash());
        transcript.Append(clientFinished);
        events.Add(CreateCryptoEvent(
            TlsQuicEncryptionLevel.Handshake,
            ref _handshakeWriteOffset,
            clientFinished));
        _state.ClientFinishedSent();
        if (_configuration.Shared.SessionCache is not null)
        {
            _authenticationExpiresAt = SessionWasResumed
                ? _offeredTicket!.AuthenticationExpiresAt
                : _authenticationExpiresAt ?? throw TlsProtocolException.Unexpected(
                    "Certificate authentication completed without a cache lifetime.");
            keySchedule.DeriveResumptionMasterSecret(transcript.CurrentHash());
        }
        NegotiatedCipherSuite = _suite.Suite;
        NegotiatedGroup = _serverHello!.SelectedGroup;
        events.Add(new TlsQuicHandshakeCompletedEvent(
            _suite.Suite,
            _serverHello.SelectedGroup,
            NegotiatedApplicationProtocol));

        _certificates?.Dispose();
        _certificates = null;
    }

    private async ValueTask AddClientAuthenticationAsync(
        List<TlsQuicEvent> events,
        CancellationToken cancellationToken)
    {
        var request = _certificateRequest!;
        var credential = _configuration.Shared.ClientCertificateSelector is null
            ? _configuration.Shared.ClientCertificate
            : await _configuration.Shared.ClientCertificateSelector(
                new TlsClientCertificateSelectionContext(
                    _configuration.ServerName,
                    TlsProtocolVersion.Tls13,
                    isPostHandshake: false,
                    request.SignatureSchemes,
                    request.DelegatedCredentialSignatureSchemes,
                    []),
                cancellationToken).ConfigureAwait(false);
        cancellationToken.ThrowIfCancellationRequested();
        var authentication = credential?.SelectTls13Authentication(
            request.SignatureSchemes,
            request.DelegatedCredentialSignatureSchemes);
        if (!authentication.HasValue)
        {
            credential = null;
        }

        var certificate = ClientAuthenticationMessages.CreateTls13Certificate(
            request.Context,
            credential,
            _configuration.Shared.Limits,
            authentication?.DelegatedCredential);
        _transcript!.Append(certificate);
        events.Add(CreateCryptoEvent(
            TlsQuicEncryptionLevel.Handshake,
            ref _handshakeWriteOffset,
            certificate));
        _state.ClientCertificateSent(credential is not null);

        if (credential is null)
        {
            return;
        }
        var transcriptHash = _transcript.CurrentHash();
        try
        {
            var certificateVerify = await ClientAuthenticationMessages
                .CreateTls13CertificateVerifyAsync(
                    credential,
                    authentication!.Value.SignatureScheme,
                    transcriptHash,
                    cancellationToken,
                    authentication.Value.DelegatedCredential).ConfigureAwait(false);
            _transcript.Append(certificateVerify);
            events.Add(CreateCryptoEvent(
                TlsQuicEncryptionLevel.Handshake,
                ref _handshakeWriteOffset,
                certificateVerify));
            _state.ClientCertificateVerifySent();
        }
        finally
        {
            CryptographicOperations.ZeroMemory(transcriptHash);
        }
    }

    private void ProcessApplicationMessage(HandshakeMessage message)
    {
        if (!IsHandshakeComplete)
        {
            throw TlsProtocolException.Unexpected(
                "Application-level CRYPTO arrived before client Finished.");
        }
        if (message.Type == HandshakeType.KeyUpdate)
        {
            throw TlsProtocolException.Unexpected("QUIC forbids the TLS KeyUpdate message.");
        }
        if (message.Type != HandshakeType.NewSessionTicket)
        {
            throw TlsProtocolException.Unexpected(
                $"QUIC received forbidden post-handshake message {message.Type}.");
        }
        var ticket = Tls13NewSessionTicketParser.Parse(message.Body);
        if (++_receivedSessionTickets >
            _configuration.Shared.Limits.MaxSessionTicketsPerConnection)
        {
            throw TlsProtocolException.Unexpected(
                "The peer exceeded the configured NewSessionTicket limit.");
        }
        var nonceKey = Convert.ToHexString(ticket.Nonce);
        if (!_receivedTicketNonces.Add(nonceKey))
        {
            throw TlsProtocolException.Illegal(
                "The QUIC peer reused a NewSessionTicket nonce on one connection.");
        }
        if (_configuration.Shared.SessionCache is not { } cache ||
            ticket.LifetimeSeconds is 0 or > Tls13NewSessionTicketParser.MaximumLifetimeSeconds)
        {
            return;
        }
        var schedule = _keySchedule ?? throw TlsProtocolException.Unexpected(
            "QUIC NewSessionTicket arrived before resumption secrets were derived.");
        var authenticationExpiresAt = _authenticationExpiresAt ??
            throw new InvalidOperationException("QUIC authentication lifetime is unavailable.");
        var issuedAt = cache.UtcNow;
        var expiresAt = issuedAt.AddSeconds(ticket.LifetimeSeconds);
        if (expiresAt > authenticationExpiresAt)
        {
            expiresAt = authenticationExpiresAt;
        }
        if (expiresAt <= issuedAt)
        {
            return;
        }
        var psk = schedule.DeriveResumptionPsk(ticket.Nonce);
        try
        {
            cache.Add(new Tls13SessionTicket(
                Tls13SessionOrigin.Create(
                    _configuration.ServerName,
                    _configuration.ServerPort),
                NegotiatedCipherSuite!.Value,
                NegotiatedApplicationProtocol,
                ticket.AgeAdd,
                ticket.Identity,
                psk,
                issuedAt,
                expiresAt,
                authenticationExpiresAt,
                ticket.MaximumEarlyDataSize,
                echConfigListHash: _configuration.Shared.Ech?.ConfigListHash,
                quicTransportParameters: _peerTransportParameters!.Encode()));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(psk);
        }
    }

    private static byte[] CreateHelloRetryRequestBinderPrefix(
        TlsCipherSuite ticketCipherSuite,
        ReadOnlySpan<byte> firstClientHello,
        ReadOnlySpan<byte> helloRetryRequest)
    {
        var suite = CipherSuiteInfo.Get(ticketCipherSuite);
        var firstHash = suite.HashAlgorithm.Name switch
        {
            "SHA256" => SHA256.HashData(firstClientHello),
            "SHA384" => SHA384.HashData(firstClientHello),
            _ => throw new NotSupportedException(),
        };
        try
        {
            var messageHash = HandshakeMessage.Encode(HandshakeType.MessageHash, firstHash);
            var prefix = new byte[messageHash.Length + helloRetryRequest.Length];
            messageHash.CopyTo(prefix, 0);
            helloRetryRequest.CopyTo(prefix.AsSpan(messageHash.Length));
            return prefix;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(firstHash);
        }
    }

    private static byte[] HashHandshake(CipherSuiteInfo suite, ReadOnlySpan<byte> handshake) =>
        suite.HashAlgorithm.Name switch
        {
            "SHA256" => SHA256.HashData(handshake),
            "SHA384" => SHA384.HashData(handshake),
            _ => throw new NotSupportedException(),
        };

    private async ValueTask ValidateCertificateEvidenceAsync(
        ServerCertificateMessage certificates,
        CancellationToken cancellationToken)
    {
        var policy = _configuration.Shared.CertificateValidation;
        if (policy.EvidenceValidator is null)
        {
            return;
        }
        var evidence = new TlsServerCertificateEvidence(
            _echRejected
                ? _configuration.Shared.Ech!.Selection.Configuration.PublicName
                : _configuration.ServerName,
            TlsProtocolVersion.Tls13,
            certificates.Certificates.Select(certificate => certificate.RawData).ToArray(),
            certificates.LeafOcspResponse,
            certificates.LeafSignedCertificateTimestamps);
        TlsServerCertificateEvidenceValidationResult result;
        try
        {
            result = await policy.EvidenceValidator(evidence, cancellationToken)
                .ConfigureAwait(false) ??
                throw new InvalidOperationException(
                    "The certificate-evidence validator returned null.");
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (TlsProtocolException)
        {
            throw;
        }
        catch (Exception exception)
        {
            throw new TlsProtocolException(
                TlsAlertDescription.CertificateUnknown,
                "The additional certificate-evidence validator failed.",
                exception);
        }

        if (result.ValidSignedCertificateTimestampCount >
            certificates.LeafSignedCertificateTimestamps.Count)
        {
            throw new TlsProtocolException(
                TlsAlertDescription.CertificateUnknown,
                "The certificate-evidence validator reported more valid SCTs than supplied.");
        }
        if (result.StapledOcspStatus == TlsStapledOcspValidationStatus.Revoked)
        {
            throw new TlsProtocolException(
                TlsAlertDescription.CertificateRevoked,
                "The stapled OCSP response proves revocation.");
        }
        if (result.StapledOcspStatus is TlsStapledOcspValidationStatus.Invalid or
                TlsStapledOcspValidationStatus.Unknown ||
            (result.StapledOcspStatus == TlsStapledOcspValidationStatus.Good &&
             certificates.LeafOcspResponse is null) ||
            (policy.RequireValidStapledOcspResponse &&
             result.StapledOcspStatus != TlsStapledOcspValidationStatus.Good))
        {
            throw new TlsProtocolException(
                TlsAlertDescription.BadCertificateStatusResponse,
                "The stapled OCSP response did not satisfy certificate policy.");
        }
        if (result.ValidSignedCertificateTimestampCount <
            policy.MinimumValidSignedCertificateTimestamps)
        {
            throw new TlsProtocolException(
                TlsAlertDescription.CertificateUnknown,
                "The server did not supply enough policy-valid certificate transparency timestamps.");
        }
    }

    private static void AddTrafficSecret(
        List<TlsQuicEvent> events,
        TlsQuicEncryptionLevel level,
        TlsQuicSecretDirection direction,
        TlsCipherSuite suite,
        byte[] secret)
    {
        try
        {
            events.Add(new TlsQuicTrafficSecretEvent(
                new TlsQuicTrafficSecret(level, direction, suite, secret)));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(secret);
        }
    }

    private static TlsQuicCryptoDataEvent CreateCryptoEvent(
        TlsQuicEncryptionLevel level,
        ref ulong offset,
        ReadOnlySpan<byte> data)
    {
        var result = new TlsQuicCryptoDataEvent(level, offset, data);
        offset = checked(offset + (ulong)data.Length);
        return result;
    }

    private TlsQuicCryptoStreamReassembler GetReassembler(
        TlsQuicEncryptionLevel level) => level switch
    {
        TlsQuicEncryptionLevel.Initial => _initialReassembler,
        TlsQuicEncryptionLevel.Handshake => _handshakeReassembler,
        TlsQuicEncryptionLevel.Application => _applicationReassembler,
        _ => throw new ArgumentOutOfRangeException(nameof(level)),
    };

    private HandshakeDeframer GetDeframer(TlsQuicEncryptionLevel level) => level switch
    {
        TlsQuicEncryptionLevel.Initial => _initialDeframer,
        TlsQuicEncryptionLevel.Handshake => _handshakeDeframer,
        TlsQuicEncryptionLevel.Application => _applicationDeframer,
        _ => throw new ArgumentOutOfRangeException(nameof(level)),
    };

    private void EnsureActive()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (!_started || _failed)
        {
            throw new InvalidOperationException("The QUIC TLS handshake is not active.");
        }
    }

    private void Fail()
    {
        _failed = true;
        _state.Fail();
    }

    /// <inheritdoc />
    public async ValueTask DisposeAsync()
    {
        if (_disposed)
        {
            return;
        }
        await _gate.WaitAsync().ConfigureAwait(false);
        try
        {
            if (_disposed)
            {
                return;
            }
            _disposed = true;
            _offer?.Dispose();
            _retryEchOffer?.Dispose();
            _firstEchOffer?.Dispose();
            _transcript?.Dispose();
            _keySchedule?.Dispose();
            _earlyKeySchedule?.Dispose();
            _offeredTicket?.Dispose();
            _certificates?.Dispose();
            if (_helloRetryRequestEncoded is not null)
            {
                CryptographicOperations.ZeroMemory(_helloRetryRequestEncoded);
            }
            _configuration.Dispose();
        }
        finally
        {
            _gate.Release();
            _gate.Dispose();
        }
    }
}
