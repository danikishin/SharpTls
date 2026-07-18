using System.Buffers.Binary;
using System.Security.Cryptography;
using SharpTls.Certificates;
using SharpTls.Cryptography;
using SharpTls.Ech;
using SharpTls.Handshake;
using SharpTls.IO;
using SharpTls.Protocol;
using SharpTls.Sessions;

namespace SharpTls.Quic;

/// <summary>
/// A recordless TLS 1.3 server state machine for QUIC. The caller owns packets,
/// CRYPTO frames, loss recovery, packet protection and HANDSHAKE_DONE.
/// </summary>
public sealed class CustomTlsQuicServer : IAsyncDisposable
{
    private readonly CustomTlsQuicServerConfiguration _configuration;
    private readonly Tls13ServerStateMachine _state = new();
    private readonly HandshakeDeframer _initialDeframer;
    private readonly HandshakeDeframer _handshakeDeframer;
    private readonly HandshakeDeframer _applicationDeframer;
    private readonly TlsQuicCryptoStreamReassembler _initialReassembler;
    private readonly TlsQuicCryptoStreamReassembler _handshakeReassembler;
    private readonly TlsQuicCryptoStreamReassembler _applicationReassembler;
    private readonly SemaphoreSlim _gate = new(1, 1);
    private readonly TlsEchServerReceiver? _echReceiver;
    private TranscriptHash? _transcript;
    private Tls13KeySchedule? _keySchedule;
    private CipherSuiteInfo? _suite;
    private Tls13ParsedClientHello? _firstHello;
    private HandshakeMessage? _firstWireClientHello;
    private HandshakeMessage? _firstInnerClientHello;
    private byte[]? _helloRetryRequest;
    private TlsQuicTransportParameters? _peerTransportParameters;
    private ClientCertificateMessage? _clientCertificates;
    private byte[][] _peerCertificateChain = [];
    private TlsCipherSuite? _retrySuite;
    private NamedGroup? _retryGroup;
    private ulong _initialWriteOffset;
    private ulong _handshakeWriteOffset;
    private ulong _applicationWriteOffset;
    private bool _awaitingClientCertificate;
    private bool _awaitingClientCertificateVerify;
    private bool _initialKeysDiscarded;
    private bool _failed;
    private bool _disposed;
    private int _issuedSessionTickets;

    /// <summary>Creates one recordless QUIC TLS server connection.</summary>
    public CustomTlsQuicServer(CustomTlsQuicServerOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);
        _configuration = options.Snapshot();
        var maximumMessage = _configuration.Shared.Limits.MaxHandshakeMessageSize;
        _initialDeframer = new HandshakeDeframer(maximumMessage);
        _handshakeDeframer = new HandshakeDeframer(maximumMessage);
        _applicationDeframer = new HandshakeDeframer(maximumMessage);
        _initialReassembler = new TlsQuicCryptoStreamReassembler(
            _configuration.MaximumCryptoStreamLength);
        _handshakeReassembler = new TlsQuicCryptoStreamReassembler(
            _configuration.MaximumCryptoStreamLength);
        _applicationReassembler = new TlsQuicCryptoStreamReassembler(
            _configuration.MaximumCryptoStreamLength);
        _echReceiver = _configuration.Shared.EncryptedClientHelloKeys.Length == 0
            ? null
            : new TlsEchServerReceiver(_configuration.Shared.EncryptedClientHelloKeys);
        _state.TransportAccepted();
    }

    /// <summary>Gets whether the authenticated client Finished has completed.</summary>
    public bool IsHandshakeComplete =>
        !_disposed && _state.State == Tls13ServerState.Connected;

    /// <summary>Gets the offered SNI host name, or null.</summary>
    public string? ServerName { get; private set; }

    /// <summary>Gets whether ClientHelloOuter carried encrypted_client_hello.</summary>
    public bool EncryptedClientHelloOffered { get; private set; }

    /// <summary>Gets whether RFC 9849 ClientHelloInner was decrypted and authenticated.</summary>
    public bool EncryptedClientHelloAccepted { get; private set; }

    /// <summary>Gets the unauthenticated outer SNI observed before ECH processing.</summary>
    public string? EncryptedClientHelloOuterServerName { get; private set; }

    /// <summary>Gets the mandatory negotiated ALPN protocol.</summary>
    public string? NegotiatedApplicationProtocol { get; private set; }

    /// <summary>Gets the negotiated TLS 1.3 cipher suite.</summary>
    public TlsCipherSuite? NegotiatedCipherSuite { get; private set; }

    /// <summary>Gets the negotiated ECDHE group.</summary>
    public NamedGroup? NegotiatedGroup { get; private set; }

    /// <summary>Gets whether this connection authenticated with a TLS 1.3 PSK ticket.</summary>
    public bool SessionWasResumed { get; private set; }

    /// <summary>Gets whether this handshake used HelloRetryRequest.</summary>
    public bool HandshakeUsedHelloRetryRequest => _retrySuite.HasValue;

    /// <summary>Gets whether authenticated replayable client 0-RTT was accepted.</summary>
    public bool EarlyDataAccepted { get; private set; }

    /// <summary>Gets the number of recordless NewSessionTicket messages emitted.</summary>
    public int IssuedSessionTicketCount => Volatile.Read(ref _issuedSessionTickets);

    /// <summary>Gets defensive DER copies of the authenticated client certificate chain.</summary>
    public IReadOnlyList<byte[]> PeerCertificateChain => Array.AsReadOnly(
        _peerCertificateChain.Select(value => (byte[])value.Clone()).ToArray());

    /// <summary>
    /// Supplies an arbitrary, possibly overlapping peer CRYPTO frame and returns an
    /// atomic batch of output bytes, traffic secrets and key-discard transitions.
    /// </summary>
    public async ValueTask<TlsQuicProcessResult> ProcessCryptoDataAsync(
        TlsQuicEncryptionLevel level,
        ulong offset,
        ReadOnlyMemory<byte> data,
        CancellationToken cancellationToken = default)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (_failed)
        {
            throw new InvalidOperationException("The QUIC TLS server handshake has failed.");
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
            if (level == TlsQuicEncryptionLevel.Application && !IsHandshakeComplete)
            {
                throw TlsProtocolException.Unexpected(
                    "Application-level CRYPTO arrived before client Finished.");
            }
            if (level == TlsQuicEncryptionLevel.Handshake && !_initialKeysDiscarded)
            {
                if (_state.State != Tls13ServerState.AwaitingClientFinished)
                {
                    throw TlsProtocolException.Unexpected(
                        "Handshake-level CRYPTO arrived before the server flight.");
                }
                _initialReassembler.Discard();
                _initialKeysDiscarded = true;
                events.Add(new TlsQuicDiscardKeysEvent(TlsQuicEncryptionLevel.Initial));
            }

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
                        await ProcessClientHelloAsync(
                            message!,
                            events,
                            cancellationToken).ConfigureAwait(false);
                        break;
                    case TlsQuicEncryptionLevel.Handshake:
                        ProcessClientHandshakeMessage(message!, events);
                        break;
                    case TlsQuicEncryptionLevel.Application:
                        ProcessApplicationMessage(message!);
                        break;
                    default:
                        throw new TlsQuicTransportException(
                            TlsQuicTransportError.ProtocolViolation,
                            "Unsupported QUIC encryption level.");
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

    private async ValueTask ProcessClientHelloAsync(
        HandshakeMessage message,
        List<TlsQuicEvent> events,
        CancellationToken cancellationToken)
    {
        if (message.Type != HandshakeType.ClientHello)
        {
            throw TlsProtocolException.Unexpected(
                "QUIC Initial CRYPTO contained a message other than ClientHello.");
        }
        if (_state.State is not (
            Tls13ServerState.AwaitingClientHello or
            Tls13ServerState.AwaitingSecondClientHello))
        {
            throw TlsProtocolException.Unexpected("QUIC received an additional ClientHello.");
        }

        if (_firstHello is null)
        {
            _firstWireClientHello = message;
            var outerHello = Tls13ClientHelloParser.Parse(message.Body);
            EncryptedClientHelloOuterServerName = outerHello.ServerName;
            EncryptedClientHelloOffered = outerHello.ExtensionBodies.ContainsKey(
                (ushort)TlsExtensionType.EncryptedClientHello);
            if (_echReceiver is not null &&
                _echReceiver.ProcessInitial(message, out var inner) ==
                    TlsEchServerProcessingResult.Accepted)
            {
                message = inner!;
                EncryptedClientHelloAccepted = true;
            }
            _firstInnerClientHello = message;
            var firstHello = Tls13ClientHelloParser.Parse(message.Body);
            _firstHello = firstHello;
            var suite = SelectCipherSuite(firstHello.CipherSuites);
            var group = SelectKeyShareGroup(firstHello);
            if (!group.HasValue)
            {
                var retryGroup = SelectRetryGroup(firstHello);
                var retry = Tls13ServerHandshakeMessages.BuildHelloRetryRequest(
                    firstHello.SessionId,
                    suite,
                    retryGroup,
                    EncryptedClientHelloAccepted);
                _helloRetryRequest = retry;
                if (EncryptedClientHelloAccepted)
                {
                    var confirmation = EchAcceptanceConfirmation.ComputeForHelloRetryRequest(
                        suite,
                        message.Encoded,
                        retry);
                    try
                    {
                        confirmation.CopyTo(retry, retry.Length - confirmation.Length);
                    }
                    finally
                    {
                        CryptographicOperations.ZeroMemory(confirmation);
                    }
                }
                _suite = CipherSuiteInfo.Get(suite);
                _transcript = new TranscriptHash(
                    _suite,
                    _configuration.Shared.Limits.MaxHandshakeTranscriptSize);
                _transcript.ResetForHelloRetryRequest(message.Encoded);
                _transcript.Append(retry);
                _retrySuite = suite;
                _retryGroup = retryGroup;
                events.Add(CreateCryptoEvent(
                    TlsQuicEncryptionLevel.Initial,
                    ref _initialWriteOffset,
                    retry));
                _state.HelloRetryRequestSent();
                return;
            }

            await CompleteClientHelloAsync(
                firstHello,
                message,
                suite,
                group.Value,
                events,
                cancellationToken).ConfigureAwait(false);
            return;
        }

        var requestedGroup = _retryGroup ??
            throw TlsProtocolException.Unexpected("Second ClientHello arrived without HRR state.");
        if (EncryptedClientHelloAccepted)
        {
            TlsEchServerReceiver.ValidateOuterRetryIdentity(
                _firstWireClientHello!,
                message);
            message = _echReceiver!.ProcessRetry(message);
        }
        var hello = Tls13ClientHelloParser.Parse(message.Body);
        Tls13ClientHelloParser.ValidateRetry(_firstHello, hello, requestedGroup);
        var retrySuite = _retrySuite!.Value;
        if (!hello.CipherSuites.Contains(retrySuite))
        {
            throw TlsProtocolException.Illegal(
                "Second ClientHello removed the HelloRetryRequest cipher suite.");
        }
        await CompleteClientHelloAsync(
            hello,
            message,
            retrySuite,
            requestedGroup,
            events,
            cancellationToken).ConfigureAwait(false);
    }

    private async ValueTask CompleteClientHelloAsync(
        Tls13ParsedClientHello hello,
        HandshakeMessage message,
        TlsCipherSuite selectedCipherSuite,
        NamedGroup selectedGroup,
        List<TlsQuicEvent> events,
        CancellationToken cancellationToken)
    {
        if (_initialDeframer.BufferedBytes != 0)
        {
            throw TlsProtocolException.Unexpected(
                "ClientHello was not aligned to the QUIC Initial encryption-level transition.");
        }
        if (!hello.ExtensionBodies.TryGetValue(
                (ushort)TlsExtensionType.QuicTransportParameters,
                out var encodedPeerParameters))
        {
            throw new TlsProtocolException(
                TlsAlertDescription.MissingExtension,
                "QUIC ClientHello omitted quic_transport_parameters.");
        }
        _peerTransportParameters = TlsQuicTransportParameters.Parse(encodedPeerParameters);
        _peerTransportParameters.ValidatePeer(TlsQuicEndpointRole.Client);
        ServerName = hello.ServerName;
        NegotiatedApplicationProtocol = SelectAlpn(hello.AlpnProtocols);

        _suite ??= CipherSuiteInfo.Get(selectedCipherSuite);
        _transcript ??= new TranscriptHash(
            _suite,
            _configuration.Shared.Limits.MaxHandshakeTranscriptSize);
        using var selectedResumption = SelectResumption(
            hello,
            message,
            _transcript,
            _suite);
        if (hello.OfferedEarlyData && selectedResumption is not null &&
            _retrySuite is null &&
            selectedResumption.State.MaximumEarlyDataSize == uint.MaxValue &&
            selectedResumption.State.QuicTransportParameters is not null &&
            _configuration.EnableEarlyData)
        {
            var remembered = TlsQuicTransportParameters.Parse(
                selectedResumption.State.QuicTransportParameters);
            if (_configuration.TransportParameters.PermitsRememberedZeroRttLimits(remembered))
            {
                EarlyDataAccepted = await _configuration.EarlyDataReplayValidator!(
                    new TlsQuicEarlyDataContext(
                        hello.ServerName,
                        NegotiatedApplicationProtocol,
                        hello.OfferedPreSharedKey!.Identities[
                            selectedResumption.IdentityIndex].Identity),
                    cancellationToken).ConfigureAwait(false);
                cancellationToken.ThrowIfCancellationRequested();
            }
        }
        _transcript.Append(message.Encoded);
        _state.ClientHelloAccepted();

        TlsServerCertificate? credential = null;
        SignatureScheme? signatureScheme = null;
        if (selectedResumption is null)
        {
            credential = await SelectCertificateAsync(hello, cancellationToken)
                .ConfigureAwait(false);
            signatureScheme = credential.SelectTls13SignatureScheme(
                hello.SignatureAlgorithms) ??
                throw new TlsProtocolException(
                    TlsAlertDescription.HandshakeFailure,
                    "No server certificate signature scheme matches ClientHello.");
        }

        using var serverKeyShare = Tls13ServerKeyExchange.Create(
            selectedGroup,
            hello.KeyShares[selectedGroup]);
        var serverHello = Tls13ServerHandshakeMessages.BuildServerHello(
            hello.SessionId,
            selectedCipherSuite,
            selectedGroup,
            serverKeyShare.PublicKey.Span,
            selectedResumption?.IdentityIndex);
        if (EncryptedClientHelloAccepted)
        {
            var confirmation = _helloRetryRequest is null
                ? EchAcceptanceConfirmation.ComputeForServerHello(
                    selectedCipherSuite,
                    _firstInnerClientHello!.Encoded,
                    serverHello)
                : EchAcceptanceConfirmation.ComputeForServerHelloAfterHelloRetryRequest(
                    selectedCipherSuite,
                    _firstInnerClientHello!.Encoded,
                    _helloRetryRequest,
                    message.Encoded,
                    serverHello);
            try
            {
                confirmation.CopyTo(
                    serverHello,
                    TlsConstants.HandshakeHeaderLength + 2 +
                        TlsConstants.RandomLength - confirmation.Length);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(confirmation);
            }
        }
        _transcript.Append(serverHello);
        _keySchedule = selectedResumption is null
            ? new Tls13KeySchedule(_suite)
            : new Tls13KeySchedule(_suite, selectedResumption.State.Psk);
        if (EarlyDataAccepted)
        {
            var clientHelloHash = HashHandshake(_suite, message.Encoded);
            try
            {
                _keySchedule.DeriveClientEarlyTrafficSecret(clientHelloHash);
                AddTrafficSecret(
                    events,
                    TlsQuicEncryptionLevel.EarlyData,
                    TlsQuicSecretDirection.Read,
                    selectedCipherSuite,
                    _keySchedule.CopyClientEarlyTrafficSecret());
            }
            finally
            {
                CryptographicOperations.ZeroMemory(clientHelloHash);
            }
        }
        var sharedSecret = serverKeyShare.ExportSharedSecret();
        try
        {
            var helloHash = _transcript.CurrentHash();
            try
            {
                _keySchedule.DeriveHandshakeSecrets(sharedSecret, helloHash);
                _keySchedule.DeriveMainSecret();
            }
            finally
            {
                CryptographicOperations.ZeroMemory(helloHash);
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(sharedSecret);
        }

        events.Add(CreateCryptoEvent(
            TlsQuicEncryptionLevel.Initial,
            ref _initialWriteOffset,
            serverHello));
        AddTrafficSecret(
            events,
            TlsQuicEncryptionLevel.Handshake,
            TlsQuicSecretDirection.Read,
            selectedCipherSuite,
            _keySchedule.CopyClientHandshakeTrafficSecret());
        AddTrafficSecret(
            events,
            TlsQuicEncryptionLevel.Handshake,
            TlsQuicSecretDirection.Write,
            selectedCipherSuite,
            _keySchedule.CopyServerHandshakeTrafficSecret());

        var echRetryConfigurations = EncryptedClientHelloOffered &&
            !EncryptedClientHelloAccepted
            ? TlsEchServerKeyConfiguration.BuildRetryConfigurationList(
                _configuration.Shared.EncryptedClientHelloKeys)
            : null;
        byte[] encryptedExtensions;
        try
        {
            encryptedExtensions = Tls13ServerHandshakeMessages.BuildEncryptedExtensions(
                ServerName is not null,
                NegotiatedApplicationProtocol,
                _configuration.TransportParameters,
                EarlyDataAccepted,
                echRetryConfigurations);
        }
        finally
        {
            if (echRetryConfigurations is not null)
            {
                CryptographicOperations.ZeroMemory(echRetryConfigurations);
            }
        }
        _transcript.Append(encryptedExtensions);
        byte[]? certificateRequest = null;
        if (selectedResumption is null &&
            _configuration.Shared.ClientAuthentication !=
            TlsServerClientAuthenticationMode.None)
        {
            certificateRequest = Tls13ServerHandshakeMessages.BuildCertificateRequest(
                _configuration.Shared.ClientCertificateSignatureAlgorithms);
            _transcript.Append(certificateRequest);
        }
        byte[]? certificate = null;
        byte[]? certificateVerify = null;
        if (selectedResumption is null)
        {
            var compression = _configuration.Shared.CertificateCompressionAlgorithms
                .FirstOrDefault(hello.CertificateCompressionAlgorithms.Contains);
            certificate = compression == default
                ? Tls13ServerHandshakeMessages.BuildCertificate(
                    credential!,
                    _configuration.Shared.Limits,
                    hello.ExtensionBodies.ContainsKey((ushort)TlsExtensionType.StatusRequest),
                    hello.ExtensionBodies.ContainsKey(
                        (ushort)TlsExtensionType.SignedCertificateTimestamp))
                : Tls13ServerHandshakeMessages.BuildCompressedCertificate(
                    credential!,
                    _configuration.Shared.Limits,
                    compression,
                    hello.ExtensionBodies.ContainsKey((ushort)TlsExtensionType.StatusRequest),
                    hello.ExtensionBodies.ContainsKey(
                        (ushort)TlsExtensionType.SignedCertificateTimestamp));
            _transcript.Append(certificate);
            certificateVerify = Tls13ServerHandshakeMessages.BuildCertificateVerify(
                credential!,
                signatureScheme!.Value,
                _transcript.CurrentHash());
            _transcript.Append(certificateVerify);
        }
        var verifyData = _keySchedule.ComputeServerFinished(_transcript.CurrentHash());
        var finished = HandshakeMessage.Encode(HandshakeType.Finished, verifyData);
        CryptographicOperations.ZeroMemory(verifyData);
        _transcript.Append(finished);
        byte[] flight = selectedResumption is not null
            ? [.. encryptedExtensions, .. finished]
            : certificateRequest is null
            ? [.. encryptedExtensions, .. certificate!, .. certificateVerify!, .. finished]
            :
            [
                .. encryptedExtensions,
                .. certificateRequest,
                .. certificate!,
                .. certificateVerify!,
                .. finished,
            ];
        try
        {
            events.Add(CreateCryptoEvent(
                TlsQuicEncryptionLevel.Handshake,
                ref _handshakeWriteOffset,
                flight));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(flight);
        }

        var serverFinishedHash = _transcript.CurrentHash();
        try
        {
            _keySchedule.DeriveApplicationTrafficSecrets(serverFinishedHash);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(serverFinishedHash);
        }
        AddTrafficSecret(
            events,
            TlsQuicEncryptionLevel.Application,
            TlsQuicSecretDirection.Write,
            selectedCipherSuite,
            _keySchedule.CopyServerApplicationTrafficSecret());
        AddTrafficSecret(
            events,
            TlsQuicEncryptionLevel.Application,
            TlsQuicSecretDirection.Read,
            selectedCipherSuite,
            _keySchedule.CopyClientApplicationTrafficSecret());

        NegotiatedCipherSuite = selectedCipherSuite;
        NegotiatedGroup = selectedGroup;
        SessionWasResumed = selectedResumption is not null;
        _awaitingClientCertificate = selectedResumption is null &&
            _configuration.Shared.ClientAuthentication !=
            TlsServerClientAuthenticationMode.None;
        _state.ServerFlightSent();
    }

    private void ProcessClientHandshakeMessage(
        HandshakeMessage message,
        List<TlsQuicEvent> events)
    {
        if (_state.State != Tls13ServerState.AwaitingClientFinished ||
            _keySchedule is null || _transcript is null)
        {
            throw TlsProtocolException.Unexpected(
                "Client Handshake CRYPTO arrived in an illegal server state.");
        }
        if (_awaitingClientCertificate)
        {
            if (message.Type != HandshakeType.Certificate)
            {
                throw TlsProtocolException.Unexpected(
                    "Client did not answer CertificateRequest with Certificate.");
            }
            _clientCertificates = ClientCertificateMessageParser.Parse(
                message.Body,
                _configuration.Shared.Limits);
            _transcript.Append(message.Encoded);
            _awaitingClientCertificate = false;
            if (_clientCertificates.Leaf is null)
            {
                if (_configuration.Shared.ClientAuthentication ==
                    TlsServerClientAuthenticationMode.Require)
                {
                    throw new TlsProtocolException(
                        TlsAlertDescription.CertificateRequired,
                        "Client returned an empty mandatory Certificate.");
                }
                _clientCertificates.Dispose();
                _clientCertificates = null;
            }
            else
            {
                ClientCertificateValidator.ValidateChain(
                    _clientCertificates,
                    _configuration.Shared.ClientCertificateValidation);
                _peerCertificateChain = _clientCertificates.Certificates
                    .Select(certificate => certificate.RawData)
                    .ToArray();
                _awaitingClientCertificateVerify = true;
            }
            return;
        }
        if (_awaitingClientCertificateVerify)
        {
            if (message.Type != HandshakeType.CertificateVerify)
            {
                throw TlsProtocolException.Unexpected(
                    "Authenticated client omitted CertificateVerify.");
            }
            _ = ClientCertificateValidator.VerifyCertificateVerify(
                message.Body,
                _clientCertificates!.Leaf!,
                _configuration.Shared.ClientCertificateSignatureAlgorithms,
                _transcript.CurrentHash());
            _transcript.Append(message.Encoded);
            _clientCertificates.Dispose();
            _clientCertificates = null;
            _awaitingClientCertificateVerify = false;
            return;
        }
        if (message.Type is HandshakeType.KeyUpdate or HandshakeType.EndOfEarlyData)
        {
            throw TlsProtocolException.Unexpected($"QUIC forbids TLS {message.Type} messages.");
        }
        if (message.Type != HandshakeType.Finished)
        {
            throw TlsProtocolException.Unexpected(
                $"Unexpected client handshake message {message.Type}.");
        }

        var expected = _keySchedule.ComputeClientFinished(_transcript.CurrentHash());
        try
        {
            if (message.Body.Length != expected.Length ||
                !CryptographicOperations.FixedTimeEquals(message.Body, expected))
            {
                throw new TlsProtocolException(
                    TlsAlertDescription.DecryptError,
                    "Client Finished verification failed.");
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(expected);
        }
        _transcript.Append(message.Encoded);
        if (_handshakeDeframer.BufferedBytes != 0)
        {
            throw TlsProtocolException.Unexpected(
                "Client Finished was not aligned to the QUIC handshake transition.");
        }
        _state.ClientFinishedReceived();
        if (_configuration.Shared.SessionTicketProtector is not null)
        {
            _keySchedule.DeriveResumptionMasterSecret(_transcript.CurrentHash());
        }
        _handshakeReassembler.Discard();
        events.Add(new TlsQuicPeerTransportParametersEvent(_peerTransportParameters!));
        events.Add(new TlsQuicDiscardKeysEvent(TlsQuicEncryptionLevel.Handshake));
        events.Add(new TlsQuicHandshakeCompletedEvent(
            NegotiatedCipherSuite!.Value,
            NegotiatedGroup!.Value,
            NegotiatedApplicationProtocol!));
        for (var index = 0;
             index < _configuration.Shared.AutomaticSessionTicketCount &&
                _configuration.Shared.SessionTicketProtector is not null;
             index++)
        {
            AddSessionTicketEvent(events);
        }
    }

    /// <summary>Emits one post-handshake NewSessionTicket at the Application CRYPTO level.</summary>
    public async ValueTask<TlsQuicProcessResult> IssueSessionTicketAsync(
        CancellationToken cancellationToken = default)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (!IsHandshakeComplete)
            {
                throw new InvalidOperationException("The QUIC TLS handshake is not complete.");
            }
            if (_configuration.Shared.SessionTicketProtector is null)
            {
                throw new InvalidOperationException("TLS session tickets are not configured.");
            }
            var events = new List<TlsQuicEvent>();
            AddSessionTicketEvent(events);
            return new TlsQuicProcessResult(events);
        }
        finally
        {
            _gate.Release();
        }
    }

    private Tls13SelectedServerResumption? SelectResumption(
        Tls13ParsedClientHello hello,
        HandshakeMessage message,
        TranscriptHash transcript,
        CipherSuiteInfo selectedSuite)
    {
        var protector = _configuration.Shared.SessionTicketProtector;
        var offer = hello.OfferedPreSharedKey;
        if (protector is null || offer is null ||
            !hello.PskKeyExchangeModes.Contains((byte)1))
        {
            return null;
        }
        var nowMilliseconds = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
        for (var index = 0; index < offer.Identities.Length; index++)
        {
            if (!protector.TryUnprotect(offer.Identities[index].Identity, out var state))
            {
                continue;
            }
            var selected = false;
            try
            {
                var ticketSuite = CipherSuiteInfo.Get(state!.CipherSuite);
                if (!string.Equals(
                        ticketSuite.HashAlgorithm.Name,
                        selectedSuite.HashAlgorithm.Name,
                        StringComparison.Ordinal) ||
                    !string.Equals(state.ServerName, hello.ServerName, StringComparison.OrdinalIgnoreCase) ||
                    !string.Equals(state.Alpn, NegotiatedApplicationProtocol, StringComparison.Ordinal) ||
                    !IsTicketAgeValid(state, offer.Identities[index].ObfuscatedTicketAge, nowMilliseconds))
                {
                    continue;
                }
                if (offer.Binders[index].Length != selectedSuite.HashLength)
                {
                    throw new TlsProtocolException(
                        TlsAlertDescription.DecryptError,
                        "Selected QUIC PSK binder length does not match the ticket hash.");
                }
                var truncatedLength = checked(
                    TlsConstants.HandshakeHeaderLength + offer.TruncatedBodyLength);
                if (truncatedLength >= message.Encoded.Length)
                {
                    throw TlsProtocolException.Decode("QUIC ClientHello PSK binder is malformed.");
                }
                using var binderTranscript = transcript.Fork();
                binderTranscript.Append(message.Encoded.AsSpan(0, truncatedLength));
                var binderHash = binderTranscript.CurrentHash();
                byte[]? expected = null;
                try
                {
                    using var binderSchedule = new Tls13KeySchedule(selectedSuite, state.Psk);
                    expected = binderSchedule.ComputeResumptionBinder(binderHash);
                    if (!CryptographicOperations.FixedTimeEquals(expected, offer.Binders[index]))
                    {
                        throw new TlsProtocolException(
                            TlsAlertDescription.DecryptError,
                            "QUIC TLS 1.3 PSK binder verification failed.");
                    }
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(binderHash);
                    if (expected is not null)
                    {
                        CryptographicOperations.ZeroMemory(expected);
                    }
                }
                selected = true;
                return new Tls13SelectedServerResumption(index, state);
            }
            finally
            {
                if (!selected)
                {
                    state!.Dispose();
                }
            }
        }
        return null;
    }

    private bool IsTicketAgeValid(
        Tls13ServerSessionTicketState state,
        uint obfuscatedAge,
        long nowMilliseconds)
    {
        long expiresAt;
        try
        {
            expiresAt = checked(
                state.IssuedAtUnixMilliseconds + state.LifetimeSeconds * 1000L);
        }
        catch (OverflowException)
        {
            return false;
        }
        if (nowMilliseconds < state.IssuedAtUnixMilliseconds || nowMilliseconds >= expiresAt)
        {
            return false;
        }
        var serverAge = nowMilliseconds - state.IssuedAtUnixMilliseconds;
        var clientAge = unchecked(obfuscatedAge - state.AgeAdd);
        return Math.Abs(serverAge - clientAge) <=
            _configuration.Shared.SessionTicketAgeTolerance.TotalMilliseconds;
    }

    private void AddSessionTicketEvent(List<TlsQuicEvent> events)
    {
        if (_issuedSessionTickets >= _configuration.Shared.Limits.MaxSessionTicketsPerConnection)
        {
            throw new InvalidOperationException("The QUIC session-ticket limit was reached.");
        }
        var protector = _configuration.Shared.SessionTicketProtector!;
        var nonce = RandomNumberGenerator.GetBytes(8);
        var ageBytes = RandomNumberGenerator.GetBytes(sizeof(uint));
        var ageAdd = BinaryPrimitives.ReadUInt32BigEndian(ageBytes);
        var psk = _keySchedule!.DeriveResumptionPsk(nonce);
        byte[]? identity = null;
        byte[]? encoded = null;
        try
        {
            using var state = new Tls13ServerSessionTicketState(
                DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
                _configuration.Shared.SessionTicketLifetimeSeconds,
                ageAdd,
                NegotiatedCipherSuite!.Value,
                ServerName,
                NegotiatedApplicationProtocol,
                psk,
                _configuration.EnableEarlyData ? uint.MaxValue : null,
                _configuration.EnableEarlyData
                    ? _configuration.TransportParameters.Encode()
                    : null);
            identity = protector.Protect(state);
            var body = new TlsBinaryWriter();
            body.WriteUInt32(_configuration.Shared.SessionTicketLifetimeSeconds);
            body.WriteUInt32(ageAdd);
            body.WriteVector8(nonce);
            body.WriteVector16(identity);
            var extensions = new TlsBinaryWriter();
            if (_configuration.EnableEarlyData)
            {
                var earlyData = new TlsBinaryWriter();
                earlyData.WriteUInt32(uint.MaxValue);
                extensions.WriteUInt16((ushort)TlsExtensionType.EarlyData);
                extensions.WriteVector16(earlyData.WrittenSpan);
            }
            body.WriteVector16(extensions.WrittenSpan);
            encoded = HandshakeMessage.Encode(HandshakeType.NewSessionTicket, body.WrittenSpan);
            events.Add(CreateCryptoEvent(
                TlsQuicEncryptionLevel.Application,
                ref _applicationWriteOffset,
                encoded));
            Interlocked.Increment(ref _issuedSessionTickets);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(nonce);
            CryptographicOperations.ZeroMemory(ageBytes);
            CryptographicOperations.ZeroMemory(psk);
            if (identity is not null)
            {
                CryptographicOperations.ZeroMemory(identity);
            }
            if (encoded is not null)
            {
                CryptographicOperations.ZeroMemory(encoded);
            }
        }
    }

    private static byte[] HashHandshake(CipherSuiteInfo suite, ReadOnlySpan<byte> handshake) =>
        suite.HashAlgorithm.Name switch
        {
            "SHA256" => SHA256.HashData(handshake),
            "SHA384" => SHA384.HashData(handshake),
            _ => throw new NotSupportedException(),
        };

    private static void ProcessApplicationMessage(HandshakeMessage message)
    {
        if (message.Type == HandshakeType.KeyUpdate)
        {
            throw TlsProtocolException.Unexpected("QUIC forbids the TLS KeyUpdate message.");
        }
        throw TlsProtocolException.Unexpected(
            $"A QUIC client sent forbidden post-handshake message {message.Type}.");
    }

    private TlsCipherSuite SelectCipherSuite(IReadOnlyList<TlsCipherSuite> offered)
    {
        foreach (var suite in _configuration.Shared.CipherSuites)
        {
            if (offered.Contains(suite) &&
                (suite != TlsCipherSuite.TlsChaCha20Poly1305Sha256 ||
                 ChaCha20Poly1305.IsSupported))
            {
                return suite;
            }
        }
        throw new TlsProtocolException(
            TlsAlertDescription.HandshakeFailure,
            "ClientHello has no mutually supported TLS 1.3 cipher suite.");
    }

    private NamedGroup? SelectKeyShareGroup(Tls13ParsedClientHello hello)
    {
        foreach (var group in _configuration.Shared.SupportedGroups)
        {
            if (hello.KeyShares.ContainsKey(group))
            {
                return group;
            }
        }
        return null;
    }

    private NamedGroup SelectRetryGroup(Tls13ParsedClientHello hello)
    {
        foreach (var group in _configuration.Shared.SupportedGroups)
        {
            if (hello.SupportedGroups.Contains(group) && !hello.KeyShares.ContainsKey(group))
            {
                return group;
            }
        }
        throw new TlsProtocolException(
            TlsAlertDescription.HandshakeFailure,
            "ClientHello has no mutually supported QUIC ECDHE group.");
    }

    private string SelectAlpn(IReadOnlyList<string> offered)
    {
        foreach (var protocol in _configuration.Shared.AlpnProtocols)
        {
            if (offered.Contains(protocol, StringComparer.Ordinal))
            {
                return protocol;
            }
        }
        throw new TlsProtocolException(
            TlsAlertDescription.NoApplicationProtocol,
            "QUIC requires a mutually supported ALPN protocol.");
    }

    private async ValueTask<TlsServerCertificate> SelectCertificateAsync(
        Tls13ParsedClientHello hello,
        CancellationToken cancellationToken)
    {
        if (_configuration.Shared.ServerCertificateSelector is null)
        {
            return _configuration.Shared.ServerCertificate!;
        }
        var selected = await _configuration.Shared.ServerCertificateSelector(
            new TlsServerCertificateSelectionContext(
                hello.ServerName,
                hello.AlpnProtocols,
                hello.SignatureAlgorithms),
            cancellationToken).ConfigureAwait(false);
        cancellationToken.ThrowIfCancellationRequested();
        return selected ?? throw new TlsProtocolException(
            TlsAlertDescription.UnrecognizedName,
            "Server certificate selector rejected the QUIC ClientHello.");
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
            _clientCertificates?.Dispose();
            _echReceiver?.Dispose();
            _transcript?.Dispose();
            _keySchedule?.Dispose();
            _configuration.Dispose();
        }
        finally
        {
            _gate.Release();
            _gate.Dispose();
        }
    }
}
