using System.Buffers.Binary;
using System.Net.Sockets;
using System.Security.Cryptography;
using SharpTls.Certificates;
using SharpTls.Cryptography;
using SharpTls.Ech;
using SharpTls.Handshake;
using SharpTls.IO;
using SharpTls.Protocol;
using SharpTls.Records;

namespace SharpTls;

/// <summary>
/// One pure managed TLS 1.3 or secure TLS 1.2 server connection over a caller-owned stream or socket.
/// The type implements TLS only; listener policy and application protocols remain caller-owned.
/// </summary>
public sealed class CustomTlsServer : IApplicationDataTransport
{
    private readonly CustomTlsServerConfiguration _configuration;
    private readonly Tls13ServerStateMachine _state = new();
    private readonly SemaphoreSlim _readGate = new(1, 1);
    private readonly SemaphoreSlim _writeGate = new(1, 1);
    private Stream? _transport;
    private TlsRecordReader? _reader;
    private TlsRecordWriter? _writer;
    private Tls13RecordCipher? _serverHandshakeCipher;
    private Tls13RecordCipher? _clientHandshakeCipher;
    private Tls13RecordCipher? _serverApplicationCipher;
    private Tls13RecordCipher? _clientApplicationCipher;
    private Tls13KeySchedule? _keySchedule;
    private Tls12AeadRecordCipher? _tls12ServerApplicationCipher;
    private Tls12AeadRecordCipher? _tls12ClientApplicationCipher;
    private Tls12KeySchedule? _tls12KeySchedule;
    private byte[]? _tls12ClientRandom;
    private byte[]? _tls12ServerRandom;
    private byte[]? _tlsUnique;
    private readonly HandshakeDeframer _postHandshakeDeframer;
    private bool _leaveTransportOpen;
    private bool _authenticated;
    private bool _peerClosed;
    private bool _localClosed;
    private bool _disposed;
    private byte[][] _peerCertificateChain = [];
    private int _pendingPeerKeyUpdateResponse;
    private int _awaitingRequestedPeerKeyUpdate;
    private int _issuedSessionTicketCount;

    /// <summary>Creates a snapshotted server configuration for one accepted connection.</summary>
    public CustomTlsServer(CustomTlsServerOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);
        _configuration = options.Snapshot();
        _postHandshakeDeframer = new HandshakeDeframer(
            _configuration.Limits.MaxHandshakeMessageSize);
    }

    /// <summary>Gets the authenticated SNI host name, or null.</summary>
    public string? ServerName { get; private set; }

    /// <summary>Gets whether ClientHelloOuter carried encrypted_client_hello.</summary>
    public bool EncryptedClientHelloOffered { get; private set; }

    /// <summary>Gets whether RFC 9849 ClientHelloInner was decrypted and authenticated.</summary>
    public bool EncryptedClientHelloAccepted { get; private set; }

    /// <summary>Gets the unauthenticated outer SNI observed before ECH processing.</summary>
    public string? EncryptedClientHelloOuterServerName { get; private set; }

    /// <summary>Gets the selected ALPN identifier, or null.</summary>
    public string? NegotiatedApplicationProtocol { get; private set; }

    /// <summary>Gets the negotiated cipher suite.</summary>
    public TlsCipherSuite? NegotiatedCipherSuite { get; private set; }

    /// <summary>Gets the negotiated ECDHE group.</summary>
    public NamedGroup? NegotiatedGroup { get; private set; }

    /// <summary>Gets the negotiated protocol version.</summary>
    public TlsProtocolVersion? NegotiatedProtocolVersion { get; private set; }

    /// <summary>Gets whether authentication and both Finished messages completed.</summary>
    public bool IsAuthenticated => !_disposed && _authenticated;

    /// <summary>Gets whether this connection used TLS 1.3 PSK or TLS 1.2 abbreviated resumption.</summary>
    public bool SessionWasResumed { get; private set; }

    /// <summary>Gets the number of NewSessionTicket messages issued on this connection.</summary>
    public int IssuedSessionTicketCount => Volatile.Read(ref _issuedSessionTicketCount);

    /// <summary>Gets defensive DER copies of the authenticated client chain.</summary>
    public IReadOnlyList<byte[]> PeerCertificateChain => Array.AsReadOnly(
        _peerCertificateChain.Select(value => (byte[])value.Clone()).ToArray());

    /// <summary>Gets the number of completed server sending-key rotations.</summary>
    public ulong ServerKeyUpdateCount { get; private set; }

    /// <summary>Gets the number of authenticated client sending-key rotations.</summary>
    public ulong ClientKeyUpdateCount { get; private set; }

    /// <summary>
    /// Gets a defensive copy of the RFC 5929 tls-unique channel binding for an
    /// authenticated TLS 1.2 connection, or null for TLS 1.3 and before authentication.
    /// </summary>
    public byte[]? TlsUnique => !_authenticated || _tlsUnique is null
        ? null
        : (byte[])_tlsUnique.Clone();

    /// <summary>Exports version-appropriate RFC 9846 or RFC 5705 keying material.</summary>
    public byte[] ExportKeyingMaterial(
        string label,
        ReadOnlySpan<byte> context,
        int outputLength)
    {
        EnsureApplicationState(allowPeerClosed: true);
        if (NegotiatedProtocolVersion == TlsProtocolVersion.Tls12)
        {
            return (_tls12KeySchedule ??
                throw new InvalidOperationException("TLS 1.2 exporter secret is unavailable."))
                .ExportKeyingMaterial(
                    label,
                    _tls12ClientRandom!,
                    _tls12ServerRandom!,
                    context,
                    outputLength);
        }
        return (_keySchedule ??
            throw new InvalidOperationException("TLS exporter secret is unavailable."))
            .ExportKeyingMaterial(label, context, outputLength);
    }

    /// <summary>Sends TLS 1.3 KeyUpdate and optionally requests a peer response.</summary>
    public async ValueTask RequestKeyUpdateAsync(
        bool requestPeerUpdate = false,
        CancellationToken cancellationToken = default)
    {
        EnsureApplicationState();
        if (NegotiatedProtocolVersion == TlsProtocolVersion.Tls12)
        {
            throw new NotSupportedException(
                "TLS 1.2 has no KeyUpdate message; reconnect before key limits are reached.");
        }
        await _writeGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            EnsureApplicationState();
            if (requestPeerUpdate && Interlocked.CompareExchange(
                ref _awaitingRequestedPeerKeyUpdate,
                1,
                0) != 0)
            {
                throw new InvalidOperationException(
                    "A request_update KeyUpdate is already awaiting a peer response.");
            }
            try
            {
                await SendKeyUpdateCoreAsync(requestPeerUpdate, cancellationToken)
                    .ConfigureAwait(false);
            }
            catch
            {
                if (requestPeerUpdate)
                {
                    Interlocked.Exchange(ref _awaitingRequestedPeerKeyUpdate, 0);
                }
                throw;
            }
        }
        finally
        {
            _writeGate.Release();
        }
    }

    /// <summary>Issues one fresh stateless TLS 1.3 resumption ticket.</summary>
    public async ValueTask IssueSessionTicketAsync(
        CancellationToken cancellationToken = default)
    {
        EnsureApplicationState();
        if (NegotiatedProtocolVersion != TlsProtocolVersion.Tls13)
        {
            throw new NotSupportedException(
                "This API issues TLS 1.3 NewSessionTicket messages only.");
        }
        if (_configuration.SessionTicketProtector is null)
        {
            throw new InvalidOperationException("TLS session tickets are not configured.");
        }
        await _writeGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            EnsureApplicationState();
            await FlushPendingKeyUpdateResponseCoreAsync(cancellationToken)
                .ConfigureAwait(false);
            await IssueSessionTicketCoreAsync(cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            _writeGate.Release();
        }
    }

    /// <summary>Authenticates an already connected readable/writable stream.</summary>
    public async ValueTask AuthenticateAsync(
        Stream transport,
        bool leaveOpen = false,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(transport);
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (_transport is not null)
        {
            throw new InvalidOperationException("This server connection has already been used.");
        }
        if (!transport.CanRead || !transport.CanWrite)
        {
            throw new ArgumentException("TLS transport must be readable and writable.", nameof(transport));
        }

        _transport = transport;
        _leaveTransportOpen = leaveOpen;
        _reader = new TlsRecordReader(transport);
        _writer = new TlsRecordWriter(transport);
        _state.TransportAccepted();
        try
        {
            await PerformHandshakeAsync(cancellationToken).ConfigureAwait(false);
        }
        catch (TlsProtocolException exception)
        {
            _state.Fail();
            await TrySendFatalAlertAsync(exception.Alert).ConfigureAwait(false);
            throw;
        }
        catch
        {
            _state.Fail();
            await TrySendFatalAlertAsync(TlsAlertDescription.InternalError).ConfigureAwait(false);
            throw;
        }
    }

    /// <summary>Authenticates an already connected socket through a managed NetworkStream.</summary>
    public ValueTask AuthenticateAsync(
        Socket socket,
        bool ownsSocket = false,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(socket);
        if (!socket.Connected)
        {
            throw new ArgumentException("Socket must already be connected.", nameof(socket));
        }
        return AuthenticateAsync(
            new NetworkStream(socket, ownsSocket),
            leaveOpen: false,
            cancellationToken);
    }

    /// <summary>Creates a standard non-seekable stream over authenticated application data.</summary>
    public CustomTlsStream AsStream(bool leaveServerOpen = false)
    {
        EnsureApplicationState();
        return new CustomTlsStream(this, leaveServerOpen);
    }

    /// <summary>Writes one non-empty application payload, fragmented into protected records.</summary>
    public async ValueTask WriteApplicationDataAsync(
        ReadOnlyMemory<byte> data,
        CancellationToken cancellationToken = default)
    {
        if (data.IsEmpty)
        {
            throw new ArgumentException("Application data cannot be empty.", nameof(data));
        }
        EnsureApplicationState();
        await _writeGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            EnsureApplicationState();
            if (NegotiatedProtocolVersion == TlsProtocolVersion.Tls12)
            {
                await WriteTls12ApplicationDataCoreAsync(data, cancellationToken)
                    .ConfigureAwait(false);
                return;
            }
            await FlushPendingKeyUpdateResponseCoreAsync(cancellationToken)
                .ConfigureAwait(false);
            if (_serverApplicationCipher!.RecordsRemaining <= 1)
            {
                await SendKeyUpdateCoreAsync(
                    requestPeerUpdate: false,
                    cancellationToken).ConfigureAwait(false);
            }
            var cipher = _serverApplicationCipher!;
            var maximum = TlsConstants.MaxPlaintextLength -
                _configuration.ApplicationDataPaddingLength;
            var offset = 0;
            var recordIndex = 0;
            while (offset < data.Length)
            {
                var length = Math.Min(
                    maximum,
                    _configuration.ApplicationDataFragmentation.GetNextSize(
                        recordIndex++,
                        data.Length - offset));
                var encrypted = cipher.Encrypt(
                    TlsContentType.ApplicationData,
                    data.Span.Slice(offset, length),
                    _configuration.ApplicationDataPaddingLength);
                try
                {
                    await _writer!.WriteRecordAsync(
                        TlsContentType.ApplicationData,
                        encrypted,
                        cancellationToken).ConfigureAwait(false);
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(encrypted);
                }
                offset += length;
            }
        }
        finally
        {
            _writeGate.Release();
        }
    }

    /// <summary>Reads the next authenticated application fragment, or null after close_notify.</summary>
    public async ValueTask<byte[]?> ReadApplicationDataAsync(
        CancellationToken cancellationToken = default)
    {
        EnsureApplicationState(allowPeerClosed: true);
        await _readGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            EnsureApplicationState(allowPeerClosed: true);
            if (_peerClosed)
            {
                return null;
            }
            if (NegotiatedProtocolVersion == TlsProtocolVersion.Tls12)
            {
                return await ReadTls12ApplicationDataCoreAsync(cancellationToken)
                    .ConfigureAwait(false);
            }
            while (true)
            {
                var record = await _reader!.ReadAsync(cancellationToken).ConfigureAwait(false);
                if (record is null)
                {
                    throw TlsProtocolException.Decode(
                        "TLS transport ended without authenticated close_notify.");
                }
                ValidateTls13RecordVersion(record, allowTls10ClientHelloVersion: false);
                if (record.ContentType != TlsContentType.ApplicationData)
                {
                    throw TlsProtocolException.Unexpected(
                        "TLS 1.3 application state received a plaintext record.");
                }
                var inner = _clientApplicationCipher!.Decrypt(record.Fragment);
                switch (inner.ContentType)
                {
                    case TlsContentType.ApplicationData:
                        if (inner.Content.Length != 0)
                        {
                            return inner.Content;
                        }
                        break;
                    case TlsContentType.Alert:
                        if (ProcessAlert(inner.Content))
                        {
                            return null;
                        }
                        break;
                    case TlsContentType.Handshake:
                        if (inner.Content.Length == 0)
                        {
                            throw TlsProtocolException.Unexpected(
                                "Received empty post-handshake bytes.");
                        }
                        _postHandshakeDeframer.Append(inner.Content);
                        while (_postHandshakeDeframer.TryRead(out var message))
                        {
                            if (message!.Type != HandshakeType.KeyUpdate ||
                                _postHandshakeDeframer.BufferedBytes != 0)
                            {
                                throw TlsProtocolException.Unexpected(
                                    $"Unsupported or unaligned post-handshake message {message.Type}.");
                            }
                            var requestUpdate = KeyUpdateProcessor.ParseRequestUpdate(message.Body);
                            RotateClientApplicationKeys();
                            Interlocked.Exchange(ref _awaitingRequestedPeerKeyUpdate, 0);
                            if (requestUpdate &&
                                KeyUpdateProcessor.CanAdvanceSendingEpoch(ServerKeyUpdateCount))
                            {
                                Interlocked.Exchange(ref _pendingPeerKeyUpdateResponse, 1);
                                await _writeGate.WaitAsync(cancellationToken).ConfigureAwait(false);
                                try
                                {
                                    await FlushPendingKeyUpdateResponseCoreAsync(cancellationToken)
                                        .ConfigureAwait(false);
                                }
                                finally
                                {
                                    _writeGate.Release();
                                }
                            }
                        }
                        break;
                    default:
                        throw TlsProtocolException.Unexpected(
                            "Application record contained an invalid inner content type.");
                }
            }
        }
        finally
        {
            _readGate.Release();
        }
    }

    private async ValueTask PerformHandshakeAsync(CancellationToken cancellationToken)
    {
        using var echReceiver = _configuration.EncryptedClientHelloKeys.Length == 0
            ? null
            : new TlsEchServerReceiver(_configuration.EncryptedClientHelloKeys);
        var deframer = new HandshakeDeframer(_configuration.Limits.MaxHandshakeMessageSize);
        var firstMessage = await ReadPlainHandshakeAsync(
                deframer,
                allowTls10ClientHelloRecordVersion: true,
                cancellationToken)
            .ConfigureAwait(false);
        if (firstMessage.Type != HandshakeType.ClientHello)
        {
            throw TlsProtocolException.Unexpected("TLS server expected ClientHello.");
        }
        var offeredVersions = TlsClientHelloVersionOfferParser.Parse(firstMessage.Body);
        var selectedVersion = _configuration.SupportedVersions.FirstOrDefault(
            offeredVersions.Contains);
        if (selectedVersion == default)
        {
            throw new TlsProtocolException(
                TlsAlertDescription.ProtocolVersion,
                "ClientHello and server have no mutually supported TLS version.");
        }
        if (selectedVersion == TlsProtocolVersion.Tls12)
        {
            await PerformTls12HandshakeAsync(
                deframer,
                firstMessage,
                cancellationToken).ConfigureAwait(false);
            return;
        }
        var firstWireMessage = firstMessage;
        var firstOuterHello = Tls13ClientHelloParser.Parse(firstWireMessage.Body);
        EncryptedClientHelloOuterServerName = firstOuterHello.ServerName;
        EncryptedClientHelloOffered = firstOuterHello.ExtensionBodies.ContainsKey(
            (ushort)TlsExtensionType.EncryptedClientHello);
        if (echReceiver is not null)
        {
            var echResult = echReceiver.ProcessInitial(firstWireMessage, out var innerMessage);
            if (echResult == TlsEchServerProcessingResult.Accepted)
            {
                firstMessage = innerMessage!;
                EncryptedClientHelloAccepted = true;
            }
        }
        var firstHello = Tls13ClientHelloParser.Parse(firstMessage.Body);
        var selectedSuite = SelectCipherSuite(firstHello.CipherSuites);
        var suite = CipherSuiteInfo.Get(selectedSuite);
        var selectedGroup = SelectKeyShareGroup(firstHello);
        TranscriptHash transcript = new(
            suite,
            _configuration.Limits.MaxHandshakeTranscriptSize);
        HandshakeMessage activeMessage = firstMessage;
        Tls13ParsedClientHello activeHello = firstHello;
        byte[]? helloRetryRequest = null;
        Tls13SelectedServerResumption? selectedResumption = null;
        try
        {
            if (!selectedGroup.HasValue)
            {
                var retryGroup = SelectRetryGroup(firstHello);
                var retry = BuildHelloRetryRequest(
                    firstHello.SessionId,
                    selectedSuite,
                    retryGroup,
                    EncryptedClientHelloAccepted);
                helloRetryRequest = retry;
                if (EncryptedClientHelloAccepted)
                {
                    var confirmation = EchAcceptanceConfirmation.ComputeForHelloRetryRequest(
                        selectedSuite,
                        firstMessage.Encoded,
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
                transcript.ResetForHelloRetryRequest(firstMessage.Encoded);
                transcript.Append(retry);
                await _writer!.WriteFragmentedAsync(
                    TlsContentType.Handshake,
                    retry,
                    _configuration.HandshakeFragmentation,
                    cancellationToken).ConfigureAwait(false);
                _state.HelloRetryRequestSent();

                var secondWireMessage = await ReadPlainHandshakeAsync(
                        deframer,
                        allowTls10ClientHelloRecordVersion: false,
                        cancellationToken)
                    .ConfigureAwait(false);
                if (secondWireMessage.Type != HandshakeType.ClientHello)
                {
                    throw TlsProtocolException.Unexpected(
                        "TLS server expected a second ClientHello after HRR.");
                }
                var secondMessage = secondWireMessage;
                if (EncryptedClientHelloAccepted)
                {
                    TlsEchServerReceiver.ValidateOuterRetryIdentity(
                        firstWireMessage,
                        secondWireMessage);
                    secondMessage = echReceiver!.ProcessRetry(secondWireMessage);
                }
                var secondHello = Tls13ClientHelloParser.Parse(secondMessage.Body);
                Tls13ClientHelloParser.ValidateRetry(firstHello, secondHello, retryGroup);
                if (!secondHello.CipherSuites.Contains(selectedSuite))
                {
                    throw TlsProtocolException.Illegal(
                        "Second ClientHello removed the HRR cipher suite.");
                }
                activeMessage = secondMessage;
                activeHello = secondHello;
                selectedGroup = retryGroup;
            }
            if (deframer.BufferedBytes != 0)
            {
                throw TlsProtocolException.Unexpected(
                    "ClientHello was not aligned to the record-layer transition.");
            }
            _state.ClientHelloAccepted();

            ServerName = activeHello.ServerName;
            NegotiatedApplicationProtocol = SelectAlpn(activeHello.AlpnProtocols);
            selectedResumption = SelectResumption(
                activeHello,
                activeMessage,
                transcript,
                suite);
            transcript.Append(activeMessage.Encoded);

            TlsServerCertificate? credential = null;
            SignatureScheme? signatureScheme = null;
            if (selectedResumption is null)
            {
                credential = await SelectCertificateAsync(activeHello, cancellationToken)
                    .ConfigureAwait(false);
                signatureScheme = credential.SelectTls13SignatureScheme(
                    activeHello.SignatureAlgorithms) ??
                    throw new TlsProtocolException(
                        TlsAlertDescription.HandshakeFailure,
                        "No server certificate signature scheme matches ClientHello.");
            }

            using var serverKeyShare = Tls13ServerKeyExchange.Create(
                selectedGroup.Value,
                activeHello.KeyShares[selectedGroup.Value]);
            var serverHello = BuildServerHello(
                activeHello.SessionId,
                selectedSuite,
                selectedGroup.Value,
                serverKeyShare.PublicKey.Span,
                selectedResumption?.IdentityIndex);
            if (EncryptedClientHelloAccepted)
            {
                var confirmation = helloRetryRequest is null
                    ? EchAcceptanceConfirmation.ComputeForServerHello(
                        selectedSuite,
                        firstMessage.Encoded,
                        serverHello)
                    : EchAcceptanceConfirmation.ComputeForServerHelloAfterHelloRetryRequest(
                        selectedSuite,
                        firstMessage.Encoded,
                        helloRetryRequest,
                        activeMessage.Encoded,
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
            transcript.Append(serverHello);
            var schedule = selectedResumption is null
                ? new Tls13KeySchedule(suite)
                : new Tls13KeySchedule(suite, selectedResumption.State.Psk);
            _keySchedule = schedule;
            var sharedSecret = serverKeyShare.ExportSharedSecret();
            try
            {
                schedule.DeriveHandshakeSecrets(sharedSecret, transcript.CurrentHash());
                schedule.DeriveMainSecret();
            }
            finally
            {
                CryptographicOperations.ZeroMemory(sharedSecret);
            }

            _serverHandshakeCipher = CreateCipher(
                suite,
                schedule.GetServerHandshakeKeys());
            _clientHandshakeCipher = CreateCipher(
                suite,
                schedule.GetClientHandshakeKeys());
            await _writer!.WriteFragmentedAsync(
                TlsContentType.Handshake,
                serverHello,
                _configuration.HandshakeFragmentation,
                cancellationToken).ConfigureAwait(false);
            if (_configuration.SendCompatibilityChangeCipherSpec)
            {
                await _writer.WriteRecordAsync(
                    TlsContentType.ChangeCipherSpec,
                    new byte[] { 1 },
                    cancellationToken).ConfigureAwait(false);
            }

            var echRetryConfigurations = EncryptedClientHelloOffered &&
                !EncryptedClientHelloAccepted
                ? TlsEchServerKeyConfiguration.BuildRetryConfigurationList(
                    _configuration.EncryptedClientHelloKeys)
                : null;
            byte[] encryptedExtensions;
            try
            {
                encryptedExtensions = BuildEncryptedExtensions(
                    ServerName is not null,
                    NegotiatedApplicationProtocol,
                    echRetryConfigurations);
            }
            finally
            {
                if (echRetryConfigurations is not null)
                {
                    CryptographicOperations.ZeroMemory(echRetryConfigurations);
                }
            }
            transcript.Append(encryptedExtensions);
            byte[]? certificateRequest = null;
            if (selectedResumption is null &&
                _configuration.ClientAuthentication !=
                TlsServerClientAuthenticationMode.None)
            {
                certificateRequest = BuildCertificateRequest(
                    _configuration.ClientCertificateSignatureAlgorithms);
                transcript.Append(certificateRequest);
            }
            byte[]? certificate = null;
            byte[]? certificateVerify = null;
            if (selectedResumption is null)
            {
                var compression = _configuration.CertificateCompressionAlgorithms
                    .FirstOrDefault(activeHello.CertificateCompressionAlgorithms.Contains);
                certificate = compression == default
                    ? Tls13ServerHandshakeMessages.BuildCertificate(
                        credential!,
                        _configuration.Limits,
                        activeHello.ExtensionBodies.ContainsKey(
                            (ushort)TlsExtensionType.StatusRequest),
                        activeHello.ExtensionBodies.ContainsKey(
                            (ushort)TlsExtensionType.SignedCertificateTimestamp))
                    : Tls13ServerHandshakeMessages.BuildCompressedCertificate(
                        credential!,
                        _configuration.Limits,
                        compression,
                        activeHello.ExtensionBodies.ContainsKey(
                            (ushort)TlsExtensionType.StatusRequest),
                        activeHello.ExtensionBodies.ContainsKey(
                            (ushort)TlsExtensionType.SignedCertificateTimestamp));
                transcript.Append(certificate);
                certificateVerify = BuildCertificateVerify(
                    credential!,
                    signatureScheme!.Value,
                    transcript.CurrentHash());
                transcript.Append(certificateVerify);
            }
            var verifyData = schedule.ComputeServerFinished(transcript.CurrentHash());
            var finished = HandshakeMessage.Encode(HandshakeType.Finished, verifyData);
            CryptographicOperations.ZeroMemory(verifyData);
            transcript.Append(finished);
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
                await WriteProtectedHandshakeAsync(
                    _serverHandshakeCipher,
                    flight,
                    cancellationToken).ConfigureAwait(false);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(flight);
            }

            schedule.DeriveApplicationTrafficSecrets(transcript.CurrentHash());
            _serverApplicationCipher = CreateCipher(
                suite,
                schedule.GetServerApplicationKeys());
            _clientApplicationCipher = CreateCipher(
                suite,
                schedule.GetClientApplicationKeys());
            _state.ServerFlightSent();
            await ReadAndVerifyClientFinishedAsync(
                deframer,
                schedule,
                transcript,
                selectedResumption is null && _configuration.ClientAuthentication !=
                    TlsServerClientAuthenticationMode.None,
                cancellationToken).ConfigureAwait(false);

            if (_configuration.SessionTicketProtector is not null)
            {
                schedule.DeriveResumptionMasterSecret(transcript.CurrentHash());
            }

            _serverHandshakeCipher.Dispose();
            _serverHandshakeCipher = null;
            _clientHandshakeCipher.Dispose();
            _clientHandshakeCipher = null;
            NegotiatedCipherSuite = selectedSuite;
            NegotiatedGroup = selectedGroup.Value;
            NegotiatedProtocolVersion = TlsProtocolVersion.Tls13;
            SessionWasResumed = selectedResumption is not null;
            _authenticated = true;
            for (var index = 0;
                 index < _configuration.AutomaticSessionTicketCount &&
                    _configuration.SessionTicketProtector is not null;
                 index++)
            {
                await IssueSessionTicketCoreAsync(cancellationToken).ConfigureAwait(false);
            }
        }
        finally
        {
            selectedResumption?.Dispose();
            transcript.Dispose();
        }
    }

    private async ValueTask<HandshakeMessage> ReadPlainHandshakeAsync(
        HandshakeDeframer deframer,
        bool allowTls10ClientHelloRecordVersion,
        CancellationToken cancellationToken)
    {
        while (true)
        {
            var record = await _reader!.ReadAsync(cancellationToken).ConfigureAwait(false) ??
                throw TlsProtocolException.Decode("Unexpected EOF before ClientHello.");
            ValidateTls13RecordVersion(record, allowTls10ClientHelloRecordVersion);
            switch (record.ContentType)
            {
                case TlsContentType.Handshake:
                    if (record.Fragment.Length == 0)
                    {
                        throw TlsProtocolException.Unexpected("Empty Handshake record.");
                    }
                    deframer.Append(record.Fragment);
                    if (deframer.TryRead(out var message))
                    {
                        return message!;
                    }
                    break;
                case TlsContentType.ChangeCipherSpec:
                    if (!record.Fragment.AsSpan().SequenceEqual(new byte[] { 1 }))
                    {
                        throw TlsProtocolException.Unexpected("Invalid compatibility CCS.");
                    }
                    break;
                case TlsContentType.Alert:
                    throw ParsePeerAlert(record.Fragment);
                default:
                    throw TlsProtocolException.Unexpected(
                        "Unexpected record before ClientHello completion.");
            }
        }
    }

    private async ValueTask PerformTls12HandshakeAsync(
        HandshakeDeframer deframer,
        HandshakeMessage clientHelloMessage,
        CancellationToken cancellationToken)
    {
        var hello = Tls12ClientHelloParser.Parse(clientHelloMessage.Body);
        ServerName = hello.ServerName;
        NegotiatedApplicationProtocol = SelectAlpn(hello.AlpnProtocols);
        var resumedWithTicket = TryResumeTls12Ticket(hello, out var resumedSession);
        resumedSession ??= _configuration.Tls12SessionCache?.TryGet(
                hello.SessionId,
                hello.CipherSuites,
                _configuration.Tls12CipherSuites,
                hello.ServerName,
                hello.AlpnProtocols);
        if (resumedSession is not null && !string.Equals(
            resumedSession.NegotiatedAlpn,
            NegotiatedApplicationProtocol,
            StringComparison.Ordinal))
        {
            resumedSession.Dispose();
            resumedSession = null;
        }
        if (resumedSession is not null)
        {
            using (resumedSession)
            {
                await PerformTls12ResumedHandshakeAsync(
                    deframer,
                    clientHelloMessage,
                    hello,
                    resumedSession,
                    resumedWithTicket,
                    cancellationToken).ConfigureAwait(false);
            }
            return;
        }
        var credential = await SelectTls12CertificateAsync(hello, cancellationToken)
            .ConfigureAwait(false);
        var (suite, signatureScheme) = SelectTls12CipherSuite(hello, credential);
        var group = SelectTls12Group(hello);
        var serverRandom = RandomNumberGenerator.GetBytes(TlsConstants.RandomLength);
        var serverSessionId = _configuration.Tls12SessionCache is null
            ? Array.Empty<byte>()
            : RandomNumberGenerator.GetBytes(TlsConstants.MaxSessionIdLength);
        var includeCertificateStatus = hello.ExtensionBodies.ContainsKey(
            (ushort)TlsExtensionType.StatusRequest) &&
            credential.HasStapledOcspResponse;
        var signedCertificateTimestamps = hello.ExtensionBodies.ContainsKey(
            (ushort)TlsExtensionType.SignedCertificateTimestamp)
            ? credential.CopySignedCertificateTimestamps()
            : [];
        var serverHello = Tls12ServerHandshakeMessages.BuildServerHello(
            serverRandom,
            serverSessionId,
            suite.Suite,
            hello.ServerName is not null,
            hello.ExtensionBodies.ContainsKey((ushort)TlsExtensionType.EcPointFormats),
            hello.SessionTicket is not null &&
                _configuration.Tls12SessionTicketProtector is not null,
            includeCertificateStatus,
            signedCertificateTimestamps,
            NegotiatedApplicationProtocol);
        using var transcript = new Tls12TranscriptHash(suite);
        transcript.Append(clientHelloMessage.Encoded);
        transcript.Append(serverHello);
        using var serverKeyShare = KeyShareFactory.Create(group);
        var certificate = Tls12ServerHandshakeMessages.BuildCertificate(
            credential,
            _configuration.Limits);
        transcript.Append(certificate);
        var certificateStatus = includeCertificateStatus
            ? Tls12ServerHandshakeMessages.BuildCertificateStatus(credential)
            : null;
        if (certificateStatus is not null)
        {
            transcript.Append(certificateStatus);
        }
        var serverKeyExchange = Tls12ServerHandshakeMessages.BuildServerKeyExchange(
            group,
            serverKeyShare.PublicKey.Span,
            signatureScheme,
            suite.CertificateKeyType,
            credential,
            hello.Random,
            serverRandom);
        transcript.Append(serverKeyExchange);
        byte[]? certificateRequest = null;
        if (_configuration.ClientAuthentication != TlsServerClientAuthenticationMode.None)
        {
            certificateRequest = Tls12ServerHandshakeMessages.BuildCertificateRequest(
                _configuration.ClientCertificateSignatureAlgorithms);
            transcript.Append(certificateRequest);
        }
        var serverHelloDone = Tls12ServerHandshakeMessages.BuildServerHelloDone();
        transcript.Append(serverHelloDone);
        byte[] flight = certificateRequest is null
            ? certificateStatus is null
                ? [.. serverHello, .. certificate, .. serverKeyExchange, .. serverHelloDone]
                : [.. serverHello, .. certificate, .. certificateStatus, .. serverKeyExchange, .. serverHelloDone]
            :
                certificateStatus is null
                ?
                [
                    .. serverHello,
                    .. certificate,
                    .. serverKeyExchange,
                    .. certificateRequest,
                    .. serverHelloDone,
                ]
                :
                [
                    .. serverHello,
                    .. certificate,
                    .. certificateStatus,
                    .. serverKeyExchange,
                    .. certificateRequest,
                    .. serverHelloDone,
                ];
        try
        {
            await _writer!.WriteFragmentedAsync(
                TlsContentType.Handshake,
                flight,
                _configuration.HandshakeFragmentation,
                cancellationToken,
                TlsConstants.Tls12Version).ConfigureAwait(false);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(flight);
        }
        _state.ClientHelloAccepted();
        _state.ServerFlightSent();

        Tls12KeySchedule? keySchedule = null;
        Tls12AeadRecordCipher? clientCipher = null;
        Tls12AeadRecordCipher? serverCipher = null;
        ClientCertificateMessage? clientCertificates = null;
        var awaitingCertificate = _configuration.ClientAuthentication !=
            TlsServerClientAuthenticationMode.None;
        var awaitingCertificateVerify = false;
        var clientKeyExchangeReceived = false;
        try
        {
            while (true)
            {
                var record = await _reader!.ReadAsync(cancellationToken).ConfigureAwait(false) ??
                    throw TlsProtocolException.Decode(
                        "Unexpected EOF during the TLS 1.2 client flight.");
                ValidateTls12RecordVersion(record.LegacyRecordVersion);
                if (record.ContentType == TlsContentType.Handshake)
                {
                    if (clientKeyExchangeReceived && !awaitingCertificateVerify)
                    {
                        throw TlsProtocolException.Unexpected(
                            "TLS 1.2 received extra plaintext Handshake data before ChangeCipherSpec.");
                    }
                    deframer.Append(record.Fragment);
                    while (deframer.TryRead(out var message))
                    {
                        if (awaitingCertificate)
                        {
                            if (message!.Type != HandshakeType.Certificate)
                            {
                                throw TlsProtocolException.Unexpected(
                                    "TLS 1.2 client omitted its Certificate response.");
                            }
                            clientCertificates = ClientCertificateMessageParser.ParseTls12(
                                message.Body,
                                _configuration.Limits);
                            transcript.Append(message.Encoded);
                            awaitingCertificate = false;
                            if (clientCertificates.Leaf is null)
                            {
                                if (_configuration.ClientAuthentication ==
                                    TlsServerClientAuthenticationMode.Require)
                                {
                                    throw new TlsProtocolException(
                                        TlsAlertDescription.CertificateRequired,
                                        "TLS 1.2 client returned an empty mandatory Certificate.");
                                }
                                clientCertificates.Dispose();
                                clientCertificates = null;
                            }
                            else
                            {
                                ClientCertificateValidator.ValidateChain(
                                    clientCertificates,
                                    _configuration.ClientCertificateValidation);
                                _peerCertificateChain = clientCertificates.Certificates
                                    .Select(item => item.RawData)
                                    .ToArray();
                                awaitingCertificateVerify = true;
                            }
                            continue;
                        }
                        if (!clientKeyExchangeReceived)
                        {
                            if (message!.Type != HandshakeType.ClientKeyExchange)
                            {
                                throw TlsProtocolException.Unexpected(
                                    "TLS 1.2 expected ClientKeyExchange.");
                            }
                            var keyExchangeReader = new TlsBinaryReader(message.Body);
                            var peerPublicKey = keyExchangeReader.ReadVector8().ToArray();
                            keyExchangeReader.EnsureEnd("TLS 1.2 ClientKeyExchange");
                            transcript.Append(message.Encoded);
                            var sharedSecret = serverKeyShare.DeriveSharedSecret(peerPublicKey);
                            try
                            {
                                keySchedule = new Tls12KeySchedule(suite);
                                var sessionHash = transcript.CurrentHash();
                                try
                                {
                                    keySchedule.DeriveExtendedMasterSecret(
                                        sharedSecret,
                                        sessionHash);
                                }
                                finally
                                {
                                    CryptographicOperations.ZeroMemory(sessionHash);
                                }
                                keySchedule.DeriveTrafficKeys(hello.Random, serverRandom);
                                clientCipher = CreateTls12Cipher(
                                    suite,
                                    keySchedule.GetClientWriteKeys());
                                serverCipher = CreateTls12Cipher(
                                    suite,
                                    keySchedule.GetServerWriteKeys());
                            }
                            finally
                            {
                                CryptographicOperations.ZeroMemory(peerPublicKey);
                                CryptographicOperations.ZeroMemory(sharedSecret);
                            }
                            clientKeyExchangeReceived = true;
                            continue;
                        }
                        if (awaitingCertificateVerify)
                        {
                            if (message!.Type != HandshakeType.CertificateVerify)
                            {
                                throw TlsProtocolException.Unexpected(
                                    "TLS 1.2 authenticated client omitted CertificateVerify.");
                            }
                            _ = ClientCertificateValidator.VerifyTls12CertificateVerify(
                                message.Body,
                                clientCertificates!.Leaf!,
                                _configuration.ClientCertificateSignatureAlgorithms,
                                transcript.CurrentHash);
                            transcript.Append(message.Encoded);
                            clientCertificates.Dispose();
                            clientCertificates = null;
                            awaitingCertificateVerify = false;
                            continue;
                        }
                        throw TlsProtocolException.Unexpected(
                            $"Unexpected TLS 1.2 client handshake message {message!.Type}.");
                    }
                    continue;
                }
                if (record.ContentType != TlsContentType.ChangeCipherSpec ||
                    !record.Fragment.AsSpan().SequenceEqual(new byte[] { 1 }) ||
                    !clientKeyExchangeReceived || awaitingCertificate ||
                    awaitingCertificateVerify || deframer.BufferedBytes != 0)
                {
                    throw TlsProtocolException.Unexpected(
                        "TLS 1.2 client ChangeCipherSpec arrived out of sequence or was malformed.");
                }

                var finishedRecord = await _reader.ReadAsync(cancellationToken).ConfigureAwait(false) ??
                    throw TlsProtocolException.Decode(
                        "Unexpected EOF before TLS 1.2 client Finished.");
                ValidateTls12RecordVersion(finishedRecord.LegacyRecordVersion);
                if (finishedRecord.ContentType != TlsContentType.Handshake)
                {
                    throw TlsProtocolException.Unexpected(
                        "TLS 1.2 client Finished used an invalid record type.");
                }
                var finishedPlaintext = clientCipher!.Decrypt(
                    finishedRecord.ContentType,
                    finishedRecord.Fragment,
                    finishedRecord.LegacyRecordVersion);
                try
                {
                    var finishedDeframer = new HandshakeDeframer(
                        _configuration.Limits.MaxHandshakeMessageSize);
                    finishedDeframer.Append(finishedPlaintext);
                    if (!finishedDeframer.TryRead(out var clientFinished) ||
                        finishedDeframer.BufferedBytes != 0 ||
                        clientFinished!.Type != HandshakeType.Finished)
                    {
                        throw TlsProtocolException.Unexpected(
                            "TLS 1.2 protected client flight did not contain exactly Finished.");
                    }
                    var expected = keySchedule!.ComputeClientFinished(transcript.CurrentHash());
                    try
                    {
                        if (clientFinished.Body.Length != expected.Length ||
                            !CryptographicOperations.FixedTimeEquals(
                                clientFinished.Body,
                                expected))
                        {
                            throw new TlsProtocolException(
                                TlsAlertDescription.DecryptError,
                                "TLS 1.2 client Finished verification failed.");
                        }
                    }
                    finally
                    {
                        CryptographicOperations.ZeroMemory(expected);
                    }
                    _tlsUnique = clientFinished.Body.ToArray();
                    transcript.Append(clientFinished.Encoded);
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(finishedPlaintext);
                }
                break;
            }

            if (hello.SessionTicket is not null &&
                _configuration.Tls12SessionTicketProtector is not null)
            {
                await WriteTls12NewSessionTicketAsync(
                    keySchedule!,
                    suite.Suite,
                    hello.ServerName,
                    NegotiatedApplicationProtocol,
                    group,
                    transcript,
                    cancellationToken).ConfigureAwait(false);
            }
            await _writer!.WriteRecordAsync(
                TlsContentType.ChangeCipherSpec,
                new byte[] { 1 },
                cancellationToken,
                TlsConstants.Tls12Version).ConfigureAwait(false);
            var serverVerifyData = keySchedule!.ComputeServerFinished(transcript.CurrentHash());
            var serverFinished = HandshakeMessage.Encode(
                HandshakeType.Finished,
                serverVerifyData);
            CryptographicOperations.ZeroMemory(serverVerifyData);
            try
            {
                await WriteTls12ProtectedAsync(
                    serverCipher!,
                    TlsContentType.Handshake,
                    serverFinished,
                    cancellationToken).ConfigureAwait(false);
                transcript.Append(serverFinished);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(serverFinished);
            }

            _state.ClientFinishedReceived();
            if (_configuration.Tls12SessionCache is { } sessionCache)
            {
                var masterSecret = keySchedule.CopyMasterSecret();
                try
                {
                    sessionCache.Add(
                        serverSessionId,
                        suite.Suite,
                        hello.ServerName,
                        NegotiatedApplicationProtocol,
                        group,
                        masterSecret);
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(masterSecret);
                }
            }
            _tls12KeySchedule = keySchedule;
            keySchedule = null;
            _tls12ClientApplicationCipher = clientCipher;
            clientCipher = null;
            _tls12ServerApplicationCipher = serverCipher;
            serverCipher = null;
            _tls12ClientRandom = (byte[])hello.Random.Clone();
            _tls12ServerRandom = (byte[])serverRandom.Clone();
            NegotiatedProtocolVersion = TlsProtocolVersion.Tls12;
            NegotiatedCipherSuite = suite.Suite;
            NegotiatedGroup = group;
            _authenticated = true;
        }
        finally
        {
            clientCertificates?.Dispose();
            keySchedule?.Dispose();
            clientCipher?.Dispose();
            serverCipher?.Dispose();
            CryptographicOperations.ZeroMemory(serverRandom);
            CryptographicOperations.ZeroMemory(serverSessionId);
        }
    }

    private async ValueTask PerformTls12ResumedHandshakeAsync(
        HandshakeDeframer deframer,
        HandshakeMessage clientHelloMessage,
        Tls12ParsedClientHello hello,
        Tls12ServerSession session,
        bool resumedWithTicket,
        CancellationToken cancellationToken)
    {
        if (deframer.BufferedBytes != 0)
        {
            throw TlsProtocolException.Unexpected(
                "TLS 1.2 abbreviated ClientHello was followed by premature handshake data.");
        }
        var suite = Tls12CipherSuiteInfo.Get(session.CipherSuite);
        var serverRandom = RandomNumberGenerator.GetBytes(TlsConstants.RandomLength);
        var serverHello = Tls12ServerHandshakeMessages.BuildServerHello(
            serverRandom,
            hello.SessionId,
            session.CipherSuite,
            hello.ServerName is not null,
            hello.ExtensionBodies.ContainsKey((ushort)TlsExtensionType.EcPointFormats),
            resumedWithTicket,
            acknowledgeStatusRequest: false,
            signedCertificateTimestamps: null,
            session.NegotiatedAlpn);
        using var transcript = new Tls12TranscriptHash(suite);
        transcript.Append(clientHelloMessage.Encoded);
        transcript.Append(serverHello);
        Tls12KeySchedule? keySchedule = null;
        Tls12AeadRecordCipher? clientCipher = null;
        Tls12AeadRecordCipher? serverCipher = null;
        try
        {
            await _writer!.WriteFragmentedAsync(
                TlsContentType.Handshake,
                serverHello,
                _configuration.HandshakeFragmentation,
                cancellationToken,
                TlsConstants.Tls12Version).ConfigureAwait(false);
            _state.ClientHelloAccepted();
            _state.ServerFlightSent();

            var masterSecret = session.CopyMasterSecret();
            try
            {
                keySchedule = new Tls12KeySchedule(suite);
                keySchedule.ImportMasterSecret(masterSecret);
                keySchedule.DeriveTrafficKeys(hello.Random, serverRandom);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(masterSecret);
            }
            clientCipher = CreateTls12Cipher(suite, keySchedule.GetClientWriteKeys());
            serverCipher = CreateTls12Cipher(suite, keySchedule.GetServerWriteKeys());

            if (resumedWithTicket)
            {
                await WriteTls12NewSessionTicketAsync(
                    keySchedule,
                    session.CipherSuite,
                    session.ServerName,
                    session.NegotiatedAlpn,
                    session.NegotiatedGroup,
                    transcript,
                    cancellationToken).ConfigureAwait(false);
            }

            await _writer.WriteRecordAsync(
                TlsContentType.ChangeCipherSpec,
                new byte[] { 1 },
                cancellationToken,
                TlsConstants.Tls12Version).ConfigureAwait(false);
            _tls12ServerApplicationCipher = serverCipher;
            serverCipher = null;
            var serverVerifyData = keySchedule.ComputeServerFinished(transcript.CurrentHash());
            var serverFinished = HandshakeMessage.Encode(HandshakeType.Finished, serverVerifyData);
            _tlsUnique = serverFinished[TlsConstants.HandshakeHeaderLength..].ToArray();
            CryptographicOperations.ZeroMemory(serverVerifyData);
            try
            {
                await WriteTls12ProtectedAsync(
                    _tls12ServerApplicationCipher,
                    TlsContentType.Handshake,
                    serverFinished,
                    cancellationToken).ConfigureAwait(false);
                transcript.Append(serverFinished);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(serverFinished);
            }

            var ccs = await _reader!.ReadAsync(cancellationToken).ConfigureAwait(false) ??
                throw TlsProtocolException.Decode(
                    "Unexpected EOF before abbreviated TLS 1.2 client ChangeCipherSpec.");
            ValidateTls12RecordVersion(ccs.LegacyRecordVersion);
            if (ccs.ContentType != TlsContentType.ChangeCipherSpec ||
                !ccs.Fragment.AsSpan().SequenceEqual(new byte[] { 1 }))
            {
                throw TlsProtocolException.Unexpected(
                    "Abbreviated TLS 1.2 client ChangeCipherSpec was malformed.");
            }

            while (true)
            {
                var record = await _reader.ReadAsync(cancellationToken).ConfigureAwait(false) ??
                    throw TlsProtocolException.Decode(
                        "Unexpected EOF before abbreviated TLS 1.2 client Finished.");
                ValidateTls12RecordVersion(record.LegacyRecordVersion);
                if (record.ContentType != TlsContentType.Handshake)
                {
                    throw TlsProtocolException.Unexpected(
                        "Abbreviated TLS 1.2 client Finished used an invalid record type.");
                }
                var plaintext = clientCipher.Decrypt(
                    record.ContentType,
                    record.Fragment,
                    record.LegacyRecordVersion);
                try
                {
                    if (plaintext.Length == 0)
                    {
                        throw TlsProtocolException.Unexpected(
                            "Abbreviated TLS 1.2 client sent an empty Handshake fragment.");
                    }
                    deframer.Append(plaintext);
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(plaintext);
                }
                if (!deframer.TryRead(out var clientFinished))
                {
                    continue;
                }
                if (clientFinished!.Type != HandshakeType.Finished || deframer.BufferedBytes != 0)
                {
                    throw TlsProtocolException.Unexpected(
                        "Abbreviated TLS 1.2 protected client flight did not contain exactly Finished.");
                }
                var expected = keySchedule.ComputeClientFinished(transcript.CurrentHash());
                try
                {
                    if (clientFinished.Body.Length != expected.Length ||
                        !CryptographicOperations.FixedTimeEquals(clientFinished.Body, expected))
                    {
                        throw new TlsProtocolException(
                            TlsAlertDescription.DecryptError,
                            "Abbreviated TLS 1.2 client Finished verification failed.");
                    }
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(expected);
                }
                break;
            }

            _state.ClientFinishedReceived();
            _tls12KeySchedule = keySchedule;
            keySchedule = null;
            _tls12ClientApplicationCipher = clientCipher;
            clientCipher = null;
            _tls12ClientRandom = (byte[])hello.Random.Clone();
            _tls12ServerRandom = (byte[])serverRandom.Clone();
            NegotiatedProtocolVersion = TlsProtocolVersion.Tls12;
            NegotiatedCipherSuite = session.CipherSuite;
            NegotiatedGroup = session.NegotiatedGroup;
            NegotiatedApplicationProtocol = session.NegotiatedAlpn;
            SessionWasResumed = true;
            _authenticated = true;
        }
        finally
        {
            keySchedule?.Dispose();
            clientCipher?.Dispose();
            serverCipher?.Dispose();
            CryptographicOperations.ZeroMemory(serverRandom);
        }
    }

    private bool TryResumeTls12Ticket(
        Tls12ParsedClientHello hello,
        out Tls12ServerSession? session)
    {
        session = null;
        if (hello.SessionTicket is not { Length: > 0 } ticket ||
            _configuration.Tls12SessionTicketProtector is not { } protector ||
            !protector.TryUnprotect(ticket, out var state))
        {
            return false;
        }
        using (state)
        {
            var now = DateTimeOffset.UtcNow;
            if (!state!.IsUsable(now) ||
                !hello.CipherSuites.Contains(state.CipherSuite) ||
                !_configuration.Tls12CipherSuites.Contains(state.CipherSuite) ||
                !_configuration.SupportedGroups.Contains(state.Group) ||
                !string.Equals(state.ServerName, hello.ServerName, StringComparison.OrdinalIgnoreCase) ||
                !string.Equals(state.Alpn, NegotiatedApplicationProtocol, StringComparison.Ordinal))
            {
                return false;
            }
            var masterSecret = state.CopyMasterSecret();
            try
            {
                session = new Tls12ServerSession(
                    hello.SessionId,
                    state.CipherSuite,
                    state.ServerName,
                    state.Alpn,
                    state.Group,
                    masterSecret,
                    DateTimeOffset.FromUnixTimeMilliseconds(state.IssuedAtUnixMilliseconds)
                        .AddSeconds(state.LifetimeSeconds));
                return true;
            }
            finally
            {
                CryptographicOperations.ZeroMemory(masterSecret);
            }
        }
    }

    private async ValueTask WriteTls12NewSessionTicketAsync(
        Tls12KeySchedule keySchedule,
        TlsCipherSuite cipherSuite,
        string? serverName,
        string? alpn,
        NamedGroup group,
        Tls12TranscriptHash transcript,
        CancellationToken cancellationToken)
    {
        var protector = _configuration.Tls12SessionTicketProtector ??
            throw new InvalidOperationException("TLS 1.2 session tickets are not configured.");
        var masterSecret = keySchedule.CopyMasterSecret();
        byte[]? ticket = null;
        byte[]? message = null;
        try
        {
            using var state = new Tls12ServerTicketState(
                DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
                _configuration.Tls12SessionTicketLifetimeSeconds,
                cipherSuite,
                serverName,
                alpn,
                group,
                masterSecret);
            ticket = protector.Protect(state);
            message = Tls12ServerHandshakeMessages.BuildNewSessionTicket(
                _configuration.Tls12SessionTicketLifetimeSeconds,
                ticket);
            transcript.Append(message);
            await _writer!.WriteFragmentedAsync(
                TlsContentType.Handshake,
                message,
                _configuration.HandshakeFragmentation,
                cancellationToken,
                TlsConstants.Tls12Version).ConfigureAwait(false);
            Interlocked.Increment(ref _issuedSessionTicketCount);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(masterSecret);
            if (ticket is not null)
            {
                CryptographicOperations.ZeroMemory(ticket);
            }
            if (message is not null)
            {
                CryptographicOperations.ZeroMemory(message);
            }
        }
    }

    private async ValueTask ReadAndVerifyClientFinishedAsync(
        HandshakeDeframer deframer,
        Tls13KeySchedule schedule,
        TranscriptHash transcript,
        bool expectClientCertificate,
        CancellationToken cancellationToken)
    {
        ClientCertificateMessage? clientCertificates = null;
        var awaitingCertificate = expectClientCertificate;
        var awaitingCertificateVerify = false;
        try
        {
            while (true)
            {
                var record = await _reader!.ReadAsync(cancellationToken).ConfigureAwait(false) ??
                    throw TlsProtocolException.Decode("Unexpected EOF before client Finished.");
                ValidateTls13RecordVersion(record, allowTls10ClientHelloVersion: false);
                if (record.ContentType == TlsContentType.ChangeCipherSpec)
                {
                    if (!record.Fragment.AsSpan().SequenceEqual(new byte[] { 1 }))
                    {
                        throw TlsProtocolException.Unexpected("Invalid compatibility CCS.");
                    }
                    continue;
                }
                if (record.ContentType != TlsContentType.ApplicationData)
                {
                    throw TlsProtocolException.Unexpected(
                        "Client Finished was not carried in TLSCiphertext.");
                }
                var inner = _clientHandshakeCipher!.Decrypt(record.Fragment);
                if (inner.ContentType == TlsContentType.Alert)
                {
                    throw ParsePeerAlert(inner.Content);
                }
                if (inner.ContentType != TlsContentType.Handshake || inner.Content.Length == 0)
                {
                    throw TlsProtocolException.Unexpected(
                        "Expected protected client Finished Handshake bytes.");
                }
                deframer.Append(inner.Content);
                while (deframer.TryRead(out var message))
                {
                    if (awaitingCertificate)
                    {
                        if (message!.Type != HandshakeType.Certificate)
                        {
                            throw TlsProtocolException.Unexpected(
                                "Client did not answer CertificateRequest with Certificate.");
                        }
                        clientCertificates = ClientCertificateMessageParser.Parse(
                            message.Body,
                            _configuration.Limits);
                        transcript.Append(message.Encoded);
                        awaitingCertificate = false;
                        if (clientCertificates.Leaf is null)
                        {
                            if (_configuration.ClientAuthentication ==
                                TlsServerClientAuthenticationMode.Require)
                            {
                                throw new TlsProtocolException(
                                    TlsAlertDescription.CertificateRequired,
                                    "Client returned an empty mandatory Certificate.");
                            }
                            clientCertificates.Dispose();
                            clientCertificates = null;
                        }
                        else
                        {
                            ClientCertificateValidator.ValidateChain(
                                clientCertificates,
                                _configuration.ClientCertificateValidation);
                            _peerCertificateChain = clientCertificates.Certificates
                                .Select(certificate => certificate.RawData)
                                .ToArray();
                            awaitingCertificateVerify = true;
                        }
                        continue;
                    }
                    if (awaitingCertificateVerify)
                    {
                        if (message!.Type != HandshakeType.CertificateVerify)
                        {
                            throw TlsProtocolException.Unexpected(
                                "Authenticated client omitted CertificateVerify.");
                        }
                        _ = ClientCertificateValidator.VerifyCertificateVerify(
                            message.Body,
                            clientCertificates!.Leaf!,
                            _configuration.ClientCertificateSignatureAlgorithms,
                            transcript.CurrentHash());
                        transcript.Append(message.Encoded);
                        clientCertificates.Dispose();
                        clientCertificates = null;
                        awaitingCertificateVerify = false;
                        continue;
                    }
                    if (message!.Type != HandshakeType.Finished)
                    {
                        throw TlsProtocolException.Unexpected(
                            $"Unexpected client handshake message {message.Type}.");
                    }
                    var expected = schedule.ComputeClientFinished(transcript.CurrentHash());
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
                    transcript.Append(message.Encoded);
                    if (deframer.BufferedBytes != 0)
                    {
                        throw TlsProtocolException.Unexpected(
                            "Client Finished was not aligned to the application key transition.");
                    }
                    _state.ClientFinishedReceived();
                    return;
                }
            }
        }
        finally
        {
            clientCertificates?.Dispose();
        }
    }

    private Tls13SelectedServerResumption? SelectResumption(
        Tls13ParsedClientHello hello,
        HandshakeMessage message,
        TranscriptHash transcript,
        CipherSuiteInfo selectedSuite)
    {
        var protector = _configuration.SessionTicketProtector;
        var offer = hello.OfferedPreSharedKey;
        if (protector is null || offer is null ||
            !hello.PskKeyExchangeModes.Contains((byte)1))
        {
            return null;
        }

        var nowMilliseconds = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
        for (var index = 0; index < offer.Identities.Length; index++)
        {
            var offeredIdentity = offer.Identities[index];
            if (!protector.TryUnprotect(offeredIdentity.Identity, out var state))
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
                    !string.Equals(
                        state.ServerName,
                        hello.ServerName,
                        StringComparison.OrdinalIgnoreCase) ||
                    !string.Equals(
                        state.Alpn,
                        NegotiatedApplicationProtocol,
                        StringComparison.Ordinal) ||
                    !IsTicketAgeValid(
                        state,
                        offeredIdentity.ObfuscatedTicketAge,
                        nowMilliseconds))
                {
                    continue;
                }
                if (hello.OfferedEarlyData)
                {
                    throw TlsProtocolException.Illegal(
                        "Client offered early_data for a ticket that did not authorize 0-RTT.");
                }
                if (offer.Binders[index].Length != selectedSuite.HashLength)
                {
                    throw new TlsProtocolException(
                        TlsAlertDescription.DecryptError,
                        "Selected PSK binder length does not match the ticket hash.");
                }

                var truncatedLength = checked(
                    TlsConstants.HandshakeHeaderLength + offer.TruncatedBodyLength);
                if (truncatedLength >= message.Encoded.Length)
                {
                    throw TlsProtocolException.Decode(
                        "ClientHello PSK binder transcript is malformed.");
                }
                using var binderTranscript = transcript.Fork();
                binderTranscript.Append(message.Encoded.AsSpan(0, truncatedLength));
                var binderHash = binderTranscript.CurrentHash();
                byte[]? expectedBinder = null;
                try
                {
                    using var binderSchedule = new Tls13KeySchedule(
                        selectedSuite,
                        state.Psk);
                    expectedBinder = binderSchedule.ComputeResumptionBinder(binderHash);
                    if (!CryptographicOperations.FixedTimeEquals(
                            expectedBinder,
                            offer.Binders[index]))
                    {
                        throw new TlsProtocolException(
                            TlsAlertDescription.DecryptError,
                            "Selected TLS 1.3 PSK binder authentication failed.");
                    }
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(binderHash);
                    if (expectedBinder is not null)
                    {
                        CryptographicOperations.ZeroMemory(expectedBinder);
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
        uint obfuscatedTicketAge,
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
        if (nowMilliseconds < state.IssuedAtUnixMilliseconds ||
            nowMilliseconds >= expiresAt)
        {
            return false;
        }

        var serverAge = nowMilliseconds - state.IssuedAtUnixMilliseconds;
        var clientAge = unchecked(obfuscatedTicketAge - state.AgeAdd);
        var difference = Math.Abs(serverAge - clientAge);
        return difference <= _configuration.SessionTicketAgeTolerance.TotalMilliseconds;
    }

    private async ValueTask IssueSessionTicketCoreAsync(
        CancellationToken cancellationToken)
    {
        var protector = _configuration.SessionTicketProtector ??
            throw new InvalidOperationException("TLS session tickets are not configured.");
        if (_issuedSessionTicketCount >= _configuration.Limits.MaxSessionTicketsPerConnection)
        {
            throw new InvalidOperationException(
                "The configured per-connection session-ticket limit was reached.");
        }
        var schedule = _keySchedule ??
            throw new InvalidOperationException("TLS resumption secrets are unavailable.");
        var cipher = _serverApplicationCipher ??
            throw new InvalidOperationException("TLS application write keys are unavailable.");
        var suite = NegotiatedCipherSuite ??
            throw new InvalidOperationException("TLS cipher suite is unavailable.");

        var nonce = RandomNumberGenerator.GetBytes(8);
        var ageAddBytes = RandomNumberGenerator.GetBytes(sizeof(uint));
        var ageAdd = BinaryPrimitives.ReadUInt32BigEndian(ageAddBytes);
        var psk = schedule.DeriveResumptionPsk(nonce);
        byte[]? identity = null;
        byte[]? encoded = null;
        using var state = new Tls13ServerSessionTicketState(
            DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
            _configuration.SessionTicketLifetimeSeconds,
            ageAdd,
            suite,
            ServerName,
            NegotiatedApplicationProtocol,
            psk);
        try
        {
            identity = protector.Protect(state);
            var body = new TlsBinaryWriter();
            body.WriteUInt32(_configuration.SessionTicketLifetimeSeconds);
            body.WriteUInt32(ageAdd);
            body.WriteVector8(nonce);
            body.WriteVector16(identity);
            body.WriteVector16([]);
            encoded = HandshakeMessage.Encode(
                HandshakeType.NewSessionTicket,
                body.WrittenSpan);
            await WriteProtectedHandshakeAsync(
                cipher,
                encoded,
                cancellationToken).ConfigureAwait(false);
            Interlocked.Increment(ref _issuedSessionTicketCount);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(nonce);
            CryptographicOperations.ZeroMemory(ageAddBytes);
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

    private TlsCipherSuite SelectCipherSuite(IReadOnlyList<TlsCipherSuite> offered)
    {
        foreach (var suite in _configuration.CipherSuites)
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

    private (Tls12CipherSuiteInfo Suite, SignatureScheme SignatureScheme)
        SelectTls12CipherSuite(
            Tls12ParsedClientHello hello,
            TlsServerCertificate credential)
    {
        foreach (var offeredSuite in _configuration.Tls12CipherSuites)
        {
            if (!hello.CipherSuites.Contains(offeredSuite))
            {
                continue;
            }
            var suite = Tls12CipherSuiteInfo.Get(offeredSuite);
            if (suite.AeadAlgorithm == Tls12AeadAlgorithm.ChaCha20Poly1305 &&
                !ChaCha20Poly1305.IsSupported)
            {
                continue;
            }
            var signature = credential.SelectTls12SignatureScheme(
                hello.SignatureAlgorithms,
                suite.CertificateKeyType);
            if (signature.HasValue)
            {
                return (suite, signature.Value);
            }
        }
        throw new TlsProtocolException(
            TlsAlertDescription.HandshakeFailure,
            "ClientHello has no TLS 1.2 suite compatible with the selected certificate.");
    }

    private NamedGroup SelectTls12Group(Tls12ParsedClientHello hello)
    {
        foreach (var group in _configuration.SupportedGroups)
        {
            if (group is not (NamedGroup.X25519MlKem768 or
                    NamedGroup.X25519Kyber768Draft00) &&
                hello.SupportedGroups.Contains(group))
            {
                return group;
            }
        }
        throw new TlsProtocolException(
            TlsAlertDescription.HandshakeFailure,
            "ClientHello has no mutually supported TLS 1.2 ECDHE group.");
    }

    private NamedGroup? SelectKeyShareGroup(Tls13ParsedClientHello hello)
    {
        foreach (var group in _configuration.SupportedGroups)
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
        foreach (var group in _configuration.SupportedGroups)
        {
            if (hello.SupportedGroups.Contains(group) && !hello.KeyShares.ContainsKey(group))
            {
                return group;
            }
        }
        throw new TlsProtocolException(
            TlsAlertDescription.HandshakeFailure,
            "ClientHello has no mutually supported ECDHE group.");
    }

    private string? SelectAlpn(IReadOnlyList<string> offered)
    {
        foreach (var protocol in _configuration.AlpnProtocols)
        {
            if (offered.Contains(protocol, StringComparer.Ordinal))
            {
                return protocol;
            }
        }
        if (_configuration.RequireAlpn)
        {
            throw new TlsProtocolException(
                TlsAlertDescription.NoApplicationProtocol,
                "ClientHello has no mutually supported ALPN protocol.");
        }
        return null;
    }

    private async ValueTask<TlsServerCertificate> SelectCertificateAsync(
        Tls13ParsedClientHello hello,
        CancellationToken cancellationToken)
    {
        if (_configuration.ServerCertificateSelector is null)
        {
            return _configuration.ServerCertificate!;
        }
        var selected = await _configuration.ServerCertificateSelector(
            new TlsServerCertificateSelectionContext(
                hello.ServerName,
                hello.AlpnProtocols,
                hello.SignatureAlgorithms),
            cancellationToken).ConfigureAwait(false);
        cancellationToken.ThrowIfCancellationRequested();
        return selected ?? throw new TlsProtocolException(
            TlsAlertDescription.UnrecognizedName,
            "Server certificate selector rejected the ClientHello.");
    }

    private async ValueTask<TlsServerCertificate> SelectTls12CertificateAsync(
        Tls12ParsedClientHello hello,
        CancellationToken cancellationToken)
    {
        if (_configuration.ServerCertificateSelector is null)
        {
            return _configuration.ServerCertificate!;
        }
        var selected = await _configuration.ServerCertificateSelector(
            new TlsServerCertificateSelectionContext(
                hello.ServerName,
                hello.AlpnProtocols,
                hello.SignatureAlgorithms),
            cancellationToken).ConfigureAwait(false);
        cancellationToken.ThrowIfCancellationRequested();
        return selected ?? throw new TlsProtocolException(
            TlsAlertDescription.UnrecognizedName,
            "Server certificate selector rejected the TLS 1.2 ClientHello.");
    }

    private static byte[] BuildServerHello(
        ReadOnlySpan<byte> sessionId,
        TlsCipherSuite suite,
        NamedGroup group,
        ReadOnlySpan<byte> keyExchange,
        int? selectedPskIdentity)
    {
        var extensions = new TlsBinaryWriter();
        var version = new TlsBinaryWriter();
        version.WriteUInt16(TlsConstants.Tls13Version);
        extensions.WriteUInt16((ushort)TlsExtensionType.SupportedVersions);
        extensions.WriteVector16(version.WrittenSpan);
        var keyShare = new TlsBinaryWriter();
        keyShare.WriteUInt16((ushort)group);
        keyShare.WriteVector16(keyExchange);
        extensions.WriteUInt16((ushort)TlsExtensionType.KeyShare);
        extensions.WriteVector16(keyShare.WrittenSpan);
        if (selectedPskIdentity.HasValue)
        {
            var selectedIdentity = new TlsBinaryWriter();
            selectedIdentity.WriteUInt16(checked((ushort)selectedPskIdentity.Value));
            extensions.WriteUInt16((ushort)TlsExtensionType.PreSharedKey);
            extensions.WriteVector16(selectedIdentity.WrittenSpan);
        }
        var body = new TlsBinaryWriter();
        body.WriteUInt16(TlsConstants.LegacyRecordVersion);
        body.WriteBytes(RandomNumberGenerator.GetBytes(TlsConstants.RandomLength));
        body.WriteVector8(sessionId);
        body.WriteUInt16((ushort)suite);
        body.WriteUInt8(0);
        body.WriteVector16(extensions.WrittenSpan);
        return HandshakeMessage.Encode(HandshakeType.ServerHello, body.WrittenSpan);
    }

    private static byte[] BuildHelloRetryRequest(
        ReadOnlySpan<byte> sessionId,
        TlsCipherSuite suite,
        NamedGroup group,
        bool includeEchAcceptanceConfirmation = false)
    {
        ReadOnlySpan<byte> random =
        [
            0xCF, 0x21, 0xAD, 0x74, 0xE5, 0x9A, 0x61, 0x11,
            0xBE, 0x1D, 0x8C, 0x02, 0x1E, 0x65, 0xB8, 0x91,
            0xC2, 0xA2, 0x11, 0x16, 0x7A, 0xBB, 0x8C, 0x5E,
            0x07, 0x9E, 0x09, 0xE2, 0xC8, 0xA8, 0x33, 0x9C,
        ];
        var extensions = new TlsBinaryWriter();
        var version = new TlsBinaryWriter();
        version.WriteUInt16(TlsConstants.Tls13Version);
        extensions.WriteUInt16((ushort)TlsExtensionType.SupportedVersions);
        extensions.WriteVector16(version.WrittenSpan);
        var keyShare = new TlsBinaryWriter();
        keyShare.WriteUInt16((ushort)group);
        extensions.WriteUInt16((ushort)TlsExtensionType.KeyShare);
        extensions.WriteVector16(keyShare.WrittenSpan);
        if (includeEchAcceptanceConfirmation)
        {
            extensions.WriteUInt16((ushort)TlsExtensionType.EncryptedClientHello);
            extensions.WriteVector16(new byte[EchAcceptanceConfirmation.ConfirmationLength]);
        }
        var body = new TlsBinaryWriter();
        body.WriteUInt16(TlsConstants.LegacyRecordVersion);
        body.WriteBytes(random);
        body.WriteVector8(sessionId);
        body.WriteUInt16((ushort)suite);
        body.WriteUInt8(0);
        body.WriteVector16(extensions.WrittenSpan);
        return HandshakeMessage.Encode(HandshakeType.ServerHello, body.WrittenSpan);
    }

    private static byte[] BuildEncryptedExtensions(
        bool acknowledgeSni,
        string? alpn,
        ReadOnlySpan<byte> echRetryConfigurations = default)
    {
        var extensions = new TlsBinaryWriter();
        if (acknowledgeSni)
        {
            extensions.WriteUInt16((ushort)TlsExtensionType.ServerName);
            extensions.WriteVector16([]);
        }
        if (alpn is not null)
        {
            var names = new TlsBinaryWriter();
            names.WriteVector8(System.Text.Encoding.ASCII.GetBytes(alpn));
            var encoded = new TlsBinaryWriter();
            encoded.WriteVector16(names.WrittenSpan);
            extensions.WriteUInt16((ushort)TlsExtensionType.ApplicationLayerProtocolNegotiation);
            extensions.WriteVector16(encoded.WrittenSpan);
        }
        if (!echRetryConfigurations.IsEmpty)
        {
            extensions.WriteUInt16((ushort)TlsExtensionType.EncryptedClientHello);
            extensions.WriteVector16(echRetryConfigurations);
        }
        var body = new TlsBinaryWriter();
        body.WriteVector16(extensions.WrittenSpan);
        return HandshakeMessage.Encode(HandshakeType.EncryptedExtensions, body.WrittenSpan);
    }

    private static byte[] BuildCertificateRequest(
        IReadOnlyList<SignatureScheme> signatureAlgorithms)
    {
        var algorithms = new TlsBinaryWriter();
        foreach (var algorithm in signatureAlgorithms)
        {
            algorithms.WriteUInt16((ushort)algorithm);
        }
        var algorithmList = new TlsBinaryWriter();
        algorithmList.WriteVector16(algorithms.WrittenSpan);
        var extensions = new TlsBinaryWriter();
        extensions.WriteUInt16((ushort)TlsExtensionType.SignatureAlgorithms);
        extensions.WriteVector16(algorithmList.WrittenSpan);
        var body = new TlsBinaryWriter();
        body.WriteVector8([]);
        body.WriteVector16(extensions.WrittenSpan);
        return HandshakeMessage.Encode(HandshakeType.CertificateRequest, body.WrittenSpan);
    }

    private byte[] BuildCertificate(TlsServerCertificate credential)
    {
        var entries = new TlsBinaryWriter();
        var chain = credential.SnapshotCertificateChain();
        if (chain.Count > _configuration.Limits.MaxCertificateCount)
        {
            throw new TlsProtocolException(
                TlsAlertDescription.InternalError,
                "Server certificate chain exceeds the configured certificate-count limit.");
        }
        foreach (var certificate in chain)
        {
            entries.WriteVector24(certificate);
            entries.WriteVector16([]);
        }
        if (entries.Length > _configuration.Limits.MaxCertificateListSize)
        {
            throw new TlsProtocolException(
                TlsAlertDescription.InternalError,
                "Server certificate chain exceeds the configured list-size limit.");
        }
        var body = new TlsBinaryWriter();
        body.WriteVector8([]);
        body.WriteVector24(entries.WrittenSpan);
        return HandshakeMessage.Encode(HandshakeType.Certificate, body.WrittenSpan);
    }

    private static byte[] BuildCertificateVerify(
        TlsServerCertificate credential,
        SignatureScheme scheme,
        ReadOnlySpan<byte> transcriptHash)
    {
        var signature = credential.SignTls13CertificateVerify(scheme, transcriptHash);
        try
        {
            var body = new TlsBinaryWriter();
            body.WriteUInt16((ushort)scheme);
            body.WriteVector16(signature);
            return HandshakeMessage.Encode(HandshakeType.CertificateVerify, body.WrittenSpan);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(signature);
        }
    }

    private async ValueTask WriteProtectedHandshakeAsync(
        Tls13RecordCipher cipher,
        ReadOnlyMemory<byte> data,
        CancellationToken cancellationToken)
    {
        var offset = 0;
        var index = 0;
        while (offset < data.Length)
        {
            var length = Math.Min(
                TlsConstants.MaxPlaintextLength,
                _configuration.HandshakeFragmentation.GetNextSize(
                    index++,
                    data.Length - offset));
            var encrypted = cipher.Encrypt(
                TlsContentType.Handshake,
                data.Span.Slice(offset, length));
            try
            {
                await _writer!.WriteRecordAsync(
                    TlsContentType.ApplicationData,
                    encrypted,
                    cancellationToken).ConfigureAwait(false);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(encrypted);
            }
            offset += length;
        }
    }

    private async ValueTask WriteTls12ApplicationDataCoreAsync(
        ReadOnlyMemory<byte> data,
        CancellationToken cancellationToken)
    {
        var cipher = _tls12ServerApplicationCipher ??
            throw new InvalidOperationException("TLS 1.2 server write keys are unavailable.");
        var offset = 0;
        var recordIndex = 0;
        while (offset < data.Length)
        {
            var length = Math.Min(
                TlsConstants.MaxPlaintextLength,
                _configuration.ApplicationDataFragmentation.GetNextSize(
                    recordIndex++,
                    data.Length - offset));
            await WriteTls12ProtectedAsync(
                cipher,
                TlsContentType.ApplicationData,
                data.Slice(offset, length),
                cancellationToken).ConfigureAwait(false);
            offset += length;
        }
    }

    private async ValueTask<byte[]?> ReadTls12ApplicationDataCoreAsync(
        CancellationToken cancellationToken)
    {
        var cipher = _tls12ClientApplicationCipher ??
            throw new InvalidOperationException("TLS 1.2 client read keys are unavailable.");
        while (true)
        {
            var record = await _reader!.ReadAsync(cancellationToken).ConfigureAwait(false) ??
                throw TlsProtocolException.Decode(
                    "TLS 1.2 transport ended without authenticated close_notify.");
            ValidateTls12RecordVersion(record.LegacyRecordVersion);
            if (record.ContentType == TlsContentType.ChangeCipherSpec)
            {
                throw TlsProtocolException.Unexpected(
                    "TLS 1.2 received a renegotiation ChangeCipherSpec.");
            }
            if (record.ContentType is not (
                TlsContentType.ApplicationData or
                TlsContentType.Alert or
                TlsContentType.Handshake))
            {
                throw TlsProtocolException.Unexpected(
                    "TLS 1.2 application state received an invalid record type.");
            }
            var plaintext = cipher.Decrypt(
                record.ContentType,
                record.Fragment,
                record.LegacyRecordVersion);
            if (record.ContentType == TlsContentType.ApplicationData)
            {
                if (plaintext.Length != 0)
                {
                    return plaintext;
                }
                CryptographicOperations.ZeroMemory(plaintext);
                continue;
            }
            try
            {
                if (record.ContentType == TlsContentType.Alert)
                {
                    if (ProcessAlert(plaintext))
                    {
                        return null;
                    }
                    continue;
                }
                throw TlsProtocolException.Unexpected(
                    "TLS 1.2 renegotiation is intentionally unsupported.");
            }
            finally
            {
                CryptographicOperations.ZeroMemory(plaintext);
            }
        }
    }

    private async ValueTask WriteTls12ProtectedAsync(
        Tls12AeadRecordCipher cipher,
        TlsContentType contentType,
        ReadOnlyMemory<byte> plaintext,
        CancellationToken cancellationToken)
    {
        var encrypted = cipher.Encrypt(
            contentType,
            plaintext.Span,
            TlsConstants.Tls12Version);
        try
        {
            await _writer!.WriteRecordAsync(
                contentType,
                encrypted,
                cancellationToken,
                TlsConstants.Tls12Version).ConfigureAwait(false);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(encrypted);
        }
    }

    private static Tls13RecordCipher CreateCipher(
        CipherSuiteInfo suite,
        (byte[] Key, byte[] Iv) material)
    {
        try
        {
            return new Tls13RecordCipher(suite, material.Key, material.Iv);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(material.Key);
            CryptographicOperations.ZeroMemory(material.Iv);
        }
    }

    private static Tls12AeadRecordCipher CreateTls12Cipher(
        Tls12CipherSuiteInfo suite,
        Tls12TrafficKeys keys)
    {
        try
        {
            return new Tls12AeadRecordCipher(suite, keys.Key, keys.FixedIv);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(keys.Key);
            CryptographicOperations.ZeroMemory(keys.FixedIv);
        }
    }

    private async ValueTask FlushPendingKeyUpdateResponseCoreAsync(
        CancellationToken cancellationToken)
    {
        if (Interlocked.Exchange(ref _pendingPeerKeyUpdateResponse, 0) == 0)
        {
            return;
        }
        try
        {
            await SendKeyUpdateCoreAsync(
                requestPeerUpdate: false,
                cancellationToken).ConfigureAwait(false);
        }
        catch
        {
            Interlocked.Exchange(ref _pendingPeerKeyUpdateResponse, 1);
            throw;
        }
    }

    private async ValueTask SendKeyUpdateCoreAsync(
        bool requestPeerUpdate,
        CancellationToken cancellationToken)
    {
        var current = _serverApplicationCipher ??
            throw new InvalidOperationException("Server write keys are unavailable.");
        if (!KeyUpdateProcessor.CanAdvanceSendingEpoch(ServerKeyUpdateCount) ||
            current.RecordsRemaining == 0)
        {
            throw new TlsProtocolException(
                TlsAlertDescription.GeneralError,
                "Server sending-key epoch or record limit is exhausted.");
        }
        var encoded = KeyUpdateProcessor.Encode(requestPeerUpdate);
        var encrypted = current.Encrypt(TlsContentType.Handshake, encoded);
        try
        {
            await _writer!.WriteRecordAsync(
                TlsContentType.ApplicationData,
                encrypted,
                cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(encrypted);
        }

        var schedule = _keySchedule ??
            throw new InvalidOperationException("Application traffic secrets are unavailable.");
        schedule.UpdateServerApplicationTrafficSecret();
        var next = CreateCipher(
            CipherSuiteInfo.Get(NegotiatedCipherSuite!.Value),
            schedule.GetServerApplicationKeys());
        _serverApplicationCipher = next;
        current.Dispose();
        ServerKeyUpdateCount++;
    }

    private void RotateClientApplicationKeys()
    {
        var current = _clientApplicationCipher ??
            throw new InvalidOperationException("Client read keys are unavailable.");
        var schedule = _keySchedule ??
            throw new InvalidOperationException("Application traffic secrets are unavailable.");
        schedule.UpdateClientApplicationTrafficSecret();
        var next = CreateCipher(
            CipherSuiteInfo.Get(NegotiatedCipherSuite!.Value),
            schedule.GetClientApplicationKeys());
        _clientApplicationCipher = next;
        current.Dispose();
        ClientKeyUpdateCount++;
    }

    private bool ProcessAlert(ReadOnlySpan<byte> alert)
    {
        if (alert.Length != 2 || alert[0] is not (1 or 2))
        {
            throw TlsProtocolException.Decode("TLS alert has invalid framing.");
        }
        if (alert[1] == (byte)TlsAlertDescription.CloseNotify && alert[0] == 1)
        {
            _peerClosed = true;
            return true;
        }
        if (alert[1] == 90)
        {
            return false;
        }
        _peerClosed = true;
        _authenticated = false;
        throw ParsePeerAlert(alert);
    }

    private static void ValidateTls13RecordVersion(
        TlsRecord record,
        bool allowTls10ClientHelloVersion)
    {
        if (record.LegacyRecordVersion == TlsConstants.LegacyRecordVersion ||
            (allowTls10ClientHelloVersion &&
             record.LegacyRecordVersion == (ushort)TlsProtocolVersion.Tls10 &&
             record.ContentType == TlsContentType.Handshake))
        {
            return;
        }
        throw new TlsProtocolException(
            TlsAlertDescription.ProtocolVersion,
            $"TLS 1.3 record used invalid legacy_record_version 0x{record.LegacyRecordVersion:X4}.");
    }

    private static void ValidateTls12RecordVersion(ushort version)
    {
        if (version != TlsConstants.Tls12Version)
        {
            throw new TlsProtocolException(
                TlsAlertDescription.ProtocolVersion,
                $"TLS 1.2 record used invalid version 0x{version:X4}.");
        }
    }

    private static TlsProtocolException ParsePeerAlert(ReadOnlySpan<byte> alert)
    {
        if (alert.Length != 2 || alert[0] is not (1 or 2))
        {
            return TlsProtocolException.Decode("TLS alert has invalid framing.");
        }
        var description = Enum.IsDefined(typeof(TlsAlertDescription), alert[1])
            ? (TlsAlertDescription)alert[1]
            : TlsAlertDescription.GeneralError;
        return new TlsProtocolException(
            description,
            $"Peer terminated TLS with alert {alert[1]}.");
    }

    private async ValueTask TrySendFatalAlertAsync(TlsAlertDescription alert)
    {
        if (_writer is null)
        {
            return;
        }
        try
        {
            byte[] content = [2, (byte)alert];
            if (_tls12ServerApplicationCipher is not null)
            {
                var tls12Encrypted = _tls12ServerApplicationCipher.Encrypt(
                    TlsContentType.Alert,
                    content,
                    TlsConstants.Tls12Version);
                try
                {
                    await _writer.WriteRecordAsync(
                        TlsContentType.Alert,
                        tls12Encrypted,
                        CancellationToken.None,
                        TlsConstants.Tls12Version).ConfigureAwait(false);
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(tls12Encrypted);
                }
                return;
            }
            var cipher = _serverApplicationCipher ?? _serverHandshakeCipher;
            if (cipher is null)
            {
                await _writer.WriteRecordAsync(
                    TlsContentType.Alert,
                    content,
                    CancellationToken.None).ConfigureAwait(false);
                return;
            }
            var encrypted = cipher.Encrypt(TlsContentType.Alert, content);
            try
            {
                await _writer.WriteRecordAsync(
                    TlsContentType.ApplicationData,
                    encrypted,
                    CancellationToken.None).ConfigureAwait(false);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(encrypted);
            }
        }
        catch
        {
            // Preserve the original protocol failure when the transport cannot carry the alert.
        }
    }

    private void EnsureApplicationState(bool allowPeerClosed = false)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (!_authenticated || _localClosed || (!allowPeerClosed && _peerClosed))
        {
            throw new InvalidOperationException("TLS server connection is not open.");
        }
    }

    /// <inheritdoc />
    public async ValueTask DisposeAsync()
    {
        if (_disposed)
        {
            return;
        }
        if (_authenticated && !_localClosed && _writer is not null &&
            (_serverApplicationCipher is not null ||
             _tls12ServerApplicationCipher is not null))
        {
            await _writeGate.WaitAsync().ConfigureAwait(false);
            try
            {
                if (!_localClosed)
                {
                    var encrypted = NegotiatedProtocolVersion == TlsProtocolVersion.Tls12
                        ? _tls12ServerApplicationCipher!.Encrypt(
                            TlsContentType.Alert,
                            new byte[] { 1, (byte)TlsAlertDescription.CloseNotify },
                            TlsConstants.Tls12Version)
                        : _serverApplicationCipher!.Encrypt(
                            TlsContentType.Alert,
                            new byte[] { 1, (byte)TlsAlertDescription.CloseNotify });
                    try
                    {
                        await _writer.WriteRecordAsync(
                            NegotiatedProtocolVersion == TlsProtocolVersion.Tls12
                                ? TlsContentType.Alert
                                : TlsContentType.ApplicationData,
                            encrypted,
                            CancellationToken.None,
                            NegotiatedProtocolVersion == TlsProtocolVersion.Tls12
                                ? TlsConstants.Tls12Version
                                : TlsConstants.LegacyRecordVersion).ConfigureAwait(false);
                    }
                    finally
                    {
                        CryptographicOperations.ZeroMemory(encrypted);
                    }
                    _localClosed = true;
                }
            }
            catch
            {
                _localClosed = true;
            }
            finally
            {
                _writeGate.Release();
            }
        }

        _disposed = true;
        _serverHandshakeCipher?.Dispose();
        _clientHandshakeCipher?.Dispose();
        _serverApplicationCipher?.Dispose();
        _clientApplicationCipher?.Dispose();
        _keySchedule?.Dispose();
        _tls12ServerApplicationCipher?.Dispose();
        _tls12ClientApplicationCipher?.Dispose();
        _tls12KeySchedule?.Dispose();
        if (_tls12ClientRandom is not null)
        {
            CryptographicOperations.ZeroMemory(_tls12ClientRandom);
        }
        if (_tls12ServerRandom is not null)
        {
            CryptographicOperations.ZeroMemory(_tls12ServerRandom);
        }
        if (_tlsUnique is not null)
        {
            CryptographicOperations.ZeroMemory(_tlsUnique);
        }
        _configuration.Dispose();
        if (!_leaveTransportOpen && _transport is not null)
        {
            await _transport.DisposeAsync().ConfigureAwait(false);
        }
        _readGate.Dispose();
        _writeGate.Dispose();
    }
}

internal sealed class Tls13SelectedServerResumption : IDisposable
{
    internal Tls13SelectedServerResumption(
        int identityIndex,
        Tls13ServerSessionTicketState state)
    {
        IdentityIndex = identityIndex;
        State = state;
    }

    internal int IdentityIndex { get; }
    internal Tls13ServerSessionTicketState State { get; }

    public void Dispose() => State.Dispose();
}
