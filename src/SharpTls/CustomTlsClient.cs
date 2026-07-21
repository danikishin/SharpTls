using System.Net.Sockets;
using System.Security.Cryptography;
using SharpTls.Certificates;
using SharpTls.Cryptography;
using SharpTls.Ech;
using SharpTls.Handshake;
using SharpTls.Protocol;
using SharpTls.Records;
using SharpTls.Sessions;

namespace SharpTls;

/// <summary>A pure managed TLS client with an explicitly encoded ClientHello.</summary>
public sealed class CustomTlsClient : IAsyncDisposable, IApplicationDataTransport
{
    private readonly CustomTlsClientConfiguration _configuration;
    private readonly Tls13ClientStateMachine _tls13State = new();
    private readonly Tls12ClientStateMachine _tls12State = new();
    private readonly SemaphoreSlim _readLock = new(1, 1);
    private readonly SemaphoreSlim _writeLock = new(1, 1);
    private Socket? _socket;
    private Stream? _stream;
    private TlsRecordReader? _recordReader;
    private TlsRecordWriter? _recordWriter;
    private HandshakeDeframer? _postHandshakeDeframer;
    private TranscriptHash? _postHandshakeAuthenticationBaseTranscript;
    private Tls13RecordCipher? _clientApplicationCipher;
    private Tls13RecordCipher? _serverApplicationCipher;
    private Tls13KeySchedule? _applicationKeySchedule;
    private Tls12AeadRecordCipher? _tls12ClientApplicationCipher;
    private Tls12AeadRecordCipher? _tls12ServerApplicationCipher;
    private Tls12KeySchedule? _tls12ApplicationKeySchedule;
    private byte[]? _tls12ClientRandom;
    private byte[]? _tls12ServerRandom;
    private byte[]? _tlsUnique;
    private bool _peerClosed;
    private bool _localClosed;
    private bool _disposed;
    private int _connectStarted;
    private int _applicationStreamCreated;
    private bool _ownsTransport;
    private TlsProtocolVersion? _activeHandshakeVersion;
    private Tls13SessionOrigin? _sessionOrigin;
    private DateTimeOffset? _tls13AuthenticationExpiresAt;
    private readonly HashSet<string> _receivedTicketNonces = new(StringComparer.Ordinal);
    private readonly HashSet<string> _receivedCertificateRequestContexts = new(StringComparer.Ordinal);
    private int _receivedSessionTicketCount;
    private int _postHandshakeAuthenticationCount;
    private int _peerKeyUpdateResponsePending;
    private int _awaitingRequestedPeerKeyUpdate;
    private int? _negotiatedReceiveRecordSizeLimit;
    private int? _negotiatedSendRecordSizeLimit;
    private byte[]? _negotiatedPeerApplicationSettings;
    private string? _authenticatedReferenceIdentity;
    private byte[][] _peerCertificateChain = [];
    private byte[]? _stapledOcspResponse;
    private byte[][] _signedCertificateTimestamps = [];
    private bool _handshakeCompleted;
    private readonly object _handshakeEventSync = new();
    private bool _insideHandshakeEventObserver;
    private long _handshakeEventSequence;

    /// <summary>Creates a client and snapshots all mutable options.</summary>
    public CustomTlsClient(CustomTlsClientOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);
        _configuration = options.Snapshot();
    }

    /// <summary>Gets whether the authenticated handshake completed and the connection remains open.</summary>
    public bool IsConnected =>
        IsHandshakeConnected() && !_localClosed && !_peerClosed;

    /// <summary>Gets the negotiated protocol version after a completed handshake.</summary>
    public TlsProtocolVersion? NegotiatedProtocolVersion { get; private set; }

    /// <summary>Gets the negotiated TLS 1.3 cipher suite after connection.</summary>
    public TlsCipherSuite? NegotiatedCipherSuite { get; private set; }

    /// <summary>Gets the negotiated ALPN protocol, or null when ALPN was not negotiated.</summary>
    public string? NegotiatedApplicationProtocol { get; private set; }

    /// <summary>
    /// Gets the negotiated experimental ALPS/application_settings code point, or null.
    /// This is not an IANA-assigned TLS extension.
    /// </summary>
    public TlsApplicationSettingsCodePoint? NegotiatedApplicationSettingsCodePoint { get; private set; }

    /// <summary>
    /// Gets a copy of the authenticated peer application-settings payload, or null when absent.
    /// The value is published only after server Finished verification.
    /// </summary>
    public byte[]? NegotiatedPeerApplicationSettings =>
        _negotiatedPeerApplicationSettings is null
            ? null
            : (byte[])_negotiatedPeerApplicationSettings.Clone();

    /// <summary>Gets the negotiated key-exchange group after connection.</summary>
    public NamedGroup? NegotiatedGroup { get; private set; }

    /// <summary>Gets whether this handshake processed a HelloRetryRequest.</summary>
    public bool HandshakeUsedHelloRetryRequest { get; private set; }

    /// <summary>Gets whether TLS 1.3 ticket or TLS 1.2 session-ID resumption authenticated this connection.</summary>
    public bool SessionWasResumed { get; private set; }

    /// <summary>Gets whether TLS 1.3 authenticated this connection with the configured external PSK.</summary>
    public bool ExternalPskWasSelected { get; private set; }

    /// <summary>Gets the outcome of the explicitly configured TLS 1.3 early-data request.</summary>
    public Tls13EarlyDataStatus EarlyDataStatus { get; private set; }

    /// <summary>Gets whether RFC 9849 ECH was configured and authenticated as accepted.</summary>
    public bool EncryptedClientHelloAccepted { get; private set; }

    /// <summary>Gets the number of completed client sending-key updates.</summary>
    public ulong ClientKeyUpdateCount { get; private set; }

    /// <summary>Gets the number of authenticated server receiving-key updates.</summary>
    public ulong ServerKeyUpdateCount { get; private set; }

    /// <summary>Gets the number of completed TLS 1.3 post-handshake authentication responses.</summary>
    public int PostHandshakeAuthenticationCount => _postHandshakeAuthenticationCount;

    /// <summary>
    /// Gets the negotiated maximum protected plaintext the peer may send to this client.
    /// Null means RFC 8449 was not negotiated.
    /// </summary>
    public int? NegotiatedReceiveRecordSizeLimit => _negotiatedReceiveRecordSizeLimit;

    /// <summary>
    /// Gets the negotiated maximum protected plaintext this client may send to the peer.
    /// Null means RFC 8449 was not negotiated.
    /// </summary>
    public int? NegotiatedSendRecordSizeLimit => _negotiatedSendRecordSizeLimit;

    /// <summary>Gets whether TLS 1.3 server authentication used an RFC 9345 credential.</summary>
    public bool ServerUsedDelegatedCredential { get; private set; }

    /// <summary>Gets whether the explicit dangerous option bypasses server PKI/name validation.</summary>
    public bool ServerCertificateValidationSkipped =>
        _configuration.CertificateValidation.DangerouslySkipServerCertificateValidation;

    /// <summary>Gets the authenticated delegated credential expiry, when one was used.</summary>
    public DateTimeOffset? ServerDelegatedCredentialExpiresAt { get; private set; }

    /// <summary>
    /// Returns a defensive, secret-free snapshot of the completed connection. The snapshot
    /// remains unchanged while later KeyUpdate or close events affect the live connection.
    /// </summary>
    public TlsConnectionState GetConnectionState()
    {
        if (!Volatile.Read(ref _handshakeCompleted))
        {
            throw new InvalidOperationException("The authenticated TLS handshake has not completed.");
        }

        return new TlsConnectionState(
            _authenticatedReferenceIdentity!,
            NegotiatedProtocolVersion!.Value,
            NegotiatedCipherSuite!.Value,
            NegotiatedApplicationProtocol,
            NegotiatedGroup!.Value,
            HandshakeUsedHelloRetryRequest,
            SessionWasResumed,
            ExternalPskWasSelected,
            _configuration.CertificateValidation.DangerouslySkipServerCertificateValidation,
            EarlyDataStatus,
            _configuration.Ech is not null,
            EncryptedClientHelloAccepted,
            _configuration.EchGrease is not null,
            NegotiatedApplicationSettingsCodePoint,
            _negotiatedPeerApplicationSettings,
            _negotiatedReceiveRecordSizeLimit,
            _negotiatedSendRecordSizeLimit,
            ServerUsedDelegatedCredential,
            ServerDelegatedCredentialExpiresAt,
            ClientKeyUpdateCount,
            ServerKeyUpdateCount,
            _postHandshakeAuthenticationCount,
            _tlsUnique,
            _peerCertificateChain,
            _stapledOcspResponse,
            _signedCertificateTimestamps,
            _localClosed,
            _peerClosed);
    }

    /// <summary>
    /// Exports connection-bound keying material using RFC 9846 section 7.5 for TLS 1.3
    /// or RFC 5705 for TLS 1.2.
    /// The caller owns the returned sensitive bytes and should zero them after use.
    /// </summary>
    public byte[] ExportKeyingMaterial(
        string label,
        ReadOnlySpan<byte> context,
        int outputLength)
    {
        EnsureApplicationState(allowPeerClosed: true);
        if (NegotiatedProtocolVersion == TlsProtocolVersion.Tls12)
        {
            return (_tls12ApplicationKeySchedule ??
                throw new InvalidOperationException("TLS 1.2 exporter secret is unavailable."))
                .ExportKeyingMaterial(
                    label,
                    _tls12ClientRandom!,
                    _tls12ServerRandom!,
                    context,
                    outputLength);
        }
        return (_applicationKeySchedule ??
            throw new InvalidOperationException("TLS exporter secret is unavailable."))
            .ExportKeyingMaterial(label, context, outputLength);
    }

    /// <summary>Connects TCP and performs the configured TLS handshake.</summary>
    public async ValueTask ConnectAsync(
        string host,
        int port,
        CancellationToken cancellationToken = default)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        ArgumentException.ThrowIfNullOrWhiteSpace(host);
        if (port is < 1 or > ushort.MaxValue)
        {
            throw new ArgumentOutOfRangeException(nameof(port));
        }
        if (Interlocked.Exchange(ref _connectStarted, 1) != 0)
        {
            throw new InvalidOperationException("A CustomTlsClient instance can connect only once.");
        }

        var socket = new Socket(SocketType.Stream, ProtocolType.Tcp)
        {
            NoDelay = _configuration.TcpNoDelay,
        };
        _socket = socket;
        _ownsTransport = true;

        try
        {
            await socket.ConnectAsync(host, port, cancellationToken).ConfigureAwait(false);
            _stream = new NetworkStream(socket, ownsSocket: true);
            _recordReader = new TlsRecordReader(_stream);
            _recordWriter = new TlsRecordWriter(_stream);
            InitializeTransportState();

            var referenceIdentity = _configuration.ServerName ?? host;
            _sessionOrigin = Tls13SessionOrigin.Create(
                referenceIdentity,
                port,
                _configuration.CertificateValidation
                    .DangerouslySkipServerCertificateValidation);
            await PerformHandshakeAsync(referenceIdentity, cancellationToken).ConfigureAwait(false);
        }
        catch
        {
            FailActiveState();
            await DisposeTransportAsync().ConfigureAwait(false);
            throw;
        }
    }

    /// <summary>
    /// Performs TLS over an already-connected caller-provided duplex stream.
    /// The reference identity is used for SNI and certificate validation unless
    /// <see cref="CustomTlsClientOptions.ServerName"/> overrides it or certificate
    /// validation is explicitly bypassed.
    /// </summary>
    public async ValueTask AuthenticateAsync(
        Stream transport,
        string referenceIdentity,
        bool leaveOpen = false,
        CancellationToken cancellationToken = default)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        ArgumentNullException.ThrowIfNull(transport);
        ArgumentException.ThrowIfNullOrWhiteSpace(referenceIdentity);
        if (!transport.CanRead || !transport.CanWrite)
        {
            throw new ArgumentException(
                "The TLS transport must be a readable and writable duplex stream.",
                nameof(transport));
        }
        if (Interlocked.Exchange(ref _connectStarted, 1) != 0)
        {
            throw new InvalidOperationException("A CustomTlsClient instance can authenticate only once.");
        }

        _stream = transport;
        _ownsTransport = !leaveOpen;
        _recordReader = new TlsRecordReader(transport);
        _recordWriter = new TlsRecordWriter(transport);

        try
        {
            cancellationToken.ThrowIfCancellationRequested();
            InitializeTransportState();
            var effectiveIdentity = _configuration.ServerName ?? referenceIdentity;
            _sessionOrigin = Tls13SessionOrigin.Create(
                effectiveIdentity,
                port: null,
                _configuration.CertificateValidation
                    .DangerouslySkipServerCertificateValidation);
            await PerformHandshakeAsync(effectiveIdentity, cancellationToken).ConfigureAwait(false);
        }
        catch
        {
            FailActiveState();
            await DisposeTransportAsync().ConfigureAwait(false);
            throw;
        }
    }

    /// <summary>
    /// Opens the authenticated connection as a standard non-seekable stream.
    /// Only one application stream can be created because it owns plaintext read buffering.
    /// </summary>
    public CustomTlsStream OpenApplicationStream(bool leaveClientOpen = false)
    {
        EnsureApplicationState();
        if (Interlocked.Exchange(ref _applicationStreamCreated, 1) != 0)
        {
            throw new InvalidOperationException(
                "Only one application stream can be opened for a TLS connection.");
        }

        return new CustomTlsStream(this, leaveClientOpen);
    }

    /// <summary>Encrypts and writes application data, splitting it into configured TLS records.</summary>
    public async ValueTask WriteApplicationDataAsync(
        ReadOnlyMemory<byte> data,
        CancellationToken cancellationToken = default)
    {
        EnsureApplicationState();
        await _writeLock.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            EnsureApplicationState();
            await FlushPendingPeerKeyUpdateResponseCoreAsync(cancellationToken)
                .ConfigureAwait(false);
            if (NegotiatedProtocolVersion == TlsProtocolVersion.Tls12)
            {
                await WriteTls12ApplicationDataCoreAsync(data, cancellationToken).ConfigureAwait(false);
                return;
            }

            if (data.IsEmpty)
            {
                await EnsureClientApplicationKeyCapacityAsync(cancellationToken).ConfigureAwait(false);
                await WriteProtectedRecordAsync(
                    _clientApplicationCipher!,
                    TlsContentType.ApplicationData,
                    data,
                    _configuration.ApplicationDataPaddingLength,
                    cancellationToken).ConfigureAwait(false);
                return;
            }

            var padding = _configuration.ApplicationDataPaddingLength;
            var maximumContent = GetTls13MaximumContentLength(padding);
            if (maximumContent < 1)
            {
                throw new InvalidOperationException(
                    "Application padding leaves no room for non-empty content.");
            }

            var offset = 0;
            var recordIndex = 0;
            while (offset < data.Length)
            {
                await EnsureClientApplicationKeyCapacityAsync(cancellationToken).ConfigureAwait(false);
                var requested = _configuration.ApplicationDataFragmentation.GetNextSize(
                    recordIndex++,
                    data.Length - offset);
                var length = Math.Min(requested, maximumContent);
                await WriteProtectedRecordAsync(
                    _clientApplicationCipher!,
                    TlsContentType.ApplicationData,
                    data.Slice(offset, length),
                    padding,
                    cancellationToken).ConfigureAwait(false);
                offset += length;
            }
        }
        catch (Exception exception) when (IsConnectionFailure(exception))
        {
            await FailAndDisposeTransportAsync().ConfigureAwait(false);
            throw;
        }
        catch (OperationCanceledException)
        {
            await FailAndDisposeTransportAsync().ConfigureAwait(false);
            throw;
        }
        finally
        {
            _writeLock.Release();
        }
    }

    /// <summary>Reads and authenticates one application-data fragment; null indicates peer close_notify.</summary>
    public async ValueTask<byte[]?> ReadApplicationDataAsync(
        CancellationToken cancellationToken = default)
    {
        EnsureApplicationState(allowPeerClosed: true);
        await _readLock.WaitAsync(cancellationToken).ConfigureAwait(false);
        var keyUpdateStateChanged = false;
        var postHandshakeAuthenticationStateChanged = false;
        try
        {
            if (_peerClosed)
            {
                return null;
            }
            if (NegotiatedProtocolVersion == TlsProtocolVersion.Tls12)
            {
                return await ReadTls12ApplicationDataCoreAsync(cancellationToken).ConfigureAwait(false);
            }

            while (true)
            {
                var record = await _recordReader!.ReadAsync(cancellationToken).ConfigureAwait(false);
                if (record is null)
                {
                    throw TlsProtocolException.Decode(
                        "TLS transport ended without an authenticated close_notify alert.");
                }
                if (record.ContentType != TlsContentType.ApplicationData)
                {
                    throw TlsProtocolException.Unexpected(
                        "Received an unprotected or unexpected record after the handshake.");
                }

                var inner = _serverApplicationCipher!.Decrypt(record.Fragment);
                ValidateReceivedProtectedPlaintextLength(inner.EncodedLength);
                switch (inner.ContentType)
                {
                    case TlsContentType.ApplicationData:
                        if (_postHandshakeDeframer!.BufferedBytes != 0)
                        {
                            throw TlsProtocolException.Unexpected(
                                "Application data interleaved a fragmented post-handshake message.");
                        }
                        await FlushPendingPeerKeyUpdateResponseAsync(cancellationToken)
                            .ConfigureAwait(false);
                        return inner.Content;

                    case TlsContentType.Alert:
                        if (_postHandshakeDeframer!.BufferedBytes != 0)
                        {
                            throw TlsProtocolException.Unexpected(
                                "An alert interleaved a fragmented post-handshake message.");
                        }
                        if (ProcessApplicationAlert(inner.Content))
                        {
                            return null;
                        }
                        break;

                    case TlsContentType.Handshake:
                        if (inner.Content.Length == 0)
                        {
                            throw TlsProtocolException.Unexpected(
                                "Received a zero-length protected Handshake fragment.");
                        }
                        _postHandshakeDeframer!.Append(inner.Content);
                        while (_postHandshakeDeframer.TryRead(out var message))
                        {
                            if (message!.Type == HandshakeType.NewSessionTicket)
                            {
                                ProcessTls13NewSessionTicket(message.Body);
                                NotifyHandshakeEvent(
                                    TlsHandshakeEventKind.NewSessionTicket,
                                    TlsHandshakeEventDirection.ServerToClient,
                                    message.Encoded.Length);
                                continue;
                            }

                            if (message.Type == HandshakeType.CertificateRequest)
                            {
                                postHandshakeAuthenticationStateChanged = true;
                                await ProcessPostHandshakeCertificateRequestAsync(
                                    message,
                                    cancellationToken).ConfigureAwait(false);
                                postHandshakeAuthenticationStateChanged = false;
                                NotifyHandshakeEvent(
                                    TlsHandshakeEventKind.CertificateRequest,
                                    TlsHandshakeEventDirection.ServerToClient,
                                    message.Encoded.Length);
                                continue;
                            }

                            if (message.Type == HandshakeType.KeyUpdate)
                            {
                                if (_postHandshakeDeframer.BufferedBytes != 0)
                                {
                                    throw TlsProtocolException.Unexpected(
                                        "KeyUpdate was not aligned to its protected record boundary.");
                                }
                                var requestUpdate = KeyUpdateProcessor.ParseRequestUpdate(message.Body);
                                keyUpdateStateChanged = true;
                                await ProcessPeerKeyUpdateAsync(requestUpdate, cancellationToken)
                                    .ConfigureAwait(false);
                                keyUpdateStateChanged = false;
                                NotifyHandshakeEvent(
                                    TlsHandshakeEventKind.KeyUpdate,
                                    TlsHandshakeEventDirection.ServerToClient,
                                    message.Encoded.Length);
                                continue;
                            }

                            throw TlsProtocolException.Unexpected(
                                $"Unsupported post-handshake message {message.Type}.");
                        }
                        break;

                    default:
                        throw TlsProtocolException.Unexpected("Unexpected protected content type.");
                }
            }
        }
        catch (TlsProtocolException exception)
        {
            if (!exception.IsPeerAlert)
            {
                await TrySendApplicationFatalAlertAsync(exception.Alert).ConfigureAwait(false);
            }

            await FailAndDisposeTransportAsync().ConfigureAwait(false);
            throw;
        }
        catch (Exception exception) when (IsConnectionFailure(exception))
        {
            await FailAndDisposeTransportAsync().ConfigureAwait(false);
            throw;
        }
        catch (OperationCanceledException) when (
            keyUpdateStateChanged || postHandshakeAuthenticationStateChanged)
        {
            await FailAndDisposeTransportAsync().ConfigureAwait(false);
            throw;
        }
        finally
        {
            _readLock.Release();
        }
    }

    /// <summary>
    /// Sends a TLS 1.3 KeyUpdate and rotates the client application traffic secret.
    /// Optionally asks the peer to update its sending keys in response.
    /// </summary>
    public async ValueTask RequestKeyUpdateAsync(
        bool requestPeerUpdate = false,
        CancellationToken cancellationToken = default)
    {
        EnsureApplicationState();
        if (NegotiatedProtocolVersion != TlsProtocolVersion.Tls13)
        {
            throw new NotSupportedException("KeyUpdate is available only for TLS 1.3 connections.");
        }
        await _writeLock.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            EnsureApplicationState();
            if (Interlocked.Exchange(ref _peerKeyUpdateResponsePending, 0) != 0)
            {
                try
                {
                    await SendKeyUpdateCoreAsync(requestPeerUpdate, cancellationToken)
                        .ConfigureAwait(false);
                    return;
                }
                catch
                {
                    Interlocked.Exchange(ref _peerKeyUpdateResponsePending, 1);
                    throw;
                }
            }
            await SendKeyUpdateCoreAsync(requestPeerUpdate, cancellationToken).ConfigureAwait(false);
        }
        catch (Exception exception) when (IsConnectionFailure(exception))
        {
            await FailAndDisposeTransportAsync().ConfigureAwait(false);
            throw;
        }
        catch (OperationCanceledException)
        {
            await FailAndDisposeTransportAsync().ConfigureAwait(false);
            throw;
        }
        finally
        {
            _writeLock.Release();
        }
    }

    /// <summary>Sends an authenticated warning-level close_notify and closes the transport.</summary>
    public async ValueTask CloseAsync(CancellationToken cancellationToken = default)
    {
        if (_disposed || _localClosed)
        {
            return;
        }

        await _writeLock.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            if (_localClosed)
            {
                return;
            }

            if (_tls12State.State == Tls12ClientState.Connected &&
                _tls12ClientApplicationCipher is not null)
            {
                await WriteTls12ProtectedRecordAsync(
                    _tls12ClientApplicationCipher,
                    TlsContentType.Alert,
                    new byte[] { 1, (byte)TlsAlertDescription.CloseNotify },
                    cancellationToken).ConfigureAwait(false);
                _tls12State.BeginClose();
            }
            else if (_tls13State.State == Tls13ClientState.Connected &&
                     _clientApplicationCipher is not null)
            {
                await EnsureClientApplicationKeyCapacityAsync(cancellationToken).ConfigureAwait(false);
                await WriteProtectedRecordAsync(
                    _clientApplicationCipher,
                    TlsContentType.Alert,
                    new byte[] { 1, (byte)TlsAlertDescription.CloseNotify },
                    paddingLength: 0,
                    cancellationToken).ConfigureAwait(false);
                _tls13State.BeginClose();
            }

            _localClosed = true;
        }
        catch (Exception exception) when (IsConnectionFailure(exception))
        {
            _localClosed = true;
            await FailAndDisposeTransportAsync().ConfigureAwait(false);
            throw;
        }
        finally
        {
            _writeLock.Release();
        }

        await DisposeTransportAsync().ConfigureAwait(false);
        if (_tls13State.State == Tls13ClientState.Closing)
        {
            _tls13State.Closed();
        }
        if (_tls12State.State == Tls12ClientState.Closing)
        {
            _tls12State.Closed();
        }
    }

    /// <inheritdoc />
    public async ValueTask DisposeAsync()
    {
        if (_disposed)
        {
            return;
        }

        try
        {
            await CloseAsync(CancellationToken.None).ConfigureAwait(false);
        }
        catch (Exception exception) when (
            exception is IOException or SocketException or ObjectDisposedException)
        {
            // Dispose must remain best-effort even when a peer has already reset the socket.
        }
        finally
        {
            try
            {
                await DisposeTransportAsync().ConfigureAwait(false);
            }
            finally
            {
                _disposed = true;
                _clientApplicationCipher?.Dispose();
                _serverApplicationCipher?.Dispose();
                _applicationKeySchedule?.Dispose();
                _postHandshakeAuthenticationBaseTranscript?.Dispose();
                _tls12ClientApplicationCipher?.Dispose();
                _tls12ServerApplicationCipher?.Dispose();
                _tls12ApplicationKeySchedule?.Dispose();
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
                _readLock.Dispose();
                _writeLock.Dispose();
            }
        }
    }

    private ValueTask PerformHandshakeAsync(
        string referenceIdentity,
        CancellationToken cancellationToken) => UsesTls12OnlyProfile()
        ? PerformTls12HandshakeAsync(referenceIdentity, cancellationToken)
        : PerformTls13HandshakeAsync(referenceIdentity, cancellationToken);

    private TlsClientHelloWireForm GetConfiguredClientHelloWireForm() =>
        _configuration.Ech is not null
            ? TlsClientHelloWireForm.EncryptedClientHelloOuter
            : _configuration.EchGrease is not null
                ? TlsClientHelloWireForm.GreaseEncryptedClientHello
                : TlsClientHelloWireForm.Direct;

    private void InspectClientHello(
        TlsClientHelloFlight flight,
        TlsClientHelloWireForm wireForm,
        ReadOnlySpan<byte> encodedHandshake,
        ushort legacyRecordVersion = TlsConstants.LegacyRecordVersion)
    {
        _configuration.ClientHelloInspector?.Invoke(
            new TlsClientHelloInspection(
                flight,
                wireForm,
                encodedHandshake,
                _configuration.HandshakeFragmentation,
                legacyRecordVersion));
        NotifyHandshakeEvent(
            TlsHandshakeEventKind.ClientHello,
            TlsHandshakeEventDirection.ClientToServer,
            encodedHandshake.Length,
            flight);
    }

    private async ValueTask PerformTls13HandshakeAsync(
        string referenceIdentity,
        CancellationToken cancellationToken)
    {
        ClientHelloBuildResult? offer = null;
        EchClientHelloBuildResult? firstEchOffer = null;
        EchClientHelloRetryBuildResult? retryEchOffer = null;
        TranscriptHash? transcript = null;
        Tls13KeySchedule? keySchedule = null;
        Tls13RecordCipher? clientHandshakeCipher = null;
        Tls13RecordCipher? serverHandshakeCipher = null;
        Tls13RecordCipher? clientApplicationCipher = null;
        Tls13RecordCipher? serverApplicationCipher = null;
        Tls13KeySchedule? offeredPskSchedule = null;
        Tls13RecordCipher? earlyDataCipher = null;
        ServerCertificateMessage? certificates = null;
        var deframer = new HandshakeDeframer(_configuration.Limits.MaxHandshakeMessageSize);
        var sentCompatibilityCcs = false;
        var certificateRequested = false;
        Tls13CertificateRequest? clientCertificateRequest = null;
        var delegatedToTls12 = false;
        DateTimeOffset? certificateNotAfter = null;
        Tls13SessionTicket? offeredTicket = null;
        var offeredTickets = new List<Tls13SessionTicket>();
        int? selectedPskIndex = null;
        var resumed = false;
        var pskAuthenticated = false;
        var attemptedEarlyData = false;
        var earlyDataAccepted = false;
        byte[]? pendingPeerApplicationSettings = null;
        TlsApplicationSettingsCodePoint? pendingApplicationSettingsCodePoint = null;
        TlsEchConfigList? echRetryConfigurations = null;
        var echAccepted = false;
        var echRejected = false;
        var echGreased = _configuration.EchGrease is not null;

        try
        {
            if (_configuration.SessionCache is { } cache)
            {
                var origin = _sessionOrigin ??
                    throw new InvalidOperationException("TLS session origin is unavailable.");
                offeredTickets.AddRange(cache.TryTakeMany(
                    origin,
                    _configuration.ClientHello.Spec.CipherSuites,
                    _configuration.ClientHello.Spec.AlpnProtocols,
                    _configuration.MaximumOfferedTls13PskIdentities,
                    _configuration.Ech?.ConfigListHash,
                    _configuration.ClientHello.Spec.ApplicationSettingsCodePoint,
                    _configuration.ClientApplicationSettings));
                if (_configuration.EarlyData is { } configuredEarlyData)
                {
                    for (var index = 0; index < offeredTickets.Count; index++)
                    {
                        var candidate = offeredTickets[index];
                        if (candidate.MaximumEarlyDataSize is not { } candidateEarlyDataSize ||
                            candidateEarlyDataSize < configuredEarlyData.Data.Length ||
                            !_configuration.ClientHello.Spec.CipherSuites.Contains(
                                candidate.CipherSuite) ||
                            (_configuration.ClientHello.Spec.ApplicationSettingsCodePoint.HasValue &&
                             candidate.ApplicationSettingsCodePoint !=
                                _configuration.ClientHello.Spec.ApplicationSettingsCodePoint))
                        {
                            continue;
                        }
                        if (index != 0)
                        {
                            (offeredTickets[0], offeredTickets[index]) =
                                (offeredTickets[index], offeredTickets[0]);
                        }
                        break;
                    }
                }
                offeredTicket = offeredTickets.FirstOrDefault();
            }
            EarlyDataStatus = _configuration.EarlyData is null
                ? Tls13EarlyDataStatus.NotConfigured
                : Tls13EarlyDataStatus.Unavailable;
            if (offeredTicket is not null && _configuration.EarlyData is { } earlyData &&
                offeredTicket.MaximumEarlyDataSize is { } maximumEarlyDataSize &&
                maximumEarlyDataSize >= earlyData.Data.Length &&
                _configuration.ClientHello.Spec.CipherSuites.Contains(offeredTicket.CipherSuite) &&
                (!_configuration.ClientHello.Spec.ApplicationSettingsCodePoint.HasValue ||
                 offeredTicket.ApplicationSettingsCodePoint ==
                    _configuration.ClientHello.Spec.ApplicationSettingsCodePoint))
            {
                attemptedEarlyData = true;
            }
            var pskOffer = offeredTicket is not null
                ? new Tls13PskOffer(
                    offeredTickets,
                    _configuration.SessionCache!.UtcNow,
                    offerEarlyData: attemptedEarlyData)
                : _configuration.ExternalPsk is { } externalPsk
                    ? new Tls13PskOffer(externalPsk)
                    : null;
            if (_configuration.Ech is { } ech)
            {
                firstEchOffer = EchClientHelloBuilder.Build(
                    referenceIdentity,
                    _configuration.ClientHello.Spec.SnapshotConfiguration(),
                    ech.OuterClientHello.Spec.SnapshotConfiguration(),
                    ech.Selection,
                    SecureRandomSource.Instance,
                    new KeyShareSet(),
                    new KeyShareSet(),
                    ech.CompressedOuterExtensions,
                    pskOffer);
                offer = firstEchOffer.Outer;
            }
            else if (_configuration.EchGrease is { } echGrease)
            {
                offer = EchGreaseClientHelloBuilder.Build(
                    referenceIdentity,
                    _configuration.ClientHello.Spec.SnapshotConfiguration(),
                    echGrease,
                    SecureRandomSource.Instance,
                    new KeyShareSet(),
                    pskOffer);
            }
            else
            {
                offer = _configuration.ClientHello.BuildSecure(referenceIdentity, pskOffer);
            }
            InspectClientHello(
                TlsClientHelloFlight.Initial,
                GetConfiguredClientHelloWireForm(),
                offer.EncodedHandshake,
                _configuration.UseInitialCompatibilityRecordVersion
                    ? (ushort)0x0301
                    : (ushort)0x0303);
            await _recordWriter!.WriteFragmentedAsync(
                TlsContentType.Handshake,
                offer.EncodedHandshake,
                _configuration.HandshakeFragmentation,
                cancellationToken,
                _configuration.UseInitialCompatibilityRecordVersion ? (ushort)0x0301 : (ushort)0x0303)
                .ConfigureAwait(false);
            _tls13State.ClientHelloSent();

            if (attemptedEarlyData)
            {
                var earlySuite = CipherSuiteInfo.Get(offeredTicket!.CipherSuite);
                var psk = offeredTicket.CopyPsk();
                var clientHelloHash = HashHandshake(
                    earlySuite,
                    firstEchOffer?.Inner.EncodedHandshake ?? offer.EncodedHandshake);
                try
                {
                    offeredPskSchedule = new Tls13KeySchedule(earlySuite, psk);
                    offeredPskSchedule.DeriveClientEarlyTrafficSecret(clientHelloHash);
                    await WriteNssKeyLogSecretAsync(
                        "CLIENT_EARLY_TRAFFIC_SECRET",
                        firstEchOffer?.Inner.Random ?? offer.Random,
                        offeredPskSchedule.CopyClientEarlyTrafficSecret(),
                        cancellationToken).ConfigureAwait(false);
                    earlyDataCipher = CreateCipher(
                        earlySuite,
                        offeredPskSchedule.TakeClientEarlyTrafficKeys());
                    await WriteTls13ApplicationFragmentsAsync(
                        earlyDataCipher,
                        _configuration.EarlyData!.Data,
                        cancellationToken,
                        offeredTicket.PeerRecordSizeLimit).ConfigureAwait(false);
                    earlyDataCipher.Dispose();
                    earlyDataCipher = null;
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(psk);
                    CryptographicOperations.ZeroMemory(clientHelloHash);
                }
            }

            var serverHelloMessage = await ReadPlainHandshakeMessageAsync(deframer, cancellationToken)
                .ConfigureAwait(false);
            if (serverHelloMessage.Type != HandshakeType.ServerHello)
            {
                throw TlsProtocolException.Unexpected("Expected ServerHello or HelloRetryRequest.");
            }
            if (TlsServerHelloVersionDetector.Detect(serverHelloMessage.Body) ==
                TlsProtocolVersion.Tls12)
            {
                if (!offer.Configuration.SupportedVersions.Contains(TlsProtocolVersion.Tls12))
                {
                    throw new TlsProtocolException(
                        TlsAlertDescription.ProtocolVersion,
                        "Server selected TLS 1.2 even though the ClientHello did not offer it.");
                }

                _tls13State.Fail();
                _activeHandshakeVersion = TlsProtocolVersion.Tls12;
                _tls12State.TransportConnected();
                _tls12State.ClientHelloSent();
                delegatedToTls12 = true;
                await PerformTls12HandshakeAsync(
                    referenceIdentity,
                    cancellationToken,
                    offer,
                    deframer,
                    serverHelloMessage).ConfigureAwait(false);
                return;
            }
            ServerHelloResult serverHello;
            if (firstEchOffer is not null)
            {
                var selectedSuite = EchAcceptanceConfirmation.ReadCipherSuite(
                    serverHelloMessage.Encoded);
                echAccepted = EchAcceptanceConfirmation.IsHelloRetryRequest(
                    serverHelloMessage.Encoded)
                    ? EchAcceptanceConfirmation.VerifyHelloRetryRequest(
                        selectedSuite,
                        firstEchOffer.Inner.EncodedHandshake,
                        serverHelloMessage.Encoded)
                    : EchAcceptanceConfirmation.VerifyServerHello(
                        selectedSuite,
                        firstEchOffer.Inner.EncodedHandshake,
                        serverHelloMessage.Encoded);
                echRejected = !echAccepted;
                offer = echAccepted ? firstEchOffer.Inner : firstEchOffer.Outer;
            }
            serverHello = ServerHelloParser.Parse(serverHelloMessage.Body, offer);
            var suite = CipherSuiteInfo.Get(serverHello.CipherSuite);

            if (serverHello.IsHelloRetryRequest)
            {
                NotifyHandshakeEvent(
                    TlsHandshakeEventKind.HelloRetryRequest,
                    TlsHandshakeEventDirection.ServerToClient,
                    serverHelloMessage.Encoded.Length);
                HandshakeUsedHelloRetryRequest = true;
                if (attemptedEarlyData)
                {
                    EarlyDataStatus = Tls13EarlyDataStatus.Rejected;
                }
                transcript = CreateTls13Transcript(suite);
                transcript.ResetForHelloRetryRequest(offer.EncodedHandshake);
                transcript.Append(serverHelloMessage.Encoded);
                _tls13State.HelloRetryRequestReceived();

                byte[]? binderPrefix = null;
                if (pskOffer is not null)
                {
                    if (offeredTickets.Count != 0)
                    {
                        var binderPrefixes = offeredTickets
                            .Select(ticket => CreateHelloRetryRequestBinderPrefix(
                                ticket.CipherSuite,
                                offer.EncodedHandshake,
                                serverHelloMessage.Encoded))
                            .Cast<byte[]?>()
                            .ToArray();
                        pskOffer = new Tls13PskOffer(
                            offeredTickets,
                            _configuration.SessionCache!.UtcNow,
                            binderPrefixes);
                    }
                    else
                    {
                        binderPrefix = CreateHelloRetryRequestBinderPrefix(
                            pskOffer.CipherSuite,
                            offer.EncodedHandshake,
                            serverHelloMessage.Encoded);
                        pskOffer = new Tls13PskOffer(
                            _configuration.ExternalPsk!,
                            binderPrefix);
                    }
                }
                ClientHelloBuildResult wireOffer;
                if (firstEchOffer is not null && echAccepted)
                {
                    retryEchOffer = EchClientHelloBuilder.BuildRetry(
                        firstEchOffer,
                        serverHello.SelectedGroup,
                        serverHello.Cookie,
                        SecureRandomSource.Instance,
                        new KeyShareSet(),
                        new KeyShareSet(),
                        pskOffer);
                    offer = retryEchOffer.Inner;
                    wireOffer = retryEchOffer.Outer;
                }
                else if (firstEchOffer is not null)
                {
                    offer = EchClientHelloBuilder.BuildOuterRetryAfterRejection(
                        firstEchOffer,
                        serverHello.SelectedGroup,
                        serverHello.Cookie,
                        SecureRandomSource.Instance,
                        new KeyShareSet(),
                        pskOffer);
                    wireOffer = offer;
                }
                else
                {
                    var secondOffer = ClientHelloEncoder.BuildRetry(
                        offer,
                        serverHello.SelectedGroup,
                        serverHello.Cookie,
                        pskOffer);
                    offer.Dispose();
                    offer = secondOffer;
                    wireOffer = offer;
                }

                InspectClientHello(
                    TlsClientHelloFlight.AfterHelloRetryRequest,
                    GetConfiguredClientHelloWireForm(),
                    wireOffer.EncodedHandshake);

                if (_configuration.SendCompatibilityChangeCipherSpec)
                {
                    await WriteCompatibilityCcsAsync(cancellationToken).ConfigureAwait(false);
                    sentCompatibilityCcs = true;
                }

                await _recordWriter.WriteFragmentedAsync(
                    TlsContentType.Handshake,
                    wireOffer.EncodedHandshake,
                    _configuration.HandshakeFragmentation,
                    cancellationToken).ConfigureAwait(false);
                transcript.Append(offer.EncodedHandshake);
                _tls13State.SecondClientHelloSent();

                var secondServerHelloMessage = await ReadPlainHandshakeMessageAsync(deframer, cancellationToken)
                    .ConfigureAwait(false);
                if (secondServerHelloMessage.Type != HandshakeType.ServerHello)
                {
                    throw TlsProtocolException.Unexpected("Expected ServerHello after HelloRetryRequest.");
                }

                if (firstEchOffer is not null && echAccepted &&
                    !EchAcceptanceConfirmation.VerifyServerHelloAfterHelloRetryRequest(
                        suite.Suite,
                        firstEchOffer.Inner.EncodedHandshake,
                        serverHelloMessage.Encoded,
                        retryEchOffer!.Inner.EncodedHandshake,
                        secondServerHelloMessage.Encoded))
                {
                    throw TlsProtocolException.Illegal(
                        "Server accepted ECH in HelloRetryRequest but not in ServerHello.");
                }

                serverHello = ServerHelloParser.Parse(
                    secondServerHelloMessage.Body,
                    offer,
                    suite.Suite,
                    serverHello.SelectedGroup);
                transcript.Append(secondServerHelloMessage.Encoded);
                NotifyHandshakeEvent(
                    TlsHandshakeEventKind.ServerHello,
                    TlsHandshakeEventDirection.ServerToClient,
                    secondServerHelloMessage.Encoded.Length);
            }
            else
            {
                transcript = CreateTls13Transcript(suite);
                transcript.Append(offer.EncodedHandshake);
                transcript.Append(serverHelloMessage.Encoded);
                NotifyHandshakeEvent(
                    TlsHandshakeEventKind.ServerHello,
                    TlsHandshakeEventDirection.ServerToClient,
                    serverHelloMessage.Encoded.Length);
            }

            if (echRejected && serverHello.SelectedPskIdentity.HasValue)
            {
                throw TlsProtocolException.Illegal(
                    "An ECH-rejecting server selected the ClientHelloOuter GREASE PSK.");
            }

            if (deframer.BufferedBytes != 0)
            {
                throw TlsProtocolException.Unexpected(
                    "ServerHello was not aligned to the record-layer key change.");
            }
            _tls13State.ServerHelloReceived();

            pskAuthenticated = serverHello.SelectedPskIdentity.HasValue;
            if (pskAuthenticated)
            {
                selectedPskIndex = serverHello.SelectedPskIdentity!.Value;
                if (pskOffer is null || selectedPskIndex.Value >= pskOffer.Count)
                {
                    throw TlsProtocolException.Illegal(
                        "ServerHello selected an unavailable PSK identity.");
                }
                offeredTicket = pskOffer.GetTicket(selectedPskIndex.Value);
                resumed = offeredTicket is not null;
                var selectedHash = CipherSuiteInfo.Get(serverHello.CipherSuite).HashAlgorithm.Name;
                var pskHash = CipherSuiteInfo.Get(
                    pskOffer.GetCipherSuite(selectedPskIndex.Value)).HashAlgorithm.Name;
                if (selectedHash != pskHash)
                {
                    throw TlsProtocolException.Illegal(
                        "ServerHello selected a cipher suite incompatible with the PSK hash.");
                }
            }
            else if (_configuration.ExternalPsk?.RequireSelection == true)
            {
                throw new TlsProtocolException(
                    TlsAlertDescription.HandshakeFailure,
                    "The server did not select the required external PSK identity.");
            }
            else
            {
                offeredTicket = null;
            }

            var sharedSecret = offer.KeyShares.Get(serverHello.SelectedGroup)
                .DeriveSharedSecret(serverHello.PeerKeyExchange!);
            byte[]? resumptionPsk = null;
            try
            {
                if (resumed && selectedPskIndex == 0 && offeredPskSchedule is not null &&
                    serverHello.CipherSuite == offeredTicket!.CipherSuite)
                {
                    keySchedule = offeredPskSchedule;
                    offeredPskSchedule = null;
                }
                else
                {
                    offeredPskSchedule?.Dispose();
                    offeredPskSchedule = null;
                    if (pskAuthenticated)
                    {
                        resumptionPsk = pskOffer!.CopyPsk(selectedPskIndex!.Value);
                    }
                    keySchedule = new Tls13KeySchedule(
                        suite,
                        resumptionPsk is null ? default : resumptionPsk);
                }
                keySchedule.DeriveHandshakeSecrets(sharedSecret, transcript.CurrentHash());
                keySchedule.DeriveMainSecret();
                await WriteNssKeyLogSecretAsync(
                    "CLIENT_HANDSHAKE_TRAFFIC_SECRET",
                    offer.Random,
                    keySchedule.CopyClientHandshakeTrafficSecret(),
                    cancellationToken).ConfigureAwait(false);
                await WriteNssKeyLogSecretAsync(
                    "SERVER_HANDSHAKE_TRAFFIC_SECRET",
                    offer.Random,
                    keySchedule.CopyServerHandshakeTrafficSecret(),
                    cancellationToken).ConfigureAwait(false);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(sharedSecret);
                if (resumptionPsk is not null)
                {
                    CryptographicOperations.ZeroMemory(resumptionPsk);
                }
            }

            serverHandshakeCipher = CreateCipher(suite, keySchedule.GetServerHandshakeKeys());
            clientHandshakeCipher = CreateCipher(suite, keySchedule.GetClientHandshakeKeys());

            var receivedServerFinished = false;
            var maximumProtectedPlaintextBeforeEncryptedExtensions = 0;
            while (!receivedServerFinished)
            {
                cancellationToken.ThrowIfCancellationRequested();
                var record = await _recordReader!.ReadAsync(cancellationToken).ConfigureAwait(false) ??
                    throw TlsProtocolException.Decode("Unexpected EOF during the encrypted handshake.");

                if (record.ContentType == TlsContentType.ChangeCipherSpec)
                {
                    ValidateCompatibilityCcs(record.Fragment);
                    continue;
                }
                if (record.ContentType != TlsContentType.ApplicationData)
                {
                    throw TlsProtocolException.Unexpected(
                        "Expected a protected handshake record after ServerHello.");
                }

                var inner = serverHandshakeCipher.Decrypt(record.Fragment);
                if (_negotiatedReceiveRecordSizeLimit.HasValue)
                {
                    ValidateReceivedProtectedPlaintextLength(inner.EncodedLength);
                }
                else
                {
                    maximumProtectedPlaintextBeforeEncryptedExtensions = Math.Max(
                        maximumProtectedPlaintextBeforeEncryptedExtensions,
                        inner.EncodedLength);
                }
                if (inner.ContentType == TlsContentType.Alert)
                {
                    if (ShouldIgnorePeerAlert(inner.Content))
                    {
                        continue;
                    }
                }
                if (inner.ContentType != TlsContentType.Handshake)
                {
                    throw TlsProtocolException.Unexpected(
                        "Server sent non-handshake content before server Finished.");
                }
                if (inner.Content.Length == 0)
                {
                    throw TlsProtocolException.Unexpected(
                        "Received a zero-length protected Handshake fragment.");
                }

                deframer.Append(inner.Content);
                while (deframer.TryRead(out var message))
                {
                    switch (message!.Type)
                    {
                        case HandshakeType.EncryptedExtensions:
                            var encryptedExtensions = EncryptedExtensionsParser.Parse(
                                message.Body,
                                offer.Configuration,
                                offeredEarlyData: attemptedEarlyData &&
                                    !HandshakeUsedHelloRetryRequest,
                                allowApplicationSettingsWithEarlyData:
                                    attemptedEarlyData &&
                                    offeredTicket?.ApplicationSettingsCodePoint.HasValue == true,
                                echWasRejected: echRejected,
                                echWasGreased: echGreased);
                            echRetryConfigurations =
                                encryptedExtensions.EchRetryConfigurations;
                            NegotiatedApplicationProtocol = encryptedExtensions.NegotiatedAlpn;
                            if (encryptedExtensions.PeerRecordSizeLimit.HasValue)
                            {
                                _negotiatedReceiveRecordSizeLimit =
                                    offer.Configuration.RecordSizeLimit!.Value;
                                _negotiatedSendRecordSizeLimit =
                                    encryptedExtensions.PeerRecordSizeLimit.Value;
                                ValidateReceivedProtectedPlaintextLength(
                                    maximumProtectedPlaintextBeforeEncryptedExtensions);
                            }
                            if (resumed &&
                                !string.Equals(
                                    NegotiatedApplicationProtocol,
                                    offeredTicket!.NegotiatedAlpn,
                                    StringComparison.Ordinal))
                            {
                                throw TlsProtocolException.Illegal(
                                    "A resumed handshake changed the ticket's negotiated ALPN.");
                            }
                            earlyDataAccepted = encryptedExtensions.EarlyDataAccepted;
                            pendingApplicationSettingsCodePoint =
                                encryptedExtensions.ApplicationSettingsCodePoint;
                            pendingPeerApplicationSettings =
                                encryptedExtensions.PeerApplicationSettings;
                            if (resumed &&
                                offeredTicket!.ApplicationSettingsCodePoint is { } ticketCodePoint &&
                                (pendingApplicationSettingsCodePoint != ticketCodePoint ||
                                 pendingPeerApplicationSettings is null ||
                                 !CryptographicOperations.FixedTimeEquals(
                                     offeredTicket.PeerApplicationSettings!,
                                     pendingPeerApplicationSettings)))
                            {
                                throw TlsProtocolException.Illegal(
                                    "A resumed handshake changed the ticket-bound application settings.");
                            }
                            if (earlyDataAccepted &&
                                (!resumed || selectedPskIndex != 0 ||
                                 serverHello.CipherSuite != offeredTicket!.CipherSuite))
                            {
                                throw TlsProtocolException.Illegal(
                                    "The server accepted early data with incompatible PSK parameters.");
                            }
                            if (attemptedEarlyData)
                            {
                                EarlyDataStatus = earlyDataAccepted
                                    ? Tls13EarlyDataStatus.Accepted
                                    : Tls13EarlyDataStatus.Rejected;
                            }
                            transcript.Append(message.Encoded);
                            _tls13State.EncryptedExtensionsReceived();
                            break;

                        case HandshakeType.CertificateRequest:
                            if (pskAuthenticated)
                            {
                                throw TlsProtocolException.Unexpected(
                                    "A PSK-authenticated handshake cannot request an initial certificate.");
                            }
                            if (certificateRequested)
                            {
                                throw TlsProtocolException.Unexpected(
                                    "Server sent multiple initial CertificateRequest messages.");
                            }
                            clientCertificateRequest = CertificateRequestParser.ParseInitial(message.Body);
                            if (!_receivedCertificateRequestContexts.Add(
                                Convert.ToHexString(clientCertificateRequest.Context)))
                            {
                                throw TlsProtocolException.Illegal(
                                    "CertificateRequest context was reused on this connection.");
                            }
                            certificateRequested = true;
                            transcript.Append(message.Encoded);
                            _tls13State.CertificateRequestReceived();
                            break;

                        case HandshakeType.Certificate:
                            if (pskAuthenticated)
                            {
                                throw TlsProtocolException.Unexpected(
                                    "A PSK-authenticated handshake cannot send Certificate.");
                            }
                            certificates = CertificateMessageParser.Parse(
                                message.Body,
                                _configuration.Limits,
                                offer.Configuration);
                            cancellationToken.ThrowIfCancellationRequested();
                            ServerCertificateValidator.ValidateChainAndHostname(
                                certificates,
                                echRejected
                                    ? _configuration.Ech!.Selection.Configuration.PublicName
                                    : referenceIdentity,
                                _configuration.CertificateValidation);
                            CapturePeerCertificateState(certificates);
                            await ValidateCertificateEvidenceAsync(
                                echRejected
                                    ? _configuration.Ech!.Selection.Configuration.PublicName
                                    : referenceIdentity,
                                TlsProtocolVersion.Tls13,
                                certificates,
                                certificates.LeafOcspResponse,
                                certificates.LeafSignedCertificateTimestamps,
                                cancellationToken).ConfigureAwait(false);
                            cancellationToken.ThrowIfCancellationRequested();
                            certificateNotAfter = new DateTimeOffset(
                                certificates.Leaf.NotAfter.ToUniversalTime());
                            if (certificates.DelegatedCredential is { } delegatedCredential &&
                                delegatedCredential.ExpiresAt < certificateNotAfter.Value)
                            {
                                certificateNotAfter = delegatedCredential.ExpiresAt;
                            }
                            transcript.Append(message.Encoded);
                            _tls13State.CertificateReceived();
                            break;

                        case HandshakeType.CompressedCertificate:
                            if (pskAuthenticated)
                            {
                                throw TlsProtocolException.Unexpected(
                                    "A PSK-authenticated handshake cannot send CompressedCertificate.");
                            }
                            var decompressedCertificate = CompressedCertificateParser.Decompress(
                                message.Body,
                                offer.Configuration,
                                _configuration.Limits);
                            certificates = CertificateMessageParser.Parse(
                                decompressedCertificate,
                                _configuration.Limits,
                                offer.Configuration);
                            cancellationToken.ThrowIfCancellationRequested();
                            ServerCertificateValidator.ValidateChainAndHostname(
                                certificates,
                                echRejected
                                    ? _configuration.Ech!.Selection.Configuration.PublicName
                                    : referenceIdentity,
                                _configuration.CertificateValidation);
                            CapturePeerCertificateState(certificates);
                            await ValidateCertificateEvidenceAsync(
                                echRejected
                                    ? _configuration.Ech!.Selection.Configuration.PublicName
                                    : referenceIdentity,
                                TlsProtocolVersion.Tls13,
                                certificates,
                                certificates.LeafOcspResponse,
                                certificates.LeafSignedCertificateTimestamps,
                                cancellationToken).ConfigureAwait(false);
                            cancellationToken.ThrowIfCancellationRequested();
                            certificateNotAfter = new DateTimeOffset(
                                certificates.Leaf.NotAfter.ToUniversalTime());
                            if (certificates.DelegatedCredential is { } compressedDelegatedCredential &&
                                compressedDelegatedCredential.ExpiresAt < certificateNotAfter.Value)
                            {
                                certificateNotAfter = compressedDelegatedCredential.ExpiresAt;
                            }
                            transcript.Append(message.Encoded);
                            _tls13State.CertificateReceived();
                            break;

                        case HandshakeType.CertificateVerify:
                            if (pskAuthenticated)
                            {
                                throw TlsProtocolException.Unexpected(
                                    "A PSK-authenticated handshake cannot send CertificateVerify.");
                            }
                            if (certificates is null)
                            {
                                throw TlsProtocolException.Unexpected(
                                    "CertificateVerify arrived before Certificate.");
                            }
                            _ = ServerCertificateValidator.ParseAndVerifyCertificateVerify(
                                message.Body,
                                certificates.Leaf,
                                offer.Configuration.SignatureAlgorithms,
                                transcript.CurrentHash(),
                                certificates.DelegatedCredential);
                            if (certificates.DelegatedCredential is { } authenticatedDelegatedCredential)
                            {
                                ServerUsedDelegatedCredential = true;
                                ServerDelegatedCredentialExpiresAt =
                                    authenticatedDelegatedCredential.ExpiresAt;
                            }
                            transcript.Append(message.Encoded);
                            _tls13State.CertificateVerifyReceived();
                            break;

                        case HandshakeType.Finished:
                            FinishedProcessor.VerifyServerFinished(
                                message.Body,
                                keySchedule,
                                transcript.CurrentHash());
                            transcript.Append(message.Encoded);
                            _tls13State.ServerFinishedReceived(pskAuthenticated);
                            if (pendingApplicationSettingsCodePoint.HasValue && !echRejected)
                            {
                                NegotiatedApplicationSettingsCodePoint =
                                    pendingApplicationSettingsCodePoint;
                                _negotiatedPeerApplicationSettings =
                                    pendingPeerApplicationSettings is null
                                        ? []
                                        : (byte[])pendingPeerApplicationSettings.Clone();
                            }
                            receivedServerFinished = true;
                            break;

                        default:
                            throw TlsProtocolException.Unexpected(
                                $"Unexpected encrypted handshake message {message.Type}.");
                    }

                    NotifyHandshakeEvent(
                        GetHandshakeEventKind(message.Type),
                        TlsHandshakeEventDirection.ServerToClient,
                        message.Encoded.Length);

                    if (receivedServerFinished)
                    {
                        break;
                    }
                }
            }

            if (deframer.BufferedBytes != 0)
            {
                throw TlsProtocolException.Unexpected(
                    "Server Finished was not aligned to the application key change.");
            }

            keySchedule.DeriveApplicationTrafficSecrets(transcript.CurrentHash());
            await WriteNssKeyLogSecretAsync(
                "CLIENT_TRAFFIC_SECRET_0",
                offer.Random,
                keySchedule.CopyClientApplicationTrafficSecret(),
                cancellationToken).ConfigureAwait(false);
            await WriteNssKeyLogSecretAsync(
                "SERVER_TRAFFIC_SECRET_0",
                offer.Random,
                keySchedule.CopyServerApplicationTrafficSecret(),
                cancellationToken).ConfigureAwait(false);
            await WriteNssKeyLogSecretAsync(
                "EXPORTER_SECRET",
                offer.Random,
                keySchedule.CopyExporterSecret(),
                cancellationToken).ConfigureAwait(false);
            serverApplicationCipher = CreateCipher(suite, keySchedule.GetServerApplicationKeys());
            clientApplicationCipher = CreateCipher(suite, keySchedule.GetClientApplicationKeys());

            if (_configuration.SendCompatibilityChangeCipherSpec && !sentCompatibilityCcs)
            {
                await WriteCompatibilityCcsAsync(cancellationToken).ConfigureAwait(false);
            }

            if (earlyDataAccepted)
            {
                var endOfEarlyData = HandshakeMessage.Encode(HandshakeType.EndOfEarlyData, []);
                await WriteProtectedHandshakeAsync(
                    clientHandshakeCipher,
                    endOfEarlyData,
                    cancellationToken).ConfigureAwait(false);
                transcript.Append(endOfEarlyData);
            }

            if (NegotiatedApplicationSettingsCodePoint is { } applicationSettingsCodePoint)
            {
                var negotiatedAlpn = NegotiatedApplicationProtocol ??
                    throw TlsProtocolException.Illegal(
                        "application_settings was negotiated without ALPN.");
                var clientSettings = _configuration.GetClientApplicationSettings(negotiatedAlpn);
                try
                {
                    var clientEncryptedExtensions =
                        Tls13ApplicationSettings.CreateClientEncryptedExtensions(
                            applicationSettingsCodePoint,
                            clientSettings);
                    await WriteProtectedHandshakeAsync(
                        clientHandshakeCipher,
                        clientEncryptedExtensions,
                        cancellationToken).ConfigureAwait(false);
                    transcript.Append(clientEncryptedExtensions);
                    _tls13State.ClientApplicationSettingsSent();
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(clientSettings);
                }
            }

            if (certificateRequested)
            {
                var configuredCredential = echRejected
                    ? null
                    : await SelectClientCertificateAsync(
                        referenceIdentity,
                        TlsProtocolVersion.Tls13,
                        isPostHandshake: false,
                        clientCertificateRequest!.SignatureSchemes,
                        clientCertificateRequest.DelegatedCredentialSignatureSchemes,
                        certificateTypes: [],
                        cancellationToken).ConfigureAwait(false);
                var authentication = configuredCredential?.SelectTls13Authentication(
                    clientCertificateRequest!.SignatureSchemes,
                    clientCertificateRequest.DelegatedCredentialSignatureSchemes);
                var selectedCredential = authentication.HasValue
                    ? configuredCredential
                    : null;
                var clientCertificate = ClientAuthenticationMessages.CreateTls13Certificate(
                    clientCertificateRequest!.Context,
                    selectedCredential,
                    _configuration.Limits,
                    authentication?.DelegatedCredential);
                await WriteProtectedHandshakeAsync(
                    clientHandshakeCipher,
                    clientCertificate,
                    cancellationToken).ConfigureAwait(false);
                transcript.Append(clientCertificate);
                _tls13State.ClientCertificateSent(selectedCredential is not null);

                if (selectedCredential is not null)
                {
                    var certificateVerifyHash = transcript.CurrentHash();
                    try
                    {
                        var certificateVerify = await ClientAuthenticationMessages
                            .CreateTls13CertificateVerifyAsync(
                                selectedCredential,
                                authentication!.Value.SignatureScheme,
                                certificateVerifyHash,
                                cancellationToken,
                                authentication.Value.DelegatedCredential).ConfigureAwait(false);
                        await WriteProtectedHandshakeAsync(
                            clientHandshakeCipher,
                            certificateVerify,
                            cancellationToken).ConfigureAwait(false);
                        transcript.Append(certificateVerify);
                        _tls13State.ClientCertificateVerifySent();
                    }
                    finally
                    {
                        CryptographicOperations.ZeroMemory(certificateVerifyHash);
                    }
                }
            }

            var clientFinished = FinishedProcessor.CreateClientFinished(
                keySchedule,
                transcript.CurrentHash());
            await WriteProtectedHandshakeAsync(
                clientHandshakeCipher,
                clientFinished,
                cancellationToken).ConfigureAwait(false);
            transcript.Append(clientFinished);
            if (_configuration.SessionCache is { } sessionCache)
            {
                if (resumed)
                {
                    _tls13AuthenticationExpiresAt = offeredTicket!.AuthenticationExpiresAt;
                }
                else if (certificateNotAfter.HasValue)
                {
                    _tls13AuthenticationExpiresAt = sessionCache.GetAuthenticationExpiry(
                        certificateNotAfter.Value);
                }
                else
                {
                    throw TlsProtocolException.Unexpected(
                        "A certificate-authenticated handshake completed without a certificate lifetime.");
                }

                keySchedule.DeriveResumptionMasterSecret(transcript.CurrentHash());
            }
            if (!echRejected &&
                EarlyDataStatus == Tls13EarlyDataStatus.Rejected &&
                _configuration.EarlyData?.RejectionPolicy ==
                    Tls13EarlyDataRejectionPolicy.RetransmitAfterHandshake)
            {
                await WriteTls13ApplicationFragmentsAsync(
                    clientApplicationCipher!,
                    _configuration.EarlyData.Data,
                    cancellationToken).ConfigureAwait(false);
                EarlyDataStatus = Tls13EarlyDataStatus.RejectedAndRetransmitted;
            }
            _tls13State.ClientFinishedSent();
            NotifyHandshakeEvent(
                TlsHandshakeEventKind.Finished,
                TlsHandshakeEventDirection.ClientToServer,
                clientFinished.Length);

            if (echRejected)
            {
                NegotiatedApplicationProtocol = null;
                NegotiatedApplicationSettingsCodePoint = null;
                _negotiatedPeerApplicationSettings = null;
                _negotiatedReceiveRecordSizeLimit = null;
                _negotiatedSendRecordSizeLimit = null;
                ServerUsedDelegatedCredential = false;
                ServerDelegatedCredentialExpiresAt = null;
                await WriteProtectedRecordAsync(
                    clientApplicationCipher!,
                    TlsContentType.Alert,
                    new byte[] { 2, (byte)TlsAlertDescription.EchRequired },
                    paddingLength: 0,
                    cancellationToken).ConfigureAwait(false);
                throw new TlsEchRejectedException(
                    _configuration.Ech!.Selection.Configuration.PublicName,
                    echRetryConfigurations);
            }

            _serverApplicationCipher = serverApplicationCipher;
            serverApplicationCipher = null;
            _clientApplicationCipher = clientApplicationCipher;
            clientApplicationCipher = null;
            _postHandshakeDeframer = deframer;
            if (offer.Configuration.SupportsPostHandshakeAuthentication)
            {
                _postHandshakeAuthenticationBaseTranscript = transcript;
                transcript = null;
            }
            _applicationKeySchedule = keySchedule;
            keySchedule = null;
            NegotiatedCipherSuite = suite.Suite;
            NegotiatedGroup = serverHello.SelectedGroup;
            NegotiatedProtocolVersion = TlsProtocolVersion.Tls13;
            SessionWasResumed = resumed;
            ExternalPskWasSelected = pskAuthenticated && _configuration.ExternalPsk is not null;
            EncryptedClientHelloAccepted = echAccepted;
            _authenticatedReferenceIdentity = referenceIdentity;
            Volatile.Write(ref _handshakeCompleted, true);
            NotifyHandshakeEvent(
                TlsHandshakeEventKind.HandshakeCompleted,
                TlsHandshakeEventDirection.Local,
                encodedLength: 0);
        }
        catch (TlsProtocolException exception) when (!exception.IsPeerAlert && !delegatedToTls12)
        {
            await TrySendHandshakeFatalAlertAsync(
                exception.Alert,
                clientHandshakeCipher).ConfigureAwait(false);
            throw;
        }
        finally
        {
            certificates?.Dispose();
            offer?.Dispose();
            retryEchOffer?.Dispose();
            firstEchOffer?.Dispose();
            transcript?.Dispose();
            keySchedule?.Dispose();
            clientHandshakeCipher?.Dispose();
            serverHandshakeCipher?.Dispose();
            clientApplicationCipher?.Dispose();
            serverApplicationCipher?.Dispose();
            offeredPskSchedule?.Dispose();
            earlyDataCipher?.Dispose();
            foreach (var ticket in offeredTickets)
            {
                ticket.Dispose();
            }
        }
    }

    private void ProcessTls13NewSessionTicket(ReadOnlySpan<byte> body)
    {
        var message = Tls13NewSessionTicketParser.Parse(body);
        if (++_receivedSessionTicketCount >
            _configuration.Limits.MaxSessionTicketsPerConnection)
        {
            throw TlsProtocolException.Unexpected(
                "The peer exceeded the configured NewSessionTicket limit.");
        }

        var nonceKey = Convert.ToHexString(message.Nonce);
        if (!_receivedTicketNonces.Add(nonceKey))
        {
            throw TlsProtocolException.Illegal(
                "The peer reused a NewSessionTicket nonce on one connection.");
        }

        if (_configuration.SessionCache is not { } cache ||
            message.LifetimeSeconds is 0 or > Tls13NewSessionTicketParser.MaximumLifetimeSeconds)
        {
            return;
        }

        var schedule = _applicationKeySchedule ??
            throw TlsProtocolException.Unexpected(
                "NewSessionTicket arrived before the resumption key schedule was available.");
        var origin = _sessionOrigin ??
            throw new InvalidOperationException("TLS session origin is unavailable.");
        var authenticationExpiresAt = _tls13AuthenticationExpiresAt ??
            throw new InvalidOperationException("TLS authentication lifetime is unavailable.");
        var suite = NegotiatedCipherSuite ??
            throw new InvalidOperationException("TLS cipher suite is unavailable.");
        var issuedAt = cache.UtcNow;
        var expiresAt = issuedAt.AddSeconds(message.LifetimeSeconds);
        if (expiresAt > authenticationExpiresAt)
        {
            expiresAt = authenticationExpiresAt;
        }
        if (expiresAt <= issuedAt)
        {
            return;
        }

        var psk = schedule.DeriveResumptionPsk(message.Nonce);
        byte[]? clientApplicationSettings = null;
        try
        {
            if (NegotiatedApplicationSettingsCodePoint.HasValue)
            {
                var negotiatedAlpn = NegotiatedApplicationProtocol ??
                    throw new InvalidOperationException(
                        "Negotiated application settings require an ALPN protocol.");
                clientApplicationSettings =
                    _configuration.GetClientApplicationSettings(negotiatedAlpn);
            }
            cache.Add(new Tls13SessionTicket(
                origin,
                suite,
                NegotiatedApplicationProtocol,
                message.AgeAdd,
                message.Identity,
                psk,
                issuedAt,
                expiresAt,
                authenticationExpiresAt,
                message.MaximumEarlyDataSize,
                _negotiatedSendRecordSizeLimit,
                EncryptedClientHelloAccepted
                    ? _configuration.Ech?.ConfigListHash
                    : null,
                NegotiatedApplicationSettingsCodePoint,
                _negotiatedPeerApplicationSettings,
                clientApplicationSettings));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(psk);
            if (clientApplicationSettings is not null)
            {
                CryptographicOperations.ZeroMemory(clientApplicationSettings);
            }
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

    private async ValueTask PerformTls12HandshakeAsync(
        string referenceIdentity,
        CancellationToken cancellationToken,
        ClientHelloBuildResult? initialOffer = null,
        HandshakeDeframer? initialDeframer = null,
        HandshakeMessage? initialServerHello = null)
    {
        ClientHelloBuildResult? offer = initialOffer;
        Tls12TranscriptHash? transcript = null;
        Tls12KeySchedule? keySchedule = null;
        Tls12AeadRecordCipher? clientCipher = null;
        Tls12AeadRecordCipher? serverCipher = null;
        ServerCertificateMessage? certificates = null;
        IKeyShare? clientShare = null;
        Tls12Session? offeredSession = null;
        var deframer = initialDeframer ??
            new HandshakeDeframer(_configuration.Limits.MaxHandshakeMessageSize);
        var clientCipherActive = false;
        var certificateRequested = false;
        Tls12CertificateRequest? clientCertificateRequest = null;

        try
        {
            if (offer is null)
            {
                if (_configuration.Tls12SessionCache is { } cache)
                {
                    var origin = _sessionOrigin ??
                        throw new InvalidOperationException("TLS session origin is unavailable.");
                    offeredSession = cache.TryGet(
                        origin,
                        _configuration.ClientHello.Spec.CipherSuites);
                    if (offeredSession?.Ticket is not null &&
                        !_configuration.ClientHello.Spec.Extensions.Any(extension =>
                            extension.RawExtensionType == (ushort)TlsExtensionType.SessionTicket))
                    {
                        offeredSession.Dispose();
                        offeredSession = null;
                    }
                }
                if (offeredSession is null)
                {
                    offer = _configuration.ClientHello.BuildSecure(referenceIdentity);
                }
                else
                {
                    byte[]? generatedTicketSessionId = null;
                    try
                    {
                        var sessionId = offeredSession.Ticket is null
                            ? offeredSession.SessionId
                            : generatedTicketSessionId = RandomNumberGenerator.GetBytes(
                                TlsConstants.MaxSessionIdLength);
                        var rawOverrides = offeredSession.Ticket is null
                            ? null
                            : new Dictionary<ushort, byte[]>
                            {
                                [(ushort)TlsExtensionType.SessionTicket] = offeredSession.Ticket,
                            };
                        offer = ClientHelloEncoder.Build(
                        referenceIdentity,
                        _configuration.ClientHello.Spec.SnapshotConfiguration(),
                        SecureRandomSource.Instance,
                        new KeyShareSet(),
                        retry: null,
                        fixedFields: new ClientHelloFixedFields(
                            SessionId: sessionId,
                            RawExtensionOverrides: rawOverrides));
                    }
                    finally
                    {
                        if (generatedTicketSessionId is not null)
                        {
                            CryptographicOperations.ZeroMemory(generatedTicketSessionId);
                        }
                    }
                }
                InspectClientHello(
                    TlsClientHelloFlight.Initial,
                    TlsClientHelloWireForm.Direct,
                    offer.EncodedHandshake,
                    _configuration.UseInitialCompatibilityRecordVersion
                        ? (ushort)0x0301
                        : (ushort)0x0303);
                await _recordWriter!.WriteFragmentedAsync(
                    TlsContentType.Handshake,
                    offer.EncodedHandshake,
                    _configuration.HandshakeFragmentation,
                    cancellationToken,
                    _configuration.UseInitialCompatibilityRecordVersion
                        ? (ushort)0x0301
                        : (ushort)0x0303)
                    .ConfigureAwait(false);
                _tls12State.ClientHelloSent();
            }

            var serverHelloMessage = initialServerHello ??
                await ReadTls12PlainHandshakeMessageAsync(
                    deframer,
                    cancellationToken).ConfigureAwait(false);
            if (serverHelloMessage.Type != HandshakeType.ServerHello)
            {
                throw TlsProtocolException.Unexpected("Expected TLS 1.2 ServerHello.");
            }

            var serverHello = Tls12ServerHelloParser.Parse(serverHelloMessage.Body, offer);
            NotifyHandshakeEvent(
                TlsHandshakeEventKind.ServerHello,
                TlsHandshakeEventDirection.ServerToClient,
                serverHelloMessage.Encoded.Length);
            if (serverHello.PeerRecordSizeLimit.HasValue)
            {
                _negotiatedReceiveRecordSizeLimit = Math.Min(
                    offer.Configuration.RecordSizeLimit!.Value,
                    TlsConstants.MaxPlaintextLength);
                _negotiatedSendRecordSizeLimit = serverHello.PeerRecordSizeLimit.Value;
            }
            transcript = new Tls12TranscriptHash(serverHello.SuiteInfo);
            transcript.Append(offer.EncodedHandshake);
            transcript.Append(serverHelloMessage.Encoded);
            var resumed = offeredSession is not null &&
                serverHello.SessionId.Length != 0 &&
                CryptographicOperations.FixedTimeEquals(
                    serverHello.SessionId,
                    offer.SessionId);
            if (resumed)
            {
                if (serverHello.CipherSuite != offeredSession!.CipherSuite)
                {
                    throw TlsProtocolException.Illegal(
                        "TLS 1.2 resumed a session with a different cipher suite.");
                }
            }
            _tls12State.ServerHelloReceived(resumed);

            if (resumed)
            {
                if (deframer.BufferedBytes != 0)
                {
                    throw TlsProtocolException.Unexpected(
                        "TLS 1.2 abbreviated ServerHello was not aligned to ChangeCipherSpec.");
                }

                var masterSecret = offeredSession!.CopyMasterSecret();
                try
                {
                    keySchedule = new Tls12KeySchedule(serverHello.SuiteInfo);
                    keySchedule.ImportMasterSecret(masterSecret);
                    await WriteNssKeyLogSecretAsync(
                        "CLIENT_RANDOM",
                        offer.Random,
                        keySchedule.CopyMasterSecret(),
                        cancellationToken).ConfigureAwait(false);
                    keySchedule.DeriveTrafficKeys(offer.Random, serverHello.Random);
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(masterSecret);
                }

                clientCipher = CreateTls12Cipher(
                    serverHello.SuiteInfo,
                    keySchedule.GetClientWriteKeys());
                serverCipher = CreateTls12Cipher(
                    serverHello.SuiteInfo,
                    keySchedule.GetServerWriteKeys());
                using var renewedTicket = await ReadTls12AbbreviatedServerFlightAsync(
                    deframer,
                    serverCipher,
                    keySchedule,
                    transcript,
                    serverHello.SessionTicketAcknowledged,
                    cancellationToken).ConfigureAwait(false);

                await _recordWriter!.WriteRecordAsync(
                    TlsContentType.ChangeCipherSpec,
                    new byte[] { 1 },
                    cancellationToken,
                    TlsConstants.Tls12Version).ConfigureAwait(false);
                _tls12State.AbbreviatedClientChangeCipherSpecSent();
                clientCipherActive = true;

                var resumedClientFinished = Tls12FinishedProcessor.CreateClientFinished(
                    keySchedule,
                    transcript.CurrentHash());
                await WriteTls12ProtectedHandshakeAsync(
                    clientCipher,
                    resumedClientFinished,
                    cancellationToken).ConfigureAwait(false);
                transcript.Append(resumedClientFinished);
                _tls12State.AbbreviatedClientFinishedSent();
                NotifyHandshakeEvent(
                    TlsHandshakeEventKind.Finished,
                    TlsHandshakeEventDirection.ClientToServer,
                    resumedClientFinished.Length);

                if (renewedTicket is { Ticket.Length: > 0 } &&
                    _configuration.Tls12SessionCache is { } resumedCache)
                {
                    var now = resumedCache.UtcNow;
                    var expiresAt = renewedTicket.LifetimeHintSeconds == 0
                        ? offeredSession.ExpiresAt
                        : now.AddSeconds(renewedTicket.LifetimeHintSeconds);
                    if (expiresAt > offeredSession.ExpiresAt)
                    {
                        expiresAt = offeredSession.ExpiresAt;
                    }
                    if (expiresAt > now)
                    {
                        var resumedMasterSecret = offeredSession.CopyMasterSecret();
                        try
                        {
                            resumedCache.Add(new Tls12Session(
                                offeredSession.Origin,
                                sessionId: [],
                                serverHello.CipherSuite,
                                serverHello.AlpnProtocol,
                                offeredSession.NegotiatedGroup,
                                resumedMasterSecret,
                                expiresAt,
                                _negotiatedSendRecordSizeLimit,
                                _negotiatedReceiveRecordSizeLimit,
                                offeredSession.PeerCertificateChain,
                                offeredSession.StapledOcspResponse,
                                offeredSession.SignedCertificateTimestamps,
                                renewedTicket.Ticket));
                        }
                        finally
                        {
                            CryptographicOperations.ZeroMemory(resumedMasterSecret);
                        }
                    }
                }

                _tls12ClientApplicationCipher = clientCipher;
                clientCipher = null;
                _tls12ServerApplicationCipher = serverCipher;
                serverCipher = null;
                _tls12ApplicationKeySchedule = keySchedule;
                keySchedule = null;
                _tls12ClientRandom = (byte[])offer.Random.Clone();
                _tls12ServerRandom = (byte[])serverHello.Random.Clone();
                NegotiatedCipherSuite = serverHello.CipherSuite;
                NegotiatedApplicationProtocol = serverHello.AlpnProtocol;
                NegotiatedGroup = offeredSession.NegotiatedGroup;
                NegotiatedProtocolVersion = TlsProtocolVersion.Tls12;
                SessionWasResumed = true;
                _peerCertificateChain = offeredSession.PeerCertificateChain
                    .Select(value => (byte[])value.Clone())
                    .ToArray();
                _stapledOcspResponse = offeredSession.StapledOcspResponse is null
                    ? null
                    : (byte[])offeredSession.StapledOcspResponse.Clone();
                _signedCertificateTimestamps = offeredSession.SignedCertificateTimestamps
                    .Select(value => (byte[])value.Clone())
                    .ToArray();
                _authenticatedReferenceIdentity = referenceIdentity;
                Volatile.Write(ref _handshakeCompleted, true);
                NotifyHandshakeEvent(
                    TlsHandshakeEventKind.HandshakeCompleted,
                    TlsHandshakeEventDirection.Local,
                    encodedLength: 0);
                return;
            }

            var certificateMessage = await ReadTls12PlainHandshakeMessageAsync(
                deframer,
                cancellationToken).ConfigureAwait(false);
            if (certificateMessage.Type != HandshakeType.Certificate)
            {
                throw TlsProtocolException.Unexpected("Expected TLS 1.2 Certificate.");
            }
            certificates = Tls12CertificateMessageParser.Parse(
                certificateMessage.Body,
                _configuration.Limits);
            cancellationToken.ThrowIfCancellationRequested();
            ServerCertificateValidator.ValidateChainAndHostname(
                certificates,
                referenceIdentity,
                _configuration.CertificateValidation);
            CapturePeerCertificateState(certificates);
            _signedCertificateTimestamps = serverHello.SignedCertificateTimestamps
                .Select(value => (byte[])value.Clone())
                .ToArray();
            cancellationToken.ThrowIfCancellationRequested();
            transcript.Append(certificateMessage.Encoded);
            _tls12State.CertificateReceived();
            NotifyHandshakeEvent(
                TlsHandshakeEventKind.Certificate,
                TlsHandshakeEventDirection.ServerToClient,
                certificateMessage.Encoded.Length);

            var serverFlightMessage = await ReadTls12PlainHandshakeMessageAsync(
                deframer,
                cancellationToken).ConfigureAwait(false);
            if (serverFlightMessage.Type == HandshakeType.CertificateStatus)
            {
                if (!serverHello.CertificateStatusExpected)
                {
                    throw TlsProtocolException.Unexpected(
                        "Server sent TLS 1.2 CertificateStatus without negotiating status_request.");
                }

                _stapledOcspResponse = Tls12CertificateStatusParser.ParseOcspResponse(
                    serverFlightMessage.Body,
                    _configuration.Limits);
                transcript.Append(serverFlightMessage.Encoded);
                _tls12State.CertificateStatusReceived();
                serverFlightMessage = await ReadTls12PlainHandshakeMessageAsync(
                    deframer,
                    cancellationToken).ConfigureAwait(false);
            }
            else if (serverHello.CertificateStatusExpected)
            {
                throw TlsProtocolException.Unexpected(
                    "Server negotiated status_request but omitted TLS 1.2 CertificateStatus.");
            }

            await ValidateCertificateEvidenceAsync(
                referenceIdentity,
                TlsProtocolVersion.Tls12,
                certificates,
                _stapledOcspResponse,
                _signedCertificateTimestamps,
                cancellationToken).ConfigureAwait(false);

            if (serverFlightMessage.Type != HandshakeType.ServerKeyExchange)
            {
                throw TlsProtocolException.Unexpected("Expected TLS 1.2 ServerKeyExchange.");
            }
            var serverKeyExchange = Tls12ServerKeyExchangeParser.Parse(
                serverFlightMessage.Body,
                offer.Configuration);
            Tls12ServerKeyExchangeParser.VerifySignature(
                serverKeyExchange,
                certificates.Leaf,
                serverHello.SuiteInfo,
                offer.Random,
                serverHello.Random);
            transcript.Append(serverFlightMessage.Encoded);
            _tls12State.ServerKeyExchangeReceived();
            NotifyHandshakeEvent(
                TlsHandshakeEventKind.ServerKeyExchange,
                TlsHandshakeEventDirection.ServerToClient,
                serverFlightMessage.Encoded.Length);

            var serverHelloDoneMessage = await ReadTls12PlainHandshakeMessageAsync(
                deframer,
                cancellationToken).ConfigureAwait(false);
            if (serverHelloDoneMessage.Type == HandshakeType.CertificateRequest)
            {
                clientCertificateRequest = Tls12CertificateRequestParser.Parse(
                    serverHelloDoneMessage.Body);
                certificateRequested = true;
                transcript.Append(serverHelloDoneMessage.Encoded);
                _tls12State.CertificateRequestReceived();
                NotifyHandshakeEvent(
                    TlsHandshakeEventKind.CertificateRequest,
                    TlsHandshakeEventDirection.ServerToClient,
                    serverHelloDoneMessage.Encoded.Length);
                serverHelloDoneMessage = await ReadTls12PlainHandshakeMessageAsync(
                    deframer,
                    cancellationToken).ConfigureAwait(false);
            }
            if (serverHelloDoneMessage.Type != HandshakeType.ServerHelloDone)
            {
                throw TlsProtocolException.Unexpected("Expected TLS 1.2 ServerHelloDone.");
            }
            Tls12ServerHelloDoneParser.Parse(serverHelloDoneMessage.Body);
            transcript.Append(serverHelloDoneMessage.Encoded);
            _tls12State.ServerHelloDoneReceived();
            NotifyHandshakeEvent(
                TlsHandshakeEventKind.ServerHelloDone,
                TlsHandshakeEventDirection.ServerToClient,
                serverHelloDoneMessage.Encoded.Length);
            if (deframer.BufferedBytes != 0)
            {
                throw TlsProtocolException.Unexpected(
                    "TLS 1.2 server flight contains data after ServerHelloDone.");
            }

            SignatureScheme? clientCertificateScheme = null;
            var clientCredential = certificateRequested
                ? await SelectClientCertificateAsync(
                    referenceIdentity,
                    TlsProtocolVersion.Tls12,
                    isPostHandshake: false,
                    clientCertificateRequest!.SignatureSchemes,
                    delegatedCredentialSchemes: null,
                    clientCertificateRequest.CertificateTypes,
                    cancellationToken).ConfigureAwait(false)
                : null;
            if (certificateRequested && clientCredential is not null)
            {
                clientCertificateScheme = clientCredential.SelectTls12SignatureScheme(
                    clientCertificateRequest!.SignatureSchemes,
                    clientCertificateRequest.CertificateTypes);
            }
            if (certificateRequested)
            {
                var clientCertificate = ClientAuthenticationMessages.CreateTls12Certificate(
                    clientCertificateScheme.HasValue ? clientCredential : null,
                    _configuration.Limits);
                await WriteTls12PlainHandshakeAsync(clientCertificate, cancellationToken)
                    .ConfigureAwait(false);
                transcript.Append(clientCertificate);
                _tls12State.ClientCertificateSent(clientCertificateScheme.HasValue);
                NotifyHandshakeEvent(
                    TlsHandshakeEventKind.Certificate,
                    TlsHandshakeEventDirection.ClientToServer,
                    clientCertificate.Length);
            }

            clientShare = KeyShareFactory.Create(serverKeyExchange.SelectedGroup);
            var clientKeyExchange = Tls12ClientKeyExchangeEncoder.Encode(clientShare.PublicKey.Span);
            await WriteTls12PlainHandshakeAsync(clientKeyExchange, cancellationToken).ConfigureAwait(false);
            transcript.Append(clientKeyExchange);
            _tls12State.ClientKeyExchangeSent();
            NotifyHandshakeEvent(
                TlsHandshakeEventKind.ClientKeyExchange,
                TlsHandshakeEventDirection.ClientToServer,
                clientKeyExchange.Length);

            var sharedSecret = clientShare.DeriveSharedSecret(serverKeyExchange.PeerPublicKey);
            try
            {
                keySchedule = new Tls12KeySchedule(serverHello.SuiteInfo);
                keySchedule.DeriveExtendedMasterSecret(sharedSecret, transcript.CurrentHash());
                await WriteNssKeyLogSecretAsync(
                    "CLIENT_RANDOM",
                    offer.Random,
                    keySchedule.CopyMasterSecret(),
                    cancellationToken).ConfigureAwait(false);
                keySchedule.DeriveTrafficKeys(offer.Random, serverHello.Random);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(sharedSecret);
            }

            if (clientCertificateScheme.HasValue)
            {
                var certificateVerifyHash = transcript.CurrentHash(
                    TlsClientCertificate.GetHashAlgorithm(clientCertificateScheme.Value));
                try
                {
                    var certificateVerify = await ClientAuthenticationMessages
                        .CreateTls12CertificateVerifyAsync(
                            clientCredential!,
                            clientCertificateScheme.Value,
                            certificateVerifyHash,
                            cancellationToken).ConfigureAwait(false);
                    await WriteTls12PlainHandshakeAsync(certificateVerify, cancellationToken)
                        .ConfigureAwait(false);
                    transcript.Append(certificateVerify);
                    _tls12State.ClientCertificateVerifySent();
                    NotifyHandshakeEvent(
                        TlsHandshakeEventKind.CertificateVerify,
                        TlsHandshakeEventDirection.ClientToServer,
                        certificateVerify.Length);
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(certificateVerifyHash);
                }
            }

            clientCipher = CreateTls12Cipher(
                serverHello.SuiteInfo,
                keySchedule.GetClientWriteKeys());
            serverCipher = CreateTls12Cipher(
                serverHello.SuiteInfo,
                keySchedule.GetServerWriteKeys());

            await _recordWriter!.WriteRecordAsync(
                TlsContentType.ChangeCipherSpec,
                new byte[] { 1 },
                cancellationToken,
                TlsConstants.Tls12Version).ConfigureAwait(false);
            _tls12State.ClientChangeCipherSpecSent();
            clientCipherActive = true;

            var clientFinished = Tls12FinishedProcessor.CreateClientFinished(
                keySchedule,
                transcript.CurrentHash());
            _tlsUnique = clientFinished[TlsConstants.HandshakeHeaderLength..].ToArray();
            await WriteTls12ProtectedHandshakeAsync(
                clientCipher,
                clientFinished,
                cancellationToken).ConfigureAwait(false);
            transcript.Append(clientFinished);
            _tls12State.ClientFinishedSent();
            NotifyHandshakeEvent(
                TlsHandshakeEventKind.Finished,
                TlsHandshakeEventDirection.ClientToServer,
                clientFinished.Length);

            using var newSessionTicket = await ReadTls12ServerFinalFlightAsync(
                deframer,
                serverCipher,
                keySchedule,
                transcript,
                serverHello.SessionTicketAcknowledged,
                cancellationToken).ConfigureAwait(false);

            if (_configuration.Tls12SessionCache is { } tls12Cache &&
                !certificateRequested)
            {
                var authenticationExpiry = tls12Cache.GetAuthenticationExpiry(
                    new DateTimeOffset(certificates.Leaf.NotAfter.ToUniversalTime()));
                var issuedAt = tls12Cache.UtcNow;
                var hasUsableTicket = newSessionTicket is { Ticket.Length: > 0 };
                var sessionExpiresAt = authenticationExpiry;
                if (hasUsableTicket && newSessionTicket!.LifetimeHintSeconds != 0)
                {
                    var hintedExpiry = issuedAt.AddSeconds(newSessionTicket.LifetimeHintSeconds);
                    if (hintedExpiry < sessionExpiresAt)
                    {
                        sessionExpiresAt = hintedExpiry;
                    }
                }
                if (sessionExpiresAt > issuedAt &&
                    (hasUsableTicket ||
                     (!serverHello.SessionTicketAcknowledged &&
                      serverHello.SessionId.Length != 0)))
                {
                    var masterSecret = keySchedule.CopyMasterSecret();
                    try
                    {
                        tls12Cache.Add(new Tls12Session(
                            _sessionOrigin ?? throw new InvalidOperationException(
                                "TLS session origin is unavailable."),
                            hasUsableTicket ? [] : serverHello.SessionId,
                            serverHello.CipherSuite,
                            serverHello.AlpnProtocol,
                            serverKeyExchange.SelectedGroup,
                            masterSecret,
                            sessionExpiresAt,
                            _negotiatedSendRecordSizeLimit,
                            _negotiatedReceiveRecordSizeLimit,
                            _peerCertificateChain,
                            _stapledOcspResponse,
                            _signedCertificateTimestamps,
                            hasUsableTicket ? newSessionTicket!.Ticket : null));
                    }
                    finally
                    {
                        CryptographicOperations.ZeroMemory(masterSecret);
                    }
                }
            }

            _tls12ClientApplicationCipher = clientCipher;
            clientCipher = null;
            _tls12ServerApplicationCipher = serverCipher;
            serverCipher = null;
            _tls12ApplicationKeySchedule = keySchedule;
            keySchedule = null;
            _tls12ClientRandom = (byte[])offer.Random.Clone();
            _tls12ServerRandom = (byte[])serverHello.Random.Clone();
            NegotiatedCipherSuite = serverHello.CipherSuite;
            NegotiatedApplicationProtocol = serverHello.AlpnProtocol;
            NegotiatedGroup = serverKeyExchange.SelectedGroup;
            NegotiatedProtocolVersion = TlsProtocolVersion.Tls12;
            _authenticatedReferenceIdentity = referenceIdentity;
            Volatile.Write(ref _handshakeCompleted, true);
            NotifyHandshakeEvent(
                TlsHandshakeEventKind.HandshakeCompleted,
                TlsHandshakeEventDirection.Local,
                encodedLength: 0);
        }
        catch (TlsProtocolException exception) when (!exception.IsPeerAlert)
        {
            await TrySendTls12HandshakeFatalAlertAsync(
                exception.Alert,
                clientCipherActive ? clientCipher : null).ConfigureAwait(false);
            throw;
        }
        finally
        {
            certificates?.Dispose();
            clientShare?.Dispose();
            offer?.Dispose();
            transcript?.Dispose();
            keySchedule?.Dispose();
            clientCipher?.Dispose();
            serverCipher?.Dispose();
            offeredSession?.Dispose();
        }
    }

    private async ValueTask<Tls12NewSessionTicket?> ReadTls12AbbreviatedServerFlightAsync(
        HandshakeDeframer deframer,
        Tls12AeadRecordCipher serverCipher,
        Tls12KeySchedule keySchedule,
        Tls12TranscriptHash transcript,
        bool sessionTicketAcknowledged,
        CancellationToken cancellationToken)
    {
        Tls12NewSessionTicket? renewedTicket = null;
        try
        {
        while (true)
        {
            var record = await _recordReader!.ReadAsync(cancellationToken).ConfigureAwait(false) ??
                throw TlsProtocolException.Decode(
                    "Unexpected EOF before abbreviated TLS 1.2 server ChangeCipherSpec.");
            ValidateTls12RecordVersion(record.LegacyRecordVersion);
            if (record.ContentType == TlsContentType.Alert)
            {
                if (ShouldIgnorePeerAlert(record.Fragment))
                {
                    continue;
                }
            }
            if (record.ContentType == TlsContentType.Handshake)
            {
                if (!sessionTicketAcknowledged || renewedTicket is not null ||
                    record.Fragment.Length == 0)
                {
                    throw TlsProtocolException.Unexpected(
                        "Unexpected message before abbreviated TLS 1.2 ChangeCipherSpec.");
                }
                deframer.Append(record.Fragment);
                while (deframer.TryRead(out var ticketMessage))
                {
                    if (ticketMessage!.Type != HandshakeType.NewSessionTicket ||
                        renewedTicket is not null)
                    {
                        throw TlsProtocolException.Unexpected(
                            "Expected one abbreviated TLS 1.2 NewSessionTicket.");
                    }
                    renewedTicket = Tls12NewSessionTicketParser.Parse(ticketMessage.Body);
                    transcript.Append(ticketMessage.Encoded);
                }
                continue;
            }
            if (record.ContentType != TlsContentType.ChangeCipherSpec)
            {
                throw TlsProtocolException.Unexpected(
                    "Expected abbreviated TLS 1.2 server ChangeCipherSpec.");
            }
            ValidateCompatibilityCcs(record.Fragment);
            if (deframer.BufferedBytes != 0 ||
                sessionTicketAcknowledged != (renewedTicket is not null))
            {
                throw TlsProtocolException.Unexpected(
                    "Abbreviated TLS 1.2 ticket flight was incomplete at ChangeCipherSpec.");
            }
            _tls12State.AbbreviatedServerChangeCipherSpecReceived();
            break;
        }

        while (true)
        {
            var record = await _recordReader!.ReadAsync(cancellationToken).ConfigureAwait(false) ??
                throw TlsProtocolException.Decode(
                    "Unexpected EOF before abbreviated TLS 1.2 server Finished.");
            ValidateTls12RecordVersion(record.LegacyRecordVersion);
            if (record.ContentType is not (TlsContentType.Handshake or TlsContentType.Alert))
            {
                throw TlsProtocolException.Unexpected(
                    "Expected abbreviated protected TLS 1.2 server Finished.");
            }
            var plaintext = serverCipher.Decrypt(
                record.ContentType,
                record.Fragment,
                record.LegacyRecordVersion);
            ValidateReceivedProtectedPlaintextLength(plaintext.Length);
            if (record.ContentType == TlsContentType.Alert)
            {
                if (ShouldIgnorePeerAlert(plaintext))
                {
                    continue;
                }
            }
            if (plaintext.Length == 0)
            {
                throw TlsProtocolException.Unexpected(
                    "Received an empty abbreviated TLS 1.2 Handshake fragment.");
            }
            deframer.Append(plaintext);
            if (!deframer.TryRead(out var message))
            {
                continue;
            }
            if (message!.Type != HandshakeType.Finished)
            {
                throw TlsProtocolException.Unexpected(
                    "Expected abbreviated TLS 1.2 server Finished.");
            }
            Tls12FinishedProcessor.VerifyServerFinished(
                message.Body,
                keySchedule,
                transcript.CurrentHash());
            _tlsUnique = message.Body.ToArray();
            transcript.Append(message.Encoded);
            if (deframer.BufferedBytes != 0)
            {
                throw TlsProtocolException.Unexpected(
                    "Abbreviated TLS 1.2 server Finished was not record-aligned.");
            }
            _tls12State.AbbreviatedServerFinishedReceived();
            NotifyHandshakeEvent(
                TlsHandshakeEventKind.Finished,
                TlsHandshakeEventDirection.ServerToClient,
                message.Encoded.Length);
            return renewedTicket;
        }
        }
        catch
        {
            renewedTicket?.Dispose();
            throw;
        }
    }

    private async ValueTask<Tls12NewSessionTicket?> ReadTls12ServerFinalFlightAsync(
        HandshakeDeframer deframer,
        Tls12AeadRecordCipher serverCipher,
        Tls12KeySchedule keySchedule,
        Tls12TranscriptHash transcript,
        bool sessionTicketAcknowledged,
        CancellationToken cancellationToken)
    {
        Tls12NewSessionTicket? receivedTicket = null;
        try
        {
        while (true)
        {
            var record = await _recordReader!.ReadAsync(cancellationToken).ConfigureAwait(false) ??
                throw TlsProtocolException.Decode(
                    "Unexpected EOF before TLS 1.2 server ChangeCipherSpec.");
            ValidateTls12RecordVersion(record.LegacyRecordVersion);
            if (record.ContentType == TlsContentType.Alert)
            {
                if (ShouldIgnorePeerAlert(record.Fragment))
                {
                    continue;
                }
            }
            if (record.ContentType == TlsContentType.ChangeCipherSpec)
            {
                ValidateCompatibilityCcs(record.Fragment);
                if (deframer.BufferedBytes != 0)
                {
                    throw TlsProtocolException.Unexpected(
                        "TLS 1.2 ChangeCipherSpec interleaved a fragmented NewSessionTicket.");
                }
                if (sessionTicketAcknowledged != (receivedTicket is not null))
                {
                    throw TlsProtocolException.Unexpected(
                        "TLS 1.2 ServerHello ticket acknowledgement did not match NewSessionTicket.");
                }
                _tls12State.ServerChangeCipherSpecReceived();
                break;
            }
            if (record.ContentType != TlsContentType.Handshake)
            {
                throw TlsProtocolException.Unexpected(
                    "Expected TLS 1.2 NewSessionTicket or ChangeCipherSpec.");
            }
            if (!sessionTicketAcknowledged || receivedTicket is not null || record.Fragment.Length == 0)
            {
                throw TlsProtocolException.Unexpected(
                    "Unexpected TLS 1.2 plaintext handshake message after client Finished.");
            }

            deframer.Append(record.Fragment);
            while (deframer.TryRead(out var message))
            {
                if (message!.Type != HandshakeType.NewSessionTicket || receivedTicket is not null)
                {
                    throw TlsProtocolException.Unexpected(
                        "Expected at most one TLS 1.2 NewSessionTicket.");
                }
                receivedTicket = Tls12NewSessionTicketParser.Parse(message.Body);
                transcript.Append(message.Encoded);
                _tls12State.NewSessionTicketReceived();
            }
        }

        while (true)
        {
            var record = await _recordReader!.ReadAsync(cancellationToken).ConfigureAwait(false) ??
                throw TlsProtocolException.Decode("Unexpected EOF before TLS 1.2 server Finished.");
            if (record.ContentType is not (TlsContentType.Handshake or TlsContentType.Alert))
            {
                throw TlsProtocolException.Unexpected(
                    "Expected a protected TLS 1.2 Finished record.");
            }

            var plaintext = serverCipher.Decrypt(
                record.ContentType,
                record.Fragment,
                record.LegacyRecordVersion);
            ValidateReceivedProtectedPlaintextLength(plaintext.Length);
            if (record.ContentType == TlsContentType.Alert)
            {
                if (ShouldIgnorePeerAlert(plaintext))
                {
                    continue;
                }
            }
            if (plaintext.Length == 0)
            {
                throw TlsProtocolException.Unexpected(
                    "Received an empty protected TLS 1.2 Handshake fragment.");
            }

            deframer.Append(plaintext);
            if (!deframer.TryRead(out var message))
            {
                continue;
            }
            if (message!.Type != HandshakeType.Finished)
            {
                throw TlsProtocolException.Unexpected("Expected TLS 1.2 server Finished.");
            }
            Tls12FinishedProcessor.VerifyServerFinished(
                message.Body,
                keySchedule,
                transcript.CurrentHash());
            transcript.Append(message.Encoded);
            if (deframer.BufferedBytes != 0)
            {
                throw TlsProtocolException.Unexpected(
                    "TLS 1.2 server Finished was not aligned to the application-data state.");
            }
            _tls12State.ServerFinishedReceived();
            NotifyHandshakeEvent(
                TlsHandshakeEventKind.Finished,
                TlsHandshakeEventDirection.ServerToClient,
                message.Encoded.Length);
            return receivedTicket;
        }
        }
        catch
        {
            receivedTicket?.Dispose();
            throw;
        }
    }

    private async ValueTask<HandshakeMessage> ReadTls12PlainHandshakeMessageAsync(
        HandshakeDeframer deframer,
        CancellationToken cancellationToken)
    {
        if (deframer.TryRead(out var buffered))
        {
            return buffered!;
        }

        while (true)
        {
            var record = await _recordReader!.ReadAsync(cancellationToken).ConfigureAwait(false) ??
                throw TlsProtocolException.Decode("Unexpected EOF during the TLS 1.2 server flight.");
            ValidateTls12RecordVersion(record.LegacyRecordVersion);
            if (record.ContentType == TlsContentType.Alert)
            {
                if (ShouldIgnorePeerAlert(record.Fragment))
                {
                    continue;
                }
            }
            if (record.ContentType != TlsContentType.Handshake)
            {
                throw TlsProtocolException.Unexpected(
                    "Expected a plaintext TLS 1.2 Handshake record.");
            }
            if (record.Fragment.Length == 0)
            {
                throw TlsProtocolException.Unexpected(
                    "Received an empty plaintext TLS 1.2 Handshake fragment.");
            }

            deframer.Append(record.Fragment);
            if (deframer.TryRead(out var message))
            {
                return message!;
            }
        }
    }

    private async ValueTask WriteTls12PlainHandshakeAsync(
        ReadOnlyMemory<byte> encodedHandshake,
        CancellationToken cancellationToken) =>
        await _recordWriter!.WriteFragmentedAsync(
            TlsContentType.Handshake,
            encodedHandshake,
            _configuration.HandshakeFragmentation,
            cancellationToken,
            TlsConstants.Tls12Version).ConfigureAwait(false);

    private async ValueTask WriteTls12ProtectedHandshakeAsync(
        Tls12AeadRecordCipher cipher,
        ReadOnlyMemory<byte> encodedHandshake,
        CancellationToken cancellationToken)
    {
        var offset = 0;
        var recordIndex = 0;
        while (offset < encodedHandshake.Length)
        {
            var length = _configuration.HandshakeFragmentation.GetNextSize(
                recordIndex++,
                encodedHandshake.Length - offset);
            length = Math.Min(length, GetTls12MaximumContentLength());
            await WriteTls12ProtectedRecordAsync(
                cipher,
                TlsContentType.Handshake,
                encodedHandshake.Slice(offset, length),
                cancellationToken).ConfigureAwait(false);
            offset += length;
        }
    }

    private async ValueTask<HandshakeMessage> ReadPlainHandshakeMessageAsync(
        HandshakeDeframer deframer,
        CancellationToken cancellationToken)
    {
        while (true)
        {
            var record = await _recordReader!.ReadAsync(cancellationToken).ConfigureAwait(false) ??
                throw TlsProtocolException.Decode("Unexpected EOF while waiting for ServerHello.");
            switch (record.ContentType)
            {
                case TlsContentType.ChangeCipherSpec:
                    ValidateCompatibilityCcs(record.Fragment);
                    continue;
                case TlsContentType.Alert:
                    if (ShouldIgnorePeerAlert(record.Fragment))
                    {
                        continue;
                    }
                    continue;
                case TlsContentType.Handshake:
                    if (record.Fragment.Length == 0)
                    {
                        throw TlsProtocolException.Unexpected(
                            "Received a zero-length plaintext Handshake fragment.");
                    }
                    deframer.Append(record.Fragment);
                    if (deframer.TryRead(out var message))
                    {
                        return message!;
                    }
                    break;
                default:
                    throw TlsProtocolException.Unexpected(
                        "Unexpected record while waiting for ServerHello.");
            }
        }
    }

    private async ValueTask WriteProtectedHandshakeAsync(
        Tls13RecordCipher cipher,
        ReadOnlyMemory<byte> encodedHandshake,
        CancellationToken cancellationToken)
    {
        if (encodedHandshake.IsEmpty)
        {
            throw new ArgumentException("Handshake content cannot be empty.", nameof(encodedHandshake));
        }

        var offset = 0;
        var index = 0;
        while (offset < encodedHandshake.Length)
        {
            var length = _configuration.HandshakeFragmentation.GetNextSize(
                index++,
                encodedHandshake.Length - offset);
            length = Math.Min(length, GetTls13MaximumContentLength(paddingLength: 0));
            await WriteProtectedRecordAsync(
                cipher,
                TlsContentType.Handshake,
                encodedHandshake.Slice(offset, length),
                paddingLength: 0,
                cancellationToken).ConfigureAwait(false);
            offset += length;
        }
    }

    private TranscriptHash CreateTls13Transcript(CipherSuiteInfo suite) => new(
        suite,
        _configuration.ClientHello.Spec.SupportsPostHandshakeAuthentication
            ? _configuration.Limits.MaxHandshakeTranscriptSize
            : 0);

    private async ValueTask<TlsClientCertificate?> SelectClientCertificateAsync(
        string serverName,
        TlsProtocolVersion protocolVersion,
        bool isPostHandshake,
        IReadOnlyList<SignatureScheme> signatureSchemes,
        IReadOnlyList<SignatureScheme>? delegatedCredentialSchemes,
        byte[] certificateTypes,
        CancellationToken cancellationToken)
    {
        var selector = _configuration.ClientCertificateSelector;
        if (selector is null)
        {
            return _configuration.ClientCertificate;
        }

        var context = new TlsClientCertificateSelectionContext(
            serverName,
            protocolVersion,
            isPostHandshake,
            signatureSchemes,
            delegatedCredentialSchemes,
            certificateTypes);
        var selected = await selector(context, cancellationToken).ConfigureAwait(false);
        cancellationToken.ThrowIfCancellationRequested();
        return selected;
    }

    private async ValueTask ProcessPostHandshakeCertificateRequestAsync(
        HandshakeMessage message,
        CancellationToken cancellationToken)
    {
        if (!_configuration.ClientHello.Spec.SupportsPostHandshakeAuthentication ||
            _postHandshakeAuthenticationBaseTranscript is null)
        {
            throw TlsProtocolException.Unexpected(
                "The server requested post-handshake authentication without client opt-in.");
        }
        if (_postHandshakeAuthenticationCount >=
            _configuration.Limits.MaxPostHandshakeAuthenticationRequests)
        {
            throw TlsProtocolException.Unexpected(
                "The peer exceeded the post-handshake authentication request limit.");
        }

        var request = CertificateRequestParser.ParsePostHandshake(message.Body);
        var contextKey = Convert.ToHexString(request.Context);
        if (!_receivedCertificateRequestContexts.Add(contextKey))
        {
            throw TlsProtocolException.Illegal(
                "CertificateRequest context was reused on this connection.");
        }

        await _writeLock.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            EnsureApplicationState();
            await FlushPendingPeerKeyUpdateResponseCoreAsync(cancellationToken)
                .ConfigureAwait(false);

            using var transcript = _postHandshakeAuthenticationBaseTranscript.Fork();
            transcript.Append(message.Encoded);
            var configuredCredential = await SelectClientCertificateAsync(
                _authenticatedReferenceIdentity!,
                TlsProtocolVersion.Tls13,
                isPostHandshake: true,
                request.SignatureSchemes,
                request.DelegatedCredentialSignatureSchemes,
                certificateTypes: [],
                cancellationToken).ConfigureAwait(false);
            var authentication = configuredCredential?.SelectTls13Authentication(
                request.SignatureSchemes,
                request.DelegatedCredentialSignatureSchemes);
            var selectedCredential = authentication.HasValue
                ? configuredCredential
                : null;
            var certificate = ClientAuthenticationMessages.CreateTls13Certificate(
                request.Context,
                selectedCredential,
                _configuration.Limits,
                authentication?.DelegatedCredential);
            transcript.Append(certificate);

            byte[]? certificateVerify = null;
            if (selectedCredential is not null)
            {
                var certificateVerifyHash = transcript.CurrentHash();
                try
                {
                    certificateVerify = await ClientAuthenticationMessages
                        .CreateTls13CertificateVerifyAsync(
                            selectedCredential,
                            authentication!.Value.SignatureScheme,
                            certificateVerifyHash,
                            cancellationToken,
                            authentication.Value.DelegatedCredential).ConfigureAwait(false);
                    transcript.Append(certificateVerify);
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(certificateVerifyHash);
                }
            }

            var estimatedFinishedLength = TlsConstants.HandshakeHeaderLength +
                GetNegotiatedSuite().HashLength;
            var requiredRecords = CountHandshakeRecords(certificate) +
                (certificateVerify is null ? 0 : CountHandshakeRecords(certificateVerify)) +
                CountHandshakeRecords(estimatedFinishedLength);
            if (_clientApplicationCipher!.RecordsRemaining <= (ulong)requiredRecords)
            {
                await SendKeyUpdateCoreAsync(
                    requestPeerUpdate: false,
                    cancellationToken).ConfigureAwait(false);
            }

            var finishedHash = transcript.CurrentHash();
            var verifyData = _applicationKeySchedule!.ComputeClientApplicationFinished(
                finishedHash);
            byte[] finished;
            try
            {
                finished = HandshakeMessage.Encode(HandshakeType.Finished, verifyData);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(finishedHash);
                CryptographicOperations.ZeroMemory(verifyData);
            }

            await WriteProtectedHandshakeAsync(
                _clientApplicationCipher,
                certificate,
                cancellationToken).ConfigureAwait(false);
            if (certificateVerify is not null)
            {
                await WriteProtectedHandshakeAsync(
                    _clientApplicationCipher,
                    certificateVerify,
                    cancellationToken).ConfigureAwait(false);
            }
            await WriteProtectedHandshakeAsync(
                _clientApplicationCipher,
                finished,
                cancellationToken).ConfigureAwait(false);
            _postHandshakeAuthenticationCount++;
        }
        finally
        {
            _writeLock.Release();
        }
    }

    private int CountHandshakeRecords(ReadOnlySpan<byte> encodedHandshake) =>
        CountHandshakeRecords(encodedHandshake.Length);

    private int CountHandshakeRecords(int encodedLength)
    {
        var count = 0;
        var remaining = encodedLength;
        while (remaining > 0)
        {
            remaining -= _configuration.HandshakeFragmentation.GetNextSize(count, remaining);
            count++;
        }
        return count;
    }

    private async ValueTask ProcessPeerKeyUpdateAsync(
        bool requestUpdate,
        CancellationToken cancellationToken)
    {
        RotateServerApplicationKeys();
        Interlocked.Exchange(ref _awaitingRequestedPeerKeyUpdate, 0);
        if (!requestUpdate)
        {
            return;
        }
        if (!KeyUpdateProcessor.CanAdvanceSendingEpoch(ClientKeyUpdateCount))
        {
            // RFC 9846 requires the receiver to ignore request_update when its
            // own sending epoch cannot advance without exceeding the limit.
            return;
        }

        await _writeLock.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            EnsureApplicationState();
            Interlocked.Exchange(ref _peerKeyUpdateResponsePending, 1);
        }
        finally
        {
            _writeLock.Release();
        }
    }

    private async ValueTask FlushPendingPeerKeyUpdateResponseAsync(
        CancellationToken cancellationToken)
    {
        if (Volatile.Read(ref _peerKeyUpdateResponsePending) == 0)
        {
            return;
        }

        await _writeLock.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            EnsureApplicationState();
            await FlushPendingPeerKeyUpdateResponseCoreAsync(cancellationToken)
                .ConfigureAwait(false);
        }
        finally
        {
            _writeLock.Release();
        }
    }

    private async ValueTask FlushPendingPeerKeyUpdateResponseCoreAsync(
        CancellationToken cancellationToken)
    {
        if (Interlocked.Exchange(ref _peerKeyUpdateResponsePending, 0) == 0)
        {
            return;
        }
        if (!KeyUpdateProcessor.CanAdvanceSendingEpoch(ClientKeyUpdateCount))
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
            Interlocked.Exchange(ref _peerKeyUpdateResponsePending, 1);
            throw;
        }
    }

    private async ValueTask SendKeyUpdateCoreAsync(
        bool requestPeerUpdate,
        CancellationToken cancellationToken)
    {
        var current = _clientApplicationCipher ??
            throw new InvalidOperationException("Client application traffic keys are unavailable.");
        if (!KeyUpdateProcessor.CanAdvanceSendingEpoch(ClientKeyUpdateCount))
        {
            throw new TlsProtocolException(
                TlsAlertDescription.GeneralError,
                "The TLS 1.3 sending-key epoch limit has been reached.");
        }
        if (current.RecordsRemaining == 0)
        {
            throw new TlsProtocolException(
                TlsAlertDescription.GeneralError,
                "No record-key capacity remains for KeyUpdate.");
        }

        var markedOutstandingRequest = false;
        if (requestPeerUpdate)
        {
            if (Interlocked.CompareExchange(
                ref _awaitingRequestedPeerKeyUpdate,
                1,
                0) != 0)
            {
                throw new InvalidOperationException(
                    "A request_update KeyUpdate is already awaiting a peer KeyUpdate response.");
            }
            markedOutstandingRequest = true;
        }

        var encoded = KeyUpdateProcessor.Encode(requestPeerUpdate);
        try
        {
            await WriteProtectedRecordAsync(
                current,
                TlsContentType.Handshake,
                encoded,
                paddingLength: 0,
                cancellationToken).ConfigureAwait(false);
        }
        catch
        {
            if (markedOutstandingRequest)
            {
                Interlocked.Exchange(ref _awaitingRequestedPeerKeyUpdate, 0);
            }
            throw;
        }

        try
        {
            var schedule = _applicationKeySchedule ??
                throw new InvalidOperationException("Application traffic secrets are unavailable.");
            schedule.UpdateClientApplicationTrafficSecret();
            var next = CreateCipher(
                GetNegotiatedSuite(),
                schedule.GetClientApplicationKeys());
            _clientApplicationCipher = next;
            current.Dispose();
            ClientKeyUpdateCount++;
            NotifyHandshakeEvent(
                TlsHandshakeEventKind.KeyUpdate,
                TlsHandshakeEventDirection.ClientToServer,
                encoded.Length);
        }
        catch (Exception exception) when (exception is not TlsProtocolException)
        {
            throw new TlsProtocolException(
                TlsAlertDescription.InternalError,
                "Failed to rotate client application traffic keys.",
                exception);
        }
    }

    private void RotateServerApplicationKeys()
    {
        var current = _serverApplicationCipher ??
            throw new InvalidOperationException("Server application traffic keys are unavailable.");
        try
        {
            var schedule = _applicationKeySchedule ??
                throw new InvalidOperationException("Application traffic secrets are unavailable.");
            schedule.UpdateServerApplicationTrafficSecret();
            var next = CreateCipher(
                GetNegotiatedSuite(),
                schedule.GetServerApplicationKeys());
            _serverApplicationCipher = next;
            current.Dispose();
            ServerKeyUpdateCount++;
        }
        catch (Exception exception) when (exception is not TlsProtocolException)
        {
            throw new TlsProtocolException(
                TlsAlertDescription.InternalError,
                "Failed to rotate server application traffic keys.",
                exception);
        }
    }

    private CipherSuiteInfo GetNegotiatedSuite() => CipherSuiteInfo.Get(
        NegotiatedCipherSuite ??
        throw new InvalidOperationException("The TLS cipher suite has not been negotiated."));

    private async ValueTask EnsureClientApplicationKeyCapacityAsync(
        CancellationToken cancellationToken)
    {
        await FlushPendingPeerKeyUpdateResponseCoreAsync(cancellationToken)
            .ConfigureAwait(false);
        var cipher = _clientApplicationCipher ??
            throw new InvalidOperationException("Client application traffic keys are unavailable.");
        if (cipher.RecordsRemaining <= 1)
        {
            await SendKeyUpdateCoreAsync(
                requestPeerUpdate: false,
                cancellationToken).ConfigureAwait(false);
        }
    }

    private async ValueTask WriteTls12ApplicationDataCoreAsync(
        ReadOnlyMemory<byte> data,
        CancellationToken cancellationToken)
    {
        var cipher = _tls12ClientApplicationCipher ??
            throw new InvalidOperationException("TLS 1.2 client write keys are unavailable.");
        if (data.IsEmpty)
        {
            await WriteTls12ProtectedRecordAsync(
                cipher,
                TlsContentType.ApplicationData,
                data,
                cancellationToken).ConfigureAwait(false);
            return;
        }

        var offset = 0;
        var recordIndex = 0;
        while (offset < data.Length)
        {
            var length = _configuration.ApplicationDataFragmentation.GetNextSize(
                recordIndex++,
                data.Length - offset);
            length = Math.Min(length, GetTls12MaximumContentLength());
            await WriteTls12ProtectedRecordAsync(
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
        var cipher = _tls12ServerApplicationCipher ??
            throw new InvalidOperationException("TLS 1.2 server write keys are unavailable.");
        while (true)
        {
            var record = await _recordReader!.ReadAsync(cancellationToken).ConfigureAwait(false);
            if (record is null)
            {
                throw TlsProtocolException.Decode(
                    "TLS transport ended without an authenticated close_notify alert.");
            }
            if (record.ContentType is not (TlsContentType.ApplicationData or
                TlsContentType.Alert or TlsContentType.Handshake))
            {
                throw TlsProtocolException.Unexpected(
                    "Received an unexpected TLS 1.2 record after the handshake.");
            }

            var plaintext = cipher.Decrypt(
                record.ContentType,
                record.Fragment,
                record.LegacyRecordVersion);
            ValidateReceivedProtectedPlaintextLength(plaintext.Length);
            switch (record.ContentType)
            {
                case TlsContentType.ApplicationData:
                    return plaintext;
                case TlsContentType.Alert:
                    if (ProcessApplicationAlert(plaintext))
                    {
                        return null;
                    }
                    break;
                case TlsContentType.Handshake:
                    throw TlsProtocolException.Unexpected(
                        "TLS 1.2 renegotiation and post-handshake messages are not supported.");
            }
        }
    }

    private async ValueTask WriteTls12ProtectedRecordAsync(
        Tls12AeadRecordCipher cipher,
        TlsContentType contentType,
        ReadOnlyMemory<byte> content,
        CancellationToken cancellationToken)
    {
        if (content.Length > GetTls12MaximumContentLength())
        {
            throw new InvalidOperationException(
                "Protected TLS 1.2 plaintext exceeds the peer record_size_limit.");
        }
        var encrypted = cipher.Encrypt(contentType, content.Span, TlsConstants.Tls12Version);
        await _recordWriter!.WriteRecordAsync(
            contentType,
            encrypted,
            cancellationToken,
            TlsConstants.Tls12Version).ConfigureAwait(false);
    }

    private async ValueTask WriteProtectedRecordAsync(
        Tls13RecordCipher cipher,
        TlsContentType contentType,
        ReadOnlyMemory<byte> content,
        int paddingLength,
        CancellationToken cancellationToken,
        int? maximumPlaintextLength = null)
    {
        var effectiveLimit = maximumPlaintextLength ??
            _negotiatedSendRecordSizeLimit ??
            TlsConstants.MaxPlaintextLength + 1;
        if (content.Length + 1 + paddingLength > effectiveLimit)
        {
            throw new InvalidOperationException(
                "TLSInnerPlaintext exceeds the peer record_size_limit.");
        }
        var encrypted = cipher.Encrypt(contentType, content.Span, paddingLength);
        await _recordWriter!.WriteRecordAsync(
            TlsContentType.ApplicationData,
            encrypted,
            cancellationToken).ConfigureAwait(false);
    }

    private async ValueTask WriteTls13ApplicationFragmentsAsync(
        Tls13RecordCipher cipher,
        ReadOnlyMemory<byte> data,
        CancellationToken cancellationToken,
        int? maximumPlaintextLength = null)
    {
        var padding = _configuration.ApplicationDataPaddingLength;
        var maximumContent = GetTls13MaximumContentLength(
            padding,
            maximumPlaintextLength);
        if (maximumContent < 1)
        {
            throw new InvalidOperationException(
                "Application padding leaves no room for non-empty content.");
        }

        var offset = 0;
        var recordIndex = 0;
        while (offset < data.Length)
        {
            var requested = _configuration.ApplicationDataFragmentation.GetNextSize(
                recordIndex++,
                data.Length - offset);
            var length = Math.Min(requested, maximumContent);
            await WriteProtectedRecordAsync(
                cipher,
                TlsContentType.ApplicationData,
                data.Slice(offset, length),
                padding,
                cancellationToken,
                maximumPlaintextLength).ConfigureAwait(false);
            offset += length;
        }
    }

    private int GetTls13MaximumContentLength(
        int paddingLength,
        int? maximumPlaintextLength = null)
    {
        var effectiveLimit = Math.Min(
            maximumPlaintextLength ??
                _negotiatedSendRecordSizeLimit ??
                TlsConstants.MaxPlaintextLength + 1,
            TlsConstants.MaxPlaintextLength + 1);
        return effectiveLimit - 1 - paddingLength;
    }

    private int GetTls12MaximumContentLength() => Math.Min(
        _negotiatedSendRecordSizeLimit ?? TlsConstants.MaxPlaintextLength,
        TlsConstants.MaxPlaintextLength);

    private void ValidateReceivedProtectedPlaintextLength(int plaintextLength)
    {
        if (_negotiatedReceiveRecordSizeLimit is { } limit && plaintextLength > limit)
        {
            throw new TlsProtocolException(
                TlsAlertDescription.RecordOverflow,
                $"Peer protected-record plaintext length {plaintextLength} exceeds the negotiated limit {limit}.");
        }
    }

    private async ValueTask WriteCompatibilityCcsAsync(CancellationToken cancellationToken) =>
        await _recordWriter!.WriteRecordAsync(
            TlsContentType.ChangeCipherSpec,
            new byte[] { 1 },
            cancellationToken).ConfigureAwait(false);

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

    private static byte[] HashHandshake(
        CipherSuiteInfo suite,
        ReadOnlySpan<byte> encodedHandshake) => suite.HashAlgorithm.Name switch
        {
            "SHA256" => SHA256.HashData(encodedHandshake),
            "SHA384" => SHA384.HashData(encodedHandshake),
            _ => throw new NotSupportedException(),
        };

    private static Tls12AeadRecordCipher CreateTls12Cipher(
        Tls12CipherSuiteInfo suite,
        Tls12TrafficKeys material)
    {
        try
        {
            return new Tls12AeadRecordCipher(suite, material.Key, material.FixedIv);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(material.Key);
            CryptographicOperations.ZeroMemory(material.FixedIv);
        }
    }

    private bool ProcessApplicationAlert(ReadOnlySpan<byte> alert)
    {
        var (level, description) = ParseAlert(alert);
        if (description == (byte)TlsAlertDescription.CloseNotify)
        {
            if (level != 1)
            {
                throw TlsProtocolException.Illegal("close_notify was not sent at warning level.");
            }
            _peerClosed = true;
            return true;
        }
        if (description == 90) // user_canceled; ignore while waiting for close_notify.
        {
            return false;
        }

        throw CreatePeerAlert(description);
    }

    private static bool ShouldIgnorePeerAlert(ReadOnlySpan<byte> alert)
    {
        var (_, description) = ParseAlert(alert);
        if (description == 90) // user_canceled is advisory and may be ignored.
        {
            return true;
        }

        throw CreatePeerAlert(description);
    }

    private static (byte Level, byte Description) ParseAlert(ReadOnlySpan<byte> alert)
    {
        if (alert.Length != 2 || alert[0] is not (1 or 2))
        {
            throw TlsProtocolException.Decode("TLS alert has invalid framing or level.");
        }
        return (alert[0], alert[1]);
    }

    private static TlsProtocolException CreatePeerAlert(byte description)
    {
        var alert = Enum.IsDefined(typeof(TlsAlertDescription), description)
            ? (TlsAlertDescription)description
            : TlsAlertDescription.GeneralError;
        return new TlsProtocolException(
            alert,
            $"Peer terminated TLS with alert {description}.",
            innerException: null,
            isPeerAlert: true);
    }

    private static void ValidateCompatibilityCcs(ReadOnlySpan<byte> fragment)
    {
        if (!fragment.SequenceEqual(new byte[] { 1 }))
        {
            throw TlsProtocolException.Unexpected("Invalid compatibility ChangeCipherSpec record.");
        }
    }

    private static void ValidateTls12RecordVersion(ushort version)
    {
        if (version != TlsConstants.Tls12Version)
        {
            throw new TlsProtocolException(
                TlsAlertDescription.ProtocolVersion,
                $"TLS 1.2 record version must be 0x0303, received 0x{version:X4}.");
        }
    }

    private void EnsureApplicationState(bool allowPeerClosed = false)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (!IsHandshakeConnected() || _localClosed || (!allowPeerClosed && _peerClosed))
        {
            throw new InvalidOperationException("The TLS connection is not open for application data.");
        }
    }

    private bool UsesTls12OnlyProfile()
    {
        var versions = _configuration.ClientHello.Spec.SupportedVersions;
        return versions.Contains(TlsProtocolVersion.Tls12) &&
               !versions.Contains(TlsProtocolVersion.Tls13);
    }

    private void CapturePeerCertificateState(ServerCertificateMessage certificates)
    {
        _peerCertificateChain = certificates.Certificates
            .Select(certificate => certificate.RawData)
            .ToArray();
        _stapledOcspResponse = certificates.LeafOcspResponse is null
            ? null
            : (byte[])certificates.LeafOcspResponse.Clone();
        _signedCertificateTimestamps = certificates.LeafSignedCertificateTimestamps
            .Select(value => (byte[])value.Clone())
            .ToArray();
    }

    private async ValueTask ValidateCertificateEvidenceAsync(
        string referenceIdentity,
        TlsProtocolVersion protocolVersion,
        ServerCertificateMessage certificates,
        byte[]? stapledOcspResponse,
        IReadOnlyList<byte[]> signedCertificateTimestamps,
        CancellationToken cancellationToken)
    {
        var policy = _configuration.CertificateValidation;
        if (policy.EvidenceValidator is null)
        {
            return;
        }

        var evidence = new TlsServerCertificateEvidence(
            referenceIdentity,
            protocolVersion,
            certificates.Certificates.Select(certificate => certificate.RawData).ToArray(),
            stapledOcspResponse,
            signedCertificateTimestamps);
        TlsServerCertificateEvidenceValidationResult result;
        try
        {
            result = await policy.EvidenceValidator(
                evidence,
                cancellationToken).ConfigureAwait(false) ??
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
            signedCertificateTimestamps.Count)
        {
            throw new TlsProtocolException(
                TlsAlertDescription.CertificateUnknown,
                "The certificate-evidence validator reported more valid SCTs than supplied.");
        }
        if (result.StapledOcspStatus == TlsStapledOcspValidationStatus.Revoked)
        {
            throw new TlsProtocolException(
                TlsAlertDescription.CertificateRevoked,
                "The stapled OCSP response proves that the server certificate is revoked.");
        }
        if (result.StapledOcspStatus is
                TlsStapledOcspValidationStatus.Invalid or
                TlsStapledOcspValidationStatus.Unknown ||
            (result.StapledOcspStatus == TlsStapledOcspValidationStatus.Good &&
             stapledOcspResponse is null) ||
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

    private async ValueTask WriteNssKeyLogSecretAsync(
        string label,
        ReadOnlyMemory<byte> clientRandom,
        byte[] secret,
        CancellationToken cancellationToken)
    {
        try
        {
            if (_configuration.DangerousNssKeyLog is { } sink)
            {
                await sink.WriteSecretAsync(
                    label,
                    clientRandom,
                    secret,
                    cancellationToken).ConfigureAwait(false);
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(secret);
        }
    }

    private void NotifyHandshakeEvent(
        TlsHandshakeEventKind kind,
        TlsHandshakeEventDirection direction,
        int encodedLength,
        TlsClientHelloFlight? clientHelloFlight = null)
    {
        var observer = _configuration.HandshakeEventObserver;
        if (observer is null)
        {
            return;
        }
        if (encodedLength < 0)
        {
            throw new ArgumentOutOfRangeException(nameof(encodedLength));
        }

        lock (_handshakeEventSync)
        {
            if (_insideHandshakeEventObserver)
            {
                throw new InvalidOperationException("TLS handshake event observers cannot be re-entered.");
            }
            _insideHandshakeEventObserver = true;
            try
            {
                observer(new TlsHandshakeEvent(
                    ++_handshakeEventSequence,
                    kind,
                    direction,
                    NegotiatedProtocolVersion ?? _activeHandshakeVersion,
                    encodedLength,
                    clientHelloFlight));
            }
            finally
            {
                _insideHandshakeEventObserver = false;
            }
        }
    }

    private static TlsHandshakeEventKind GetHandshakeEventKind(HandshakeType type) => type switch
    {
        HandshakeType.EncryptedExtensions => TlsHandshakeEventKind.EncryptedExtensions,
        HandshakeType.CertificateRequest => TlsHandshakeEventKind.CertificateRequest,
        HandshakeType.Certificate or HandshakeType.CompressedCertificate =>
            TlsHandshakeEventKind.Certificate,
        HandshakeType.CertificateVerify => TlsHandshakeEventKind.CertificateVerify,
        HandshakeType.Finished => TlsHandshakeEventKind.Finished,
        HandshakeType.NewSessionTicket => TlsHandshakeEventKind.NewSessionTicket,
        HandshakeType.KeyUpdate => TlsHandshakeEventKind.KeyUpdate,
        _ => throw new ArgumentOutOfRangeException(nameof(type)),
    };

    private void InitializeTransportState()
    {
        if (UsesTls12OnlyProfile())
        {
            _activeHandshakeVersion = TlsProtocolVersion.Tls12;
            _tls12State.TransportConnected();
        }
        else
        {
            _activeHandshakeVersion = TlsProtocolVersion.Tls13;
            _tls13State.TransportConnected();
        }
    }

    private bool IsHandshakeConnected() =>
        _tls13State.State == Tls13ClientState.Connected ||
        _tls12State.State == Tls12ClientState.Connected;

    private void FailActiveState()
    {
        if (_activeHandshakeVersion == TlsProtocolVersion.Tls12 ||
            NegotiatedProtocolVersion == TlsProtocolVersion.Tls12)
        {
            _tls12State.Fail();
        }
        else
        {
            _tls13State.Fail();
        }
    }

    private async ValueTask DisposeTransportAsync()
    {
        if (_stream is not null)
        {
            if (_ownsTransport)
            {
                await _stream.DisposeAsync().ConfigureAwait(false);
            }
            _stream = null;
        }
        else
        {
            _socket?.Dispose();
        }

        _socket = null;
        _recordReader = null;
        _recordWriter = null;
    }

    private async ValueTask FailAndDisposeTransportAsync()
    {
        FailActiveState();
        try
        {
            await DisposeTransportAsync().ConfigureAwait(false);
        }
        catch (Exception exception) when (
            exception is IOException or SocketException or ObjectDisposedException)
        {
            // Preserve the protocol/I/O failure which caused the connection to become unusable.
        }
    }

    private static bool IsConnectionFailure(Exception exception) =>
        exception is TlsProtocolException or IOException or SocketException or ObjectDisposedException;

    private async ValueTask TrySendHandshakeFatalAlertAsync(
        TlsAlertDescription alert,
        Tls13RecordCipher? clientHandshakeCipher)
    {
        if (_recordWriter is null)
        {
            return;
        }

        try
        {
            byte[] payload = [2, (byte)alert];
            if (clientHandshakeCipher is null)
            {
                await _recordWriter.WriteRecordAsync(
                    TlsContentType.Alert,
                    payload,
                    CancellationToken.None).ConfigureAwait(false);
            }
            else
            {
                await WriteProtectedRecordAsync(
                    clientHandshakeCipher,
                    TlsContentType.Alert,
                    payload,
                    paddingLength: 0,
                    CancellationToken.None).ConfigureAwait(false);
            }
        }
        catch (Exception exception) when (IsConnectionFailure(exception))
        {
            // Alert transmission is best-effort; preserve the original protocol failure.
        }
    }

    private async ValueTask TrySendTls12HandshakeFatalAlertAsync(
        TlsAlertDescription alert,
        Tls12AeadRecordCipher? clientCipher)
    {
        if (_recordWriter is null)
        {
            return;
        }

        try
        {
            byte[] payload = [2, (byte)alert];
            if (clientCipher is null)
            {
                await _recordWriter.WriteRecordAsync(
                    TlsContentType.Alert,
                    payload,
                    CancellationToken.None,
                    TlsConstants.Tls12Version).ConfigureAwait(false);
            }
            else
            {
                await WriteTls12ProtectedRecordAsync(
                    clientCipher,
                    TlsContentType.Alert,
                    payload,
                    CancellationToken.None).ConfigureAwait(false);
            }
        }
        catch (Exception exception) when (IsConnectionFailure(exception))
        {
            // Alert transmission is best-effort; preserve the original protocol failure.
        }
    }

    private async ValueTask TrySendApplicationFatalAlertAsync(TlsAlertDescription alert)
    {
        if (_recordWriter is null ||
            (_clientApplicationCipher is null && _tls12ClientApplicationCipher is null) ||
            !_writeLock.Wait(0))
        {
            return;
        }

        try
        {
            if (NegotiatedProtocolVersion == TlsProtocolVersion.Tls12)
            {
                await WriteTls12ProtectedRecordAsync(
                    _tls12ClientApplicationCipher!,
                    TlsContentType.Alert,
                    new byte[] { 2, (byte)alert },
                    CancellationToken.None).ConfigureAwait(false);
            }
            else
            {
                await WriteProtectedRecordAsync(
                    _clientApplicationCipher!,
                    TlsContentType.Alert,
                    new byte[] { 2, (byte)alert },
                    paddingLength: 0,
                    CancellationToken.None).ConfigureAwait(false);
            }
        }
        catch (Exception exception) when (IsConnectionFailure(exception))
        {
            // Alert transmission is best-effort; preserve the original protocol failure.
        }
        finally
        {
            _writeLock.Release();
        }
    }
}
