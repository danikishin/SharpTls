using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using SharpTls.Certificates;
using SharpTls.Cryptography;
using SharpTls.Ech;
using SharpTls.Handshake;
using SharpTls.IO;
using SharpTls.Protocol;
using SharpTls.Records;

namespace SharpTls.Tests.Interop;

/// <summary>A minimal managed TLS 1.3 server that verifies the client's authentication block.</summary>
internal sealed class ManagedTls13MutualAuthServer : IAsyncDisposable
{
    private static readonly CipherSuiteInfo Suite =
        CipherSuiteInfo.Get(TlsCipherSuite.TlsAes128GcmSha256);

    private readonly TcpListener _listener;
    private readonly CancellationTokenSource _stopping = new();
    private readonly X509Certificate2 _serverLeaf;
    private readonly X509Certificate2 _serverIssuer;
    private readonly RSA _serverKey;
    private readonly SignatureScheme _serverSignatureScheme;
    private readonly byte[] _expectedClientLeaf;
    private readonly bool _requestPostHandshakeAuthentication;
    private readonly bool _expectPostHandshakeRejection;
    private readonly bool _repeatPostHandshakeContext;
    private readonly bool _expectEmptyPostHandshakeCertificate;
    private readonly int? _serverRecordSizeLimit;
    private readonly byte[] _expectedApplicationRequest;
    private readonly byte[] _applicationResponse;
    private readonly bool _violateClientRecordSizeLimitAfterHandshake;
    private readonly ECDsa? _serverDelegatedCredentialKey;
    private readonly RSA? _serverRsaDelegatedCredentialKey;
    private readonly byte[]? _serverRsaDelegatedCredentialSpki;
    private readonly bool _tamperDelegatedCredential;
    private readonly bool _expectDelegatedCredentialRejection;
    private readonly TlsApplicationSettingsCodePoint? _applicationSettingsCodePoint;
    private readonly string _applicationSettingsProtocol;
    private readonly byte[] _serverApplicationSettings;
    private readonly byte[] _expectedClientApplicationSettings;
    private readonly bool _expectApplicationSettingsRejection;
    private readonly TlsEchConfig? _echConfiguration;
    private readonly byte[]? _echPrivateKey;
    private readonly bool _expectEmptyInitialCertificate;
    private readonly bool _expectEchRequiredAlert;
    private readonly byte[]? _echRetryConfigurations;
    private readonly bool _useEchHelloRetryRequest;
    private readonly byte[]? _resumptionTicketIdentity;
    private readonly byte[]? _resumptionPsk;
    private readonly byte[]? _expectedEarlyData;
    private readonly bool _selectOuterGreasePsk;
    private readonly byte[]? _newSessionTicketIdentity;
    private readonly uint? _newSessionTicketMaximumEarlyDataSize;
    private readonly bool _ignoreRejectedEarlyDataRecord;
    private readonly bool _requestClientDelegatedCredential;
    private readonly byte[]? _serverOcspResponse;
    private readonly byte[][] _serverSignedCertificateTimestamps;
    private readonly bool _expectCertificateEvidenceRejection;
    private readonly TlsAlertDescription _expectedCertificateEvidenceAlert;
    private ECDsa? _clientDelegatedCredentialKey;
    private byte[]? _issuedResumptionPsk;
    private readonly Task _runTask;

    internal ManagedTls13MutualAuthServer(
        X509Certificate2 serverLeaf,
        X509Certificate2 serverIssuer,
        RSA serverKey,
        ReadOnlySpan<byte> expectedClientLeaf,
        bool requestPostHandshakeAuthentication = false,
        bool expectPostHandshakeRejection = false,
        bool repeatPostHandshakeContext = false,
        bool expectEmptyPostHandshakeCertificate = false,
        int? serverRecordSizeLimit = null,
        byte[]? expectedApplicationRequest = null,
        byte[]? applicationResponse = null,
        bool violateClientRecordSizeLimitAfterHandshake = false,
        ECDsa? serverDelegatedCredentialKey = null,
        bool tamperDelegatedCredential = false,
        bool expectDelegatedCredentialRejection = false,
        TlsApplicationSettingsCodePoint? applicationSettingsCodePoint = null,
        string applicationSettingsProtocol = "h2",
        byte[]? serverApplicationSettings = null,
        byte[]? expectedClientApplicationSettings = null,
        bool expectApplicationSettingsRejection = false,
        TlsEchConfig? echConfiguration = null,
        byte[]? echPrivateKey = null,
        bool expectEmptyInitialCertificate = false,
        bool expectEchRequiredAlert = false,
        byte[]? echRetryConfigurations = null,
        bool useEchHelloRetryRequest = false,
        byte[]? resumptionTicketIdentity = null,
        byte[]? resumptionPsk = null,
        byte[]? expectedEarlyData = null,
        bool selectOuterGreasePsk = false,
        byte[]? newSessionTicketIdentity = null,
        uint? newSessionTicketMaximumEarlyDataSize = null,
        bool ignoreRejectedEarlyDataRecord = false,
        SignatureScheme serverSignatureScheme = SignatureScheme.RsaPssRsaeSha256,
        RSA? serverRsaDelegatedCredentialKey = null,
        byte[]? serverRsaDelegatedCredentialSpki = null,
        bool requestClientDelegatedCredential = false,
        byte[]? serverOcspResponse = null,
        byte[][]? serverSignedCertificateTimestamps = null,
        bool expectCertificateEvidenceRejection = false,
        TlsAlertDescription expectedCertificateEvidenceAlert =
            TlsAlertDescription.BadCertificateStatusResponse)
    {
        _serverLeaf = serverLeaf;
        _serverIssuer = serverIssuer;
        _serverKey = serverKey;
        if (serverSignatureScheme is not (
            SignatureScheme.RsaPssRsaeSha256 or
            SignatureScheme.RsaPssRsaeSha384 or
            SignatureScheme.RsaPssRsaeSha512 or
            SignatureScheme.RsaPssPssSha256 or
            SignatureScheme.RsaPssPssSha384 or
            SignatureScheme.RsaPssPssSha512))
        {
            throw new ArgumentOutOfRangeException(nameof(serverSignatureScheme));
        }
        _serverSignatureScheme = serverSignatureScheme;
        _expectedClientLeaf = expectedClientLeaf.ToArray();
        if (serverRecordSizeLimit is < 64 or > TlsConstants.MaxPlaintextLength + 1)
        {
            throw new ArgumentOutOfRangeException(nameof(serverRecordSizeLimit));
        }
        _requestPostHandshakeAuthentication = requestPostHandshakeAuthentication;
        _expectPostHandshakeRejection = expectPostHandshakeRejection;
        _repeatPostHandshakeContext = repeatPostHandshakeContext;
        _expectEmptyPostHandshakeCertificate = expectEmptyPostHandshakeCertificate;
        _serverRecordSizeLimit = serverRecordSizeLimit;
        _expectedApplicationRequest = expectedApplicationRequest?.ToArray() ?? "ping"u8.ToArray();
        _applicationResponse = applicationResponse?.ToArray() ?? "pong"u8.ToArray();
        _violateClientRecordSizeLimitAfterHandshake =
            violateClientRecordSizeLimitAfterHandshake;
        _serverDelegatedCredentialKey = serverDelegatedCredentialKey;
        if ((serverRsaDelegatedCredentialKey is null) !=
                (serverRsaDelegatedCredentialSpki is null) ||
            (serverDelegatedCredentialKey is not null && serverRsaDelegatedCredentialKey is not null))
        {
            throw new ArgumentException(
                "Configure exactly one complete ECDSA or RSASSA-PSS delegated key.");
        }
        _serverRsaDelegatedCredentialKey = serverRsaDelegatedCredentialKey;
        _serverRsaDelegatedCredentialSpki = serverRsaDelegatedCredentialSpki?.ToArray();
        _tamperDelegatedCredential = tamperDelegatedCredential;
        _expectDelegatedCredentialRejection = expectDelegatedCredentialRejection;
        if (applicationSettingsCodePoint.HasValue &&
            !Enum.IsDefined(applicationSettingsCodePoint.Value))
        {
            throw new ArgumentOutOfRangeException(nameof(applicationSettingsCodePoint));
        }
        _applicationSettingsCodePoint = applicationSettingsCodePoint;
        _applicationSettingsProtocol = applicationSettingsProtocol;
        _serverApplicationSettings = serverApplicationSettings?.ToArray() ?? [];
        _expectedClientApplicationSettings =
            expectedClientApplicationSettings?.ToArray() ?? [];
        if (expectApplicationSettingsRejection && !applicationSettingsCodePoint.HasValue)
        {
            throw new ArgumentException(
                "An application-settings rejection requires an application_settings code point.",
                nameof(expectApplicationSettingsRejection));
        }
        _expectApplicationSettingsRejection = expectApplicationSettingsRejection;
        if ((echConfiguration is null) != (echPrivateKey is null))
        {
            throw new ArgumentException(
                "ECH configuration and private key must be supplied together.");
        }
        if (echConfiguration is not null &&
            (echConfiguration.KemId != TlsHpkeKemId.DhkemX25519HkdfSha256 ||
             echPrivateKey!.Length != 32))
        {
            throw new ArgumentException("The managed ECH server requires a 32-byte X25519 key.");
        }
        _echConfiguration = echConfiguration;
        _echPrivateKey = echPrivateKey?.ToArray();
        _expectEmptyInitialCertificate = expectEmptyInitialCertificate;
        _expectEchRequiredAlert = expectEchRequiredAlert;
        _echRetryConfigurations = echRetryConfigurations?.ToArray();
        if (useEchHelloRetryRequest && echConfiguration is null)
        {
            throw new ArgumentException(
                "The managed ECH HelloRetryRequest path requires an ECH configuration.",
                nameof(useEchHelloRetryRequest));
        }
        _useEchHelloRetryRequest = useEchHelloRetryRequest;
        if ((resumptionTicketIdentity is null) != (resumptionPsk is null) ||
            resumptionTicketIdentity is { Length: 0 } ||
            resumptionPsk is { Length: not 32 })
        {
            throw new ArgumentException(
                "Managed resumption requires a non-empty identity and 32-byte SHA-256 PSK.");
        }
        _resumptionTicketIdentity = resumptionTicketIdentity?.ToArray();
        _resumptionPsk = resumptionPsk?.ToArray();
        if (expectedEarlyData is { Length: 0 } ||
            (expectedEarlyData is not null && resumptionPsk is null))
        {
            throw new ArgumentException(
                "Managed ECH early data requires a resumption PSK and non-empty payload.");
        }
        _expectedEarlyData = expectedEarlyData?.ToArray();
        if (selectOuterGreasePsk && echConfiguration is not null)
        {
            throw new ArgumentException(
                "The outer GREASE PSK negative path must reject ECH.");
        }
        _selectOuterGreasePsk = selectOuterGreasePsk;
        if (newSessionTicketIdentity is { Length: 0 } ||
            (newSessionTicketMaximumEarlyDataSize.HasValue &&
             newSessionTicketIdentity is null))
        {
            throw new ArgumentException(
                "A managed NewSessionTicket requires a non-empty identity.");
        }
        _newSessionTicketIdentity = newSessionTicketIdentity?.ToArray();
        _newSessionTicketMaximumEarlyDataSize = newSessionTicketMaximumEarlyDataSize;
        if (ignoreRejectedEarlyDataRecord && echConfiguration is not null)
        {
            throw new ArgumentException(
                "Rejected early-data simulation requires the server to reject ECH.");
        }
        _ignoreRejectedEarlyDataRecord = ignoreRejectedEarlyDataRecord;
        _requestClientDelegatedCredential = requestClientDelegatedCredential;
        if (serverOcspResponse is { Length: 0 } ||
            serverSignedCertificateTimestamps?.Any(value => value is null or { Length: 0 }) == true)
        {
            throw new ArgumentException("Certificate evidence entries must be non-empty.");
        }
        _serverOcspResponse = serverOcspResponse?.ToArray();
        _serverSignedCertificateTimestamps = serverSignedCertificateTimestamps?
            .Select(value => value.ToArray())
            .ToArray() ?? [];
        if (expectCertificateEvidenceRejection &&
            serverOcspResponse is null && _serverSignedCertificateTimestamps.Length == 0)
        {
            throw new ArgumentException(
                "An evidence rejection test requires certificate evidence.",
                nameof(expectCertificateEvidenceRejection));
        }
        _expectCertificateEvidenceRejection = expectCertificateEvidenceRejection;
        _expectedCertificateEvidenceAlert = expectedCertificateEvidenceAlert;
        _listener = new TcpListener(IPAddress.Loopback, 0);
        _listener.Start(1);
        _runTask = RunAsync(_stopping.Token);
    }

    internal int Port => ((IPEndPoint)_listener.LocalEndpoint).Port;

    internal Task Completion => _runTask;

    internal bool ClientCertificateVerified { get; private set; }

    internal bool ClientDelegatedCredentialVerified { get; private set; }

    internal bool CertificateEvidenceRejectionObserved { get; private set; }

    internal bool PostHandshakeRequestWasRejected { get; private set; }

    internal int MaximumReceivedProtectedPlaintextLength { get; private set; }

    internal bool DelegatedCredentialRejectionObserved { get; private set; }

    internal bool ClientApplicationSettingsVerified { get; private set; }

    internal bool ApplicationSettingsRejectionObserved { get; private set; }

    internal bool EchAccepted { get; private set; }

    internal string? EchOuterServerName { get; private set; }

    internal string? EchInnerServerName { get; private set; }

    internal bool EchRequiredAlertReceived { get; private set; }

    internal bool EchHelloRetryRequestCompleted { get; private set; }

    internal bool EchInnerPskVerified { get; private set; }

    internal bool EchOuterPskWasGreased { get; private set; }

    internal byte[]? ReceivedEarlyData { get; private set; }

    internal bool OuterGreasePskSelectionAlertReceived { get; private set; }

    internal byte[] CopyIssuedResumptionPsk() => _issuedResumptionPsk is null
        ? throw new InvalidOperationException("The server has not issued a resumption PSK.")
        : (byte[])_issuedResumptionPsk.Clone();

    internal bool RejectedEarlyDataRecordIgnored { get; private set; }

    public async ValueTask DisposeAsync()
    {
        _stopping.Cancel();
        _listener.Stop();
        try
        {
            await _runTask.ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (_stopping.IsCancellationRequested)
        {
        }
        catch (SocketException) when (_stopping.IsCancellationRequested)
        {
        }
        finally
        {
            _stopping.Dispose();
            CryptographicOperations.ZeroMemory(_expectedClientLeaf);
            CryptographicOperations.ZeroMemory(_expectedApplicationRequest);
            CryptographicOperations.ZeroMemory(_applicationResponse);
            CryptographicOperations.ZeroMemory(_serverApplicationSettings);
            CryptographicOperations.ZeroMemory(_expectedClientApplicationSettings);
            if (_echPrivateKey is not null)
            {
                CryptographicOperations.ZeroMemory(_echPrivateKey);
            }
            if (_echRetryConfigurations is not null)
            {
                CryptographicOperations.ZeroMemory(_echRetryConfigurations);
            }
            if (_resumptionTicketIdentity is not null)
            {
                CryptographicOperations.ZeroMemory(_resumptionTicketIdentity);
            }
            if (_resumptionPsk is not null)
            {
                CryptographicOperations.ZeroMemory(_resumptionPsk);
            }
            if (_expectedEarlyData is not null)
            {
                CryptographicOperations.ZeroMemory(_expectedEarlyData);
            }
            if (ReceivedEarlyData is not null)
            {
                CryptographicOperations.ZeroMemory(ReceivedEarlyData);
            }
            if (_newSessionTicketIdentity is not null)
            {
                CryptographicOperations.ZeroMemory(_newSessionTicketIdentity);
            }
            if (_issuedResumptionPsk is not null)
            {
                CryptographicOperations.ZeroMemory(_issuedResumptionPsk);
            }
            if (_serverOcspResponse is not null)
            {
                CryptographicOperations.ZeroMemory(_serverOcspResponse);
            }
            foreach (var sct in _serverSignedCertificateTimestamps)
            {
                CryptographicOperations.ZeroMemory(sct);
            }
            _clientDelegatedCredentialKey?.Dispose();
            _clientDelegatedCredentialKey = null;
        }
    }

    private async Task RunAsync(CancellationToken cancellationToken)
    {
        using var socket = await _listener.AcceptSocketAsync(cancellationToken).ConfigureAwait(false);
        _listener.Stop();
        await using var stream = new NetworkStream(socket, ownsSocket: true);
        var reader = new TlsRecordReader(stream);
        var writer = new TlsRecordWriter(stream);
        using var echReceiver = _echConfiguration is null
            ? null
            : new ManagedEchReceiver(_echConfiguration, _echPrivateKey!);
        var wireClientHello = await ReadClientHelloAsync(reader, cancellationToken).ConfigureAwait(false);
        EchOuterServerName = ReadServerName(wireClientHello.Encoded);
        var clientHello = echReceiver is null
            ? wireClientHello
            : echReceiver.Decrypt(wireClientHello, isRetry: false);
        if (_echConfiguration is not null)
        {
            EchAccepted = true;
            EchInnerServerName = ReadServerName(clientHello.Encoded);
        }
        var parsed = ParseClientHello(clientHello.Encoded, NamedGroup.Secp256r1);
        var isResumption = _resumptionPsk is not null;
        if (isResumption)
        {
            if (!parsed.PskIdentity.AsSpan().SequenceEqual(_resumptionTicketIdentity) ||
                parsed.PskBinder is null)
            {
                throw new CryptographicException(
                    "ClientHelloInner did not contain the expected resumption identity.");
            }
            VerifyPskBinder(clientHello.Encoded, parsed.PskBinder, _resumptionPsk!);
            EchInnerPskVerified = true;

            if (_echConfiguration is not null)
            {
                var outerPsk = ParseClientHello(
                    wireClientHello.Encoded,
                    NamedGroup.Secp256r1);
                if (outerPsk.PskIdentity is null || outerPsk.PskBinder is null ||
                    outerPsk.PskIdentity.Length != parsed.PskIdentity!.Length ||
                    outerPsk.PskBinder.Length != parsed.PskBinder.Length ||
                    outerPsk.PskIdentity.AsSpan().SequenceEqual(_resumptionTicketIdentity) ||
                    (_expectedEarlyData is not null && !outerPsk.OfferedEarlyData))
                {
                    throw new CryptographicException(
                        "ClientHelloOuter did not contain a length-matched GREASE PSK.");
                }
                EchOuterPskWasGreased = true;
            }
        }
        HandshakeMessage? firstInnerClientHello = null;
        byte[]? helloRetryRequest = null;
        var selectedGroup = NamedGroup.Secp256r1;
        using var transcript = new TranscriptHash(Suite);
        if (_useEchHelloRetryRequest)
        {
            firstInnerClientHello = clientHello;
            helloRetryRequest = BuildHelloRetryRequest(
                parsed.SessionId,
                NamedGroup.Secp384r1,
                includeEchConfirmation: true);
            var retryConfirmation = EchAcceptanceConfirmation.ComputeForHelloRetryRequest(
                Suite.Suite,
                firstInnerClientHello.Encoded,
                helloRetryRequest);
            try
            {
                retryConfirmation.CopyTo(
                    helloRetryRequest,
                    helloRetryRequest.Length - retryConfirmation.Length);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(retryConfirmation);
            }

            transcript.ResetForHelloRetryRequest(firstInnerClientHello.Encoded);
            transcript.Append(helloRetryRequest);
            await writer.WriteRecordAsync(
                TlsContentType.Handshake,
                helloRetryRequest,
                cancellationToken).ConfigureAwait(false);

            var retryWireClientHello = await ReadClientHelloAsync(
                reader,
                cancellationToken,
                allowCompatibilityCcs: true).ConfigureAwait(false);
            ValidateRetryIdentity(
                wireClientHello.Encoded,
                retryWireClientHello.Encoded,
                "ClientHelloOuter");
            clientHello = echReceiver!.Decrypt(retryWireClientHello, isRetry: true);
            ValidateRetryIdentity(
                firstInnerClientHello.Encoded,
                clientHello.Encoded,
                "ClientHelloInner");
            EchInnerServerName = ReadServerName(clientHello.Encoded);
            parsed = ParseClientHello(clientHello.Encoded, NamedGroup.Secp384r1);
            if (isResumption)
            {
                if (!parsed.PskIdentity.AsSpan().SequenceEqual(_resumptionTicketIdentity) ||
                    parsed.PskBinder is null)
                {
                    throw new CryptographicException(
                        "Second ClientHelloInner omitted the expected resumption identity.");
                }
                var firstHash = SHA256.HashData(firstInnerClientHello.Encoded);
                var messageHash = HandshakeMessage.Encode(
                    HandshakeType.MessageHash,
                    firstHash);
                byte[] binderPrefix = [.. messageHash, .. helloRetryRequest];
                try
                {
                    VerifyPskBinder(
                        clientHello.Encoded,
                        parsed.PskBinder,
                        _resumptionPsk!,
                        binderPrefix);
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(firstHash);
                    CryptographicOperations.ZeroMemory(messageHash);
                    CryptographicOperations.ZeroMemory(binderPrefix);
                }

                var retryOuterPsk = ParseClientHello(
                    retryWireClientHello.Encoded,
                    NamedGroup.Secp384r1);
                if (retryOuterPsk.PskIdentity is null ||
                    retryOuterPsk.PskBinder is null ||
                    retryOuterPsk.PskIdentity.Length != parsed.PskIdentity!.Length ||
                    retryOuterPsk.PskBinder.Length != parsed.PskBinder.Length ||
                    retryOuterPsk.PskIdentity.AsSpan().SequenceEqual(
                        _resumptionTicketIdentity))
                {
                    throw new CryptographicException(
                        "Second ClientHelloOuter did not contain a GREASE PSK.");
                }
            }
            selectedGroup = NamedGroup.Secp384r1;
            transcript.Append(clientHello.Encoded);
            EchHelloRetryRequestCompleted = true;
        }
        else
        {
            transcript.Append(clientHello.Encoded);
        }
        if ((_serverDelegatedCredentialKey is not null ||
                _serverRsaDelegatedCredentialKey is not null) &&
            !parsed.OfferedDelegatedCredentials)
        {
            throw new InvalidDataException("The client did not offer delegated credentials.");
        }
        if (_applicationSettingsCodePoint is { } applicationSettingsCodePoint &&
            (parsed.ApplicationSettingsCodePoint != applicationSettingsCodePoint ||
             !parsed.ApplicationSettingsProtocols.Contains(
                 _applicationSettingsProtocol,
                 StringComparer.Ordinal) ||
             !parsed.AlpnProtocols.Contains(
                 _applicationSettingsProtocol,
                 StringComparer.Ordinal)))
        {
            throw new InvalidDataException(
                "The client did not coherently offer the expected application_settings protocol.");
        }

        using var schedule = new Tls13KeySchedule(
            Suite,
            _resumptionPsk is null ? default : _resumptionPsk);
        using var earlyDataCipher = _expectedEarlyData is null
            ? null
            : CreateEarlyDataCipher(schedule, clientHello.Encoded, parsed.OfferedEarlyData);
        using var serverKeyShare = KeyShareFactory.Create(selectedGroup);
        var serverHello = BuildServerHello(
            parsed.SessionId,
            selectedGroup,
            serverKeyShare.PublicKey.Span,
            selectPsk: isResumption || _selectOuterGreasePsk);
        if (EchAccepted)
        {
            var confirmation = _useEchHelloRetryRequest
                ? EchAcceptanceConfirmation.ComputeForServerHelloAfterHelloRetryRequest(
                    Suite.Suite,
                    firstInnerClientHello!.Encoded,
                    helloRetryRequest!,
                    clientHello.Encoded,
                    serverHello)
                : EchAcceptanceConfirmation.ComputeForServerHello(
                    Suite.Suite,
                    clientHello.Encoded,
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
        var sharedSecret = serverKeyShare.DeriveSharedSecret(parsed.ClientKeyExchange);
        var helloHash = transcript.CurrentHash();
        try
        {
            schedule.DeriveHandshakeSecrets(sharedSecret, helloHash);
            schedule.DeriveMainSecret();
        }
        finally
        {
            CryptographicOperations.ZeroMemory(sharedSecret);
            CryptographicOperations.ZeroMemory(helloHash);
        }

        using var serverHandshakeCipher = CreateCipher(schedule.GetServerHandshakeKeys());
        using var clientHandshakeCipher = CreateCipher(schedule.GetClientHandshakeKeys());
        await writer.WriteRecordAsync(
            TlsContentType.Handshake,
            serverHello,
            cancellationToken).ConfigureAwait(false);

        if (_selectOuterGreasePsk)
        {
            var alert = await reader.ReadAsync(cancellationToken).ConfigureAwait(false) ??
                throw new EndOfStreamException(
                    "Client closed without rejecting the selected outer GREASE PSK.");
            if (alert.ContentType != TlsContentType.Alert ||
                !alert.Fragment.AsSpan().SequenceEqual(
                    [(byte)2, (byte)TlsAlertDescription.IllegalParameter]))
            {
                throw new InvalidDataException(
                    "Client did not reject outer GREASE PSK selection with illegal_parameter.");
            }
            OuterGreasePskSelectionAlertReceived = true;
            return;
        }

        if (_ignoreRejectedEarlyDataRecord)
        {
            var ignored = await reader.ReadAsync(cancellationToken).ConfigureAwait(false) ??
                throw new EndOfStreamException(
                    "Client closed before its rejected early-data record.");
            if (ignored.ContentType != TlsContentType.ApplicationData)
            {
                throw new InvalidDataException(
                    "Rejected early data was not carried in application_data.");
            }
            RejectedEarlyDataRecordIgnored = true;
        }

        if (earlyDataCipher is not null)
        {
            ReceivedEarlyData = await ReadProtectedContentAsync(
                reader,
                earlyDataCipher,
                _expectedEarlyData!.Length,
                cancellationToken).ConfigureAwait(false);
            if (!ReceivedEarlyData.AsSpan().SequenceEqual(_expectedEarlyData))
            {
                throw new CryptographicException("ECH early data decrypted incorrectly.");
            }
        }

        var encryptedExtensions = BuildEncryptedExtensions(
            _serverRecordSizeLimit,
            _applicationSettingsCodePoint,
            _applicationSettingsProtocol,
            _serverApplicationSettings,
            _echRetryConfigurations,
            acceptEarlyData: earlyDataCipher is not null);
        transcript.Append(encryptedExtensions);
        byte[]? certificateRequest = null;
        byte[]? certificate = null;
        byte[]? certificateVerify = null;
        if (!isResumption)
        {
            certificateRequest = BuildCertificateRequest(
                [],
                SignatureScheme.RsaPssRsaeSha256,
                _requestClientDelegatedCredential);
            var delegatedCredential = _serverDelegatedCredentialKey is null &&
                    _serverRsaDelegatedCredentialKey is null
                ? null
                : BuildDelegatedCredential();
            certificate = BuildCertificate(delegatedCredential);
            transcript.Append(certificateRequest);
            transcript.Append(certificate);
            certificateVerify = BuildServerCertificateVerify(transcript.CurrentHash());
            transcript.Append(certificateVerify);
        }
        var finishedHash = transcript.CurrentHash();
        var verifyData = schedule.ComputeServerFinished(finishedHash);
        var finished = HandshakeMessage.Encode(HandshakeType.Finished, verifyData);
        CryptographicOperations.ZeroMemory(finishedHash);
        CryptographicOperations.ZeroMemory(verifyData);
        transcript.Append(finished);

        byte[] serverFlight = isResumption
            ? [.. encryptedExtensions, .. finished]
            :
            [
                .. encryptedExtensions,
                .. certificateRequest!,
                .. certificate!,
                .. certificateVerify!,
                .. finished,
            ];
        try
        {
            await WriteProtectedFragmentsAsync(
                writer,
                serverHandshakeCipher,
                TlsContentType.Handshake,
                serverFlight,
                parsed.RecordSizeLimit,
                cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(serverFlight);
        }

        if (_expectDelegatedCredentialRejection)
        {
            await ReadExpectedPostHandshakeAlertAsync(
                reader,
                clientHandshakeCipher,
                TlsAlertDescription.IllegalParameter,
                cancellationToken).ConfigureAwait(false);
            DelegatedCredentialRejectionObserved = true;
            return;
        }
        if (_expectApplicationSettingsRejection)
        {
            await ReadExpectedPostHandshakeAlertAsync(
                reader,
                clientHandshakeCipher,
                TlsAlertDescription.IllegalParameter,
                cancellationToken).ConfigureAwait(false);
            ApplicationSettingsRejectionObserved = true;
            return;
        }
        if (_expectCertificateEvidenceRejection)
        {
            await ReadExpectedPostHandshakeAlertAsync(
                reader,
                clientHandshakeCipher,
                _expectedCertificateEvidenceAlert,
                cancellationToken).ConfigureAwait(false);
            CertificateEvidenceRejectionObserved = true;
            return;
        }

        var applicationHash = transcript.CurrentHash();
        try
        {
            schedule.DeriveApplicationTrafficSecrets(applicationHash);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(applicationHash);
        }
        using var serverApplicationCipher = CreateCipher(schedule.GetServerApplicationKeys());
        using var clientApplicationCipher = CreateCipher(schedule.GetClientApplicationKeys());

        await ReadAndVerifyClientAuthenticationAsync(
            reader,
            clientHandshakeCipher,
            schedule,
            transcript,
            expectCertificateAuthentication: !isResumption,
            expectEndOfEarlyData: earlyDataCipher is not null,
            cancellationToken).ConfigureAwait(false);

        if (_newSessionTicketIdentity is not null)
        {
            var resumptionHash = transcript.CurrentHash();
            try
            {
                schedule.DeriveResumptionMasterSecret(resumptionHash);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(resumptionHash);
            }
            byte[] nonce = [0x42];
            _issuedResumptionPsk = schedule.DeriveResumptionPsk(nonce);
            var newSessionTicket = BuildNewSessionTicket(
                _newSessionTicketIdentity,
                nonce,
                _newSessionTicketMaximumEarlyDataSize);
            try
            {
                await WriteProtectedAsync(
                    writer,
                    serverApplicationCipher,
                    TlsContentType.Handshake,
                    newSessionTicket,
                    cancellationToken).ConfigureAwait(false);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(newSessionTicket);
            }
        }

        if (_expectEchRequiredAlert)
        {
            await ReadExpectedPostHandshakeAlertAsync(
                reader,
                clientApplicationCipher,
                TlsAlertDescription.EchRequired,
                cancellationToken).ConfigureAwait(false);
            EchRequiredAlertReceived = true;
            return;
        }

        if (_requestPostHandshakeAuthentication)
        {
            if (!parsed.OfferedPostHandshakeAuthentication && !_expectPostHandshakeRejection)
            {
                throw new InvalidDataException(
                    "The client did not advertise post_handshake_auth.");
            }

            var requestContext = "pha-request-1"u8.ToArray();
            var postHandshakeRequest = BuildCertificateRequest(
                requestContext,
                _expectEmptyPostHandshakeCertificate
                    ? SignatureScheme.EcdsaSecp256r1Sha256
                    : SignatureScheme.RsaPssRsaeSha256,
                _requestClientDelegatedCredential &&
                    !_expectEmptyPostHandshakeCertificate);
            transcript.Append(postHandshakeRequest);
            await WriteProtectedAsync(
                writer,
                serverApplicationCipher,
                TlsContentType.Handshake,
                postHandshakeRequest,
                cancellationToken).ConfigureAwait(false);
            if (_expectPostHandshakeRejection)
            {
                await ReadExpectedPostHandshakeAlertAsync(
                    reader,
                    clientApplicationCipher,
                    TlsAlertDescription.UnexpectedMessage,
                    cancellationToken).ConfigureAwait(false);
                PostHandshakeRequestWasRejected = true;
                return;
            }
            await ReadAndVerifyPostHandshakeAuthenticationAsync(
                reader,
                clientApplicationCipher,
                schedule,
                transcript,
                requestContext,
                cancellationToken).ConfigureAwait(false);
            if (_repeatPostHandshakeContext)
            {
                await WriteProtectedAsync(
                    writer,
                    serverApplicationCipher,
                    TlsContentType.Handshake,
                    postHandshakeRequest,
                    cancellationToken).ConfigureAwait(false);
                await ReadExpectedPostHandshakeAlertAsync(
                    reader,
                    clientApplicationCipher,
                    TlsAlertDescription.IllegalParameter,
                    cancellationToken).ConfigureAwait(false);
                PostHandshakeRequestWasRejected = true;
                return;
            }
            await WriteProtectedAsync(
                writer,
                serverApplicationCipher,
                TlsContentType.ApplicationData,
                "pong"u8.ToArray(),
                cancellationToken).ConfigureAwait(false);
            return;
        }

        var request = await ReadProtectedContentAsync(
            reader,
            clientApplicationCipher,
            expectedLength: _expectedApplicationRequest.Length,
            cancellationToken).ConfigureAwait(false);
        if (!request.AsSpan().SequenceEqual(_expectedApplicationRequest))
        {
            throw new InvalidDataException("The client application request was incorrect.");
        }

        if (_violateClientRecordSizeLimitAfterHandshake)
        {
            await WriteProtectedAsync(
                writer,
                serverApplicationCipher,
                TlsContentType.ApplicationData,
                _applicationResponse,
                cancellationToken).ConfigureAwait(false);
        }
        else
        {
            await WriteProtectedFragmentsAsync(
                writer,
                serverApplicationCipher,
                TlsContentType.ApplicationData,
                _applicationResponse,
                parsed.RecordSizeLimit,
                cancellationToken).ConfigureAwait(false);
        }
    }

    private async ValueTask ReadAndVerifyClientAuthenticationAsync(
        TlsRecordReader reader,
        Tls13RecordCipher cipher,
        Tls13KeySchedule schedule,
        TranscriptHash transcript,
        bool expectCertificateAuthentication,
        bool expectEndOfEarlyData,
        CancellationToken cancellationToken)
    {
        var deframer = new HandshakeDeframer(256 * 1024);
        X509Certificate2? clientLeaf = null;
        var state = expectEndOfEarlyData
            ? -2
            : _applicationSettingsCodePoint.HasValue
            ? -1
            : expectCertificateAuthentication ? 0 : 2;
        try
        {
            while (true)
            {
                var record = await reader.ReadAsync(cancellationToken).ConfigureAwait(false) ??
                    throw new EndOfStreamException("The client closed before its authentication block.");
                if (record.ContentType == TlsContentType.ChangeCipherSpec)
                {
                    if (!record.Fragment.AsSpan().SequenceEqual(new byte[] { 1 }))
                    {
                        throw new InvalidDataException("Malformed compatibility CCS.");
                    }
                    continue;
                }
                if (record.ContentType != TlsContentType.ApplicationData)
                {
                    throw new InvalidDataException("Expected a protected client handshake record.");
                }

                var inner = cipher.Decrypt(record.Fragment);
                ValidateClientProtectedPlaintext(inner.EncodedLength);
                if (inner.ContentType != TlsContentType.Handshake || inner.Content.Length == 0)
                {
                    throw new InvalidDataException(
                        $"Expected protected client handshake content in state {state}, got {inner.ContentType} ({Convert.ToHexString(inner.Content)}).");
                }
                deframer.Append(inner.Content);
                while (deframer.TryRead(out var message))
                {
                    switch (state, message!.Type)
                    {
                        case (-2, HandshakeType.EndOfEarlyData):
                            if (message.Body.Length != 0)
                            {
                                throw new InvalidDataException(
                                    "EndOfEarlyData contained a non-empty body.");
                            }
                            transcript.Append(message.Encoded);
                            state = _applicationSettingsCodePoint.HasValue
                                ? -1
                                : expectCertificateAuthentication ? 0 : 2;
                            break;

                        case (-1, HandshakeType.EncryptedExtensions):
                            ParseAndValidateClientApplicationSettings(message.Body);
                            transcript.Append(message.Encoded);
                            ClientApplicationSettingsVerified = true;
                            state = expectCertificateAuthentication ? 0 : 2;
                            break;

                        case (0, HandshakeType.Certificate):
                            clientLeaf = ParseAndValidateClientCertificate(
                                message.Body,
                                expectedContext: [],
                                allowEmpty: _expectEmptyInitialCertificate);
                            if (_expectEmptyInitialCertificate && clientLeaf is not null)
                            {
                                throw new InvalidDataException(
                                    "ECH rejection sent a non-empty client Certificate.");
                            }
                            transcript.Append(message.Encoded);
                            state = clientLeaf is null ? 2 : 1;
                            break;

                        case (1, HandshakeType.CertificateVerify):
                            VerifyClientCertificateVerify(
                                message.Body,
                                clientLeaf,
                                transcript.CurrentHash());
                            transcript.Append(message.Encoded);
                            state = 2;
                            ClientCertificateVerified = true;
                            break;

                        case (2, HandshakeType.Finished):
                            var transcriptHash = transcript.CurrentHash();
                            var expected = schedule.ComputeClientFinished(transcriptHash);
                            try
                            {
                                if (!CryptographicOperations.FixedTimeEquals(expected, message.Body))
                                {
                                    throw new CryptographicException("The client Finished was invalid.");
                                }
                            }
                            finally
                            {
                                CryptographicOperations.ZeroMemory(transcriptHash);
                                CryptographicOperations.ZeroMemory(expected);
                            }
                            if (deframer.BufferedBytes != 0)
                            {
                                throw new InvalidDataException("Data followed the client Finished.");
                            }
                            transcript.Append(message.Encoded);
                            return;

                        default:
                            throw new InvalidDataException(
                                $"Unexpected client authentication message {message.Type} in state {state}.");
                    }
                }
            }
        }
        finally
        {
            clientLeaf?.Dispose();
        }
    }

    private void ParseAndValidateClientApplicationSettings(ReadOnlySpan<byte> body)
    {
        var reader = new TlsBinaryReader(body);
        var extensions = new TlsBinaryReader(reader.ReadVector16());
        reader.EnsureEnd("test client EncryptedExtensions");
        var expectedType = (ushort)(_applicationSettingsCodePoint ??
            throw new InvalidOperationException("No application_settings code point was configured."));
        if (extensions.ReadUInt16() != expectedType ||
            !extensions.ReadVector16().SequenceEqual(_expectedClientApplicationSettings))
        {
            throw new InvalidDataException(
                "The client returned the wrong application_settings payload.");
        }
        extensions.EnsureEnd("test client application_settings extensions");
    }

    private static async ValueTask ReadExpectedPostHandshakeAlertAsync(
        TlsRecordReader reader,
        Tls13RecordCipher cipher,
        TlsAlertDescription expectedAlert,
        CancellationToken cancellationToken)
    {
        var record = await reader.ReadAsync(cancellationToken).ConfigureAwait(false) ??
            throw new EndOfStreamException("The client closed without a fatal alert.");
        if (record.ContentType != TlsContentType.ApplicationData)
        {
            throw new InvalidDataException("The client fatal alert was not protected.");
        }
        var inner = cipher.Decrypt(record.Fragment);
        if (inner.ContentType != TlsContentType.Alert ||
            !inner.Content.AsSpan().SequenceEqual(new byte[] { 2, (byte)expectedAlert }))
        {
            throw new InvalidDataException("The client sent the wrong post-handshake alert.");
        }
    }

    private async ValueTask ReadAndVerifyPostHandshakeAuthenticationAsync(
        TlsRecordReader reader,
        Tls13RecordCipher cipher,
        Tls13KeySchedule schedule,
        TranscriptHash transcript,
        ReadOnlyMemory<byte> expectedContext,
        CancellationToken cancellationToken)
    {
        var deframer = new HandshakeDeframer(256 * 1024);
        X509Certificate2? clientLeaf = null;
        var state = 0;
        try
        {
            while (true)
            {
                var record = await reader.ReadAsync(cancellationToken).ConfigureAwait(false) ??
                    throw new EndOfStreamException("The client closed during post-handshake auth.");
                if (record.ContentType != TlsContentType.ApplicationData)
                {
                    throw new InvalidDataException("Expected a protected post-handshake response.");
                }
                var inner = cipher.Decrypt(record.Fragment);
                ValidateClientProtectedPlaintext(inner.EncodedLength);
                if (inner.ContentType != TlsContentType.Handshake || inner.Content.Length == 0)
                {
                    throw new InvalidDataException(
                        "Application data interleaved the post-handshake authentication response.");
                }
                deframer.Append(inner.Content);
                while (deframer.TryRead(out var message))
                {
                    switch (state, message!.Type)
                    {
                        case (0, HandshakeType.Certificate):
                            clientLeaf = ParseAndValidateClientCertificate(
                                message.Body,
                                expectedContext.Span,
                                allowEmpty: _expectEmptyPostHandshakeCertificate);
                            transcript.Append(message.Encoded);
                            state = clientLeaf is null ? 2 : 1;
                            break;

                        case (1, HandshakeType.CertificateVerify):
                            VerifyClientCertificateVerify(
                                message.Body,
                                clientLeaf,
                                transcript.CurrentHash());
                            transcript.Append(message.Encoded);
                            state = 2;
                            break;

                        case (2, HandshakeType.Finished):
                            var transcriptHash = transcript.CurrentHash();
                            var expected = schedule.ComputeClientApplicationFinished(
                                transcriptHash);
                            try
                            {
                                if (!CryptographicOperations.FixedTimeEquals(expected, message.Body))
                                {
                                    throw new CryptographicException(
                                        "The post-handshake Finished was invalid.");
                                }
                            }
                            finally
                            {
                                CryptographicOperations.ZeroMemory(transcriptHash);
                                CryptographicOperations.ZeroMemory(expected);
                            }
                            if (deframer.BufferedBytes != 0)
                            {
                                throw new InvalidDataException(
                                    "Data followed the post-handshake Finished.");
                            }
                            transcript.Append(message.Encoded);
                            return;

                        default:
                            throw new InvalidDataException(
                                $"Unexpected post-handshake response {message.Type} in state {state}.");
                    }
                }
            }
        }
        finally
        {
            clientLeaf?.Dispose();
        }
    }

    private X509Certificate2? ParseAndValidateClientCertificate(
        ReadOnlySpan<byte> body,
        ReadOnlySpan<byte> expectedContext,
        bool allowEmpty)
    {
        var reader = new TlsBinaryReader(body);
        if (!reader.ReadVector8().SequenceEqual(expectedContext))
        {
            throw new InvalidDataException("The client Certificate context was incorrect.");
        }
        var entries = new TlsBinaryReader(reader.ReadVector24());
        reader.EnsureEnd("test client Certificate");
        if (entries.End)
        {
            return allowEmpty
                ? null
                : throw new InvalidDataException("The client sent an empty Certificate response.");
        }

        var leafDer = entries.ReadVector24().ToArray();
        var leafExtensions = entries.ReadVector16();
        if (!leafDer.AsSpan().SequenceEqual(_expectedClientLeaf))
        {
            throw new CryptographicException("The client sent the wrong leaf certificate.");
        }
        _clientDelegatedCredentialKey?.Dispose();
        _clientDelegatedCredentialKey = ParseClientDelegatedCredential(
            leafDer,
            leafExtensions);
        while (!entries.End)
        {
            _ = entries.ReadVector24();
            if (!entries.ReadVector16().IsEmpty)
            {
                throw new InvalidDataException("The client sent unexpected Certificate extensions.");
            }
        }

        return X509CertificateLoader.LoadCertificate(leafDer);
    }

    private ECDsa? ParseClientDelegatedCredential(
        ReadOnlySpan<byte> leafDer,
        ReadOnlySpan<byte> encodedExtensions)
    {
        var extensions = new TlsBinaryReader(encodedExtensions);
        byte[]? encodedCredential = null;
        var seen = new HashSet<ushort>();
        while (!extensions.End)
        {
            var type = extensions.ReadUInt16();
            var data = extensions.ReadVector16();
            if (!seen.Add(type))
            {
                throw new InvalidDataException(
                    "The client sent a duplicate Certificate extension.");
            }
            if (type != (ushort)TlsExtensionType.DelegatedCredential)
            {
                throw new InvalidDataException(
                    "The client sent an unexpected Certificate extension.");
            }
            encodedCredential = data.ToArray();
        }

        if (encodedCredential is null)
        {
            return null;
        }
        if (!_requestClientDelegatedCredential)
        {
            throw new InvalidDataException(
                "The client sent an unrequested delegated credential.");
        }

        var reader = new TlsBinaryReader(encodedCredential);
        var validTime = reader.ReadUInt32();
        if (reader.ReadUInt16() !=
            (ushort)SignatureScheme.EcdsaSecp256r1Sha256)
        {
            throw new InvalidDataException(
                "The client delegated credential selected the wrong delegated-key algorithm.");
        }
        var subjectPublicKeyInfo = reader.ReadVector24().ToArray();
        if (subjectPublicKeyInfo.Length == 0 ||
            reader.ReadUInt16() != (ushort)SignatureScheme.RsaPssRsaeSha256)
        {
            throw new InvalidDataException(
                "The client delegated credential selected the wrong delegation algorithm.");
        }
        var signedFieldsLength = encodedCredential.Length - reader.Remaining;
        var signature = reader.ReadVector16().ToArray();
        reader.EnsureEnd("test client delegated credential");
        if (signature.Length == 0)
        {
            throw new InvalidDataException(
                "The client delegated credential signature was empty.");
        }

        using var leaf = X509CertificateLoader.LoadCertificate(leafDer);
        Tls13DelegatedCredentialParser.ValidateDelegationCertificate(leaf);
        var notBefore = new DateTimeOffset(leaf.NotBefore.ToUniversalTime());
        var notAfter = new DateTimeOffset(leaf.NotAfter.ToUniversalTime());
        var expiresAt = notBefore.AddSeconds(validTime);
        var now = DateTimeOffset.UtcNow;
        if (now > expiresAt || expiresAt > now.AddDays(7) || expiresAt >= notAfter)
        {
            throw new CryptographicException(
                "The client delegated credential lifetime was invalid.");
        }

        var signedContent = Tls13DelegatedCredentialParser.BuildClientSignedContent(
            leafDer,
            encodedCredential.AsSpan(0, signedFieldsLength));
        try
        {
            if (!Tls13DelegatedCredentialParser.VerifyDelegationSignature(
                leaf,
                SignatureScheme.RsaPssRsaeSha256,
                signedContent,
                signature))
            {
                throw new CryptographicException(
                    "The client delegated credential signature was invalid.");
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(signedContent);
            CryptographicOperations.ZeroMemory(signature);
        }

        var key = ECDsa.Create();
        try
        {
            key.ImportSubjectPublicKeyInfo(subjectPublicKeyInfo, out var bytesRead);
            if (bytesRead != subjectPublicKeyInfo.Length || key.KeySize != 256)
            {
                throw new CryptographicException(
                    "The client delegated credential public key was invalid.");
            }
            return key;
        }
        catch
        {
            key.Dispose();
            throw;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(subjectPublicKeyInfo);
            CryptographicOperations.ZeroMemory(encodedCredential);
        }
    }

    private void VerifyClientCertificateVerify(
        ReadOnlySpan<byte> body,
        X509Certificate2? clientLeaf,
        ReadOnlySpan<byte> transcriptHash)
    {
        if (clientLeaf is null)
        {
            throw new InvalidDataException("Client CertificateVerify preceded Certificate.");
        }
        var reader = new TlsBinaryReader(body);
        var scheme = reader.ReadUInt16();
        var expectedScheme = _clientDelegatedCredentialKey is null
            ? SignatureScheme.RsaPssRsaeSha256
            : SignatureScheme.EcdsaSecp256r1Sha256;
        if (scheme != (ushort)expectedScheme)
        {
            throw new InvalidDataException("The client selected an unexpected signature scheme.");
        }
        var signature = reader.ReadVector16();
        reader.EnsureEnd("test client CertificateVerify");
        var content = ClientAuthenticationMessages.BuildTls13ClientCertificateVerifyContent(
            transcriptHash);
        bool verified;
        if (_clientDelegatedCredentialKey is not null)
        {
            verified = _clientDelegatedCredentialKey.VerifyData(
                content,
                signature,
                HashAlgorithmName.SHA256,
                DSASignatureFormat.Rfc3279DerSequence);
            _clientDelegatedCredentialKey.Dispose();
            _clientDelegatedCredentialKey = null;
            ClientDelegatedCredentialVerified = verified;
        }
        else
        {
            using var publicKey = clientLeaf.GetRSAPublicKey();
            verified = publicKey?.VerifyData(
                content,
                signature,
                HashAlgorithmName.SHA256,
                RSASignaturePadding.Pss) == true;
        }
        if (!verified)
        {
            throw new CryptographicException("The client CertificateVerify was invalid.");
        }
    }

    private byte[] BuildServerCertificateVerify(ReadOnlySpan<byte> transcriptHash)
    {
        var content = ServerCertificateValidator.BuildCertificateVerifyContent(transcriptHash);
        var serverHash = TlsClientCertificate.GetHashAlgorithm(_serverSignatureScheme);
        var signature = _serverDelegatedCredentialKey is null &&
                _serverRsaDelegatedCredentialKey is null
            ? _serverKey.SignData(
                content,
                serverHash,
                RSASignaturePadding.Pss)
            : _serverDelegatedCredentialKey is not null
                ? _serverDelegatedCredentialKey.SignData(
                content,
                HashAlgorithmName.SHA256,
                DSASignatureFormat.Rfc3279DerSequence)
                : _serverRsaDelegatedCredentialKey!.SignData(
                    content,
                    HashAlgorithmName.SHA256,
                    RSASignaturePadding.Pss);
        try
        {
            var body = new TlsBinaryWriter();
            body.WriteUInt16((ushort)(_serverDelegatedCredentialKey is not null
                ? SignatureScheme.EcdsaSecp256r1Sha256
                : _serverRsaDelegatedCredentialKey is not null
                    ? SignatureScheme.RsaPssPssSha256
                    : _serverSignatureScheme));
            body.WriteVector16(signature);
            return HandshakeMessage.Encode(HandshakeType.CertificateVerify, body.WrittenSpan);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(content);
            CryptographicOperations.ZeroMemory(signature);
        }
    }

    private byte[] BuildCertificate(byte[]? delegatedCredential)
    {
        var entries = new TlsBinaryWriter();
        entries.WriteVector24(_serverLeaf.RawData);
        var leafExtensions = new TlsBinaryWriter();
        if (delegatedCredential is not null)
        {
            leafExtensions.WriteUInt16((ushort)TlsExtensionType.DelegatedCredential);
            leafExtensions.WriteVector16(delegatedCredential);
        }
        if (_serverOcspResponse is not null)
        {
            var status = new TlsBinaryWriter();
            status.WriteUInt8(1);
            status.WriteVector24(_serverOcspResponse);
            leafExtensions.WriteUInt16((ushort)TlsExtensionType.StatusRequest);
            leafExtensions.WriteVector16(status.WrittenSpan);
        }
        if (_serverSignedCertificateTimestamps.Length != 0)
        {
            var list = new TlsBinaryWriter();
            foreach (var sct in _serverSignedCertificateTimestamps)
            {
                list.WriteVector16(sct);
            }
            var encodedList = new TlsBinaryWriter();
            encodedList.WriteVector16(list.WrittenSpan);
            leafExtensions.WriteUInt16(
                (ushort)TlsExtensionType.SignedCertificateTimestamp);
            leafExtensions.WriteVector16(encodedList.WrittenSpan);
        }
        entries.WriteVector16(leafExtensions.WrittenSpan);
        entries.WriteVector24(_serverIssuer.RawData);
        entries.WriteVector16([]);
        var body = new TlsBinaryWriter();
        body.WriteVector8([]);
        body.WriteVector24(entries.WrittenSpan);
        return HandshakeMessage.Encode(HandshakeType.Certificate, body.WrittenSpan);
    }

    private byte[] BuildDelegatedCredential()
    {
        var notBefore = new DateTimeOffset(_serverLeaf.NotBefore.ToUniversalTime());
        var expiry = DateTimeOffset.UtcNow.AddDays(1);
        var validTime = checked((uint)Math.Ceiling((expiry - notBefore).TotalSeconds));
        var unsigned = new TlsBinaryWriter();
        unsigned.WriteUInt32(validTime);
        var credentialScheme = _serverDelegatedCredentialKey is not null
            ? SignatureScheme.EcdsaSecp256r1Sha256
            : SignatureScheme.RsaPssPssSha256;
        var subjectPublicKeyInfo = _serverDelegatedCredentialKey is not null
            ? _serverDelegatedCredentialKey.ExportSubjectPublicKeyInfo()
            : _serverRsaDelegatedCredentialSpki!;
        unsigned.WriteUInt16((ushort)credentialScheme);
        unsigned.WriteVector24(subjectPublicKeyInfo);
        unsigned.WriteUInt16((ushort)SignatureScheme.RsaPssRsaeSha256);
        var signedContent = Tls13DelegatedCredentialParser.BuildSignedContent(
            _serverLeaf.RawData,
            unsigned.WrittenSpan);
        var signature = _serverKey.SignData(
            signedContent,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pss);
        if (_tamperDelegatedCredential)
        {
            signature[^1] ^= 1;
        }
        try
        {
            var encoded = new TlsBinaryWriter();
            encoded.WriteBytes(unsigned.WrittenSpan);
            encoded.WriteVector16(signature);
            return encoded.ToArray();
        }
        finally
        {
            CryptographicOperations.ZeroMemory(signedContent);
            CryptographicOperations.ZeroMemory(signature);
        }
    }

    private static byte[] BuildCertificateRequest(
        ReadOnlySpan<byte> requestContext,
        SignatureScheme signatureScheme,
        bool requestClientDelegatedCredential)
    {
        var algorithms = new TlsBinaryWriter();
        algorithms.WriteUInt16((ushort)signatureScheme);
        var algorithmList = new TlsBinaryWriter();
        algorithmList.WriteVector16(algorithms.WrittenSpan);
        var extensions = new TlsBinaryWriter();
        extensions.WriteUInt16((ushort)TlsExtensionType.SignatureAlgorithms);
        extensions.WriteVector16(algorithmList.WrittenSpan);
        if (requestClientDelegatedCredential)
        {
            var delegatedAlgorithms = new TlsBinaryWriter();
            delegatedAlgorithms.WriteUInt16(
                (ushort)SignatureScheme.EcdsaSecp256r1Sha256);
            var delegatedAlgorithmList = new TlsBinaryWriter();
            delegatedAlgorithmList.WriteVector16(delegatedAlgorithms.WrittenSpan);
            extensions.WriteUInt16((ushort)TlsExtensionType.DelegatedCredential);
            extensions.WriteVector16(delegatedAlgorithmList.WrittenSpan);
        }
        var body = new TlsBinaryWriter();
        body.WriteVector8(requestContext);
        body.WriteVector16(extensions.WrittenSpan);
        return HandshakeMessage.Encode(HandshakeType.CertificateRequest, body.WrittenSpan);
    }

    private static byte[] BuildEncryptedExtensions(
        int? recordSizeLimit,
        TlsApplicationSettingsCodePoint? applicationSettingsCodePoint,
        string applicationSettingsProtocol,
        ReadOnlySpan<byte> serverApplicationSettings,
        byte[]? echRetryConfigurations,
        bool acceptEarlyData)
    {
        var extensions = new TlsBinaryWriter();
        if (acceptEarlyData)
        {
            extensions.WriteUInt16((ushort)TlsExtensionType.EarlyData);
            extensions.WriteVector16([]);
        }
        if (applicationSettingsCodePoint.HasValue)
        {
            extensions.WriteUInt16((ushort)applicationSettingsCodePoint.Value);
            extensions.WriteVector16(serverApplicationSettings);

            var protocols = new TlsBinaryWriter();
            protocols.WriteVector8(System.Text.Encoding.ASCII.GetBytes(
                applicationSettingsProtocol));
            var alpn = new TlsBinaryWriter();
            alpn.WriteVector16(protocols.WrittenSpan);
            extensions.WriteUInt16((ushort)TlsExtensionType.ApplicationLayerProtocolNegotiation);
            extensions.WriteVector16(alpn.WrittenSpan);
        }
        if (recordSizeLimit.HasValue)
        {
            var data = new TlsBinaryWriter(2);
            data.WriteUInt16(checked((ushort)recordSizeLimit.Value));
            extensions.WriteUInt16((ushort)TlsExtensionType.RecordSizeLimit);
            extensions.WriteVector16(data.WrittenSpan);
        }
        if (echRetryConfigurations is not null)
        {
            extensions.WriteUInt16((ushort)TlsExtensionType.EncryptedClientHello);
            extensions.WriteVector16(echRetryConfigurations);
        }
        var body = new TlsBinaryWriter();
        body.WriteVector16(extensions.WrittenSpan);
        return HandshakeMessage.Encode(HandshakeType.EncryptedExtensions, body.WrittenSpan);
    }

    private static byte[] BuildNewSessionTicket(
        ReadOnlySpan<byte> identity,
        ReadOnlySpan<byte> nonce,
        uint? maximumEarlyDataSize)
    {
        var extensions = new TlsBinaryWriter();
        if (maximumEarlyDataSize.HasValue)
        {
            var earlyData = new TlsBinaryWriter(sizeof(uint));
            earlyData.WriteUInt32(maximumEarlyDataSize.Value);
            extensions.WriteUInt16((ushort)TlsExtensionType.EarlyData);
            extensions.WriteVector16(earlyData.WrittenSpan);
        }
        var body = new TlsBinaryWriter();
        body.WriteUInt32(3600);
        body.WriteUInt32(0xA1B2C3D4);
        body.WriteVector8(nonce);
        body.WriteVector16(identity);
        body.WriteVector16(extensions.WrittenSpan);
        return HandshakeMessage.Encode(HandshakeType.NewSessionTicket, body.WrittenSpan);
    }

    private static Tls13RecordCipher CreateEarlyDataCipher(
        Tls13KeySchedule schedule,
        ReadOnlySpan<byte> clientHello,
        bool offeredEarlyData)
    {
        if (!offeredEarlyData)
        {
            throw new InvalidDataException(
                "ClientHelloInner omitted early_data for the expected early payload.");
        }
        var clientHelloHash = SHA256.HashData(clientHello);
        try
        {
            schedule.DeriveClientEarlyTrafficSecret(clientHelloHash);
            return CreateCipher(schedule.TakeClientEarlyTrafficKeys());
        }
        finally
        {
            CryptographicOperations.ZeroMemory(clientHelloHash);
        }
    }

    private static byte[] BuildServerHello(
        ReadOnlySpan<byte> sessionId,
        NamedGroup group,
        ReadOnlySpan<byte> serverKeyExchange,
        bool selectPsk = false)
    {
        var extensions = new TlsBinaryWriter();
        var version = new TlsBinaryWriter();
        version.WriteUInt16(TlsConstants.Tls13Version);
        extensions.WriteUInt16((ushort)TlsExtensionType.SupportedVersions);
        extensions.WriteVector16(version.WrittenSpan);
        var keyShare = new TlsBinaryWriter();
        keyShare.WriteUInt16((ushort)group);
        keyShare.WriteVector16(serverKeyExchange);
        extensions.WriteUInt16((ushort)TlsExtensionType.KeyShare);
        extensions.WriteVector16(keyShare.WrittenSpan);
        if (selectPsk)
        {
            extensions.WriteUInt16((ushort)TlsExtensionType.PreSharedKey);
            extensions.WriteVector16([0, 0]);
        }
        var body = new TlsBinaryWriter();
        body.WriteUInt16(TlsConstants.LegacyRecordVersion);
        body.WriteBytes(RandomNumberGenerator.GetBytes(TlsConstants.RandomLength));
        body.WriteVector8(sessionId);
        body.WriteUInt16((ushort)Suite.Suite);
        body.WriteUInt8(0);
        body.WriteVector16(extensions.WrittenSpan);
        return HandshakeMessage.Encode(HandshakeType.ServerHello, body.WrittenSpan);
    }

    private static byte[] BuildHelloRetryRequest(
        ReadOnlySpan<byte> sessionId,
        NamedGroup selectedGroup,
        bool includeEchConfirmation)
    {
        ReadOnlySpan<byte> retryRandom =
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
        keyShare.WriteUInt16((ushort)selectedGroup);
        extensions.WriteUInt16((ushort)TlsExtensionType.KeyShare);
        extensions.WriteVector16(keyShare.WrittenSpan);
        if (includeEchConfirmation)
        {
            extensions.WriteUInt16((ushort)TlsExtensionType.EncryptedClientHello);
            extensions.WriteVector16(new byte[EchAcceptanceConfirmation.ConfirmationLength]);
        }

        var body = new TlsBinaryWriter();
        body.WriteUInt16(TlsConstants.LegacyRecordVersion);
        body.WriteBytes(retryRandom);
        body.WriteVector8(sessionId);
        body.WriteUInt16((ushort)Suite.Suite);
        body.WriteUInt8(0);
        body.WriteVector16(extensions.WrittenSpan);
        return HandshakeMessage.Encode(HandshakeType.ServerHello, body.WrittenSpan);
    }

    private static byte[] ReconstructClientHelloInner(
        ReadOnlySpan<byte> encodedInner,
        ReadOnlySpan<byte> encodedOuter)
    {
        var outerSessionId = ReadClientHelloIdentity(encodedOuter).SessionId;
        const int sessionIdLengthOffset = 2 + TlsConstants.RandomLength;
        if (encodedInner.Length <= sessionIdLengthOffset ||
            encodedInner[sessionIdLengthOffset] != 0)
        {
            throw new InvalidDataException(
                "EncodedClientHelloInner has a non-empty legacy session ID.");
        }

        var actualLength = FindEncodedClientHelloInnerLength(encodedInner);
        if (encodedInner[actualLength..].IndexOfAnyExcept((byte)0) >= 0)
        {
            throw new InvalidDataException("EncodedClientHelloInner padding is non-zero.");
        }
        var body = new TlsBinaryWriter(actualLength + outerSessionId.Length);
        body.WriteBytes(encodedInner[..sessionIdLengthOffset]);
        body.WriteVector8(outerSessionId);
        body.WriteBytes(encodedInner[(sessionIdLengthOffset + 1)..actualLength]);
        var reconstructed = HandshakeMessage.Encode(
            HandshakeType.ClientHello,
            body.WrittenSpan);
        return ExpandOuterExtensions(reconstructed, encodedOuter);
    }

    private static byte[] ExpandOuterExtensions(
        ReadOnlySpan<byte> encodedInner,
        ReadOnlySpan<byte> encodedOuter)
    {
        var inner = ParseWireClientHello(encodedInner);
        var markerIndex = Array.FindIndex(
            inner.Extensions,
            extension => extension.Type == (ushort)TlsExtensionType.EchOuterExtensions);
        if (markerIndex < 0)
        {
            return encodedInner.ToArray();
        }
        if (Array.FindLastIndex(
            inner.Extensions,
            extension => extension.Type == (ushort)TlsExtensionType.EchOuterExtensions) !=
            markerIndex)
        {
            throw new InvalidDataException(
                "EncodedClientHelloInner contains duplicate ech_outer_extensions.");
        }

        var references = new TlsBinaryReader(inner.Extensions[markerIndex].Data);
        var encodedTypes = references.ReadVector8(254);
        references.EnsureEnd("test ech_outer_extensions");
        if (encodedTypes.Length < 2 || (encodedTypes.Length & 1) != 0)
        {
            throw new InvalidDataException("ech_outer_extensions has an invalid length.");
        }
        var typeReader = new TlsBinaryReader(encodedTypes);
        var types = new List<ushort>();
        var seen = new HashSet<ushort>();
        while (!typeReader.End)
        {
            var type = typeReader.ReadUInt16();
            if (type is (ushort)TlsExtensionType.EncryptedClientHello or
                (ushort)TlsExtensionType.EchOuterExtensions || !seen.Add(type))
            {
                throw new InvalidDataException(
                    "ech_outer_extensions contains a duplicate or forbidden type.");
            }
            types.Add(type);
        }

        var outer = ParseWireClientHello(encodedOuter);
        var replacements = new List<TestWireExtension>(types.Count);
        var outerIndex = 0;
        foreach (var type in types)
        {
            while (outerIndex < outer.Extensions.Length &&
                outer.Extensions[outerIndex].Type != type)
            {
                outerIndex++;
            }
            if (outerIndex == outer.Extensions.Length)
            {
                throw new InvalidDataException(
                    "ech_outer_extensions referenced a missing or out-of-order outer extension.");
            }
            replacements.Add(outer.Extensions[outerIndex++]);
        }

        var encodedExtensions = new TlsBinaryWriter();
        for (var index = 0; index < inner.Extensions.Length; index++)
        {
            if (index == markerIndex)
            {
                foreach (var replacement in replacements)
                {
                    encodedExtensions.WriteUInt16(replacement.Type);
                    encodedExtensions.WriteVector16(replacement.Data);
                }
                continue;
            }
            encodedExtensions.WriteUInt16(inner.Extensions[index].Type);
            encodedExtensions.WriteVector16(inner.Extensions[index].Data);
        }
        var expandedBody = new TlsBinaryWriter(
            inner.BodyPrefix.Length + encodedExtensions.Length + 2);
        expandedBody.WriteBytes(inner.BodyPrefix);
        expandedBody.WriteVector16(encodedExtensions.WrittenSpan);
        return HandshakeMessage.Encode(HandshakeType.ClientHello, expandedBody.WrittenSpan);
    }

    private static TestWireClientHello ParseWireClientHello(ReadOnlySpan<byte> encoded)
    {
        var body = encoded[TlsConstants.HandshakeHeaderLength..];
        var offset = 2 + TlsConstants.RandomLength;
        offset = SkipVector8(body, offset);
        offset = SkipVector16(body, offset);
        offset = SkipVector8(body, offset);
        EnsureAvailable(body, offset, 2);
        var extensionsLength = BinaryPrimitives.ReadUInt16BigEndian(body[offset..]);
        var extensionsOffset = offset + 2;
        EnsureAvailable(body, extensionsOffset, extensionsLength);
        if (extensionsOffset + extensionsLength != body.Length)
        {
            throw new InvalidDataException("ClientHello extension vector is malformed.");
        }

        var reader = new TlsBinaryReader(body.Slice(extensionsOffset, extensionsLength));
        var extensions = new List<TestWireExtension>();
        var seen = new HashSet<ushort>();
        while (!reader.End)
        {
            var type = reader.ReadUInt16();
            if (!seen.Add(type))
            {
                throw new InvalidDataException("ClientHello contains duplicate extensions.");
            }
            extensions.Add(new TestWireExtension(type, reader.ReadVector16().ToArray()));
        }
        return new TestWireClientHello(body[..offset].ToArray(), extensions.ToArray());
    }

    private static void ValidateRetryIdentity(
        ReadOnlySpan<byte> first,
        ReadOnlySpan<byte> second,
        string name)
    {
        var firstIdentity = ReadClientHelloIdentity(first);
        var secondIdentity = ReadClientHelloIdentity(second);
        if (!firstIdentity.Random.AsSpan().SequenceEqual(secondIdentity.Random) ||
            !firstIdentity.SessionId.AsSpan().SequenceEqual(secondIdentity.SessionId))
        {
            throw new InvalidDataException(
                $"{name} retry changed its random or legacy session ID.");
        }
    }

    private static (byte[] Random, byte[] SessionId) ReadClientHelloIdentity(
        ReadOnlySpan<byte> encoded)
    {
        var body = new TlsBinaryReader(encoded[TlsConstants.HandshakeHeaderLength..]);
        _ = body.ReadUInt16();
        var random = body.ReadBytes(TlsConstants.RandomLength).ToArray();
        var sessionId = body.ReadVector8(TlsConstants.MaxSessionIdLength).ToArray();
        return (random, sessionId);
    }

    private static int FindEncodedClientHelloInnerLength(ReadOnlySpan<byte> encodedInner)
    {
        var offset = 2 + TlsConstants.RandomLength;
        EnsureAvailable(encodedInner, offset, 1);
        offset += 1 + encodedInner[offset];
        offset = SkipVector16(encodedInner, offset);
        offset = SkipVector8(encodedInner, offset);
        EnsureAvailable(encodedInner, offset, 2);
        var extensionsLength = BinaryPrimitives.ReadUInt16BigEndian(encodedInner[offset..]);
        offset += 2;
        EnsureAvailable(encodedInner, offset, extensionsLength);
        return offset + extensionsLength;
    }

    private static void ValidateClientHelloInner(ReadOnlySpan<byte> encoded)
    {
        var body = new TlsBinaryReader(encoded[TlsConstants.HandshakeHeaderLength..]);
        _ = body.ReadUInt16();
        _ = body.ReadBytes(TlsConstants.RandomLength);
        _ = body.ReadVector8(TlsConstants.MaxSessionIdLength);
        _ = body.ReadVector16();
        _ = body.ReadVector8();
        var extensions = new TlsBinaryReader(body.ReadVector16());
        body.EnsureEnd("test ClientHelloInner");
        var foundEch = false;
        var tls13Only = false;
        while (!extensions.End)
        {
            var type = extensions.ReadUInt16();
            var data = extensions.ReadVector16();
            if (type == (ushort)TlsExtensionType.EncryptedClientHello)
            {
                if (foundEch || !data.SequenceEqual([(byte)1]))
                {
                    throw new InvalidDataException(
                        "ClientHelloInner has an invalid ECH marker.");
                }
                foundEch = true;
            }
            else if (type == (ushort)TlsExtensionType.SupportedVersions)
            {
                var versionData = new TlsBinaryReader(data);
                var versions = new TlsBinaryReader(versionData.ReadVector8());
                versionData.EnsureEnd("test ClientHelloInner supported_versions");
                tls13Only = versions.Remaining == 2 &&
                    versions.ReadUInt16() == TlsConstants.Tls13Version;
                versions.EnsureEnd("test ClientHelloInner version list");
            }
        }
        if (!foundEch || !tls13Only)
        {
            throw new InvalidDataException(
                "ClientHelloInner did not contain ECH and TLS 1.3-only offers.");
        }
    }

    private static string? ReadServerName(ReadOnlySpan<byte> encoded)
    {
        var body = new TlsBinaryReader(encoded[TlsConstants.HandshakeHeaderLength..]);
        _ = body.ReadUInt16();
        _ = body.ReadBytes(TlsConstants.RandomLength);
        _ = body.ReadVector8(TlsConstants.MaxSessionIdLength);
        _ = body.ReadVector16();
        _ = body.ReadVector8();
        var extensions = new TlsBinaryReader(body.ReadVector16());
        body.EnsureEnd("test ClientHello SNI");
        while (!extensions.End)
        {
            var type = extensions.ReadUInt16();
            var data = extensions.ReadVector16();
            if (type != (ushort)TlsExtensionType.ServerName)
            {
                continue;
            }
            var nameData = new TlsBinaryReader(data);
            var names = new TlsBinaryReader(nameData.ReadVector16());
            nameData.EnsureEnd("test ClientHello SNI extension");
            if (names.ReadUInt8() != 0)
            {
                throw new InvalidDataException("ClientHello SNI type is invalid.");
            }
            var name = names.ReadVector16();
            names.EnsureEnd("test ClientHello SNI list");
            return System.Text.Encoding.ASCII.GetString(name);
        }
        return null;
    }

    private static int SkipVector8(ReadOnlySpan<byte> input, int offset)
    {
        EnsureAvailable(input, offset, 1);
        var length = input[offset];
        EnsureAvailable(input, offset + 1, length);
        return offset + 1 + length;
    }

    private static int SkipVector16(ReadOnlySpan<byte> input, int offset)
    {
        EnsureAvailable(input, offset, 2);
        var length = BinaryPrimitives.ReadUInt16BigEndian(input[offset..]);
        EnsureAvailable(input, offset + 2, length);
        return offset + 2 + length;
    }

    private static void EnsureAvailable(
        ReadOnlySpan<byte> input,
        int offset,
        int length)
    {
        if (offset < 0 || length < 0 || offset > input.Length - length)
        {
            throw new InvalidDataException("ECH ClientHello is truncated.");
        }
    }

    private static void Zero(byte[]? value)
    {
        if (value is not null)
        {
            CryptographicOperations.ZeroMemory(value);
        }
    }

    private sealed class ManagedEchReceiver : IDisposable
    {
        private readonly TlsEchConfig _configuration;
        private readonly byte[] _privateKey;
        private HpkeReceiverContext? _context;
        private TlsHpkeSymmetricCipherSuite? _selectedSuite;
        private bool _retryProcessed;
        private bool _disposed;

        internal ManagedEchReceiver(
            TlsEchConfig configuration,
            byte[] privateKey)
        {
            _configuration = configuration;
            _privateKey = privateKey;
        }

        internal HandshakeMessage Decrypt(HandshakeMessage outer, bool isRetry)
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            if (isRetry ? _context is null || _retryProcessed : _context is not null)
            {
                throw new InvalidDataException("ECH HPKE context was used in an illegal state.");
            }

            var aad = outer.Encoded.AsSpan(TlsConstants.HandshakeHeaderLength).ToArray();
            byte[]? encapsulatedKey = null;
            byte[]? ciphertext = null;
            byte[]? encodedInner = null;
            byte[]? info = null;
            try
            {
                var offset = 2 + TlsConstants.RandomLength;
                EnsureAvailable(aad, offset, 1);
                var outerSessionIdLength = aad[offset];
                EnsureAvailable(aad, offset + 1, outerSessionIdLength);
                offset += 1 + outerSessionIdLength;
                offset = SkipVector16(aad, offset);
                offset = SkipVector8(aad, offset);
                EnsureAvailable(aad, offset, 2);
                var extensionsLength = BinaryPrimitives.ReadUInt16BigEndian(aad.AsSpan(offset));
                offset += 2;
                EnsureAvailable(aad, offset, extensionsLength);
                var extensionsEnd = offset + extensionsLength;
                if (extensionsEnd != aad.Length)
                {
                    throw new InvalidDataException("ClientHelloOuter extension framing is invalid.");
                }

                var found = false;
                while (offset < extensionsEnd)
                {
                    EnsureAvailable(aad, offset, 4);
                    var type = BinaryPrimitives.ReadUInt16BigEndian(aad.AsSpan(offset));
                    var dataLength = BinaryPrimitives.ReadUInt16BigEndian(aad.AsSpan(offset + 2));
                    offset += 4;
                    EnsureAvailable(aad, offset, dataLength);
                    if (type != (ushort)TlsExtensionType.EncryptedClientHello)
                    {
                        offset += dataLength;
                        continue;
                    }
                    if (found)
                    {
                        throw new InvalidDataException(
                            "ClientHelloOuter contains duplicate ECH extensions.");
                    }
                    found = true;

                    var dataOffset = offset;
                    var data = new TlsBinaryReader(aad.AsSpan(dataOffset, dataLength));
                    if (data.ReadUInt8() != 0)
                    {
                        throw new InvalidDataException("ClientHelloOuter ECH marker is not outer.");
                    }
                    var suite = new TlsHpkeSymmetricCipherSuite(
                        (TlsHpkeKdfId)data.ReadUInt16(),
                        (TlsHpkeAeadId)data.ReadUInt16());
                    if (data.ReadUInt8() != _configuration.ConfigId ||
                        !_configuration.CipherSuites.Contains(suite) ||
                        isRetry && suite != _selectedSuite)
                    {
                        throw new InvalidDataException(
                            "ClientHelloOuter selected the wrong ECH configuration.");
                    }
                    encapsulatedKey = data.ReadVector16().ToArray();
                    ciphertext = data.ReadVector16().ToArray();
                    data.EnsureEnd("test ClientHelloOuter ECH");
                    if (isRetry ? encapsulatedKey.Length != 0 : encapsulatedKey.Length == 0)
                    {
                        throw new InvalidDataException(
                            "ClientHelloOuter used an invalid ECH encapsulated key for its flight.");
                    }

                    var payloadOffsetInData = 1 + 2 + 2 + 1 + 2 +
                        encapsulatedKey.Length + 2;
                    aad.AsSpan(dataOffset + payloadOffsetInData, ciphertext.Length).Clear();
                    if (!isRetry)
                    {
                        var encodedConfig = _configuration.GetEncodedConfig();
                        info = new byte[8 + encodedConfig.Length];
                        "tls ech"u8.CopyTo(info);
                        encodedConfig.CopyTo(info, 8);
                        CryptographicOperations.ZeroMemory(encodedConfig);
                        _context = HpkeReceiverContext.SetupBaseX25519(
                            suite,
                            _privateKey,
                            encapsulatedKey,
                            info);
                        _selectedSuite = suite;
                    }

                    encodedInner = _context!.Open(aad, ciphertext);
                    var reconstructed = ReconstructClientHelloInner(
                        encodedInner,
                        outer.Encoded);
                    ValidateClientHelloInner(reconstructed);
                    if (isRetry)
                    {
                        _retryProcessed = true;
                    }
                    return new HandshakeMessage(
                        HandshakeType.ClientHello,
                        reconstructed.AsSpan(TlsConstants.HandshakeHeaderLength).ToArray(),
                        reconstructed);
                }

                throw new InvalidDataException("ClientHelloOuter omitted ECH.");
            }
            finally
            {
                CryptographicOperations.ZeroMemory(aad);
                Zero(encapsulatedKey);
                Zero(ciphertext);
                Zero(encodedInner);
                Zero(info);
            }
        }

        public void Dispose()
        {
            if (_disposed)
            {
                return;
            }
            _disposed = true;
            _context?.Dispose();
            _context = null;
        }
    }

    private static ParsedClientHello ParseClientHello(
        ReadOnlySpan<byte> encoded,
        NamedGroup requiredGroup)
    {
        var body = new TlsBinaryReader(encoded[TlsConstants.HandshakeHeaderLength..]);
        _ = body.ReadUInt16();
        _ = body.ReadBytes(TlsConstants.RandomLength);
        var sessionId = body.ReadVector8().ToArray();
        _ = body.ReadVector16();
        _ = body.ReadVector8();
        var extensions = new TlsBinaryReader(body.ReadVector16());
        body.EnsureEnd("test ClientHello");
        byte[]? exchange = null;
        var offeredPostHandshakeAuthentication = false;
        int? recordSizeLimit = null;
        var offeredDelegatedCredentials = false;
        TlsApplicationSettingsCodePoint? applicationSettingsCodePoint = null;
        var applicationSettingsProtocols = Array.Empty<string>();
        var alpnProtocols = Array.Empty<string>();
        byte[]? pskIdentity = null;
        byte[]? pskBinder = null;
        var offeredEarlyData = false;
        while (!extensions.End)
        {
            var type = extensions.ReadUInt16();
            var data = extensions.ReadVector16();
            if (type == (ushort)TlsExtensionType.EarlyData)
            {
                if (!data.IsEmpty)
                {
                    throw new InvalidDataException("early_data was not empty.");
                }
                offeredEarlyData = true;
                continue;
            }
            if (type == (ushort)TlsExtensionType.PreSharedKey)
            {
                if (!extensions.End)
                {
                    throw new InvalidDataException(
                        "pre_shared_key was not the final ClientHello extension.");
                }
                var psk = new TlsBinaryReader(data);
                var identities = new TlsBinaryReader(psk.ReadVector16());
                pskIdentity = identities.ReadVector16().ToArray();
                _ = identities.ReadUInt32();
                identities.EnsureEnd("test PSK identities");
                var binders = new TlsBinaryReader(psk.ReadVector16());
                pskBinder = binders.ReadVector8().ToArray();
                binders.EnsureEnd("test PSK binders");
                psk.EnsureEnd("test pre_shared_key");
                continue;
            }
            if (type == (ushort)TlsExtensionType.PostHandshakeAuthentication)
            {
                if (!data.IsEmpty)
                {
                    throw new InvalidDataException("post_handshake_auth was not empty.");
                }
                offeredPostHandshakeAuthentication = true;
                continue;
            }
            if (type == (ushort)TlsExtensionType.RecordSizeLimit)
            {
                var limit = new TlsBinaryReader(data);
                recordSizeLimit = limit.ReadUInt16();
                limit.EnsureEnd("test record_size_limit");
                continue;
            }
            if (type == (ushort)TlsExtensionType.DelegatedCredential)
            {
                var delegated = new TlsBinaryReader(data);
                var algorithms = new TlsBinaryReader(delegated.ReadVector16());
                delegated.EnsureEnd("test delegated_credential");
                while (!algorithms.End)
                {
                    var algorithm = (SignatureScheme)algorithms.ReadUInt16();
                    if (algorithm is SignatureScheme.EcdsaSecp256r1Sha256 or
                        SignatureScheme.RsaPssPssSha256)
                    {
                        offeredDelegatedCredentials = true;
                    }
                }
                continue;
            }
            if (type == (ushort)TlsExtensionType.ApplicationLayerProtocolNegotiation)
            {
                alpnProtocols = ParseProtocolNameList(data);
                continue;
            }
            if (type is (ushort)TlsApplicationSettingsCodePoint.LegacyDraft or
                (ushort)TlsApplicationSettingsCodePoint.ChromeExperiment)
            {
                applicationSettingsCodePoint = (TlsApplicationSettingsCodePoint)type;
                applicationSettingsProtocols = ParseProtocolNameList(data);
                continue;
            }
            if (type != (ushort)TlsExtensionType.KeyShare)
            {
                continue;
            }

            var shares = new TlsBinaryReader(data);
            var entries = new TlsBinaryReader(shares.ReadVector16());
            shares.EnsureEnd("test key_share");
            while (!entries.End)
            {
                var group = entries.ReadUInt16();
                var candidate = entries.ReadVector16();
                if (group == (ushort)requiredGroup)
                {
                    exchange = candidate.ToArray();
                }
            }
        }

        return new ParsedClientHello(
            sessionId,
            exchange ?? throw new InvalidDataException(
                $"ClientHello omitted a {requiredGroup} key share."),
            offeredPostHandshakeAuthentication,
            recordSizeLimit,
            offeredDelegatedCredentials,
            applicationSettingsCodePoint,
            applicationSettingsProtocols,
            alpnProtocols,
            pskIdentity,
            pskBinder,
            offeredEarlyData);
    }

    private static void VerifyPskBinder(
        ReadOnlySpan<byte> encodedClientHello,
        ReadOnlySpan<byte> actualBinder,
        ReadOnlySpan<byte> psk,
        ReadOnlySpan<byte> transcriptPrefix = default)
    {
        var encodedBindersLength = 2 + 1 + actualBinder.Length;
        if (encodedClientHello.Length <= encodedBindersLength)
        {
            throw new InvalidDataException("ClientHello PSK binder prefix is truncated.");
        }
        byte[] binderHash;
        using (var transcript = IncrementalHash.CreateHash(HashAlgorithmName.SHA256))
        {
            if (!transcriptPrefix.IsEmpty)
            {
                transcript.AppendData(transcriptPrefix);
            }
            transcript.AppendData(encodedClientHello[..^encodedBindersLength]);
            binderHash = transcript.GetHashAndReset();
        }
        try
        {
            using var schedule = new Tls13KeySchedule(Suite, psk);
            var expected = schedule.ComputeResumptionBinder(binderHash);
            try
            {
                if (!CryptographicOperations.FixedTimeEquals(expected, actualBinder))
                {
                    throw new CryptographicException(
                        "ClientHelloInner resumption binder did not authenticate.");
                }
            }
            finally
            {
                CryptographicOperations.ZeroMemory(expected);
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(binderHash);
        }
    }

    private static string[] ParseProtocolNameList(ReadOnlySpan<byte> data)
    {
        var reader = new TlsBinaryReader(data);
        var protocols = new TlsBinaryReader(reader.ReadVector16());
        reader.EnsureEnd("test protocol-name list");
        var result = new List<string>();
        while (!protocols.End)
        {
            var value = protocols.ReadVector8(TlsConstants.MaxAlpnProtocolLength);
            if (value.IsEmpty || value.IndexOfAnyInRange((byte)0x80, byte.MaxValue) >= 0)
            {
                throw new InvalidDataException("A protocol-name list entry was invalid.");
            }
            result.Add(System.Text.Encoding.ASCII.GetString(value));
        }
        return result.ToArray();
    }

    private static async ValueTask<HandshakeMessage> ReadClientHelloAsync(
        TlsRecordReader reader,
        CancellationToken cancellationToken,
        bool allowCompatibilityCcs = false)
    {
        var deframer = new HandshakeDeframer(64 * 1024);
        while (true)
        {
            var record = await reader.ReadAsync(cancellationToken).ConfigureAwait(false) ??
                throw new EndOfStreamException("The client closed before ClientHello.");
            if (allowCompatibilityCcs && record.ContentType == TlsContentType.ChangeCipherSpec)
            {
                if (!record.Fragment.AsSpan().SequenceEqual([(byte)1]))
                {
                    throw new InvalidDataException("Malformed compatibility CCS.");
                }
                continue;
            }
            if (record.ContentType != TlsContentType.Handshake)
            {
                throw new InvalidDataException("Expected a plaintext ClientHello record.");
            }
            deframer.Append(record.Fragment);
            if (deframer.TryRead(out var message))
            {
                return message!.Type == HandshakeType.ClientHello && deframer.BufferedBytes == 0
                    ? message
                    : throw new InvalidDataException("The first flight was not one ClientHello.");
            }
        }
    }

    private async ValueTask<byte[]> ReadProtectedContentAsync(
        TlsRecordReader reader,
        Tls13RecordCipher cipher,
        int expectedLength,
        CancellationToken cancellationToken)
    {
        var result = new byte[expectedLength];
        var offset = 0;
        while (offset < result.Length)
        {
            var record = await reader.ReadAsync(cancellationToken).ConfigureAwait(false) ??
                throw new EndOfStreamException("The client closed inside application data.");
            if (record.ContentType != TlsContentType.ApplicationData)
            {
                throw new InvalidDataException("Expected protected application data.");
            }
            var inner = cipher.Decrypt(record.Fragment);
            ValidateClientProtectedPlaintext(inner.EncodedLength);
            if (inner.ContentType != TlsContentType.ApplicationData ||
                inner.Content.Length > result.Length - offset)
            {
                throw new InvalidDataException("Protected application content was invalid.");
            }
            inner.Content.CopyTo(result, offset);
            offset += inner.Content.Length;
        }
        return result;
    }

    private void ValidateClientProtectedPlaintext(int encodedLength)
    {
        MaximumReceivedProtectedPlaintextLength = Math.Max(
            MaximumReceivedProtectedPlaintextLength,
            encodedLength);
        if (_serverRecordSizeLimit is { } limit && encodedLength > limit)
        {
            throw new InvalidDataException(
                $"Client protected plaintext {encodedLength} exceeded server limit {limit}.");
        }
    }

    private static async ValueTask WriteProtectedAsync(
        TlsRecordWriter writer,
        Tls13RecordCipher cipher,
        TlsContentType type,
        ReadOnlyMemory<byte> content,
        CancellationToken cancellationToken)
    {
        var encrypted = cipher.Encrypt(type, content.Span);
        try
        {
            await writer.WriteRecordAsync(
                TlsContentType.ApplicationData,
                encrypted,
                cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(encrypted);
        }
    }

    private static async ValueTask WriteProtectedFragmentsAsync(
        TlsRecordWriter writer,
        Tls13RecordCipher cipher,
        TlsContentType type,
        ReadOnlyMemory<byte> content,
        int? maximumPlaintextLength,
        CancellationToken cancellationToken)
    {
        var maximumContentLength = (maximumPlaintextLength ??
            TlsConstants.MaxPlaintextLength + 1) - 1;
        if (maximumContentLength < 1)
        {
            throw new InvalidDataException("Test server record limit leaves no content space.");
        }

        var offset = 0;
        while (offset < content.Length)
        {
            var length = Math.Min(maximumContentLength, content.Length - offset);
            await WriteProtectedAsync(
                writer,
                cipher,
                type,
                content.Slice(offset, length),
                cancellationToken).ConfigureAwait(false);
            offset += length;
        }
    }

    private static Tls13RecordCipher CreateCipher((byte[] Key, byte[] Iv) keys)
    {
        try
        {
            return new Tls13RecordCipher(Suite, keys.Key, keys.Iv);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(keys.Key);
            CryptographicOperations.ZeroMemory(keys.Iv);
        }
    }

    private sealed record ParsedClientHello(
        byte[] SessionId,
        byte[] ClientKeyExchange,
        bool OfferedPostHandshakeAuthentication,
        int? RecordSizeLimit,
        bool OfferedDelegatedCredentials,
        TlsApplicationSettingsCodePoint? ApplicationSettingsCodePoint,
        string[] ApplicationSettingsProtocols,
        string[] AlpnProtocols,
        byte[]? PskIdentity,
        byte[]? PskBinder,
        bool OfferedEarlyData);

    private sealed record TestWireClientHello(
        byte[] BodyPrefix,
        TestWireExtension[] Extensions);

    private sealed record TestWireExtension(ushort Type, byte[] Data);
}
