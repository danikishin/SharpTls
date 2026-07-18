using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using SharpTls.Cryptography;
using SharpTls.Handshake;
using SharpTls.IO;
using SharpTls.Protocol;
using SharpTls.Records;

namespace SharpTls.Tests.Interop;

/// <summary>
/// A deliberately small, managed TLS 1.3 PSK server used only to exercise the
/// client's resumption and early-data state transitions over a real TCP stream.
/// It supports one AES-128-GCM/P-256 connection and authenticates every binder,
/// Finished message, and protected record that it consumes.
/// </summary>
internal sealed class ManagedTls13ResumptionServer : IAsyncDisposable
{
    private static readonly CipherSuiteInfo Suite =
        CipherSuiteInfo.Get(TlsCipherSuite.TlsAes128GcmSha256);

    private readonly TcpListener _listener;
    private readonly CancellationTokenSource _stopping = new();
    private readonly byte[][] _ticketIdentities;
    private readonly byte[][] _psks;
    private readonly int _selectedPskIdentity;
    private readonly bool _expectEarlyDataOffer;
    private readonly byte[] _expectedRequest;
    private readonly bool _acceptEarlyData;
    private readonly bool _expectRetransmission;
    private readonly int _keyUpdatesBeforeResponse;
    private readonly bool _requestClientKeyUpdate;
    private readonly bool _expectClientRequestedKeyUpdate;
    private readonly int? _maximumEarlyRecordPlaintextLength;
    private readonly bool _externalPsk;
    private readonly Task _runTask;

    internal ManagedTls13ResumptionServer(
        ReadOnlySpan<byte> ticketIdentity,
        ReadOnlySpan<byte> psk,
        ReadOnlySpan<byte> expectedRequest,
        bool acceptEarlyData,
        bool expectRetransmission,
        int keyUpdatesBeforeResponse = 0,
        bool requestClientKeyUpdate = false,
        bool expectClientRequestedKeyUpdate = false,
        int? maximumEarlyRecordPlaintextLength = null,
        bool externalPsk = false,
        IReadOnlyList<byte[]>? additionalTicketIdentities = null,
        IReadOnlyList<byte[]>? additionalPsks = null,
        int selectedPskIdentity = 0,
        bool expectEarlyDataOffer = true)
    {
        if (ticketIdentity.IsEmpty)
        {
            throw new ArgumentException("A test ticket identity is required.", nameof(ticketIdentity));
        }
        if (psk.Length != Suite.HashLength)
        {
            throw new ArgumentException("The test PSK must be a SHA-256 PSK.", nameof(psk));
        }
        if (expectedRequest.IsEmpty)
        {
            throw new ArgumentException("Expected early data cannot be empty.", nameof(expectedRequest));
        }
        if (acceptEarlyData && expectRetransmission)
        {
            throw new ArgumentException("Accepted early data must not be retransmitted.");
        }
        if (externalPsk && (acceptEarlyData || expectRetransmission ||
            maximumEarlyRecordPlaintextLength.HasValue ||
            additionalTicketIdentities is { Count: > 0 } ||
            selectedPskIdentity != 0))
        {
            throw new ArgumentException(
                "The external-PSK test path does not offer resumption early data.");
        }
        if (keyUpdatesBeforeResponse is < 0 or > 256)
        {
            throw new ArgumentOutOfRangeException(nameof(keyUpdatesBeforeResponse));
        }

        additionalTicketIdentities ??= [];
        additionalPsks ??= [];
        if (additionalTicketIdentities.Count != additionalPsks.Count ||
            additionalTicketIdentities.Count > 63 ||
            additionalTicketIdentities.Any(identity => identity is null || identity.Length == 0) ||
            additionalPsks.Any(key => key is null || key.Length != Suite.HashLength) ||
            selectedPskIdentity < 0 ||
            selectedPskIdentity > additionalTicketIdentities.Count ||
            (acceptEarlyData && selectedPskIdentity != 0))
        {
            throw new ArgumentException("The managed multi-PSK test configuration is invalid.");
        }

        _ticketIdentities = [ticketIdentity.ToArray(),
            .. additionalTicketIdentities.Select(identity => identity.ToArray())];
        _psks = [psk.ToArray(), .. additionalPsks.Select(key => key.ToArray())];
        _selectedPskIdentity = selectedPskIdentity;
        _expectEarlyDataOffer = !externalPsk && expectEarlyDataOffer;
        _expectedRequest = expectedRequest.ToArray();
        _acceptEarlyData = acceptEarlyData;
        _expectRetransmission = expectRetransmission;
        _keyUpdatesBeforeResponse = keyUpdatesBeforeResponse;
        _requestClientKeyUpdate = requestClientKeyUpdate;
        _expectClientRequestedKeyUpdate = expectClientRequestedKeyUpdate;
        _maximumEarlyRecordPlaintextLength = maximumEarlyRecordPlaintextLength;
        _externalPsk = externalPsk;
        _listener = new TcpListener(IPAddress.Loopback, 0);
        _listener.Start(1);
        _runTask = RunAsync(_stopping.Token);
    }

    internal int Port => ((IPEndPoint)_listener.LocalEndpoint).Port;

    internal Task Completion => _runTask;

    internal byte[]? ReceivedEarlyData { get; private set; }

    internal byte[]? ReceivedApplicationData { get; private set; }

    internal int ReceivedClientKeyUpdateResponses { get; private set; }

    internal int MaximumReceivedEarlyRecordPlaintextLength { get; private set; }

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
            foreach (var identity in _ticketIdentities)
            {
                CryptographicOperations.ZeroMemory(identity);
            }
            foreach (var key in _psks)
            {
                CryptographicOperations.ZeroMemory(key);
            }
            CryptographicOperations.ZeroMemory(_expectedRequest);
        }
    }

    private async Task RunAsync(CancellationToken cancellationToken)
    {
        using var socket = await _listener.AcceptSocketAsync(cancellationToken).ConfigureAwait(false);
        _listener.Stop();
        await using var stream = new NetworkStream(socket, ownsSocket: true);
        var reader = new TlsRecordReader(stream);
        var writer = new TlsRecordWriter(stream);

        var clientHello = await ReadClientHelloAsync(reader, cancellationToken).ConfigureAwait(false);
        var parsed = ParseClientHello(clientHello.Encoded);
        if (parsed.Identities.Length != _ticketIdentities.Length ||
            parsed.Identities.Where((identity, index) =>
                !identity.AsSpan().SequenceEqual(_ticketIdentities[index])).Any())
        {
            throw new CryptographicException("The client offered unexpected PSK identities.");
        }
        if (parsed.OfferedEarlyData != _expectEarlyDataOffer)
        {
            throw new InvalidOperationException(
                _expectEarlyDataOffer
                    ? "The resumption client did not offer early_data."
                    : "The client unexpectedly offered early_data.");
        }

        VerifyBinders(clientHello.Encoded, parsed.Binders, _psks, _externalPsk);
        using var schedule = new Tls13KeySchedule(Suite, _psks[_selectedPskIdentity]);

        Tls13RecordCipher? earlyCipher = null;
        if (_expectEarlyDataOffer)
        {
            var clientHelloHash = SHA256.HashData(clientHello.Encoded);
            try
            {
                using var earlySchedule = new Tls13KeySchedule(Suite, _psks[0]);
                earlySchedule.DeriveClientEarlyTrafficSecret(clientHelloHash);
                earlyCipher = CreateCipher(earlySchedule.TakeClientEarlyTrafficKeys());
            }
            finally
            {
                CryptographicOperations.ZeroMemory(clientHelloHash);
            }
        }

        using var serverKeyShare = KeyShareFactory.Create(NamedGroup.Secp256r1);
        var serverHello = BuildServerHello(
            parsed.SessionId,
            serverKeyShare.PublicKey.Span,
            _selectedPskIdentity);
        using var transcript = new TranscriptHash(Suite);
        transcript.Append(clientHello.Encoded);
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

        if (_expectEarlyDataOffer)
        {
            try
            {
                ReceivedEarlyData = await ReadProtectedContentAsync(
                    reader,
                    earlyCipher!,
                    TlsContentType.ApplicationData,
                    _expectedRequest.Length,
                    allowCompatibilityCcs: false,
                    cancellationToken,
                    _maximumEarlyRecordPlaintextLength).ConfigureAwait(false);
            }
            finally
            {
                earlyCipher!.Dispose();
            }
            if (!ReceivedEarlyData.AsSpan().SequenceEqual(_expectedRequest))
            {
                throw new CryptographicException("The decrypted early application data was incorrect.");
            }
        }

        var encryptedExtensions = BuildEncryptedExtensions(_acceptEarlyData);
        transcript.Append(encryptedExtensions);
        var serverFinishedHash = transcript.CurrentHash();
        byte[]? serverVerifyData = null;
        try
        {
            serverVerifyData = schedule.ComputeServerFinished(serverFinishedHash);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(serverFinishedHash);
        }
        var serverFinished = HandshakeMessage.Encode(HandshakeType.Finished, serverVerifyData);
        CryptographicOperations.ZeroMemory(serverVerifyData);
        transcript.Append(serverFinished);

        var serverFlight = new byte[encryptedExtensions.Length + serverFinished.Length];
        encryptedExtensions.CopyTo(serverFlight, 0);
        serverFinished.CopyTo(serverFlight, encryptedExtensions.Length);
        try
        {
            await WriteProtectedAsync(
                writer,
                serverHandshakeCipher,
                TlsContentType.Handshake,
                serverFlight,
                cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(serverFlight);
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
        var serverApplicationCipher = CreateCipher(schedule.GetServerApplicationKeys());
        using var clientApplicationCipher = CreateCipher(schedule.GetClientApplicationKeys());
        try
        {
            await ReadAndVerifyClientFlightAsync(
                reader,
                clientHandshakeCipher,
                schedule,
                transcript,
                expectEndOfEarlyData: _acceptEarlyData,
                cancellationToken).ConfigureAwait(false);

            if (_externalPsk || (!_acceptEarlyData && _expectRetransmission))
            {
                ReceivedApplicationData = await ReadProtectedContentAsync(
                    reader,
                    clientApplicationCipher,
                    TlsContentType.ApplicationData,
                    _expectedRequest.Length,
                    allowCompatibilityCcs: false,
                    cancellationToken).ConfigureAwait(false);
                if (!ReceivedApplicationData.AsSpan().SequenceEqual(_expectedRequest))
                {
                    throw new CryptographicException("The authenticated application data was incorrect.");
                }
            }

            if (_expectClientRequestedKeyUpdate)
            {
                await ReadClientKeyUpdateAsync(
                    reader,
                    clientApplicationCipher,
                    expectedRequestUpdate: true,
                    cancellationToken).ConfigureAwait(false);
                var responseUpdate = KeyUpdateProcessor.Encode(requestPeerUpdate: false);
                await WriteProtectedAsync(
                    writer,
                    serverApplicationCipher,
                    TlsContentType.Handshake,
                    responseUpdate,
                    cancellationToken).ConfigureAwait(false);
                schedule.UpdateServerApplicationTrafficSecret();
                var next = CreateCipher(schedule.GetServerApplicationKeys());
                serverApplicationCipher.Dispose();
                serverApplicationCipher = next;
            }

            for (var index = 0; index < _keyUpdatesBeforeResponse; index++)
            {
                var update = KeyUpdateProcessor.Encode(
                    requestPeerUpdate: _requestClientKeyUpdate);
                await WriteProtectedAsync(
                    writer,
                    serverApplicationCipher,
                    TlsContentType.Handshake,
                    update,
                    cancellationToken).ConfigureAwait(false);
                schedule.UpdateServerApplicationTrafficSecret();
                var next = CreateCipher(schedule.GetServerApplicationKeys());
                serverApplicationCipher.Dispose();
                serverApplicationCipher = next;
            }
            var response = "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"u8.ToArray();
            try
            {
                await WriteProtectedAsync(
                    writer,
                    serverApplicationCipher,
                    TlsContentType.ApplicationData,
                    response,
                    cancellationToken).ConfigureAwait(false);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(response);
            }

            if (_requestClientKeyUpdate && _keyUpdatesBeforeResponse > 0)
            {
                await ReadClientKeyUpdateResponseAsync(
                    reader,
                    clientApplicationCipher,
                    cancellationToken).ConfigureAwait(false);
            }
        }
        finally
        {
            serverApplicationCipher.Dispose();
        }
    }

    private async ValueTask ReadClientKeyUpdateResponseAsync(
        TlsRecordReader reader,
        Tls13RecordCipher cipher,
        CancellationToken cancellationToken)
    {
        await ReadClientKeyUpdateAsync(
            reader,
            cipher,
            expectedRequestUpdate: false,
            cancellationToken).ConfigureAwait(false);
        ReceivedClientKeyUpdateResponses++;
    }

    private static async ValueTask ReadClientKeyUpdateAsync(
        TlsRecordReader reader,
        Tls13RecordCipher cipher,
        bool expectedRequestUpdate,
        CancellationToken cancellationToken)
    {
        var record = await reader.ReadAsync(cancellationToken).ConfigureAwait(false) ??
            throw new EndOfStreamException("The client closed before its KeyUpdate response.");
        if (record.ContentType != TlsContentType.ApplicationData)
        {
            throw new InvalidDataException("Expected a protected KeyUpdate response.");
        }
        var inner = cipher.Decrypt(record.Fragment);
        if (inner.ContentType != TlsContentType.Handshake)
        {
            throw new InvalidDataException("The KeyUpdate response had the wrong content type.");
        }
        var deframer = new HandshakeDeframer(64);
        deframer.Append(inner.Content);
        if (!deframer.TryRead(out var message) || deframer.BufferedBytes != 0 ||
            message!.Type != HandshakeType.KeyUpdate ||
            KeyUpdateProcessor.ParseRequestUpdate(message.Body) != expectedRequestUpdate)
        {
            throw new InvalidDataException("The client KeyUpdate response was malformed.");
        }
    }

    private static async ValueTask<HandshakeMessage> ReadClientHelloAsync(
        TlsRecordReader reader,
        CancellationToken cancellationToken)
    {
        var deframer = new HandshakeDeframer(64 * 1024);
        while (true)
        {
            var record = await reader.ReadAsync(cancellationToken).ConfigureAwait(false) ??
                throw new EndOfStreamException("The client closed before ClientHello.");
            if (record.ContentType != TlsContentType.Handshake)
            {
                throw new InvalidDataException("Expected a plaintext ClientHello record.");
            }

            deframer.Append(record.Fragment);
            if (!deframer.TryRead(out var message))
            {
                continue;
            }
            if (message!.Type != HandshakeType.ClientHello || deframer.BufferedBytes != 0)
            {
                throw new InvalidDataException("The first client flight was not one ClientHello.");
            }
            return message;
        }
    }

    private static ParsedClientHello ParseClientHello(ReadOnlySpan<byte> encoded)
    {
        if (encoded.Length < TlsConstants.HandshakeHeaderLength ||
            encoded[0] != (byte)HandshakeType.ClientHello)
        {
            throw new InvalidDataException("Invalid ClientHello framing.");
        }

        var body = new TlsBinaryReader(encoded[TlsConstants.HandshakeHeaderLength..]);
        if (body.ReadUInt16() != TlsConstants.LegacyRecordVersion)
        {
            throw new InvalidDataException("ClientHello legacy_version was invalid.");
        }
        _ = body.ReadBytes(TlsConstants.RandomLength);
        var sessionId = body.ReadVector8(TlsConstants.MaxSessionIdLength).ToArray();
        _ = body.ReadVector16();
        _ = body.ReadVector8();
        var extensions = new TlsBinaryReader(body.ReadVector16());
        body.EnsureEnd("test ClientHello");

        byte[]? clientKeyExchange = null;
        var identitiesList = new List<byte[]>();
        var bindersList = new List<byte[]>();
        var offeredEarlyData = false;
        var pskWasLast = false;
        while (!extensions.End)
        {
            var type = extensions.ReadUInt16();
            var data = extensions.ReadVector16();
            pskWasLast = false;
            switch ((TlsExtensionType)type)
            {
                case TlsExtensionType.KeyShare:
                    var shares = new TlsBinaryReader(data);
                    var entries = new TlsBinaryReader(shares.ReadVector16());
                    shares.EnsureEnd("test key_share");
                    while (!entries.End)
                    {
                        var group = entries.ReadUInt16();
                        var exchange = entries.ReadVector16();
                        if (group == (ushort)NamedGroup.Secp256r1)
                        {
                            clientKeyExchange = exchange.ToArray();
                        }
                    }
                    break;

                case TlsExtensionType.EarlyData:
                    if (!data.IsEmpty)
                    {
                        throw new InvalidDataException("ClientHello early_data was not empty.");
                    }
                    offeredEarlyData = true;
                    break;

                case TlsExtensionType.PreSharedKey:
                    var psk = new TlsBinaryReader(data);
                    var identities = new TlsBinaryReader(psk.ReadVector16());
                    while (!identities.End)
                    {
                        identitiesList.Add(identities.ReadVector16().ToArray());
                        _ = identities.ReadUInt32();
                    }
                    var binders = new TlsBinaryReader(psk.ReadVector16());
                    while (!binders.End)
                    {
                        bindersList.Add(binders.ReadVector8().ToArray());
                    }
                    psk.EnsureEnd("test pre_shared_key");
                    pskWasLast = extensions.End;
                    break;
            }
        }

        if (clientKeyExchange is null || identitiesList.Count == 0 ||
            identitiesList.Count != bindersList.Count || !pskWasLast)
        {
            throw new InvalidDataException(
                "ClientHello omitted P-256/PSK data or did not place pre_shared_key last.");
        }
        return new ParsedClientHello(
            sessionId,
            clientKeyExchange,
            identitiesList.ToArray(),
            bindersList.ToArray(),
            offeredEarlyData);
    }

    private static void VerifyBinders(
        ReadOnlySpan<byte> clientHello,
        IReadOnlyList<byte[]> actualBinders,
        IReadOnlyList<byte[]> psks,
        bool externalPsk)
    {
        if (actualBinders.Count != psks.Count ||
            actualBinders.Any(binder => binder.Length != Suite.HashLength))
        {
            throw new CryptographicException("The client PSK binder set was invalid.");
        }

        var encodedBindersLength = 2 + actualBinders.Count * (1 + Suite.HashLength);
        var truncatedHash = SHA256.HashData(clientHello[..^encodedBindersLength]);
        try
        {
            for (var index = 0; index < actualBinders.Count; index++)
            {
                using var schedule = new Tls13KeySchedule(Suite, psks[index]);
                var expected = externalPsk
                    ? schedule.ComputeExternalBinder(truncatedHash)
                    : schedule.ComputeResumptionBinder(truncatedHash);
                try
                {
                    if (!CryptographicOperations.FixedTimeEquals(
                        expected,
                        actualBinders[index]))
                    {
                        throw new CryptographicException(
                            $"Client PSK binder {index} was invalid.");
                    }
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(expected);
                }
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(truncatedHash);
        }
    }

    private static byte[] BuildServerHello(
        ReadOnlySpan<byte> sessionId,
        ReadOnlySpan<byte> serverKeyExchange,
        int selectedPskIdentity)
    {
        var extensions = new TlsBinaryWriter();

        var supportedVersion = new TlsBinaryWriter();
        supportedVersion.WriteUInt16(TlsConstants.Tls13Version);
        extensions.WriteUInt16((ushort)TlsExtensionType.SupportedVersions);
        extensions.WriteVector16(supportedVersion.WrittenSpan);

        var keyShare = new TlsBinaryWriter();
        keyShare.WriteUInt16((ushort)NamedGroup.Secp256r1);
        keyShare.WriteVector16(serverKeyExchange);
        extensions.WriteUInt16((ushort)TlsExtensionType.KeyShare);
        extensions.WriteVector16(keyShare.WrittenSpan);

        var selectedIdentity = new TlsBinaryWriter();
        selectedIdentity.WriteUInt16(checked((ushort)selectedPskIdentity));
        extensions.WriteUInt16((ushort)TlsExtensionType.PreSharedKey);
        extensions.WriteVector16(selectedIdentity.WrittenSpan);

        var body = new TlsBinaryWriter();
        body.WriteUInt16(TlsConstants.LegacyRecordVersion);
        body.WriteBytes(RandomNumberGenerator.GetBytes(TlsConstants.RandomLength));
        body.WriteVector8(sessionId);
        body.WriteUInt16((ushort)Suite.Suite);
        body.WriteUInt8(0);
        body.WriteVector16(extensions.WrittenSpan);
        return HandshakeMessage.Encode(HandshakeType.ServerHello, body.WrittenSpan);
    }

    private static byte[] BuildEncryptedExtensions(bool acceptEarlyData)
    {
        var extensions = new TlsBinaryWriter();
        if (acceptEarlyData)
        {
            extensions.WriteUInt16((ushort)TlsExtensionType.EarlyData);
            extensions.WriteVector16([]);
        }

        var body = new TlsBinaryWriter();
        body.WriteVector16(extensions.WrittenSpan);
        return HandshakeMessage.Encode(HandshakeType.EncryptedExtensions, body.WrittenSpan);
    }

    private static async ValueTask ReadAndVerifyClientFlightAsync(
        TlsRecordReader reader,
        Tls13RecordCipher cipher,
        Tls13KeySchedule schedule,
        TranscriptHash transcript,
        bool expectEndOfEarlyData,
        CancellationToken cancellationToken)
    {
        var deframer = new HandshakeDeframer(64 * 1024);
        var sawEndOfEarlyData = false;
        while (true)
        {
            var record = await reader.ReadAsync(cancellationToken).ConfigureAwait(false) ??
                throw new EndOfStreamException("The client closed before Finished.");
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
            if (inner.ContentType != TlsContentType.Handshake)
            {
                throw new InvalidDataException("Expected a protected client handshake message.");
            }
            deframer.Append(inner.Content);
            while (deframer.TryRead(out var message))
            {
                if (message!.Type == HandshakeType.EndOfEarlyData)
                {
                    if (!expectEndOfEarlyData || sawEndOfEarlyData || message.Body.Length != 0)
                    {
                        throw new InvalidDataException("Unexpected EndOfEarlyData.");
                    }
                    sawEndOfEarlyData = true;
                    transcript.Append(message.Encoded);
                    continue;
                }
                if (message.Type != HandshakeType.Finished ||
                    sawEndOfEarlyData != expectEndOfEarlyData)
                {
                    throw new InvalidDataException("Unexpected client handshake flight.");
                }

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
                transcript.Append(message.Encoded);
                if (deframer.BufferedBytes != 0)
                {
                    throw new InvalidDataException("Data followed client Finished.");
                }
                return;
            }
        }
    }

    private async ValueTask<byte[]> ReadProtectedContentAsync(
        TlsRecordReader reader,
        Tls13RecordCipher cipher,
        TlsContentType expectedType,
        int expectedLength,
        bool allowCompatibilityCcs,
        CancellationToken cancellationToken,
        int? maximumPlaintextLength = null)
    {
        var result = new byte[expectedLength];
        var offset = 0;
        while (offset < result.Length)
        {
            var record = await reader.ReadAsync(cancellationToken).ConfigureAwait(false) ??
                throw new EndOfStreamException("The client closed inside protected content.");
            if (allowCompatibilityCcs && record.ContentType == TlsContentType.ChangeCipherSpec)
            {
                continue;
            }
            if (record.ContentType != TlsContentType.ApplicationData)
            {
                throw new InvalidDataException("Expected a protected application-data record.");
            }

            var inner = cipher.Decrypt(record.Fragment);
            if (maximumPlaintextLength.HasValue)
            {
                MaximumReceivedEarlyRecordPlaintextLength = Math.Max(
                    MaximumReceivedEarlyRecordPlaintextLength,
                    inner.EncodedLength);
                if (inner.EncodedLength > maximumPlaintextLength.Value)
                {
                    throw new InvalidDataException(
                        "Early-data record exceeded the ticket's peer record limit.");
                }
            }
            if (inner.ContentType != expectedType || inner.Content.Length > result.Length - offset)
            {
                throw new InvalidDataException("Protected content type or length was invalid.");
            }
            inner.Content.CopyTo(result, offset);
            offset += inner.Content.Length;
        }
        return result;
    }

    private static async ValueTask WriteProtectedAsync(
        TlsRecordWriter writer,
        Tls13RecordCipher cipher,
        TlsContentType innerType,
        ReadOnlyMemory<byte> content,
        CancellationToken cancellationToken)
    {
        var encrypted = cipher.Encrypt(innerType, content.Span);
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
        byte[][] Identities,
        byte[][] Binders,
        bool OfferedEarlyData);
}
