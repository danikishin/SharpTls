using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using SharpTls.Cryptography;
using SharpTls.Handshake;
using SharpTls.IO;
using SharpTls.Protocol;
using SharpTls.Records;

namespace SharpTls.Tests.Interop;

/// <summary>A strict one-connection TLS 1.2 abbreviated-handshake test peer.</summary>
internal sealed class ManagedTls12SessionIdServer : IAsyncDisposable
{
    private static readonly Tls12CipherSuiteInfo Suite = Tls12CipherSuiteInfo.Get(
        TlsCipherSuite.TlsEcdheRsaWithAes128GcmSha256);
    private readonly TcpListener _listener;
    private readonly CancellationTokenSource _stopping = new();
    private readonly byte[] _sessionId;
    private readonly byte[] _masterSecret;
    private readonly byte[] _expectedRequest;
    private readonly byte[]? _expectedTicket;
    private readonly byte[]? _renewedTicket;
    private readonly Task _runTask;

    internal ManagedTls12SessionIdServer(
        ReadOnlySpan<byte> sessionId,
        ReadOnlySpan<byte> masterSecret,
        ReadOnlySpan<byte> expectedRequest,
        byte[]? expectedTicket = null,
        byte[]? renewedTicket = null)
    {
        if (sessionId.Length > TlsConstants.MaxSessionIdLength ||
            (sessionId.IsEmpty && (expectedTicket is null || expectedTicket.Length == 0)))
        {
            throw new ArgumentOutOfRangeException(nameof(sessionId));
        }
        if (masterSecret.Length != TlsConstants.Tls12MasterSecretLength)
        {
            throw new ArgumentOutOfRangeException(nameof(masterSecret));
        }
        if (expectedRequest.IsEmpty)
        {
            throw new ArgumentException("Expected application data cannot be empty.", nameof(expectedRequest));
        }
        if (expectedTicket is { Length: > ushort.MaxValue } ||
            renewedTicket is { Length: > ushort.MaxValue } ||
            (renewedTicket is not null && expectedTicket is null))
        {
            throw new ArgumentOutOfRangeException(nameof(expectedTicket));
        }
        _sessionId = sessionId.ToArray();
        _masterSecret = masterSecret.ToArray();
        _expectedRequest = expectedRequest.ToArray();
        _expectedTicket = expectedTicket is null ? null : (byte[])expectedTicket.Clone();
        _renewedTicket = renewedTicket is null ? null : (byte[])renewedTicket.Clone();
        _listener = new TcpListener(IPAddress.Loopback, 0);
        _listener.Start(1);
        _runTask = RunAsync(_stopping.Token);
    }

    internal int Port => ((IPEndPoint)_listener.LocalEndpoint).Port;
    internal Task Completion => _runTask;
    internal byte[]? ReceivedApplicationData { get; private set; }
    internal byte[]? TlsUnique { get; private set; }

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
            CryptographicOperations.ZeroMemory(_sessionId);
            CryptographicOperations.ZeroMemory(_masterSecret);
            CryptographicOperations.ZeroMemory(_expectedRequest);
            if (_expectedTicket is not null)
            {
                CryptographicOperations.ZeroMemory(_expectedTicket);
            }
            if (_renewedTicket is not null)
            {
                CryptographicOperations.ZeroMemory(_renewedTicket);
            }
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
        var parsedClientHello = ParseAndValidateClientHello(clientHello.Encoded);
        var clientRandom = parsedClientHello.Random;
        var serverRandom = RandomNumberGenerator.GetBytes(TlsConstants.RandomLength);
        var serverHello = BuildServerHello(
            serverRandom,
            parsedClientHello.SessionId,
            acknowledgeTicket: _renewedTicket is not null);

        using var transcript = new Tls12TranscriptHash(Suite);
        transcript.Append(clientHello.Encoded);
        transcript.Append(serverHello);
        using var schedule = new Tls12KeySchedule(Suite);
        schedule.ImportMasterSecret(_masterSecret);
        schedule.DeriveTrafficKeys(clientRandom, serverRandom);
        using var serverCipher = CreateCipher(schedule.GetServerWriteKeys());
        using var clientCipher = CreateCipher(schedule.GetClientWriteKeys());

        await writer.WriteRecordAsync(
            TlsContentType.Handshake,
            serverHello,
            cancellationToken,
            TlsConstants.Tls12Version).ConfigureAwait(false);
        byte[]? newSessionTicket = null;
        if (_renewedTicket is not null)
        {
            var ticketBody = new TlsBinaryWriter();
            ticketBody.WriteUInt32(3600);
            ticketBody.WriteVector16(_renewedTicket);
            newSessionTicket = HandshakeMessage.Encode(
                HandshakeType.NewSessionTicket,
                ticketBody.WrittenSpan);
            transcript.Append(newSessionTicket);
            await writer.WriteRecordAsync(
                TlsContentType.Handshake,
                newSessionTicket,
                cancellationToken,
                TlsConstants.Tls12Version).ConfigureAwait(false);
        }
        await writer.WriteRecordAsync(
            TlsContentType.ChangeCipherSpec,
            new byte[] { 1 },
            cancellationToken,
            TlsConstants.Tls12Version).ConfigureAwait(false);

        var serverFinishedHash = transcript.CurrentHash();
        var serverVerifyData = schedule.ComputeServerFinished(serverFinishedHash);
        CryptographicOperations.ZeroMemory(serverFinishedHash);
        var serverFinished = HandshakeMessage.Encode(HandshakeType.Finished, serverVerifyData);
        TlsUnique = serverFinished[TlsConstants.HandshakeHeaderLength..].ToArray();
        CryptographicOperations.ZeroMemory(serverVerifyData);
        transcript.Append(serverFinished);
        await WriteProtectedAsync(
            writer,
            serverCipher,
            TlsContentType.Handshake,
            serverFinished,
            cancellationToken).ConfigureAwait(false);

        var clientCcs = await reader.ReadAsync(cancellationToken).ConfigureAwait(false) ??
            throw new EndOfStreamException("Client closed before abbreviated ChangeCipherSpec.");
        if (clientCcs.ContentType != TlsContentType.ChangeCipherSpec ||
            clientCcs.LegacyRecordVersion != TlsConstants.Tls12Version ||
            !clientCcs.Fragment.AsSpan().SequenceEqual(new byte[] { 1 }))
        {
            throw new InvalidDataException("Client abbreviated ChangeCipherSpec was malformed.");
        }

        var clientFinishedRecord = await reader.ReadAsync(cancellationToken).ConfigureAwait(false) ??
            throw new EndOfStreamException("Client closed before abbreviated Finished.");
        if (clientFinishedRecord.ContentType != TlsContentType.Handshake)
        {
            throw new InvalidDataException("Expected protected client Finished.");
        }
        var clientFinishedBytes = clientCipher.Decrypt(
            clientFinishedRecord.ContentType,
            clientFinishedRecord.Fragment,
            clientFinishedRecord.LegacyRecordVersion);
        var clientFinished = ParseSingleHandshake(clientFinishedBytes);
        if (clientFinished.Type != HandshakeType.Finished)
        {
            throw new InvalidDataException("Expected abbreviated client Finished.");
        }
        var clientFinishedHash = transcript.CurrentHash();
        var expectedFinished = schedule.ComputeClientFinished(clientFinishedHash);
        try
        {
            if (!CryptographicOperations.FixedTimeEquals(expectedFinished, clientFinished.Body))
            {
                throw new CryptographicException("Abbreviated client Finished was invalid.");
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(clientFinishedHash);
            CryptographicOperations.ZeroMemory(expectedFinished);
            CryptographicOperations.ZeroMemory(clientFinishedBytes);
        }

        ReceivedApplicationData = await ReadApplicationDataAsync(
            reader,
            clientCipher,
            _expectedRequest.Length,
            cancellationToken).ConfigureAwait(false);
        if (!ReceivedApplicationData.AsSpan().SequenceEqual(_expectedRequest))
        {
            throw new CryptographicException("TLS 1.2 resumed application data was incorrect.");
        }

        var response = "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"u8.ToArray();
        try
        {
            await WriteProtectedAsync(
                writer,
                serverCipher,
                TlsContentType.ApplicationData,
                response,
                cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(clientRandom);
            CryptographicOperations.ZeroMemory(serverRandom);
            CryptographicOperations.ZeroMemory(serverHello);
            CryptographicOperations.ZeroMemory(serverFinished);
            if (newSessionTicket is not null)
            {
                CryptographicOperations.ZeroMemory(newSessionTicket);
            }
            CryptographicOperations.ZeroMemory(response);
        }
    }

    private ParsedClientHello ParseAndValidateClientHello(ReadOnlySpan<byte> encoded)
    {
        var message = ParseSingleHandshake(encoded);
        if (message.Type != HandshakeType.ClientHello)
        {
            throw new InvalidDataException("Expected ClientHello.");
        }
        var body = new TlsBinaryReader(message.Body);
        if (body.ReadUInt16() != TlsConstants.LegacyRecordVersion)
        {
            throw new InvalidDataException("ClientHello legacy version was invalid.");
        }
        var random = body.ReadBytes(TlsConstants.RandomLength).ToArray();
        var offeredSessionId = body.ReadVector8(TlsConstants.MaxSessionIdLength).ToArray();
        if (_expectedTicket is null && !offeredSessionId.AsSpan().SequenceEqual(_sessionId))
        {
            throw new InvalidDataException("Client did not offer the cached TLS 1.2 session ID.");
        }
        if (_expectedTicket is not null && offeredSessionId.Length == 0)
        {
            throw new InvalidDataException("Ticket resumption did not use a distinguishing session ID.");
        }
        var suites = new TlsBinaryReader(body.ReadVector16());
        var suiteOffered = false;
        while (!suites.End)
        {
            suiteOffered |= suites.ReadUInt16() == (ushort)Suite.Suite;
        }
        _ = body.ReadVector8();
        var extensions = new TlsBinaryReader(body.ReadVector16());
        body.EnsureEnd("TLS 1.2 abbreviated ClientHello");
        var ems = false;
        var secureRenegotiation = false;
        byte[]? offeredTicket = null;
        while (!extensions.End)
        {
            var type = extensions.ReadUInt16();
            var data = extensions.ReadVector16();
            if (type == (ushort)TlsExtensionType.ExtendedMasterSecret)
            {
                ems = data.IsEmpty;
            }
            else if (type == (ushort)TlsExtensionType.RenegotiationInfo)
            {
                secureRenegotiation = data.SequenceEqual(new byte[] { 0 });
            }
            else if (type == (ushort)TlsExtensionType.SessionTicket)
            {
                offeredTicket = data.ToArray();
            }
        }
        if (!suiteOffered || !ems || !secureRenegotiation ||
            (_expectedTicket is not null &&
             (offeredTicket is null ||
              !CryptographicOperations.FixedTimeEquals(offeredTicket, _expectedTicket))))
        {
            throw new InvalidDataException("ClientHello omitted the resumed suite or security extensions.");
        }
        return new ParsedClientHello(random, offeredSessionId);
    }

    private static byte[] BuildServerHello(
        ReadOnlySpan<byte> serverRandom,
        ReadOnlySpan<byte> sessionId,
        bool acknowledgeTicket)
    {
        var extensions = new TlsBinaryWriter();
        extensions.WriteUInt16((ushort)TlsExtensionType.ExtendedMasterSecret);
        extensions.WriteVector16([]);
        extensions.WriteUInt16((ushort)TlsExtensionType.RenegotiationInfo);
        extensions.WriteVector16([0]);
        if (acknowledgeTicket)
        {
            extensions.WriteUInt16((ushort)TlsExtensionType.SessionTicket);
            extensions.WriteVector16([]);
        }

        var body = new TlsBinaryWriter();
        body.WriteUInt16(TlsConstants.Tls12Version);
        body.WriteBytes(serverRandom);
        body.WriteVector8(sessionId);
        body.WriteUInt16((ushort)Suite.Suite);
        body.WriteUInt8(0);
        body.WriteVector16(extensions.WrittenSpan);
        return HandshakeMessage.Encode(HandshakeType.ServerHello, body.WrittenSpan);
    }

    private static async ValueTask<HandshakeMessage> ReadClientHelloAsync(
        TlsRecordReader reader,
        CancellationToken cancellationToken)
    {
        var deframer = new HandshakeDeframer(64 * 1024);
        while (true)
        {
            var record = await reader.ReadAsync(cancellationToken).ConfigureAwait(false) ??
                throw new EndOfStreamException("Client closed before ClientHello.");
            if (record.ContentType != TlsContentType.Handshake)
            {
                throw new InvalidDataException("Expected ClientHello handshake record.");
            }
            deframer.Append(record.Fragment);
            if (deframer.TryRead(out var message))
            {
                if (deframer.BufferedBytes != 0)
                {
                    throw new InvalidDataException("Data followed ClientHello.");
                }
                return message!;
            }
        }
    }

    private static HandshakeMessage ParseSingleHandshake(ReadOnlySpan<byte> encoded)
    {
        var reader = new TlsBinaryReader(encoded);
        var type = (HandshakeType)reader.ReadUInt8();
        var body = reader.ReadBytes(reader.ReadUInt24()).ToArray();
        reader.EnsureEnd("single TLS handshake message");
        return new HandshakeMessage(type, body, encoded.ToArray());
    }

    private static async ValueTask<byte[]> ReadApplicationDataAsync(
        TlsRecordReader reader,
        Tls12AeadRecordCipher cipher,
        int expectedLength,
        CancellationToken cancellationToken)
    {
        var result = new byte[expectedLength];
        var offset = 0;
        while (offset < result.Length)
        {
            var record = await reader.ReadAsync(cancellationToken).ConfigureAwait(false) ??
                throw new EndOfStreamException("Client closed inside application data.");
            if (record.ContentType != TlsContentType.ApplicationData)
            {
                throw new InvalidDataException("Expected TLS 1.2 application data.");
            }
            var plaintext = cipher.Decrypt(
                record.ContentType,
                record.Fragment,
                record.LegacyRecordVersion);
            if (plaintext.Length > result.Length - offset)
            {
                throw new InvalidDataException("Client application data exceeded the expected length.");
            }
            plaintext.CopyTo(result, offset);
            offset += plaintext.Length;
            CryptographicOperations.ZeroMemory(plaintext);
        }
        return result;
    }

    private static async ValueTask WriteProtectedAsync(
        TlsRecordWriter writer,
        Tls12AeadRecordCipher cipher,
        TlsContentType contentType,
        ReadOnlyMemory<byte> plaintext,
        CancellationToken cancellationToken)
    {
        var encrypted = cipher.Encrypt(contentType, plaintext.Span, TlsConstants.Tls12Version);
        try
        {
            await writer.WriteRecordAsync(
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

    private static Tls12AeadRecordCipher CreateCipher(Tls12TrafficKeys keys)
    {
        try
        {
            return new Tls12AeadRecordCipher(Suite, keys.Key, keys.FixedIv);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(keys.Key);
            CryptographicOperations.ZeroMemory(keys.FixedIv);
        }
    }

    private sealed record ParsedClientHello(byte[] Random, byte[] SessionId);
}
