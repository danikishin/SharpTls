using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using SharpTls.Certificates;
using SharpTls.Cryptography;
using SharpTls.Handshake;
using SharpTls.IO;
using SharpTls.Protocol;
using SharpTls.Quic;
using SharpTls.Tests.Certificates;

namespace SharpTls.Tests.Quic;

public sealed class CustomTlsQuicClientTests
{
    private static readonly CipherSuiteInfo Suite =
        CipherSuiteInfo.Get(TlsCipherSuite.TlsAes128GcmSha256);

    [Fact]
    public void SemanticTransportParametersPreserveConfiguredExtensionOrderAndJson()
    {
        var parameters = CreateClientParameters();
        var profile = CreateProfile(parameters);
        var deterministic = profile.BuildDeterministicForTesting(
            "example.com",
            "quic-extension-order"u8.ToArray());

        Assert.Equal(
            [
                (ushort)TlsExtensionType.ServerName,
                (ushort)TlsExtensionType.SupportedVersions,
                (ushort)TlsExtensionType.SupportedGroups,
                (ushort)TlsExtensionType.SignatureAlgorithms,
                (ushort)TlsExtensionType.KeyShare,
                (ushort)TlsExtensionType.ApplicationLayerProtocolNegotiation,
                (ushort)TlsExtensionType.QuicTransportParameters,
            ],
            ReadExtensionTypes(deterministic));
        Assert.Equal(
            parameters.Encode(),
            ReadExtension(deterministic, TlsExtensionType.QuicTransportParameters));

        var encodedJson = ClientHelloSpecJson.SerializeUtf8(profile.Spec);
        var roundTrip = ClientHelloSpecJson.Deserialize(encodedJson);
        Assert.Equal(parameters.Encode(), roundTrip.QuicTransportParameters!.Encode());
        Assert.Equal(
            deterministic,
            ClientHelloProfiles.FromSpec(roundTrip).BuildDeterministicForTesting(
                "example.com",
                "quic-extension-order"u8.ToArray()));
    }

    [Fact]
    public void OptionsRejectMissingQuicExtensionAndAlpn()
    {
        Assert.Throws<ArgumentException>(() => new CustomTlsQuicClient(
            new CustomTlsQuicClientOptions
            {
                ServerName = "example.com",
                ClientHello = ClientHelloProfiles.Custom(builder => builder.WithTls13()),
            }));

        Assert.Throws<InvalidOperationException>(() => ClientHelloProfiles.Custom(builder => builder
            .WithTls13()
            .WithQuicTransportParameters(CreateClientParameters())));
    }

    [Fact]
    public async Task FullRecordlessHandshakeAuthenticatesParametersAndSecrets()
    {
        using var pki = TestPki.Create();
        var profile = CreateProfile(CreateClientParameters());
        await using var client = new CustomTlsQuicClient(new CustomTlsQuicClientOptions
        {
            ServerName = "example.com",
            ClientHello = profile,
            CertificateValidation = new CustomTlsCertificateValidationOptions
            {
                CustomTrustRoots = [pki.Root],
                RevocationMode = X509RevocationMode.NoCheck,
            },
        });

        using var start = client.StartHandshake();
        var clientHello = Assert.Single(start.Events.OfType<TlsQuicCryptoDataEvent>());
        Assert.Equal(TlsQuicEncryptionLevel.Initial, clientHello.Level);
        Assert.Equal(0UL, clientHello.Offset);
        var parsed = ParseClientHello(clientHello.Data, NamedGroup.Secp256r1);

        using var serverKeyShare = KeyShareFactory.Create(NamedGroup.Secp256r1);
        var serverHello = BuildServerHello(
            parsed.SessionId,
            NamedGroup.Secp256r1,
            serverKeyShare.PublicKey.Span);
        using var transcript = new TranscriptHash(Suite);
        transcript.Append(clientHello.Data);
        transcript.Append(serverHello);
        using var schedule = new Tls13KeySchedule(Suite);
        var sharedSecret = serverKeyShare.DeriveSharedSecret(parsed.KeyExchange);
        try
        {
            schedule.DeriveHandshakeSecrets(sharedSecret, transcript.CurrentHash());
            schedule.DeriveMainSecret();
        }
        finally
        {
            CryptographicOperations.ZeroMemory(sharedSecret);
        }

        using var helloResult = await client.ProcessCryptoDataAsync(
            TlsQuicEncryptionLevel.Initial,
            offset: 0,
            serverHello);
        AssertSecret(
            helloResult,
            TlsQuicEncryptionLevel.Handshake,
            TlsQuicSecretDirection.Read,
            schedule.CopyServerHandshakeTrafficSecret());
        AssertSecret(
            helloResult,
            TlsQuicEncryptionLevel.Handshake,
            TlsQuicSecretDirection.Write,
            schedule.CopyClientHandshakeTrafficSecret());

        var serverParameters = new TlsQuicTransportParameters(
        [
            new TlsQuicTransportParameter(
                (ulong)TlsQuicTransportParameterId.InitialSourceConnectionId,
                [0xA0, 0xA1, 0xA2, 0xA3]),
            TlsQuicTransportParameter.VariableInteger(
                TlsQuicTransportParameterId.ActiveConnectionIdLimit,
                4),
            new TlsQuicTransportParameter(0x173E, [0x99]),
        ]);
        var encryptedExtensions = BuildEncryptedExtensions("h3", serverParameters);
        var certificate = BuildCertificate(pki.Leaf, pki.Root);
        transcript.Append(encryptedExtensions);
        transcript.Append(certificate);
        var certificateVerify = BuildCertificateVerify(
            (RSA)pki.LeafKey,
            transcript.CurrentHash());
        transcript.Append(certificateVerify);
        var verifyData = schedule.ComputeServerFinished(transcript.CurrentHash());
        var finished = HandshakeMessage.Encode(HandshakeType.Finished, verifyData);
        CryptographicOperations.ZeroMemory(verifyData);
        transcript.Append(finished);
        byte[] flight =
        [
            .. encryptedExtensions,
            .. certificate,
            .. certificateVerify,
            .. finished,
        ];

        var split = flight.Length / 3;
        using var gap = await client.ProcessCryptoDataAsync(
            TlsQuicEncryptionLevel.Handshake,
            checked((ulong)split),
            flight.AsMemory(split));
        Assert.Empty(gap.Events);
        using var completed = await client.ProcessCryptoDataAsync(
            TlsQuicEncryptionLevel.Handshake,
            offset: 0,
            flight.AsMemory(0, split));

        Assert.True(client.IsHandshakeComplete);
        Assert.Equal(TlsCipherSuite.TlsAes128GcmSha256, client.NegotiatedCipherSuite);
        Assert.Equal(NamedGroup.Secp256r1, client.NegotiatedGroup);
        Assert.Equal("h3", client.NegotiatedApplicationProtocol);
        Assert.Equal(2, client.PeerCertificateChain.Count);
        Assert.Equal(pki.Leaf.RawData, client.PeerCertificateChain[0]);
        Assert.Equal(
            serverParameters.Encode(),
            Assert.Single(completed.Events.OfType<TlsQuicPeerTransportParametersEvent>())
                .Parameters.Encode());
        Assert.Single(completed.Events.OfType<TlsQuicHandshakeCompletedEvent>());

        schedule.DeriveApplicationTrafficSecrets(transcript.CurrentHash());
        AssertSecret(
            completed,
            TlsQuicEncryptionLevel.Application,
            TlsQuicSecretDirection.Read,
            schedule.CopyServerApplicationTrafficSecret());
        AssertSecret(
            completed,
            TlsQuicEncryptionLevel.Application,
            TlsQuicSecretDirection.Write,
            schedule.CopyClientApplicationTrafficSecret());

        var clientFinishedEvent = Assert.Single(
            completed.Events.OfType<TlsQuicCryptoDataEvent>());
        Assert.Equal(TlsQuicEncryptionLevel.Handshake, clientFinishedEvent.Level);
        Assert.Equal(0UL, clientFinishedEvent.Offset);
        var clientFinished = new HandshakeDeframer(1024);
        clientFinished.Append(clientFinishedEvent.Data);
        Assert.True(clientFinished.TryRead(out var parsedFinished));
        Assert.Equal(HandshakeType.Finished, parsedFinished!.Type);
        var expectedClientFinished = schedule.ComputeClientFinished(transcript.CurrentHash());
        try
        {
            Assert.True(CryptographicOperations.FixedTimeEquals(
                expectedClientFinished,
                parsedFinished.Body));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(expectedClientFinished);
        }

        using var initialDiscard = client.NotifyHandshakePacketSent();
        Assert.Equal(
            TlsQuicEncryptionLevel.Initial,
            Assert.Single(initialDiscard.Events.OfType<TlsQuicDiscardKeysEvent>()).Level);
        using var handshakeDiscard = client.ConfirmHandshake();
        Assert.Equal(
            TlsQuicEncryptionLevel.Handshake,
            Assert.Single(handshakeDiscard.Events.OfType<TlsQuicDiscardKeysEvent>()).Level);
    }

    [Fact]
    public async Task MissingServerTransportParametersFailsWithMissingExtension()
    {
        using var pki = TestPki.Create();
        await using var client = CreateClient(pki, CreateProfile(CreateClientParameters()));
        using var start = client.StartHandshake();
        var hello = Assert.Single(start.Events.OfType<TlsQuicCryptoDataEvent>()).Data;
        var parsed = ParseClientHello(hello, NamedGroup.Secp256r1);
        using var keyShare = KeyShareFactory.Create(NamedGroup.Secp256r1);
        var serverHello = BuildServerHello(
            parsed.SessionId,
            NamedGroup.Secp256r1,
            keyShare.PublicKey.Span);
        using var helloOutput = await client.ProcessCryptoDataAsync(
            TlsQuicEncryptionLevel.Initial,
            0,
            serverHello);

        var body = new TlsBinaryWriter();
        var extensions = new TlsBinaryWriter();
        WriteAlpn(extensions, "h3");
        body.WriteVector16(extensions.WrittenSpan);
        var encryptedExtensions = HandshakeMessage.Encode(
            HandshakeType.EncryptedExtensions,
            body.WrittenSpan);
        var failure = await Assert.ThrowsAsync<TlsProtocolException>(async () =>
            await client.ProcessCryptoDataAsync(
                TlsQuicEncryptionLevel.Handshake,
                0,
                encryptedExtensions));
        Assert.Equal(TlsAlertDescription.MissingExtension, failure.Alert);
        Assert.Equal(
            0x100UL + (byte)TlsAlertDescription.MissingExtension,
            TlsQuicTransportException.GetCryptoErrorCode(failure.Alert));
    }

    [Fact]
    public async Task HelloRetryRequestKeepsInitialOffsetsAndDerivesSecondHelloSecrets()
    {
        using var pki = TestPki.Create();
        var profile = ClientHelloProfiles.Custom(builder => builder
            .WithTls13()
            .WithCipherSuites(TlsCipherSuite.TlsAes128GcmSha256)
            .WithSupportedGroups(NamedGroup.Secp256r1, NamedGroup.Secp384r1)
            .WithKeyShares(NamedGroup.Secp256r1)
            .WithAlpn("h3")
            .WithQuicTransportParameters(CreateClientParameters())
            .WithExtensionOrder(
                ClientHelloExtensionKind.ServerName,
                ClientHelloExtensionKind.SupportedVersions,
                ClientHelloExtensionKind.SupportedGroups,
                ClientHelloExtensionKind.SignatureAlgorithms,
                ClientHelloExtensionKind.KeyShare,
                ClientHelloExtensionKind.ApplicationLayerProtocolNegotiation,
                ClientHelloExtensionKind.QuicTransportParameters));
        await using var client = CreateClient(pki, profile);
        using var start = client.StartHandshake();
        var firstHello = Assert.Single(start.Events.OfType<TlsQuicCryptoDataEvent>());
        var firstParsed = ParseClientHello(firstHello.Data, NamedGroup.Secp256r1);
        var retry = BuildHelloRetryRequest(firstParsed.SessionId, NamedGroup.Secp384r1);

        using var retryResult = await client.ProcessCryptoDataAsync(
            TlsQuicEncryptionLevel.Initial,
            0,
            retry);
        var secondHello = Assert.Single(retryResult.Events.OfType<TlsQuicCryptoDataEvent>());
        Assert.Equal(TlsQuicEncryptionLevel.Initial, secondHello.Level);
        Assert.Equal((ulong)firstHello.Data.Length, secondHello.Offset);
        var secondParsed = ParseClientHello(secondHello.Data, NamedGroup.Secp384r1);
        Assert.Equal(firstParsed.SessionId, secondParsed.SessionId);
        Assert.Equal(
            CreateClientParameters().Encode(),
            ReadExtension(secondHello.Data, TlsExtensionType.QuicTransportParameters));

        using var keyShare = KeyShareFactory.Create(NamedGroup.Secp384r1);
        var serverHello = BuildServerHello(
            secondParsed.SessionId,
            NamedGroup.Secp384r1,
            keyShare.PublicKey.Span);
        using var transcript = new TranscriptHash(Suite);
        transcript.ResetForHelloRetryRequest(firstHello.Data);
        transcript.Append(retry);
        transcript.Append(secondHello.Data);
        transcript.Append(serverHello);
        using var schedule = new Tls13KeySchedule(Suite);
        var sharedSecret = keyShare.DeriveSharedSecret(secondParsed.KeyExchange);
        try
        {
            schedule.DeriveHandshakeSecrets(sharedSecret, transcript.CurrentHash());
            schedule.DeriveMainSecret();
        }
        finally
        {
            CryptographicOperations.ZeroMemory(sharedSecret);
        }

        using var helloResult = await client.ProcessCryptoDataAsync(
            TlsQuicEncryptionLevel.Initial,
            checked((ulong)retry.Length),
            serverHello);
        AssertSecret(
            helloResult,
            TlsQuicEncryptionLevel.Handshake,
            TlsQuicSecretDirection.Read,
            schedule.CopyServerHandshakeTrafficSecret());
        AssertSecret(
            helloResult,
            TlsQuicEncryptionLevel.Handshake,
            TlsQuicSecretDirection.Write,
            schedule.CopyClientHandshakeTrafficSecret());
    }

    private static CustomTlsQuicClient CreateClient(TestPki pki, ClientHelloProfile profile) =>
        new(new CustomTlsQuicClientOptions
        {
            ServerName = "example.com",
            ClientHello = profile,
            CertificateValidation = new CustomTlsCertificateValidationOptions
            {
                CustomTrustRoots = [pki.Root],
                RevocationMode = X509RevocationMode.NoCheck,
            },
        });

    private static ClientHelloProfile CreateProfile(TlsQuicTransportParameters parameters) =>
        ClientHelloProfiles.Custom(builder => builder
            .WithTls13()
            .WithCipherSuites(TlsCipherSuite.TlsAes128GcmSha256)
            .WithAlpn("h3")
            .WithQuicTransportParameters(parameters)
            .WithExtensionOrder(
                ClientHelloExtensionKind.ServerName,
                ClientHelloExtensionKind.SupportedVersions,
                ClientHelloExtensionKind.SupportedGroups,
                ClientHelloExtensionKind.SignatureAlgorithms,
                ClientHelloExtensionKind.KeyShare,
                ClientHelloExtensionKind.ApplicationLayerProtocolNegotiation,
                ClientHelloExtensionKind.QuicTransportParameters));

    private static TlsQuicTransportParameters CreateClientParameters() => new(
    [
        new TlsQuicTransportParameter(
            (ulong)TlsQuicTransportParameterId.InitialSourceConnectionId,
            [0x01, 0x02, 0x03, 0x04]),
        TlsQuicTransportParameter.VariableInteger(
            TlsQuicTransportParameterId.MaxUdpPayloadSize,
            1400),
        TlsQuicTransportParameter.VariableInteger(
            TlsQuicTransportParameterId.ActiveConnectionIdLimit,
            2),
    ]);

    private static (byte[] SessionId, byte[] KeyExchange) ParseClientHello(
        ReadOnlySpan<byte> encoded,
        NamedGroup group)
    {
        var reader = new TlsBinaryReader(encoded);
        Assert.Equal((byte)HandshakeType.ClientHello, reader.ReadUInt8());
        var body = new TlsBinaryReader(reader.ReadBytes(reader.ReadUInt24()));
        reader.EnsureEnd("ClientHello");
        Assert.Equal(TlsConstants.LegacyRecordVersion, body.ReadUInt16());
        _ = body.ReadBytes(TlsConstants.RandomLength);
        var sessionId = body.ReadVector8().ToArray();
        _ = body.ReadVector16();
        _ = body.ReadVector8();
        var extensions = new TlsBinaryReader(body.ReadVector16());
        body.EnsureEnd("ClientHello body");
        while (!extensions.End)
        {
            var type = extensions.ReadUInt16();
            var data = extensions.ReadVector16();
            if (type != (ushort)TlsExtensionType.KeyShare)
            {
                continue;
            }
            var keyShares = new TlsBinaryReader(data);
            var entries = new TlsBinaryReader(keyShares.ReadVector16());
            keyShares.EnsureEnd("key_share");
            while (!entries.End)
            {
                var candidateGroup = entries.ReadUInt16();
                var keyExchange = entries.ReadVector16().ToArray();
                if (candidateGroup == (ushort)group)
                {
                    return (sessionId, keyExchange);
                }
            }
        }
        throw new InvalidDataException("Required key share was absent.");
    }

    private static byte[] BuildServerHello(
        ReadOnlySpan<byte> sessionId,
        NamedGroup group,
        ReadOnlySpan<byte> serverKeyExchange)
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
        NamedGroup group)
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
        keyShare.WriteUInt16((ushort)group);
        extensions.WriteUInt16((ushort)TlsExtensionType.KeyShare);
        extensions.WriteVector16(keyShare.WrittenSpan);

        var body = new TlsBinaryWriter();
        body.WriteUInt16(TlsConstants.LegacyRecordVersion);
        body.WriteBytes(retryRandom);
        body.WriteVector8(sessionId);
        body.WriteUInt16((ushort)Suite.Suite);
        body.WriteUInt8(0);
        body.WriteVector16(extensions.WrittenSpan);
        return HandshakeMessage.Encode(HandshakeType.ServerHello, body.WrittenSpan);
    }

    private static byte[] BuildEncryptedExtensions(
        string alpn,
        TlsQuicTransportParameters parameters)
    {
        var extensions = new TlsBinaryWriter();
        WriteAlpn(extensions, alpn);
        extensions.WriteUInt16((ushort)TlsExtensionType.QuicTransportParameters);
        extensions.WriteVector16(parameters.Encode());
        var body = new TlsBinaryWriter();
        body.WriteVector16(extensions.WrittenSpan);
        return HandshakeMessage.Encode(HandshakeType.EncryptedExtensions, body.WrittenSpan);
    }

    private static void WriteAlpn(TlsBinaryWriter extensions, string alpn)
    {
        var names = new TlsBinaryWriter();
        names.WriteVector8(Encoding.ASCII.GetBytes(alpn));
        var encoded = new TlsBinaryWriter();
        encoded.WriteVector16(names.WrittenSpan);
        extensions.WriteUInt16((ushort)TlsExtensionType.ApplicationLayerProtocolNegotiation);
        extensions.WriteVector16(encoded.WrittenSpan);
    }

    private static byte[] BuildCertificate(
        X509Certificate2 leaf,
        X509Certificate2 issuer)
    {
        var entries = new TlsBinaryWriter();
        entries.WriteVector24(leaf.RawData);
        entries.WriteVector16([]);
        entries.WriteVector24(issuer.RawData);
        entries.WriteVector16([]);
        var body = new TlsBinaryWriter();
        body.WriteVector8([]);
        body.WriteVector24(entries.WrittenSpan);
        return HandshakeMessage.Encode(HandshakeType.Certificate, body.WrittenSpan);
    }

    private static byte[] BuildCertificateVerify(RSA key, ReadOnlySpan<byte> transcriptHash)
    {
        var content = ServerCertificateValidator.BuildCertificateVerifyContent(transcriptHash);
        var signature = key.SignData(
            content,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pss);
        try
        {
            var body = new TlsBinaryWriter();
            body.WriteUInt16((ushort)SignatureScheme.RsaPssRsaeSha256);
            body.WriteVector16(signature);
            return HandshakeMessage.Encode(HandshakeType.CertificateVerify, body.WrittenSpan);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(content);
            CryptographicOperations.ZeroMemory(signature);
        }
    }

    private static void AssertSecret(
        TlsQuicProcessResult result,
        TlsQuicEncryptionLevel level,
        TlsQuicSecretDirection direction,
        byte[] expected)
    {
        try
        {
            var secret = Assert.Single(
                result.Events.OfType<TlsQuicTrafficSecretEvent>(),
                item => item.Secret.Level == level &&
                    item.Secret.Direction == direction);
            Assert.Equal(expected, secret.Secret.CopySecret());
        }
        finally
        {
            CryptographicOperations.ZeroMemory(expected);
        }
    }

    private static ushort[] ReadExtensionTypes(ReadOnlySpan<byte> handshake)
    {
        var extensions = ReadExtensions(handshake);
        var result = new List<ushort>();
        while (!extensions.End)
        {
            result.Add(extensions.ReadUInt16());
            _ = extensions.ReadVector16();
        }
        return result.ToArray();
    }

    private static byte[] ReadExtension(
        ReadOnlySpan<byte> handshake,
        TlsExtensionType extensionType)
    {
        var extensions = ReadExtensions(handshake);
        while (!extensions.End)
        {
            var type = extensions.ReadUInt16();
            var data = extensions.ReadVector16();
            if (type == (ushort)extensionType)
            {
                return data.ToArray();
            }
        }
        throw new InvalidDataException("Extension not found.");
    }

    private static TlsBinaryReader ReadExtensions(ReadOnlySpan<byte> handshake)
    {
        var message = new TlsBinaryReader(handshake);
        _ = message.ReadUInt8();
        var body = new TlsBinaryReader(message.ReadBytes(message.ReadUInt24()));
        _ = body.ReadUInt16();
        _ = body.ReadBytes(TlsConstants.RandomLength);
        _ = body.ReadVector8();
        _ = body.ReadVector16();
        _ = body.ReadVector8();
        return new TlsBinaryReader(body.ReadVector16());
    }
}
