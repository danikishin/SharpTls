using System.IO.Compression;
using SharpTls.Certificates;
using SharpTls.Cryptography;
using SharpTls.Dns;
using SharpTls.Handshake;
using SharpTls.IO;
using SharpTls.Protocol;
using SharpTls.Quic;
using SharpTls.Records;
using SharpTls.Sessions;

namespace SharpTls.Fuzzing;

internal sealed class ProtocolFuzzTargets : IDisposable
{
    internal const int MaximumInputLength = 65_535;
    private const int MaximumStateMachineActions = 512;
    private const ushort InitialClientRecordVersion = 0x0301;

    private static readonly string[] Names =
    [
        "clienthello",
        "serverflight",
        "certificates",
        "records",
        "sessions",
        "ech-quic-dns",
        "state-machines",
    ];

    private readonly ClientHelloBuildResult _offer;
    private readonly ClientHelloConfiguration _certificateOffer;
    private readonly TlsLimits _limits = new()
    {
        MaxHandshakeMessageSize = 64 * 1024,
        MaxCertificateListSize = 64 * 1024,
        MaxCertificateCount = 8,
        MaxHandshakeTranscriptSize = 128 * 1024,
    };

    internal ProtocolFuzzTargets()
    {
        using var random = new DeterministicRandomSource("SharpTls-fuzz-corpus-v1"u8.ToArray());
        _offer = ClientHelloEncoder.Build(
            "fuzz.invalid",
            ClientHelloProfiles.UTlsFirefox105.Spec.SnapshotConfiguration(),
            random,
            new KeyShareSet(deterministicForTesting: true),
            retry: null);
        _certificateOffer = CreateCertificateOffer();
    }

    internal static IReadOnlyList<string> TargetNames => Array.AsReadOnly(Names);

    internal void VerifyStructuralSeeds()
    {
        var handshake = (byte[])_offer.EncodedHandshake.Clone();
        var clientHelloBody = handshake[TlsConstants.HandshakeHeaderLength..];
        _ = TlsClientHelloVersionOfferParser.Parse(clientHelloBody);
        _ = Tls12ClientHelloParser.Parse(clientHelloBody);
        _ = Tls13ClientHelloParser.Parse(clientHelloBody);
        _ = ClientHelloCapture.Import(BuildRecord(
            TlsContentType.Handshake,
            handshake,
            InitialClientRecordVersion));
        _ = ClientHelloSpecJson.Deserialize(
            ClientHelloSpecJson.SerializeUtf8(ClientHelloProfiles.UTlsFirefox120.Spec));

        _ = ServerHelloParser.Parse(BuildTls13ServerHello(), _offer);
        _ = ServerHelloParser.Parse(
            Tls13ServerHandshakeMessages.BuildHelloRetryRequest(
                _offer.SessionId,
                TlsCipherSuite.TlsAes128GcmSha256,
                NamedGroup.Secp384r1)[TlsConstants.HandshakeHeaderLength..],
            _offer);
        _ = EncryptedExtensionsParser.Parse(
            Tls13ServerHandshakeMessages.BuildEncryptedExtensions(true, "h2")
                [TlsConstants.HandshakeHeaderLength..],
            _offer.Configuration);
        var certificateRequest = Tls13ServerHandshakeMessages.BuildCertificateRequest(
            [SignatureScheme.EcdsaSecp256r1Sha256])
            [TlsConstants.HandshakeHeaderLength..];
        _ = CertificateRequestParser.ParseInitial(certificateRequest);
        _ = CertificateRequestParser.ParsePostHandshake(certificateRequest);
        _ = Tls12ServerHelloParser.Parse(
            Tls12ServerHandshakeMessages.BuildServerHello(
                Enumerable.Range(1, TlsConstants.RandomLength).Select(value => (byte)value).ToArray(),
                [],
                TlsCipherSuite.TlsEcdheRsaWithAes128GcmSha256,
                true,
                true,
                true,
                true,
                null,
                "h2")[TlsConstants.HandshakeHeaderLength..],
            _offer);
        _ = Tls12ServerKeyExchangeParser.Parse(
            BuildTls12ServerKeyExchange(),
            _offer.Configuration);
        _ = Tls12CertificateRequestParser.Parse(
            Tls12ServerHandshakeMessages.BuildCertificateRequest(
                [SignatureScheme.RsaPssRsaeSha256])
                [TlsConstants.HandshakeHeaderLength..]);
        _ = KeyUpdateProcessor.ParseRequestUpdate([0]);
        _ = KeyUpdateProcessor.ParseRequestUpdate([1]);
        _ = Tls12CertificateStatusParser.ParseOcspResponse([1, 0, 0, 1, 0x30], _limits);
        Tls12ServerHelloDoneParser.Parse([]);

        var tls13Certificate = BuildTls13CertificateBody();
        var tls12Certificate = BuildTls12CertificateBody();
        using (CertificateMessageParser.Parse(tls13Certificate, _limits, _certificateOffer)) { }
        using (Tls12CertificateMessageParser.Parse(tls12Certificate, _limits)) { }
        using (ClientCertificateMessageParser.Parse(tls13Certificate, _limits)) { }
        using (ClientCertificateMessageParser.ParseTls12(tls12Certificate, _limits)) { }
        var decompressed = CompressedCertificateParser.Decompress(
            BuildCompressedCertificateBody(tls13Certificate),
            _certificateOffer,
            _limits);
        if (!decompressed.AsSpan().SequenceEqual(tls13Certificate))
        {
            throw new InvalidOperationException("Compressed certificate fuzz seed does not round-trip.");
        }

        var recordBytes = BuildRecord(
            TlsContentType.Handshake,
            handshake,
            InitialClientRecordVersion);
        using (var stream = new MemoryStream(recordBytes, writable: false))
        {
            var reader = new TlsRecordReader(stream);
            _ = reader.ReadAsync(CancellationToken.None).AsTask().GetAwaiter().GetResult()
                ?? throw new InvalidOperationException("TLS record fuzz seed did not parse.");
        }
        var tls13Ciphertext = BuildTls13CiphertextSeed();
        var tls13Suite = CipherSuiteInfo.Get(TlsCipherSuite.TlsAes128GcmSha256);
        using (var decryptor = new Tls13RecordCipher(
            tls13Suite,
            new byte[tls13Suite.KeyLength],
            new byte[tls13Suite.IvLength],
            maximumRecords: 1))
        {
            _ = decryptor.Decrypt(tls13Ciphertext);
        }
        var tls12Ciphertext = BuildTls12CiphertextSeed();
        var tls12Suite = Tls12CipherSuiteInfo.Get(
            TlsCipherSuite.TlsEcdheRsaWithAes128GcmSha256);
        using (var decryptor = new Tls12AeadRecordCipher(
            tls12Suite,
            new byte[tls12Suite.KeyLength],
            new byte[tls12Suite.FixedIvLength],
            maximumRecords: 1))
        {
            _ = decryptor.Decrypt(TlsContentType.ApplicationData, tls12Ciphertext);
        }

        VerifySessionSeeds();
        _ = TlsEchConfigList.Parse(BuildEchConfigList());
        _ = TlsQuicTransportParameters.Parse(BuildQuicTransportParameters());
        var dns = BuildDnsHttpsNoDataResponse();
        _ = DnsMessageParser.ParseHttpsResponse(
            dns,
            0x1234,
            "fuzz.invalid",
            MaximumInputLength,
            maximumRecords: 256);
        VerifyStateMachineSeeds();
    }

    internal IReadOnlyList<byte[]> CreateSeedCorpus(string target = "all")
    {
        if (string.Equals(target, "all", StringComparison.Ordinal))
        {
            var unique = new Dictionary<string, byte[]>(StringComparer.Ordinal);
            foreach (var name in Names)
            {
                foreach (var seed in CreateSeedCorpus(name))
                {
                    unique.TryAdd(Convert.ToBase64String(seed), seed);
                }
            }
            return [.. unique.Values];
        }
        if (!Names.Contains(target, StringComparer.Ordinal))
        {
            throw new ArgumentException($"Unknown fuzz target '{target}'.", nameof(target));
        }

        var seeds = CreateBoundarySeeds();
        switch (target)
        {
            case "clienthello":
                AddClientHelloSeeds(seeds);
                break;
            case "serverflight":
                AddServerFlightSeeds(seeds);
                break;
            case "certificates":
                AddCertificateSeeds(seeds);
                break;
            case "records":
                AddRecordSeeds(seeds);
                break;
            case "sessions":
                AddSessionSeeds(seeds);
                break;
            case "ech-quic-dns":
                AddEchQuicDnsSeeds(seeds);
                break;
            case "state-machines":
                AddStateMachineSeeds(seeds);
                break;
        }
        return seeds;
    }

    private void AddClientHelloSeeds(List<byte[]> seeds)
    {
        var handshake = (byte[])_offer.EncodedHandshake.Clone();
        var body = handshake.Length >= 4 ? handshake[4..] : [];
        seeds.Add(handshake);
        seeds.Add(body);
        seeds.Add(BuildRecord(TlsContentType.Handshake, handshake, InitialClientRecordVersion));
        seeds.Add(ClientHelloProfiles.UTlsFirefox120.BuildDeterministicForTesting(
            "fuzz.invalid",
            "SharpTls-fuzz-firefox120"u8.ToArray()));
        seeds.Add(ClientHelloSpecJson.SerializeUtf8(ClientHelloProfiles.UTlsFirefox120.Spec));
    }

    private void AddServerFlightSeeds(List<byte[]> seeds)
    {
        seeds.Add(BuildTls13ServerHello());
        seeds.Add(Tls13ServerHandshakeMessages.BuildHelloRetryRequest(
            _offer.SessionId,
            TlsCipherSuite.TlsAes128GcmSha256,
            NamedGroup.Secp384r1)[TlsConstants.HandshakeHeaderLength..]);
        seeds.Add(Tls13ServerHandshakeMessages.BuildEncryptedExtensions(
            acknowledgeSni: true,
            alpn: "h2")[TlsConstants.HandshakeHeaderLength..]);
        seeds.Add(Tls13ServerHandshakeMessages.BuildCertificateRequest(
            [SignatureScheme.EcdsaSecp256r1Sha256])
            [TlsConstants.HandshakeHeaderLength..]);
        seeds.Add(Tls12ServerHandshakeMessages.BuildServerHello(
            Enumerable.Range(1, TlsConstants.RandomLength).Select(value => (byte)value).ToArray(),
            [],
            TlsCipherSuite.TlsEcdheRsaWithAes128GcmSha256,
            acknowledgeSni: true,
            acknowledgeEcPointFormats: true,
            acknowledgeSessionTicket: true,
            acknowledgeStatusRequest: true,
            signedCertificateTimestamps: null,
            alpn: "h2")[TlsConstants.HandshakeHeaderLength..]);
        seeds.Add(BuildTls12ServerKeyExchange());
        seeds.Add(Tls12ServerHandshakeMessages.BuildCertificateRequest(
            [SignatureScheme.RsaPssRsaeSha256])
            [TlsConstants.HandshakeHeaderLength..]);
        seeds.Add([0]);
        seeds.Add([1]);
        seeds.Add([1, 0, 0, 1, 0x30]);
        seeds.Add([]);
    }

    private void AddCertificateSeeds(List<byte[]> seeds)
    {
        var tls13 = BuildTls13CertificateBody();
        var tls12 = BuildTls12CertificateBody();
        seeds.Add(tls13);
        seeds.Add(tls12);
        seeds.Add(BuildCompressedCertificateBody(tls13));
    }

    private void AddRecordSeeds(List<byte[]> seeds)
    {
        var handshake = (byte[])_offer.EncodedHandshake.Clone();
        seeds.Add(BuildRecord(TlsContentType.Handshake, handshake, InitialClientRecordVersion));
        seeds.Add(BuildRecord(TlsContentType.ChangeCipherSpec, [1], TlsConstants.LegacyRecordVersion));

        seeds.Add(BuildTls13CiphertextSeed());
        seeds.Add(BuildTls12CiphertextSeed());
    }

    private static void AddSessionSeeds(List<byte[]> seeds)
    {
        var extensions = new TlsBinaryWriter();
        var earlyData = new TlsBinaryWriter();
        earlyData.WriteUInt32(4_096);
        extensions.WriteUInt16((ushort)TlsExtensionType.EarlyData);
        extensions.WriteVector16(earlyData.WrittenSpan);
        var tls13Ticket = new TlsBinaryWriter();
        tls13Ticket.WriteUInt32(3_600);
        tls13Ticket.WriteUInt32(0x1020_3040);
        tls13Ticket.WriteVector8([1, 2, 3]);
        tls13Ticket.WriteVector16([4, 5, 6, 7]);
        tls13Ticket.WriteVector16(extensions.WrittenSpan);
        seeds.Add(tls13Ticket.ToArray());
        seeds.Add(Tls12ServerHandshakeMessages.BuildNewSessionTicket(3_600, [8, 9, 10])
            [TlsConstants.HandshakeHeaderLength..]);

        using (var tls13State = new Tls13ServerSessionTicketState(
            1_700_000_000_000,
            3_600,
            0x5566_7788,
            TlsCipherSuite.TlsAes128GcmSha256,
            "fuzz.invalid",
            "h2",
            new byte[32]))
        {
            seeds.Add(tls13State.Encode());
        }
        using var tls12State = new Tls12ServerTicketState(
            1_700_000_000_000,
            3_600,
            TlsCipherSuite.TlsEcdheRsaWithAes128GcmSha256,
            "fuzz.invalid",
            "http/1.1",
            NamedGroup.X25519,
            new byte[TlsConstants.Tls12MasterSecretLength]);
        seeds.Add(tls12State.Encode());
    }

    private static void AddEchQuicDnsSeeds(List<byte[]> seeds)
    {
        seeds.Add(BuildEchConfigList());
        seeds.Add(BuildQuicTransportParameters());
        seeds.Add(BuildDnsHttpsNoDataResponse());
    }

    private static byte[] BuildQuicTransportParameters() =>
        new TlsQuicTransportParameters(
        [
            TlsQuicTransportParameter.VariableInteger(
                TlsQuicTransportParameterId.MaxUdpPayloadSize,
                1200),
            TlsQuicTransportParameter.VariableInteger(
                TlsQuicTransportParameterId.InitialMaxData,
                65_536),
        ]).Encode();

    private static void AddStateMachineSeeds(List<byte[]> seeds)
    {
        // Direct and HelloRetryRequest TLS 1.3 client paths, including client auth.
        seeds.Add([0, 1, 4, 5, 7, 8, 9, 13, 14, 15]);
        seeds.Add([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 129, 12, 13, 14, 15]);
        // Direct and HRR TLS 1.3 server paths.
        seeds.Add([0, 2, 3, 4, 5, 6]);
        seeds.Add([0, 1, 2, 3, 4, 5, 6]);
        // TLS 1.2 full, client-auth, and abbreviated handshakes.
        seeds.Add([0, 1, 2, 7, 9, 11, 13, 15, 16, 17, 18, 19, 20, 21]);
        seeds.Add([0, 1, 2, 7, 8, 9, 10, 11, 144, 13, 14, 15, 16, 17, 18, 19, 20, 21]);
        seeds.Add([0, 1, 134, 3, 4, 5, 6, 20, 21]);
    }

    internal void Run(string target, ReadOnlySpan<byte> input)
    {
        if (input.Length > MaximumInputLength)
        {
            throw new ArgumentOutOfRangeException(
                nameof(input),
                $"Fuzz inputs are bounded to {MaximumInputLength} bytes.");
        }

        var owned = input.ToArray();
        if (string.Equals(target, "all", StringComparison.Ordinal))
        {
            foreach (var name in Names)
            {
                RunCore(name, owned);
            }
            return;
        }

        if (!Names.Contains(target, StringComparer.Ordinal))
        {
            throw new ArgumentException($"Unknown fuzz target '{target}'.", nameof(target));
        }
        RunCore(target, owned);
    }

    public void Dispose() => _offer.Dispose();

    private void RunCore(string target, byte[] input)
    {
        switch (target)
        {
            case "clienthello":
                RunClientHello(input);
                break;
            case "serverflight":
                RunServerFlight(input);
                break;
            case "certificates":
                RunCertificates(input);
                break;
            case "records":
                RunRecords(input);
                break;
            case "sessions":
                RunSessions(input);
                break;
            case "ech-quic-dns":
                RunEchQuicDns(input);
                break;
            case "state-machines":
                RunStateMachines(input);
                break;
            default:
                throw new InvalidOperationException("Validated fuzz target was not dispatched.");
        }
    }

    private static void RunClientHello(byte[] input)
    {
        ProtocolBoundary(() => TlsClientHelloVersionOfferParser.Parse(input));
        ProtocolBoundary(() => Tls12ClientHelloParser.Parse(input));
        ProtocolBoundary(() => Tls13ClientHelloParser.Parse(input));
        CaptureBoundary(() => ClientHelloCapture.Import(input));
        JsonBoundary(() => ClientHelloSpecJson.Deserialize(input));
        Deframe(input);
    }

    private void RunServerFlight(byte[] input)
    {
        ProtocolBoundary(() => ServerHelloParser.Parse(input, _offer));
        ProtocolBoundary(() => Tls12ServerHelloParser.Parse(input, _offer));
        ProtocolBoundary(() => EncryptedExtensionsParser.Parse(
            input,
            _offer.Configuration,
            offeredEarlyData: true,
            allowApplicationSettingsWithEarlyData: true,
            echWasRejected: true));
        ProtocolBoundary(() => Tls12ServerKeyExchangeParser.Parse(input, _offer.Configuration));
        ProtocolBoundary(() => CertificateRequestParser.ParseInitial(input));
        ProtocolBoundary(() => CertificateRequestParser.ParsePostHandshake(input));
        ProtocolBoundary(() => Tls12CertificateRequestParser.Parse(input));
        ProtocolBoundary(() => KeyUpdateProcessor.ParseRequestUpdate(input));
        ProtocolBoundary(() => Tls12CertificateStatusParser.ParseOcspResponse(input, _limits));
        ProtocolBoundary(() => Tls12ServerHelloDoneParser.Parse(input));
    }

    private void RunCertificates(byte[] input)
    {
        ProtocolBoundary(() =>
        {
            using var parsed = CertificateMessageParser.Parse(
                input,
                _limits,
                _certificateOffer);
        });
        ProtocolBoundary(() =>
        {
            using var parsed = Tls12CertificateMessageParser.Parse(input, _limits);
        });
        ProtocolBoundary(() =>
        {
            using var parsed = ClientCertificateMessageParser.Parse(input, _limits);
        });
        ProtocolBoundary(() =>
        {
            using var parsed = ClientCertificateMessageParser.ParseTls12(input, _limits);
        });
        ProtocolBoundary(() => CompressedCertificateParser.Decompress(
            input,
            _certificateOffer,
            _limits));
    }

    private static void RunRecords(byte[] input)
    {
        ProtocolBoundary(() =>
        {
            using var stream = new MemoryStream(input, writable: false);
            var reader = new TlsRecordReader(stream);
            for (var count = 0; count < 8; count++)
            {
                if (reader.ReadAsync(CancellationToken.None).AsTask()
                    .GetAwaiter().GetResult() is null)
                {
                    break;
                }
            }
        });
        Deframe(input);
        ProtocolBoundary(() =>
        {
            var suite = CipherSuiteInfo.Get(TlsCipherSuite.TlsAes128GcmSha256);
            using var cipher = new Tls13RecordCipher(
                suite,
                new byte[suite.KeyLength],
                new byte[suite.IvLength],
                maximumRecords: 1);
            _ = cipher.Decrypt(input);
        });
        ProtocolBoundary(() =>
        {
            var suite = Tls12CipherSuiteInfo.Get(
                TlsCipherSuite.TlsEcdheRsaWithAes128GcmSha256);
            using var cipher = new Tls12AeadRecordCipher(
                suite,
                new byte[suite.KeyLength],
                new byte[suite.FixedIvLength],
                maximumRecords: 1);
            _ = cipher.Decrypt(TlsContentType.ApplicationData, input);
        });
    }

    private static void RunSessions(byte[] input)
    {
        ProtocolBoundary(() => Tls13NewSessionTicketParser.Parse(input));
        ProtocolBoundary(() => Tls12NewSessionTicketParser.Parse(input));
        ProtocolBoundary(() => Tls13ServerSessionTicketState.Decode(input));
        ProtocolBoundary(() => Tls12ServerTicketState.Decode(input));
    }

    private static void RunEchQuicDns(byte[] input)
    {
        ProtocolBoundary(() => TlsEchConfigList.Parse(input));
        QuicBoundary(() => TlsQuicTransportParameters.Parse(input));
        QuicBoundary(() =>
        {
            var reassembler = new TlsQuicCryptoStreamReassembler(64 * 1024);
            _ = reassembler.Add(0, input);
            _ = reassembler.Add(0, input);
            reassembler.Discard();
            if (input.Length != 0)
            {
                _ = reassembler.Add((ulong)input.Length, input.AsSpan(0, 1));
            }
        });
        DnsBoundary(() => DnsMessageParser.HasTruncatedFlag(input));
        DnsBoundary(() => DnsMessageParser.ParseHttpsResponse(
            input,
            input.Length >= 2 ? (ushort)((input[0] << 8) | input[1]) : (ushort)0,
            "fuzz.invalid",
            MaximumInputLength,
            maximumRecords: 256));
    }

    private static void RunStateMachines(byte[] input)
    {
        var client13 = new Tls13ClientStateMachine();
        var server13 = new Tls13ServerStateMachine();
        var client12 = new Tls12ClientStateMachine();
        // State space saturates quickly, while rejected transitions allocate
        // exceptions. Keep each fuzz invocation strictly bounded so long random
        // inputs cannot dominate a coverage campaign without adding coverage.
        foreach (var value in input.AsSpan(0, Math.Min(input.Length, MaximumStateMachineActions)))
        {
            ProtocolBoundary(() => ApplyTls13ClientAction(client13, value));
            ProtocolBoundary(() => ApplyTls13ServerAction(server13, value));
            ProtocolBoundary(() => ApplyTls12ClientAction(client12, value));
        }
    }

    private byte[] BuildTls13ServerHello()
    {
        var extensions = new TlsBinaryWriter();
        extensions.WriteUInt16((ushort)TlsExtensionType.SupportedVersions);
        extensions.WriteVector16([0x03, 0x04]);
        var keyShare = new TlsBinaryWriter();
        keyShare.WriteUInt16((ushort)NamedGroup.X25519);
        keyShare.WriteVector16(Enumerable.Range(1, 32).Select(value => (byte)value).ToArray());
        extensions.WriteUInt16((ushort)TlsExtensionType.KeyShare);
        extensions.WriteVector16(keyShare.WrittenSpan);
        var body = new TlsBinaryWriter();
        body.WriteUInt16(TlsConstants.LegacyRecordVersion);
        body.WriteBytes(Enumerable.Range(0, TlsConstants.RandomLength).Select(value => (byte)value).ToArray());
        body.WriteVector8(_offer.SessionId);
        body.WriteUInt16((ushort)TlsCipherSuite.TlsAes128GcmSha256);
        body.WriteUInt8(0);
        body.WriteVector16(extensions.WrittenSpan);
        return body.ToArray();
    }

    private static byte[] BuildTls12ServerKeyExchange()
    {
        var body = new TlsBinaryWriter();
        body.WriteUInt8(3);
        body.WriteUInt16((ushort)NamedGroup.X25519);
        body.WriteVector8(Enumerable.Range(1, 32).Select(value => (byte)value).ToArray());
        body.WriteUInt16((ushort)SignatureScheme.RsaPssRsaeSha256);
        body.WriteVector16([1]);
        return body.ToArray();
    }

    private static byte[] BuildTls13CiphertextSeed()
    {
        var suite = CipherSuiteInfo.Get(TlsCipherSuite.TlsAes128GcmSha256);
        using var encryptor = new Tls13RecordCipher(
            suite,
            new byte[suite.KeyLength],
            new byte[suite.IvLength],
            maximumRecords: 1);
        return encryptor.Encrypt(TlsContentType.ApplicationData, "tls13-seed"u8);
    }

    private static byte[] BuildTls12CiphertextSeed()
    {
        var suite = Tls12CipherSuiteInfo.Get(
            TlsCipherSuite.TlsEcdheRsaWithAes128GcmSha256);
        using var encryptor = new Tls12AeadRecordCipher(
            suite,
            new byte[suite.KeyLength],
            new byte[suite.FixedIvLength],
            maximumRecords: 1);
        return encryptor.Encrypt(TlsContentType.ApplicationData, "tls12-seed"u8);
    }

    private static byte[] BuildTls13CertificateBody()
    {
        var entries = new TlsBinaryWriter();
        entries.WriteVector24(FuzzCertificateDer);
        entries.WriteVector16([]);
        var body = new TlsBinaryWriter();
        body.WriteVector8([]);
        body.WriteVector24(entries.WrittenSpan);
        return body.ToArray();
    }

    private static byte[] BuildTls12CertificateBody()
    {
        var entries = new TlsBinaryWriter();
        entries.WriteVector24(FuzzCertificateDer);
        var body = new TlsBinaryWriter();
        body.WriteVector24(entries.WrittenSpan);
        return body.ToArray();
    }

    private static byte[] BuildCompressedCertificateBody(ReadOnlySpan<byte> certificateBody)
    {
        using var output = new MemoryStream();
        using (var compressor = new ZLibStream(
            output,
            CompressionLevel.SmallestSize,
            leaveOpen: true))
        {
            compressor.Write(certificateBody);
        }
        var body = new TlsBinaryWriter();
        body.WriteUInt16((ushort)TlsCertificateCompressionAlgorithm.Zlib);
        body.WriteUInt24(certificateBody.Length);
        body.WriteVector24(output.ToArray());
        return body.ToArray();
    }

    private static byte[] BuildEchConfigList()
    {
        var suites = new TlsBinaryWriter();
        suites.WriteUInt16((ushort)TlsHpkeKdfId.HkdfSha256);
        suites.WriteUInt16((ushort)TlsHpkeAeadId.Aes128Gcm);
        var contents = new TlsBinaryWriter();
        contents.WriteUInt8(7);
        contents.WriteUInt16((ushort)TlsHpkeKemId.DhkemX25519HkdfSha256);
        contents.WriteVector16(Enumerable.Repeat((byte)1, 32).ToArray());
        contents.WriteVector16(suites.WrittenSpan);
        contents.WriteUInt8(0);
        contents.WriteVector8("public.example"u8);
        contents.WriteVector16([]);
        var config = new TlsBinaryWriter();
        config.WriteUInt16((ushort)TlsExtensionType.EncryptedClientHello);
        config.WriteVector16(contents.WrittenSpan);
        var list = new TlsBinaryWriter();
        list.WriteVector16(config.WrittenSpan);
        return list.ToArray();
    }

    private static byte[] BuildDnsHttpsNoDataResponse()
    {
        var response = new TlsBinaryWriter();
        response.WriteUInt16(0x1234);
        response.WriteUInt16(0x8180);
        response.WriteUInt16(1);
        response.WriteUInt16(0);
        response.WriteUInt16(0);
        response.WriteUInt16(0);
        response.WriteVector8("fuzz"u8);
        response.WriteVector8("invalid"u8);
        response.WriteUInt8(0);
        response.WriteUInt16(65);
        response.WriteUInt16(1);
        return response.ToArray();
    }

    private static void VerifySessionSeeds()
    {
        var seeds = CreateBoundarySeeds();
        AddSessionSeeds(seeds);
        _ = Tls13NewSessionTicketParser.Parse(seeds[^4]);
        using (Tls12NewSessionTicketParser.Parse(seeds[^3])) { }
        using (Tls13ServerSessionTicketState.Decode(seeds[^2])) { }
        using (Tls12ServerTicketState.Decode(seeds[^1])) { }
    }

    private static void VerifyStateMachineSeeds()
    {
        var client13Direct = new Tls13ClientStateMachine();
        foreach (var value in new byte[] { 0, 1, 4, 5, 7, 8, 9, 13, 14, 15 })
        {
            ApplyTls13ClientAction(client13Direct, value);
        }
        var client13RetryAndAuth = new Tls13ClientStateMachine();
        foreach (var value in new byte[] { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 129, 12, 13, 14, 15 })
        {
            ApplyTls13ClientAction(client13RetryAndAuth, value);
        }
        var server13Direct = new Tls13ServerStateMachine();
        foreach (var value in new byte[] { 0, 2, 3, 4, 5, 6 })
        {
            ApplyTls13ServerAction(server13Direct, value);
        }
        var server13Retry = new Tls13ServerStateMachine();
        foreach (var value in new byte[] { 0, 1, 2, 3, 4, 5, 6 })
        {
            ApplyTls13ServerAction(server13Retry, value);
        }
        VerifyTls12StateMachine([0, 1, 2, 7, 9, 11, 13, 15, 16, 17, 18, 19, 20, 21]);
        VerifyTls12StateMachine([0, 1, 2, 7, 8, 9, 10, 11, 144, 13, 14, 15, 16, 17, 18, 19, 20, 21]);
        VerifyTls12StateMachine([0, 1, 134, 3, 4, 5, 6, 20, 21]);
        if (client13Direct.State != Tls13ClientState.Closed ||
            client13RetryAndAuth.State != Tls13ClientState.Closed ||
            server13Direct.State != Tls13ServerState.Closed ||
            server13Retry.State != Tls13ServerState.Closed)
        {
            throw new InvalidOperationException("TLS 1.3 state-machine fuzz seed did not reach Closed.");
        }
    }

    private static void VerifyTls12StateMachine(ReadOnlySpan<byte> sequence)
    {
        var state = new Tls12ClientStateMachine();
        foreach (var value in sequence)
        {
            ApplyTls12ClientAction(state, value);
        }
        if (state.State != Tls12ClientState.Closed)
        {
            throw new InvalidOperationException("TLS 1.2 state-machine fuzz seed did not reach Closed.");
        }
    }

    private static byte[] BuildRecord(
        TlsContentType contentType,
        ReadOnlySpan<byte> payload,
        ushort version)
    {
        var record = new TlsBinaryWriter(TlsConstants.RecordHeaderLength + payload.Length);
        record.WriteUInt8((byte)contentType);
        record.WriteUInt16(version);
        record.WriteVector16(payload);
        return record.ToArray();
    }

    private static List<byte[]> CreateBoundarySeeds() =>
    [
        [],
        [0],
        [1],
        [0, 0],
        [0, 1, 0],
        [0, 0, 0, 0],
    ];

    private static ClientHelloConfiguration CreateCertificateOffer() =>
        ClientHelloProfiles.Custom(builder => builder.WithExtensionLayout(
            ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.ServerName),
            ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.SupportedVersions),
            ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.SupportedGroups),
            ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.SignatureAlgorithms),
            ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.KeyShare),
            ClientHelloExtensionSpec.Raw(
                (ushort)TlsExtensionType.CompressCertificate,
                [2, 0, (byte)TlsCertificateCompressionAlgorithm.Zlib])))
        .Spec
        .SnapshotConfiguration();

    private static byte[] FuzzCertificateDer { get; } = Convert.FromBase64String(
        "MIIBgjCCASmgAwIBAgIUfUfnL0XmgEWwqQqC2bzr3q/G1AMwCgYIKoZIzj0EAwIw" +
        "FzEVMBMGA1UEAwwMZnV6ei5pbnZhbGlkMB4XDTI2MDcxODE4NTQ1NloXDTM2MDcx" +
        "NTE4NTQ1NlowFzEVMBMGA1UEAwwMZnV6ei5pbnZhbGlkMFkwEwYHKoZIzj0CAQYI" +
        "KoZIzj0DAQcDQgAEDX5+lnWIJzxtu0gpsCzSXG7+4QGm96nUAJoFWdaeIUpcOM/2" +
        "9IvLYYDSm00vIJvsMkVfbht9hLKS1uesiKdxz6NTMFEwHQYDVR0OBBYEFN8Oclx7" +
        "oGXsVqax++GJ8dGf3FdBMB8GA1UdIwQYMBaAFN8Oclx7oGXsVqax++GJ8dGf3FdB" +
        "MA8GA1UdEwEB/wQFMAMBAf8wCgYIKoZIzj0EAwIDRwAwRAIgFckvFfrFEKYuWqlD" +
        "YSrJU5HCExdwJQc6AHf8f473YyACIAWpUp7HsxX2QLZwpNCeyhZmlLRE+njgIB5n" +
        "ZoCbLaO9");

    private static void ApplyTls13ClientAction(Tls13ClientStateMachine state, byte value)
    {
        switch (value % 17)
        {
            case 0: state.TransportConnected(); break;
            case 1: state.ClientHelloSent(); break;
            case 2: state.HelloRetryRequestReceived(); break;
            case 3: state.SecondClientHelloSent(); break;
            case 4: state.ServerHelloReceived(); break;
            case 5: state.EncryptedExtensionsReceived(); break;
            case 6: state.CertificateRequestReceived(); break;
            case 7: state.CertificateReceived(); break;
            case 8: state.CertificateVerifyReceived(); break;
            case 9: state.ServerFinishedReceived((value & 0x80) != 0); break;
            case 10: state.ClientCertificateSent((value & 0x80) != 0); break;
            case 11: state.ClientApplicationSettingsSent(); break;
            case 12: state.ClientCertificateVerifySent(); break;
            case 13: state.ClientFinishedSent(); break;
            case 14: state.BeginClose(); break;
            case 15: state.Closed(); break;
            case 16: state.Fail(); break;
        }
    }

    private static void ApplyTls13ServerAction(Tls13ServerStateMachine state, byte value)
    {
        switch (value % 8)
        {
            case 0: state.TransportAccepted(); break;
            case 1: state.HelloRetryRequestSent(); break;
            case 2: state.ClientHelloAccepted(); break;
            case 3: state.ServerFlightSent(); break;
            case 4: state.ClientFinishedReceived(); break;
            case 5: state.BeginClose(); break;
            case 6: state.Closed(); break;
            case 7: state.Fail(); break;
        }
    }

    private static void ApplyTls12ClientAction(Tls12ClientStateMachine state, byte value)
    {
        switch (value % 22)
        {
            case 0: state.TransportConnected(); break;
            case 1: state.ClientHelloSent(); break;
            case 2: state.ServerHelloReceived((value & 0x80) != 0); break;
            case 3: state.AbbreviatedServerChangeCipherSpecReceived(); break;
            case 4: state.AbbreviatedServerFinishedReceived(); break;
            case 5: state.AbbreviatedClientChangeCipherSpecSent(); break;
            case 6: state.AbbreviatedClientFinishedSent(); break;
            case 7: state.CertificateReceived(); break;
            case 8: state.CertificateStatusReceived(); break;
            case 9: state.ServerKeyExchangeReceived(); break;
            case 10: state.CertificateRequestReceived(); break;
            case 11: state.ServerHelloDoneReceived(); break;
            case 12: state.ClientCertificateSent((value & 0x80) != 0); break;
            case 13: state.ClientKeyExchangeSent(); break;
            case 14: state.ClientCertificateVerifySent(); break;
            case 15: state.ClientChangeCipherSpecSent(); break;
            case 16: state.ClientFinishedSent(); break;
            case 17: state.NewSessionTicketReceived(); break;
            case 18: state.ServerChangeCipherSpecReceived(); break;
            case 19: state.ServerFinishedReceived(); break;
            case 20: state.BeginClose(); break;
            case 21:
                if ((value & 0x80) != 0) state.Fail();
                else state.Closed();
                break;
        }
    }

    private static void Deframe(byte[] input)
    {
        ProtocolBoundary(() =>
        {
            var deframer = new HandshakeDeframer(maximumMessageSize: 64 * 1024);
            var offset = 0;
            while (offset < input.Length)
            {
                var length = Math.Min(((offset * 13) % 31) + 1, input.Length - offset);
                deframer.Append(input.AsSpan(offset, length));
                while (deframer.TryRead(out _))
                {
                }
                offset += length;
            }
            deframer.EnsureEmptyAtEndOfStream();
        });
    }

    private static void ProtocolBoundary(Action action)
    {
        try { action(); }
        catch (TlsProtocolException) { }
    }

    private static void CaptureBoundary(Action action)
    {
        try { action(); }
        catch (TlsProtocolException) { }
        catch (TlsQuicTransportException) { }
        catch (NotSupportedException) { }
    }

    private static void JsonBoundary(Action action)
    {
        try { action(); }
        catch (InvalidDataException) { }
    }

    private static void QuicBoundary(Action action)
    {
        try { action(); }
        catch (TlsQuicTransportException) { }
    }

    private static void DnsBoundary(Action action)
    {
        try { action(); }
        catch (TlsEchDnsException) { }
    }
}
