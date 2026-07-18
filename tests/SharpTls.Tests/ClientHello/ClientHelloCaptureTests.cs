using SharpTls.Handshake;
using SharpTls.IO;
using SharpTls.Protocol;
using SharpTls.Quic;

namespace SharpTls.Tests.ClientHello;

public sealed class ClientHelloCaptureTests
{
    [Fact]
    public void BareSharpTlsCaptureRoundTripsByteForByteWithSameSeed()
    {
        var profile = CreateImportableProfile();
        var seed = new byte[] { 1, 4, 1, 4 };
        var captured = profile.BuildDeterministicForTesting("example.com", seed);

        var imported = ClientHelloCapture.Import(captured);
        var rebuilt = ClientHelloProfiles.FromSpec(imported.Spec)
            .BuildDeterministicForTesting("example.com", seed);

        Assert.False(imported.WasRecordFramed);
        Assert.Equal("example.com", imported.CapturedServerName);
        Assert.Equal(captured, rebuilt);
    }

    [Fact]
    public void FragmentedRecordCaptureIsReassembledAndNormalized()
    {
        var profile = CreateImportableProfile();
        var seed = new byte[] { 2, 7, 1, 8 };
        var captured = profile.BuildDeterministicForTesting("example.com", seed);
        var recordWire = FrameRecords(captured, 7, 19, captured.Length - 26);

        var imported = ClientHelloCapture.Import(recordWire);
        var rebuilt = ClientHelloProfiles.FromSpec(imported.Spec)
            .BuildDeterministicForTesting("example.com", seed);

        Assert.True(imported.WasRecordFramed);
        Assert.Equal(captured, rebuilt);
        Assert.Equal([7, 19, captured.Length - 26], imported.RecordFragmentSizes);
        Assert.Equal([0x0303, 0x0303, 0x0303], imported.RecordVersions);
        var recreatedPolicy = Assert.IsType<TlsRecordFragmentation>(
            imported.CreateRecordFragmentation());
        Assert.Equal(imported.RecordFragmentSizes.Max(), recreatedPolicy.MaximumFragmentSize);
        Assert.Equal(imported.RecordFragmentSizes, recreatedPolicy.ExplicitFragmentSizes);
    }

    [Fact]
    public void FixedSessionIdIsImportedOnlyWhenExplicitlyRequested()
    {
        var profile = ClientHelloProfiles.Custom(builder => builder.WithSessionId([9, 8, 7]));
        var captured = profile.BuildDeterministicForTesting("example.com", [3]);

        var defaultImport = ClientHelloCapture.Import(captured);
        var preservingImport = ClientHelloCapture.Import(
            captured,
            options: new ClientHelloImportOptions { PreserveSessionId = true });

        Assert.Null(defaultImport.Spec.SessionId);
        Assert.Equal(new byte[] { 9, 8, 7 }, preservingImport.Spec.SessionId);
    }

    [Fact]
    public void TruncatedRecordAndTrailingHandshakeBytesAreRejected()
    {
        var captured = CreateImportableProfile()
            .BuildDeterministicForTesting("example.com", [5]);
        var framed = FrameRecords(captured, captured.Length);

        Assert.Throws<TlsProtocolException>(() => ClientHelloCapture.Import(framed[..^1]));
        Assert.Throws<TlsProtocolException>(() => ClientHelloCapture.Import([.. captured, 0]));
    }

    [Fact]
    public void BareCaptureHasNoInventedRecordMetadataAndInvalidRecordVersionIsRejected()
    {
        var captured = CreateImportableProfile()
            .BuildDeterministicForTesting("example.com", [5, 1]);
        var bare = ClientHelloCapture.Import(captured);

        Assert.Empty(bare.RecordFragmentSizes);
        Assert.Empty(bare.RecordVersions);
        Assert.Null(bare.CreateRecordFragmentation());

        var framed = FrameRecords(captured, captured.Length);
        framed[1] = 0x02;
        framed[2] = 0x00;
        var exception = Assert.Throws<TlsProtocolException>(() =>
            ClientHelloCapture.Import(framed));
        Assert.Equal(TlsAlertDescription.ProtocolVersion, exception.Alert);
    }

    [Fact]
    public void UnsupportedCapturedGroupIsReportedWithoutAdvertisingIt()
    {
        var captured = CreateImportableProfile()
            .BuildDeterministicForTesting("example.com", [6]);
        ReplaceFirstSupportedGroup(captured, 0xFE00);

        var exception = Assert.Throws<NotSupportedException>(() =>
            ClientHelloCapture.Import(captured));

        Assert.Contains("group", exception.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void IncoherentCapturedSemanticExtensionsUseProtocolErrorBoundary()
    {
        var original = ClientHelloProfiles.Custom(builder => builder
            .WithTls13()
            .WithCipherSuites(TlsCipherSuite.TlsAes128GcmSha256)
            .WithSupportedGroups(NamedGroup.Secp256r1)
            .WithKeyShares(NamedGroup.Secp256r1)
            .WithSignatureAlgorithms(SignatureScheme.EcdsaSecp256r1Sha256)
            .WithDelegatedCredentials(SignatureScheme.EcdsaSecp256r1Sha256)
            .WithExtensionLayout(
                ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.ServerName),
                ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.SupportedVersions),
                ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.SupportedGroups),
                ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.SignatureAlgorithms),
                ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.DelegatedCredential),
                ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.KeyShare)))
            .BuildDeterministicForTesting("example.com", [4, 2, 4, 2]);
        var captured = RemoveExtension(original, TlsExtensionType.SupportedVersions);

        var exception = Assert.Throws<TlsProtocolException>(() =>
            ClientHelloCapture.Import(captured));

        Assert.Equal(TlsAlertDescription.IllegalParameter, exception.Alert);
        Assert.IsType<InvalidOperationException>(exception.InnerException);
    }

    [Fact]
    public void P521CaptureRoundTripsWithFreshDeterministicShare()
    {
        var profile = ClientHelloProfiles.Custom(builder => builder
            .WithSupportedGroups(NamedGroup.Secp521r1)
            .WithKeyShares(NamedGroup.Secp521r1));
        var captured = profile.BuildDeterministicForTesting("example.com", [5, 2, 1]);

        var imported = ClientHelloCapture.Import(captured);
        var rebuilt = ClientHelloProfiles.FromSpec(imported.Spec)
            .BuildDeterministicForTesting("example.com", [5, 2, 1]);

        Assert.Equal(captured, rebuilt);
    }

    [Fact]
    public void X25519CaptureRoundTripsWithFreshDeterministicShare()
    {
        var profile = ClientHelloProfiles.Custom(builder => builder
            .WithSupportedGroups(NamedGroup.X25519)
            .WithKeyShares(NamedGroup.X25519));
        var captured = profile.BuildDeterministicForTesting("example.com", [2, 5, 5, 1, 9]);

        var imported = ClientHelloCapture.Import(captured);
        var rebuilt = ClientHelloProfiles.FromSpec(imported.Spec)
            .BuildDeterministicForTesting("example.com", [2, 5, 5, 1, 9]);

        Assert.Equal(captured, rebuilt);
    }

    [Fact]
    public void MultiValueGreaseCaptureInfersAndReproducesEqualityPattern()
    {
        var policy = ClientHelloGreasePolicy.Create(0, 1, 0, 2, 1);
        var profile = ClientHelloProfiles.Custom(builder => builder
            .WithGrease(policy)
            .WithCipherSuites(TlsCipherSuite.TlsAes128GcmSha256)
            .WithSupportedGroups(NamedGroup.Secp256r1));
        var seed = new byte[] { 8, 6, 7, 5 };
        var captured = profile.BuildDeterministicForTesting("example.com", seed);

        var imported = ClientHelloCapture.Import(captured);
        var rebuilt = ClientHelloProfiles.FromSpec(imported.Spec)
            .BuildDeterministicForTesting("example.com", seed);

        Assert.Equal(captured, rebuilt);
        Assert.Equal(new[] { 0, 1, 0, 2, 1 }, imported.Spec.GreasePolicy!.ValueClasses);
    }

    [Fact]
    public void GreaseEchCaptureIsNormalizedToFreshSemanticGeneration()
    {
        var profile = ClientHelloProfiles.Custom(builder => builder
            .WithGreaseEncryptedClientHello(
                [new TlsHpkeSymmetricCipherSuite(
                    TlsHpkeKdfId.HkdfSha256,
                    TlsHpkeAeadId.Aes128Gcm)],
                160)
            .WithExtensionLayout(
                ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.ServerName),
                ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.SupportedVersions),
                ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.EncryptedClientHello),
                ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.SupportedGroups),
                ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.SignatureAlgorithms),
                ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.KeyShare)));
        var seed = new byte[] { 9, 8, 4, 9 };
        var captured = profile.BuildDeterministicForTesting("example.com", seed);

        var imported = ClientHelloCapture.Import(captured);
        var rebuilt = ClientHelloProfiles.FromSpec(imported.Spec)
            .BuildDeterministicForTesting("example.com", seed);

        Assert.True(imported.Spec.GreaseEncryptedClientHello);
        Assert.Equal(profile.Spec.GreaseEchCipherSuites, imported.Spec.GreaseEchCipherSuites);
        Assert.Equal([160], imported.Spec.GreaseEchPayloadLengths);
        Assert.Equal(captured, rebuilt);
        Assert.Equal(
            ClientHelloExtensionKind.EncryptedClientHello,
            imported.Spec.Extensions[2].BuiltInKind);
    }

    [Fact]
    public void MalformedCapturedEchIsRejectedInsteadOfReplayedAsRawData()
    {
        var profile = ClientHelloProfiles.Custom(builder => builder.WithExtensionLayout(
            ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.ServerName),
            ClientHelloExtensionSpec.Raw((ushort)TlsExtensionType.EncryptedClientHello, [0]),
            ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.SupportedVersions),
            ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.SupportedGroups),
            ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.SignatureAlgorithms),
            ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.KeyShare)));
        var captured = profile.BuildDeterministicForTesting("example.com", [1, 2, 3]);

        Assert.Throws<TlsProtocolException>(() => ClientHelloCapture.Import(captured));
    }

    [Fact]
    public void TruncatedCapturedQuicTransportParameterIsRejectedAtTheQuicBoundary()
    {
        var profile = ClientHelloProfiles.Custom(builder => builder.WithExtensionLayout(
            ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.ServerName),
            ClientHelloExtensionSpec.Raw(0xFDE8, [0x40]),
            ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.SupportedVersions),
            ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.SupportedGroups),
            ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.SignatureAlgorithms),
            ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.KeyShare)));
        var captured = profile.BuildDeterministicForTesting("example.com", [4, 2, 4, 2]);
        var rawExtensionOffset = captured.AsSpan().IndexOf(
            new byte[] { 0xFD, 0xE8, 0, 1, 0x40 });
        Assert.True(rawExtensionOffset >= 0);
        captured[rawExtensionOffset] = 0;
        captured[rawExtensionOffset + 1] = (byte)TlsExtensionType.QuicTransportParameters;

        Assert.Throws<TlsQuicTransportException>(() => ClientHelloCapture.Import(captured));
    }

    private static ClientHelloProfile CreateImportableProfile() =>
        ClientHelloProfiles.Custom(builder => builder
            .WithGrease()
            .WithCipherSuites(TlsCipherSuite.TlsAes128GcmSha256)
            .WithSupportedGroups(NamedGroup.Secp256r1)
            .WithCertificateSignatureAlgorithms(
                SignatureScheme.RsaPkcs1Sha256,
                SignatureScheme.EcdsaSecp256r1Sha256)
            .WithDelegatedCredentials(SignatureScheme.EcdsaSecp256r1Sha256)
            .WithAlpn("http/1.1")
            .WithApplicationSettings(
                TlsApplicationSettingsCodePoint.ChromeExperiment,
                "http/1.1")
            .WithRecordSizeLimit(4096)
            .WithPadding(5)
            .WithExtensionLayout(
                ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.Grease),
                ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.ServerName),
                ClientHelloExtensionSpec.Raw(0xFDE8, [1, 2]),
                ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.SupportedVersions),
                ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.SupportedGroups),
                ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.SignatureAlgorithms),
                ClientHelloExtensionSpec.BuiltIn(
                    ClientHelloExtensionKind.SignatureAlgorithmsCert),
                ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.DelegatedCredential),
                ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.KeyShare),
                ClientHelloExtensionSpec.BuiltIn(
                    ClientHelloExtensionKind.ApplicationLayerProtocolNegotiation),
                ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.ApplicationSettings),
                ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.RecordSizeLimit),
                ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.Padding)));

    private static byte[] FrameRecords(byte[] handshake, params int[] fragmentSizes)
    {
        var writer = new TlsBinaryWriter();
        var offset = 0;
        foreach (var length in fragmentSizes)
        {
            writer.WriteUInt8((byte)TlsContentType.Handshake);
            writer.WriteUInt16(TlsConstants.LegacyRecordVersion);
            writer.WriteUInt16((ushort)length);
            writer.WriteBytes(handshake.AsSpan(offset, length));
            offset += length;
        }
        Assert.Equal(handshake.Length, offset);
        return writer.ToArray();
    }

    private static void ReplaceFirstSupportedGroup(byte[] handshake, ushort replacement)
    {
        var reader = new TlsBinaryReader(handshake);
        _ = reader.ReadUInt8();
        var body = new TlsBinaryReader(reader.ReadBytes(reader.ReadUInt24()));
        _ = body.ReadUInt16();
        _ = body.ReadBytes(TlsConstants.RandomLength);
        _ = body.ReadVector8();
        _ = body.ReadVector16();
        _ = body.ReadVector8();
        var extensions = body.ReadVector16();
        var extensionReader = new TlsBinaryReader(extensions);
        var extensionsOffset = handshake.Length - extensions.Length;
        var scanned = 0;
        while (!extensionReader.End)
        {
            var type = extensionReader.ReadUInt16();
            var data = extensionReader.ReadVector16();
            if (type == (ushort)TlsExtensionType.SupportedGroups)
            {
                var dataOffset = extensionsOffset + scanned + 4;
                var vectorLength = (handshake[dataOffset] << 8) | handshake[dataOffset + 1];
                Assert.True(vectorLength >= 2);
                var firstGroupOffset = dataOffset + 2;
                if ((handshake[firstGroupOffset] & 0x0F) == 0x0A)
                {
                    firstGroupOffset += 2;
                }
                handshake[firstGroupOffset] = (byte)(replacement >> 8);
                handshake[firstGroupOffset + 1] = (byte)replacement;
                return;
            }

            scanned += 4 + data.Length;
        }

        throw new InvalidOperationException("Test ClientHello has no supported_groups extension.");
    }

    private static byte[] RemoveExtension(byte[] handshake, TlsExtensionType removedType)
    {
        var message = new TlsBinaryReader(handshake);
        Assert.Equal((byte)HandshakeType.ClientHello, message.ReadUInt8());
        var body = new TlsBinaryReader(message.ReadBytes(message.ReadUInt24()));
        message.EnsureEnd("test ClientHello");
        var legacyVersion = body.ReadUInt16();
        var random = body.ReadBytes(TlsConstants.RandomLength).ToArray();
        var sessionId = body.ReadVector8().ToArray();
        var cipherSuites = body.ReadVector16().ToArray();
        var compression = body.ReadVector8().ToArray();
        var extensions = new TlsBinaryReader(body.ReadVector16());
        body.EnsureEnd("test ClientHello body");
        var rebuiltExtensions = new TlsBinaryWriter();
        var removed = false;
        while (!extensions.End)
        {
            var type = extensions.ReadUInt16();
            var data = extensions.ReadVector16();
            if (type == (ushort)removedType)
            {
                removed = true;
                continue;
            }
            rebuiltExtensions.WriteUInt16(type);
            rebuiltExtensions.WriteVector16(data);
        }
        Assert.True(removed);

        var rebuiltBody = new TlsBinaryWriter();
        rebuiltBody.WriteUInt16(legacyVersion);
        rebuiltBody.WriteBytes(random);
        rebuiltBody.WriteVector8(sessionId);
        rebuiltBody.WriteVector16(cipherSuites);
        rebuiltBody.WriteVector8(compression);
        rebuiltBody.WriteVector16(rebuiltExtensions.WrittenSpan);
        return HandshakeMessage.Encode(HandshakeType.ClientHello, rebuiltBody.WrittenSpan);
    }

}
