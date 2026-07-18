using System.IO.Compression;
using SharpTls.Certificates;
using SharpTls.Handshake;
using SharpTls.IO;
using SharpTls.Protocol;

namespace SharpTls.Tests.Certificates;

public sealed class CompressedCertificateTests
{
    [Theory]
    [InlineData((ushort)1)]
    [InlineData((ushort)2)]
    public void ManagedAlgorithmsRoundTripExactly(ushort algorithm)
    {
        var certificateBody = Enumerable.Range(0, 8_193)
            .Select(index => (byte)((index * 31) & 0xFF))
            .ToArray();
        var compressed = Compress(certificateBody, algorithm);
        var message = Encode(algorithm, certificateBody.Length, compressed);

        var decompressed = CompressedCertificateParser.Decompress(
            message,
            CreateOffer(algorithm),
            TlsLimits.Default);

        Assert.Equal(certificateBody, decompressed);
    }

    [Theory]
    [InlineData(-1)]
    [InlineData(1)]
    public void DeclaredLengthMismatchIsRejected(int adjustment)
    {
        var certificateBody = Enumerable.Repeat((byte)0xA5, 4_096).ToArray();
        var compressed = Compress(certificateBody, algorithm: 2);
        var message = Encode(2, certificateBody.Length + adjustment, compressed);

        var exception = Assert.Throws<TlsProtocolException>(() =>
            CompressedCertificateParser.Decompress(
                message,
                CreateOffer(2),
                TlsLimits.Default));

        Assert.Equal(TlsAlertDescription.BadCertificate, exception.Alert);
    }

    [Fact]
    public void UnoferredAndCorruptAlgorithmsAreRejected()
    {
        var body = Enumerable.Repeat((byte)7, 256).ToArray();
        var zlib = Encode(1, body.Length, Compress(body, 1));
        var corrupt = Encode(2, body.Length, [1, 2, 3, 4, 5]);

        var unoffered = Assert.Throws<TlsProtocolException>(() =>
            CompressedCertificateParser.Decompress(zlib, CreateOffer(2), TlsLimits.Default));
        var invalid = Assert.Throws<TlsProtocolException>(() =>
            CompressedCertificateParser.Decompress(corrupt, CreateOffer(2), TlsLimits.Default));

        Assert.Equal(TlsAlertDescription.BadCertificate, unoffered.Alert);
        Assert.Equal(TlsAlertDescription.BadCertificate, invalid.Alert);
    }

    [Fact]
    public void DeclaredOutputIsBoundedBeforeDecompression()
    {
        var writer = new TlsBinaryWriter();
        writer.WriteUInt16(2);
        writer.WriteUInt24(TlsLimits.Default.MaxHandshakeMessageSize + 1);
        writer.WriteVector24([1]);

        var exception = Assert.Throws<TlsProtocolException>(() =>
            CompressedCertificateParser.Decompress(
                writer.WrittenSpan,
                CreateOffer(2),
                TlsLimits.Default));

        Assert.Equal(TlsAlertDescription.BadCertificate, exception.Alert);
    }

    [Theory]
    [InlineData(TlsCertificateCompressionAlgorithm.Zlib)]
    [InlineData(TlsCertificateCompressionAlgorithm.Brotli)]
    public void ServerEncoderProducesAnExactlyRecoverableCertificateBody(
        TlsCertificateCompressionAlgorithm algorithm)
    {
        using var pki = TestPki.Create();
        using var credential = new TlsServerCertificate(
            pki.Leaf,
            (System.Security.Cryptography.RSA)pki.LeafKey,
            [pki.Root]);
        var uncompressed = Tls13ServerHandshakeMessages.BuildCertificate(
            credential,
            TlsLimits.Default);
        var compressed = Tls13ServerHandshakeMessages.BuildCompressedCertificate(
            credential,
            TlsLimits.Default,
            algorithm);

        Assert.Equal((byte)HandshakeType.CompressedCertificate, compressed[0]);
        var recovered = CompressedCertificateParser.Decompress(
            compressed.AsSpan(TlsConstants.HandshakeHeaderLength),
            CreateOffer((ushort)algorithm),
            TlsLimits.Default);
        Assert.Equal(uncompressed.AsSpan(TlsConstants.HandshakeHeaderLength).ToArray(), recovered);
    }

    [Theory]
    [InlineData(new byte[] { 0 })]
    [InlineData(new byte[] { 1, 0 })]
    [InlineData(new byte[] { 4, 0, 2, 0, 2 })]
    public void ServerParserRejectsMalformedOrDuplicateCompressionOffers(byte[] extensionBody)
    {
        var profile = ClientHelloProfiles.Custom(builder => builder
            .WithTls13()
            .WithCipherSuites(TlsCipherSuite.TlsAes128GcmSha256)
            .WithSupportedGroups(NamedGroup.Secp256r1)
            .WithKeyShares(NamedGroup.Secp256r1)
            .WithExtensionLayout(
                ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.ServerName),
                ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.SupportedVersions),
                ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.SupportedGroups),
                ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.SignatureAlgorithms),
                ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.KeyShare),
                ClientHelloExtensionSpec.Raw(
                    (ushort)TlsExtensionType.CompressCertificate,
                    extensionBody)));
        var encoded = profile.BuildDeterministicForTesting("example.com", [4, 3, 2, 1]);

        Assert.Throws<TlsProtocolException>(() => Tls13ClientHelloParser.Parse(
            encoded.AsSpan(TlsConstants.HandshakeHeaderLength)));
    }

    private static ClientHelloConfiguration CreateOffer(ushort algorithm) =>
        ClientHelloProfiles.Custom(builder => builder.WithExtensionLayout(
            ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.ServerName),
            ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.SupportedVersions),
            ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.SupportedGroups),
            ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.SignatureAlgorithms),
            ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.KeyShare),
            ClientHelloExtensionSpec.Raw(27, [2, (byte)(algorithm >> 8), (byte)algorithm])))
        .Spec
        .SnapshotConfiguration();

    private static byte[] Encode(ushort algorithm, int uncompressedLength, byte[] compressed)
    {
        var writer = new TlsBinaryWriter();
        writer.WriteUInt16(algorithm);
        writer.WriteUInt24(uncompressedLength);
        writer.WriteVector24(compressed);
        return writer.ToArray();
    }

    private static byte[] Compress(byte[] value, ushort algorithm)
    {
        using var output = new MemoryStream();
        using (Stream compressor = algorithm switch
        {
            1 => new ZLibStream(output, CompressionLevel.SmallestSize, leaveOpen: true),
            2 => new BrotliStream(output, CompressionLevel.SmallestSize, leaveOpen: true),
            _ => throw new ArgumentOutOfRangeException(nameof(algorithm)),
        })
        {
            compressor.Write(value);
        }
        return output.ToArray();
    }
}
