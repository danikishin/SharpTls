using System.Security.Cryptography;
using SharpTls.Certificates;
using SharpTls.Cryptography;
using SharpTls.Handshake;
using SharpTls.IO;
using SharpTls.Protocol;
using SharpTls.Tests.Certificates;

namespace SharpTls.Tests.Handshake;

public sealed class Tls12ServerFlightParserTests
{
    [Fact]
    public void Tls12CertificateListParsesWithoutTls13EntryExtensions()
    {
        using var pki = TestPki.Create();
        var body = EncodeCertificateList(pki.Leaf.RawData, pki.Root.RawData);

        using var parsed = Tls12CertificateMessageParser.Parse(body, TlsLimits.Default);

        Assert.Equal(2, parsed.Certificates.Count);
        Assert.Equal(pki.Leaf.RawData, parsed.Leaf.RawData);
    }

    [Theory]
    [InlineData("000000")]
    [InlineData("00000400000501")]
    [InlineData("000003000000")]
    public void EmptyTruncatedAndEmptyDerCertificateListsAreRejected(string hex)
    {
        var exception = Assert.Throws<TlsProtocolException>(() =>
            Tls12CertificateMessageParser.Parse(
                Convert.FromHexString(hex),
                TlsLimits.Default));

        Assert.True(exception.Alert is TlsAlertDescription.BadCertificate or TlsAlertDescription.DecodeError);
    }

    [Fact]
    public void RsaPssServerKeyExchangeParsesVerifiesAndAgrees()
    {
        using var pki = TestPki.Create();
        using var offer = ClientHelloProfiles.UTlsAndroid11OkHttp.BuildSecure("example.com");
        using var serverShare = KeyShareFactory.Create(NamedGroup.Secp256r1);
        var serverRandom = RandomNumberGenerator.GetBytes(32);
        var body = BuildServerKeyExchange(
            serverShare,
            SignatureScheme.RsaPssRsaeSha256,
            offer.Random,
            serverRandom,
            data => ((RSA)pki.LeafKey).SignData(
                data,
                HashAlgorithmName.SHA256,
                RSASignaturePadding.Pss));

        var parsed = Tls12ServerKeyExchangeParser.Parse(body, offer.Configuration);
        Tls12ServerKeyExchangeParser.VerifySignature(
            parsed,
            pki.Leaf,
            Tls12CipherSuiteInfo.Get(TlsCipherSuite.TlsEcdheRsaWithAes128GcmSha256),
            offer.Random,
            serverRandom);
        using var clientShare = KeyShareFactory.Create(parsed.SelectedGroup);
        var clientSecret = clientShare.DeriveSharedSecret(parsed.PeerPublicKey);
        var serverSecret = serverShare.DeriveSharedSecret(clientShare.PublicKey.Span);
        try
        {
            Assert.Equal(clientSecret, serverSecret);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(clientSecret);
            CryptographicOperations.ZeroMemory(serverSecret);
        }
    }

    [Fact]
    public void P521ServerKeyExchangeParsesAndAgrees()
    {
        var profile = ClientHelloProfiles.Custom(builder => builder
            .WithLegacyTls12ClientHello()
            .WithCipherSuites(TlsCipherSuite.TlsEcdheRsaWithAes128GcmSha256)
            .WithSupportedGroups(NamedGroup.Secp521r1)
            .WithSignatureAlgorithms(SignatureScheme.RsaPssRsaeSha256)
            .WithExtensionLayout(
                ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.ServerName),
                ClientHelloExtensionSpec.Raw(23, []),
                ClientHelloExtensionSpec.Raw(0xFF01, [0]),
                ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.SupportedGroups),
                ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.SignatureAlgorithms)));
        using var offer = profile.BuildSecure("example.com");
        using var serverShare = KeyShareFactory.Create(NamedGroup.Secp521r1);
        var body = BuildUnsignedServerKeyExchange(
            NamedGroup.Secp521r1,
            serverShare.PublicKey.Span,
            SignatureScheme.RsaPssRsaeSha256,
            [1]);

        var parsed = Tls12ServerKeyExchangeParser.Parse(body, offer.Configuration);
        using var clientShare = KeyShareFactory.Create(parsed.SelectedGroup);
        var clientSecret = clientShare.DeriveSharedSecret(parsed.PeerPublicKey);
        var serverSecret = serverShare.DeriveSharedSecret(clientShare.PublicKey.Span);
        try
        {
            Assert.Equal(NamedGroup.Secp521r1, parsed.SelectedGroup);
            Assert.Equal(clientSecret, serverSecret);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(clientSecret);
            CryptographicOperations.ZeroMemory(serverSecret);
        }
    }

    [Fact]
    public void RsaPssSubjectPublicKeyVerifiesTls12ServerKeyExchange()
    {
        using var pki = RsaPssTestCertificate.Create(
            HashAlgorithmName.SHA256,
            serverAuthentication: true);
        var profile = ClientHelloProfiles.Custom(builder => builder
            .WithLegacyTls12ClientHello()
            .WithCipherSuites(TlsCipherSuite.TlsEcdheRsaWithAes128GcmSha256)
            .WithSupportedGroups(NamedGroup.Secp256r1)
            .WithSignatureAlgorithms(SignatureScheme.RsaPssPssSha256)
            .WithExtensionLayout(
                ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.ServerName),
                ClientHelloExtensionSpec.Raw(23, []),
                ClientHelloExtensionSpec.Raw(0xFF01, [0]),
                ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.SupportedGroups),
                ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.SignatureAlgorithms)));
        using var offer = profile.BuildSecure("example.com");
        using var serverShare = KeyShareFactory.Create(NamedGroup.Secp256r1);
        var serverRandom = RandomNumberGenerator.GetBytes(32);
        var body = BuildServerKeyExchange(
            serverShare,
            SignatureScheme.RsaPssPssSha256,
            offer.Random,
            serverRandom,
            data => pki.Key.SignData(
                data,
                HashAlgorithmName.SHA256,
                RSASignaturePadding.Pss));

        var parsed = Tls12ServerKeyExchangeParser.Parse(body, offer.Configuration);
        Tls12ServerKeyExchangeParser.VerifySignature(
            parsed,
            pki.Certificate,
            Tls12CipherSuiteInfo.Get(TlsCipherSuite.TlsEcdheRsaWithAes128GcmSha256),
            offer.Random,
            serverRandom);

        Assert.Equal(SignatureScheme.RsaPssPssSha256, parsed.SignatureScheme);
    }

    [Fact]
    public void EcdsaServerKeyExchangeParsesAndVerifies()
    {
        using var pki = TestPki.Create(ecdsaLeaf: true);
        using var offer = ClientHelloProfiles.UTlsAndroid11OkHttp.BuildSecure("example.com");
        using var serverShare = KeyShareFactory.Create(NamedGroup.X25519);
        var serverRandom = RandomNumberGenerator.GetBytes(32);
        var body = BuildServerKeyExchange(
            serverShare,
            SignatureScheme.EcdsaSecp256r1Sha256,
            offer.Random,
            serverRandom,
            data => ((ECDsa)pki.LeafKey).SignData(
                data,
                HashAlgorithmName.SHA256,
                DSASignatureFormat.Rfc3279DerSequence));

        var parsed = Tls12ServerKeyExchangeParser.Parse(body, offer.Configuration);
        Tls12ServerKeyExchangeParser.VerifySignature(
            parsed,
            pki.Leaf,
            Tls12CipherSuiteInfo.Get(TlsCipherSuite.TlsEcdheEcdsaWithAes128GcmSha256),
            offer.Random,
            serverRandom);

        Assert.Equal(NamedGroup.X25519, parsed.SelectedGroup);
    }

    [Fact]
    public void TamperedSignatureWrongCertificateTypeAndSha1FailClosed()
    {
        using var rsaPki = TestPki.Create();
        using var ecdsaPki = TestPki.Create(ecdsaLeaf: true);
        using var offer = ClientHelloProfiles.UTlsAndroid11OkHttp.BuildSecure("example.com");
        using var serverShare = KeyShareFactory.Create(NamedGroup.Secp256r1);
        var serverRandom = RandomNumberGenerator.GetBytes(32);
        var body = BuildServerKeyExchange(
            serverShare,
            SignatureScheme.RsaPssRsaeSha256,
            offer.Random,
            serverRandom,
            data => ((RSA)rsaPki.LeafKey).SignData(
                data,
                HashAlgorithmName.SHA256,
                RSASignaturePadding.Pss));
        var parsed = Tls12ServerKeyExchangeParser.Parse(body, offer.Configuration);
        parsed.Signature[^1] ^= 1;

        Assert.Equal(
            TlsAlertDescription.DecryptError,
            Assert.Throws<TlsProtocolException>(() =>
                Tls12ServerKeyExchangeParser.VerifySignature(
                    parsed,
                    rsaPki.Leaf,
                    Tls12CipherSuiteInfo.Get(TlsCipherSuite.TlsEcdheRsaWithAes128GcmSha256),
                    offer.Random,
                    serverRandom)).Alert);
        Assert.Equal(
            TlsAlertDescription.UnsupportedCertificate,
            Assert.Throws<TlsProtocolException>(() =>
                Tls12ServerKeyExchangeParser.VerifySignature(
                    parsed with { Signature = [1] },
                    ecdsaPki.Leaf,
                    Tls12CipherSuiteInfo.Get(TlsCipherSuite.TlsEcdheRsaWithAes128GcmSha256),
                    offer.Random,
                    serverRandom)).Alert);

        var sha1Body = BuildServerKeyExchange(
            serverShare,
            SignatureScheme.RsaPkcs1Sha1,
            offer.Random,
            serverRandom,
            _ => [1]);
        Assert.Equal(
            TlsAlertDescription.HandshakeFailure,
            Assert.Throws<TlsProtocolException>(() =>
                Tls12ServerKeyExchangeParser.Parse(sha1Body, offer.Configuration)).Alert);
    }

    [Fact]
    public void UnoferedGroupAndMalformedPointAreRejected()
    {
        var profile = ClientHelloProfiles.Custom(builder => builder
            .WithLegacyTls12ClientHello()
            .WithCipherSuites(TlsCipherSuite.TlsEcdheRsaWithAes128GcmSha256)
            .WithSupportedGroups(NamedGroup.Secp256r1)
            .WithSignatureAlgorithms(SignatureScheme.RsaPssRsaeSha256)
            .WithExtensionLayout(
                ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.ServerName),
                ClientHelloExtensionSpec.Raw(23, []),
                ClientHelloExtensionSpec.Raw(0xFF01, [0]),
                ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.SupportedGroups),
                ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.SignatureAlgorithms)));
        using var offer = profile.BuildSecure("example.com");
        using var p384 = KeyShareFactory.Create(NamedGroup.Secp384r1);
        var body = BuildUnsignedServerKeyExchange(
            p384.Group,
            p384.PublicKey.Span,
            SignatureScheme.RsaPssRsaeSha256,
            [1]);

        Assert.Equal(
            TlsAlertDescription.IllegalParameter,
            Assert.Throws<TlsProtocolException>(() =>
                Tls12ServerKeyExchangeParser.Parse(body, offer.Configuration)).Alert);

        var malformed = BuildUnsignedServerKeyExchange(
            NamedGroup.Secp256r1,
            new byte[65],
            SignatureScheme.RsaPssRsaeSha256,
            [1]);
        Assert.Equal(
            TlsAlertDescription.IllegalParameter,
            Assert.Throws<TlsProtocolException>(() =>
                Tls12ServerKeyExchangeParser.Parse(malformed, offer.Configuration)).Alert);
    }

    [Fact]
    public void CertificateStatusAndServerHelloDoneAreStrictlyFramed()
    {
        Assert.Equal(
            new byte[] { 1, 2, 3 },
            Tls12CertificateStatusParser.ParseOcspResponse(
                [1, 0, 0, 3, 1, 2, 3],
                TlsLimits.Default));
        Tls12ServerHelloDoneParser.Parse([]);

        Assert.Equal(
            TlsAlertDescription.DecodeError,
            Assert.Throws<TlsProtocolException>(() =>
                Tls12CertificateStatusParser.ParseOcspResponse(
                    [1, 0, 0, 0],
                    TlsLimits.Default)).Alert);
        Assert.Equal(
            TlsAlertDescription.DecodeError,
            Assert.Throws<TlsProtocolException>(() =>
                Tls12ServerHelloDoneParser.Parse([0])).Alert);
    }

    private static byte[] EncodeCertificateList(params byte[][] certificates)
    {
        var list = new TlsBinaryWriter();
        foreach (var certificate in certificates)
        {
            list.WriteVector24(certificate);
        }

        var body = new TlsBinaryWriter();
        body.WriteVector24(list.WrittenSpan);
        return body.ToArray();
    }

    private static byte[] BuildServerKeyExchange(
        IKeyShare serverShare,
        SignatureScheme scheme,
        ReadOnlySpan<byte> clientRandom,
        ReadOnlySpan<byte> serverRandom,
        Func<byte[], byte[]> signer)
    {
        var parameters = EncodeParameters(serverShare.Group, serverShare.PublicKey.Span);
        byte[] signedContent = [.. clientRandom, .. serverRandom, .. parameters];
        var signature = signer(signedContent);
        return BuildUnsignedServerKeyExchange(
            serverShare.Group,
            serverShare.PublicKey.Span,
            scheme,
            signature);
    }

    private static byte[] BuildUnsignedServerKeyExchange(
        NamedGroup group,
        ReadOnlySpan<byte> publicKey,
        SignatureScheme scheme,
        ReadOnlySpan<byte> signature)
    {
        var body = new TlsBinaryWriter();
        body.WriteBytes(EncodeParameters(group, publicKey));
        body.WriteUInt16((ushort)scheme);
        body.WriteVector16(signature);
        return body.ToArray();
    }

    private static byte[] EncodeParameters(NamedGroup group, ReadOnlySpan<byte> publicKey)
    {
        var parameters = new TlsBinaryWriter();
        parameters.WriteUInt8(3);
        parameters.WriteUInt16((ushort)group);
        parameters.WriteVector8(publicKey);
        return parameters.ToArray();
    }
}
