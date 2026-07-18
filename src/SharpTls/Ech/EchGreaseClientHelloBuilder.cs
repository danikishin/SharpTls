using System.Security.Cryptography;
using SharpTls.Cryptography;
using SharpTls.IO;
using SharpTls.Protocol;

namespace SharpTls.Ech;

internal static class EchGreaseClientHelloBuilder
{
    private const int AeadTagLength = 16;

    internal static ClientHelloBuildResult Build(
        string serverName,
        ClientHelloConfiguration configuration,
        TlsEchGreaseConfiguration grease,
        IRandomSource randomSource,
        KeyShareSet keyShares,
        Tls13PskOffer? pskOffer = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(serverName);
        ArgumentNullException.ThrowIfNull(configuration);
        ArgumentNullException.ThrowIfNull(grease);
        ArgumentNullException.ThrowIfNull(randomSource);
        ArgumentNullException.ThrowIfNull(keyShares);
        if (!configuration.SupportedVersions.Contains(TlsProtocolVersion.Tls13))
        {
            throw new ArgumentException(
                "The GREASE ECH builder requires a TLS 1.3-capable ClientHello.",
                nameof(configuration));
        }

        ClientHelloBuildResult? lengthModel = null;
        byte[]? encodedLengthModel = null;
        byte[]? greaseBody = null;
        byte[]? encapsulatedPrivateKey = null;
        byte[]? encapsulatedKey = null;
        try
        {
            if (grease.PayloadLengths is null)
            {
                var innerConfiguration = EchClientHelloBuilder.InsertEchExtension(
                    configuration,
                    [1]);
                lengthModel = ClientHelloEncoder.Build(
                    serverName,
                    innerConfiguration,
                    randomSource,
                    new KeyShareSet(),
                    retry: null,
                    pskOffer: pskOffer);
                encodedLengthModel = EchClientHelloBuilder.EncodeAndPadInner(
                    lengthModel.EncodedHandshake,
                    maximumNameLength: 0);
            }

            var suite = SelectSuite(grease.CipherSuites, randomSource);
            Span<byte> configId = stackalloc byte[1];
            randomSource.Fill(configId);
            encapsulatedPrivateKey = new byte[X25519.KeyLength];
            encapsulatedKey = new byte[X25519.KeyLength];
            randomSource.Fill(encapsulatedPrivateKey);
            X25519.DerivePublicKey(encapsulatedPrivateKey, encapsulatedKey);
            var preEncryptionPayloadLength = grease.PayloadLengths is null
                ? encodedLengthModel!.Length
                : SelectPayloadLength(grease.PayloadLengths, randomSource);
            var payload = new byte[checked(preEncryptionPayloadLength + AeadTagLength)];
            randomSource.Fill(payload);
            try
            {
                greaseBody = EncodeOuterEch(
                    suite,
                    configId[0],
                    encapsulatedKey,
                    payload);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(payload);
            }

            var outerConfiguration = EchClientHelloBuilder.InsertEchExtension(
                configuration,
                greaseBody);
            var result = ClientHelloEncoder.Build(
                serverName,
                outerConfiguration,
                randomSource,
                keyShares,
                retry: null,
                pskOffer: pskOffer);
            return result;
        }
        catch
        {
            keyShares?.Dispose();
            throw;
        }
        finally
        {
            lengthModel?.Dispose();
            Zero(encodedLengthModel);
            Zero(greaseBody);
            Zero(encapsulatedPrivateKey);
            Zero(encapsulatedKey);
        }
    }

    internal static byte[] ReadExtensionBody(ReadOnlySpan<byte> encodedHandshake)
    {
        var body = new TlsBinaryReader(
            encodedHandshake[TlsConstants.HandshakeHeaderLength..]);
        _ = body.ReadUInt16();
        _ = body.ReadBytes(TlsConstants.RandomLength);
        _ = body.ReadVector8(TlsConstants.MaxSessionIdLength);
        _ = body.ReadVector16();
        _ = body.ReadVector8();
        var extensions = new TlsBinaryReader(body.ReadVector16());
        body.EnsureEnd("GREASE ClientHello");
        while (!extensions.End)
        {
            var type = extensions.ReadUInt16();
            var data = extensions.ReadVector16();
            if (type == (ushort)TlsExtensionType.EncryptedClientHello)
            {
                return data.ToArray();
            }
        }
        throw new InvalidOperationException("GREASE ClientHello omitted encrypted_client_hello.");
    }

    private static TlsHpkeSymmetricCipherSuite SelectSuite(
        IReadOnlyList<TlsHpkeSymmetricCipherSuite> suites,
        IRandomSource randomSource)
    {
        if (suites.Count == 0 || suites.Count > byte.MaxValue)
        {
            throw new ArgumentException("GREASE ECH requires between 1 and 255 HPKE suites.");
        }

        Span<byte> sample = stackalloc byte[1];
        var ceiling = byte.MaxValue - (byte.MaxValue + 1) % suites.Count;
        do
        {
            randomSource.Fill(sample);
        }
        while (sample[0] > ceiling);
        return suites[sample[0] % suites.Count];
    }

    private static int SelectPayloadLength(
        IReadOnlyList<int> payloadLengths,
        IRandomSource randomSource)
    {
        if (payloadLengths.Count == 0 || payloadLengths.Count > byte.MaxValue)
        {
            throw new ArgumentException(
                "GREASE ECH requires between 1 and 255 candidate payload lengths.");
        }

        Span<byte> sample = stackalloc byte[1];
        var ceiling = byte.MaxValue - (byte.MaxValue + 1) % payloadLengths.Count;
        do
        {
            randomSource.Fill(sample);
        }
        while (sample[0] > ceiling);
        return payloadLengths[sample[0] % payloadLengths.Count];
    }

    private static byte[] EncodeOuterEch(
        TlsHpkeSymmetricCipherSuite suite,
        byte configId,
        ReadOnlySpan<byte> encapsulatedKey,
        ReadOnlySpan<byte> payload)
    {
        var body = new TlsBinaryWriter();
        body.WriteUInt8(0);
        body.WriteUInt16((ushort)suite.KdfId);
        body.WriteUInt16((ushort)suite.AeadId);
        body.WriteUInt8(configId);
        body.WriteVector16(encapsulatedKey);
        body.WriteVector16(payload);
        return body.ToArray();
    }

    private static void Zero(byte[]? value)
    {
        if (value is not null)
        {
            CryptographicOperations.ZeroMemory(value);
        }
    }
}
