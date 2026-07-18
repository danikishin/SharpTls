using System.Buffers.Binary;
using System.Security.Cryptography;
using SharpTls.Cryptography;
using SharpTls.Handshake;
using SharpTls.Protocol;

namespace SharpTls.Ech;

internal static class EchAcceptanceConfirmation
{
    internal const int ConfirmationLength = 8;

    private static ReadOnlySpan<byte> HelloRetryRequestRandom =>
    [
        0xCF, 0x21, 0xAD, 0x74, 0xE5, 0x9A, 0x61, 0x11,
        0xBE, 0x1D, 0x8C, 0x02, 0x1E, 0x65, 0xB8, 0x91,
        0xC2, 0xA2, 0x11, 0x16, 0x7A, 0xBB, 0x8C, 0x5E,
        0x07, 0x9E, 0x09, 0xE2, 0xC8, 0xA8, 0x33, 0x9C,
    ];

    internal static TlsCipherSuite ReadCipherSuite(ReadOnlySpan<byte> encodedServerHello)
    {
        var layout = ParseServerHelloLayout(encodedServerHello);
        return ParseCipherSuite(layout.CipherSuite);
    }

    internal static bool IsHelloRetryRequest(ReadOnlySpan<byte> encodedServerHello) =>
        ParseServerHelloLayout(encodedServerHello).IsHelloRetryRequest;

    internal static byte[] ComputeForServerHello(
        TlsCipherSuite cipherSuite,
        ReadOnlySpan<byte> encodedClientHelloInner,
        ReadOnlySpan<byte> encodedServerHello)
    {
        var clientRandom = ReadClientRandom(encodedClientHelloInner);
        var layout = ParseServerHelloLayout(encodedServerHello);
        ValidateCipherSuite(cipherSuite, layout.CipherSuite);
        if (layout.IsHelloRetryRequest)
        {
            throw TlsProtocolException.Unexpected(
                "ECH ServerHello acceptance confirmation cannot be computed from HelloRetryRequest.");
        }

        var modifiedServerHello = encodedServerHello.ToArray();
        modifiedServerHello.AsSpan(
            layout.RandomOffset + TlsConstants.RandomLength - ConfirmationLength,
            ConfirmationLength).Clear();
        try
        {
            return Compute(
                CipherSuiteInfo.Get(cipherSuite),
                clientRandom,
                "ech accept confirmation",
                encodedClientHelloInner,
                modifiedServerHello);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(modifiedServerHello);
        }
    }

    internal static bool VerifyServerHello(
        TlsCipherSuite cipherSuite,
        ReadOnlySpan<byte> encodedClientHelloInner,
        ReadOnlySpan<byte> encodedServerHello)
    {
        var layout = ParseServerHelloLayout(encodedServerHello);
        if (layout.IsHelloRetryRequest)
        {
            throw TlsProtocolException.Unexpected(
                "ECH ServerHello acceptance confirmation cannot be verified on HelloRetryRequest.");
        }

        var expected = ComputeForServerHello(
            cipherSuite,
            encodedClientHelloInner,
            encodedServerHello);
        try
        {
            return CryptographicOperations.FixedTimeEquals(
                expected,
                encodedServerHello.Slice(
                    layout.RandomOffset + TlsConstants.RandomLength - ConfirmationLength,
                    ConfirmationLength));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(expected);
        }
    }

    internal static byte[] ComputeForHelloRetryRequest(
        TlsCipherSuite cipherSuite,
        ReadOnlySpan<byte> encodedClientHelloInner,
        ReadOnlySpan<byte> encodedHelloRetryRequest)
    {
        var clientRandom = ReadClientRandom(encodedClientHelloInner);
        var layout = ParseServerHelloLayout(encodedHelloRetryRequest);
        ValidateCipherSuite(cipherSuite, layout.CipherSuite);
        if (!layout.IsHelloRetryRequest)
        {
            throw TlsProtocolException.Unexpected(
                "ECH HRR acceptance confirmation requires HelloRetryRequest.");
        }
        if (!layout.EchConfirmationOffset.HasValue)
        {
            throw new TlsProtocolException(
                TlsAlertDescription.MissingExtension,
                "HelloRetryRequest omitted the ECH acceptance confirmation extension.");
        }
        if (layout.EchConfirmationLength != ConfirmationLength)
        {
            throw TlsProtocolException.Decode(
                "HelloRetryRequest ECH acceptance confirmation must contain exactly 8 bytes.");
        }

        var suite = CipherSuiteInfo.Get(cipherSuite);
        var firstClientHelloHash = Hash(suite, encodedClientHelloInner);
        var syntheticMessageHash = HandshakeMessage.Encode(
            HandshakeType.MessageHash,
            firstClientHelloHash);
        var modifiedHelloRetryRequest = encodedHelloRetryRequest.ToArray();
        modifiedHelloRetryRequest.AsSpan(
            layout.EchConfirmationOffset.Value,
            ConfirmationLength).Clear();
        try
        {
            return Compute(
                suite,
                clientRandom,
                "hrr ech accept confirmation",
                syntheticMessageHash,
                modifiedHelloRetryRequest);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(firstClientHelloHash);
            CryptographicOperations.ZeroMemory(syntheticMessageHash);
            CryptographicOperations.ZeroMemory(modifiedHelloRetryRequest);
        }
    }

    internal static bool VerifyHelloRetryRequest(
        TlsCipherSuite cipherSuite,
        ReadOnlySpan<byte> encodedClientHelloInner,
        ReadOnlySpan<byte> encodedHelloRetryRequest)
    {
        var layout = ParseServerHelloLayout(encodedHelloRetryRequest);
        if (!layout.IsHelloRetryRequest)
        {
            throw TlsProtocolException.Unexpected(
                "ECH HRR acceptance confirmation requires HelloRetryRequest.");
        }
        if (!layout.EchConfirmationOffset.HasValue)
        {
            return false;
        }

        var expected = ComputeForHelloRetryRequest(
            cipherSuite,
            encodedClientHelloInner,
            encodedHelloRetryRequest);
        try
        {
            return CryptographicOperations.FixedTimeEquals(
                expected,
                encodedHelloRetryRequest.Slice(
                    layout.EchConfirmationOffset.Value,
                    ConfirmationLength));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(expected);
        }
    }

    internal static byte[] ComputeForServerHelloAfterHelloRetryRequest(
        TlsCipherSuite cipherSuite,
        ReadOnlySpan<byte> encodedFirstClientHelloInner,
        ReadOnlySpan<byte> encodedHelloRetryRequest,
        ReadOnlySpan<byte> encodedSecondClientHelloInner,
        ReadOnlySpan<byte> encodedServerHello)
    {
        var clientRandom = ReadClientRandom(encodedFirstClientHelloInner);
        _ = ReadClientRandom(encodedSecondClientHelloInner);
        var retryLayout = ParseServerHelloLayout(encodedHelloRetryRequest);
        var serverLayout = ParseServerHelloLayout(encodedServerHello);
        ValidateCipherSuite(cipherSuite, retryLayout.CipherSuite);
        ValidateCipherSuite(cipherSuite, serverLayout.CipherSuite);
        if (!retryLayout.IsHelloRetryRequest || serverLayout.IsHelloRetryRequest)
        {
            throw TlsProtocolException.Unexpected(
                "ECH post-HRR acceptance confirmation requires HRR followed by ServerHello.");
        }

        var suite = CipherSuiteInfo.Get(cipherSuite);
        var firstClientHelloHash = Hash(suite, encodedFirstClientHelloInner);
        var syntheticMessageHash = HandshakeMessage.Encode(
            HandshakeType.MessageHash,
            firstClientHelloHash);
        var modifiedServerHello = encodedServerHello.ToArray();
        modifiedServerHello.AsSpan(
            serverLayout.RandomOffset + TlsConstants.RandomLength - ConfirmationLength,
            ConfirmationLength).Clear();
        try
        {
            return Compute(
                suite,
                clientRandom,
                "ech accept confirmation",
                syntheticMessageHash,
                encodedHelloRetryRequest,
                encodedSecondClientHelloInner,
                modifiedServerHello);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(firstClientHelloHash);
            CryptographicOperations.ZeroMemory(syntheticMessageHash);
            CryptographicOperations.ZeroMemory(modifiedServerHello);
        }
    }

    internal static bool VerifyServerHelloAfterHelloRetryRequest(
        TlsCipherSuite cipherSuite,
        ReadOnlySpan<byte> encodedFirstClientHelloInner,
        ReadOnlySpan<byte> encodedHelloRetryRequest,
        ReadOnlySpan<byte> encodedSecondClientHelloInner,
        ReadOnlySpan<byte> encodedServerHello)
    {
        var layout = ParseServerHelloLayout(encodedServerHello);
        if (layout.IsHelloRetryRequest)
        {
            throw TlsProtocolException.Unexpected(
                "ECH post-HRR acceptance confirmation requires ServerHello.");
        }

        var expected = ComputeForServerHelloAfterHelloRetryRequest(
            cipherSuite,
            encodedFirstClientHelloInner,
            encodedHelloRetryRequest,
            encodedSecondClientHelloInner,
            encodedServerHello);
        try
        {
            return CryptographicOperations.FixedTimeEquals(
                expected,
                encodedServerHello.Slice(
                    layout.RandomOffset + TlsConstants.RandomLength - ConfirmationLength,
                    ConfirmationLength));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(expected);
        }
    }

    private static byte[] Compute(
        CipherSuiteInfo suite,
        ReadOnlySpan<byte> clientRandom,
        string label,
        ReadOnlySpan<byte> firstMessage,
        ReadOnlySpan<byte> secondMessage)
    {
        using var transcript = IncrementalHash.CreateHash(suite.HashAlgorithm);
        transcript.AppendData(firstMessage);
        transcript.AppendData(secondMessage);
        var transcriptHash = transcript.GetHashAndReset();
        try
        {
            return ComputeFromTranscriptHash(suite, clientRandom, label, transcriptHash);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(transcriptHash);
        }
    }

    private static byte[] Compute(
        CipherSuiteInfo suite,
        ReadOnlySpan<byte> clientRandom,
        string label,
        ReadOnlySpan<byte> firstMessage,
        ReadOnlySpan<byte> secondMessage,
        ReadOnlySpan<byte> thirdMessage,
        ReadOnlySpan<byte> fourthMessage)
    {
        using var transcript = IncrementalHash.CreateHash(suite.HashAlgorithm);
        transcript.AppendData(firstMessage);
        transcript.AppendData(secondMessage);
        transcript.AppendData(thirdMessage);
        transcript.AppendData(fourthMessage);
        var transcriptHash = transcript.GetHashAndReset();
        try
        {
            return ComputeFromTranscriptHash(suite, clientRandom, label, transcriptHash);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(transcriptHash);
        }
    }

    private static byte[] ComputeFromTranscriptHash(
        CipherSuiteInfo suite,
        ReadOnlySpan<byte> clientRandom,
        string label,
        ReadOnlySpan<byte> transcriptHash)
    {
        var zeros = new byte[suite.HashLength];
        var secret = Tls13Hkdf.Extract(suite.HashAlgorithm, clientRandom, zeros);
        try
        {
            return Tls13Hkdf.ExpandLabel(
                suite.HashAlgorithm,
                secret,
                label,
                transcriptHash,
                ConfirmationLength);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(zeros);
            CryptographicOperations.ZeroMemory(secret);
        }
    }

    private static ReadOnlySpan<byte> ReadClientRandom(
        ReadOnlySpan<byte> encodedClientHello)
    {
        ValidateHandshake(encodedClientHello, HandshakeType.ClientHello);
        const int randomOffset = TlsConstants.HandshakeHeaderLength + 2;
        if (encodedClientHello.Length < randomOffset + TlsConstants.RandomLength)
        {
            throw TlsProtocolException.Decode("ClientHello is truncated before random.");
        }
        return encodedClientHello.Slice(randomOffset, TlsConstants.RandomLength);
    }

    private static ServerHelloLayout ParseServerHelloLayout(
        ReadOnlySpan<byte> encodedServerHello)
    {
        ValidateHandshake(encodedServerHello, HandshakeType.ServerHello);
        var offset = TlsConstants.HandshakeHeaderLength;
        EnsureAvailable(encodedServerHello, offset, 2 + TlsConstants.RandomLength + 1);
        offset += 2;
        var randomOffset = offset;
        var isRetry = encodedServerHello.Slice(offset, TlsConstants.RandomLength)
            .SequenceEqual(HelloRetryRequestRandom);
        offset += TlsConstants.RandomLength;

        var sessionIdLength = encodedServerHello[offset++];
        if (sessionIdLength > TlsConstants.MaxSessionIdLength)
        {
            throw TlsProtocolException.Decode("ServerHello legacy session ID is too long.");
        }
        EnsureAvailable(encodedServerHello, offset, sessionIdLength + 2 + 1 + 2);
        offset += sessionIdLength;
        var cipherSuite = BinaryPrimitives.ReadUInt16BigEndian(encodedServerHello[offset..]);
        offset += 2;
        offset++;

        var extensionsLength = BinaryPrimitives.ReadUInt16BigEndian(encodedServerHello[offset..]);
        offset += 2;
        EnsureAvailable(encodedServerHello, offset, extensionsLength);
        if (offset + extensionsLength != encodedServerHello.Length)
        {
            throw TlsProtocolException.Decode(
                "ServerHello extension vector does not consume the handshake body.");
        }

        int? echConfirmationOffset = null;
        var echConfirmationLength = 0;
        var extensionsEnd = offset + extensionsLength;
        while (offset < extensionsEnd)
        {
            EnsureAvailable(encodedServerHello, offset, 4);
            var type = BinaryPrimitives.ReadUInt16BigEndian(encodedServerHello[offset..]);
            var length = BinaryPrimitives.ReadUInt16BigEndian(encodedServerHello[(offset + 2)..]);
            offset += 4;
            EnsureAvailable(encodedServerHello, offset, length);
            if (type == (ushort)TlsExtensionType.EncryptedClientHello)
            {
                if (echConfirmationOffset.HasValue)
                {
                    throw TlsProtocolException.Illegal(
                        "ServerHello contains duplicate encrypted_client_hello extensions.");
                }
                echConfirmationOffset = offset;
                echConfirmationLength = length;
            }
            offset += length;
        }

        return new ServerHelloLayout(
            randomOffset,
            cipherSuite,
            isRetry,
            echConfirmationOffset,
            echConfirmationLength);
    }

    private static void ValidateHandshake(
        ReadOnlySpan<byte> encodedHandshake,
        HandshakeType expectedType)
    {
        if (encodedHandshake.Length < TlsConstants.HandshakeHeaderLength)
        {
            throw TlsProtocolException.Decode("TLS handshake header is truncated.");
        }
        if (encodedHandshake[0] != (byte)expectedType)
        {
            throw TlsProtocolException.Unexpected(
                $"Expected {expectedType} while computing ECH acceptance confirmation.");
        }
        var declaredLength = (encodedHandshake[1] << 16) |
                             (encodedHandshake[2] << 8) |
                             encodedHandshake[3];
        if (declaredLength != encodedHandshake.Length - TlsConstants.HandshakeHeaderLength)
        {
            throw TlsProtocolException.Decode(
                "TLS handshake length is inconsistent with the encoded message.");
        }
    }

    private static void ValidateCipherSuite(
        TlsCipherSuite expected,
        ushort encoded)
    {
        if ((ushort)expected != encoded)
        {
            throw TlsProtocolException.Illegal(
                "ECH acceptance confirmation cipher suite does not match ServerHello.");
        }
        _ = CipherSuiteInfo.Get(expected);
    }

    private static TlsCipherSuite ParseCipherSuite(ushort encoded)
    {
        var suite = (TlsCipherSuite)encoded;
        try
        {
            _ = CipherSuiteInfo.Get(suite);
        }
        catch (NotSupportedException exception)
        {
            throw new TlsProtocolException(
                TlsAlertDescription.IllegalParameter,
                $"ECH acceptance confirmation uses unsupported cipher suite 0x{encoded:X4}.",
                exception);
        }
        return suite;
    }

    private static byte[] Hash(CipherSuiteInfo suite, ReadOnlySpan<byte> value) =>
        suite.HashAlgorithm.Name switch
        {
            "SHA256" => SHA256.HashData(value),
            "SHA384" => SHA384.HashData(value),
            _ => throw new NotSupportedException(
                $"Hash algorithm {suite.HashAlgorithm.Name} is not supported."),
        };

    private static void EnsureAvailable(
        ReadOnlySpan<byte> input,
        int offset,
        int length)
    {
        if (offset < 0 || length < 0 || offset > input.Length - length)
        {
            throw TlsProtocolException.Decode("ServerHello is truncated.");
        }
    }

    private readonly record struct ServerHelloLayout(
        int RandomOffset,
        ushort CipherSuite,
        bool IsHelloRetryRequest,
        int? EchConfirmationOffset,
        int EchConfirmationLength);
}
