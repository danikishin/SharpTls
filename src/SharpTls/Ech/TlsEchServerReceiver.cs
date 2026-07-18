using System.Buffers.Binary;
using System.Security.Cryptography;
using SharpTls.Handshake;
using SharpTls.IO;
using SharpTls.Protocol;

namespace SharpTls.Ech;

internal enum TlsEchServerProcessingResult
{
    NotOffered,
    Rejected,
    Accepted,
}

/// <summary>One-connection RFC 9849 ECH receiver with single-use HRR context state.</summary>
internal sealed class TlsEchServerReceiver : IDisposable
{
    private const int HpkeTagLength = 16;

    private readonly TlsEchServerKeyConfiguration[] _keys;
    private HpkeReceiverContext? _context;
    private TlsEchServerKeyConfiguration? _selectedKey;
    private TlsHpkeSymmetricCipherSuite? _selectedSuite;
    private bool _initialProcessed;
    private bool _retryProcessed;
    private bool _disposed;

    internal TlsEchServerReceiver(TlsEchServerKeyConfiguration[] keys)
    {
        _keys = keys;
    }

    internal TlsEchServerProcessingResult ProcessInitial(
        HandshakeMessage outer,
        out HandshakeMessage? inner)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (_initialProcessed)
        {
            throw new InvalidOperationException("The initial ECH ClientHello was already processed.");
        }
        _initialProcessed = true;
        inner = null;

        ParsedOuterEch? parsed = null;
        try
        {
            parsed = ParseOuter(outer, isRetry: false);
            if (parsed is null)
            {
                return TlsEchServerProcessingResult.NotOffered;
            }

            var key = _keys.FirstOrDefault(candidate =>
                candidate.Configuration.ConfigId == parsed.ConfigId &&
                candidate.Configuration.CipherSuites.Contains(parsed.Suite) &&
                GetEncapsulatedKeyLength(candidate.Configuration.KemId) ==
                    parsed.EncapsulatedKey.Length);
            if (key is null)
            {
                return TlsEchServerProcessingResult.Rejected;
            }

            try
            {
                _context = CreateContext(key, parsed);
                var encodedInner = _context.Open(parsed.AssociatedData, parsed.Ciphertext);
                HandshakeMessage? candidate = null;
                try
                {
                    candidate = ReconstructClientHelloInner(encodedInner, outer.Encoded);
                    ValidateClientHelloInner(candidate);
                    inner = candidate;
                    candidate = null;
                }
                finally
                {
                    ZeroHandshakeMessage(candidate);
                    CryptographicOperations.ZeroMemory(encodedInner);
                }
                _selectedKey = key;
                _selectedSuite = parsed.Suite;
                return TlsEchServerProcessingResult.Accepted;
            }
            catch (Exception exception) when (IsRejectableClientInput(exception))
            {
                _context?.Dispose();
                _context = null;
                _selectedKey = null;
                _selectedSuite = null;
                inner = null;
                return TlsEchServerProcessingResult.Rejected;
            }
        }
        finally
        {
            parsed?.Dispose();
        }
    }

    internal HandshakeMessage ProcessRetry(HandshakeMessage outer)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (!_initialProcessed || _context is null || _selectedKey is null ||
            !_selectedSuite.HasValue || _retryProcessed)
        {
            throw TlsProtocolException.Unexpected(
                "ECH retry attempted without one accepted initial ClientHelloOuter.");
        }

        using var parsed = ParseOuter(outer, isRetry: true) ??
            throw new TlsProtocolException(
                TlsAlertDescription.MissingExtension,
                "Second ClientHelloOuter omitted encrypted_client_hello.");
        if (parsed.ConfigId != _selectedKey.Configuration.ConfigId ||
            parsed.Suite != _selectedSuite.Value ||
            parsed.EncapsulatedKey.Length != 0)
        {
            throw TlsProtocolException.Illegal(
                "Second ClientHelloOuter changed its ECH configuration, suite, or encapsulated key.");
        }

        try
        {
            var encodedInner = _context.Open(parsed.AssociatedData, parsed.Ciphertext);
            HandshakeMessage? candidate = null;
            try
            {
                candidate = ReconstructClientHelloInner(encodedInner, outer.Encoded);
                ValidateClientHelloInner(candidate);
                _retryProcessed = true;
                var inner = candidate;
                candidate = null;
                return inner;
            }
            finally
            {
                ZeroHandshakeMessage(candidate);
                CryptographicOperations.ZeroMemory(encodedInner);
            }
        }
        catch (Exception exception) when (IsRejectableClientInput(exception))
        {
            throw new TlsProtocolException(
                TlsAlertDescription.DecryptError,
                "Second ECH ClientHello authentication or reconstruction failed.",
                exception);
        }
    }

    internal static void ValidateOuterRetryIdentity(
        HandshakeMessage first,
        HandshakeMessage second)
    {
        var firstIdentity = ReadClientHelloIdentity(first.Encoded);
        var secondIdentity = ReadClientHelloIdentity(second.Encoded);
        if (!firstIdentity.Random.AsSpan().SequenceEqual(secondIdentity.Random) ||
            !firstIdentity.SessionId.AsSpan().SequenceEqual(secondIdentity.SessionId))
        {
            throw TlsProtocolException.Illegal(
                "Second ClientHelloOuter changed its random or legacy session ID.");
        }
    }

    private static HpkeReceiverContext CreateContext(
        TlsEchServerKeyConfiguration key,
        ParsedOuterEch parsed)
    {
        var privateKey = key.CopyPrivateKey();
        var encodedConfig = key.Configuration.GetEncodedConfig();
        var publicKey = key.Configuration.GetPublicKey();
        var info = new byte[8 + encodedConfig.Length];
        try
        {
            "tls ech"u8.CopyTo(info);
            encodedConfig.CopyTo(info, 8);
            return key.Configuration.KemId switch
            {
                TlsHpkeKemId.DhkemX25519HkdfSha256 =>
                    HpkeReceiverContext.SetupBaseX25519(
                        parsed.Suite,
                        privateKey,
                        parsed.EncapsulatedKey,
                        info),
                TlsHpkeKemId.DhkemP256HkdfSha256 or
                TlsHpkeKemId.DhkemP384HkdfSha384 or
                TlsHpkeKemId.DhkemP521HkdfSha512 =>
                    HpkeReceiverContext.SetupBaseNist(
                        key.Configuration.KemId,
                        parsed.Suite,
                        privateKey,
                        publicKey,
                        parsed.EncapsulatedKey,
                        info),
                _ => throw new NotSupportedException(
                    $"ECH KEM 0x{(ushort)key.Configuration.KemId:X4} is unsupported."),
            };
        }
        finally
        {
            CryptographicOperations.ZeroMemory(privateKey);
            CryptographicOperations.ZeroMemory(encodedConfig);
            CryptographicOperations.ZeroMemory(publicKey);
            CryptographicOperations.ZeroMemory(info);
        }
    }

    private static ParsedOuterEch? ParseOuter(
        HandshakeMessage outer,
        bool isRetry)
    {
        if (outer.Type != HandshakeType.ClientHello)
        {
            throw TlsProtocolException.Unexpected("ECH receiver expected ClientHello.");
        }
        var associatedData = outer.Body.ToArray();
        try
        {
            var offset = 2 + TlsConstants.RandomLength;
            offset = SkipVector8(associatedData, offset);
            offset = SkipVector16(associatedData, offset);
            offset = SkipVector8(associatedData, offset);
            EnsureAvailable(associatedData, offset, 2);
            var extensionsLength = BinaryPrimitives.ReadUInt16BigEndian(
                associatedData.AsSpan(offset));
            offset += 2;
            EnsureAvailable(associatedData, offset, extensionsLength);
            var extensionsEnd = offset + extensionsLength;
            if (extensionsEnd != associatedData.Length)
            {
                throw TlsProtocolException.Decode(
                    "ClientHelloOuter extension vector has trailing bytes.");
            }

            while (offset < extensionsEnd)
            {
                EnsureAvailable(associatedData, offset, 4);
                var type = BinaryPrimitives.ReadUInt16BigEndian(
                    associatedData.AsSpan(offset));
                var dataLength = BinaryPrimitives.ReadUInt16BigEndian(
                    associatedData.AsSpan(offset + 2));
                offset += 4;
                EnsureAvailable(associatedData, offset, dataLength);
                if (type != (ushort)TlsExtensionType.EncryptedClientHello)
                {
                    offset += dataLength;
                    continue;
                }

                var dataOffset = offset;
                var reader = new TlsBinaryReader(
                    associatedData.AsSpan(dataOffset, dataLength));
                if (reader.ReadUInt8() != 0)
                {
                    throw TlsProtocolException.Illegal(
                        "ClientHelloOuter encrypted_client_hello has a non-outer marker.");
                }
                var kdf = reader.ReadUInt16();
                var aead = reader.ReadUInt16();
                var configId = reader.ReadUInt8();
                var encapsulatedKey = reader.ReadVector16().ToArray();
                var ciphertext = reader.ReadVector16().ToArray();
                reader.EnsureEnd("ClientHelloOuter encrypted_client_hello");
                if (ciphertext.Length < HpkeTagLength)
                {
                    throw TlsProtocolException.Decode(
                        "ClientHelloOuter ECH payload is shorter than an HPKE authentication tag.");
                }
                if (isRetry ? encapsulatedKey.Length != 0 : encapsulatedKey.Length == 0)
                {
                    throw TlsProtocolException.Illegal(
                        "ClientHelloOuter ECH encapsulated-key length is invalid for its flight.");
                }

                var payloadOffset = 1 + 2 + 2 + 1 + 2 +
                    encapsulatedKey.Length + 2;
                associatedData.AsSpan(
                    dataOffset + payloadOffset,
                    ciphertext.Length).Clear();
                var parsed = new ParsedOuterEch(
                    new TlsHpkeSymmetricCipherSuite(
                        (TlsHpkeKdfId)kdf,
                        (TlsHpkeAeadId)aead),
                    configId,
                    encapsulatedKey,
                    ciphertext,
                    associatedData);
                associatedData = null!;
                return parsed;
            }
            return null;
        }
        finally
        {
            if (associatedData is not null)
            {
                CryptographicOperations.ZeroMemory(associatedData);
            }
        }
    }

    private static HandshakeMessage ReconstructClientHelloInner(
        ReadOnlySpan<byte> encodedInner,
        ReadOnlySpan<byte> encodedOuter)
    {
        var outerSessionId = ReadClientHelloIdentity(encodedOuter).SessionId;
        const int sessionIdLengthOffset = 2 + TlsConstants.RandomLength;
        if (encodedInner.Length <= sessionIdLengthOffset ||
            encodedInner[sessionIdLengthOffset] != 0)
        {
            throw TlsProtocolException.Illegal(
                "EncodedClientHelloInner has a non-empty legacy session ID.");
        }

        var actualLength = FindEncodedClientHelloInnerLength(encodedInner);
        if (encodedInner[actualLength..].IndexOfAnyExcept((byte)0) >= 0)
        {
            throw TlsProtocolException.Illegal("EncodedClientHelloInner padding is non-zero.");
        }
        var body = new TlsBinaryWriter(actualLength + outerSessionId.Length);
        body.WriteBytes(encodedInner[..sessionIdLengthOffset]);
        body.WriteVector8(outerSessionId);
        body.WriteBytes(encodedInner[(sessionIdLengthOffset + 1)..actualLength]);
        var reconstructed = HandshakeMessage.Encode(
            HandshakeType.ClientHello,
            body.WrittenSpan);
        byte[]? expanded = null;
        try
        {
            expanded = ExpandOuterExtensions(reconstructed, encodedOuter);
            return new HandshakeMessage(
                HandshakeType.ClientHello,
                expanded.AsSpan(TlsConstants.HandshakeHeaderLength).ToArray(),
                expanded);
        }
        finally
        {
            if (!ReferenceEquals(expanded, reconstructed))
            {
                CryptographicOperations.ZeroMemory(reconstructed);
            }
        }
    }

    private static byte[] ExpandOuterExtensions(
        byte[] encodedInner,
        ReadOnlySpan<byte> encodedOuter)
    {
        using var inner = ParseWireClientHello(encodedInner);
        var markerIndex = Array.FindIndex(
            inner.Extensions,
            extension => extension.Type == (ushort)TlsExtensionType.EchOuterExtensions);
        if (markerIndex < 0)
        {
            return encodedInner;
        }

        var references = new TlsBinaryReader(inner.Extensions[markerIndex].Data);
        var encodedTypes = references.ReadVector8(254);
        references.EnsureEnd("ech_outer_extensions");
        if (encodedTypes.Length < 2 || (encodedTypes.Length & 1) != 0)
        {
            throw TlsProtocolException.Decode(
                "ech_outer_extensions has an invalid extension-type vector.");
        }
        var typeReader = new TlsBinaryReader(encodedTypes);
        var types = new List<ushort>();
        var seen = new HashSet<ushort>();
        while (!typeReader.End)
        {
            var type = typeReader.ReadUInt16();
            if (type is (ushort)TlsExtensionType.EncryptedClientHello or
                (ushort)TlsExtensionType.EchOuterExtensions or
                (ushort)TlsExtensionType.ServerName or
                (ushort)TlsExtensionType.PreSharedKey || !seen.Add(type))
            {
                throw TlsProtocolException.Illegal(
                    "ech_outer_extensions contains a duplicate or forbidden type.");
            }
            types.Add(type);
        }

        using var outer = ParseWireClientHello(encodedOuter);
        var replacements = new List<WireExtension>(types.Count);
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
                throw TlsProtocolException.Illegal(
                    "ech_outer_extensions referenced a missing or reordered outer extension.");
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

    private static WireClientHello ParseWireClientHello(ReadOnlySpan<byte> encoded)
    {
        if (encoded.Length < TlsConstants.HandshakeHeaderLength ||
            encoded[0] != (byte)HandshakeType.ClientHello)
        {
            throw TlsProtocolException.Decode("ECH ClientHello framing is invalid.");
        }
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
            throw TlsProtocolException.Decode("ECH ClientHello extension vector is malformed.");
        }

        var reader = new TlsBinaryReader(body.Slice(extensionsOffset, extensionsLength));
        var extensions = new List<WireExtension>();
        var seen = new HashSet<ushort>();
        while (!reader.End)
        {
            var type = reader.ReadUInt16();
            if (!seen.Add(type))
            {
                throw TlsProtocolException.Illegal("ECH ClientHello contains duplicate extensions.");
            }
            extensions.Add(new WireExtension(type, reader.ReadVector16().ToArray()));
        }
        return new WireClientHello(body[..offset].ToArray(), extensions.ToArray());
    }

    private static void ValidateClientHelloInner(HandshakeMessage inner)
    {
        var parsed = Tls13ClientHelloParser.Parse(inner.Body);
        if (!parsed.SupportedVersions.SequenceEqual([TlsProtocolVersion.Tls13]) ||
            !parsed.ExtensionBodies.TryGetValue(
                (ushort)TlsExtensionType.EncryptedClientHello,
                out var marker) ||
            !marker.AsSpan().SequenceEqual([(byte)1]))
        {
            throw TlsProtocolException.Illegal(
                "ClientHelloInner must contain the inner ECH marker and offer only TLS 1.3.");
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
        offset = SkipVector8(encodedInner, offset);
        offset = SkipVector16(encodedInner, offset);
        offset = SkipVector8(encodedInner, offset);
        EnsureAvailable(encodedInner, offset, 2);
        var extensionsLength = BinaryPrimitives.ReadUInt16BigEndian(encodedInner[offset..]);
        offset += 2;
        EnsureAvailable(encodedInner, offset, extensionsLength);
        return offset + extensionsLength;
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
            throw TlsProtocolException.Decode("ECH ClientHello is truncated.");
        }
    }

    private static int GetEncapsulatedKeyLength(TlsHpkeKemId kemId) => kemId switch
    {
        TlsHpkeKemId.DhkemX25519HkdfSha256 => 32,
        TlsHpkeKemId.DhkemP256HkdfSha256 => 65,
        TlsHpkeKemId.DhkemP384HkdfSha384 => 97,
        TlsHpkeKemId.DhkemP521HkdfSha512 => 133,
        _ => -1,
    };

    private static bool IsRejectableClientInput(Exception exception) => exception is
        CryptographicException or TlsProtocolException or InvalidDataException or
        ArgumentException;

    private static void ZeroHandshakeMessage(HandshakeMessage? message)
    {
        if (message is null)
        {
            return;
        }
        CryptographicOperations.ZeroMemory(message.Body);
        CryptographicOperations.ZeroMemory(message.Encoded);
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
        _selectedKey = null;
        _selectedSuite = null;
    }

    private sealed class ParsedOuterEch : IDisposable
    {
        internal ParsedOuterEch(
            TlsHpkeSymmetricCipherSuite suite,
            byte configId,
            byte[] encapsulatedKey,
            byte[] ciphertext,
            byte[] associatedData)
        {
            Suite = suite;
            ConfigId = configId;
            EncapsulatedKey = encapsulatedKey;
            Ciphertext = ciphertext;
            AssociatedData = associatedData;
        }

        internal TlsHpkeSymmetricCipherSuite Suite { get; }
        internal byte ConfigId { get; }
        internal byte[] EncapsulatedKey { get; }
        internal byte[] Ciphertext { get; }
        internal byte[] AssociatedData { get; }

        public void Dispose()
        {
            CryptographicOperations.ZeroMemory(EncapsulatedKey);
            CryptographicOperations.ZeroMemory(Ciphertext);
            CryptographicOperations.ZeroMemory(AssociatedData);
        }
    }

    private sealed class WireExtension : IDisposable
    {
        internal WireExtension(ushort type, byte[] data)
        {
            Type = type;
            Data = data;
        }

        internal ushort Type { get; }
        internal byte[] Data { get; }

        public void Dispose() => CryptographicOperations.ZeroMemory(Data);
    }

    private sealed class WireClientHello : IDisposable
    {
        internal WireClientHello(byte[] bodyPrefix, WireExtension[] extensions)
        {
            BodyPrefix = bodyPrefix;
            Extensions = extensions;
        }

        internal byte[] BodyPrefix { get; }
        internal WireExtension[] Extensions { get; }

        public void Dispose()
        {
            CryptographicOperations.ZeroMemory(BodyPrefix);
            foreach (var extension in Extensions)
            {
                extension.Dispose();
            }
        }
    }
}
