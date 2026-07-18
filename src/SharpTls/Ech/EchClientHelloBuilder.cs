using System.Buffers.Binary;
using System.Security.Cryptography;
using SharpTls.Cryptography;
using SharpTls.Handshake;
using SharpTls.IO;
using SharpTls.Protocol;

namespace SharpTls.Ech;

internal sealed class EchClientHelloBuildResult : IDisposable
{
    private bool _retryStarted;
    private bool _disposed;

    internal EchClientHelloBuildResult(
        string privateServerName,
        ClientHelloBuildResult inner,
        ClientHelloBuildResult outer,
        byte[] encodedInner,
        HpkeSenderContext hpkeContext,
        EchConfigSelection selection,
        TlsExtensionType[] compressedOuterExtensions)
    {
        PrivateServerName = privateServerName;
        Inner = inner;
        Outer = outer;
        EncodedInner = encodedInner;
        HpkeContext = hpkeContext;
        Selection = selection;
        CompressedOuterExtensions = compressedOuterExtensions;
    }

    internal string PrivateServerName { get; }
    internal ClientHelloBuildResult Inner { get; }
    internal ClientHelloBuildResult Outer { get; }
    internal byte[] EncodedInner { get; }
    internal HpkeSenderContext HpkeContext { get; }
    internal EchConfigSelection Selection { get; }
    internal TlsExtensionType[] CompressedOuterExtensions { get; }

    internal void BeginRetry()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (_retryStarted)
        {
            throw TlsProtocolException.Unexpected(
                "RFC 9849 permits only one ECH ClientHello retry on a connection.");
        }
        _retryStarted = true;
    }

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }
        _disposed = true;
        Inner.Dispose();
        Outer.Dispose();
        HpkeContext.Dispose();
        CryptographicOperations.ZeroMemory(EncodedInner);
    }
}

internal sealed class EchClientHelloRetryBuildResult : IDisposable
{
    private bool _disposed;

    internal EchClientHelloRetryBuildResult(
        ClientHelloBuildResult inner,
        ClientHelloBuildResult outer,
        byte[] encodedInner)
    {
        Inner = inner;
        Outer = outer;
        EncodedInner = encodedInner;
    }

    internal ClientHelloBuildResult Inner { get; }
    internal ClientHelloBuildResult Outer { get; }
    internal byte[] EncodedInner { get; }

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }
        _disposed = true;
        Inner.Dispose();
        Outer.Dispose();
        CryptographicOperations.ZeroMemory(EncodedInner);
    }
}

internal static class EchClientHelloBuilder
{
    internal static EchClientHelloBuildResult Build(
        string privateServerName,
        ClientHelloConfiguration innerConfiguration,
        ClientHelloConfiguration outerConfiguration,
        EchConfigSelection selection,
        IRandomSource randomSource,
        KeyShareSet innerKeyShares,
        KeyShareSet outerKeyShares,
        IReadOnlyList<TlsExtensionType>? compressedOuterExtensions = null,
        Tls13PskOffer? pskOffer = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(privateServerName);
        ArgumentNullException.ThrowIfNull(innerConfiguration);
        ArgumentNullException.ThrowIfNull(outerConfiguration);
        ArgumentNullException.ThrowIfNull(selection);
        ArgumentNullException.ThrowIfNull(randomSource);
        ArgumentNullException.ThrowIfNull(innerKeyShares);
        ArgumentNullException.ThrowIfNull(outerKeyShares);
        if (innerConfiguration.SupportedVersions.Any(version =>
            version != TlsProtocolVersion.Tls13))
        {
            throw new ArgumentException(
                "RFC 9849 ClientHelloInner cannot offer TLS 1.2 or below.",
                nameof(innerConfiguration));
        }
        if (!outerConfiguration.SupportedVersions.Contains(TlsProtocolVersion.Tls13))
        {
            throw new ArgumentException(
                "RFC 9849 ClientHelloOuter must offer TLS 1.3.",
                nameof(outerConfiguration));
        }

        ClientHelloBuildResult? inner = null;
        ClientHelloBuildResult? outer = null;
        HpkeSenderContext? hpke = null;
        byte[]? encodedInner = null;
        byte[]? compressedInner = null;
        try
        {
            var compression = compressedOuterExtensions?.ToArray() ?? [];
            var innerWithEch = InsertEchExtension(innerConfiguration, [1]);
            inner = ClientHelloEncoder.Build(
                privateServerName,
                innerWithEch,
                randomSource,
                innerKeyShares,
                retry: null,
                pskOffer: pskOffer);
            compressedInner = compression.Length == 0
                ? null
                : CompressClientHelloInner(inner.EncodedHandshake, compression);
            encodedInner = EncodeAndPadInner(
                compressedInner ?? inner.EncodedHandshake,
                selection.Configuration.MaximumNameLength);

            var encodedConfig = selection.Configuration.GetEncodedConfig();
            var info = new byte[8 + encodedConfig.Length];
            "tls ech"u8.CopyTo(info);
            info[7] = 0;
            encodedConfig.CopyTo(info, 8);
            try
            {
                hpke = HpkeSenderContext.SetupBase(
                    selection.Configuration.KemId,
                    selection.CipherSuite,
                    selection.Configuration.GetPublicKey(),
                    info,
                    randomSource);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(info);
                CryptographicOperations.ZeroMemory(encodedConfig);
            }

            var placeholder = EncodeOuterEch(
                selection,
                hpke.EncapsulatedKey,
                new byte[checked(encodedInner.Length + 16)]);
            var outerWithEch = InsertEchExtension(outerConfiguration, placeholder);
            outer = ClientHelloEncoder.Build(
                selection.Configuration.PublicName,
                outerWithEch,
                randomSource,
                outerKeyShares,
                retry: null,
                fixedFields: new ClientHelloFixedFields(SessionId: inner.SessionId),
                greasePskOffer: pskOffer is null
                    ? null
                    : Tls13GreasePskOffer.From(pskOffer));
            if (outer.Random.AsSpan().SequenceEqual(inner.Random))
            {
                throw new CryptographicException(
                    "ClientHelloInner and ClientHelloOuter random values must be independent.");
            }
            ValidateCompressedOuterExtensions(
                inner.EncodedHandshake,
                outer.EncodedHandshake,
                compression);

            var payload = hpke.Seal(
                outer.EncodedHandshake.AsSpan(TlsConstants.HandshakeHeaderLength),
                encodedInner);
            var (payloadOffset, payloadLength) = LocateOuterPayload(outer.EncodedHandshake);
            if (payloadLength != payload.Length)
            {
                throw new InvalidOperationException("ECH payload placeholder length changed.");
            }
            payload.CopyTo(outer.EncodedHandshake, payloadOffset);
            CryptographicOperations.ZeroMemory(payload);

            var result = new EchClientHelloBuildResult(
                privateServerName,
                inner,
                outer,
                encodedInner,
                hpke,
                selection,
                compression);
            inner = null;
            outer = null;
            encodedInner = null;
            hpke = null;
            return result;
        }
        catch
        {
            innerKeyShares.Dispose();
            outerKeyShares.Dispose();
            throw;
        }
        finally
        {
            inner?.Dispose();
            outer?.Dispose();
            hpke?.Dispose();
            if (encodedInner is not null)
            {
                CryptographicOperations.ZeroMemory(encodedInner);
            }
            if (compressedInner is not null)
            {
                CryptographicOperations.ZeroMemory(compressedInner);
            }
        }
    }

    internal static EchClientHelloRetryBuildResult BuildRetry(
        EchClientHelloBuildResult first,
        NamedGroup selectedGroup,
        byte[]? cookie,
        IRandomSource randomSource,
        KeyShareSet innerKeyShares,
        KeyShareSet outerKeyShares,
        Tls13PskOffer? pskOffer = null)
    {
        ArgumentNullException.ThrowIfNull(first);
        ArgumentNullException.ThrowIfNull(randomSource);
        ArgumentNullException.ThrowIfNull(innerKeyShares);
        ArgumentNullException.ThrowIfNull(outerKeyShares);
        if (!first.Inner.Configuration.SupportedGroups.Contains(selectedGroup) ||
            first.Inner.Configuration.KeyShareGroups.Contains(selectedGroup))
        {
            throw TlsProtocolException.Illegal(
                "ECH HelloRetryRequest selected an unoffered or already-shared inner group.");
        }
        if (!first.Outer.Configuration.SupportedGroups.Contains(selectedGroup))
        {
            throw TlsProtocolException.Illegal(
                "The ECH outer profile cannot encode the HelloRetryRequest-selected group.");
        }
        var innerEch = first.Inner.Configuration.ExtensionLayout.SingleOrDefault(extension =>
            extension.RawExtensionType == (ushort)TlsExtensionType.EncryptedClientHello);
        if (innerEch is null || !innerEch.RawData.SequenceEqual([(byte)1]))
        {
            throw new InvalidOperationException(
                "The first ClientHelloInner does not contain the RFC 9849 inner marker.");
        }

        first.BeginRetry();
        ClientHelloBuildResult? inner = null;
        ClientHelloBuildResult? outer = null;
        byte[]? encodedInner = null;
        byte[]? compressedInner = null;
        try
        {
            inner = ClientHelloEncoder.Build(
                first.PrivateServerName,
                first.Inner.Configuration,
                randomSource,
                innerKeyShares,
                new ClientHelloRetryParameters(
                    first.Inner.Random,
                    first.Inner.SessionId,
                    first.Inner.GreaseValues,
                    selectedGroup,
                    cookie is null ? null : (byte[])cookie.Clone()),
                pskOffer);
            compressedInner = first.CompressedOuterExtensions.Length == 0
                ? null
                : CompressClientHelloInner(
                    inner.EncodedHandshake,
                    first.CompressedOuterExtensions);
            encodedInner = EncodeAndPadInner(
                compressedInner ?? inner.EncodedHandshake,
                first.Selection.Configuration.MaximumNameLength);

            var placeholder = EncodeOuterEch(
                first.Selection,
                [],
                new byte[checked(encodedInner.Length + TlsConstants.AeadTagLength)]);
            var outerConfiguration = ReplaceEchExtension(
                first.Outer.Configuration,
                placeholder);
            outer = ClientHelloEncoder.Build(
                first.Selection.Configuration.PublicName,
                outerConfiguration,
                randomSource,
                outerKeyShares,
                new ClientHelloRetryParameters(
                    first.Outer.Random,
                    first.Outer.SessionId,
                    first.Outer.GreaseValues,
                    selectedGroup,
                    Cookie: null),
                greasePskOffer: pskOffer is null
                    ? null
                    : Tls13GreasePskOffer.From(pskOffer));

            if (!inner.Random.AsSpan().SequenceEqual(first.Inner.Random) ||
                !outer.Random.AsSpan().SequenceEqual(first.Outer.Random) ||
                !inner.SessionId.AsSpan().SequenceEqual(first.Inner.SessionId) ||
                !outer.SessionId.AsSpan().SequenceEqual(first.Outer.SessionId) ||
                !inner.SessionId.AsSpan().SequenceEqual(outer.SessionId))
            {
                throw new InvalidOperationException(
                    "ECH retry changed a ClientHello random or legacy session ID.");
            }
            ValidateCompressedOuterExtensions(
                inner.EncodedHandshake,
                outer.EncodedHandshake,
                first.CompressedOuterExtensions);

            var payload = first.HpkeContext.Seal(
                outer.EncodedHandshake.AsSpan(TlsConstants.HandshakeHeaderLength),
                encodedInner);
            try
            {
                var (payloadOffset, payloadLength) =
                    LocateOuterPayload(outer.EncodedHandshake);
                if (payloadLength != payload.Length)
                {
                    throw new InvalidOperationException(
                        "ECH retry payload placeholder length changed.");
                }
                payload.CopyTo(outer.EncodedHandshake, payloadOffset);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(payload);
            }

            var result = new EchClientHelloRetryBuildResult(inner, outer, encodedInner);
            inner = null;
            outer = null;
            encodedInner = null;
            return result;
        }
        catch
        {
            innerKeyShares.Dispose();
            outerKeyShares.Dispose();
            throw;
        }
        finally
        {
            inner?.Dispose();
            outer?.Dispose();
            if (encodedInner is not null)
            {
                CryptographicOperations.ZeroMemory(encodedInner);
            }
            if (compressedInner is not null)
            {
                CryptographicOperations.ZeroMemory(compressedInner);
            }
        }
    }

    internal static ClientHelloBuildResult BuildOuterRetryAfterRejection(
        EchClientHelloBuildResult first,
        NamedGroup selectedGroup,
        byte[]? cookie,
        IRandomSource randomSource,
        KeyShareSet outerKeyShares,
        Tls13PskOffer? innerPskOffer = null)
    {
        ArgumentNullException.ThrowIfNull(first);
        ArgumentNullException.ThrowIfNull(randomSource);
        ArgumentNullException.ThrowIfNull(outerKeyShares);
        if (!first.Outer.Configuration.SupportedGroups.Contains(selectedGroup) ||
            first.Outer.Configuration.KeyShareGroups.Contains(selectedGroup))
        {
            throw TlsProtocolException.Illegal(
                "Rejected ECH HelloRetryRequest selected an unoffered or already-shared outer group.");
        }

        var firstEchBody = ReadEchExtensionBody(first.Outer.EncodedHandshake);
        var retryConfiguration = ReplaceEchExtension(
            first.Outer.Configuration,
            firstEchBody);
        first.BeginRetry();
        return ClientHelloEncoder.Build(
            first.Selection.Configuration.PublicName,
            retryConfiguration,
            randomSource,
            outerKeyShares,
            new ClientHelloRetryParameters(
                first.Outer.Random,
                first.Outer.SessionId,
                first.Outer.GreaseValues,
                selectedGroup,
                cookie is null ? null : (byte[])cookie.Clone()),
            greasePskOffer: innerPskOffer is null
                ? null
                : Tls13GreasePskOffer.From(innerPskOffer));
    }

    internal static ClientHelloConfiguration InsertEchExtension(
        ClientHelloConfiguration configuration,
        ReadOnlySpan<byte> body)
    {
        if (configuration.ExtensionLayout.Any(extension =>
            extension.RawExtensionType == (ushort)TlsExtensionType.EncryptedClientHello))
        {
            throw new ArgumentException(
                "The supplied ClientHello profile already owns encrypted_client_hello.",
                nameof(configuration));
        }
        var extensions = configuration.ExtensionLayout
            .Select(extension => extension.Snapshot())
            .ToList();
        var managedSlotIndex = extensions.FindIndex(extension =>
            extension.BuiltInKind == ClientHelloExtensionKind.EncryptedClientHello);
        if (managedSlotIndex >= 0)
        {
            extensions[managedSlotIndex] = ClientHelloExtensionSpec.Raw(
                (ushort)TlsExtensionType.EncryptedClientHello,
                body.ToArray());
            return configuration with { ExtensionLayout = extensions.ToArray() };
        }
        var pskIndex = extensions.FindIndex(extension =>
            extension.BuiltInKind == ClientHelloExtensionKind.PreSharedKey);
        extensions.Insert(
            pskIndex < 0 ? extensions.Count : pskIndex,
            ClientHelloExtensionSpec.Raw(
                (ushort)TlsExtensionType.EncryptedClientHello,
                body.ToArray()));
        return configuration with { ExtensionLayout = extensions.ToArray() };
    }

    internal static byte[] CompressClientHelloInner(
        ReadOnlySpan<byte> encodedClientHelloInner,
        IReadOnlyList<TlsExtensionType> outerExtensions)
    {
        ArgumentNullException.ThrowIfNull(outerExtensions);
        if (outerExtensions.Count is 0 or > 127)
        {
            throw new ArgumentException(
                "ech_outer_extensions requires between 1 and 127 extension types.",
                nameof(outerExtensions));
        }
        if (outerExtensions.Distinct().Count() != outerExtensions.Count ||
            outerExtensions.Any(type => type is
                TlsExtensionType.EncryptedClientHello or
                TlsExtensionType.EchOuterExtensions))
        {
            throw new ArgumentException(
                "ech_outer_extensions contains a duplicate or forbidden type.",
                nameof(outerExtensions));
        }

        var parsed = ParseClientHelloExtensions(encodedClientHelloInner);
        var selectedIndices = outerExtensions
            .Select(type => FindUniqueExtension(parsed.Extensions, (ushort)type, "ClientHelloInner"))
            .ToArray();
        for (var index = 1; index < selectedIndices.Length; index++)
        {
            if (selectedIndices[index] != selectedIndices[0] + index)
            {
                throw new InvalidOperationException(
                    $"Compressed extensions must be contiguous and ordered in ClientHelloInner; indices were {string.Join(",", selectedIndices)}.");
            }
        }

        var encodedTypes = new TlsBinaryWriter(outerExtensions.Count * 2);
        foreach (var type in outerExtensions)
        {
            encodedTypes.WriteUInt16((ushort)type);
        }
        var referenceBody = new TlsBinaryWriter(encodedTypes.Length + 1);
        referenceBody.WriteVector8(encodedTypes.WrittenSpan);
        var extensions = new TlsBinaryWriter();
        for (var index = 0; index < parsed.Extensions.Length; index++)
        {
            if (index == selectedIndices[0])
            {
                extensions.WriteUInt16((ushort)TlsExtensionType.EchOuterExtensions);
                extensions.WriteVector16(referenceBody.WrittenSpan);
            }
            if (index >= selectedIndices[0] &&
                index < selectedIndices[0] + selectedIndices.Length)
            {
                continue;
            }
            extensions.WriteUInt16(parsed.Extensions[index].Type);
            extensions.WriteVector16(parsed.Extensions[index].Data);
        }

        var body = new TlsBinaryWriter(parsed.BodyPrefix.Length + extensions.Length + 2);
        body.WriteBytes(parsed.BodyPrefix);
        body.WriteVector16(extensions.WrittenSpan);
        return HandshakeMessage.Encode(HandshakeType.ClientHello, body.WrittenSpan);
    }

    private static void ValidateCompressedOuterExtensions(
        ReadOnlySpan<byte> encodedClientHelloInner,
        ReadOnlySpan<byte> encodedClientHelloOuter,
        IReadOnlyList<TlsExtensionType> outerExtensions)
    {
        if (outerExtensions.Count == 0)
        {
            return;
        }

        var inner = ParseClientHelloExtensions(encodedClientHelloInner).Extensions;
        var outer = ParseClientHelloExtensions(encodedClientHelloOuter).Extensions;
        var previousOuterIndex = -1;
        foreach (var type in outerExtensions)
        {
            var innerIndex = FindUniqueExtension(inner, (ushort)type, "ClientHelloInner");
            var outerIndex = FindUniqueExtension(outer, (ushort)type, "ClientHelloOuter");
            if (outerIndex <= previousOuterIndex)
            {
                throw new InvalidOperationException(
                    "Compressed extensions do not have the same relative order in ClientHelloOuter.");
            }
            if (!inner[innerIndex].Data.AsSpan().SequenceEqual(outer[outerIndex].Data))
            {
                throw new InvalidOperationException(
                    $"Compressed extension 0x{(ushort)type:X4} differs between inner and outer ClientHello.");
            }
            previousOuterIndex = outerIndex;
        }
    }

    private static ParsedClientHelloExtensions ParseClientHelloExtensions(
        ReadOnlySpan<byte> encodedClientHello)
    {
        if (encodedClientHello.Length < TlsConstants.HandshakeHeaderLength ||
            encodedClientHello[0] != (byte)HandshakeType.ClientHello)
        {
            throw new InvalidOperationException("ECH compression input is not a ClientHello.");
        }
        var declaredLength = (encodedClientHello[1] << 16) |
            (encodedClientHello[2] << 8) | encodedClientHello[3];
        if (declaredLength != encodedClientHello.Length - TlsConstants.HandshakeHeaderLength)
        {
            throw new InvalidOperationException("ECH compression ClientHello length is invalid.");
        }

        var body = encodedClientHello[TlsConstants.HandshakeHeaderLength..];
        var offset = 2 + TlsConstants.RandomLength;
        offset = SkipVector8(body, offset);
        offset = SkipVector16(body, offset);
        offset = SkipVector8(body, offset);
        if (offset > body.Length - 2)
        {
            throw new InvalidOperationException("ECH compression ClientHello is truncated.");
        }
        var extensionsLength = BinaryPrimitives.ReadUInt16BigEndian(body[offset..]);
        var extensionsOffset = offset + 2;
        if (extensionsOffset > body.Length - extensionsLength ||
            extensionsOffset + extensionsLength != body.Length)
        {
            throw new InvalidOperationException(
                "ECH compression ClientHello extension vector is malformed.");
        }

        var reader = new TlsBinaryReader(body.Slice(extensionsOffset, extensionsLength));
        var extensions = new List<WireExtension>();
        var seen = new HashSet<ushort>();
        while (!reader.End)
        {
            var type = reader.ReadUInt16();
            var data = reader.ReadVector16().ToArray();
            if (!seen.Add(type))
            {
                throw new InvalidOperationException(
                    "ECH compression ClientHello contains duplicate extensions.");
            }
            extensions.Add(new WireExtension(type, data));
        }
        return new ParsedClientHelloExtensions(
            body[..offset].ToArray(),
            extensions.ToArray());
    }

    private static int FindUniqueExtension(
        IReadOnlyList<WireExtension> extensions,
        ushort type,
        string messageName)
    {
        var found = -1;
        for (var index = 0; index < extensions.Count; index++)
        {
            if (extensions[index].Type != type)
            {
                continue;
            }
            if (found >= 0)
            {
                throw new InvalidOperationException(
                    $"{messageName} contains duplicate extension 0x{type:X4}.");
            }
            found = index;
        }
        return found >= 0
            ? found
            : throw new InvalidOperationException(
                $"{messageName} omitted compressed extension 0x{type:X4}.");
    }

    private static int SkipVector8(ReadOnlySpan<byte> input, int offset)
    {
        if ((uint)offset >= (uint)input.Length)
        {
            throw new InvalidOperationException("ECH compression vector is truncated.");
        }
        var length = input[offset];
        if (offset + 1 > input.Length - length)
        {
            throw new InvalidOperationException("ECH compression vector is truncated.");
        }
        return offset + 1 + length;
    }

    private static int SkipVector16(ReadOnlySpan<byte> input, int offset)
    {
        if (offset < 0 || offset > input.Length - 2)
        {
            throw new InvalidOperationException("ECH compression vector is truncated.");
        }
        var length = BinaryPrimitives.ReadUInt16BigEndian(input[offset..]);
        if (offset + 2 > input.Length - length)
        {
            throw new InvalidOperationException("ECH compression vector is truncated.");
        }
        return offset + 2 + length;
    }

    private sealed record ParsedClientHelloExtensions(
        byte[] BodyPrefix,
        WireExtension[] Extensions);

    private sealed record WireExtension(ushort Type, byte[] Data);

    private static ClientHelloConfiguration ReplaceEchExtension(
        ClientHelloConfiguration configuration,
        ReadOnlySpan<byte> body)
    {
        var replaced = false;
        var replacementBody = body.ToArray();
        var extensions = configuration.ExtensionLayout
            .Select(extension =>
            {
                if (extension.RawExtensionType !=
                    (ushort)TlsExtensionType.EncryptedClientHello)
                {
                    return extension.Snapshot();
                }
                if (replaced)
                {
                    throw new InvalidOperationException(
                        "ClientHelloOuter contains duplicate encrypted_client_hello slots.");
                }
                replaced = true;
                return ClientHelloExtensionSpec.Raw(
                    (ushort)TlsExtensionType.EncryptedClientHello,
                    replacementBody);
            })
            .ToArray();
        if (!replaced)
        {
            throw new InvalidOperationException(
                "ClientHelloOuter omitted encrypted_client_hello.");
        }
        return configuration with { ExtensionLayout = extensions };
    }

    internal static byte[] EncodeAndPadInner(
        ReadOnlySpan<byte> encodedHandshake,
        byte maximumNameLength)
    {
        if (encodedHandshake.Length < TlsConstants.HandshakeHeaderLength + 35 ||
            encodedHandshake[0] != (byte)HandshakeType.ClientHello)
        {
            throw new InvalidOperationException("ClientHelloInner encoding is malformed.");
        }
        var body = encodedHandshake[TlsConstants.HandshakeHeaderLength..];
        const int sessionIdLengthOffset = 2 + TlsConstants.RandomLength;
        var sessionIdLength = body[sessionIdLengthOffset];
        var remainderOffset = sessionIdLengthOffset + 1 + sessionIdLength;
        if (remainderOffset > body.Length)
        {
            throw new InvalidOperationException("ClientHelloInner session ID is truncated.");
        }

        var encoded = new TlsBinaryWriter(body.Length + maximumNameLength + 32);
        encoded.WriteBytes(body[..sessionIdLengthOffset]);
        encoded.WriteUInt8(0);
        encoded.WriteBytes(body[remainderOffset..]);
        var innerServerNameLength = ReadServerNameLength(encodedHandshake);
        var namePadding = innerServerNameLength.HasValue
            ? Math.Max(0, maximumNameLength - innerServerNameLength.Value)
            : maximumNameLength + 9;
        if (namePadding != 0)
        {
            encoded.WriteBytes(new byte[namePadding]);
        }
        var finalPadding = (32 - (encoded.Length & 31)) & 31;
        if (finalPadding != 0)
        {
            encoded.WriteBytes(new byte[finalPadding]);
        }
        if (encoded.Length + 16 > ushort.MaxValue)
        {
            throw new InvalidOperationException(
                "Padded EncodedClientHelloInner exceeds the ECH payload vector bound.");
        }
        return encoded.ToArray();
    }

    private static int? ReadServerNameLength(ReadOnlySpan<byte> encodedHandshake)
    {
        var body = new TlsBinaryReader(
            encodedHandshake[TlsConstants.HandshakeHeaderLength..]);
        _ = body.ReadUInt16();
        _ = body.ReadBytes(TlsConstants.RandomLength);
        _ = body.ReadVector8(TlsConstants.MaxSessionIdLength);
        _ = body.ReadVector16();
        _ = body.ReadVector8();
        var extensions = new TlsBinaryReader(body.ReadVector16());
        body.EnsureEnd("ClientHelloInner");
        while (!extensions.End)
        {
            var type = extensions.ReadUInt16();
            var data = extensions.ReadVector16();
            if (type != (ushort)TlsExtensionType.ServerName)
            {
                continue;
            }
            var dataReader = new TlsBinaryReader(data);
            var names = new TlsBinaryReader(dataReader.ReadVector16());
            dataReader.EnsureEnd("ClientHelloInner server_name");
            if (names.ReadUInt8() != 0)
            {
                throw new InvalidOperationException("ClientHelloInner SNI type is invalid.");
            }
            var name = names.ReadVector16();
            names.EnsureEnd("ClientHelloInner server_name list");
            return name.Length;
        }
        return null;
    }

    private static byte[] EncodeOuterEch(
        EchConfigSelection selection,
        ReadOnlySpan<byte> encapsulatedKey,
        ReadOnlySpan<byte> payload)
    {
        var body = new TlsBinaryWriter();
        body.WriteUInt8(0);
        body.WriteUInt16((ushort)selection.CipherSuite.KdfId);
        body.WriteUInt16((ushort)selection.CipherSuite.AeadId);
        body.WriteUInt8(selection.Configuration.ConfigId);
        body.WriteVector16(encapsulatedKey);
        body.WriteVector16(payload);
        return body.ToArray();
    }

    private static (int Offset, int Length) LocateOuterPayload(byte[] encodedHandshake)
    {
        var span = encodedHandshake.AsSpan();
        var offset = TlsConstants.HandshakeHeaderLength + 2 + TlsConstants.RandomLength;
        offset += 1 + span[offset];
        offset += 2 + BinaryPrimitives.ReadUInt16BigEndian(span[offset..]);
        offset += 1 + span[offset];
        var extensionsLength = BinaryPrimitives.ReadUInt16BigEndian(span[offset..]);
        offset += 2;
        var extensionsEnd = checked(offset + extensionsLength);
        while (offset < extensionsEnd)
        {
            var type = BinaryPrimitives.ReadUInt16BigEndian(span[offset..]);
            var dataLength = BinaryPrimitives.ReadUInt16BigEndian(span[(offset + 2)..]);
            var dataOffset = offset + 4;
            if (type == (ushort)TlsExtensionType.EncryptedClientHello)
            {
                var cursor = dataOffset;
                if (span[cursor++] != 0)
                {
                    throw new InvalidOperationException("ClientHelloOuter ECH type is not outer.");
                }
                cursor += 2 + 2 + 1;
                var encLength = BinaryPrimitives.ReadUInt16BigEndian(span[cursor..]);
                cursor += 2 + encLength;
                var payloadLength = BinaryPrimitives.ReadUInt16BigEndian(span[cursor..]);
                cursor += 2;
                if (cursor + payloadLength != dataOffset + dataLength ||
                    span.Slice(cursor, payloadLength).IndexOfAnyExcept((byte)0) >= 0)
                {
                    throw new InvalidOperationException("ClientHelloOuter ECH placeholder is malformed.");
                }
                return (cursor, payloadLength);
            }
            offset = checked(dataOffset + dataLength);
        }
        throw new InvalidOperationException("ClientHelloOuter omitted encrypted_client_hello.");
    }

    private static byte[] ReadEchExtensionBody(ReadOnlySpan<byte> encodedHandshake)
    {
        var body = new TlsBinaryReader(
            encodedHandshake[TlsConstants.HandshakeHeaderLength..]);
        _ = body.ReadUInt16();
        _ = body.ReadBytes(TlsConstants.RandomLength);
        _ = body.ReadVector8(TlsConstants.MaxSessionIdLength);
        _ = body.ReadVector16();
        _ = body.ReadVector8();
        var extensions = new TlsBinaryReader(body.ReadVector16());
        body.EnsureEnd("ClientHelloOuter");
        while (!extensions.End)
        {
            var type = extensions.ReadUInt16();
            var data = extensions.ReadVector16();
            if (type == (ushort)TlsExtensionType.EncryptedClientHello)
            {
                return data.ToArray();
            }
        }
        throw new InvalidOperationException(
            "ClientHelloOuter omitted encrypted_client_hello.");
    }
}
