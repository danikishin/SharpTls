using System.Globalization;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using SharpTls.Cryptography;
using SharpTls.Handshake;
using SharpTls.IO;
using SharpTls.Protocol;

namespace SharpTls;

internal sealed record ClientHelloRetryParameters(
    byte[] Random,
    byte[] SessionId,
    ClientHelloGreaseValues? GreaseValues,
    NamedGroup SelectedGroup,
    byte[]? Cookie);

internal sealed record ClientHelloFixedFields(
    byte[]? Random = null,
    byte[]? SessionId = null,
    IReadOnlyDictionary<ushort, byte[]>? RawExtensionOverrides = null);

internal readonly record struct ClientHelloGreaseValues(
    ushort CipherSuite,
    ushort SupportedVersion,
    ushort SupportedGroup,
    ushort KeyShare,
    ushort Extension,
    ushort SecondaryExtension)
{
    internal ushort Get(ClientHelloGreaseSlot slot) => slot switch
    {
        ClientHelloGreaseSlot.CipherSuite => CipherSuite,
        ClientHelloGreaseSlot.SupportedVersion => SupportedVersion,
        ClientHelloGreaseSlot.SupportedGroup => SupportedGroup,
        ClientHelloGreaseSlot.KeyShare => KeyShare,
        ClientHelloGreaseSlot.Extension => Extension,
        ClientHelloGreaseSlot.SecondaryExtension => SecondaryExtension,
        _ => throw new ArgumentOutOfRangeException(nameof(slot)),
    };
}

internal sealed class ClientHelloBuildResult : IDisposable
{
    internal ClientHelloBuildResult(
        byte[] encodedHandshake,
        byte[] random,
        byte[] sessionId,
        ClientHelloGreaseValues? greaseValues,
        KeyShareSet keyShares,
        ClientHelloConfiguration configuration,
        int offeredPskCount)
    {
        EncodedHandshake = encodedHandshake;
        Random = random;
        SessionId = sessionId;
        GreaseValues = greaseValues;
        KeyShares = keyShares;
        Configuration = configuration;
        OfferedPskCount = offeredPskCount;
    }

    internal byte[] EncodedHandshake { get; }
    internal byte[] Random { get; }
    internal byte[] SessionId { get; }
    internal ClientHelloGreaseValues? GreaseValues { get; }
    internal KeyShareSet KeyShares { get; }
    internal ClientHelloConfiguration Configuration { get; }
    internal int OfferedPskCount { get; }

    public void Dispose() => KeyShares.Dispose();
}

internal static class ClientHelloEncoder
{
    internal static ClientHelloBuildResult BuildRetry(
        ClientHelloBuildResult first,
        NamedGroup selectedGroup,
        byte[]? cookie,
        Tls13PskOffer? pskOffer = null)
    {
        ArgumentNullException.ThrowIfNull(first);
        if (!first.Configuration.SupportedGroups.Contains(selectedGroup) ||
            first.Configuration.KeyShareGroups.Contains(selectedGroup))
        {
            throw TlsProtocolException.Illegal(
                "HelloRetryRequest selected a group that was unoffered or already had a key share.");
        }

        return Build(
            serverName: ExtractServerNameForRetry(first),
            first.Configuration,
            SecureRandomSource.Instance,
            new KeyShareSet(),
            new ClientHelloRetryParameters(
                first.Random,
                first.SessionId,
                first.GreaseValues,
                selectedGroup,
                cookie is null ? null : (byte[])cookie.Clone()),
            pskOffer);
    }

    internal static ClientHelloBuildResult Build(
        string serverName,
        ClientHelloConfiguration configuration,
        IRandomSource randomSource,
        KeyShareSet keyShareSet,
        ClientHelloRetryParameters? retry,
        Tls13PskOffer? pskOffer = null,
        ClientHelloFixedFields? fixedFields = null,
        Tls13GreasePskOffer? greasePskOffer = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(serverName);
        ArgumentNullException.ThrowIfNull(configuration);
        ArgumentNullException.ThrowIfNull(randomSource);
        ArgumentNullException.ThrowIfNull(keyShareSet);
        if (pskOffer is not null && greasePskOffer.HasValue)
        {
            throw new ArgumentException(
                "A ClientHello cannot contain both a real and GREASE PSK offer.");
        }

        try
        {
            var normalizedServerName = NormalizeServerName(serverName, configuration.IncludeSni);
            if (fixedFields?.Random is { Length: not TlsConstants.RandomLength })
            {
                throw new ArgumentException("A fixed ClientHello random must contain 32 bytes.");
            }
            if (fixedFields?.SessionId is { Length: > TlsConstants.MaxSessionIdLength })
            {
                throw new ArgumentException("A fixed ClientHello session ID exceeds 32 bytes.");
            }
            if (fixedFields?.RawExtensionOverrides is { } rawOverrides)
            {
                var configuredRawTypes = configuration.ExtensionLayout
                    .Where(extension => extension.RawExtensionType.HasValue)
                    .Select(extension => extension.RawExtensionType!.Value)
                    .ToHashSet();
                foreach (var pair in rawOverrides)
                {
                    ArgumentNullException.ThrowIfNull(pair.Value);
                    if (!configuredRawTypes.Contains(pair.Key))
                    {
                        throw new ArgumentException(
                            $"Raw extension override 0x{pair.Key:X4} has no configured raw slot.");
                    }
                    if (pair.Value.Length > ushort.MaxValue)
                    {
                        throw new ArgumentOutOfRangeException(
                            nameof(fixedFields),
                            "A raw extension override exceeds 65535 bytes.");
                    }
                }
            }
            var random = fixedFields?.Random is { } fixedRandom
                ? (byte[])fixedRandom.Clone()
                : retry?.Random is { } retryRandom
                ? (byte[])retryRandom.Clone()
                : Fill(randomSource, TlsConstants.RandomLength);
            var sessionId = fixedFields?.SessionId is { } fixedSessionId
                ? (byte[])fixedSessionId.Clone()
                : retry?.SessionId is { } retrySessionId
                ? (byte[])retrySessionId.Clone()
                : configuration.SessionId is { } configuredSessionId
                    ? (byte[])configuredSessionId.Clone()
                    : Fill(randomSource, TlsConstants.MaxSessionIdLength);
            ClientHelloGreaseValues? greaseValues = configuration.GreasePolicy is { } greasePolicy
                ? retry?.GreaseValues ?? SelectGreaseValues(
                    greasePolicy,
                    configuration.SecondaryGreaseExtensionBody is not null,
                    randomSource)
                : null;

            var keyShareGroups = retry is null
                ? configuration.KeyShareGroups
                : [retry.SelectedGroup];
            var keyShares = keyShareSet.Generate(keyShareGroups);
            var greaseKeyShareBody = configuration.GreasePolicy is not null && retry is null
                ? configuration.FixedGreaseKeyShareBody is { } fixedBody
                    ? (byte[])fixedBody.Clone()
                    : Fill(randomSource, 1)
                : null;

            if (retry is null && configuration.ShuffleExtensions)
            {
                configuration = configuration with
                {
                    ShuffleExtensions = false,
                    ExtensionLayout = ShuffleChromeExtensions(
                        GetActiveExtensionLayout(
                            configuration.ExtensionLayout,
                            pskOffer,
                            greasePskOffer),
                        randomSource),
                };
            }

            var extensions = BuildExtensions(
                normalizedServerName,
                configuration,
                keyShares,
                greaseValues,
                greaseKeyShareBody,
                retry,
                pskOffer,
                greasePskOffer,
                randomSource,
                fixedFields?.RawExtensionOverrides);

            var suitesWriter = new TlsBinaryWriter();
            if (greaseValues.HasValue)
            {
                suitesWriter.WriteUInt16(greaseValues.Value.CipherSuite);
            }
            foreach (var suite in configuration.CipherSuites)
            {
                suitesWriter.WriteUInt16((ushort)suite);
            }

            if (configuration.UseBoringPadding)
            {
                ApplyBoringPadding(extensions, sessionId.Length, suitesWriter.Length);
            }

            var extensionsWriter = new TlsBinaryWriter();
            foreach (var extension in extensions)
            {
                extensionsWriter.WriteUInt16(extension.Type);
                extensionsWriter.WriteVector16(extension.Data);
            }

            var body = new TlsBinaryWriter();
            body.WriteUInt16(TlsConstants.LegacyRecordVersion);
            body.WriteBytes(random);
            body.WriteVector8(sessionId);
            body.WriteVector16(suitesWriter.WrittenSpan);
            body.WriteVector8([0]);
            body.WriteVector16(extensionsWriter.WrittenSpan);

            var encoded = HandshakeMessage.Encode(HandshakeType.ClientHello, body.WrittenSpan);
            if (pskOffer is not null)
            {
                ApplyPskBinder(encoded, pskOffer);
            }
            return new ClientHelloBuildResult(
                encoded,
                random,
                sessionId,
                greaseValues,
                keyShareSet,
                retry is null
                    ? configuration
                    : configuration with { KeyShareGroups = [retry.SelectedGroup] },
                pskOffer?.Count ?? greasePskOffer?.IdentityLengths.Length ?? 0);
        }
        catch
        {
            keyShareSet.Dispose();
            throw;
        }
    }

    private static List<EncodedExtension> BuildExtensions(
        string? normalizedServerName,
        ClientHelloConfiguration configuration,
        IReadOnlyList<IKeyShare> keyShares,
        ClientHelloGreaseValues? greaseValues,
        byte[]? greaseKeyShareBody,
        ClientHelloRetryParameters? retry,
        Tls13PskOffer? pskOffer,
        Tls13GreasePskOffer? greasePskOffer,
        IRandomSource randomSource,
        IReadOnlyDictionary<ushort, byte[]>? rawExtensionOverrides)
    {
        var order = configuration.ExtensionLayout
            .Select(extension => extension.Snapshot())
            .ToList();
        if (retry?.Cookie is not null)
        {
            var keyShareIndex = order.FindIndex(extension =>
                extension.BuiltInKind == ClientHelloExtensionKind.KeyShare);
            if (keyShareIndex < 0)
            {
                throw new InvalidOperationException("ClientHello layout has no key_share slot.");
            }

            order.Insert(
                keyShareIndex,
                ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.Cookie));
        }

        var result = new List<EncodedExtension>(order.Count);
        foreach (var extension in order)
        {
            if (extension.BuiltInKind == ClientHelloExtensionKind.PreSharedKey &&
                pskOffer is null && !greasePskOffer.HasValue)
            {
                continue;
            }
            if (extension.BuiltInKind == ClientHelloExtensionKind.EarlyData &&
                pskOffer?.OfferEarlyData != true &&
                greasePskOffer?.OfferEarlyData != true)
            {
                continue;
            }
            if (extension.BuiltInKind is not { } kind)
            {
                var rawType = extension.RawExtensionType!.Value;
                result.Add(new EncodedExtension(
                    rawType,
                    rawExtensionOverrides is not null &&
                        rawExtensionOverrides.TryGetValue(rawType, out var overrideData)
                        ? (byte[])overrideData.Clone()
                        : extension.RawData.ToArray()));
                continue;
            }

            result.Add(kind switch
            {
                ClientHelloExtensionKind.Grease => new EncodedExtension(
                    greaseValues!.Value.Extension,
                    []),
                ClientHelloExtensionKind.SecondaryGrease => new EncodedExtension(
                    greaseValues!.Value.SecondaryExtension,
                    (byte[])configuration.SecondaryGreaseExtensionBody!.Clone()),
                ClientHelloExtensionKind.ServerName => EncodeServerName(normalizedServerName!),
                ClientHelloExtensionKind.SupportedVersions => EncodeSupportedVersions(
                    configuration.SupportedVersions,
                    greaseValues?.SupportedVersion),
                ClientHelloExtensionKind.Cookie => EncodeCookie(retry!.Cookie!),
                ClientHelloExtensionKind.SupportedGroups => EncodeSupportedGroups(
                    configuration.SupportedGroups,
                    greaseValues?.SupportedGroup),
                ClientHelloExtensionKind.SignatureAlgorithms => EncodeSignatureAlgorithms(
                    configuration.SignatureAlgorithms),
                ClientHelloExtensionKind.SignatureAlgorithmsCert => EncodeSignatureAlgorithmsCert(
                    configuration.CertificateSignatureAlgorithms!),
                ClientHelloExtensionKind.KeyShare => EncodeKeyShares(
                    keyShares,
                    retry is null ? greaseValues?.KeyShare : null,
                    greaseKeyShareBody),
                ClientHelloExtensionKind.PskKeyExchangeModes => new EncodedExtension(
                    (ushort)TlsExtensionType.PskKeyExchangeModes,
                    [1, 1]),
                ClientHelloExtensionKind.EarlyData => new EncodedExtension(
                    (ushort)TlsExtensionType.EarlyData,
                    []),
                ClientHelloExtensionKind.PreSharedKey => pskOffer is not null
                    ? EncodePreSharedKey(pskOffer)
                    : EncodeGreasePreSharedKey(greasePskOffer!.Value, randomSource),
                ClientHelloExtensionKind.ApplicationLayerProtocolNegotiation => EncodeAlpn(
                    configuration.AlpnProtocols),
                ClientHelloExtensionKind.ApplicationSettings => EncodeApplicationSettings(
                    configuration.ApplicationSettingsCodePoint!.Value,
                    configuration.ApplicationSettingsProtocols),
                ClientHelloExtensionKind.PostHandshakeAuthentication => new EncodedExtension(
                    (ushort)TlsExtensionType.PostHandshakeAuthentication,
                    []),
                ClientHelloExtensionKind.RecordSizeLimit => EncodeRecordSizeLimit(
                    configuration.RecordSizeLimit!.Value),
                ClientHelloExtensionKind.DelegatedCredential => EncodeSignatureAlgorithms(
                    TlsExtensionType.DelegatedCredential,
                    configuration.DelegatedCredentialSignatureAlgorithms!),
                ClientHelloExtensionKind.QuicTransportParameters => new EncodedExtension(
                    (ushort)TlsExtensionType.QuicTransportParameters,
                    (byte[])configuration.QuicTransportParameters!.Clone()),
                ClientHelloExtensionKind.EncryptedClientHello =>
                    throw new InvalidOperationException(
                        "The managed ECH slot was not populated by an ECH builder."),
                ClientHelloExtensionKind.Padding => new EncodedExtension(
                    (ushort)TlsExtensionType.Padding,
                    new byte[configuration.PaddingLength ?? 0]),
                _ => throw new InvalidOperationException($"Unknown ClientHello extension kind {kind}."),
            });
        }

        if (result.Select(extension => extension.Type).Distinct().Count() != result.Count)
        {
            throw new InvalidOperationException("ClientHello contains duplicate extension types.");
        }

        return result;
    }

    private static ClientHelloExtensionSpec[] ShuffleChromeExtensions(
        IReadOnlyList<ClientHelloExtensionSpec> extensions,
        IRandomSource randomSource)
    {
        var result = extensions.Select(extension => extension.Snapshot()).ToArray();
        for (var index = result.Length - 1; index > 0; index--)
        {
            var swapIndex = NextInt32(randomSource, index + 1);
            if (IsChromeShuffleInvariant(result[index]) ||
                IsChromeShuffleInvariant(result[swapIndex]))
            {
                continue;
            }

            (result[index], result[swapIndex]) = (result[swapIndex], result[index]);
        }

        return result;
    }

    private static ClientHelloExtensionSpec[] GetActiveExtensionLayout(
        IEnumerable<ClientHelloExtensionSpec> extensions,
        Tls13PskOffer? pskOffer,
        Tls13GreasePskOffer? greasePskOffer) => extensions
        .Where(extension => extension.BuiltInKind switch
        {
            ClientHelloExtensionKind.PreSharedKey =>
                pskOffer is not null || greasePskOffer.HasValue,
            ClientHelloExtensionKind.EarlyData =>
                pskOffer?.OfferEarlyData == true || greasePskOffer?.OfferEarlyData == true,
            _ => true,
        })
        .Select(extension => extension.Snapshot())
        .ToArray();

    private static bool IsChromeShuffleInvariant(ClientHelloExtensionSpec extension) =>
        extension.BuiltInKind is ClientHelloExtensionKind.Grease or
            ClientHelloExtensionKind.SecondaryGrease or
            ClientHelloExtensionKind.Padding or
            ClientHelloExtensionKind.PreSharedKey;

    private static int NextInt32(IRandomSource randomSource, int exclusiveUpperBound)
    {
        if (exclusiveUpperBound <= 0)
        {
            throw new ArgumentOutOfRangeException(nameof(exclusiveUpperBound));
        }

        var bound = (uint)exclusiveUpperBound;
        var threshold = unchecked(0u - bound) % bound;
        Span<byte> bytes = stackalloc byte[sizeof(uint)];
        uint value;
        do
        {
            randomSource.Fill(bytes);
            value = System.Buffers.Binary.BinaryPrimitives.ReadUInt32BigEndian(bytes);
        }
        while (value < threshold);

        return (int)(value % bound);
    }

    private static void ApplyBoringPadding(
        List<EncodedExtension> extensions,
        int sessionIdLength,
        int cipherSuitesLength)
    {
        var paddingIndex = extensions.FindIndex(extension =>
            extension.Type == (ushort)TlsExtensionType.Padding);
        if (paddingIndex < 0)
        {
            throw new InvalidOperationException("Boring padding is enabled without a padding slot.");
        }

        extensions.RemoveAt(paddingIndex);
        var extensionsLength = extensions.Sum(extension => 4 + extension.Data.Length);
        var unpaddedLength = TlsConstants.HandshakeHeaderLength +
            2 + TlsConstants.RandomLength + 1 + sessionIdLength +
            2 + cipherSuitesLength + 2 + 2 + extensionsLength;
        if (unpaddedLength <= 0xFF || unpaddedLength >= 0x200)
        {
            return;
        }

        var paddingLength = 0x200 - unpaddedLength;
        paddingLength = paddingLength >= 5 ? paddingLength - 4 : 1;
        extensions.Insert(
            paddingIndex,
            new EncodedExtension((ushort)TlsExtensionType.Padding, new byte[paddingLength]));
    }

    private static EncodedExtension EncodeServerName(string serverName)
    {
        var name = Encoding.ASCII.GetBytes(serverName);
        var entry = new TlsBinaryWriter();
        entry.WriteUInt8(0);
        entry.WriteVector16(name);
        var data = new TlsBinaryWriter();
        data.WriteVector16(entry.WrittenSpan);
        return new EncodedExtension((ushort)TlsExtensionType.ServerName, data.ToArray());
    }

    private static EncodedExtension EncodeApplicationSettings(
        TlsApplicationSettingsCodePoint codePoint,
        IReadOnlyList<string> protocols)
    {
        var encoded = EncodeAlpn(protocols);
        return new EncodedExtension((ushort)codePoint, encoded.Data);
    }

    private static EncodedExtension EncodeSupportedVersions(
        IReadOnlyList<TlsProtocolVersion> supportedVersions,
        ushort? greaseValue)
    {
        var versions = new TlsBinaryWriter();
        if (greaseValue.HasValue)
        {
            versions.WriteUInt16(greaseValue.Value);
        }
        foreach (var version in supportedVersions)
        {
            versions.WriteUInt16((ushort)version);
        }
        var data = new TlsBinaryWriter();
        data.WriteVector8(versions.WrittenSpan);
        return new EncodedExtension((ushort)TlsExtensionType.SupportedVersions, data.ToArray());
    }

    private static EncodedExtension EncodeSupportedGroups(
        IReadOnlyList<NamedGroup> groups,
        ushort? greaseValue)
    {
        var values = new TlsBinaryWriter();
        if (greaseValue.HasValue)
        {
            values.WriteUInt16(greaseValue.Value);
        }
        foreach (var group in groups)
        {
            values.WriteUInt16((ushort)group);
        }
        var data = new TlsBinaryWriter();
        data.WriteVector16(values.WrittenSpan);
        return new EncodedExtension((ushort)TlsExtensionType.SupportedGroups, data.ToArray());
    }

    private static EncodedExtension EncodeSignatureAlgorithms(IReadOnlyList<SignatureScheme> algorithms)
        => EncodeSignatureAlgorithms(
            TlsExtensionType.SignatureAlgorithms,
            algorithms);

    private static EncodedExtension EncodeSignatureAlgorithmsCert(
        IReadOnlyList<SignatureScheme> algorithms) => EncodeSignatureAlgorithms(
            TlsExtensionType.SignatureAlgorithmsCert,
            algorithms);

    private static EncodedExtension EncodeSignatureAlgorithms(
        TlsExtensionType extensionType,
        IReadOnlyList<SignatureScheme> algorithms)
    {
        var values = new TlsBinaryWriter();
        foreach (var algorithm in algorithms)
        {
            values.WriteUInt16((ushort)algorithm);
        }
        var data = new TlsBinaryWriter();
        data.WriteVector16(values.WrittenSpan);
        return new EncodedExtension((ushort)extensionType, data.ToArray());
    }

    private static EncodedExtension EncodeKeyShares(
        IReadOnlyList<IKeyShare> keyShares,
        ushort? greaseValue,
        byte[]? greaseKeyShareBody)
    {
        var entries = new TlsBinaryWriter();
        if (greaseValue.HasValue)
        {
            entries.WriteUInt16(greaseValue.Value);
            entries.WriteVector16(greaseKeyShareBody!);
        }
        foreach (var keyShare in keyShares)
        {
            entries.WriteUInt16((ushort)keyShare.Group);
            entries.WriteVector16(keyShare.PublicKey.Span);
        }
        var data = new TlsBinaryWriter();
        data.WriteVector16(entries.WrittenSpan);
        return new EncodedExtension((ushort)TlsExtensionType.KeyShare, data.ToArray());
    }

    private static EncodedExtension EncodeAlpn(IReadOnlyList<string> protocols)
    {
        var names = new TlsBinaryWriter();
        foreach (var protocol in protocols)
        {
            names.WriteVector8(Encoding.ASCII.GetBytes(protocol));
        }
        var data = new TlsBinaryWriter();
        data.WriteVector16(names.WrittenSpan);
        return new EncodedExtension(
            (ushort)TlsExtensionType.ApplicationLayerProtocolNegotiation,
            data.ToArray());
    }

    private static EncodedExtension EncodeRecordSizeLimit(int limit)
    {
        var data = new TlsBinaryWriter(2);
        data.WriteUInt16(checked((ushort)limit));
        return new EncodedExtension((ushort)TlsExtensionType.RecordSizeLimit, data.ToArray());
    }

    private static EncodedExtension EncodeCookie(ReadOnlySpan<byte> cookie)
    {
        var data = new TlsBinaryWriter();
        data.WriteVector16(cookie);
        return new EncodedExtension((ushort)TlsExtensionType.Cookie, data.ToArray());
    }

    private static EncodedExtension EncodePreSharedKey(Tls13PskOffer offer)
    {
        var identities = new TlsBinaryWriter();
        var identityEntries = new TlsBinaryWriter();
        var binderEntries = new TlsBinaryWriter();
        for (var index = 0; index < offer.Count; index++)
        {
            identityEntries.WriteVector16(offer.GetIdentity(index));
            identityEntries.WriteUInt32(offer.GetObfuscatedAge(index));
            var suite = CipherSuiteInfo.Get(offer.GetCipherSuite(index));
            binderEntries.WriteVector8(new byte[suite.HashLength]);
        }
        identities.WriteVector16(identityEntries.WrittenSpan);

        var binders = new TlsBinaryWriter();
        binders.WriteVector16(binderEntries.WrittenSpan);

        var data = new TlsBinaryWriter();
        data.WriteBytes(identities.WrittenSpan);
        data.WriteBytes(binders.WrittenSpan);
        return new EncodedExtension((ushort)TlsExtensionType.PreSharedKey, data.ToArray());
    }

    private static EncodedExtension EncodeGreasePreSharedKey(
        Tls13GreasePskOffer offer,
        IRandomSource randomSource)
    {
        if (offer.IdentityLengths.Length is < 1 or > 64 ||
            offer.BinderLengths.Length != offer.IdentityLengths.Length ||
            offer.ProhibitedIdentities.Length != offer.IdentityLengths.Length ||
            offer.IdentityLengths.Where((length, index) =>
                length is < 1 or > ushort.MaxValue ||
                offer.BinderLengths[index] is < 1 or > byte.MaxValue ||
                offer.ProhibitedIdentities[index].Length != length).Any())
        {
            throw new ArgumentOutOfRangeException(
                nameof(offer),
                "A GREASE PSK must mirror valid inner identity and binder lengths.");
        }

        var generatedIdentities = new List<byte[]>(offer.IdentityLengths.Length);
        var generatedAges = new List<byte[]>(offer.IdentityLengths.Length);
        var generatedBinders = new List<byte[]>(offer.IdentityLengths.Length);
        try
        {
            var identityEntries = new TlsBinaryWriter();
            var binderEntries = new TlsBinaryWriter();
            for (var index = 0; index < offer.IdentityLengths.Length; index++)
            {
                var identityBytes = Fill(randomSource, offer.IdentityLengths[index]);
                if (identityBytes.AsSpan().SequenceEqual(offer.ProhibitedIdentities[index]))
                {
                    identityBytes[0] ^= 1;
                }
                var ageBytes = Fill(randomSource, sizeof(uint));
                var binderBytes = Fill(randomSource, offer.BinderLengths[index]);
                generatedIdentities.Add(identityBytes);
                generatedAges.Add(ageBytes);
                generatedBinders.Add(binderBytes);
                identityEntries.WriteVector16(identityBytes);
                identityEntries.WriteBytes(ageBytes);
                binderEntries.WriteVector8(binderBytes);
            }
            var identities = new TlsBinaryWriter();
            identities.WriteVector16(identityEntries.WrittenSpan);

            var binders = new TlsBinaryWriter();
            binders.WriteVector16(binderEntries.WrittenSpan);

            var data = new TlsBinaryWriter();
            data.WriteBytes(identities.WrittenSpan);
            data.WriteBytes(binders.WrittenSpan);
            return new EncodedExtension(
                (ushort)TlsExtensionType.PreSharedKey,
                data.ToArray());
        }
        finally
        {
            foreach (var value in generatedIdentities)
            {
                CryptographicOperations.ZeroMemory(value);
            }
            foreach (var value in generatedAges)
            {
                CryptographicOperations.ZeroMemory(value);
            }
            foreach (var value in generatedBinders)
            {
                CryptographicOperations.ZeroMemory(value);
            }
        }
    }

    private static void ApplyPskBinder(Span<byte> encodedClientHello, Tls13PskOffer offer)
    {
        var binderLengths = Enumerable.Range(0, offer.Count)
            .Select(index => CipherSuiteInfo.Get(
                offer.GetCipherSuite(index)).HashLength)
            .ToArray();
        var encodedBindersLength = checked(
            2 + binderLengths.Sum(length => 1 + length));
        if (encodedClientHello.Length <= encodedBindersLength)
        {
            throw new InvalidOperationException("Encoded ClientHello has no PSK binder prefix.");
        }

        var truncatedLength = encodedClientHello.Length - encodedBindersLength;
        var binderOffset = truncatedLength + 2;
        for (var index = 0; index < offer.Count; index++)
        {
            var suite = CipherSuiteInfo.Get(offer.GetCipherSuite(index));
            if (encodedClientHello[binderOffset] != suite.HashLength)
            {
                throw new InvalidOperationException("Encoded PSK binder length changed.");
            }
            using var transcript = IncrementalHash.CreateHash(suite.HashAlgorithm);
            if (offer.GetBinderTranscriptPrefix(index) is { } prefix)
            {
                transcript.AppendData(prefix);
            }
            transcript.AppendData(encodedClientHello[..truncatedLength]);
            var binderHash = new byte[suite.HashLength];
            transcript.GetHashAndReset(binderHash);
            var psk = offer.CopyPsk(index);
            byte[]? binder = null;
            try
            {
                using var schedule = new Tls13KeySchedule(suite, psk);
                binder = offer.IsExternalAt(index)
                    ? schedule.ComputeExternalBinder(binderHash)
                    : schedule.ComputeResumptionBinder(binderHash);
                binder.CopyTo(encodedClientHello[(binderOffset + 1)..]);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(binderHash);
                CryptographicOperations.ZeroMemory(psk);
                if (binder is not null)
                {
                    CryptographicOperations.ZeroMemory(binder);
                }
            }
            binderOffset += 1 + suite.HashLength;
        }
        if (binderOffset != encodedClientHello.Length)
        {
            throw new InvalidOperationException("Encoded PSK binders did not end ClientHello.");
        }
    }

    private static string? NormalizeServerName(string serverName, bool includeSni)
    {
        if (!includeSni)
        {
            return null;
        }

        if (IPAddress.TryParse(serverName, out _))
        {
            throw new ArgumentException("SNI cannot contain an IP address; disable SNI explicitly.", nameof(serverName));
        }

        var withoutFinalDot = serverName.EndsWith(".", StringComparison.Ordinal)
            ? serverName[..^1]
            : serverName;
        var ascii = new IdnMapping().GetAscii(withoutFinalDot);
        if (ascii.Length is < 1 or > 253 || ascii.Contains('\0', StringComparison.Ordinal))
        {
            throw new ArgumentException("The SNI DNS name is invalid.", nameof(serverName));
        }

        return ascii;
    }

    private static string ExtractServerNameForRetry(ClientHelloBuildResult first)
    {
        var body = new TlsBinaryReader(first.EncodedHandshake.AsSpan(TlsConstants.HandshakeHeaderLength));
        _ = body.ReadUInt16();
        _ = body.ReadBytes(TlsConstants.RandomLength);
        _ = body.ReadVector8(TlsConstants.MaxSessionIdLength);
        _ = body.ReadVector16();
        _ = body.ReadVector8();
        var extensions = new TlsBinaryReader(body.ReadVector16());
        while (!extensions.End)
        {
            var type = extensions.ReadUInt16();
            var data = extensions.ReadVector16();
            if (type != (ushort)TlsExtensionType.ServerName)
            {
                continue;
            }

            var sni = new TlsBinaryReader(data);
            var names = new TlsBinaryReader(sni.ReadVector16());
            if (names.ReadUInt8() != 0)
            {
                throw new InvalidOperationException("Encoded SNI has an unexpected name type.");
            }

            return Encoding.ASCII.GetString(names.ReadVector16());
        }

        return "retry.invalid";
    }

    private static byte[] Fill(IRandomSource randomSource, int length)
    {
        var result = new byte[length];
        randomSource.Fill(result);
        return result;
    }

    private static ushort SelectGrease(IRandomSource randomSource)
    {
        Span<byte> selection = stackalloc byte[1];
        randomSource.Fill(selection);
        return (ushort)(0x0A0A + ((selection[0] & 0x0F) * 0x1010));
    }

    private static ClientHelloGreaseValues SelectGreaseValues(
        ClientHelloGreasePolicy policy,
        bool includeSecondaryExtension,
        IRandomSource randomSource)
    {
        var generatedCount = includeSecondaryExtension
            ? policy.DistinctValueCount
            : policy.ValueClasses.Distinct().Count();
        var generated = new ushort[generatedCount];
        for (var valueClass = 0; valueClass < generated.Length; valueClass++)
        {
            ushort selected;
            do
            {
                selected = SelectGrease(randomSource);
            }
            while (generated.AsSpan(0, valueClass).Contains(selected));
            generated[valueClass] = selected;
        }

        return new ClientHelloGreaseValues(
            generated[policy.GetValueClass(ClientHelloGreaseSlot.CipherSuite)],
            generated[policy.GetValueClass(ClientHelloGreaseSlot.SupportedVersion)],
            generated[policy.GetValueClass(ClientHelloGreaseSlot.SupportedGroup)],
            generated[policy.GetValueClass(ClientHelloGreaseSlot.KeyShare)],
            generated[policy.GetValueClass(ClientHelloGreaseSlot.Extension)],
            includeSecondaryExtension
                ? generated[policy.GetValueClass(ClientHelloGreaseSlot.SecondaryExtension)]
                : generated[policy.GetValueClass(ClientHelloGreaseSlot.Extension)]);
    }

    private sealed record EncodedExtension(ushort Type, byte[] Data);
}
