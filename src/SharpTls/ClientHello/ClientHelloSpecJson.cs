using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using SharpTls.Protocol;
using SharpTls.Quic;

namespace SharpTls;

/// <summary>Controls bounded ClientHello specification JSON processing.</summary>
public sealed class ClientHelloSpecJsonOptions
{
    /// <summary>Gets or sets the maximum UTF-8 document size.</summary>
    public int MaximumDocumentSize { get; set; } = 256 * 1024;

    /// <summary>Gets or sets whether serialized JSON is indented.</summary>
    public bool WriteIndented { get; set; }
}

/// <summary>Imports and exports the versioned SharpTls ClientHello specification format.</summary>
public static class ClientHelloSpecJson
{
    private const string FormatName = "sharptls-clienthello-spec";
    private const int CurrentVersion = 6;

    private static readonly JsonDocumentOptions DocumentOptions = new()
    {
        AllowTrailingCommas = false,
        CommentHandling = JsonCommentHandling.Disallow,
        MaxDepth = 32,
    };

    private static readonly JsonSerializerOptions SerializerOptions = new()
    {
        MaxDepth = 32,
        PropertyNameCaseInsensitive = false,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
    };

    /// <summary>Serializes a specification without random, key shares, binders, or secrets.</summary>
    public static byte[] SerializeUtf8(
        ClientHelloSpec spec,
        ClientHelloSpecJsonOptions? options = null)
    {
        ArgumentNullException.ThrowIfNull(spec);
        options ??= new ClientHelloSpecJsonOptions();
        ValidateOptions(options);

        var serializerOptions = new JsonSerializerOptions(SerializerOptions)
        {
            WriteIndented = options.WriteIndented,
        };
        var result = JsonSerializer.SerializeToUtf8Bytes(CreateDocument(spec), serializerOptions);
        if (result.Length > options.MaximumDocumentSize)
        {
            throw new InvalidOperationException(
                "Serialized ClientHello specification exceeds the configured JSON size limit.");
        }

        return result;
    }

    /// <summary>Serializes a specification as UTF-8 JSON text.</summary>
    public static string Serialize(
        ClientHelloSpec spec,
        ClientHelloSpecJsonOptions? options = null) =>
        Encoding.UTF8.GetString(SerializeUtf8(spec, options));

    /// <summary>Parses a strict, bounded UTF-8 versioned specification document.</summary>
    public static ClientHelloSpec Deserialize(
        ReadOnlySpan<byte> utf8Json,
        ClientHelloSpecJsonOptions? options = null)
    {
        options ??= new ClientHelloSpecJsonOptions();
        ValidateOptions(options);
        if (utf8Json.IsEmpty || utf8Json.Length > options.MaximumDocumentSize)
        {
            throw new InvalidDataException(
                "ClientHello specification JSON is empty or exceeds its configured size limit.");
        }

        var input = utf8Json.ToArray();
        SpecificationDocument document;
        try
        {
            using var parsed = JsonDocument.Parse(input, DocumentOptions);
            if (parsed.RootElement.ValueKind != JsonValueKind.Object)
            {
                throw new InvalidDataException("ClientHello specification JSON root must be an object.");
            }
            EnsureNoDuplicateProperties(parsed.RootElement);
            document = JsonSerializer.Deserialize<SpecificationDocument>(input, SerializerOptions) ??
                throw new InvalidDataException("ClientHello specification JSON is null.");
        }
        catch (JsonException exception)
        {
            throw new InvalidDataException("ClientHello specification JSON is malformed.", exception);
        }
        catch (InvalidOperationException exception) when (
            exception.InnerException is DecoderFallbackException)
        {
            throw new InvalidDataException(
                "ClientHello specification JSON contains invalid UTF-8.",
                exception);
        }

        try
        {
            return CreateSpec(document);
        }
        catch (Exception exception) when (
            exception is ArgumentException or NotSupportedException or InvalidOperationException or IOException)
        {
            throw new InvalidDataException(
                "ClientHello specification JSON contains an invalid or unsupported value.",
                exception);
        }
    }

    /// <summary>Parses a strict, bounded versioned specification JSON string.</summary>
    public static ClientHelloSpec Deserialize(
        string json,
        ClientHelloSpecJsonOptions? options = null)
    {
        ArgumentNullException.ThrowIfNull(json);
        options ??= new ClientHelloSpecJsonOptions();
        ValidateOptions(options);
        if (Encoding.UTF8.GetByteCount(json) > options.MaximumDocumentSize)
        {
            throw new InvalidDataException(
                "ClientHello specification JSON exceeds its configured size limit.");
        }

        return Deserialize(Encoding.UTF8.GetBytes(json), options);
    }

    private static SpecificationDocument CreateDocument(ClientHelloSpec spec) => new()
    {
        Format = FormatName,
        Version = CurrentVersion,
        CipherSuites = spec.CipherSuites.Select(value => value.ToString()).ToArray(),
        SupportedVersions = spec.SupportedVersions.Select(value => value.ToString()).ToArray(),
        SupportedGroups = spec.SupportedGroups.Select(value => value.ToString()).ToArray(),
        KeyShareGroups = spec.KeyShareGroups.Select(value => value.ToString()).ToArray(),
        SignatureAlgorithms = spec.SignatureAlgorithms.Select(value => value.ToString()).ToArray(),
        CertificateSignatureAlgorithms = spec.CertificateSignatureAlgorithms?
            .Select(value => value.ToString())
            .ToArray(),
        RecordSizeLimit = spec.RecordSizeLimit,
        DelegatedCredentialSignatureAlgorithms = spec.DelegatedCredentialSignatureAlgorithms?
            .Select(value => value.ToString())
            .ToArray(),
        AllowUnsupportedDelegatedCredentialAlgorithmsForWireFidelity =
            spec.AllowsUnsupportedDelegatedCredentialAlgorithmsForWireFidelity,
        QuicTransportParameters = spec.QuicTransportParameters?.Encode(),
        AllowDuplicateSignatureAlgorithms = spec.AllowsDuplicateSignatureAlgorithms,
        AlpnProtocols = spec.AlpnProtocols.ToArray(),
        ApplicationSettingsCodePoint = spec.ApplicationSettingsCodePoint?.ToString(),
        ApplicationSettingsProtocols = spec.ApplicationSettingsProtocols.ToArray(),
        SessionId = spec.SessionId,
        PaddingLength = spec.PaddingLength,
        UseBoringPadding = spec.UseBoringPadding,
        ShuffleExtensions = spec.ShuffleExtensions,
        GreaseEncryptedClientHello = spec.GreaseEncryptedClientHello,
        GreaseEchCipherSuites = spec.GreaseEchCipherSuites.Select(suite =>
            new HpkeSuiteDocument
            {
                KdfId = suite.KdfId.ToString(),
                AeadId = suite.AeadId.ToString(),
            }).ToArray(),
        GreaseEchPayloadLengths = spec.GreaseEchPayloadLengths.ToArray(),
        GreaseValueClasses = spec.GreasePolicy?.ValueClasses.ToArray(),
        SecondaryGreaseExtensionValueClass = spec.GreasePolicy?.SecondaryExtensionValueClass,
        SecondaryGreaseExtensionBody = spec.SecondaryGreaseExtensionBody,
        FixedGreaseKeyShareBody = spec.FixedGreaseKeyShareBody,
        IncludeSni = spec.IncludeSni,
        Extensions = spec.Extensions.Select(extension => extension.BuiltInKind.HasValue
            ? new ExtensionDocument
            {
                Kind = "builtIn",
                BuiltIn = extension.BuiltInKind.Value.ToString(),
                Type = null,
                Data = null,
            }
            : new ExtensionDocument
            {
                Kind = "raw",
                BuiltIn = null,
                Type = extension.RawExtensionType,
                Data = extension.GetRawData(),
            }).ToArray(),
    };

    private static ClientHelloSpec CreateSpec(SpecificationDocument document)
    {
        if (!string.Equals(document.Format, FormatName, StringComparison.Ordinal) ||
            document.Version is not (1 or 2 or 3 or 4 or 5 or CurrentVersion))
        {
            throw new NotSupportedException(
                $"Unsupported ClientHello specification format or version {document.Version}.");
        }
        if (document.CipherSuites is null || document.SupportedGroups is null ||
            document.KeyShareGroups is null || document.SignatureAlgorithms is null ||
            document.AlpnProtocols is null || document.Extensions is null)
        {
            throw new ArgumentException("A required ClientHello specification array is null.");
        }

        var extensions = document.Extensions.Select(ParseExtension).ToList();
        if (document.GreaseEncryptedClientHello && !extensions.Any(extension =>
            extension.BuiltInKind == ClientHelloExtensionKind.EncryptedClientHello))
        {
            // Early v6 writers represented semantic GREASE-ECH policy but relied on the
            // encoder's implicit insertion before pre_shared_key. Normalize those documents
            // to the now-explicit exact slot without changing their historical wire order.
            var pskIndex = extensions.FindIndex(extension =>
                extension.BuiltInKind == ClientHelloExtensionKind.PreSharedKey);
            extensions.Insert(
                pskIndex < 0 ? extensions.Count : pskIndex,
                ClientHelloExtensionSpec.BuiltIn(
                    ClientHelloExtensionKind.EncryptedClientHello));
        }
        var parsedExtensions = extensions.ToArray();
        var builder = new ClientHelloBuilder()
            .WithCipherSuites(ParseEnums<TlsCipherSuite>(document.CipherSuites, "cipher suite"))
            .WithSupportedVersions(document.Version == 1 || document.SupportedVersions is null
                ? [TlsProtocolVersion.Tls13]
                : ParseEnums<TlsProtocolVersion>(document.SupportedVersions, "TLS version"))
            .WithSupportedGroups(ParseEnums<NamedGroup>(document.SupportedGroups, "supported group"))
            .WithKeyShares(ParseEnums<NamedGroup>(document.KeyShareGroups, "key-share group"))
            .WithSignatureAlgorithms(ParseEnums<SignatureScheme>(
                document.SignatureAlgorithms,
                "signature algorithm"))
            .AllowDuplicateSignatureAlgorithms(document.AllowDuplicateSignatureAlgorithms)
            .WithAlpn(document.AlpnProtocols)
            .WithApplicationSettings(
                document.ApplicationSettingsCodePoint is null
                    ? TlsApplicationSettingsCodePoint.LegacyDraft
                    : ParseEnum<TlsApplicationSettingsCodePoint>(
                        document.ApplicationSettingsCodePoint,
                        "application-settings code point"),
                document.ApplicationSettingsProtocols ?? [])
            .WithRecordSizeLimit(document.RecordSizeLimit)
            .WithDelegatedCredentials(document.DelegatedCredentialSignatureAlgorithms is null
                ? null
                : ParseEnums<SignatureScheme>(
                    document.DelegatedCredentialSignatureAlgorithms,
                    "delegated credential signature algorithm"))
            .WithQuicTransportParameters(document.QuicTransportParameters is null
                ? null
                : TlsQuicTransportParameters.Parse(document.QuicTransportParameters))
            .AllowUnsupportedDelegatedCredentialAlgorithmsForWireFidelity(
                document.AllowUnsupportedDelegatedCredentialAlgorithmsForWireFidelity)
            .WithSessionId(document.SessionId)
            .WithPadding(document.PaddingLength)
            .WithSni(document.IncludeSni)
            .WithExtensionLayout(parsedExtensions);
        if (document.CertificateSignatureAlgorithms is not null)
        {
            builder.WithCertificateSignatureAlgorithms(ParseEnums<SignatureScheme>(
                document.CertificateSignatureAlgorithms,
                "certificate signature algorithm"));
        }
        var hasSupportedVersionsExtension = parsedExtensions.Any(extension =>
            extension.BuiltInKind == ClientHelloExtensionKind.SupportedVersions);
        if (!hasSupportedVersionsExtension)
        {
            if (document.SupportedVersions is not null &&
                !ParseEnums<TlsProtocolVersion>(document.SupportedVersions, "TLS version")
                    .SequenceEqual([TlsProtocolVersion.Tls12]))
            {
                throw new ArgumentException(
                    "A legacy ClientHello without supported_versions must represent TLS 1.2.");
            }
            builder.WithLegacyTls12ClientHello();
        }
        if (document.UseBoringPadding)
        {
            builder.WithBoringPadding();
        }
        builder.WithExtensionShuffling(document.ShuffleExtensions);
        if (document.GreaseEncryptedClientHello)
        {
            var suites = document.GreaseEchCipherSuites is { Length: > 0 }
                ? document.GreaseEchCipherSuites.Select(ParseHpkeSuite).ToArray()
                : TlsEchGreaseOptions.DefaultCipherSuites.ToArray();
            builder.WithGreaseEncryptedClientHello(
                suites,
                document.GreaseEchPayloadLengths ?? []);
        }
        else if (document.GreaseEchPayloadLengths is { Length: > 0 } ||
            document.GreaseEchCipherSuites is { Length: > 0 })
        {
            throw new ArgumentException(
                "GREASE-ECH payload lengths require the semantic GREASE-ECH flag.");
        }
        if (document.GreaseValueClasses is { } classes)
        {
            if (classes.Length != 5)
            {
                throw new ArgumentException("GREASE value classes must contain exactly five entries.");
            }
            var policy = document.SecondaryGreaseExtensionValueClass is { } secondaryClass
                ? ClientHelloGreasePolicy.CreateWithSecondaryExtension(
                    classes[0], classes[1], classes[2], classes[3], classes[4], secondaryClass)
                : ClientHelloGreasePolicy.Create(
                    classes[0], classes[1], classes[2], classes[3], classes[4]);
            builder.WithGrease(policy);
            builder.WithGreaseKeyShareBody(document.FixedGreaseKeyShareBody);
            if (document.SecondaryGreaseExtensionBody is not null)
            {
                builder.WithSecondaryGreaseExtension(document.SecondaryGreaseExtensionBody);
            }
        }
        else if (document.SecondaryGreaseExtensionValueClass.HasValue ||
            document.SecondaryGreaseExtensionBody is not null ||
            document.FixedGreaseKeyShareBody is not null)
        {
            throw new ArgumentException("Secondary GREASE configuration requires a GREASE policy.");
        }
        return builder.BuildSpec();
    }

    private static ClientHelloExtensionSpec ParseExtension(ExtensionDocument extension)
    {
        ArgumentNullException.ThrowIfNull(extension);
        return extension.Kind switch
        {
            "builtIn" when extension.BuiltIn is not null &&
                extension.Type is null && extension.Data is null =>
                ClientHelloExtensionSpec.BuiltIn(ParseEnum<ClientHelloExtensionKind>(
                    extension.BuiltIn,
                    "built-in extension")),
            "raw" when extension.BuiltIn is null &&
                extension.Type.HasValue && extension.Data is not null =>
                ClientHelloExtensionSpec.Raw(extension.Type.Value, extension.Data),
            _ => throw new ArgumentException(
                "An extension must be exactly one well-formed builtIn or raw entry."),
        };
    }

    private static TEnum[] ParseEnums<TEnum>(IEnumerable<string> values, string description)
        where TEnum : struct, Enum => values.Select(value => ParseEnum<TEnum>(value, description)).ToArray();

    private static TEnum ParseEnum<TEnum>(string value, string description)
        where TEnum : struct, Enum
    {
        if (value is null || !Enum.TryParse(value, ignoreCase: false, out TEnum parsed) ||
            !Enum.IsDefined(parsed))
        {
            throw new NotSupportedException($"Unknown {description} '{value}'.");
        }

        return parsed;
    }

    private static void EnsureNoDuplicateProperties(JsonElement element)
    {
        if (element.ValueKind == JsonValueKind.Object)
        {
            var names = new HashSet<string>(StringComparer.Ordinal);
            foreach (var property in element.EnumerateObject())
            {
                if (!names.Add(property.Name))
                {
                    throw new InvalidDataException(
                        $"Duplicate JSON property '{property.Name}' is not allowed.");
                }
                EnsureNoDuplicateProperties(property.Value);
            }
        }
        else if (element.ValueKind == JsonValueKind.Array)
        {
            foreach (var item in element.EnumerateArray())
            {
                EnsureNoDuplicateProperties(item);
            }
        }
    }

    private static void ValidateOptions(ClientHelloSpecJsonOptions options)
    {
        if (options.MaximumDocumentSize is < 256 or > 4 * 1024 * 1024)
        {
            throw new ArgumentOutOfRangeException(nameof(options.MaximumDocumentSize));
        }
    }

    private sealed class SpecificationDocument
    {
        public required string Format { get; init; }

        public required int Version { get; init; }

        public required string[] CipherSuites { get; init; }

        public string[]? SupportedVersions { get; init; }

        public required string[] SupportedGroups { get; init; }

        public required string[] KeyShareGroups { get; init; }

        public required string[] SignatureAlgorithms { get; init; }

        public string[]? CertificateSignatureAlgorithms { get; init; }

        public int? RecordSizeLimit { get; init; }

        public string[]? DelegatedCredentialSignatureAlgorithms { get; init; }

        public bool AllowUnsupportedDelegatedCredentialAlgorithmsForWireFidelity { get; init; }

        public byte[]? QuicTransportParameters { get; init; }

        public bool AllowDuplicateSignatureAlgorithms { get; init; }

        public required string[] AlpnProtocols { get; init; }

        public string? ApplicationSettingsCodePoint { get; init; }

        public string[]? ApplicationSettingsProtocols { get; init; }

        public required byte[]? SessionId { get; init; }

        public required int? PaddingLength { get; init; }

        public bool UseBoringPadding { get; init; }

        public bool ShuffleExtensions { get; init; }

        public bool GreaseEncryptedClientHello { get; init; }

        public HpkeSuiteDocument[]? GreaseEchCipherSuites { get; init; }

        public int[]? GreaseEchPayloadLengths { get; init; }

        public required int[]? GreaseValueClasses { get; init; }

        public int? SecondaryGreaseExtensionValueClass { get; init; }

        public byte[]? SecondaryGreaseExtensionBody { get; init; }

        public byte[]? FixedGreaseKeyShareBody { get; init; }

        public required bool IncludeSni { get; init; }

        public required ExtensionDocument[] Extensions { get; init; }
    }

    private sealed class ExtensionDocument
    {
        public required string Kind { get; init; }

        public required string? BuiltIn { get; init; }

        public required ushort? Type { get; init; }

        public required byte[]? Data { get; init; }
    }

    private sealed class HpkeSuiteDocument
    {
        public required string KdfId { get; init; }

        public required string AeadId { get; init; }
    }

    private static TlsHpkeSymmetricCipherSuite ParseHpkeSuite(HpkeSuiteDocument document)
    {
        ArgumentNullException.ThrowIfNull(document);
        return new TlsHpkeSymmetricCipherSuite(
            ParseEnum<TlsHpkeKdfId>(document.KdfId, "GREASE-ECH KDF"),
            ParseEnum<TlsHpkeAeadId>(document.AeadId, "GREASE-ECH AEAD"));
    }
}
