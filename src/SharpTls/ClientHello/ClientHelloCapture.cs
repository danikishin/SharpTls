using System.Text;
using SharpTls.Cryptography;
using SharpTls.IO;
using SharpTls.Protocol;
using SharpTls.Quic;

namespace SharpTls;

/// <summary>Identifies the framing accepted by the captured ClientHello importer.</summary>
public enum ClientHelloCaptureFormat
{
    /// <summary>Detect a bare Handshake message or one or more TLSPlaintext records.</summary>
    Auto,
    /// <summary>The input starts with the four-byte Handshake header.</summary>
    Handshake,
    /// <summary>The input consists only of TLSPlaintext Handshake records.</summary>
    TlsRecords,
}

/// <summary>Controls security-sensitive captured ClientHello normalization.</summary>
public sealed class ClientHelloImportOptions
{
    /// <summary>
    /// Gets or sets whether the captured legacy session ID is copied. The default
    /// regenerates it per connection together with random and key shares.
    /// </summary>
    public bool PreserveSessionId { get; set; }

    /// <summary>Gets or sets the maximum accepted record-framed or bare input size.</summary>
    public int MaximumInputSize { get; set; } = 256 * 1024;
}

/// <summary>Result of normalizing captured wire bytes into a reusable safe specification.</summary>
public sealed class ClientHelloCaptureResult
{
    internal ClientHelloCaptureResult(
        ClientHelloSpec spec,
        string? capturedServerName,
        bool wasRecordFramed,
        IReadOnlyList<int> recordFragmentSizes,
        IReadOnlyList<ushort> recordVersions)
    {
        Spec = spec;
        CapturedServerName = capturedServerName;
        WasRecordFramed = wasRecordFramed;
        RecordFragmentSizes = Array.AsReadOnly(recordFragmentSizes.ToArray());
        RecordVersions = Array.AsReadOnly(recordVersions.ToArray());
    }

    /// <summary>Gets the executable immutable specification.</summary>
    public ClientHelloSpec Spec { get; }

    /// <summary>Gets the normalized captured SNI name, or null when SNI was absent.</summary>
    public string? CapturedServerName { get; }

    /// <summary>Gets whether the source used TLS record framing.</summary>
    public bool WasRecordFramed { get; }

    /// <summary>Gets captured TLSPlaintext fragment lengths in exact record order.</summary>
    public IReadOnlyList<int> RecordFragmentSizes { get; }

    /// <summary>Gets captured TLSPlaintext legacy_record_version values in exact record order.</summary>
    public IReadOnlyList<ushort> RecordVersions { get; }

    /// <summary>
    /// Creates a policy that reproduces the captured record boundaries for an equal-length
    /// rebuilt ClientHello, or returns null when the source was a bare Handshake message.
    /// </summary>
    public TlsRecordFragmentation? CreateRecordFragmentation() =>
        RecordFragmentSizes.Count == 0
            ? null
            : new TlsRecordFragmentation(
                RecordFragmentSizes.Max(),
                RecordFragmentSizes);
}

/// <summary>Imports supported captured TLS 1.3 ClientHello wire images.</summary>
public static class ClientHelloCapture
{
    /// <summary>
    /// Parses and normalizes a captured ClientHello. Ephemeral random and key-share
    /// bytes are validated structurally but never copied into the resulting spec.
    /// </summary>
    public static ClientHelloCaptureResult Import(
        ReadOnlySpan<byte> input,
        ClientHelloCaptureFormat format = ClientHelloCaptureFormat.Auto,
        ClientHelloImportOptions? options = null)
    {
        options ??= new ClientHelloImportOptions();
        ValidateOptions(options);
        if (input.IsEmpty || input.Length > options.MaximumInputSize)
        {
            throw TlsProtocolException.Decode("Captured ClientHello input is empty or exceeds its limit.");
        }

        var recordFramed = format switch
        {
            ClientHelloCaptureFormat.Auto => input[0] == (byte)TlsContentType.Handshake,
            ClientHelloCaptureFormat.Handshake => false,
            ClientHelloCaptureFormat.TlsRecords => true,
            _ => throw new ArgumentOutOfRangeException(nameof(format)),
        };
        if (format == ClientHelloCaptureFormat.Auto &&
            input[0] is not ((byte)HandshakeType.ClientHello or (byte)TlsContentType.Handshake))
        {
            throw TlsProtocolException.Decode("Captured input is neither a ClientHello nor Handshake records.");
        }

        var extracted = recordFramed
            ? ExtractHandshakeFromRecords(input, options.MaximumInputSize)
            : new CapturedRecordSequence(input.ToArray(), [], []);
        var handshake = extracted.Handshake;
        var parsed = ParseHandshake(handshake, options);
        return new ClientHelloCaptureResult(
            parsed.Spec,
            parsed.ServerName,
            recordFramed,
            extracted.FragmentSizes,
            extracted.RecordVersions);
    }

    private static (ClientHelloSpec Spec, string? ServerName) ParseHandshake(
        ReadOnlySpan<byte> handshake,
        ClientHelloImportOptions options)
    {
        var message = new TlsBinaryReader(handshake);
        if (message.ReadUInt8() != (byte)HandshakeType.ClientHello)
        {
            throw TlsProtocolException.Unexpected("Captured Handshake message is not ClientHello.");
        }
        var bodyLength = message.ReadUInt24();
        var body = new TlsBinaryReader(message.ReadBytes(bodyLength));
        message.EnsureEnd("captured ClientHello Handshake");

        if (body.ReadUInt16() != TlsConstants.LegacyRecordVersion)
        {
            throw new TlsProtocolException(
                TlsAlertDescription.ProtocolVersion,
                "Captured ClientHello legacy_version is not 0x0303.");
        }
        _ = body.ReadBytes(TlsConstants.RandomLength);
        var sessionId = body.ReadVector8(TlsConstants.MaxSessionIdLength).ToArray();
        var grease = new GreaseImportTracker();
        var cipherSuites = ParseCipherSuites(body.ReadVector16(), grease);
        var compressionMethods = body.ReadVector8();
        if (!compressionMethods.SequenceEqual(new byte[] { 0 }))
        {
            throw new NotSupportedException(
                "Only the TLS 1.3 null legacy compression vector can be imported.");
        }

        var extensions = new TlsBinaryReader(body.ReadVector16());
        body.EnsureEnd("captured ClientHello");
        var seenTypes = new HashSet<ushort>();
        var layout = new List<ClientHelloExtensionSpec>();
        var groups = Array.Empty<NamedGroup>();
        var keyShareGroups = Array.Empty<NamedGroup>();
        var signatures = Array.Empty<SignatureScheme>();
        SignatureScheme[]? certificateSignatures = null;
        int? recordSizeLimit = null;
        SignatureScheme[]? delegatedCredentialSignatures = null;
        TlsQuicTransportParameters? quicTransportParameters = null;
        var supportedVersions = Array.Empty<TlsProtocolVersion>();
        var alpn = Array.Empty<string>();
        TlsApplicationSettingsCodePoint? applicationSettingsCodePoint = null;
        var applicationSettingsProtocols = Array.Empty<string>();
        TlsHpkeSymmetricCipherSuite? greaseEchCipherSuite = null;
        int? greaseEchPayloadLength = null;
        string? serverName = null;
        int? paddingLength = null;
        byte[]? secondaryGreaseBody = null;
        var includeSni = false;

        while (!extensions.End)
        {
            var type = extensions.ReadUInt16();
            var data = extensions.ReadVector16();
            if (!seenTypes.Add(type))
            {
                throw TlsProtocolException.Illegal(
                    $"Captured ClientHello contains duplicate extension 0x{type:X4}.");
            }

            if (IsGreaseValue(type))
            {
                if (!grease.HasPrimaryExtension)
                {
                    if (!data.IsEmpty)
                    {
                        throw new NotSupportedException(
                            "The primary semantic GREASE extension must have an empty body.");
                    }
                    grease.Observe(type, GreaseLocation.Extension);
                    layout.Add(ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.Grease));
                }
                else
                {
                    grease.Observe(type, GreaseLocation.SecondaryExtension);
                    secondaryGreaseBody = data.ToArray();
                    layout.Add(ClientHelloExtensionSpec.BuiltIn(
                        ClientHelloExtensionKind.SecondaryGrease));
                }
                continue;
            }

            if (type is (ushort)TlsApplicationSettingsCodePoint.LegacyDraft or
                (ushort)TlsApplicationSettingsCodePoint.ChromeExperiment)
            {
                applicationSettingsCodePoint = (TlsApplicationSettingsCodePoint)type;
                applicationSettingsProtocols = ParseAlpn(data);
                layout.Add(ClientHelloExtensionSpec.BuiltIn(
                    ClientHelloExtensionKind.ApplicationSettings));
                continue;
            }

            switch ((TlsExtensionType)type)
            {
                case TlsExtensionType.ServerName:
                    serverName = ParseServerName(data);
                    includeSni = true;
                    layout.Add(ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.ServerName));
                    break;
                case TlsExtensionType.SupportedVersions:
                    supportedVersions = ParseSupportedVersions(data, grease);
                    layout.Add(ClientHelloExtensionSpec.BuiltIn(
                        ClientHelloExtensionKind.SupportedVersions));
                    break;
                case TlsExtensionType.SupportedGroups:
                    groups = ParseSupportedGroups(data, grease);
                    layout.Add(ClientHelloExtensionSpec.BuiltIn(
                        ClientHelloExtensionKind.SupportedGroups));
                    break;
                case TlsExtensionType.SignatureAlgorithms:
                    signatures = ParseSignatureAlgorithms(data);
                    layout.Add(ClientHelloExtensionSpec.BuiltIn(
                        ClientHelloExtensionKind.SignatureAlgorithms));
                    break;
                case TlsExtensionType.SignatureAlgorithmsCert:
                    certificateSignatures = ParseSignatureAlgorithms(data);
                    layout.Add(ClientHelloExtensionSpec.BuiltIn(
                        ClientHelloExtensionKind.SignatureAlgorithmsCert));
                    break;
                case TlsExtensionType.KeyShare:
                    keyShareGroups = ParseKeyShares(data, grease);
                    layout.Add(ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.KeyShare));
                    break;
                case TlsExtensionType.ApplicationLayerProtocolNegotiation:
                    alpn = ParseAlpn(data);
                    layout.Add(ClientHelloExtensionSpec.BuiltIn(
                        ClientHelloExtensionKind.ApplicationLayerProtocolNegotiation));
                    break;
                case TlsExtensionType.Padding:
                    if (data.IndexOfAnyExcept((byte)0) >= 0)
                    {
                        throw TlsProtocolException.Illegal(
                            "Captured padding extension contains a non-zero byte.");
                    }
                    paddingLength = data.Length;
                    layout.Add(ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.Padding));
                    break;
                case TlsExtensionType.PostHandshakeAuthentication:
                    if (!data.IsEmpty)
                    {
                        throw TlsProtocolException.Illegal(
                            "Captured post_handshake_auth extension is not empty.");
                    }
                    layout.Add(ClientHelloExtensionSpec.BuiltIn(
                        ClientHelloExtensionKind.PostHandshakeAuthentication));
                    break;
                case TlsExtensionType.RecordSizeLimit:
                    var recordSizeReader = new TlsBinaryReader(data);
                    recordSizeLimit = recordSizeReader.ReadUInt16();
                    recordSizeReader.EnsureEnd("record_size_limit");
                    if (recordSizeLimit is < 64 or > TlsConstants.MaxPlaintextLength + 1)
                    {
                        throw TlsProtocolException.Illegal(
                            "Captured record_size_limit is outside the TLS 1.3 range.");
                    }
                    layout.Add(ClientHelloExtensionSpec.BuiltIn(
                        ClientHelloExtensionKind.RecordSizeLimit));
                    break;
                case TlsExtensionType.DelegatedCredential:
                    delegatedCredentialSignatures = ParseSignatureAlgorithms(data);
                    layout.Add(ClientHelloExtensionSpec.BuiltIn(
                        ClientHelloExtensionKind.DelegatedCredential));
                    break;
                case TlsExtensionType.QuicTransportParameters:
                    quicTransportParameters = TlsQuicTransportParameters.Parse(data);
                    quicTransportParameters.ValidatePeer(TlsQuicEndpointRole.Client);
                    layout.Add(ClientHelloExtensionSpec.BuiltIn(
                        ClientHelloExtensionKind.QuicTransportParameters));
                    break;
                case TlsExtensionType.EncryptedClientHello:
                    (greaseEchCipherSuite, greaseEchPayloadLength) = ParseGreaseEch(data);
                    layout.Add(ClientHelloExtensionSpec.BuiltIn(
                        ClientHelloExtensionKind.EncryptedClientHello));
                    break;
                case TlsExtensionType.Cookie:
                    throw new NotSupportedException(
                        "Importing a second ClientHello with an HRR cookie is not supported.");
                default:
                    layout.Add(ClientHelloExtensionSpec.Raw(type, data.ToArray()));
                    break;
            }
        }

        grease.ValidateExecutableShape();
        var hasSupportedVersions = layout.Any(extension =>
            extension.BuiltInKind == ClientHelloExtensionKind.SupportedVersions);
        var hasKeyShare = layout.Any(extension =>
            extension.BuiltInKind == ClientHelloExtensionKind.KeyShare);
        if (!hasSupportedVersions)
        {
            supportedVersions = [TlsProtocolVersion.Tls12];
        }
        if (groups.Length == 0 || signatures.Length == 0 ||
            (hasSupportedVersions && supportedVersions.Contains(TlsProtocolVersion.Tls13) && !hasKeyShare))
        {
            throw new NotSupportedException(
                "Captured ClientHello lacks required semantic extensions.");
        }

        try
        {
            var builder = new ClientHelloBuilder()
                .WithCipherSuites(cipherSuites)
                .WithSupportedVersions(supportedVersions)
                .WithSupportedGroups(groups)
                .WithKeyShares(keyShareGroups)
                .WithSignatureAlgorithms(signatures)
                .AllowDuplicateSignatureAlgorithms(signatures.Distinct().Count() != signatures.Length)
                .WithSni(includeSni)
                .WithAlpn(alpn)
                .WithApplicationSettings(
                    applicationSettingsCodePoint ?? TlsApplicationSettingsCodePoint.LegacyDraft,
                    applicationSettingsProtocols)
                .WithRecordSizeLimit(recordSizeLimit)
                .WithDelegatedCredentials(delegatedCredentialSignatures)
                .WithQuicTransportParameters(quicTransportParameters)
                .AllowUnsupportedDelegatedCredentialAlgorithmsForWireFidelity(
                    delegatedCredentialSignatures?.Any(scheme => scheme is not (
                        SignatureScheme.EcdsaSecp256r1Sha256 or
                        SignatureScheme.EcdsaSecp384r1Sha384 or
                        SignatureScheme.EcdsaSecp521r1Sha512 or
                        SignatureScheme.RsaPssPssSha256 or
                        SignatureScheme.RsaPssPssSha384 or
                        SignatureScheme.RsaPssPssSha512)) == true)
                .WithPadding(paddingLength)
                .WithSessionId(options.PreserveSessionId ? sessionId : null)
                .WithExtensionLayout(layout.ToArray());
            if (certificateSignatures is not null)
            {
                builder.WithCertificateSignatureAlgorithms(certificateSignatures);
            }
            if (!hasSupportedVersions)
            {
                builder.WithLegacyTls12ClientHello();
            }
            if (grease.Policy is { } greasePolicy)
            {
                builder.WithGrease(greasePolicy);
                builder.WithGreaseKeyShareBody(grease.FixedKeyShareBody);
                if (secondaryGreaseBody is not null)
                {
                    builder.WithSecondaryGreaseExtension(secondaryGreaseBody);
                }
            }
            if (greaseEchCipherSuite.HasValue)
            {
                builder.WithGreaseEncryptedClientHello(
                    [greaseEchCipherSuite.Value],
                    greaseEchPayloadLength!.Value);
            }
            return (builder.BuildSpec(), serverName);
        }
        catch (NotSupportedException)
        {
            throw;
        }
        catch (Exception exception) when (exception is ArgumentException or InvalidOperationException)
        {
            throw new TlsProtocolException(
                TlsAlertDescription.IllegalParameter,
                "Captured ClientHello fields do not form an executable coherent specification.",
                exception);
        }
    }

    private static (TlsHpkeSymmetricCipherSuite Suite, int PayloadLength) ParseGreaseEch(
        ReadOnlySpan<byte> data)
    {
        var reader = new TlsBinaryReader(data);
        if (reader.ReadUInt8() != 0)
        {
            throw TlsProtocolException.Illegal(
                "Captured encrypted_client_hello is not an outer ClientHello value.");
        }
        var kdfId = (TlsHpkeKdfId)reader.ReadUInt16();
        var aeadId = (TlsHpkeAeadId)reader.ReadUInt16();
        _ = reader.ReadUInt8(); // GREASE config_id is intentionally unconstrained.
        var encapsulatedKey = reader.ReadVector16();
        var payload = reader.ReadVector16();
        reader.EnsureEnd("captured encrypted_client_hello");
        if (encapsulatedKey.Length != X25519.KeyLength || payload.Length <= 16)
        {
            throw TlsProtocolException.Illegal(
                "Captured GREASE ECH has an invalid X25519 encapsulated key or payload length.");
        }
        if (kdfId is not (TlsHpkeKdfId.HkdfSha256 or
            TlsHpkeKdfId.HkdfSha384 or TlsHpkeKdfId.HkdfSha512) ||
            aeadId is not (TlsHpkeAeadId.Aes128Gcm or
                TlsHpkeAeadId.Aes256Gcm or TlsHpkeAeadId.ChaCha20Poly1305))
        {
            throw new NotSupportedException(
                "Captured GREASE ECH selects an unsupported HPKE suite.");
        }

        return (new TlsHpkeSymmetricCipherSuite(kdfId, aeadId), payload.Length - 16);
    }

    private static CapturedRecordSequence ExtractHandshakeFromRecords(
        ReadOnlySpan<byte> input,
        int limit)
    {
        var writer = new TlsBinaryWriter(Math.Min(input.Length, limit));
        var records = new TlsBinaryReader(input);
        var fragmentSizes = new List<int>();
        var recordVersions = new List<ushort>();
        while (!records.End)
        {
            if (records.ReadUInt8() != (byte)TlsContentType.Handshake)
            {
                throw TlsProtocolException.Unexpected(
                    "Captured ClientHello record sequence contains a non-Handshake record.");
            }
            var legacyRecordVersion = records.ReadUInt16();
            if (legacyRecordVersion is not (0x0301 or TlsConstants.LegacyRecordVersion))
            {
                throw new TlsProtocolException(
                    TlsAlertDescription.ProtocolVersion,
                    "Captured ClientHello record has an invalid legacy_record_version.");
            }
            var length = records.ReadUInt16();
            if (length == 0 || length > TlsConstants.MaxPlaintextLength)
            {
                throw new TlsProtocolException(
                    TlsAlertDescription.RecordOverflow,
                    "Captured ClientHello record has an invalid fragment length.");
            }
            writer.WriteBytes(records.ReadBytes(length));
            fragmentSizes.Add(length);
            recordVersions.Add(legacyRecordVersion);
            if (writer.Length > limit)
            {
                throw TlsProtocolException.Decode("Reassembled captured ClientHello exceeds its limit.");
            }
        }

        return new CapturedRecordSequence(
            writer.ToArray(),
            fragmentSizes.ToArray(),
            recordVersions.ToArray());
    }

    private sealed record CapturedRecordSequence(
        byte[] Handshake,
        int[] FragmentSizes,
        ushort[] RecordVersions);

    private static TlsCipherSuite[] ParseCipherSuites(
        ReadOnlySpan<byte> encoded,
        GreaseImportTracker grease)
    {
        if (encoded.Length < 2 || (encoded.Length & 1) != 0)
        {
            throw TlsProtocolException.Decode("Captured cipher_suites vector has an invalid length.");
        }

        var reader = new TlsBinaryReader(encoded);
        var result = new List<TlsCipherSuite>();
        while (!reader.End)
        {
            var code = reader.ReadUInt16();
            if (IsGreaseValue(code))
            {
                grease.Observe(code, GreaseLocation.CipherSuite);
                continue;
            }
            if (!Enum.IsDefined(typeof(TlsCipherSuite), code))
            {
                throw new NotSupportedException(
                    $"Captured cipher suite 0x{code:X4} is not executable yet.");
            }
            result.Add((TlsCipherSuite)code);
        }

        return result.ToArray();
    }

    private static string ParseServerName(ReadOnlySpan<byte> data)
    {
        var reader = new TlsBinaryReader(data);
        var names = new TlsBinaryReader(reader.ReadVector16());
        reader.EnsureEnd("captured server_name");
        if (names.ReadUInt8() != 0)
        {
            throw TlsProtocolException.Illegal("Captured SNI uses an unsupported name type.");
        }
        var name = names.ReadVector16();
        if (name.IsEmpty || name.IndexOfAnyInRange((byte)0x80, byte.MaxValue) >= 0)
        {
            throw TlsProtocolException.Illegal("Captured SNI is empty or non-ASCII.");
        }
        names.EnsureEnd("captured SNI list");
        return Encoding.ASCII.GetString(name);
    }

    private static TlsProtocolVersion[] ParseSupportedVersions(
        ReadOnlySpan<byte> data,
        GreaseImportTracker grease)
    {
        var reader = new TlsBinaryReader(data);
        var versions = new TlsBinaryReader(reader.ReadVector8());
        reader.EnsureEnd("captured supported_versions");
        var hasTls13 = false;
        var result = new List<TlsProtocolVersion>();
        while (!versions.End)
        {
            var version = versions.ReadUInt16();
            if (IsGreaseValue(version))
            {
                grease.Observe(version, GreaseLocation.SupportedVersion);
            }
            else if (Enum.IsDefined(typeof(TlsProtocolVersion), version))
            {
                var parsed = (TlsProtocolVersion)version;
                hasTls13 |= parsed == TlsProtocolVersion.Tls13;
                result.Add(parsed);
            }
            else
            {
                throw new NotSupportedException(
                    $"Captured additional TLS version 0x{version:X4} is not executable yet.");
            }
        }
        if (!hasTls13)
        {
            throw new NotSupportedException("Captured supported_versions does not offer TLS 1.3.");
        }
        return result.ToArray();
    }

    private static NamedGroup[] ParseSupportedGroups(
        ReadOnlySpan<byte> data,
        GreaseImportTracker grease)
    {
        var reader = new TlsBinaryReader(data);
        var groups = new TlsBinaryReader(reader.ReadVector16());
        reader.EnsureEnd("captured supported_groups");
        var result = new List<NamedGroup>();
        while (!groups.End)
        {
            var code = groups.ReadUInt16();
            if (IsGreaseValue(code))
            {
                grease.Observe(code, GreaseLocation.SupportedGroup);
                continue;
            }
            result.Add(code switch
            {
                (ushort)NamedGroup.Secp256r1 => NamedGroup.Secp256r1,
                (ushort)NamedGroup.Secp384r1 => NamedGroup.Secp384r1,
                (ushort)NamedGroup.Secp521r1 => NamedGroup.Secp521r1,
                (ushort)NamedGroup.X25519 => NamedGroup.X25519,
                (ushort)NamedGroup.X25519MlKem768 => NamedGroup.X25519MlKem768,
                (ushort)NamedGroup.X25519Kyber768Draft00 =>
                    NamedGroup.X25519Kyber768Draft00,
                (ushort)NamedGroup.Ffdhe2048 => NamedGroup.Ffdhe2048,
                (ushort)NamedGroup.Ffdhe3072 => NamedGroup.Ffdhe3072,
                _ => throw new NotSupportedException(
                    $"Captured group 0x{code:X4} is not executable yet."),
            });
        }
        return result.ToArray();
    }

    private static SignatureScheme[] ParseSignatureAlgorithms(ReadOnlySpan<byte> data)
    {
        var reader = new TlsBinaryReader(data);
        var algorithms = new TlsBinaryReader(reader.ReadVector16());
        reader.EnsureEnd("captured signature_algorithms");
        var result = new List<SignatureScheme>();
        while (!algorithms.End)
        {
            var code = algorithms.ReadUInt16();
            if (!Enum.IsDefined(typeof(SignatureScheme), code))
            {
                throw new NotSupportedException(
                    $"Captured signature scheme 0x{code:X4} is not executable yet.");
            }
            result.Add((SignatureScheme)code);
        }
        return result.ToArray();
    }

    private static NamedGroup[] ParseKeyShares(
        ReadOnlySpan<byte> data,
        GreaseImportTracker grease)
    {
        var reader = new TlsBinaryReader(data);
        var entries = new TlsBinaryReader(reader.ReadVector16());
        reader.EnsureEnd("captured key_share");
        var result = new List<NamedGroup>();
        while (!entries.End)
        {
            var code = entries.ReadUInt16();
            var keyExchange = entries.ReadVector16();
            if (IsGreaseValue(code))
            {
                if (keyExchange.IsEmpty)
                {
                    throw TlsProtocolException.Illegal("Captured GREASE key share is empty.");
                }
                grease.ObserveKeyShare(code, keyExchange);
                continue;
            }

            var group = code switch
            {
                (ushort)NamedGroup.Secp256r1 => NamedGroup.Secp256r1,
                (ushort)NamedGroup.Secp384r1 => NamedGroup.Secp384r1,
                (ushort)NamedGroup.Secp521r1 => NamedGroup.Secp521r1,
                (ushort)NamedGroup.X25519 => NamedGroup.X25519,
                (ushort)NamedGroup.X25519MlKem768 => NamedGroup.X25519MlKem768,
                (ushort)NamedGroup.X25519Kyber768Draft00 =>
                    NamedGroup.X25519Kyber768Draft00,
                _ => throw new NotSupportedException(
                    $"Captured key-share group 0x{code:X4} is not executable yet."),
            };
            var expectedLength = group switch
            {
                NamedGroup.Secp256r1 => 65,
                NamedGroup.Secp384r1 => 97,
                NamedGroup.Secp521r1 => 133,
                NamedGroup.X25519 => 32,
                NamedGroup.X25519MlKem768 => X25519MlKem768KeyShare.ClientShareSize,
                NamedGroup.X25519Kyber768Draft00 =>
                    X25519Kyber768Draft00KeyShare.ClientShareSize,
                _ => throw new InvalidOperationException("Unsupported imported group invariant."),
            };
            if (keyExchange.Length != expectedLength ||
                ((group is NamedGroup.Secp256r1 or NamedGroup.Secp384r1 or
                    NamedGroup.Secp521r1) && keyExchange[0] != 4))
            {
                throw TlsProtocolException.Illegal(
                    $"Captured {group} key share has invalid framing.");
            }
            result.Add(group);
        }
        return result.ToArray();
    }

    private static string[] ParseAlpn(ReadOnlySpan<byte> data)
    {
        var reader = new TlsBinaryReader(data);
        var names = new TlsBinaryReader(reader.ReadVector16());
        reader.EnsureEnd("captured ALPN");
        var result = new List<string>();
        while (!names.End)
        {
            var name = names.ReadVector8(TlsConstants.MaxAlpnProtocolLength);
            if (name.IsEmpty || name.IndexOfAnyInRange((byte)0x80, byte.MaxValue) >= 0)
            {
                throw TlsProtocolException.Illegal("Captured ALPN contains an empty or non-ASCII name.");
            }
            result.Add(Encoding.ASCII.GetString(name));
        }
        return result.ToArray();
    }

    private static void ValidateOptions(ClientHelloImportOptions options)
    {
        if (options.MaximumInputSize is < 1024 or > 4 * 1024 * 1024)
        {
            throw new ArgumentOutOfRangeException(nameof(options.MaximumInputSize));
        }
    }

    private static bool IsGreaseValue(ushort value) =>
        (value & 0x0F0F) == 0x0A0A && (byte)(value >> 8) == (byte)value;

    [Flags]
    private enum GreaseLocation
    {
        CipherSuite = 1,
        SupportedVersion = 2,
        SupportedGroup = 4,
        KeyShare = 8,
        Extension = 16,
        SecondaryExtension = 32,
    }

    private sealed class GreaseImportTracker
    {
        private const GreaseLocation ExecutableShape =
            GreaseLocation.CipherSuite |
            GreaseLocation.SupportedVersion |
            GreaseLocation.SupportedGroup |
            GreaseLocation.KeyShare |
            GreaseLocation.Extension;

        private readonly Dictionary<GreaseLocation, ushort> _values = [];
        private GreaseLocation _locations;

        internal ClientHelloGreasePolicy? Policy { get; private set; }

        internal bool HasPrimaryExtension => (_locations & GreaseLocation.Extension) != 0;

        internal byte[]? FixedKeyShareBody { get; private set; }

        internal void ObserveKeyShare(ushort value, ReadOnlySpan<byte> body)
        {
            Observe(value, GreaseLocation.KeyShare);
            FixedKeyShareBody = body.ToArray();
        }

        internal void Observe(ushort value, GreaseLocation location)
        {
            if ((_locations & location) != 0)
            {
                throw TlsProtocolException.Illegal(
                    $"Captured ClientHello contains multiple GREASE entries at {location}.");
            }
            _values.Add(location, value);
            _locations |= location;
        }

        internal void ValidateExecutableShape()
        {
            if (_locations == 0)
            {
                return;
            }
            var hasSecondary = (_locations & GreaseLocation.SecondaryExtension) != 0;
            var expectedShape = hasSecondary
                ? ExecutableShape | GreaseLocation.SecondaryExtension
                : ExecutableShape;
            if (_locations != expectedShape)
            {
                throw new NotSupportedException(
                    "Captured GREASE placement cannot yet be reproduced by the semantic GREASE policy.");
            }

            var order = new List<GreaseLocation>
            {
                GreaseLocation.CipherSuite,
                GreaseLocation.SupportedVersion,
                GreaseLocation.SupportedGroup,
                GreaseLocation.KeyShare,
                GreaseLocation.Extension,
            };
            if (hasSecondary)
            {
                order.Add(GreaseLocation.SecondaryExtension);
            }
            var normalized = new int[order.Count];
            var classes = new Dictionary<ushort, int>();
            for (var index = 0; index < order.Count; index++)
            {
                var value = _values[order[index]];
                if (!classes.TryGetValue(value, out var valueClass))
                {
                    valueClass = classes.Count;
                    classes.Add(value, valueClass);
                }
                normalized[index] = valueClass;
            }
            Policy = hasSecondary
                ? ClientHelloGreasePolicy.CreateWithSecondaryExtension(
                    normalized[0], normalized[1], normalized[2],
                    normalized[3], normalized[4], normalized[5])
                : ClientHelloGreasePolicy.Create(
                    normalized[0], normalized[1], normalized[2], normalized[3], normalized[4]);
        }
    }
}
