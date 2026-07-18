using System.Buffers.Binary;
using System.Security.Cryptography;
using SharpTls.Cryptography;
using SharpTls.Protocol;

namespace SharpTls;

/// <summary>A weighted ALPN offer used by randomized ClientHello generation.</summary>
public sealed class ClientHelloAlpnVariant
{
    private readonly string[] _protocols;

    /// <summary>Creates a weighted ALPN variant. An empty protocol list means no ALPN extension.</summary>
    public ClientHelloAlpnVariant(int weight, params string[] protocols)
    {
        if (weight < 1)
        {
            throw new ArgumentOutOfRangeException(nameof(weight));
        }
        ArgumentNullException.ThrowIfNull(protocols);

        Weight = weight;
        _protocols = (string[])protocols.Clone();
    }

    /// <summary>Gets this variant's positive selection weight.</summary>
    public int Weight { get; }

    /// <summary>Gets a copy of the ALPN names in wire order.</summary>
    public IReadOnlyList<string> Protocols => Array.AsReadOnly((string[])_protocols.Clone());

    internal ClientHelloAlpnVariant Snapshot() => new(Weight, _protocols);

    internal string[] SnapshotProtocols() => (string[])_protocols.Clone();
}

/// <summary>Controls generation of executable, internally coherent randomized profiles.</summary>
public sealed class ClientHelloRandomizationOptions
{
    /// <summary>Gets or sets candidate cipher suites. Their order is shuffled per profile.</summary>
    public IReadOnlyList<TlsCipherSuite> CipherSuites { get; set; } =
    [
        TlsCipherSuite.TlsAes128GcmSha256,
        TlsCipherSuite.TlsAes256GcmSha384,
        TlsCipherSuite.TlsChaCha20Poly1305Sha256,
    ];

    /// <summary>Gets or sets candidate supported groups. Their order is shuffled per profile.</summary>
    public IReadOnlyList<NamedGroup> SupportedGroups { get; set; } =
        [NamedGroup.X25519, NamedGroup.Secp256r1, NamedGroup.Secp384r1, NamedGroup.Secp521r1];

    /// <summary>Gets or sets candidate CertificateVerify schemes.</summary>
    public IReadOnlyList<SignatureScheme> SignatureAlgorithms { get; set; } =
    [
        SignatureScheme.EcdsaSecp256r1Sha256,
        SignatureScheme.EcdsaSecp384r1Sha384,
        SignatureScheme.EcdsaSecp521r1Sha512,
        SignatureScheme.RsaPssRsaeSha256,
        SignatureScheme.RsaPssRsaeSha384,
        SignatureScheme.RsaPssRsaeSha512,
        SignatureScheme.RsaPssPssSha256,
        SignatureScheme.RsaPssPssSha384,
        SignatureScheme.RsaPssPssSha512,
    ];

    /// <summary>Gets or sets weighted ALPN variants, including an optional empty variant.</summary>
    public IReadOnlyList<ClientHelloAlpnVariant> AlpnVariants { get; set; } =
    [
        new ClientHelloAlpnVariant(5, "h2", "http/1.1"),
        new ClientHelloAlpnVariant(3, "http/1.1"),
        new ClientHelloAlpnVariant(2),
    ];

    /// <summary>Gets or sets the chance, from 0 through 100, of semantic GREASE.</summary>
    public int GreaseProbabilityPercent { get; set; } = 75;

    /// <summary>Gets or sets the GREASE value-sharing pattern used when selected.</summary>
    public ClientHelloGreasePolicy GreasePolicy { get; set; } = ClientHelloGreasePolicy.PerSlot;

    /// <summary>Gets or sets the chance, from 0 through 100, of a padding extension.</summary>
    public int PaddingProbabilityPercent { get; set; } = 50;

    /// <summary>Gets or sets the minimum generated padding body length.</summary>
    public int MinimumPaddingLength { get; set; }

    /// <summary>Gets or sets the maximum generated padding body length.</summary>
    public int MaximumPaddingLength { get; set; } = 32;

    /// <summary>Gets or sets the minimum number of initial non-GREASE key shares.</summary>
    public int MinimumKeyShareCount { get; set; } = 1;

    /// <summary>Gets or sets the maximum number of initial non-GREASE key shares.</summary>
    public int MaximumKeyShareCount { get; set; } = 1;

    /// <summary>Gets or sets whether extension slots are shuffled.</summary>
    public bool ShuffleExtensions { get; set; } = true;

    /// <summary>
    /// Gets or sets whether generated profiles contain conditional psk_dhe_ke, early_data,
    /// and final pre_shared_key slots. With no ticket or external PSK, only psk_dhe_ke is sent.
    /// </summary>
    public bool EnableSessionResumption { get; set; } = true;

    /// <summary>
    /// Gets or sets the chance, from 0 through 100, of ALPS/application_settings when the
    /// selected ALPN variant contains h2.
    /// </summary>
    public int ApplicationSettingsProbabilityPercent { get; set; } = 33;

    /// <summary>Gets or sets the uTLS-compatible application_settings code point.</summary>
    public TlsApplicationSettingsCodePoint ApplicationSettingsCodePoint { get; set; } =
        TlsApplicationSettingsCodePoint.ChromeExperiment;

    /// <summary>Gets or sets the chance, from 0 through 100, of semantic GREASE ECH.</summary>
    public int GreaseEchProbabilityPercent { get; set; }

    /// <summary>Gets or sets ordered GREASE-ECH HPKE-suite candidates.</summary>
    public IReadOnlyList<TlsHpkeSymmetricCipherSuite> GreaseEchCipherSuites { get; set; } =
        TlsEchGreaseOptions.DefaultCipherSuites;

    /// <summary>Gets or sets candidate GREASE-ECH pre-encryption payload lengths.</summary>
    public IReadOnlyList<int> GreaseEchPayloadLengths { get; set; } = [128, 160, 192, 224];

    internal ClientHelloRandomizationConfiguration Snapshot()
    {
        ArgumentNullException.ThrowIfNull(CipherSuites);
        ArgumentNullException.ThrowIfNull(SupportedGroups);
        ArgumentNullException.ThrowIfNull(SignatureAlgorithms);
        ArgumentNullException.ThrowIfNull(AlpnVariants);
        ArgumentNullException.ThrowIfNull(GreasePolicy);
        ArgumentNullException.ThrowIfNull(GreaseEchCipherSuites);
        ArgumentNullException.ThrowIfNull(GreaseEchPayloadLengths);

        if (GreaseProbabilityPercent is < 0 or > 100)
        {
            throw new ArgumentOutOfRangeException(nameof(GreaseProbabilityPercent));
        }
        if (PaddingProbabilityPercent is < 0 or > 100)
        {
            throw new ArgumentOutOfRangeException(nameof(PaddingProbabilityPercent));
        }
        if (ApplicationSettingsProbabilityPercent is < 0 or > 100)
        {
            throw new ArgumentOutOfRangeException(nameof(ApplicationSettingsProbabilityPercent));
        }
        if (GreaseEchProbabilityPercent is < 0 or > 100)
        {
            throw new ArgumentOutOfRangeException(nameof(GreaseEchProbabilityPercent));
        }
        if (!Enum.IsDefined(ApplicationSettingsCodePoint))
        {
            throw new ArgumentOutOfRangeException(nameof(ApplicationSettingsCodePoint));
        }
        if (MinimumPaddingLength < 0 || MaximumPaddingLength < MinimumPaddingLength ||
            MaximumPaddingLength > ushort.MaxValue)
        {
            throw new ArgumentOutOfRangeException(nameof(MaximumPaddingLength));
        }
        if (MinimumKeyShareCount < 0 || MaximumKeyShareCount < MinimumKeyShareCount)
        {
            throw new ArgumentOutOfRangeException(nameof(MaximumKeyShareCount));
        }

        var suites = CipherSuites.ToArray();
        var groups = SupportedGroups.ToArray();
        var signatures = SignatureAlgorithms.ToArray();
        var alpn = AlpnVariants.Select(variant =>
        {
            ArgumentNullException.ThrowIfNull(variant);
            return variant.Snapshot();
        }).ToArray();
        var greaseEchSuites = GreaseEchCipherSuites.ToArray();
        var greaseEchPayloadLengths = GreaseEchPayloadLengths.ToArray();
        if (suites.Length == 0 || groups.Length == 0 || signatures.Length == 0 || alpn.Length == 0)
        {
            throw new ArgumentException("Randomization candidate collections cannot be empty.");
        }
        if (greaseEchSuites.Length is 0 or > byte.MaxValue ||
            greaseEchSuites.Distinct().Count() != greaseEchSuites.Length)
        {
            throw new ArgumentException(
                "GREASE-ECH requires between 1 and 255 distinct HPKE suites.",
                nameof(GreaseEchCipherSuites));
        }
        if (greaseEchPayloadLengths.Length is 0 or > byte.MaxValue ||
            greaseEchPayloadLengths.Distinct().Count() != greaseEchPayloadLengths.Length ||
            greaseEchPayloadLengths.Any(length => length is < 1 or > ushort.MaxValue - 16))
        {
            throw new ArgumentException(
                "GREASE-ECH requires 1 to 255 distinct bounded payload lengths.",
                nameof(GreaseEchPayloadLengths));
        }
        foreach (var suite in greaseEchSuites)
        {
            if (suite.KdfId is not (TlsHpkeKdfId.HkdfSha256 or
                TlsHpkeKdfId.HkdfSha384 or TlsHpkeKdfId.HkdfSha512) ||
                suite.AeadId is not (TlsHpkeAeadId.Aes128Gcm or
                    TlsHpkeAeadId.Aes256Gcm or TlsHpkeAeadId.ChaCha20Poly1305))
            {
                throw new NotSupportedException(
                    "Randomized GREASE-ECH contains an unsupported HPKE suite.");
            }
        }
        if (suites.Distinct().Count() != suites.Length ||
            groups.Distinct().Count() != groups.Length ||
            signatures.Distinct().Count() != signatures.Length)
        {
            throw new ArgumentException("Randomization candidates cannot contain duplicates.");
        }

        return new ClientHelloRandomizationConfiguration(
            suites,
            groups,
            signatures,
            alpn,
            GreasePolicy.Snapshot(),
            GreaseProbabilityPercent,
            PaddingProbabilityPercent,
            MinimumPaddingLength,
            MaximumPaddingLength,
            MinimumKeyShareCount,
            MaximumKeyShareCount,
            ShuffleExtensions,
            EnableSessionResumption,
            ApplicationSettingsProbabilityPercent,
            ApplicationSettingsCodePoint,
            GreaseEchProbabilityPercent,
            greaseEchSuites,
            greaseEchPayloadLengths);
    }
}

/// <summary>Creates secure or deterministic-test randomized ClientHello profiles.</summary>
public static class ClientHelloProfileRandomizer
{
    private static readonly Lazy<IReadOnlySet<NamedGroup>> AvailableGroups = new(
        ProbeAvailableGroups,
        LazyThreadSafetyMode.ExecutionAndPublication);

    /// <summary>Creates a profile using runtime cryptographic entropy.</summary>
    public static ClientHelloProfile CreateSecure(ClientHelloRandomizationOptions? options = null) =>
        Create(options, SecureRandomSource.Instance);

    internal static ClientHelloProfile CreateSecure(
        ClientHelloRandomizationConfiguration configuration) =>
        Create(configuration, SecureRandomSource.Instance);

    /// <summary>
    /// Creates repeatable profile policy for tests. A connection made from the resulting
    /// profile still uses secure handshake entropy unless its test-only wire builder is called.
    /// </summary>
    public static ClientHelloProfile CreateDeterministicForTesting(
        byte[] seed,
        ClientHelloRandomizationOptions? options = null)
    {
        ArgumentNullException.ThrowIfNull(seed);
        using var random = new DeterministicRandomSource(seed);
        return Create(options, random);
    }

    private static ClientHelloProfile Create(
        ClientHelloRandomizationOptions? options,
        IRandomSource random) =>
        Create((options ?? new ClientHelloRandomizationOptions()).Snapshot(), random);

    private static ClientHelloProfile Create(
        ClientHelloRandomizationConfiguration configuration,
        IRandomSource random)
    {
        var suites = configuration.CipherSuites.Where(IsCipherSuiteAvailable).ToArray();
        var groups = configuration.SupportedGroups.Where(IsGroupAvailable).ToArray();
        if (suites.Length == 0)
        {
            throw new PlatformNotSupportedException(
                "None of the configured TLS 1.3 AEAD suites is available on this runtime.");
        }
        if (groups.Length == 0)
        {
            throw new PlatformNotSupportedException(
                "None of the configured ECDHE groups is available on this runtime.");
        }
        if (configuration.MinimumKeyShareCount > groups.Length)
        {
            throw new ArgumentOutOfRangeException(
                nameof(ClientHelloRandomizationOptions.MinimumKeyShareCount),
                "The minimum key-share count exceeds the available group count.");
        }

        Shuffle(suites, random);
        Shuffle(groups, random);
        var signatures = (SignatureScheme[])configuration.SignatureAlgorithms.Clone();
        Shuffle(signatures, random);

        var maximumShares = Math.Min(configuration.MaximumKeyShareCount, groups.Length);
        var shareCount = NextInt(
            random,
            configuration.MinimumKeyShareCount,
            checked(maximumShares + 1));
        var keyShares = groups[..shareCount];
        var alpn = SelectWeightedAlpn(configuration.AlpnVariants, random);
        var grease = Chance(random, configuration.GreaseProbabilityPercent);
        var applicationSettings = alpn.Contains("h2", StringComparer.Ordinal) &&
            Chance(random, configuration.ApplicationSettingsProbabilityPercent);
        var greaseEch = Chance(random, configuration.GreaseEchProbabilityPercent);
        int? padding = Chance(random, configuration.PaddingProbabilityPercent)
            ? NextInt(
                random,
                configuration.MinimumPaddingLength,
                checked(configuration.MaximumPaddingLength + 1))
            : null;

        var extensions = new List<ClientHelloExtensionSpec>
        {
            ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.ServerName),
            ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.SupportedVersions),
            ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.SupportedGroups),
            ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.SignatureAlgorithms),
            ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.KeyShare),
        };
        if (alpn.Length != 0)
        {
            extensions.Add(ClientHelloExtensionSpec.BuiltIn(
                ClientHelloExtensionKind.ApplicationLayerProtocolNegotiation));
        }
        if (applicationSettings)
        {
            extensions.Add(ClientHelloExtensionSpec.BuiltIn(
                ClientHelloExtensionKind.ApplicationSettings));
        }
        if (grease)
        {
            extensions.Add(ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.Grease));
        }
        if (padding.HasValue)
        {
            extensions.Add(ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.Padding));
        }
        if (greaseEch)
        {
            extensions.Add(ClientHelloExtensionSpec.BuiltIn(
                ClientHelloExtensionKind.EncryptedClientHello));
        }
        if (configuration.EnableSessionResumption)
        {
            extensions.Add(ClientHelloExtensionSpec.BuiltIn(
                ClientHelloExtensionKind.PskKeyExchangeModes));
            extensions.Add(ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.EarlyData));
        }
        if (configuration.ShuffleExtensions)
        {
            Shuffle(extensions, random);
        }
        if (configuration.EnableSessionResumption)
        {
            // RFC 8446 section 4.2.11 requires pre_shared_key to be the final slot.
            extensions.Add(ClientHelloExtensionSpec.BuiltIn(
                ClientHelloExtensionKind.PreSharedKey));
        }

        return ClientHelloProfiles.Custom(builder =>
        {
            builder
                .WithCipherSuites(suites)
                .WithSupportedGroups(groups)
                .WithKeyShares(keyShares)
                .WithSignatureAlgorithms(signatures)
                .WithAlpn(alpn)
                .WithPadding(padding)
                .WithExtensionLayout(extensions.ToArray());
            if (applicationSettings)
            {
                builder.WithApplicationSettings(
                    configuration.ApplicationSettingsCodePoint,
                    "h2");
            }
            if (grease)
            {
                builder.WithGrease(configuration.GreasePolicy);
            }
            if (greaseEch)
            {
                builder.WithGreaseEncryptedClientHello(
                    configuration.GreaseEchCipherSuites,
                    configuration.GreaseEchPayloadLengths);
            }
        });
    }

    private static string[] SelectWeightedAlpn(
        IReadOnlyList<ClientHelloAlpnVariant> variants,
        IRandomSource random)
    {
        var totalWeight = 0;
        foreach (var variant in variants)
        {
            totalWeight = checked(totalWeight + variant.Weight);
        }

        var selected = NextInt(random, 0, totalWeight);
        foreach (var variant in variants)
        {
            if (selected < variant.Weight)
            {
                return variant.SnapshotProtocols();
            }
            selected -= variant.Weight;
        }

        throw new InvalidOperationException("Weighted ALPN selection invariant failed.");
    }

    private static bool IsCipherSuiteAvailable(TlsCipherSuite suite) => suite switch
    {
        TlsCipherSuite.TlsAes128GcmSha256 or TlsCipherSuite.TlsAes256GcmSha384 =>
            AesGcm.IsSupported,
        TlsCipherSuite.TlsChaCha20Poly1305Sha256 => ChaCha20Poly1305.IsSupported,
        _ => false,
    };

    private static bool IsGroupAvailable(NamedGroup group) => AvailableGroups.Value.Contains(group);

    private static IReadOnlySet<NamedGroup> ProbeAvailableGroups()
    {
        var available = new HashSet<NamedGroup>();
        available.Add(NamedGroup.X25519);
        foreach (var group in new[]
        {
            NamedGroup.Secp256r1,
            NamedGroup.Secp384r1,
            NamedGroup.Secp521r1,
        })
        {
            try
            {
                using var agreement = group switch
                {
                    NamedGroup.Secp256r1 => ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256),
                    NamedGroup.Secp384r1 => ECDiffieHellman.Create(ECCurve.NamedCurves.nistP384),
                    NamedGroup.Secp521r1 => ECDiffieHellman.Create(ECCurve.NamedCurves.nistP521),
                    _ => throw new InvalidOperationException(),
                };
                available.Add(group);
            }
            catch (Exception exception) when (
                exception is PlatformNotSupportedException or CryptographicException)
            {
                // This runtime cannot safely execute this candidate.
            }
        }

        return available;
    }

    private static bool Chance(IRandomSource random, int percent) =>
        percent == 100 || (percent != 0 && NextInt(random, 0, 100) < percent);

    private static int NextInt(IRandomSource random, int minimum, int exclusiveMaximum)
    {
        if (exclusiveMaximum <= minimum)
        {
            if (exclusiveMaximum == minimum && minimum == 0)
            {
                return 0;
            }
            throw new ArgumentOutOfRangeException(nameof(exclusiveMaximum));
        }

        var width = checked((uint)(exclusiveMaximum - minimum));
        if (width == 1)
        {
            return minimum;
        }
        var range = 1UL << 32;
        var cutoff = range - (range % width);
        Span<byte> bytes = stackalloc byte[sizeof(uint)];
        uint value;
        do
        {
            random.Fill(bytes);
            value = BinaryPrimitives.ReadUInt32LittleEndian(bytes);
        }
        while (value >= cutoff);

        return checked(minimum + (int)(value % width));
    }

    private static void Shuffle<T>(T[] values, IRandomSource random)
    {
        for (var index = values.Length - 1; index > 0; index--)
        {
            var selected = NextInt(random, 0, index + 1);
            (values[index], values[selected]) = (values[selected], values[index]);
        }
    }

    private static void Shuffle<T>(IList<T> values, IRandomSource random)
    {
        for (var index = values.Count - 1; index > 0; index--)
        {
            var selected = NextInt(random, 0, index + 1);
            (values[index], values[selected]) = (values[selected], values[index]);
        }
    }
}

internal sealed record ClientHelloRandomizationConfiguration(
    TlsCipherSuite[] CipherSuites,
    NamedGroup[] SupportedGroups,
    SignatureScheme[] SignatureAlgorithms,
    ClientHelloAlpnVariant[] AlpnVariants,
    ClientHelloGreasePolicy GreasePolicy,
    int GreaseProbabilityPercent,
    int PaddingProbabilityPercent,
    int MinimumPaddingLength,
    int MaximumPaddingLength,
    int MinimumKeyShareCount,
    int MaximumKeyShareCount,
    bool ShuffleExtensions,
    bool EnableSessionResumption,
    int ApplicationSettingsProbabilityPercent,
    TlsApplicationSettingsCodePoint ApplicationSettingsCodePoint,
    int GreaseEchProbabilityPercent,
    TlsHpkeSymmetricCipherSuite[] GreaseEchCipherSuites,
    int[] GreaseEchPayloadLengths);
