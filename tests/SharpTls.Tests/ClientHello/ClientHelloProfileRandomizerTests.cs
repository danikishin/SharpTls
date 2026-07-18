using SharpTls.Protocol;

namespace SharpTls.Tests.ClientHello;

public sealed class ClientHelloProfileRandomizerTests
{
    [Fact]
    public void SameTestSeedProducesSameProfileSpecificationAndWireImage()
    {
        var first = ClientHelloProfileRandomizer.CreateDeterministicForTesting([1, 7, 2, 9]);
        var second = ClientHelloProfileRandomizer.CreateDeterministicForTesting([1, 7, 2, 9]);

        Assert.Equal(
            ClientHelloSpecJson.Serialize(first.Spec),
            ClientHelloSpecJson.Serialize(second.Spec));
        Assert.Equal(
            first.BuildDeterministicForTesting("example.com", [4, 2]),
            second.BuildDeterministicForTesting("example.com", [4, 2]));
    }

    [Fact]
    public void GeneratedProfilesRemainExecutableAcrossSeedCorpus()
    {
        for (var value = 1; value <= 250; value++)
        {
            var profile = ClientHelloProfileRandomizer.CreateDeterministicForTesting(
                BitConverter.GetBytes(value));
            var encoded = profile.BuildDeterministicForTesting("example.com", [9, 1]);

            Assert.Equal((byte)1, encoded[0]);
            Assert.NotEmpty(profile.Spec.CipherSuites);
            Assert.NotEmpty(profile.Spec.SupportedGroups);
            Assert.All(profile.Spec.KeyShareGroups, group =>
                Assert.Contains(group, profile.Spec.SupportedGroups));
            Assert.Equal(
                profile.Spec.Extensions.Count,
                profile.Spec.Extensions.Select(ExtensionIdentity).Distinct().Count());
        }
    }

    [Fact]
    public void ZeroProbabilityDisablesGreaseAndPaddingAndEmptyAlpnVariantRemovesAlpn()
    {
        var options = new ClientHelloRandomizationOptions
        {
            GreaseProbabilityPercent = 0,
            PaddingProbabilityPercent = 0,
            AlpnVariants = [new ClientHelloAlpnVariant(1)],
        };

        var spec = ClientHelloProfileRandomizer
            .CreateDeterministicForTesting([3], options)
            .Spec;

        Assert.False(spec.Grease);
        Assert.Null(spec.PaddingLength);
        Assert.Empty(spec.AlpnProtocols);
        Assert.DoesNotContain(spec.Extensions, extension =>
            extension.BuiltInKind is ClientHelloExtensionKind.Grease or
                ClientHelloExtensionKind.Padding or
                ClientHelloExtensionKind.ApplicationLayerProtocolNegotiation);
    }

    [Fact]
    public void ForcedModernFeaturesProduceExecutableResumptionAlpsAndGreaseEchLayout()
    {
        var options = new ClientHelloRandomizationOptions
        {
            AlpnVariants = [new ClientHelloAlpnVariant(1, "h2", "http/1.1")],
            GreaseProbabilityPercent = 100,
            PaddingProbabilityPercent = 100,
            ApplicationSettingsProbabilityPercent = 100,
            GreaseEchProbabilityPercent = 100,
            ShuffleExtensions = true,
        };

        var profile = ClientHelloProfileRandomizer.CreateDeterministicForTesting(
            [2, 0, 2, 6],
            options);
        var spec = profile.Spec;
        var encoded = profile.BuildDeterministicForTesting("example.com", [9, 8, 4, 9]);
        var restored = ClientHelloSpecJson.Deserialize(ClientHelloSpecJson.Serialize(spec));

        Assert.True(spec.SupportsSessionResumption);
        Assert.True(spec.SupportsEarlyData);
        Assert.True(spec.GreaseEncryptedClientHello);
        Assert.Equal(
            TlsApplicationSettingsCodePoint.ChromeExperiment,
            spec.ApplicationSettingsCodePoint);
        Assert.Equal(["h2"], spec.ApplicationSettingsProtocols);
        Assert.Equal(
            ClientHelloExtensionKind.PreSharedKey,
            spec.Extensions[^1].BuiltInKind);
        Assert.Equal(
            encoded,
            ClientHelloProfiles.FromSpec(restored)
                .BuildDeterministicForTesting("example.com", [9, 8, 4, 9]));
    }

    [Fact]
    public void InvalidBoundsAndDuplicateCandidatesAreRejected()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() =>
            ClientHelloProfileRandomizer.CreateSecure(new ClientHelloRandomizationOptions
            {
                GreaseProbabilityPercent = 101,
            }));
        Assert.Throws<ArgumentException>(() =>
            ClientHelloProfileRandomizer.CreateSecure(new ClientHelloRandomizationOptions
            {
                SupportedGroups = [NamedGroup.Secp256r1, NamedGroup.Secp256r1],
            }));
        Assert.Throws<ArgumentOutOfRangeException>(() =>
            ClientHelloProfileRandomizer.CreateSecure(new ClientHelloRandomizationOptions
            {
                MinimumKeyShareCount = 5,
                MaximumKeyShareCount = 5,
            }));
        Assert.Throws<ArgumentException>(() =>
            ClientHelloProfileRandomizer.CreateSecure(new ClientHelloRandomizationOptions
            {
                GreaseEchPayloadLengths = [],
            }));
        Assert.Throws<NotSupportedException>(() =>
            ClientHelloProfileRandomizer.CreateSecure(new ClientHelloRandomizationOptions
            {
                GreaseEchCipherSuites =
                [
                    new TlsHpkeSymmetricCipherSuite(
                        (TlsHpkeKdfId)ushort.MaxValue,
                        TlsHpkeAeadId.Aes128Gcm),
                ],
            }));
    }

    [Fact]
    public void EmptyDeterministicSeedIsRejected()
    {
        Assert.Throws<ArgumentException>(() =>
            ClientHelloProfileRandomizer.CreateDeterministicForTesting([]));
    }

    [Fact]
    public void DeterministicCorpusTracksConfiguredWeightsWithoutCollapsingOrderEntropy()
    {
        const int sampleCount = 4_096;
        var grease = 0;
        var padding = 0;
        var h2 = 0;
        var http11Only = 0;
        var noAlpn = 0;
        var extensionOrders = new HashSet<string>(StringComparer.Ordinal);
        var firstGroups = new Dictionary<NamedGroup, int>();
        var firstSuites = new Dictionary<TlsCipherSuite, int>();

        for (var value = 1; value <= sampleCount; value++)
        {
            var spec = ClientHelloProfileRandomizer
                .CreateDeterministicForTesting(BitConverter.GetBytes(value))
                .Spec;
            grease += spec.Grease ? 1 : 0;
            padding += spec.PaddingLength.HasValue ? 1 : 0;
            if (spec.AlpnProtocols.SequenceEqual(new[] { "h2", "http/1.1" }))
            {
                h2++;
            }
            else if (spec.AlpnProtocols.SequenceEqual(new[] { "http/1.1" }))
            {
                http11Only++;
            }
            else
            {
                Assert.Empty(spec.AlpnProtocols);
                noAlpn++;
            }

            extensionOrders.Add(string.Join(',', spec.Extensions.Select(ExtensionIdentity)));
            Increment(firstGroups, spec.SupportedGroups[0]);
            Increment(firstSuites, spec.CipherSuites[0]);
        }

        Assert.InRange(grease, sampleCount * 68 / 100, sampleCount * 82 / 100);
        Assert.InRange(padding, sampleCount * 43 / 100, sampleCount * 57 / 100);
        Assert.InRange(h2, sampleCount * 43 / 100, sampleCount * 57 / 100);
        Assert.InRange(http11Only, sampleCount * 24 / 100, sampleCount * 36 / 100);
        Assert.InRange(noAlpn, sampleCount * 14 / 100, sampleCount * 26 / 100);
        Assert.True(extensionOrders.Count > 500);
        Assert.All(firstGroups.Values, count => Assert.True(count > sampleCount / 5));
        Assert.All(firstSuites.Values, count => Assert.True(count > sampleCount / 5));
    }

    private static string ExtensionIdentity(ClientHelloExtensionSpec extension) =>
        extension.BuiltInKind?.ToString() ?? $"raw:{extension.RawExtensionType:X4}";

    private static void Increment<T>(Dictionary<T, int> counts, T value)
        where T : notnull
    {
        counts.TryGetValue(value, out var count);
        counts[value] = count + 1;
    }
}
