using SharpTls.Fuzzing;

namespace SharpTls.Tests.Protocol;

public sealed class ManagedFuzzHarnessTests
{
    [Fact]
    public void StructuralSeedsReachSuccessfulParserAndStateMachinePaths()
    {
        using var targets = new ProtocolFuzzTargets();
        targets.VerifyStructuralSeeds();
    }

    [Fact]
    public void EveryRegisteredTargetAcceptsSeedAndHostileInputsWithinItsBoundary()
    {
        using var targets = new ProtocolFuzzTargets();
        var random = new Random(0x29_2026);
        var hostileInputs = new List<byte[]>();
        for (var index = 0; index < 64; index++)
        {
            var input = new byte[random.Next(0, 1025)];
            random.NextBytes(input);
            hostileInputs.Add(input);
        }

        foreach (var target in ProtocolFuzzTargets.TargetNames)
        {
            var inputs = targets.CreateSeedCorpus(target)
                .Select(input => (byte[])input.Clone())
                .Concat(hostileInputs)
                .ToList();
            foreach (var input in inputs)
            {
                targets.Run(target, input);
            }
        }
    }

    [Fact]
    public void UnknownTargetAndOversizedInputAreRejectedBeforeDispatch()
    {
        using var targets = new ProtocolFuzzTargets();

        Assert.Throws<ArgumentException>(() => targets.Run("unknown", []));
        Assert.Throws<ArgumentException>(() => targets.CreateSeedCorpus("unknown"));
        Assert.Throws<ArgumentOutOfRangeException>(() => targets.Run(
            "clienthello",
            new byte[ProtocolFuzzTargets.MaximumInputLength + 1]));
    }

    [Fact]
    public void EveryTargetHasDistinctBoundedStructuralSeedsAndAllIsTheirUnion()
    {
        using var targets = new ProtocolFuzzTargets();
        var perTargetFingerprints = new HashSet<string>(StringComparer.Ordinal);
        var union = new HashSet<string>(StringComparer.Ordinal);

        foreach (var target in ProtocolFuzzTargets.TargetNames)
        {
            var seeds = targets.CreateSeedCorpus(target);
            Assert.True(seeds.Count > 6);
            Assert.All(seeds, seed => Assert.InRange(
                seed.Length,
                0,
                ProtocolFuzzTargets.MaximumInputLength));
            Assert.True(perTargetFingerprints.Add(string.Join(
                ',',
                seeds.Select(Convert.ToBase64String))));
            union.UnionWith(seeds.Select(Convert.ToBase64String));
        }

        Assert.Equal(
            union,
            targets.CreateSeedCorpus().Select(Convert.ToBase64String).ToHashSet(StringComparer.Ordinal));
    }

    [Fact]
    public void SeedCorpusIsStableAcrossIndependentRegistries()
    {
        using var first = new ProtocolFuzzTargets();
        using var second = new ProtocolFuzzTargets();

        foreach (var target in ProtocolFuzzTargets.TargetNames)
        {
            Assert.Equal(
                first.CreateSeedCorpus(target).Select(Convert.ToHexString),
                second.CreateSeedCorpus(target).Select(Convert.ToHexString));
        }
    }
}
