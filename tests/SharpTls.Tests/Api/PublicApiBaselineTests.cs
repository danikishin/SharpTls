using SharpTls.ApiCompatibility;

namespace SharpTls.Tests.Api;

public sealed class PublicApiBaselineTests
{
    [Fact]
    public void ExportedApiMatchesTheReviewedBaseline()
    {
        var expected = File.ReadAllText(
            Path.Combine(AppContext.BaseDirectory, "Api", "PublicApi.Shipped.txt"))
            .ReplaceLineEndings("\n");
        var actual = PublicApiContract.Generate(typeof(CustomTlsClient).Assembly);
        if (!string.Equals(expected, actual, StringComparison.Ordinal))
        {
            var expectedLines = expected.Split('\n');
            var actualLines = actual.Split('\n');
            var firstDifference = Enumerable.Range(0, Math.Max(expectedLines.Length, actualLines.Length))
                .First(index => index >= expectedLines.Length || index >= actualLines.Length ||
                                !string.Equals(expectedLines[index], actualLines[index], StringComparison.Ordinal));
            var expectedLine = firstDifference < expectedLines.Length ? expectedLines[firstDifference] : "<end>";
            var actualLine = firstDifference < actualLines.Length ? actualLines[firstDifference] : "<end>";
            Assert.Fail(
                $"Public API baseline differs at line {firstDifference + 1}.\nExpected: {expectedLine}\nActual:   {actualLine}\nRun tools/SharpTls.ApiCompat, review the complete semantic-versioning impact, then update PublicApi.Shipped.txt intentionally.");
        }
    }
}
