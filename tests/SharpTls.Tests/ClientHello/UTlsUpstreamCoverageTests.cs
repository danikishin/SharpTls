using System.Reflection;

namespace SharpTls.Tests.ClientHello;

public sealed class UTlsUpstreamCoverageTests
{
    // UTLSIdToSpec concrete IDs at pinned commit 880e27d8b0e5daafd2a39bb3fb2e0c29211c0d40.
    internal static readonly string[] PinnedPropertyNames =
    [
        "UTlsFirefox55", "UTlsFirefox56", "UTlsFirefox63", "UTlsFirefox65",
        "UTlsFirefox99", "UTlsFirefox102", "UTlsFirefox105", "UTlsFirefox120",
        "UTlsFirefox148",
        "UTlsChrome58", "UTlsChrome62", "UTlsChrome70", "UTlsChrome72",
        "UTlsChrome83", "UTlsChrome87", "UTlsChrome96", "UTlsChrome100",
        "UTlsChrome102", "UTlsChrome106Shuffle", "UTlsChrome100Psk",
        "UTlsChrome112PskShuffle", "UTlsChrome114PaddingPskShuffle",
        "UTlsChrome115Pq", "UTlsChrome115PqPsk", "UTlsChrome120",
        "UTlsChrome120Pq", "UTlsChrome131", "UTlsChrome133",
        "UTlsIOS11_1", "UTlsIOS12_1", "UTlsIOS13", "UTlsIOS14",
        "UTlsAndroid11OkHttp", "UTlsEdge85", "UTlsEdge106", "UTlsSafari16",
        "UTlsSafari263", "UTls360_7_5", "UTls360_11_0", "UTlsQQ11_1",
    ];

    [Fact]
    public void EveryPinnedUpstreamIdHasABuildableSharpTlsProperty()
    {
        Assert.Equal(40, PinnedPropertyNames.Length);
        Assert.Equal(PinnedPropertyNames.Length, PinnedPropertyNames.Distinct().Count());

        foreach (var propertyName in PinnedPropertyNames)
        {
            var property = typeof(ClientHelloProfiles).GetProperty(
                propertyName,
                BindingFlags.Public | BindingFlags.Static);
            var profile = Assert.IsType<ClientHelloProfile>(property?.GetValue(null));
            var handshake = profile.BuildDeterministicForTesting(
                "example.com",
                [4, 0, 8, 8, 0]);
            Assert.NotEmpty(handshake);
        }
    }

    [Fact]
    public async Task SecureConnectionPolicyExecutesThirtyNineProfilesAndClassifiesTheUnsafeLegacyImage()
    {
        var wireOnly = new List<string>();
        foreach (var propertyName in PinnedPropertyNames)
        {
            var property = typeof(ClientHelloProfiles).GetProperty(
                propertyName,
                BindingFlags.Public | BindingFlags.Static);
            var profile = Assert.IsType<ClientHelloProfile>(property?.GetValue(null));
            try
            {
                await using var client = new CustomTlsClient(new CustomTlsClientOptions
                {
                    ServerName = "example.com",
                    ClientHello = profile,
                });
            }
            catch (ArgumentException)
            {
                wireOnly.Add(propertyName);
            }
        }

        Assert.Equal(["UTls360_7_5"], wireOnly);
    }
}
