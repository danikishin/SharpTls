namespace SharpTls.Tests.ClientHello;

public sealed class UTlsAutoProfileTests
{
    public static TheoryData<ClientHelloProfile, ClientHelloProfile> Aliases => new()
    {
        { ClientHelloProfiles.UTlsChromeAuto, ClientHelloProfiles.UTlsChrome133 },
        { ClientHelloProfiles.UTlsFirefoxAuto, ClientHelloProfiles.UTlsFirefox148 },
        { ClientHelloProfiles.UTlsEdgeAuto, ClientHelloProfiles.UTlsEdge106 },
        { ClientHelloProfiles.UTlsIOSAuto, ClientHelloProfiles.UTlsIOS14 },
        { ClientHelloProfiles.UTlsSafariAuto, ClientHelloProfiles.UTlsSafari263 },
        { ClientHelloProfiles.UTlsAndroidAuto, ClientHelloProfiles.UTlsAndroid11OkHttp },
    };

    [Theory]
    [MemberData(nameof(Aliases))]
    public void AutoAliasResolvesToPinnedExecutableProfile(
        ClientHelloProfile alias,
        ClientHelloProfile pinned)
    {
        Assert.Same(pinned, alias);
        Assert.Equal(
            pinned.BuildDeterministicForTesting("example.com", [2, 0, 2, 6]),
            alias.BuildDeterministicForTesting("example.com", [2, 0, 2, 6]));
    }
}
