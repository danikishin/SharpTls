using System.Security.Cryptography;
using SharpTls.Cryptography;
using SharpTls.Protocol;

namespace SharpTls.Tests.ClientHello;

public sealed class LegacyUTlsProfileTests
{
    public static TheoryData<ClientHelloProfile, string> GoldenProfiles => new()
    {
        { ClientHelloProfiles.UTlsChrome58, "68DBDDB21A0456B8D6CE78F535CEB72C0031BC474390D51855B97FE42E2064EF" },
        { ClientHelloProfiles.UTlsChrome70, "F2BEAA5797D6A7479516B7008FB7A17C6C38BA48E27FF28555C2293E2156E98A" },
        { ClientHelloProfiles.UTlsChrome72, "BD4BC2F3608185E59B2FE93D1FFBA278398574A2AFDDEBEA65A5996AB5E366E8" },
        { ClientHelloProfiles.UTlsFirefox55, "CE222D68DF4A66159C3ACD2300702FF0A1FD465E00DED4585918702B31E4F4D6" },
        { ClientHelloProfiles.UTlsFirefox63, "D4E778FA926F14F0805F8C377FBD58A3DC5A21F4C5E46E7B439FA1F00E0F5C17" },
        { ClientHelloProfiles.UTlsIOS11_1, "9CC5A61236FBA388531C8DBCFCCB47781C180305EBB4215AA9B5E2EC9F64D654" },
        { ClientHelloProfiles.UTlsIOS12_1, "E02FB22A5556E12551CD8854FC7734C51523BC3D669B2FBFCF80A6876232F13C" },
        { ClientHelloProfiles.UTls360_7_5, "CA823C1B1D497B8A6C4E89763F5DC484CAC05FD665889E06D3448F9BD58A1DEB" },
        { ClientHelloProfiles.UTls360_11_0, "FEBD2F7F0F67543582031100427D5EED517C5E5595ABF18A8F3DBEFD9E821F93" },
        { ClientHelloProfiles.UTlsQQ11_1, "AD8CF643A3EC0974858209BB4E18DFFE1E4A01A14E8552D168AABF3960A1C41A" },
    };

    [Theory]
    [MemberData(nameof(GoldenProfiles))]
    public void LegacyUpstreamProfilesHavePinnedFullWireSnapshots(
        ClientHelloProfile profile,
        string expectedSha256)
    {
        var encoded = profile.BuildDeterministicForTesting("example.com", [7, 8, 9]);
        Assert.Equal(expectedSha256, Convert.ToHexString(SHA256.HashData(encoded)));

        var json = ClientHelloSpecJson.Serialize(profile.Spec);
        var restored = ClientHelloProfiles.FromSpec(ClientHelloSpecJson.Deserialize(json));
        Assert.Equal(
            encoded,
            restored.BuildDeterministicForTesting("example.com", [7, 8, 9]));
    }

    [Fact]
    public void LegacyAliasesMatchPinnedUpstreamIdentityAliases()
    {
        Assert.Same(ClientHelloProfiles.UTlsChrome58, ClientHelloProfiles.UTlsChrome62);
        Assert.Same(ClientHelloProfiles.UTlsFirefox55, ClientHelloProfiles.UTlsFirefox56);
        Assert.Same(ClientHelloProfiles.UTlsFirefox63, ClientHelloProfiles.UTlsFirefox65);
        Assert.Same(ClientHelloProfiles.UTls360_11_0, ClientHelloProfiles.UTls360Auto);
        Assert.Same(ClientHelloProfiles.UTlsQQ11_1, ClientHelloProfiles.UTlsQQAuto);
    }

    [Fact]
    public void LegacyProfilesRetainExactTlsGenerationAndResumptionShape()
    {
        Assert.Equal(
            [TlsProtocolVersion.Tls12],
            ClientHelloProfiles.UTlsChrome58.Spec.SupportedVersions);
        Assert.Empty(ClientHelloProfiles.UTlsFirefox55.Spec.SessionId!);
        Assert.Equal(
            [TlsProtocolVersion.Tls13, TlsProtocolVersion.Tls12,
             TlsProtocolVersion.Tls11, TlsProtocolVersion.Tls10],
            ClientHelloProfiles.UTlsChrome70.Spec.SupportedVersions);
        Assert.True(ClientHelloProfiles.UTlsChrome70.Spec.SupportsSessionResumption);
        Assert.True(ClientHelloProfiles.UTlsChrome72.Spec.SupportsSessionResumption);
        Assert.True(ClientHelloProfiles.UTlsFirefox63.Spec.SupportsSessionResumption);
    }

    [Fact]
    public void FingerprintOnlyWeakSuitesHaveNoExecutableRecordCipher()
    {
        Assert.Throws<NotSupportedException>(() =>
            CipherSuiteInfo.Get(TlsCipherSuite.TlsDheRsaWithAes128CbcSha));
        Assert.Throws<NotSupportedException>(() =>
            CipherSuiteInfo.Get(TlsCipherSuite.TlsRsaWithRc4_128Sha));
        Assert.Throws<ArgumentException>(() => new CustomTlsClient(
            new CustomTlsClientOptions { ClientHello = ClientHelloProfiles.UTls360_7_5 }));
    }
}
