using System.Security.Cryptography;
using SharpTls.IO;
using SharpTls.Protocol;

namespace SharpTls.Tests.ClientHello;

public sealed class AdditionalUTlsProfileTests
{
    public static TheoryData<ClientHelloProfile, bool, bool, string> PinnedPskProfiles => new()
    {
        { ClientHelloProfiles.UTlsChrome100Psk, false, false, "1593A9807DF0108C1618CF3FFDE6A3F358B033F277EB25FFCC9F340C28BA1F57" },
        { ClientHelloProfiles.UTlsChrome112PskShuffle, true, false, "9C8A4DBC9035644703489FA3960EB0E131E1451760F304D3224647D45B8E0DF5" },
        { ClientHelloProfiles.UTlsChrome114PaddingPskShuffle, true, true, "AFD300B675EB3C09DCA223D51EBEA7CBEC9F03518373540E97B8767F1927612B" },
    };

    public static IEnumerable<object[]> PinnedProfiles()
    {
        yield return
        [
            "chrome-96",
            ClientHelloProfiles.UTlsChrome96,
            "DEA5F83E2DD137A8AE781B9F0697FE28EAD82505A25F3B16D3B83B923F4307BE",
        ];
        yield return
        [
            "chrome-100",
            ClientHelloProfiles.UTlsChrome100,
            "09F96CDC60C23BDAA46B3FBB3AE5B34058B225D1827FBAB6D8D8E773D80A32FA",
        ];
        yield return
        [
            "chrome-106-shuffle",
            ClientHelloProfiles.UTlsChrome106Shuffle,
            "AC66F645EB436B2139BE68FBA3D7DF1751D98B1270D2BC72DBC8870A362221B1",
        ];
        yield return
        [
            "firefox-102",
            ClientHelloProfiles.UTlsFirefox102,
            "28905D8AB05CBAC1D61A79D11E5FB2F887B08A5602828DFF5B08C70B7672DD61",
        ];
        yield return
        [
            "firefox-105",
            ClientHelloProfiles.UTlsFirefox105,
            "94349319AEB236307CCA78DF085BC30938B5A7967F831BE1484AA0160C627BC1",
        ];
        yield return
        [
            "ios-13",
            ClientHelloProfiles.UTlsIOS13,
            "05E93D82977BE2688862D16FF1DD99B86A7BFC5A960A96CDA30E1DECC73BDB41",
        ];
    }

    [Theory]
    [MemberData(nameof(PinnedProfiles))]
    public void DeterministicWireImageMatchesPinnedSnapshot(
        string _,
        ClientHelloProfile profile,
        string expectedSha256)
    {
        var hello = profile.BuildDeterministicForTesting(
            "example.com",
            [0x88, 0x02, 0x7D, 0x13, 0x60, 0x51]);

        Assert.Equal(512, hello.Length);
        var actualSha256 = Convert.ToHexString(SHA256.HashData(hello));
        Assert.True(
            string.Equals(expectedSha256, actualSha256, StringComparison.Ordinal),
            actualSha256);
    }

    [Fact]
    public void ChromiumAlpsProfilesPreservePinnedVersionsOrderingAndAliases()
    {
        Assert.Equal(
            [
                TlsProtocolVersion.Tls13,
                TlsProtocolVersion.Tls12,
                TlsProtocolVersion.Tls11,
                TlsProtocolVersion.Tls10,
            ],
            ClientHelloProfiles.UTlsChrome96.Spec.SupportedVersions);
        Assert.Equal(
            [TlsProtocolVersion.Tls13, TlsProtocolVersion.Tls12],
            ClientHelloProfiles.UTlsChrome100.Spec.SupportedVersions);
        Assert.Equal(
            TlsApplicationSettingsCodePoint.LegacyDraft,
            ClientHelloProfiles.UTlsChrome96.Spec.ApplicationSettingsCodePoint);
        Assert.Equal(["h2"], ClientHelloProfiles.UTlsChrome96.Spec.ApplicationSettingsProtocols);
        Assert.Same(ClientHelloProfiles.UTlsChrome100, ClientHelloProfiles.UTlsChrome102);
        Assert.Same(ClientHelloProfiles.UTlsChrome100, ClientHelloProfiles.UTlsEdge106);
        Assert.True(ClientHelloProfiles.UTlsChrome106Shuffle.Spec.ShuffleExtensions);
        Assert.Same(ClientHelloProfiles.UTlsChrome133, ClientHelloProfiles.UTlsChromeAuto);

        Assert.Equal(
            [
                -1,
                (ushort)TlsExtensionType.ServerName,
                23,
                0xFF01,
                (ushort)TlsExtensionType.SupportedGroups,
                11,
                35,
                (ushort)TlsExtensionType.ApplicationLayerProtocolNegotiation,
                5,
                (ushort)TlsExtensionType.SignatureAlgorithms,
                18,
                (ushort)TlsExtensionType.KeyShare,
                (ushort)TlsExtensionType.PskKeyExchangeModes,
                (ushort)TlsExtensionType.SupportedVersions,
                27,
                (ushort)TlsApplicationSettingsCodePoint.LegacyDraft,
                -1,
                (ushort)TlsExtensionType.Padding,
            ],
            NormalizeGrease(ReadExtensionTypes(
                ClientHelloProfiles.UTlsChrome96.BuildDeterministicForTesting(
                    "example.com",
                    [9, 6]))));
    }

    [Fact]
    public void Chrome106ShufflesOnlyMovableExtensionsAndPreservesRetryOrder()
    {
        var profile = ClientHelloProfiles.UTlsChrome106Shuffle;
        using var first = profile.BuildSecure("example.com");
        using var retry = ClientHelloEncoder.BuildRetry(
            first,
            NamedGroup.Secp256r1,
            [7, 8, 9]);

        var firstTypes = ReadExtensionTypes(first.EncodedHandshake);
        var retryTypes = ReadExtensionTypes(retry.EncodedHandshake).ToList();
        retryTypes.Remove((ushort)TlsExtensionType.Cookie);

        Assert.Equal(firstTypes, retryTypes);
        Assert.True(IsGrease(firstTypes[0]));
        Assert.True(IsGrease(firstTypes[^2]));
        Assert.Equal((ushort)TlsExtensionType.Padding, firstTypes[^1]);

        var deterministicA = ReadExtensionTypes(
            profile.BuildDeterministicForTesting("example.com", [1, 0, 6]));
        var deterministicB = ReadExtensionTypes(
            profile.BuildDeterministicForTesting("example.com", [1, 0, 6]));
        var deterministicC = ReadExtensionTypes(
            profile.BuildDeterministicForTesting("example.com", [1, 0, 7]));
        Assert.Equal(deterministicA, deterministicB);
        Assert.NotEqual(deterministicA, deterministicC);
        Assert.True(IsGrease(deterministicA[0]));
        Assert.True(IsGrease(deterministicA[^2]));
        Assert.Equal((ushort)TlsExtensionType.Padding, deterministicA[^1]);
    }

    [Fact]
    public void Chrome120PreservesPinnedGreaseEchPolicyAndExecutableWireShape()
    {
        var profile = ClientHelloProfiles.UTlsChrome120;
        var seed = new byte[] { 1, 2, 0, 1, 2, 0 };
        var hello = profile.BuildDeterministicForTesting("example.com", seed);
        var types = ReadExtensionTypes(hello);

        Assert.True(profile.Spec.ShuffleExtensions);
        Assert.True(profile.Spec.UseBoringPadding);
        Assert.Equal(
            [new TlsHpkeSymmetricCipherSuite(
                TlsHpkeKdfId.HkdfSha256,
                TlsHpkeAeadId.Aes128Gcm)],
            profile.Spec.GreaseEchCipherSuites);
        Assert.Equal([128, 160, 192, 224], profile.Spec.GreaseEchPayloadLengths);
        Assert.Contains((ushort)TlsExtensionType.EncryptedClientHello, types);
        Assert.Equal(2, types.Count(IsGrease));

        var ech = new TlsBinaryReader(
            SharpTls.Ech.EchGreaseClientHelloBuilder.ReadExtensionBody(hello));
        Assert.Equal(0, ech.ReadUInt8());
        Assert.Equal((ushort)TlsHpkeKdfId.HkdfSha256, ech.ReadUInt16());
        Assert.Equal((ushort)TlsHpkeAeadId.Aes128Gcm, ech.ReadUInt16());
        _ = ech.ReadUInt8();
        Assert.Equal(32, ech.ReadVector16().Length);
        Assert.Contains(ech.ReadVector16().Length, new[] { 144, 176, 208, 240 });
        ech.EnsureEnd("Chrome 120 GREASE ECH");

        var restored = ClientHelloProfiles.FromSpec(
            ClientHelloSpecJson.Deserialize(ClientHelloSpecJson.Serialize(profile.Spec)));
        Assert.Equal(hello, restored.BuildDeterministicForTesting("example.com", seed));
    }

    [Theory]
    [MemberData(nameof(PinnedPskProfiles))]
    public void ChromePskVariantsPreserveUpstreamPaddingAndShuffleShape(
        ClientHelloProfile profile,
        bool shuffle,
        bool padding,
        string expectedSha256)
    {
        var seed = new byte[] { 1, 1, 2, 1, 1, 4 };
        var hello = profile.BuildDeterministicForTesting("example.com", seed);
        var types = ReadExtensionTypes(hello);

        Assert.True(profile.Spec.SupportsSessionResumption);
        Assert.Equal(
            ClientHelloExtensionKind.PreSharedKey,
            profile.Spec.Extensions[^1].BuiltInKind);
        Assert.Equal(shuffle, profile.Spec.ShuffleExtensions);
        Assert.Equal(padding, profile.Spec.UseBoringPadding);
        Assert.Equal(padding, types.Contains((ushort)TlsExtensionType.Padding));
        Assert.DoesNotContain((ushort)TlsExtensionType.PreSharedKey, types);

        var actualSha256 = Convert.ToHexString(SHA256.HashData(hello));
        Assert.True(
            string.Equals(expectedSha256, actualSha256, StringComparison.Ordinal),
            actualSha256);

        var restored = ClientHelloProfiles.FromSpec(
            ClientHelloSpecJson.Deserialize(ClientHelloSpecJson.Serialize(profile.Spec)));
        Assert.Equal(hello, restored.BuildDeterministicForTesting("example.com", seed));
    }

    [Fact]
    public void FirefoxProfilesPreserveAlpnDifferenceAndPinnedWireOrder()
    {
        Assert.Equal(["h2"], ClientHelloProfiles.UTlsFirefox102.Spec.AlpnProtocols);
        Assert.Equal(
            ["h2", "http/1.1"],
            ClientHelloProfiles.UTlsFirefox105.Spec.AlpnProtocols);
        Assert.Equal(
            [TlsProtocolVersion.Tls13, TlsProtocolVersion.Tls12],
            ClientHelloProfiles.UTlsFirefox102.Spec.SupportedVersions);
        Assert.Equal(
            [0, 23, 0xFF01, 10, 11, 35, 16, 5, 34, 51, 43, 13, 45, 28, 21],
            ReadExtensionTypes(ClientHelloProfiles.UTlsFirefox102.BuildDeterministicForTesting(
                "example.com",
                [1, 0, 2]))
                .Select(value => (int)value));
    }

    [Fact]
    public void Firefox120EmitsPinnedSemanticGreaseEch()
    {
        var profile = ClientHelloProfiles.UTlsFirefox120;
        var seed = new byte[] { 1, 2, 0, 2, 6 };
        var hello = profile.BuildDeterministicForTesting("example.com", seed);

        Assert.True(profile.Spec.GreaseEncryptedClientHello);
        Assert.Equal([223], profile.Spec.GreaseEchPayloadLengths);
        Assert.Equal(
            [0, 23, 0xFF01, 10, 11, 35, 16, 5, 34, 51, 43, 13, 45, 28, 0xFE0D],
            ReadExtensionTypes(hello).Select(value => (int)value));

        var ech = new TlsBinaryReader(
            SharpTls.Ech.EchGreaseClientHelloBuilder.ReadExtensionBody(hello));
        Assert.Equal(0, ech.ReadUInt8());
        _ = ech.ReadUInt16();
        _ = ech.ReadUInt16();
        _ = ech.ReadUInt8();
        Assert.Equal(32, ech.ReadVector16().Length);
        Assert.Equal(239, ech.ReadVector16().Length);
        ech.EnsureEnd("Firefox 120 GREASE ECH");

        var json = ClientHelloSpecJson.Serialize(profile.Spec);
        var restored = ClientHelloProfiles.FromSpec(ClientHelloSpecJson.Deserialize(json));
        Assert.Equal(hello, restored.BuildDeterministicForTesting("example.com", seed));

        var hash = Convert.ToHexString(SHA256.HashData(hello));
        Assert.True(
            string.Equals(
                "90E7C6693EE9A4C3A26D7874D363CD20DAD0BC109C0F5329AAEB4217E648289A",
                hash,
                StringComparison.Ordinal),
            hash);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void Chrome131And133UseStandardHybridGroupAndPinnedAlps(bool chrome133)
    {
        var profile = chrome133
            ? ClientHelloProfiles.UTlsChrome133
            : ClientHelloProfiles.UTlsChrome131;
        var seed = new byte[] { 1, 3, 1, 0, 2, 6, 7 };
        var hello = profile.BuildDeterministicForTesting("example.com", seed);
        var types = ReadExtensionTypes(hello);

        Assert.Equal(
            [NamedGroup.X25519MlKem768, NamedGroup.X25519],
            profile.Spec.KeyShareGroups);
        Assert.Equal(NamedGroup.X25519MlKem768, profile.Spec.SupportedGroups[0]);
        Assert.False(profile.Spec.UseBoringPadding);
        Assert.True(profile.Spec.ShuffleExtensions);
        Assert.Contains((ushort)TlsExtensionType.EncryptedClientHello, types);
        Assert.Contains(
            (ushort)(chrome133
                ? TlsApplicationSettingsCodePoint.ChromeExperiment
                : TlsApplicationSettingsCodePoint.LegacyDraft),
            types);
        Assert.DoesNotContain((ushort)TlsExtensionType.Padding, types);

        var restored = ClientHelloProfiles.FromSpec(
            ClientHelloSpecJson.Deserialize(ClientHelloSpecJson.Serialize(profile.Spec)));
        Assert.Equal(hello, restored.BuildDeterministicForTesting("example.com", seed));
    }

    public static TheoryData<ClientHelloProfile, bool, bool, bool> LegacyPqProfiles => new()
    {
        { ClientHelloProfiles.UTlsChrome115Pq, false, true, false },
        { ClientHelloProfiles.UTlsChrome115PqPsk, true, false, false },
        { ClientHelloProfiles.UTlsChrome120Pq, false, false, true },
    };

    [Theory]
    [MemberData(nameof(LegacyPqProfiles))]
    public void LegacyChromePqProfilesPreserveDraftGroupAndConditionalFeatures(
        ClientHelloProfile profile,
        bool psk,
        bool padding,
        bool ech)
    {
        var hello = profile.BuildDeterministicForTesting("example.com", [1, 1, 5, 7]);
        var types = ReadExtensionTypes(hello);

        Assert.Equal(NamedGroup.X25519Kyber768Draft00, profile.Spec.SupportedGroups[0]);
        Assert.Equal(
            [NamedGroup.X25519Kyber768Draft00, NamedGroup.X25519],
            profile.Spec.KeyShareGroups);
        Assert.Equal(psk, profile.Spec.SupportsSessionResumption);
        Assert.Equal(padding, profile.Spec.UseBoringPadding);
        Assert.Equal(ech, profile.Spec.GreaseEncryptedClientHello);
        Assert.False(!padding && types.Contains((ushort)TlsExtensionType.Padding));
        Assert.Equal(ech, types.Contains((ushort)TlsExtensionType.EncryptedClientHello));
        Assert.DoesNotContain((ushort)TlsExtensionType.PreSharedKey, types);
    }

    [Fact]
    public void Firefox148PreservesHybridReuseAndExactExtensionOrder()
    {
        var profile = ClientHelloProfiles.UTlsFirefox148;
        var hello = profile.BuildDeterministicForTesting("example.com", [1, 4, 8]);

        Assert.Same(profile, ClientHelloProfiles.UTlsFirefoxAuto);
        Assert.Equal(
            [NamedGroup.X25519MlKem768, NamedGroup.X25519, NamedGroup.Secp256r1],
            profile.Spec.KeyShareGroups);
        Assert.Equal(
            [0, 23, 0xFF01, 10, 11, 16, 5, 34, 18, 51, 43, 13, 28, 27, 0xFE0D],
            ReadExtensionTypes(hello).Select(value => (int)value));
        Assert.Equal(
            [
                new TlsHpkeSymmetricCipherSuite(
                    TlsHpkeKdfId.HkdfSha256,
                    TlsHpkeAeadId.Aes128Gcm),
                new TlsHpkeSymmetricCipherSuite(
                    TlsHpkeKdfId.HkdfSha256,
                    TlsHpkeAeadId.ChaCha20Poly1305),
            ],
            profile.Spec.GreaseEchCipherSuites);
    }

    [Fact]
    public void Safari263PreservesHybridAndAppleWireOrder()
    {
        var profile = ClientHelloProfiles.UTlsSafari263;
        var hello = profile.BuildDeterministicForTesting("example.com", [2, 6, 3]);

        Assert.Same(profile, ClientHelloProfiles.UTlsSafariAuto);
        Assert.Equal(
            [NamedGroup.X25519MlKem768, NamedGroup.X25519],
            profile.Spec.KeyShareGroups);
        Assert.Equal(
            [-1, 0, 23, 0xFF01, 10, 11, 16, 5, 13, 18, 51, 45, 43, 27, -1],
            NormalizeGrease(ReadExtensionTypes(hello)));
        Assert.Equal(
            2,
            profile.Spec.SignatureAlgorithms.Count(
                scheme => scheme == SignatureScheme.RsaPssRsaeSha384));

        var captured = ClientHelloCapture.Import(hello);
        Assert.Equal(
            hello,
            ClientHelloProfiles.FromSpec(captured.Spec)
                .BuildDeterministicForTesting("example.com", [2, 6, 3]));
    }

    [Fact]
    public void IOS13PreservesPreGreaseAppleOrderingAndDuplicateSignatures()
    {
        var profile = ClientHelloProfiles.UTlsIOS13;

        Assert.False(profile.Spec.Grease);
        Assert.True(profile.Spec.AllowsDuplicateSignatureAlgorithms);
        Assert.Equal(
            [0xFF01, 0, 23, 13, 5, 18, 16, 11, 51, 45, 43, 10, 21],
            ReadExtensionTypes(profile.BuildDeterministicForTesting("example.com", [1, 3]))
                .Select(value => (int)value));
        Assert.Equal(
            2,
            profile.Spec.SignatureAlgorithms.Count(
                scheme => scheme == SignatureScheme.RsaPssRsaeSha384));
    }

    [Theory]
    [MemberData(nameof(PinnedProfiles))]
    public void AddedProfilesRoundTripThroughCaptureAndJson(
        string _,
        ClientHelloProfile profile,
        string __)
    {
        _ = __;
        var seed = new byte[] { 2, 0, 2, 6, 7, 1, 7 };
        var original = profile.BuildDeterministicForTesting("example.com", seed);
        var capture = ClientHelloCapture.Import(original);
        var json = ClientHelloSpecJson.Deserialize(ClientHelloSpecJson.Serialize(profile.Spec));

        Assert.Equal(
            original,
            ClientHelloProfiles.FromSpec(capture.Spec)
                .BuildDeterministicForTesting("example.com", seed));
        Assert.Equal(
            original,
            ClientHelloProfiles.FromSpec(json)
                .BuildDeterministicForTesting("example.com", seed));
    }

    private static ushort[] ReadExtensionTypes(byte[] handshake)
    {
        var reader = new TlsBinaryReader(handshake);
        Assert.Equal((byte)HandshakeType.ClientHello, reader.ReadUInt8());
        var body = new TlsBinaryReader(reader.ReadBytes(reader.ReadUInt24()));
        reader.EnsureEnd("ClientHello test framing");
        _ = body.ReadUInt16();
        _ = body.ReadBytes(TlsConstants.RandomLength);
        _ = body.ReadVector8();
        _ = body.ReadVector16();
        _ = body.ReadVector8();
        var extensions = new TlsBinaryReader(body.ReadVector16());
        body.EnsureEnd("ClientHello test body");
        var result = new List<ushort>();
        while (!extensions.End)
        {
            result.Add(extensions.ReadUInt16());
            _ = extensions.ReadVector16();
        }
        return result.ToArray();
    }

    private static int[] NormalizeGrease(IEnumerable<ushort> values) =>
        values.Select(value => IsGrease(value) ? -1 : value).ToArray();

    private static bool IsGrease(ushort value) =>
        (value & 0x0F0F) == 0x0A0A && (byte)(value >> 8) == (byte)value;
}
