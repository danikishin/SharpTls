using System.Security.Cryptography;
using SharpTls.Protocol;

namespace SharpTls.Tests.ClientHello;

public sealed class ClientHelloProfileManifestTests
{
    [Fact]
    public void ImportedManifestRetainsProvenanceButNotEphemeralWireBytes()
    {
        var sourceProfile = ClientHelloProfiles.Custom(builder => builder
            .WithGrease(ClientHelloGreasePolicy.PerSlot)
            .WithAlpn("h2", "http/1.1")
            .WithPadding(9));
        var seed = new byte[] { 2, 0, 2, 6 };
        var capture = sourceProfile.BuildDeterministicForTesting("example.com", seed);
        var expectedDigest = SHA256.HashData(capture);
        var capturedAt = new DateTimeOffset(2026, 7, 17, 12, 0, 0, TimeSpan.Zero);

        var manifest = ClientHelloProfileManifest.Import(
            "example-client/1.2.3",
            "example-client",
            "1.2.3",
            capturedAt,
            capture);
        capture.AsSpan().Fill(0xFF);

        Assert.Equal("example-client/1.2.3", manifest.Id);
        Assert.Equal("example-client", manifest.Family);
        Assert.Equal("1.2.3", manifest.Version);
        Assert.Equal(capturedAt, manifest.CapturedAt);
        Assert.Equal("example.com", manifest.CapturedServerName);
        Assert.Equal(expectedDigest, manifest.SourceSha256);
        Assert.Equal(new[] { "h2", "http/1.1" }, manifest.RequiredApplicationProtocols);
        Assert.Equal(
            sourceProfile.BuildDeterministicForTesting("example.com", seed),
            manifest.CreateProfile().BuildDeterministicForTesting("example.com", seed));
    }

    [Fact]
    public void CatalogRejectsDuplicateIdsAndReturnsSortedSnapshots()
    {
        var first = CreateManifest("z/profile");
        var second = CreateManifest("a/profile");
        var catalog = new ClientHelloProfileCatalog();
        catalog.Register(first);
        catalog.Register(second);

        Assert.Equal(new[] { "a/profile", "z/profile" }, catalog.Profiles.Select(item => item.Id));
        Assert.Same(first, catalog.GetRequired("z/profile"));
        Assert.True(catalog.TryGet("a/profile", out var found));
        Assert.Same(second, found);
        Assert.Throws<ArgumentException>(() => catalog.Register(first));
        Assert.Throws<KeyNotFoundException>(() => catalog.GetRequired("missing"));
    }

    [Fact]
    public void CatalogSupportsConcurrentDistinctRegistration()
    {
        var catalog = new ClientHelloProfileCatalog();

        Parallel.For(0, 64, index =>
            catalog.Register(CreateManifest($"client/{index:D2}")));

        Assert.Equal(64, catalog.Profiles.Count);
    }

    [Theory]
    [InlineData("")]
    [InlineData("bad\nfamily")]
    public void ManifestMetadataIsStrict(string value)
    {
        var capture = ClientHelloProfiles.ModernTls13
            .BuildDeterministicForTesting("example.com", [1]);

        Assert.Throws<ArgumentException>(() => ClientHelloProfileManifest.Import(
            value,
            "family",
            "1",
            DateTimeOffset.UtcNow,
            capture));
    }

    private static ClientHelloProfileManifest CreateManifest(string id)
    {
        var capture = ClientHelloProfiles.Custom(builder =>
                builder.WithCipherSuites(TlsCipherSuite.TlsAes128GcmSha256))
            .BuildDeterministicForTesting("example.com", [7]);
        return ClientHelloProfileManifest.Import(
            id,
            "test",
            "1",
            DateTimeOffset.UnixEpoch,
            capture);
    }
}
