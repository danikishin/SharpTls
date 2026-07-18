using System.Security.Cryptography;
using SharpTls.Protocol;

namespace SharpTls.Tests.Sessions;

public sealed class Tls12SessionCacheTests
{
    [Fact]
    public void CacheBindsOriginAndSuiteAndReturnsIndependentSecretCopies()
    {
        var now = new DateTimeOffset(2026, 7, 18, 12, 0, 0, TimeSpan.Zero);
        var clock = new ManualTimeProvider(now);
        using var cache = new Tls12SessionCache(4, TimeSpan.FromHours(2), clock);
        var secret = Enumerable.Range(0, 48).Select(value => (byte)value).ToArray();
        cache.Add(CreateSession(
            Tls13SessionOrigin.Create("example.com", 443),
            [1, 2, 3],
            secret,
            now.AddHours(1),
            "http/1.1"));

        Assert.Null(cache.TryGet(
            Tls13SessionOrigin.Create("other.example", 443),
            [TlsCipherSuite.TlsEcdheRsaWithAes128GcmSha256]));
        Assert.Null(cache.TryGet(
            Tls13SessionOrigin.Create("example.com", 443),
            [TlsCipherSuite.TlsEcdheRsaWithAes256GcmSha384]));

        using var first = cache.TryGet(
            Tls13SessionOrigin.Create("example.com", 443),
            [TlsCipherSuite.TlsEcdheRsaWithAes128GcmSha256]);
        Assert.NotNull(first);
        var copied = first.CopyMasterSecret();
        copied[0] ^= 0xFF;
        using var second = cache.TryGet(
            Tls13SessionOrigin.Create("example.com", 443),
            [TlsCipherSuite.TlsEcdheRsaWithAes128GcmSha256]);
        var secondSecret = second!.CopyMasterSecret();
        try
        {
            Assert.Equal(secret, secondSecret);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(secret);
            CryptographicOperations.ZeroMemory(copied);
            CryptographicOperations.ZeroMemory(secondSecret);
        }
    }

    [Fact]
    public void CachePurgesExpiryAndEvictsOldestWithBoundedCapacity()
    {
        var now = new DateTimeOffset(2026, 7, 18, 12, 0, 0, TimeSpan.Zero);
        var clock = new ManualTimeProvider(now);
        using var cache = new Tls12SessionCache(2, TimeSpan.FromHours(1), clock);
        var origin = Tls13SessionOrigin.Create("example.com", 443);
        cache.Add(CreateSession(origin, [1], new byte[48], now.AddMinutes(1), null));
        cache.Add(CreateSession(origin, [2], new byte[48], now.AddMinutes(2), null));
        cache.Add(CreateSession(origin, [3], new byte[48], now.AddMinutes(3), null));

        Assert.Equal(2, cache.Count);
        clock.UtcNow = now.AddMinutes(4);
        Assert.Equal(0, cache.Count);
    }

    [Fact]
    public void CacheRejectsInvalidBoundsAndSessionSecrets()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => new Tls12SessionCache(0));
        Assert.Throws<ArgumentOutOfRangeException>(() =>
            new Tls12SessionCache(1, TimeSpan.FromDays(8)));
        Assert.Throws<ArgumentOutOfRangeException>(() => new Tls12Session(
            Tls13SessionOrigin.Create("example.com", 443),
            [],
            TlsCipherSuite.TlsEcdheRsaWithAes128GcmSha256,
            null,
            NamedGroup.Secp256r1,
            new byte[48],
            DateTimeOffset.UtcNow.AddHours(1),
            null,
            null,
            [],
            null,
            []));
    }

    private static Tls12Session CreateSession(
        Tls13SessionOrigin origin,
        byte[] sessionId,
        byte[] masterSecret,
        DateTimeOffset expiresAt,
        string? alpn) => new(
            origin,
            sessionId,
            TlsCipherSuite.TlsEcdheRsaWithAes128GcmSha256,
            alpn,
            NamedGroup.Secp256r1,
            masterSecret,
            expiresAt,
            peerRecordSizeLimit: null,
            localRecordSizeLimit: null,
            peerCertificateChain: [[1, 2, 3]],
            stapledOcspResponse: [4],
            signedCertificateTimestamps: [[5]]);

    private sealed class ManualTimeProvider(DateTimeOffset value) : TimeProvider
    {
        internal DateTimeOffset UtcNow { get; set; } = value;
        public override DateTimeOffset GetUtcNow() => UtcNow;
    }
}
