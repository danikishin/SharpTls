using System.Security.Cryptography;
using SharpTls.Cryptography;
using SharpTls.Handshake;
using SharpTls.IO;
using SharpTls.Protocol;
using SharpTls.Sessions;

namespace SharpTls.Tests.Sessions;

public sealed class Tls13SessionTests
{
    [Fact]
    public void Rfc8448ResumptionPskAndBinderMatchPublishedTrace()
    {
        var suite = CipherSuiteInfo.Get(TlsCipherSuite.TlsAes128GcmSha256);
        var sharedSecret = Hex(
            "8bd4054fb55b9d63fdfbacf9f04b9f0d35e6d63f537563efd46272900f89492d");
        var helloHash = Hex(
            "860c06edc07858ee8e78f0e7428c58edd6b43f2ca3e6e95f02ed063cf0e1cad8");
        var clientFinishedHash = Hex(
            "209145a96ee8e2a122ff810047cc952684658d6049e86429426db87c54ad143d");
        byte[] psk;
        using (var schedule = new Tls13KeySchedule(suite))
        {
            schedule.DeriveHandshakeSecrets(sharedSecret, helloHash);
            schedule.DeriveMainSecret();
            schedule.DeriveApplicationTrafficSecrets(new byte[suite.HashLength]);
            schedule.DeriveResumptionMasterSecret(clientFinishedHash);
            psk = schedule.DeriveResumptionPsk([0, 0]);
        }

        try
        {
            Assert.Equal(Hex(
                "4ecd0eb6ec3b4d87f5d6028f922ca4c5851a277fd41311c9e62d2c9492e1c4f3"), psk);

            using var resumedSchedule = new Tls13KeySchedule(suite, psk);
            var binderHash = Hex(
                "63224b2e4573f2d3454ca84b9d009a04f6be9e05711a8396473aefa01e924a14");
            var binder = resumedSchedule.ComputeResumptionBinder(binderHash);
            Assert.Equal(Hex(
                "3add4fb2d8fdf822a0ca3cf7678ef5e88dae990141c5924d57bb6fa31b9e5f9d"), binder);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(psk);
        }
    }

    [Fact]
    public void Rfc8448EarlyTrafficKeysMatchPublishedTrace()
    {
        var psk = Hex(
            "4ecd0eb6ec3b4d87f5d6028f922ca4c5851a277fd41311c9e62d2c9492e1c4f3");
        using var schedule = new Tls13KeySchedule(
            CipherSuiteInfo.Get(TlsCipherSuite.TlsAes128GcmSha256),
            psk);
        schedule.DeriveClientEarlyTrafficSecret(Hex(
            "08ad0fa05d7c7233b1775ba2ff9f4c5b8b59276b7f227f13a976245f5d960913"));
        var keys = schedule.TakeClientEarlyTrafficKeys();
        try
        {
            Assert.Equal(Hex("920205a5b7bf2115e6fc5c2942834f54"), keys.Key);
            Assert.Equal(Hex("6d475f0993c8e564610db2b9"), keys.Iv);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(psk);
            CryptographicOperations.ZeroMemory(keys.Key);
            CryptographicOperations.ZeroMemory(keys.Iv);
        }
    }

    [Fact]
    public void NewSessionTicketParserReadsEarlyDataAndIgnoresUnknownExtensions()
    {
        var extensions = new TlsBinaryWriter();
        extensions.WriteUInt16(0xFEED);
        extensions.WriteVector16([1, 2, 3]);
        extensions.WriteUInt16((ushort)TlsExtensionType.EarlyData);
        extensions.WriteVector16([0, 1, 0, 0]);
        var body = BuildTicket(
            lifetime: 3600,
            ageAdd: 0xAABBCCDD,
            nonce: [4, 5],
            identity: [6, 7, 8],
            extensions.WrittenSpan);

        var parsed = Tls13NewSessionTicketParser.Parse(body);

        Assert.Equal(3600u, parsed.LifetimeSeconds);
        Assert.Equal(0xAABBCCDDu, parsed.AgeAdd);
        Assert.Equal(new byte[] { 4, 5 }, parsed.Nonce);
        Assert.Equal(new byte[] { 6, 7, 8 }, parsed.Identity);
        Assert.Equal(65536u, parsed.MaximumEarlyDataSize);
    }

    [Fact]
    public void NewSessionTicketParserRejectsEmptyTicketDuplicateAndMalformedEarlyData()
    {
        Assert.Equal(
            TlsAlertDescription.DecodeError,
            Assert.Throws<TlsProtocolException>(() =>
                Tls13NewSessionTicketParser.Parse(BuildTicket(1, 2, [], [], []))).Alert);

        var duplicate = new TlsBinaryWriter();
        duplicate.WriteUInt16((ushort)TlsExtensionType.EarlyData);
        duplicate.WriteVector16([0, 0, 0, 1]);
        duplicate.WriteUInt16((ushort)TlsExtensionType.EarlyData);
        duplicate.WriteVector16([0, 0, 0, 2]);
        Assert.Equal(
            TlsAlertDescription.IllegalParameter,
            Assert.Throws<TlsProtocolException>(() =>
                Tls13NewSessionTicketParser.Parse(
                    BuildTicket(1, 2, [], [1], duplicate.WrittenSpan))).Alert);

        var malformed = new TlsBinaryWriter();
        malformed.WriteUInt16((ushort)TlsExtensionType.EarlyData);
        malformed.WriteVector16([0, 0, 0]);
        Assert.Equal(
            TlsAlertDescription.DecodeError,
            Assert.Throws<TlsProtocolException>(() =>
                Tls13NewSessionTicketParser.Parse(
                    BuildTicket(1, 2, [], [1], malformed.WrittenSpan))).Alert);
    }

    [Fact]
    public void NewSessionTicketParserConsumesMaximumExtensionVector()
    {
        var extensions = new TlsBinaryWriter(ushort.MaxValue);
        extensions.WriteUInt16(0xFEED);
        extensions.WriteVector16(new byte[ushort.MaxValue - 4]);

        var parsed = Tls13NewSessionTicketParser.Parse(
            BuildTicket(1, 2, [], [1], extensions.WrittenSpan));

        Assert.Equal(new byte[] { 1 }, parsed.Identity);
        Assert.Null(parsed.MaximumEarlyDataSize);
    }

    [Fact]
    public void CacheIsOriginAlpnHashAndLifetimeBoundAndTicketsAreSingleUse()
    {
        var clock = new ManualTimeProvider(new DateTimeOffset(2026, 7, 17, 12, 0, 0, TimeSpan.Zero));
        using var cache = new Tls13SessionCache(4, 2, TimeSpan.FromHours(12), clock);
        var origin = Tls13SessionOrigin.Create("EXAMPLE.com.", 443);
        var ticket = CreateTicket(
            origin,
            TlsCipherSuite.TlsAes128GcmSha256,
            "http/1.1",
            [1],
            clock.GetUtcNow(),
            clock.GetUtcNow().AddHours(1),
            clock.GetUtcNow().AddHours(2));
        cache.Add(ticket);

        Assert.Null(cache.TryTake(
            Tls13SessionOrigin.Create("example.com", 8443),
            [TlsCipherSuite.TlsAes128GcmSha256],
            ["http/1.1"]));
        Assert.Null(cache.TryTake(
            origin,
            [TlsCipherSuite.TlsAes256GcmSha384],
            ["http/1.1"]));
        Assert.Null(cache.TryTake(
            origin,
            [TlsCipherSuite.TlsAes128GcmSha256],
            ["h2"]));

        var taken = cache.TryTake(
            origin,
            [TlsCipherSuite.TlsChaCha20Poly1305Sha256],
            ["h2", "http/1.1"]);
        Assert.Same(ticket, taken);
        Assert.Equal(0, cache.Count);
        Assert.Null(cache.TryTake(
            origin,
            [TlsCipherSuite.TlsAes128GcmSha256],
            ["http/1.1"]));
        taken!.Dispose();
    }

    [Fact]
    public void CacheSeparatesPlainAndExactEchConfigurationSources()
    {
        var clock = new ManualTimeProvider(
            new DateTimeOffset(2026, 7, 17, 12, 0, 0, TimeSpan.Zero));
        using var cache = new Tls13SessionCache(4, 4, TimeSpan.FromHours(1), clock);
        var origin = Tls13SessionOrigin.Create("private.example", 443);
        var firstSource = SHA256.HashData("first ECHConfigList"u8);
        var otherSource = SHA256.HashData("other ECHConfigList"u8);
        var echTicket = new Tls13SessionTicket(
            origin,
            TlsCipherSuite.TlsAes128GcmSha256,
            negotiatedAlpn: null,
            ageAdd: 0,
            identity: [1],
            psk: new byte[32],
            clock.GetUtcNow(),
            clock.GetUtcNow().AddMinutes(30),
            clock.GetUtcNow().AddMinutes(30),
            maximumEarlyDataSize: null,
            echConfigListHash: firstSource);
        var ownedBinding = echTicket.EchConfigListHash!;
        cache.Add(echTicket);

        Assert.Null(cache.TryTake(
            origin,
            [TlsCipherSuite.TlsAes128GcmSha256],
            [],
            echConfigListHash: null));
        Assert.Null(cache.TryTake(
            origin,
            [TlsCipherSuite.TlsAes128GcmSha256],
            [],
            otherSource));
        var taken = cache.TryTake(
            origin,
            [TlsCipherSuite.TlsAes128GcmSha256],
            [],
            firstSource);
        Assert.Same(echTicket, taken);
        taken!.Dispose();
        Assert.All(ownedBinding, value => Assert.Equal(0, value));

        cache.Add(CreateTicket(
            origin,
            TlsCipherSuite.TlsAes128GcmSha256,
            null,
            [2],
            clock.GetUtcNow(),
            clock.GetUtcNow().AddMinutes(30),
            clock.GetUtcNow().AddMinutes(30)));
        Assert.Null(cache.TryTake(
            origin,
            [TlsCipherSuite.TlsAes128GcmSha256],
            [],
            firstSource));
        using var plain = cache.TryTake(
            origin,
            [TlsCipherSuite.TlsAes128GcmSha256],
            []);
        Assert.NotNull(plain);
    }

    [Fact]
    public void CacheRequiresExactTicketBoundApplicationSettings()
    {
        var clock = new ManualTimeProvider(
            new DateTimeOffset(2026, 7, 18, 12, 0, 0, TimeSpan.Zero));
        using var cache = new Tls13SessionCache(4, 4, TimeSpan.FromHours(1), clock);
        var origin = Tls13SessionOrigin.Create("example.com", 443);
        var ticket = new Tls13SessionTicket(
            origin,
            TlsCipherSuite.TlsAes128GcmSha256,
            "h2",
            ageAdd: 0,
            identity: [1],
            psk: new byte[32],
            clock.GetUtcNow(),
            clock.GetUtcNow().AddMinutes(30),
            clock.GetUtcNow().AddMinutes(30),
            maximumEarlyDataSize: 1024,
            applicationSettingsCodePoint: TlsApplicationSettingsCodePoint.LegacyDraft,
            peerApplicationSettings: [1, 2],
            clientApplicationSettings: [3, 4]);
        cache.Add(ticket);

        Assert.Null(cache.TryTake(
            origin,
            [TlsCipherSuite.TlsAes128GcmSha256],
            ["h2"]));
        Assert.Null(cache.TryTake(
            origin,
            [TlsCipherSuite.TlsAes128GcmSha256],
            ["h2"],
            applicationSettingsCodePoint: TlsApplicationSettingsCodePoint.ChromeExperiment,
            clientApplicationSettings: new Dictionary<string, byte[]> { ["h2"] = [3, 4] }));
        Assert.Null(cache.TryTake(
            origin,
            [TlsCipherSuite.TlsAes128GcmSha256],
            ["h2"],
            applicationSettingsCodePoint: TlsApplicationSettingsCodePoint.LegacyDraft,
            clientApplicationSettings: new Dictionary<string, byte[]> { ["h2"] = [3, 5] }));

        using var taken = cache.TryTake(
            origin,
            [TlsCipherSuite.TlsChaCha20Poly1305Sha256],
            ["h2"],
            applicationSettingsCodePoint: TlsApplicationSettingsCodePoint.LegacyDraft,
            clientApplicationSettings: new Dictionary<string, byte[]> { ["h2"] = [3, 4] });
        Assert.Same(ticket, taken);
    }

    [Fact]
    public void CacheTakesBoundedMatchingTicketSetInPreferenceOrder()
    {
        var clock = new ManualTimeProvider(
            new DateTimeOffset(2026, 7, 18, 12, 0, 0, TimeSpan.Zero));
        using var cache = new Tls13SessionCache(8, 8, TimeSpan.FromHours(1), clock);
        var origin = Tls13SessionOrigin.Create("example.com", 443);
        for (byte identity = 1; identity <= 3; identity++)
        {
            cache.Add(CreateTicket(
                origin,
                TlsCipherSuite.TlsAes128GcmSha256,
                null,
                [identity],
                clock.GetUtcNow(),
                clock.GetUtcNow().AddMinutes(30),
                clock.GetUtcNow().AddMinutes(30)));
        }

        var taken = cache.TryTakeMany(
            origin,
            [TlsCipherSuite.TlsAes128GcmSha256],
            [],
            maximumCount: 2);
        try
        {
            Assert.Equal(2, taken.Count);
            Assert.Equal(new byte[] { 3 }, taken[0].Identity);
            Assert.Equal(new byte[] { 2 }, taken[1].Identity);
            Assert.Equal(1, cache.Count);
        }
        finally
        {
            foreach (var ticket in taken)
            {
                ticket.Dispose();
            }
        }

        using var remaining = cache.TryTake(
            origin,
            [TlsCipherSuite.TlsAes128GcmSha256],
            []);
        Assert.Equal(new byte[] { 1 }, remaining!.Identity);
    }

    [Fact]
    public void CacheEvictionExpirationAndDisposeZeroizeOwnedTicketState()
    {
        var clock = new ManualTimeProvider(new DateTimeOffset(2026, 7, 17, 12, 0, 0, TimeSpan.Zero));
        using var cache = new Tls13SessionCache(2, 1, TimeSpan.FromHours(1), clock);
        var origin = Tls13SessionOrigin.Create("example.com", 443);
        var first = CreateTicket(
            origin,
            TlsCipherSuite.TlsAes128GcmSha256,
            null,
            [1, 2],
            clock.GetUtcNow(),
            clock.GetUtcNow().AddMinutes(10),
            clock.GetUtcNow().AddHours(1));
        var firstIdentity = first.Identity;
        cache.Add(first);
        cache.Add(CreateTicket(
            origin,
            TlsCipherSuite.TlsAes128GcmSha256,
            null,
            [3, 4],
            clock.GetUtcNow(),
            clock.GetUtcNow().AddMinutes(10),
            clock.GetUtcNow().AddHours(1)));

        Assert.Equal(new byte[] { 0, 0 }, firstIdentity);
        Assert.Throws<ObjectDisposedException>(() => first.CopyPsk());
        Assert.Equal(1, cache.Count);

        clock.Advance(TimeSpan.FromMinutes(11));
        Assert.Equal(0, cache.Count);
    }

    [Fact]
    public void EncryptedPersistentStateRoundTripsEverySecurityBindingAcrossKeyRotation()
    {
        var now = new DateTimeOffset(2026, 7, 18, 12, 0, 0, TimeSpan.Zero);
        var clock = new ManualTimeProvider(now);
        var origin = Tls13SessionOrigin.Create("Private.Example.", 443);
        var identity = Convert.FromHexString("0102030405060708");
        var psk = Enumerable.Repeat((byte)0xA5, 32).ToArray();
        var echBinding = SHA256.HashData("ECHConfigList"u8);
        var peerApplicationSettings = new byte[] { 1, 2, 3 };
        var clientApplicationSettings = new byte[] { 4, 5, 6 };
        using var source = new Tls13SessionCache(4, 4, TimeSpan.FromDays(2), clock);
        source.Add(new Tls13SessionTicket(
            origin,
            TlsCipherSuite.TlsAes128GcmSha256,
            "http/1.1",
            0xAABBCCDD,
            identity,
            psk,
            now,
            now.AddHours(2),
            now.AddDays(1),
            maximumEarlyDataSize: 16384,
            peerRecordSizeLimit: 1200,
            echConfigListHash: echBinding,
            applicationSettingsCodePoint: TlsApplicationSettingsCodePoint.LegacyDraft,
            peerApplicationSettings: peerApplicationSettings,
            clientApplicationSettings: clientApplicationSettings));

        var oldKey = Enumerable.Repeat((byte)0x11, 32).ToArray();
        var newKey = Enumerable.Repeat((byte)0x22, 32).ToArray();
        using var oldProtector = new Tls13SessionStateProtector("2026-07", oldKey);
        var protectedState = source.ExportEncrypted(oldProtector);

        Assert.Equal("STSC", System.Text.Encoding.ASCII.GetString(protectedState, 0, 4));
        Assert.False(ContainsSequence(protectedState, psk));
        Assert.False(ContainsSequence(protectedState, identity));

        using var rotatedProtector = new Tls13SessionStateProtector("2026-08", newKey);
        rotatedProtector.AddDecryptionKey("2026-07", oldKey);
        using var destination = new Tls13SessionCache(4, 4, TimeSpan.FromDays(2), clock);
        destination.ImportEncrypted(protectedState, rotatedProtector);

        Assert.Equal(1, destination.Count);
        using var restored = destination.TryTake(
            origin,
            [TlsCipherSuite.TlsChaCha20Poly1305Sha256],
            ["http/1.1"],
            echBinding,
            TlsApplicationSettingsCodePoint.LegacyDraft,
            new Dictionary<string, byte[]>
            {
                ["http/1.1"] = clientApplicationSettings,
            });
        Assert.NotNull(restored);
        Assert.Equal(0xAABBCCDDu, restored.AgeAdd);
        Assert.Equal(now, restored.IssuedAt);
        Assert.Equal(now.AddHours(2), restored.ExpiresAt);
        Assert.Equal(now.AddDays(1), restored.AuthenticationExpiresAt);
        Assert.Equal(16384u, restored.MaximumEarlyDataSize);
        Assert.Equal(1200, restored.PeerRecordSizeLimit);
        Assert.Equal(
            TlsApplicationSettingsCodePoint.LegacyDraft,
            restored.ApplicationSettingsCodePoint);
        Assert.Equal(peerApplicationSettings, restored.PeerApplicationSettings);
        Assert.Equal(clientApplicationSettings, restored.ClientApplicationSettings);
        Assert.Equal(psk, restored.CopyPsk());

        Assert.True(rotatedProtector.RemoveDecryptionKey("2026-07"));
        Assert.Throws<CryptographicException>(() =>
            destination.ImportEncrypted(protectedState, rotatedProtector));
    }

    [Fact]
    public void PersistentStateRejectsTamperingWrongKeysTruncationAndOversizeWithoutMutation()
    {
        var now = new DateTimeOffset(2026, 7, 18, 12, 0, 0, TimeSpan.Zero);
        var clock = new ManualTimeProvider(now);
        var origin = Tls13SessionOrigin.Create("example.com", 443);
        using var source = new Tls13SessionCache(4, 4, TimeSpan.FromHours(1), clock);
        source.Add(CreateTicket(
            origin,
            TlsCipherSuite.TlsAes128GcmSha256,
            null,
            [1, 2, 3],
            now,
            now.AddMinutes(30),
            now.AddHours(1)));
        var key = Enumerable.Repeat((byte)0x33, 32).ToArray();
        using var protector = new Tls13SessionStateProtector("key", key);
        var protectedState = source.ExportEncrypted(protector);

        using var destination = new Tls13SessionCache(4, 4, TimeSpan.FromHours(1), clock);
        destination.Add(CreateTicket(
            origin,
            TlsCipherSuite.TlsAes128GcmSha256,
            null,
            [9],
            now,
            now.AddMinutes(30),
            now.AddHours(1)));
        var tampered = (byte[])protectedState.Clone();
        tampered[^1] ^= 1;
        Assert.ThrowsAny<CryptographicException>(() =>
            destination.ImportEncrypted(tampered, protector));
        Assert.Equal(1, destination.Count);

        using var wrongProtector = new Tls13SessionStateProtector(
            "key",
            Enumerable.Repeat((byte)0x44, 32).ToArray());
        Assert.ThrowsAny<CryptographicException>(() =>
            destination.ImportEncrypted(protectedState, wrongProtector));
        Assert.Throws<InvalidDataException>(() =>
            destination.ImportEncrypted(protectedState.AsSpan(0, 10), protector));
        Assert.Equal(1, destination.Count);

        using var smallProtector = new Tls13SessionStateProtector("small", key, 256);
        using var largeSource = new Tls13SessionCache(1, 1, TimeSpan.FromHours(1), clock);
        largeSource.Add(CreateTicket(
            origin,
            TlsCipherSuite.TlsAes128GcmSha256,
            null,
            Enumerable.Repeat((byte)7, 300).ToArray(),
            now,
            now.AddMinutes(30),
            now.AddHours(1)));
        Assert.Throws<InvalidOperationException>(() => largeSource.ExportEncrypted(smallProtector));
    }

    [Fact]
    public void DecryptedPersistentStateImportIsAtomicAndDropsExpiredTickets()
    {
        var now = new DateTimeOffset(2026, 7, 18, 12, 0, 0, TimeSpan.Zero);
        var clock = new ManualTimeProvider(now);
        var origin = Tls13SessionOrigin.Create("example.com", 443);
        using var source = new Tls13SessionCache(4, 4, TimeSpan.FromHours(1), clock);
        source.Add(CreateTicket(
            origin,
            TlsCipherSuite.TlsAes128GcmSha256,
            null,
            [1],
            now,
            now.AddMinutes(1),
            now.AddHours(1)));
        var plaintext = source.ExportStatePlaintext(4096);
        try
        {
            using var destination = new Tls13SessionCache(4, 4, TimeSpan.FromHours(1), clock);
            destination.Add(CreateTicket(
                origin,
                TlsCipherSuite.TlsAes128GcmSha256,
                null,
                [9],
                now,
                now.AddMinutes(30),
                now.AddHours(1)));

            var malformed = (byte[])plaintext.Clone();
            malformed[5] = 0;
            malformed[6] = 2;
            Assert.Throws<InvalidDataException>(() => destination.ImportStatePlaintext(malformed));
            Assert.Equal(1, destination.Count);

            clock.Advance(TimeSpan.FromMinutes(2));
            destination.ImportStatePlaintext(plaintext);
            Assert.Equal(1, destination.Count);
            using var remaining = destination.TryTake(
                origin,
                [TlsCipherSuite.TlsAes128GcmSha256],
                []);
            Assert.NotNull(remaining);
            Assert.Equal(new byte[] { 9 }, remaining.Identity);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(plaintext);
        }
    }

    [Fact]
    public void PersistentStateProtectorValidatesKeyManagementAndLifetime()
    {
        Assert.Throws<ArgumentException>(() =>
            new Tls13SessionStateProtector("key", new byte[31]));
        Assert.Throws<ArgumentException>(() =>
            new Tls13SessionStateProtector("bad key\n", new byte[32]));
        Assert.Throws<ArgumentOutOfRangeException>(() =>
            new Tls13SessionStateProtector("key", new byte[32], 255));

        using var protector = new Tls13SessionStateProtector("current", new byte[32]);
        Assert.Throws<ArgumentException>(() =>
            protector.AddDecryptionKey("current", new byte[32]));
        Assert.Throws<InvalidOperationException>(() =>
            protector.RemoveDecryptionKey("current"));
        Assert.False(protector.RemoveDecryptionKey("missing"));

        protector.Dispose();
        Assert.Throws<ObjectDisposedException>(() =>
            protector.AddDecryptionKey("old", new byte[32]));
    }

    [Fact]
    public async Task CacheConcurrentAddAndTakePreservesSingleUseOwnership()
    {
        const int ticketCount = 32;
        var clock = new ManualTimeProvider(
            new DateTimeOffset(2026, 7, 17, 12, 0, 0, TimeSpan.Zero));
        using var cache = new Tls13SessionCache(
            ticketCount,
            ticketCount,
            TimeSpan.FromHours(1),
            clock);
        var origin = Tls13SessionOrigin.Create("example.com", 443);

        await Task.WhenAll(Enumerable.Range(0, ticketCount).Select(index => Task.Run(() =>
            cache.Add(CreateTicket(
                origin,
                TlsCipherSuite.TlsAes128GcmSha256,
                null,
                [(byte)(index + 1)],
                clock.GetUtcNow(),
                clock.GetUtcNow().AddMinutes(30),
                clock.GetUtcNow().AddHours(1))))));

        var taken = await Task.WhenAll(Enumerable.Range(0, ticketCount).Select(_ => Task.Run(() =>
            cache.TryTake(
                origin,
                [TlsCipherSuite.TlsAes128GcmSha256],
                []))));
        try
        {
            Assert.All(taken, Assert.NotNull);
            Assert.Equal(
                ticketCount,
                taken.Select(ticket => Convert.ToHexString(ticket!.Identity)).Distinct().Count());
            Assert.Equal(0, cache.Count);
        }
        finally
        {
            foreach (var ticket in taken)
            {
                ticket?.Dispose();
            }
        }
    }

    [Fact]
    public void ObfuscatedAgeUsesMillisecondsModuloUint32()
    {
        var issued = new DateTimeOffset(2026, 7, 17, 12, 0, 0, TimeSpan.Zero);
        using var ticket = CreateTicket(
            Tls13SessionOrigin.Create("example.com", 443),
            TlsCipherSuite.TlsAes128GcmSha256,
            null,
            [1],
            issued,
            issued.AddHours(1),
            issued.AddHours(1),
            ageAdd: uint.MaxValue - 499);

        Assert.Equal(500u, ticket.GetObfuscatedAge(issued.AddSeconds(1)));
        Assert.Equal(uint.MaxValue - 499, ticket.GetObfuscatedAge(issued.AddSeconds(-1)));
    }

    [Fact]
    public void ClientHelloPskExtensionIsLastAndBinderCoversTruncatedHello()
    {
        var now = new DateTimeOffset(2026, 7, 17, 12, 0, 1, TimeSpan.Zero);
        using var ticket = CreateTicket(
            Tls13SessionOrigin.Create("example.com", 443),
            TlsCipherSuite.TlsAes128GcmSha256,
            null,
            [9, 8, 7],
            now.AddSeconds(-1),
            now.AddHours(1),
            now.AddHours(1),
            ageAdd: 100);
        var spec = ClientHelloProfiles.Custom(builder => builder
            .WithTls13()
            .WithCipherSuites(TlsCipherSuite.TlsAes128GcmSha256)
            .WithSupportedGroups(NamedGroup.Secp256r1)
            .WithKeyShares(NamedGroup.Secp256r1)
            .WithSessionResumption()).Spec;
        using var random = new DeterministicRandomSource([1, 2, 3]);
        using var encoded = ClientHelloEncoder.Build(
            "example.com",
            spec.SnapshotConfiguration(),
            random,
            new KeyShareSet(KeyShareFactory.CreateDeterministicForTesting),
            retry: null,
            pskOffer: new Tls13PskOffer(ticket, now));

        var extensions = ReadExtensions(encoded.EncodedHandshake);
        Assert.Equal((ushort)TlsExtensionType.PreSharedKey, extensions[^1].Type);
        Assert.Equal(
            new byte[] { 1, 1 },
            Assert.Single(extensions, extension =>
                extension.Type == (ushort)TlsExtensionType.PskKeyExchangeModes).Data);

        var psk = new TlsBinaryReader(extensions[^1].Data);
        var identities = new TlsBinaryReader(psk.ReadVector16());
        Assert.Equal(new byte[] { 9, 8, 7 }, identities.ReadVector16().ToArray());
        Assert.Equal(1100u, identities.ReadUInt32());
        identities.EnsureEnd("PSK identities");
        var binders = new TlsBinaryReader(psk.ReadVector16());
        var actualBinder = binders.ReadVector8().ToArray();
        binders.EnsureEnd("PSK binders");
        psk.EnsureEnd("pre_shared_key");

        var truncatedLength = encoded.EncodedHandshake.Length - (2 + 1 + 32);
        var binderHash = SHA256.HashData(encoded.EncodedHandshake.AsSpan(0, truncatedLength));
        var ticketPsk = ticket.CopyPsk();
        try
        {
            using var schedule = new Tls13KeySchedule(
                CipherSuiteInfo.Get(TlsCipherSuite.TlsAes128GcmSha256),
                ticketPsk);
            Assert.Equal(schedule.ComputeResumptionBinder(binderHash), actualBinder);
            Assert.Contains(actualBinder, value => value != 0);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(ticketPsk);
            CryptographicOperations.ZeroMemory(binderHash);
        }
    }

    [Fact]
    public void ClientHelloEncodesAndAuthenticatesMultipleHashSpecificPskBinders()
    {
        var now = new DateTimeOffset(2026, 7, 18, 12, 0, 0, TimeSpan.Zero);
        using var sha256Ticket = new Tls13SessionTicket(
            Tls13SessionOrigin.Create("example.com", 443),
            TlsCipherSuite.TlsAes128GcmSha256,
            negotiatedAlpn: null,
            ageAdd: 10,
            identity: [1, 2, 3],
            psk: Enumerable.Repeat((byte)0x11, 32).ToArray(),
            now,
            now.AddHours(1),
            now.AddHours(1),
            maximumEarlyDataSize: null);
        using var sha384Ticket = new Tls13SessionTicket(
            Tls13SessionOrigin.Create("example.com", 443),
            TlsCipherSuite.TlsAes256GcmSha384,
            negotiatedAlpn: null,
            ageAdd: 20,
            identity: [4, 5, 6, 7],
            psk: Enumerable.Repeat((byte)0x22, 48).ToArray(),
            now,
            now.AddHours(1),
            now.AddHours(1),
            maximumEarlyDataSize: null);
        var configuration = ClientHelloProfiles.Custom(builder => builder
            .WithTls13()
            .WithCipherSuites(
                TlsCipherSuite.TlsAes128GcmSha256,
                TlsCipherSuite.TlsAes256GcmSha384)
            .WithSupportedGroups(NamedGroup.Secp256r1)
            .WithKeyShares(NamedGroup.Secp256r1)
            .WithSessionResumption()).Spec.SnapshotConfiguration();
        using var random = new DeterministicRandomSource([7, 8, 9]);
        using var hello = ClientHelloEncoder.Build(
            "example.com",
            configuration,
            random,
            new KeyShareSet(KeyShareFactory.CreateDeterministicForTesting),
            retry: null,
            pskOffer: new Tls13PskOffer([sha256Ticket, sha384Ticket], now));

        Assert.Equal(2, hello.OfferedPskCount);
        var extension = Assert.Single(
            ReadExtensions(hello.EncodedHandshake),
            item => item.Type == (ushort)TlsExtensionType.PreSharedKey);
        var pskReader = new TlsBinaryReader(extension.Data);
        var identities = new TlsBinaryReader(pskReader.ReadVector16());
        Assert.Equal(new byte[] { 1, 2, 3 }, identities.ReadVector16().ToArray());
        Assert.Equal(10u, identities.ReadUInt32());
        Assert.Equal(new byte[] { 4, 5, 6, 7 }, identities.ReadVector16().ToArray());
        Assert.Equal(20u, identities.ReadUInt32());
        identities.EnsureEnd("multi PSK identities");
        var binders = new TlsBinaryReader(pskReader.ReadVector16());
        var actualSha256Binder = binders.ReadVector8().ToArray();
        var actualSha384Binder = binders.ReadVector8().ToArray();
        binders.EnsureEnd("multi PSK binders");
        pskReader.EnsureEnd("multi pre_shared_key");

        var encodedBinderBlockLength = 2 + 1 + 32 + 1 + 48;
        var truncated = hello.EncodedHandshake.AsSpan(
            0,
            hello.EncodedHandshake.Length - encodedBinderBlockLength);
        var sha256Hash = SHA256.HashData(truncated);
        var sha384Hash = SHA384.HashData(truncated);
        var sha256Psk = sha256Ticket.CopyPsk();
        var sha384Psk = sha384Ticket.CopyPsk();
        try
        {
            using var sha256Schedule = new Tls13KeySchedule(
                CipherSuiteInfo.Get(TlsCipherSuite.TlsAes128GcmSha256),
                sha256Psk);
            using var sha384Schedule = new Tls13KeySchedule(
                CipherSuiteInfo.Get(TlsCipherSuite.TlsAes256GcmSha384),
                sha384Psk);
            Assert.Equal(
                sha256Schedule.ComputeResumptionBinder(sha256Hash),
                actualSha256Binder);
            Assert.Equal(
                sha384Schedule.ComputeResumptionBinder(sha384Hash),
                actualSha384Binder);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(sha256Hash);
            CryptographicOperations.ZeroMemory(sha384Hash);
            CryptographicOperations.ZeroMemory(sha256Psk);
            CryptographicOperations.ZeroMemory(sha384Psk);
        }
    }

    [Fact]
    public void ConditionalPskSlotIsAbsentWithoutTicketButModesRemainAdvertised()
    {
        var encoded = ClientHelloProfiles.ModernTls13.BuildDeterministicForTesting(
            "example.com",
            [9, 9, 9]);
        var types = ReadExtensions(encoded).Select(extension => extension.Type).ToArray();

        Assert.Contains((ushort)TlsExtensionType.PskKeyExchangeModes, types);
        Assert.DoesNotContain((ushort)TlsExtensionType.PreSharedKey, types);
        Assert.True(ClientHelloProfiles.ModernTls13.Spec.SupportsSessionResumption);
        Assert.True(ClientHelloProfiles.ModernTls13.Spec.SupportsEarlyData);
    }

    [Fact]
    public void EarlyDataIndicationIsEmptyAndImmediatelyPrecedesFinalPsk()
    {
        var now = new DateTimeOffset(2026, 7, 17, 12, 0, 0, TimeSpan.Zero);
        using var ticket = CreateTicket(
            Tls13SessionOrigin.Create("example.com", 443),
            TlsCipherSuite.TlsAes128GcmSha256,
            null,
            [1],
            now,
            now.AddHours(1),
            now.AddHours(1));
        using var offer = ClientHelloProfiles.ModernTls13.BuildSecure(
            "example.com",
            new Tls13PskOffer(ticket, now, OfferEarlyData: true));
        var extensions = ReadExtensions(offer.EncodedHandshake);

        Assert.Equal((ushort)TlsExtensionType.EarlyData, extensions[^2].Type);
        Assert.Empty(extensions[^2].Data);
        Assert.Equal((ushort)TlsExtensionType.PreSharedKey, extensions[^1].Type);
    }

    [Fact]
    public void ResumptionLayoutMustHaveDheModeAndFinalPskSlot()
    {
        Assert.Throws<ArgumentException>(() => ClientHelloProfiles.Custom(builder => builder
            .WithExtensionLayout(
                ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.ServerName),
                ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.SupportedVersions),
                ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.SupportedGroups),
                ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.SignatureAlgorithms),
                ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.KeyShare),
                ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.PreSharedKey))));

        Assert.Throws<ArgumentException>(() => ClientHelloProfiles.Custom(builder => builder
            .WithSessionResumption()
            .WithExtensionOrder(
                ClientHelloExtensionKind.ServerName,
                ClientHelloExtensionKind.SupportedVersions,
                ClientHelloExtensionKind.SupportedGroups,
                ClientHelloExtensionKind.SignatureAlgorithms,
                ClientHelloExtensionKind.KeyShare,
                ClientHelloExtensionKind.PreSharedKey,
                ClientHelloExtensionKind.PskKeyExchangeModes)));
    }

    [Fact]
    public void HelloRetryRequestBinderIncludesSyntheticFirstHelloAndRetry()
    {
        var now = new DateTimeOffset(2026, 7, 17, 12, 0, 0, TimeSpan.Zero);
        using var ticket = CreateTicket(
            Tls13SessionOrigin.Create("example.com", 443),
            TlsCipherSuite.TlsAes128GcmSha256,
            null,
            [1, 2, 3],
            now.AddSeconds(-1),
            now.AddHours(1),
            now.AddHours(1));
        var configuration = ClientHelloProfiles.Custom(builder => builder
            .WithTls13()
            .WithCipherSuites(TlsCipherSuite.TlsAes128GcmSha256)
            .WithSupportedGroups(NamedGroup.Secp256r1)
            .WithKeyShares()
            .WithSessionResumption()).Spec.SnapshotConfiguration();
        using var random = new DeterministicRandomSource([4, 5, 6]);
        using var first = ClientHelloEncoder.Build(
            "example.com",
            configuration,
            random,
            new KeyShareSet(KeyShareFactory.CreateDeterministicForTesting),
            retry: null,
            pskOffer: new Tls13PskOffer(ticket, now));
        var retry = HandshakeMessage.Encode(HandshakeType.ServerHello, [7, 8, 9]);
        var firstHash = SHA256.HashData(first.EncodedHandshake);
        var messageHash = HandshakeMessage.Encode(HandshakeType.MessageHash, firstHash);
        byte[] prefix = [.. messageHash, .. retry];
        using var second = ClientHelloEncoder.BuildRetry(
            first,
            NamedGroup.Secp256r1,
            cookie: [10],
            pskOffer: new Tls13PskOffer(ticket, now.AddMilliseconds(25), prefix));

        var truncatedLength = second.EncodedHandshake.Length - (2 + 1 + 32);
        using var incremental = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        incremental.AppendData(prefix);
        incremental.AppendData(second.EncodedHandshake.AsSpan(0, truncatedLength));
        var binderHash = incremental.GetHashAndReset();
        var psk = ticket.CopyPsk();
        try
        {
            using var schedule = new Tls13KeySchedule(
                CipherSuiteInfo.Get(TlsCipherSuite.TlsAes128GcmSha256),
                psk);
            var expected = schedule.ComputeResumptionBinder(binderHash);
            var extension = Assert.Single(ReadExtensions(second.EncodedHandshake), item =>
                item.Type == (ushort)TlsExtensionType.PreSharedKey);
            var body = new TlsBinaryReader(extension.Data);
            _ = body.ReadVector16();
            var binders = new TlsBinaryReader(body.ReadVector16());
            Assert.Equal(expected, binders.ReadVector8().ToArray());
        }
        finally
        {
            CryptographicOperations.ZeroMemory(firstHash);
            CryptographicOperations.ZeroMemory(binderHash);
            CryptographicOperations.ZeroMemory(psk);
        }
    }

    [Fact]
    public void HelloRetryRequestComputesSeparatePrefixesForMultiplePskHashes()
    {
        var now = new DateTimeOffset(2026, 7, 18, 12, 0, 0, TimeSpan.Zero);
        using var sha256Ticket = new Tls13SessionTicket(
            Tls13SessionOrigin.Create("example.com", 443),
            TlsCipherSuite.TlsAes128GcmSha256,
            negotiatedAlpn: null,
            ageAdd: 0,
            identity: [1],
            psk: Enumerable.Repeat((byte)0x31, 32).ToArray(),
            now,
            now.AddHours(1),
            now.AddHours(1),
            maximumEarlyDataSize: null);
        using var sha384Ticket = new Tls13SessionTicket(
            Tls13SessionOrigin.Create("example.com", 443),
            TlsCipherSuite.TlsAes256GcmSha384,
            negotiatedAlpn: null,
            ageAdd: 0,
            identity: [2],
            psk: Enumerable.Repeat((byte)0x32, 48).ToArray(),
            now,
            now.AddHours(1),
            now.AddHours(1),
            maximumEarlyDataSize: null);
        var configuration = ClientHelloProfiles.Custom(builder => builder
            .WithTls13()
            .WithCipherSuites(
                TlsCipherSuite.TlsAes128GcmSha256,
                TlsCipherSuite.TlsAes256GcmSha384)
            .WithSupportedGroups(NamedGroup.Secp256r1)
            .WithKeyShares()
            .WithSessionResumption()).Spec.SnapshotConfiguration();
        using var firstRandom = new DeterministicRandomSource([1, 2, 3]);
        using var first = ClientHelloEncoder.Build(
            "example.com",
            configuration,
            firstRandom,
            new KeyShareSet(KeyShareFactory.CreateDeterministicForTesting),
            retry: null,
            pskOffer: new Tls13PskOffer([sha256Ticket, sha384Ticket], now));
        var retry = HandshakeMessage.Encode(HandshakeType.ServerHello, [9, 8, 7]);
        var sha256FirstHash = SHA256.HashData(first.EncodedHandshake);
        var sha384FirstHash = SHA384.HashData(first.EncodedHandshake);
        var sha256MessageHash = HandshakeMessage.Encode(
            HandshakeType.MessageHash,
            sha256FirstHash);
        var sha384MessageHash = HandshakeMessage.Encode(
            HandshakeType.MessageHash,
            sha384FirstHash);
        byte[] sha256Prefix = [.. sha256MessageHash, .. retry];
        byte[] sha384Prefix = [.. sha384MessageHash, .. retry];
        using var second = ClientHelloEncoder.BuildRetry(
            first,
            NamedGroup.Secp256r1,
            cookie: null,
            new Tls13PskOffer(
                [sha256Ticket, sha384Ticket],
                now,
                [sha256Prefix, sha384Prefix]));

        var extension = Assert.Single(
            ReadExtensions(second.EncodedHandshake),
            item => item.Type == (ushort)TlsExtensionType.PreSharedKey);
        var pskReader = new TlsBinaryReader(extension.Data);
        _ = pskReader.ReadVector16();
        var binders = new TlsBinaryReader(pskReader.ReadVector16());
        var sha256Binder = binders.ReadVector8().ToArray();
        var sha384Binder = binders.ReadVector8().ToArray();
        binders.EnsureEnd("HRR multi binders");
        pskReader.EnsureEnd("HRR multi PSK");
        var binderBlockLength = 2 + 1 + 32 + 1 + 48;
        var truncatedSecond = second.EncodedHandshake.AsSpan(
            0,
            second.EncodedHandshake.Length - binderBlockLength);
        var sha256TranscriptHash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        var sha384TranscriptHash = IncrementalHash.CreateHash(HashAlgorithmName.SHA384);
        var sha256Psk = sha256Ticket.CopyPsk();
        var sha384Psk = sha384Ticket.CopyPsk();
        try
        {
            sha256TranscriptHash.AppendData(sha256Prefix);
            sha256TranscriptHash.AppendData(truncatedSecond);
            sha384TranscriptHash.AppendData(sha384Prefix);
            sha384TranscriptHash.AppendData(truncatedSecond);
            var expectedSha256Hash = sha256TranscriptHash.GetHashAndReset();
            var expectedSha384Hash = sha384TranscriptHash.GetHashAndReset();
            try
            {
                using var sha256Schedule = new Tls13KeySchedule(
                    CipherSuiteInfo.Get(TlsCipherSuite.TlsAes128GcmSha256),
                    sha256Psk);
                using var sha384Schedule = new Tls13KeySchedule(
                    CipherSuiteInfo.Get(TlsCipherSuite.TlsAes256GcmSha384),
                    sha384Psk);
                Assert.Equal(
                    sha256Schedule.ComputeResumptionBinder(expectedSha256Hash),
                    sha256Binder);
                Assert.Equal(
                    sha384Schedule.ComputeResumptionBinder(expectedSha384Hash),
                    sha384Binder);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(expectedSha256Hash);
                CryptographicOperations.ZeroMemory(expectedSha384Hash);
            }
        }
        finally
        {
            sha256TranscriptHash.Dispose();
            sha384TranscriptHash.Dispose();
            CryptographicOperations.ZeroMemory(sha256FirstHash);
            CryptographicOperations.ZeroMemory(sha384FirstHash);
            CryptographicOperations.ZeroMemory(sha256MessageHash);
            CryptographicOperations.ZeroMemory(sha384MessageHash);
            CryptographicOperations.ZeroMemory(sha256Prefix);
            CryptographicOperations.ZeroMemory(sha384Prefix);
            CryptographicOperations.ZeroMemory(sha256Psk);
            CryptographicOperations.ZeroMemory(sha384Psk);
        }
    }

    private static Tls13SessionTicket CreateTicket(
        Tls13SessionOrigin origin,
        TlsCipherSuite suite,
        string? alpn,
        byte[] identity,
        DateTimeOffset issued,
        DateTimeOffset expires,
        DateTimeOffset authenticationExpires,
        uint ageAdd = 0) => new(
            origin,
            suite,
            alpn,
            ageAdd,
            identity,
            new byte[CipherSuiteInfo.Get(suite).HashLength],
            issued,
            expires,
            authenticationExpires,
            maximumEarlyDataSize: null);

    private static byte[] BuildTicket(
        uint lifetime,
        uint ageAdd,
        ReadOnlySpan<byte> nonce,
        ReadOnlySpan<byte> identity,
        ReadOnlySpan<byte> extensions)
    {
        var body = new TlsBinaryWriter();
        body.WriteUInt32(lifetime);
        body.WriteUInt32(ageAdd);
        body.WriteVector8(nonce);
        body.WriteVector16(identity);
        body.WriteVector16(extensions);
        return body.ToArray();
    }

    private static byte[] Hex(string value) => Convert.FromHexString(value);

    private static bool ContainsSequence(ReadOnlySpan<byte> haystack, ReadOnlySpan<byte> needle)
    {
        if (needle.IsEmpty)
        {
            return true;
        }
        for (var index = 0; index <= haystack.Length - needle.Length; index++)
        {
            if (haystack.Slice(index, needle.Length).SequenceEqual(needle))
            {
                return true;
            }
        }
        return false;
    }

    private static List<(ushort Type, byte[] Data)> ReadExtensions(byte[] encoded)
    {
        var handshake = new TlsBinaryReader(encoded);
        Assert.Equal((byte)HandshakeType.ClientHello, handshake.ReadUInt8());
        var body = new TlsBinaryReader(handshake.ReadBytes(handshake.ReadUInt24()));
        _ = body.ReadUInt16();
        _ = body.ReadBytes(32);
        _ = body.ReadVector8();
        _ = body.ReadVector16();
        _ = body.ReadVector8();
        var extensionReader = new TlsBinaryReader(body.ReadVector16());
        var extensions = new List<(ushort Type, byte[] Data)>();
        while (!extensionReader.End)
        {
            extensions.Add((extensionReader.ReadUInt16(), extensionReader.ReadVector16().ToArray()));
        }
        return extensions;
    }

    private sealed class ManualTimeProvider(DateTimeOffset value) : TimeProvider
    {
        private DateTimeOffset _value = value;

        public override DateTimeOffset GetUtcNow() => _value;

        internal void Advance(TimeSpan duration) => _value += duration;
    }
}
