using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography.X509Certificates;
using SharpTls.Protocol;

namespace SharpTls.Tests.ClientHello;

public sealed class ClientHelloProfileRollerTests
{
    [Fact]
    public void CacheIsOriginBoundAndLeastRecentlyUsed()
    {
        var roller = new ClientHelloProfileRoller(new ClientHelloRollerOptions
        {
            CacheCapacity = 2,
        });
        var first = CreateProfile(1);
        var second = CreateProfile(2);
        var third = CreateProfile(3);
        roller.StoreCachedForTesting("first", first);
        roller.StoreCachedForTesting("second", second);

        Assert.True(roller.TryGetCachedForTesting("first", out var cached));
        Assert.Same(first, cached);
        roller.StoreCachedForTesting("third", third);

        Assert.False(roller.TryGetCachedForTesting("second", out _));
        Assert.True(roller.TryGetCachedForTesting("first", out _));
        Assert.True(roller.TryGetCachedForTesting("third", out _));
        Assert.Equal(2, roller.CachedOriginCount);
    }

    [Fact]
    public void OnlyExplicitPeerNegotiationAlertsAreRetryable()
    {
        var retryable = new TlsProtocolException(
            TlsAlertDescription.HandshakeFailure,
            "peer rejected profile",
            innerException: null,
            isPeerAlert: true);
        var certificateFailure = new TlsProtocolException(
            TlsAlertDescription.BadCertificate,
            "bad certificate",
            innerException: null,
            isPeerAlert: true);
        var localFailure = new TlsProtocolException(
            TlsAlertDescription.HandshakeFailure,
            "local validation",
            innerException: null,
            isPeerAlert: false);

        Assert.True(ClientHelloProfileRoller.IsRetryableForTesting(retryable));
        Assert.False(ClientHelloProfileRoller.IsRetryableForTesting(certificateFailure));
        Assert.False(ClientHelloProfileRoller.IsRetryableForTesting(localFailure));
        Assert.False(ClientHelloProfileRoller.IsRetryableForTesting(new IOException("network")));
    }

    [Fact]
    public void InvalidRetryAndCacheBoundsAreRejected()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() =>
            new ClientHelloProfileRoller(new ClientHelloRollerOptions { MaximumAttempts = 0 }));
        Assert.Throws<ArgumentOutOfRangeException>(() =>
            new ClientHelloProfileRoller(new ClientHelloRollerOptions { CacheCapacity = 0 }));
        Assert.Throws<ArgumentOutOfRangeException>(() =>
            new ClientHelloProfileRoller(new ClientHelloRollerOptions
            {
                InitialRetryDelay = TimeSpan.FromSeconds(2),
                MaximumRetryDelay = TimeSpan.FromSeconds(1),
            }));
        Assert.Throws<ArgumentException>(() =>
            new ClientHelloProfileRoller(new ClientHelloRollerOptions
            {
                CandidateProfiles = [],
                IncludeRandomizedProfile = false,
            }));
    }

    [Fact]
    public void FullClientOptionSurfaceIsPreservedForEveryCandidate()
    {
        using var tls13Cache = new Tls13SessionCache();
        using var tls12Cache = new Tls12SessionCache();
        using var psk = new Tls13ExternalPsk([1], new byte[16]);
        using var keyLogBytes = new MemoryStream();
        using var keyLog = new TlsNssKeyLogSink(
            keyLogBytes,
            acknowledgeSecretExposure: true);
        var settings = new Dictionary<string, byte[]>(StringComparer.Ordinal)
        {
            ["h2"] = [1, 2, 3],
        };
        Action<TlsClientHelloInspection> inspector = _ => { };
        Action<TlsHandshakeEvent> eventObserver = _ => { };
        var source = new CustomTlsClientOptions
        {
            ServerName = "example.com",
            ClientHello = ClientHelloProfiles.ModernTls13,
            HandshakeFragmentation = new TlsRecordFragmentation(123, [1, 7]),
            ApplicationDataFragmentation = new TlsRecordFragmentation(456, [2, 8]),
            ApplicationDataPaddingLength = 9,
            Limits = TlsLimits.Default with { MaxEarlyDataSize = 321 },
            CertificateValidation = new CustomTlsCertificateValidationOptions
            {
                DangerouslySkipServerCertificateValidation = true,
                RevocationMode = X509RevocationMode.Offline,
                RevocationFlag = X509RevocationFlag.EntireChain,
                AllowUnknownRevocationStatus = false,
                DisableCertificateDownloads = true,
                UrlRetrievalTimeout = TimeSpan.FromSeconds(3),
                MinimumValidSignedCertificateTimestamps = 2,
            },
            TcpNoDelay = false,
            SendCompatibilityChangeCipherSpec = false,
            UseInitialCompatibilityRecordVersion = false,
            SessionCache = tls13Cache,
            MaximumOfferedTls13PskIdentities = 7,
            Tls12SessionCache = tls12Cache,
            ExternalPsk = psk,
            EarlyData = new Tls13EarlyDataOptions([9], acknowledgeReplayRisk: true),
            EncryptedClientHelloGrease = new TlsEchGreaseOptions
            {
                CipherSuites =
                [
                    new TlsHpkeSymmetricCipherSuite(
                        TlsHpkeKdfId.HkdfSha256,
                        TlsHpkeAeadId.Aes128Gcm),
                ],
                PayloadLengths = [128, 160],
            },
            ClientApplicationSettings = settings,
            ClientHelloInspector = inspector,
            DangerousNssKeyLog = keyLog,
            HandshakeEventObserver = eventObserver,
        };
        var replacement = CreateProfile(42);

        var clone = ClientHelloProfileRoller.CloneWithProfileForTesting(source, replacement);
        settings["h2"][0] = 99;

        Assert.Same(replacement, clone.ClientHello);
        Assert.Equal([1, 7], clone.HandshakeFragmentation.ExplicitFragmentSizes);
        Assert.Equal([2, 8], clone.ApplicationDataFragmentation.ExplicitFragmentSizes);
        Assert.Equal(9, clone.ApplicationDataPaddingLength);
        Assert.Equal(321, clone.Limits.MaxEarlyDataSize);
        Assert.Equal(X509RevocationMode.Offline, clone.CertificateValidation.RevocationMode);
        Assert.Equal(X509RevocationFlag.EntireChain, clone.CertificateValidation.RevocationFlag);
        Assert.False(clone.CertificateValidation.AllowUnknownRevocationStatus);
        Assert.True(clone.CertificateValidation.DangerouslySkipServerCertificateValidation);
        Assert.True(clone.CertificateValidation.DisableCertificateDownloads);
        Assert.Equal(2, clone.CertificateValidation.MinimumValidSignedCertificateTimestamps);
        Assert.False(clone.TcpNoDelay);
        Assert.False(clone.SendCompatibilityChangeCipherSpec);
        Assert.False(clone.UseInitialCompatibilityRecordVersion);
        Assert.Same(tls13Cache, clone.SessionCache);
        Assert.Equal(7, clone.MaximumOfferedTls13PskIdentities);
        Assert.Same(tls12Cache, clone.Tls12SessionCache);
        Assert.Same(psk, clone.ExternalPsk);
        Assert.Equal([9], clone.EarlyData!.Data);
        Assert.Equal([128, 160], clone.EncryptedClientHelloGrease!.PayloadLengths);
        Assert.Equal(1, clone.ClientApplicationSettings!["h2"][0]);
        Assert.Same(inspector, clone.ClientHelloInspector);
        Assert.Same(keyLog, clone.DangerousNssKeyLog);
        Assert.Same(eventObserver, clone.HandshakeEventObserver);
    }

    [Fact]
    public void ClearCacheRemovesEveryOrigin()
    {
        var roller = new ClientHelloProfileRoller();
        roller.StoreCachedForTesting("one", CreateProfile(1));
        roller.StoreCachedForTesting("two", CreateProfile(2));

        roller.ClearCache();

        Assert.Equal(0, roller.CachedOriginCount);
        Assert.False(roller.TryGetCachedForTesting("one", out _));
    }

    [Fact]
    public async Task PeerHandshakeFailureRetriesAreBounded()
    {
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var endpoint = (IPEndPoint)listener.LocalEndpoint;
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        var accepted = 0;
        var inspected = 0;
        var server = Task.Run(async () =>
        {
            for (var attempt = 0; attempt < 3; attempt++)
            {
                using var socket = await listener.AcceptSocketAsync(timeout.Token);
                accepted++;
                await using var stream = new NetworkStream(socket, ownsSocket: false);
                var header = new byte[5];
                await ReadExactlyAsync(stream, header, timeout.Token);
                var payloadLength = (header[3] << 8) | header[4];
                await ReadExactlyAsync(stream, new byte[payloadLength], timeout.Token);
                await stream.WriteAsync(
                    new byte[] { 21, 3, 3, 0, 2, 2, (byte)TlsAlertDescription.HandshakeFailure },
                    timeout.Token);
            }
        }, timeout.Token);
        var roller = new ClientHelloProfileRoller(new ClientHelloRollerOptions
        {
            MaximumAttempts = 3,
            InitialRetryDelay = TimeSpan.Zero,
            MaximumRetryDelay = TimeSpan.Zero,
        });

        var exception = await Assert.ThrowsAsync<TlsProtocolException>(async () =>
            await roller.ConnectAsync(
                new CustomTlsClientOptions
                {
                    ServerName = "localhost",
                    ClientHelloInspector = _ => Interlocked.Increment(ref inspected),
                },
                "127.0.0.1",
                endpoint.Port,
                timeout.Token));
        await server;

        Assert.Equal(TlsAlertDescription.HandshakeFailure, exception.Alert);
        Assert.Equal(3, accepted);
        Assert.Equal(3, inspected);
        Assert.Equal(0, roller.CachedOriginCount);
    }

    private static ClientHelloProfile CreateProfile(byte seed) =>
        ClientHelloProfileRandomizer.CreateDeterministicForTesting([seed]);

    private static async Task ReadExactlyAsync(
        Stream stream,
        Memory<byte> destination,
        CancellationToken cancellationToken)
    {
        var offset = 0;
        while (offset < destination.Length)
        {
            var read = await stream.ReadAsync(destination[offset..], cancellationToken);
            if (read == 0)
            {
                throw new EndOfStreamException();
            }
            offset += read;
        }
    }
}
