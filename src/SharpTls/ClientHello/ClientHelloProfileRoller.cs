using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using SharpTls.Protocol;

namespace SharpTls;

/// <summary>Controls bounded profile retry and successful-profile caching.</summary>
public sealed class ClientHelloRollerOptions
{
    /// <summary>Gets or sets the maximum connections attempted for one call.</summary>
    public int MaximumAttempts { get; set; } = 4;

    /// <summary>Gets or sets the maximum number of origin-bound successful profiles cached.</summary>
    public int CacheCapacity { get; set; } = 256;

    /// <summary>Gets or sets the delay before the first eligible profile retry.</summary>
    public TimeSpan InitialRetryDelay { get; set; } = TimeSpan.FromMilliseconds(50);

    /// <summary>Gets or sets the cap for exponential retry delay.</summary>
    public TimeSpan MaximumRetryDelay { get; set; } = TimeSpan.FromMilliseconds(500);

    /// <summary>Gets or sets randomized profile generation policy.</summary>
    public ClientHelloRandomizationOptions Randomization { get; set; } = new();

    /// <summary>
    /// Gets or sets pinned profiles tried alongside the randomized candidate. The defaults
    /// match uTLS Roller families while using SharpTls's current verified Auto aliases.
    /// </summary>
    public IReadOnlyList<ClientHelloProfile> CandidateProfiles { get; set; } =
    [
        ClientHelloProfiles.UTlsChromeAuto,
        ClientHelloProfiles.UTlsFirefoxAuto,
        ClientHelloProfiles.UTlsIOSAuto,
    ];

    /// <summary>Gets or sets whether one fresh coherent randomized candidate joins the pool.</summary>
    public bool IncludeRandomizedProfile { get; set; } = true;

    internal ClientHelloRollerConfiguration Snapshot()
    {
        ArgumentNullException.ThrowIfNull(Randomization);
        ArgumentNullException.ThrowIfNull(CandidateProfiles);
        if (MaximumAttempts is < 1 or > 8)
        {
            throw new ArgumentOutOfRangeException(nameof(MaximumAttempts));
        }
        if (CacheCapacity is < 1 or > 16_384)
        {
            throw new ArgumentOutOfRangeException(nameof(CacheCapacity));
        }
        if (InitialRetryDelay < TimeSpan.Zero ||
            MaximumRetryDelay < InitialRetryDelay ||
            MaximumRetryDelay > TimeSpan.FromSeconds(30))
        {
            throw new ArgumentOutOfRangeException(nameof(MaximumRetryDelay));
        }

        var candidates = CandidateProfiles.Select(profile =>
        {
            ArgumentNullException.ThrowIfNull(profile);
            return profile;
        }).ToArray();
        if (candidates.Length > 64 ||
            candidates.Distinct(ReferenceEqualityComparer.Instance).Count() != candidates.Length)
        {
            throw new ArgumentException(
                "Roller accepts at most 64 distinct candidate profile instances.",
                nameof(CandidateProfiles));
        }
        if (candidates.Length == 0 && !IncludeRandomizedProfile)
        {
            throw new ArgumentException(
                "Roller requires at least one pinned or randomized candidate profile.",
                nameof(CandidateProfiles));
        }

        return new ClientHelloRollerConfiguration(
            MaximumAttempts,
            CacheCapacity,
            InitialRetryDelay,
            MaximumRetryDelay,
            Randomization.Snapshot(),
            candidates,
            IncludeRandomizedProfile);
    }
}

/// <summary>
/// Tries bounded coherent ClientHello profiles and remembers a successful profile per origin.
/// Retries are limited to explicit peer negotiation alerts and never bypass authentication.
/// </summary>
public sealed class ClientHelloProfileRoller
{
    private readonly object _cacheLock = new();
    private readonly Dictionary<string, CacheEntry> _cache = new(StringComparer.Ordinal);
    private readonly LinkedList<string> _lru = new();
    private readonly ClientHelloRollerConfiguration _configuration;

    /// <summary>Creates a roller and snapshots its mutable options.</summary>
    public ClientHelloProfileRoller(ClientHelloRollerOptions? options = null)
    {
        _configuration = (options ?? new ClientHelloRollerOptions()).Snapshot();
    }

    /// <summary>Gets the current number of cached origins.</summary>
    public int CachedOriginCount
    {
        get
        {
            lock (_cacheLock)
            {
                return _cache.Count;
            }
        }
    }

    /// <summary>
    /// Connects with a cached successful profile or bounded randomized candidates.
    /// The caller owns the returned authenticated client and must dispose it.
    /// </summary>
    public async ValueTask<CustomTlsClient> ConnectAsync(
        CustomTlsClientOptions baseOptions,
        string host,
        int port,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(baseOptions);
        ArgumentException.ThrowIfNullOrWhiteSpace(host);
        if (port is < 1 or > ushort.MaxValue)
        {
            throw new ArgumentOutOfRangeException(nameof(port));
        }

        var template = SnapshotBaseOptions(baseOptions);
        try
        {
            // Validate the caller's original options once. Candidate-specific incompatibility may
            // then be skipped without concealing a malformed base configuration.
            await using (var validationClient = new CustomTlsClient(
                CloneWithProfile(template, template.ClientHello)))
            {
            }

            var cacheKey = CreateCacheKey(host, port, template.ServerName);
            _ = TryGetCached(cacheKey, out var cachedProfile);
            var candidates = CreateCandidateSequence(cachedProfile);
            Exception? lastNegotiationFailure = null;
            Exception? lastCompatibilityFailure = null;
            var networkAttempts = 0;

            foreach (var profile in candidates)
            {
                cancellationToken.ThrowIfCancellationRequested();
                if (networkAttempts >= _configuration.MaximumAttempts)
                {
                    break;
                }

                CustomTlsClient client;
                try
                {
                    client = new CustomTlsClient(CloneWithProfile(template, profile));
                }
                catch (Exception exception) when (IsCandidateCompatibilityFailure(exception))
                {
                    lastCompatibilityFailure = exception;
                    RemoveCached(cacheKey, profile);
                    continue;
                }

                networkAttempts++;
                try
                {
                    await client.ConnectAsync(host, port, cancellationToken).ConfigureAwait(false);
                    StoreCached(cacheKey, profile);
                    return client;
                }
                catch (Exception exception) when (IsRetryable(exception))
                {
                    lastNegotiationFailure = exception;
                    await client.DisposeAsync().ConfigureAwait(false);
                    RemoveCached(cacheKey, profile);
                    if (networkAttempts < _configuration.MaximumAttempts)
                    {
                        var delay = GetRetryDelay(networkAttempts - 1);
                        if (delay > TimeSpan.Zero)
                        {
                            await Task.Delay(delay, cancellationToken).ConfigureAwait(false);
                        }
                    }
                }
                catch
                {
                    await client.DisposeAsync().ConfigureAwait(false);
                    throw;
                }
            }

            if (lastNegotiationFailure is not null)
            {
                System.Runtime.ExceptionServices.ExceptionDispatchInfo
                    .Capture(lastNegotiationFailure)
                    .Throw();
            }
            throw new InvalidOperationException(
                "No Roller candidate is compatible with the supplied TLS client options.",
                lastCompatibilityFailure);
        }
        finally
        {
            template.ExternalPsk?.Dispose();
        }
    }

    /// <summary>Removes every remembered successful origin profile.</summary>
    public void ClearCache()
    {
        lock (_cacheLock)
        {
            _cache.Clear();
            _lru.Clear();
        }
    }

    internal bool TryGetCachedForTesting(string cacheKey, out ClientHelloProfile? profile) =>
        TryGetCached(cacheKey, out profile);

    internal void StoreCachedForTesting(string cacheKey, ClientHelloProfile profile) =>
        StoreCached(cacheKey, profile);

    internal static bool IsRetryableForTesting(Exception exception) => IsRetryable(exception);

    internal static CustomTlsClientOptions CloneWithProfileForTesting(
        CustomTlsClientOptions source,
        ClientHelloProfile profile) => CloneWithProfile(source, profile);

    private static CustomTlsClientOptions SnapshotBaseOptions(CustomTlsClientOptions source)
    {
        var snapshot = CloneWithProfile(source, source.ClientHello);
        snapshot.ExternalPsk = source.ExternalPsk?.Clone();
        return snapshot;
    }

    private static CustomTlsClientOptions CloneWithProfile(
        CustomTlsClientOptions template,
        ClientHelloProfile profile)
    {
        var certificate = template.CertificateValidation;
        return new CustomTlsClientOptions
        {
            ServerName = template.ServerName,
            ClientHello = profile,
            HandshakeFragmentation = template.HandshakeFragmentation,
            ApplicationDataFragmentation = template.ApplicationDataFragmentation,
            ApplicationDataPaddingLength = template.ApplicationDataPaddingLength,
            Limits = template.Limits with { },
            CertificateValidation = new CustomTlsCertificateValidationOptions
            {
                RevocationMode = certificate.RevocationMode,
                RevocationFlag = certificate.RevocationFlag,
                DisableCertificateDownloads = certificate.DisableCertificateDownloads,
                UrlRetrievalTimeout = certificate.UrlRetrievalTimeout,
                CustomTrustRoots = certificate.CustomTrustRoots?.ToArray(),
                EvidenceValidator = certificate.EvidenceValidator,
                RequireValidStapledOcspResponse = certificate.RequireValidStapledOcspResponse,
                MinimumValidSignedCertificateTimestamps =
                    certificate.MinimumValidSignedCertificateTimestamps,
            },
            TcpNoDelay = template.TcpNoDelay,
            SendCompatibilityChangeCipherSpec = template.SendCompatibilityChangeCipherSpec,
            UseInitialCompatibilityRecordVersion = template.UseInitialCompatibilityRecordVersion,
            SessionCache = template.SessionCache,
            MaximumOfferedTls13PskIdentities = template.MaximumOfferedTls13PskIdentities,
            Tls12SessionCache = template.Tls12SessionCache,
            ExternalPsk = template.ExternalPsk,
            EarlyData = template.EarlyData is null
                ? null
                : new Tls13EarlyDataOptions(
                    template.EarlyData.Data,
                    acknowledgeReplayRisk: true,
                    template.EarlyData.RejectionPolicy),
            EncryptedClientHello = template.EncryptedClientHello is null
                ? null
                : new TlsEchOptions
                {
                    ConfigList = template.EncryptedClientHello.ConfigList,
                    OuterClientHello = template.EncryptedClientHello.OuterClientHello,
                    CompressedOuterExtensions =
                        template.EncryptedClientHello.CompressedOuterExtensions.ToArray(),
                },
            EncryptedClientHelloGrease = template.EncryptedClientHelloGrease is null
                ? null
                : new TlsEchGreaseOptions
                {
                    CipherSuites = template.EncryptedClientHelloGrease.CipherSuites.ToArray(),
                    PayloadLengths = template.EncryptedClientHelloGrease.PayloadLengths?.ToArray(),
                },
            ClientApplicationSettings = template.ClientApplicationSettings?.ToDictionary(
                pair => pair.Key,
                pair => (byte[])pair.Value.Clone(),
                StringComparer.Ordinal),
            ClientCertificate = template.ClientCertificate,
            ClientCertificateSelector = template.ClientCertificateSelector,
            ClientHelloInspector = template.ClientHelloInspector,
            DangerousNssKeyLog = template.DangerousNssKeyLog,
            HandshakeEventObserver = template.HandshakeEventObserver,
        };
    }

    private IReadOnlyList<ClientHelloProfile> CreateCandidateSequence(
        ClientHelloProfile? cachedProfile)
    {
        var candidates = _configuration.CandidateProfiles.ToList();
        Shuffle(candidates);
        if (_configuration.IncludeRandomizedProfile)
        {
            var randomized = ClientHelloProfileRandomizer.CreateSecure(
                _configuration.Randomization);
            candidates.Insert(RandomNumberGenerator.GetInt32(candidates.Count + 1), randomized);
        }
        if (cachedProfile is not null)
        {
            candidates.RemoveAll(profile => ReferenceEquals(profile, cachedProfile));
            candidates.Insert(0, cachedProfile);
        }
        return candidates;
    }

    private static void Shuffle(List<ClientHelloProfile> profiles)
    {
        for (var index = profiles.Count - 1; index > 0; index--)
        {
            var swapIndex = RandomNumberGenerator.GetInt32(index + 1);
            (profiles[index], profiles[swapIndex]) = (profiles[swapIndex], profiles[index]);
        }
    }

    private static bool IsCandidateCompatibilityFailure(Exception exception) =>
        exception is ArgumentException or NotSupportedException;

    private static string CreateCacheKey(string host, int port, string? serverName)
    {
        var normalizedHost = host.TrimEnd('.').ToLowerInvariant();
        var normalizedIdentity = (serverName ?? host).TrimEnd('.').ToLowerInvariant();
        return $"{normalizedHost}:{port}|{normalizedIdentity}";
    }

    private TimeSpan GetRetryDelay(int completedAttempt)
    {
        var multiplier = 1L << Math.Min(completedAttempt, 30);
        var ticks = Math.Min(
            _configuration.MaximumRetryDelay.Ticks,
            _configuration.InitialRetryDelay.Ticks * multiplier);
        return TimeSpan.FromTicks(ticks);
    }

    private static bool IsRetryable(Exception exception) =>
        exception is TlsProtocolException
        {
            IsPeerAlert: true,
            Alert: TlsAlertDescription.HandshakeFailure or
                TlsAlertDescription.ProtocolVersion or
                TlsAlertDescription.MissingExtension or
                TlsAlertDescription.UnsupportedExtension or
                TlsAlertDescription.NoApplicationProtocol,
        };

    private bool TryGetCached(string cacheKey, out ClientHelloProfile? profile)
    {
        lock (_cacheLock)
        {
            if (!_cache.TryGetValue(cacheKey, out var entry))
            {
                profile = null;
                return false;
            }

            _lru.Remove(entry.Node);
            _lru.AddFirst(entry.Node);
            profile = entry.Profile;
            return true;
        }
    }

    private void StoreCached(string cacheKey, ClientHelloProfile profile)
    {
        lock (_cacheLock)
        {
            if (_cache.TryGetValue(cacheKey, out var existing))
            {
                existing.Profile = profile;
                _lru.Remove(existing.Node);
                _lru.AddFirst(existing.Node);
                return;
            }

            var node = _lru.AddFirst(cacheKey);
            _cache.Add(cacheKey, new CacheEntry(profile, node));
            while (_cache.Count > _configuration.CacheCapacity)
            {
                var oldest = _lru.Last!;
                _lru.RemoveLast();
                _cache.Remove(oldest.Value);
            }
        }
    }

    private void RemoveCached(string cacheKey, ClientHelloProfile expectedProfile)
    {
        lock (_cacheLock)
        {
            if (!_cache.TryGetValue(cacheKey, out var existing) ||
                !ReferenceEquals(existing.Profile, expectedProfile))
            {
                return;
            }

            _cache.Remove(cacheKey);
            _lru.Remove(existing.Node);
        }
    }

    private sealed class CacheEntry(
        ClientHelloProfile profile,
        LinkedListNode<string> node)
    {
        internal ClientHelloProfile Profile { get; set; } = profile;

        internal LinkedListNode<string> Node { get; } = node;
    }
}

internal sealed record ClientHelloRollerConfiguration(
    int MaximumAttempts,
    int CacheCapacity,
    TimeSpan InitialRetryDelay,
    TimeSpan MaximumRetryDelay,
    ClientHelloRandomizationConfiguration Randomization,
    ClientHelloProfile[] CandidateProfiles,
    bool IncludeRandomizedProfile);
