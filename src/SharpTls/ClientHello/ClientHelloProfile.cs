using SharpTls.Cryptography;
using SharpTls.Ech;

namespace SharpTls;

/// <summary>An immutable ClientHello layout and algorithm profile.</summary>
public sealed class ClientHelloProfile
{
    private readonly ClientHelloConfiguration _configuration;

    internal ClientHelloProfile(ClientHelloConfiguration configuration)
    {
        _configuration = configuration.Snapshot();
    }

    /// <summary>Gets an immutable snapshot of this profile's reusable specification.</summary>
    public ClientHelloSpec Spec => new(_configuration);

    /// <summary>
    /// Produces a byte-for-byte repeatable ClientHello for snapshot tests.
    /// The result uses fixed test-only ECDHE keys and must never be sent on a network.
    /// </summary>
    public byte[] BuildDeterministicForTesting(string serverName, byte[] seed)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(serverName);
        ArgumentNullException.ThrowIfNull(seed);

        using var random = new DeterministicRandomSource(seed);
        using var keyShares = new KeyShareSet(deterministicForTesting: true);
        using var result = Build(
            serverName,
            random,
            keyShares,
            pskOffer: null);
        return (byte[])result.EncodedHandshake.Clone();
    }

    internal ClientHelloBuildResult BuildSecure(
        string serverName,
        Tls13PskOffer? pskOffer = null) => Build(
            serverName,
            SecureRandomSource.Instance,
            new KeyShareSet(),
            pskOffer);

    private ClientHelloBuildResult Build(
        string serverName,
        IRandomSource randomSource,
        KeyShareSet keyShares,
        Tls13PskOffer? pskOffer)
    {
        if (_configuration.GreaseEchPayloadLengths is null)
        {
            return ClientHelloEncoder.Build(
                serverName,
                _configuration,
                randomSource,
                keyShares,
                retry: null,
                pskOffer: pskOffer);
        }

        return EchGreaseClientHelloBuilder.Build(
            serverName,
            _configuration,
            new TlsEchGreaseConfiguration(
                (TlsHpkeSymmetricCipherSuite[])_configuration.GreaseEchCipherSuites!.Clone(),
                _configuration.GreaseEchPayloadLengths),
            randomSource,
            keyShares,
            pskOffer);
    }
}

/// <summary>Factory methods for built-in and custom ClientHello profiles.</summary>
public static partial class ClientHelloProfiles
{
    /// <summary>Gets the default production TLS 1.3 profile.</summary>
    public static ClientHelloProfile ModernTls13 { get; } = Custom(builder =>
        builder.WithSessionResumption());

    /// <summary>Creates a validated immutable custom profile.</summary>
    public static ClientHelloProfile Custom(Action<ClientHelloBuilder> configure)
    {
        ArgumentNullException.ThrowIfNull(configure);
        var builder = new ClientHelloBuilder();
        configure(builder);
        return FromSpec(builder.BuildSpec());
    }

    /// <summary>Creates an executable profile from an immutable specification.</summary>
    public static ClientHelloProfile FromSpec(ClientHelloSpec spec)
    {
        ArgumentNullException.ThrowIfNull(spec);
        return new ClientHelloProfile(spec.SnapshotConfiguration());
    }
}
