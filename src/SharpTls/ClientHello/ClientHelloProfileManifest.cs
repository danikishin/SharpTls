using System.Collections.Concurrent;
using System.Security.Cryptography;
using SharpTls.Protocol;

namespace SharpTls;

/// <summary>
/// Immutable provenance and executable specification for one reviewed captured profile.
/// Raw capture bytes and ephemeral wire material are not retained.
/// </summary>
public sealed class ClientHelloProfileManifest
{
    private readonly byte[] _sourceSha256;
    private readonly ClientHelloSpec _spec;

    private ClientHelloProfileManifest(
        string id,
        string family,
        string version,
        DateTimeOffset capturedAt,
        byte[] sourceSha256,
        ClientHelloCaptureResult imported)
    {
        Id = id;
        Family = family;
        Version = version;
        CapturedAt = capturedAt;
        _sourceSha256 = sourceSha256;
        _spec = new ClientHelloSpec(imported.Spec.SnapshotConfiguration());
        CapturedServerName = imported.CapturedServerName;
        SourceWasRecordFramed = imported.WasRecordFramed;
    }

    /// <summary>Gets the stable catalog identifier.</summary>
    public string Id { get; }

    /// <summary>Gets the captured client family, without an implicit “latest” meaning.</summary>
    public string Family { get; }

    /// <summary>Gets the exact captured client version label.</summary>
    public string Version { get; }

    /// <summary>Gets when the source capture was collected.</summary>
    public DateTimeOffset CapturedAt { get; }

    /// <summary>Gets the captured SNI value as provenance, or null when absent.</summary>
    public string? CapturedServerName { get; }

    /// <summary>Gets whether the reviewed source included TLS record framing.</summary>
    public bool SourceWasRecordFramed { get; }

    /// <summary>Gets a copy of the SHA-256 digest of the complete source input.</summary>
    public byte[] SourceSha256 => (byte[])_sourceSha256.Clone();

    /// <summary>Gets an immutable executable specification snapshot.</summary>
    public ClientHelloSpec Spec => new(_spec.SnapshotConfiguration());

    /// <summary>Gets the ALPN protocols which the application layer must be prepared to use.</summary>
    public IReadOnlyList<string> RequiredApplicationProtocols => _spec.AlpnProtocols;

    /// <summary>Creates an executable profile with fresh connection entropy and key shares.</summary>
    public ClientHelloProfile CreateProfile() => ClientHelloProfiles.FromSpec(_spec);

    /// <summary>
    /// Imports, validates, hashes, and normalizes a reviewed source capture into a manifest.
    /// Unsupported captures fail rather than entering the executable catalog.
    /// </summary>
    public static ClientHelloProfileManifest Import(
        string id,
        string family,
        string version,
        DateTimeOffset capturedAt,
        ReadOnlySpan<byte> sourceCapture,
        ClientHelloCaptureFormat format = ClientHelloCaptureFormat.Auto,
        ClientHelloImportOptions? importOptions = null)
    {
        ValidateMetadata(id, nameof(id));
        ValidateMetadata(family, nameof(family));
        ValidateMetadata(version, nameof(version));
        var maximumInputSize = importOptions?.MaximumInputSize ?? 256 * 1024;
        if (maximumInputSize is < 1024 or > 4 * 1024 * 1024)
        {
            throw new ArgumentOutOfRangeException(nameof(importOptions));
        }
        if (sourceCapture.IsEmpty || sourceCapture.Length > maximumInputSize)
        {
            throw TlsProtocolException.Decode(
                "Profile source capture is empty or exceeds its configured size limit.");
        }

        var sourceSnapshot = sourceCapture.ToArray();
        try
        {
            var imported = ClientHelloCapture.Import(sourceSnapshot, format, importOptions);
            var digest = SHA256.HashData(sourceSnapshot);
            return new ClientHelloProfileManifest(
                id,
                family,
                version,
                capturedAt,
                digest,
                imported);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(sourceSnapshot);
        }
    }

    private static void ValidateMetadata(string value, string parameterName)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(value, parameterName);
        if (value.Length > 128 || value.Any(character => character is < ' ' or > '~'))
        {
            throw new ArgumentException(
                "Profile metadata must contain 1-128 printable ASCII characters.",
                parameterName);
        }
    }
}

/// <summary>Thread-safe registry of explicit, versioned, executable captured profiles.</summary>
public sealed class ClientHelloProfileCatalog
{
    private readonly ConcurrentDictionary<string, ClientHelloProfileManifest> _profiles =
        new(StringComparer.Ordinal);

    /// <summary>Gets a stable identifier-sorted snapshot of registered manifests.</summary>
    public IReadOnlyList<ClientHelloProfileManifest> Profiles => Array.AsReadOnly(
        _profiles.Values.OrderBy(profile => profile.Id, StringComparer.Ordinal).ToArray());

    /// <summary>Registers one manifest and rejects duplicate identifiers.</summary>
    public void Register(ClientHelloProfileManifest manifest)
    {
        ArgumentNullException.ThrowIfNull(manifest);
        if (!_profiles.TryAdd(manifest.Id, manifest))
        {
            throw new ArgumentException(
                $"A ClientHello profile named '{manifest.Id}' is already registered.",
                nameof(manifest));
        }
    }

    /// <summary>Finds a registered manifest by its exact case-sensitive identifier.</summary>
    public bool TryGet(string id, out ClientHelloProfileManifest? manifest)
    {
        ArgumentNullException.ThrowIfNull(id);
        return _profiles.TryGetValue(id, out manifest);
    }

    /// <summary>Gets a registered manifest or throws when the exact identifier is absent.</summary>
    public ClientHelloProfileManifest GetRequired(string id)
    {
        ArgumentNullException.ThrowIfNull(id);
        return _profiles.TryGetValue(id, out var profile)
            ? profile
            : throw new KeyNotFoundException($"No ClientHello profile named '{id}' is registered.");
    }
}
