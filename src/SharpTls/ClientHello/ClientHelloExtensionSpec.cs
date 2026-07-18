namespace SharpTls;

/// <summary>
/// Describes one exact ClientHello extension slot as either a SharpTls semantic
/// built-in or an opaque raw wire value.
/// </summary>
public sealed class ClientHelloExtensionSpec
{
    private readonly byte[] _rawData;

    private ClientHelloExtensionSpec(
        ClientHelloExtensionKind? builtInKind,
        ushort? rawExtensionType,
        byte[] rawData)
    {
        BuiltInKind = builtInKind;
        RawExtensionType = rawExtensionType;
        _rawData = rawData;
    }

    /// <summary>Gets the semantic built-in kind, or null for an opaque raw extension.</summary>
    public ClientHelloExtensionKind? BuiltInKind { get; }

    /// <summary>Gets the exact raw wire type, or null for a semantic built-in.</summary>
    public ushort? RawExtensionType { get; }

    /// <summary>Creates a semantic extension slot whose body SharpTls constructs safely.</summary>
    public static ClientHelloExtensionSpec BuiltIn(ClientHelloExtensionKind kind)
    {
        if (!Enum.IsDefined(kind))
        {
            throw new ArgumentOutOfRangeException(nameof(kind));
        }

        return new ClientHelloExtensionSpec(kind, null, []);
    }

    /// <summary>
    /// Creates an opaque extension with an exact body. SharpTls does not implement
    /// response semantics for raw extensions and fails if a peer requires them.
    /// </summary>
    public static ClientHelloExtensionSpec Raw(ushort extensionType, byte[] data)
    {
        ArgumentNullException.ThrowIfNull(data);
        if (data.Length > ushort.MaxValue)
        {
            throw new ArgumentOutOfRangeException(nameof(data));
        }

        return new ClientHelloExtensionSpec(null, extensionType, (byte[])data.Clone());
    }

    /// <summary>Returns a copy of the opaque body, or an empty array for a built-in slot.</summary>
    public byte[] GetRawData() => (byte[])_rawData.Clone();

    internal ReadOnlySpan<byte> RawData => _rawData;

    internal ClientHelloExtensionSpec Snapshot() => BuiltInKind.HasValue
        ? BuiltIn(BuiltInKind.Value)
        : Raw(RawExtensionType!.Value, _rawData);
}
