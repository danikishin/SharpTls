namespace SharpTls;

/// <summary>Identifies a semantic RFC 8701 GREASE placement.</summary>
public enum ClientHelloGreaseSlot
{
    /// <summary>The leading cipher_suites value.</summary>
    CipherSuite,
    /// <summary>The leading supported_versions value.</summary>
    SupportedVersion,
    /// <summary>The leading supported_groups value.</summary>
    SupportedGroup,
    /// <summary>The leading key_share entry.</summary>
    KeyShare,
    /// <summary>The empty GREASE extension type.</summary>
    Extension,
    /// <summary>The optional second GREASE extension type.</summary>
    SecondaryExtension,
}

/// <summary>
/// Defines which GREASE placements share a generated value. It never fixes the
/// actual GREASE code point; secure generation chooses fresh values per connection.
/// </summary>
public sealed class ClientHelloGreasePolicy
{
    private const int SlotCount = 6;
    private readonly int[] _valueClasses;

    private ClientHelloGreasePolicy(int[] valueClasses)
    {
        _valueClasses = valueClasses;
        DistinctValueCount = valueClasses.Distinct().Count();
    }

    /// <summary>Gets a policy which uses one fresh GREASE value in every placement.</summary>
    public static ClientHelloGreasePolicy Consistent { get; } = Create(0, 0, 0, 0, 0);

    /// <summary>Gets a policy which uses a distinct fresh value in every placement.</summary>
    public static ClientHelloGreasePolicy PerSlot { get; } =
        CreateWithSecondaryExtension(0, 1, 2, 3, 4, 5);

    /// <summary>Gets the number of independently generated GREASE values.</summary>
    public int DistinctValueCount { get; }

    /// <summary>
    /// Creates an equality pattern for cipher suite, supported version, supported
    /// group, key share, and extension placements, in that order. Equal class labels
    /// share a generated value; label numbers are normalized by first occurrence.
    /// </summary>
    public static ClientHelloGreasePolicy Create(
        int cipherSuiteClass,
        int supportedVersionClass,
        int supportedGroupClass,
        int keyShareClass,
        int extensionClass)
        => CreateWithSecondaryExtension(
            cipherSuiteClass,
            supportedVersionClass,
            supportedGroupClass,
            keyShareClass,
            extensionClass,
            extensionClass);

    /// <summary>
    /// Creates an equality pattern including an optional second GREASE extension slot.
    /// </summary>
    public static ClientHelloGreasePolicy CreateWithSecondaryExtension(
        int cipherSuiteClass,
        int supportedVersionClass,
        int supportedGroupClass,
        int keyShareClass,
        int extensionClass,
        int secondaryExtensionClass)
    {
        int[] requested =
        [
            cipherSuiteClass,
            supportedVersionClass,
            supportedGroupClass,
            keyShareClass,
            extensionClass,
            secondaryExtensionClass,
        ];
        if (requested.Any(value => value is < 0 or > 15))
        {
            throw new ArgumentOutOfRangeException(
                nameof(cipherSuiteClass),
                "GREASE value-class labels must be between 0 and 15.");
        }

        var normalized = new int[SlotCount];
        var classes = new Dictionary<int, int>();
        for (var index = 0; index < requested.Length; index++)
        {
            if (!classes.TryGetValue(requested[index], out var normalizedClass))
            {
                normalizedClass = classes.Count;
                classes.Add(requested[index], normalizedClass);
            }
            normalized[index] = normalizedClass;
        }

        return new ClientHelloGreasePolicy(normalized);
    }

    /// <summary>Gets the normalized generated-value class for a placement.</summary>
    public int GetValueClass(ClientHelloGreaseSlot slot)
    {
        if (!Enum.IsDefined(slot))
        {
            throw new ArgumentOutOfRangeException(nameof(slot));
        }
        return _valueClasses[(int)slot];
    }

    /// <summary>Gets a copy of the original five normalized classes in documented slot order.</summary>
    public IReadOnlyList<int> ValueClasses => Array.AsReadOnly(_valueClasses[..5]);

    /// <summary>Gets the normalized generated-value class for the optional second GREASE extension.</summary>
    public int SecondaryExtensionValueClass => _valueClasses[(int)ClientHelloGreaseSlot.SecondaryExtension];

    internal ClientHelloGreasePolicy Snapshot() => new((int[])_valueClasses.Clone());
}
