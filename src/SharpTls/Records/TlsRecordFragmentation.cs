using SharpTls.Protocol;

namespace SharpTls;

/// <summary>Controls how a plaintext byte sequence is split across TLS records.</summary>
public sealed class TlsRecordFragmentation
{
    private readonly int[] _explicitFragmentSizes;

    /// <summary>Creates a fragmentation policy.</summary>
    /// <param name="maximumFragmentSize">Maximum plaintext bytes in any emitted record.</param>
    /// <param name="explicitFragmentSizes">
    /// Optional sizes for the first records. Remaining bytes use <paramref name="maximumFragmentSize"/>.
    /// </param>
    public TlsRecordFragmentation(
        int maximumFragmentSize = TlsConstants.MaxPlaintextLength,
        IEnumerable<int>? explicitFragmentSizes = null)
    {
        if (maximumFragmentSize is < 1 or > TlsConstants.MaxPlaintextLength)
        {
            throw new ArgumentOutOfRangeException(nameof(maximumFragmentSize));
        }

        MaximumFragmentSize = maximumFragmentSize;
        _explicitFragmentSizes = explicitFragmentSizes?.ToArray() ?? [];

        if (_explicitFragmentSizes.Any(size => size < 1 || size > maximumFragmentSize))
        {
            throw new ArgumentOutOfRangeException(
                nameof(explicitFragmentSizes),
                "Every explicit fragment size must be positive and no larger than the maximum.");
        }
    }

    /// <summary>Gets the standard maximum-size fragmentation policy.</summary>
    public static TlsRecordFragmentation Default { get; } = new();

    /// <summary>Gets the maximum plaintext bytes in one record.</summary>
    public int MaximumFragmentSize { get; }

    /// <summary>Gets a copy of the exact initial fragment sizes.</summary>
    public IReadOnlyList<int> ExplicitFragmentSizes => Array.AsReadOnly((int[])_explicitFragmentSizes.Clone());

    internal int GetNextSize(int recordIndex, int remaining)
    {
        var requested = recordIndex < _explicitFragmentSizes.Length
            ? _explicitFragmentSizes[recordIndex]
            : MaximumFragmentSize;

        return Math.Min(requested, remaining);
    }
}
