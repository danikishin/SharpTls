namespace SharpTls;

/// <summary>Identifies which ClientHello flight is about to be written.</summary>
public enum TlsClientHelloFlight
{
    /// <summary>The first ClientHello of a handshake.</summary>
    Initial,

    /// <summary>The second ClientHello produced after a valid HelloRetryRequest.</summary>
    AfterHelloRetryRequest,
}

/// <summary>Describes the form of the ClientHello visible on the transport.</summary>
public enum TlsClientHelloWireForm
{
    /// <summary>A direct ClientHello without an encrypted_client_hello extension.</summary>
    Direct,

    /// <summary>An RFC 9849 ClientHelloOuter carrying an encrypted ClientHelloInner.</summary>
    EncryptedClientHelloOuter,

    /// <summary>A syntactically valid GREASE encrypted_client_hello offer.</summary>
    GreaseEncryptedClientHello,
}

/// <summary>
/// Provides an immutable snapshot of one encoded ClientHello immediately before it is sent.
/// </summary>
public sealed class TlsClientHelloInspection
{
    private readonly byte[] _encodedHandshake;
    private readonly byte[] _encodedTlsRecords;
    private readonly int[] _recordFragmentSizes;

    internal TlsClientHelloInspection(
        TlsClientHelloFlight flight,
        TlsClientHelloWireForm wireForm,
        ReadOnlySpan<byte> encodedHandshake,
        TlsRecordFragmentation fragmentation,
        ushort legacyRecordVersion)
    {
        if (encodedHandshake.Length == 0)
        {
            throw new ArgumentException("An inspected ClientHello cannot be empty.", nameof(encodedHandshake));
        }
        ArgumentNullException.ThrowIfNull(fragmentation);

        Flight = flight;
        WireForm = wireForm;
        LegacyRecordVersion = legacyRecordVersion;
        _encodedHandshake = encodedHandshake.ToArray();
        (_encodedTlsRecords, _recordFragmentSizes) = EncodeTlsRecords(
            encodedHandshake,
            fragmentation,
            legacyRecordVersion);
    }

    /// <summary>Gets the initial or post-HelloRetryRequest flight.</summary>
    public TlsClientHelloFlight Flight { get; }

    /// <summary>Gets whether the transport sees a direct, ECH outer, or GREASE-ECH ClientHello.</summary>
    public TlsClientHelloWireForm WireForm { get; }

    /// <summary>Gets the encoded handshake-message length, including its four-byte header.</summary>
    public int EncodedHandshakeLength => _encodedHandshake.Length;

    /// <summary>Gets the exact legacy_record_version used by every planned ClientHello record.</summary>
    public ushort LegacyRecordVersion { get; }

    /// <summary>Gets the exact plaintext fragment lengths in planned TLS-record order.</summary>
    public IReadOnlyList<int> RecordFragmentSizes =>
        Array.AsReadOnly((int[])_recordFragmentSizes.Clone());

    /// <summary>Gets the total byte length of the planned TLS records, including record headers.</summary>
    public int EncodedTlsRecordsLength => _encodedTlsRecords.Length;

    /// <summary>
    /// Returns a caller-owned copy of the exact encoded handshake message. Mutating the returned
    /// array cannot change the ClientHello that SharpTls subsequently writes.
    /// </summary>
    public byte[] GetEncodedHandshake() => (byte[])_encodedHandshake.Clone();

    /// <summary>
    /// Returns a caller-owned copy of the exact TLSPlaintext records that SharpTls will write.
    /// It includes record headers, the configured fragmentation pattern, and record version.
    /// </summary>
    public byte[] GetEncodedTlsRecords() => (byte[])_encodedTlsRecords.Clone();

    private static (byte[] Records, int[] FragmentSizes) EncodeTlsRecords(
        ReadOnlySpan<byte> handshake,
        TlsRecordFragmentation fragmentation,
        ushort legacyRecordVersion)
    {
        var fragmentSizes = new List<int>();
        var remaining = handshake.Length;
        while (remaining > 0)
        {
            var length = fragmentation.GetNextSize(fragmentSizes.Count, remaining);
            fragmentSizes.Add(length);
            remaining -= length;
        }

        var records = new byte[checked(
            handshake.Length + fragmentSizes.Count * Protocol.TlsConstants.RecordHeaderLength)];
        var sourceOffset = 0;
        var destinationOffset = 0;
        foreach (var length in fragmentSizes)
        {
            records[destinationOffset] = (byte)Protocol.TlsContentType.Handshake;
            records[destinationOffset + 1] = (byte)(legacyRecordVersion >> 8);
            records[destinationOffset + 2] = (byte)legacyRecordVersion;
            records[destinationOffset + 3] = (byte)(length >> 8);
            records[destinationOffset + 4] = (byte)length;
            handshake.Slice(sourceOffset, length).CopyTo(
                records.AsSpan(destinationOffset + Protocol.TlsConstants.RecordHeaderLength));
            sourceOffset += length;
            destinationOffset += Protocol.TlsConstants.RecordHeaderLength + length;
        }

        return (records, fragmentSizes.ToArray());
    }
}
