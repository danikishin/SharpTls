namespace SharpTls.Quic;

internal static class QuicVariableLengthInteger
{
    internal const ulong MaximumValue = (1UL << 62) - 1;

    internal static int GetEncodedLength(ulong value) => value switch
    {
        <= 63 => 1,
        <= 16_383 => 2,
        <= 1_073_741_823 => 4,
        <= MaximumValue => 8,
        _ => throw new ArgumentOutOfRangeException(nameof(value)),
    };

    internal static void Write(List<byte> destination, ulong value)
    {
        ArgumentNullException.ThrowIfNull(destination);
        var length = GetEncodedLength(value);
        Span<byte> encoded = stackalloc byte[8];
        for (var index = length - 1; index >= 0; index--)
        {
            encoded[index] = (byte)value;
            value >>= 8;
        }
        encoded[0] |= length switch
        {
            1 => (byte)0x00,
            2 => (byte)0x40,
            4 => (byte)0x80,
            8 => (byte)0xC0,
            _ => throw new InvalidOperationException(),
        };
        for (var index = 0; index < length; index++)
        {
            destination.Add(encoded[index]);
        }
    }

    internal static ulong Read(ReadOnlySpan<byte> source, ref int offset)
    {
        if ((uint)offset >= (uint)source.Length)
        {
            throw ParameterError("Truncated QUIC variable-length integer.");
        }
        var length = 1 << (source[offset] >> 6);
        if (source.Length - offset < length)
        {
            throw ParameterError("Truncated QUIC variable-length integer.");
        }
        ulong value = (ulong)(source[offset] & 0x3F);
        for (var index = 1; index < length; index++)
        {
            value = (value << 8) | source[offset + index];
        }
        offset += length;
        return value;
    }

    internal static byte[] Encode(ulong value)
    {
        var encoded = new List<byte>(GetEncodedLength(value));
        Write(encoded, value);
        return [.. encoded];
    }

    internal static ulong ReadExact(ReadOnlySpan<byte> source, string parameterName)
    {
        var offset = 0;
        var value = Read(source, ref offset);
        if (offset != source.Length)
        {
            throw ParameterError(
                $"QUIC transport parameter {parameterName} is not one exact variable-length integer.");
        }
        return value;
    }

    internal static TlsQuicTransportException ParameterError(string message) => new(
        TlsQuicTransportError.TransportParameterError,
        message);
}
