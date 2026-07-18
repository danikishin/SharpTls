using SharpTls.Protocol;

namespace SharpTls.IO;

internal ref struct TlsBinaryReader
{
    private readonly ReadOnlySpan<byte> _input;
    private int _offset;

    internal TlsBinaryReader(ReadOnlySpan<byte> input)
    {
        _input = input;
        _offset = 0;
    }

    internal readonly int Remaining => _input.Length - _offset;

    internal readonly bool End => _offset == _input.Length;

    internal byte ReadUInt8()
    {
        EnsureAvailable(1);
        return _input[_offset++];
    }

    internal ushort ReadUInt16()
    {
        EnsureAvailable(2);
        var value = (ushort)((_input[_offset] << 8) | _input[_offset + 1]);
        _offset += 2;
        return value;
    }

    internal int ReadUInt24()
    {
        EnsureAvailable(3);
        var value = (_input[_offset] << 16) |
                    (_input[_offset + 1] << 8) |
                    _input[_offset + 2];
        _offset += 3;
        return value;
    }

    internal uint ReadUInt32()
    {
        EnsureAvailable(4);
        var value = ((uint)_input[_offset] << 24) |
                    ((uint)_input[_offset + 1] << 16) |
                    ((uint)_input[_offset + 2] << 8) |
                    _input[_offset + 3];
        _offset += 4;
        return value;
    }

    internal ulong ReadUInt64()
    {
        var high = ReadUInt32();
        var low = ReadUInt32();
        return ((ulong)high << 32) | low;
    }

    internal ReadOnlySpan<byte> ReadBytes(int length)
    {
        if (length < 0)
        {
            throw TlsProtocolException.Decode("A TLS vector requested a negative length.");
        }

        EnsureAvailable(length);
        var result = _input.Slice(_offset, length);
        _offset += length;
        return result;
    }

    internal ReadOnlySpan<byte> ReadVector8(int maximumLength = byte.MaxValue)
    {
        var length = ReadUInt8();
        EnsureVectorLimit(length, maximumLength);
        return ReadBytes(length);
    }

    internal ReadOnlySpan<byte> ReadVector16(int maximumLength = ushort.MaxValue)
    {
        var length = ReadUInt16();
        EnsureVectorLimit(length, maximumLength);
        return ReadBytes(length);
    }

    internal ReadOnlySpan<byte> ReadVector24(int maximumLength = 0xFFFFFF)
    {
        var length = ReadUInt24();
        EnsureVectorLimit(length, maximumLength);
        return ReadBytes(length);
    }

    internal void EnsureEnd(string context)
    {
        if (!End)
        {
            throw TlsProtocolException.Decode($"{context} contains {Remaining} trailing byte(s).");
        }
    }

    private readonly void EnsureAvailable(int length)
    {
        if ((uint)length > (uint)Remaining)
        {
            throw TlsProtocolException.Decode(
                $"Truncated TLS input: requested {length} byte(s), only {Remaining} remain.");
        }
    }

    private static void EnsureVectorLimit(int length, int maximumLength)
    {
        if (maximumLength < 0 || length > maximumLength)
        {
            throw TlsProtocolException.Decode(
                $"TLS vector length {length} exceeds the configured limit {maximumLength}.");
        }
    }
}
