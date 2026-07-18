using System.Buffers;

namespace SharpTls.IO;

internal sealed class TlsBinaryWriter
{
    private readonly ArrayBufferWriter<byte> _buffer;

    internal TlsBinaryWriter(int initialCapacity = 256)
    {
        if (initialCapacity < 0)
        {
            throw new ArgumentOutOfRangeException(nameof(initialCapacity));
        }

        _buffer = new ArrayBufferWriter<byte>(initialCapacity);
    }

    internal int Length => _buffer.WrittenCount;

    internal ReadOnlySpan<byte> WrittenSpan => _buffer.WrittenSpan;

    internal void WriteUInt8(byte value)
    {
        var destination = _buffer.GetSpan(1);
        destination[0] = value;
        _buffer.Advance(1);
    }

    internal void WriteUInt16(ushort value)
    {
        var destination = _buffer.GetSpan(2);
        destination[0] = (byte)(value >> 8);
        destination[1] = (byte)value;
        _buffer.Advance(2);
    }

    internal void WriteUInt24(int value)
    {
        if ((uint)value > 0xFFFFFFu)
        {
            throw new ArgumentOutOfRangeException(nameof(value));
        }

        var destination = _buffer.GetSpan(3);
        destination[0] = (byte)(value >> 16);
        destination[1] = (byte)(value >> 8);
        destination[2] = (byte)value;
        _buffer.Advance(3);
    }

    internal void WriteUInt32(uint value)
    {
        var destination = _buffer.GetSpan(4);
        destination[0] = (byte)(value >> 24);
        destination[1] = (byte)(value >> 16);
        destination[2] = (byte)(value >> 8);
        destination[3] = (byte)value;
        _buffer.Advance(4);
    }

    internal void WriteUInt64(ulong value)
    {
        WriteUInt32((uint)(value >> 32));
        WriteUInt32((uint)value);
    }

    internal void WriteBytes(ReadOnlySpan<byte> value)
    {
        value.CopyTo(_buffer.GetSpan(value.Length));
        _buffer.Advance(value.Length);
    }

    internal void WriteVector8(ReadOnlySpan<byte> value)
    {
        if (value.Length > byte.MaxValue)
        {
            throw new ArgumentOutOfRangeException(nameof(value));
        }

        WriteUInt8((byte)value.Length);
        WriteBytes(value);
    }

    internal void WriteVector16(ReadOnlySpan<byte> value)
    {
        if (value.Length > ushort.MaxValue)
        {
            throw new ArgumentOutOfRangeException(nameof(value));
        }

        WriteUInt16((ushort)value.Length);
        WriteBytes(value);
    }

    internal void WriteVector24(ReadOnlySpan<byte> value)
    {
        if (value.Length > 0xFFFFFF)
        {
            throw new ArgumentOutOfRangeException(nameof(value));
        }

        WriteUInt24(value.Length);
        WriteBytes(value);
    }

    internal byte[] ToArray() => _buffer.WrittenSpan.ToArray();

    internal void Clear() => _buffer.Clear();
}
