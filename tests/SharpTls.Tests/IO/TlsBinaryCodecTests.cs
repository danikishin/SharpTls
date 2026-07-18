using SharpTls.IO;
using SharpTls.Protocol;

namespace SharpTls.Tests.IO;

public sealed class TlsBinaryCodecTests
{
    [Fact]
    public void IntegersAndVectorsRoundTripAtBoundaries()
    {
        var writer = new TlsBinaryWriter();
        writer.WriteUInt8(byte.MaxValue);
        writer.WriteUInt16(ushort.MaxValue);
        writer.WriteUInt24(0xFFFFFF);
        writer.WriteUInt32(uint.MaxValue);
        writer.WriteUInt64(ulong.MaxValue);
        writer.WriteVector8([1, 2, 3]);
        writer.WriteVector16([4, 5, 6, 7]);
        writer.WriteVector24([8, 9]);

        var reader = new TlsBinaryReader(writer.WrittenSpan);
        Assert.Equal(byte.MaxValue, reader.ReadUInt8());
        Assert.Equal(ushort.MaxValue, reader.ReadUInt16());
        Assert.Equal(0xFFFFFF, reader.ReadUInt24());
        Assert.Equal(uint.MaxValue, reader.ReadUInt32());
        Assert.Equal(ulong.MaxValue, reader.ReadUInt64());
        Assert.True(reader.ReadVector8().SequenceEqual(new byte[] { 1, 2, 3 }));
        Assert.True(reader.ReadVector16().SequenceEqual(new byte[] { 4, 5, 6, 7 }));
        Assert.True(reader.ReadVector24().SequenceEqual(new byte[] { 8, 9 }));
        reader.EnsureEnd("test vector");
    }

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(2)]
    public void TruncatedUInt24FailsClosed(int availableBytes)
    {
        var error = ReadUInt24(new byte[availableBytes]);
        Assert.Equal(TlsAlertDescription.DecodeError, error.Alert);
    }

    [Fact]
    public void DeclaredVectorLongerThanInputIsRejected()
    {
        var error = ReadVector16([0, 4, 1, 2]);
        Assert.Equal(TlsAlertDescription.DecodeError, error.Alert);
    }

    [Fact]
    public void VectorPolicyLimitIsCheckedBeforePayloadRead()
    {
        var error = ReadVector16([0, 3, 1, 2, 3], maximum: 2);
        Assert.Contains("configured limit", error.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void TrailingDataIsRejected()
    {
        var error = EnsureEnd([42]);
        Assert.Equal(TlsAlertDescription.DecodeError, error.Alert);
    }

    [Theory]
    [InlineData(-1)]
    [InlineData(0x1000000)]
    public void WriterRejectsOutOfRangeUInt24(int value)
    {
        var writer = new TlsBinaryWriter();
        Assert.Throws<ArgumentOutOfRangeException>(() => writer.WriteUInt24(value));
    }

    private static TlsProtocolException ReadUInt24(byte[] input)
    {
        try
        {
            var reader = new TlsBinaryReader(input);
            _ = reader.ReadUInt24();
            throw new Xunit.Sdk.XunitException("Expected a TLS protocol exception.");
        }
        catch (TlsProtocolException exception)
        {
            return exception;
        }
    }

    private static TlsProtocolException ReadVector16(byte[] input, int maximum = ushort.MaxValue)
    {
        try
        {
            var reader = new TlsBinaryReader(input);
            _ = reader.ReadVector16(maximum);
            throw new Xunit.Sdk.XunitException("Expected a TLS protocol exception.");
        }
        catch (TlsProtocolException exception)
        {
            return exception;
        }
    }

    private static TlsProtocolException EnsureEnd(byte[] input)
    {
        try
        {
            var reader = new TlsBinaryReader(input);
            reader.EnsureEnd("hostile input");
            throw new Xunit.Sdk.XunitException("Expected a TLS protocol exception.");
        }
        catch (TlsProtocolException exception)
        {
            return exception;
        }
    }
}
