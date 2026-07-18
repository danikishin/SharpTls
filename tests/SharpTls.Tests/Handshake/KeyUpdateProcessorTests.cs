using SharpTls.Handshake;
using SharpTls.Protocol;

namespace SharpTls.Tests.Handshake;

public sealed class KeyUpdateProcessorTests
{
    [Theory]
    [InlineData(0, false)]
    [InlineData(1, true)]
    public void DefinedRequestValuesRoundTrip(byte value, bool expected)
    {
        Assert.Equal(expected, KeyUpdateProcessor.ParseRequestUpdate([value]));

        var encoded = KeyUpdateProcessor.Encode(expected);
        Assert.Equal(new byte[] { (byte)HandshakeType.KeyUpdate, 0, 0, 1, value }, encoded);
    }

    [Theory]
    [InlineData(new byte[] { })]
    [InlineData(new byte[] { 0, 0 })]
    public void InvalidBodyLengthIsDecodeError(byte[] body)
    {
        var exception = Assert.Throws<TlsProtocolException>(() =>
            KeyUpdateProcessor.ParseRequestUpdate(body));

        Assert.Equal(TlsAlertDescription.DecodeError, exception.Alert);
    }

    [Fact]
    public void UndefinedRequestValueIsIllegalParameter()
    {
        var exception = Assert.Throws<TlsProtocolException>(() =>
            KeyUpdateProcessor.ParseRequestUpdate([2]));

        Assert.Equal(TlsAlertDescription.IllegalParameter, exception.Alert);
    }

    [Fact]
    public void SendingEpochIsBoundedToFortyEightBits()
    {
        Assert.True(KeyUpdateProcessor.CanAdvanceSendingEpoch(0));
        Assert.True(KeyUpdateProcessor.CanAdvanceSendingEpoch(
            KeyUpdateProcessor.MaximumSendingEpoch - 1));
        Assert.False(KeyUpdateProcessor.CanAdvanceSendingEpoch(
            KeyUpdateProcessor.MaximumSendingEpoch));
        Assert.False(KeyUpdateProcessor.CanAdvanceSendingEpoch(ulong.MaxValue));
    }
}
