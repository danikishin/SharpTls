using SharpTls.Handshake;
using SharpTls.Protocol;

namespace SharpTls.Tests.Handshake;

public sealed class HandshakeDeframerTests
{
    [Fact]
    public void ReassemblesMessageAcrossEveryByteBoundary()
    {
        var encoded = HandshakeMessage.Encode(HandshakeType.ServerHello, [1, 2, 3, 4, 5]);

        for (var split = 0; split < encoded.Length; split++)
        {
            var deframer = new HandshakeDeframer(1024);
            deframer.Append(encoded.AsSpan(0, split));
            Assert.False(deframer.TryRead(out _));
            deframer.Append(encoded.AsSpan(split));

            Assert.True(deframer.TryRead(out var message));
            Assert.NotNull(message);
            Assert.Equal(HandshakeType.ServerHello, message.Type);
            Assert.Equal([1, 2, 3, 4, 5], message.Body);
            Assert.Equal(encoded, message.Encoded);
            Assert.False(deframer.TryRead(out _));
        }
    }

    [Fact]
    public void ReadsCoalescedMessagesWithoutLosingBytes()
    {
        var first = HandshakeMessage.Encode(HandshakeType.EncryptedExtensions, []);
        var second = HandshakeMessage.Encode(HandshakeType.Finished, [9, 8, 7]);
        var deframer = new HandshakeDeframer(1024);
        deframer.Append([.. first, .. second]);

        Assert.True(deframer.TryRead(out var firstMessage));
        Assert.Equal(HandshakeType.EncryptedExtensions, firstMessage!.Type);
        Assert.True(deframer.TryRead(out var secondMessage));
        Assert.Equal(HandshakeType.Finished, secondMessage!.Type);
        Assert.Equal([9, 8, 7], secondMessage.Body);
    }

    [Fact]
    public void OversizedDeclaredMessageIsRejectedAfterHeader()
    {
        var deframer = new HandshakeDeframer(16);

        var exception = Assert.Throws<TlsProtocolException>(() =>
            deframer.Append([(byte)HandshakeType.Certificate, 0, 0, 17]));

        Assert.Equal(TlsAlertDescription.DecodeError, exception.Alert);
    }

    [Fact]
    public void PartialMessageAtEofIsRejected()
    {
        var deframer = new HandshakeDeframer(1024);
        deframer.Append([(byte)HandshakeType.ServerHello, 0, 0, 2, 1]);

        var exception = Assert.Throws<TlsProtocolException>(deframer.EnsureEmptyAtEndOfStream);
        Assert.Equal(TlsAlertDescription.DecodeError, exception.Alert);
    }

    [Fact]
    public void UnknownHandshakeTypeIsRejectedOnlyWhenComplete()
    {
        var deframer = new HandshakeDeframer(1024);
        deframer.Append([250, 0, 0, 0]);

        var exception = Assert.Throws<TlsProtocolException>(() => deframer.TryRead(out _));
        Assert.Equal(TlsAlertDescription.UnexpectedMessage, exception.Alert);
    }
}
