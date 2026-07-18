using SharpTls.Protocol;

namespace SharpTls.Handshake;

internal sealed class HandshakeDeframer
{
    private readonly int _maximumMessageSize;
    private byte[] _buffer;
    private int _count;

    internal HandshakeDeframer(int maximumMessageSize)
    {
        if (maximumMessageSize is < 1 or > 0xFFFFFF)
        {
            throw new ArgumentOutOfRangeException(nameof(maximumMessageSize));
        }

        _maximumMessageSize = maximumMessageSize;
        _buffer = new byte[Math.Min(maximumMessageSize + TlsConstants.HandshakeHeaderLength, 4096)];
    }

    internal int BufferedBytes => _count;

    internal void Append(ReadOnlySpan<byte> fragment)
    {
        var maximumBuffered = _maximumMessageSize + TlsConstants.HandshakeHeaderLength +
                              TlsConstants.MaxPlaintextLength;
        if (fragment.Length > maximumBuffered - _count)
        {
            throw TlsProtocolException.Decode("Buffered handshake input exceeds the configured limit.");
        }

        EnsureCapacity(_count + fragment.Length);
        fragment.CopyTo(_buffer.AsSpan(_count));
        _count += fragment.Length;

        ValidateAvailableHeader();
    }

    internal bool TryRead(out HandshakeMessage? message)
    {
        message = null;
        if (_count < TlsConstants.HandshakeHeaderLength)
        {
            return false;
        }

        var bodyLength = ReadBodyLength(_buffer);
        if (bodyLength > _maximumMessageSize)
        {
            throw TlsProtocolException.Decode(
                $"Handshake message length {bodyLength} exceeds the configured limit {_maximumMessageSize}.");
        }

        var encodedLength = TlsConstants.HandshakeHeaderLength + bodyLength;
        if (_count < encodedLength)
        {
            return false;
        }

        var encoded = _buffer.AsSpan(0, encodedLength).ToArray();
        var type = ParseHandshakeType(encoded[0]);
        var body = encoded.AsSpan(TlsConstants.HandshakeHeaderLength).ToArray();
        message = new HandshakeMessage(type, body, encoded);

        _count -= encodedLength;
        if (_count > 0)
        {
            Buffer.BlockCopy(_buffer, encodedLength, _buffer, 0, _count);
        }

        ValidateAvailableHeader();
        return true;
    }

    internal void EnsureEmptyAtEndOfStream()
    {
        if (_count != 0)
        {
            throw TlsProtocolException.Decode("Unexpected EOF inside a fragmented handshake message.");
        }
    }

    private void ValidateAvailableHeader()
    {
        if (_count >= TlsConstants.HandshakeHeaderLength && ReadBodyLength(_buffer) > _maximumMessageSize)
        {
            throw TlsProtocolException.Decode("Handshake message declares an oversized body.");
        }
    }

    private void EnsureCapacity(int needed)
    {
        if (needed <= _buffer.Length)
        {
            return;
        }

        var newLength = Math.Max(needed, Math.Min(_buffer.Length * 2, _maximumMessageSize +
            TlsConstants.HandshakeHeaderLength + TlsConstants.MaxPlaintextLength));
        Array.Resize(ref _buffer, newLength);
    }

    private static int ReadBodyLength(ReadOnlySpan<byte> header) =>
        (header[1] << 16) | (header[2] << 8) | header[3];

    private static HandshakeType ParseHandshakeType(byte value) => value switch
    {
        (byte)HandshakeType.HelloRequest => HandshakeType.HelloRequest,
        (byte)HandshakeType.ClientHello => HandshakeType.ClientHello,
        (byte)HandshakeType.ServerHello => HandshakeType.ServerHello,
        (byte)HandshakeType.NewSessionTicket => HandshakeType.NewSessionTicket,
        (byte)HandshakeType.EndOfEarlyData => HandshakeType.EndOfEarlyData,
        (byte)HandshakeType.EncryptedExtensions => HandshakeType.EncryptedExtensions,
        (byte)HandshakeType.Certificate => HandshakeType.Certificate,
        (byte)HandshakeType.ServerKeyExchange => HandshakeType.ServerKeyExchange,
        (byte)HandshakeType.CertificateRequest => HandshakeType.CertificateRequest,
        (byte)HandshakeType.ServerHelloDone => HandshakeType.ServerHelloDone,
        (byte)HandshakeType.CertificateVerify => HandshakeType.CertificateVerify,
        (byte)HandshakeType.ClientKeyExchange => HandshakeType.ClientKeyExchange,
        (byte)HandshakeType.CertificateStatus => HandshakeType.CertificateStatus,
        (byte)HandshakeType.CompressedCertificate => HandshakeType.CompressedCertificate,
        (byte)HandshakeType.Finished => HandshakeType.Finished,
        (byte)HandshakeType.KeyUpdate => HandshakeType.KeyUpdate,
        (byte)HandshakeType.MessageHash => HandshakeType.MessageHash,
        _ => throw TlsProtocolException.Unexpected($"Unknown handshake message type {value}."),
    };
}
