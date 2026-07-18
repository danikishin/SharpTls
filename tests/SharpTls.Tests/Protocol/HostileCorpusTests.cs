using SharpTls.Certificates;
using SharpTls.Handshake;
using SharpTls.Protocol;
using SharpTls.Quic;

namespace SharpTls.Tests.Protocol;

public sealed class HostileCorpusTests
{
    [Fact]
    public void BoundedRandomInputsNeverEscapeAsImplementationExceptions()
    {
        var random = new Random(0x5A17_2026);
        using var offer = ClientHelloProfiles.ModernTls13.BuildSecure("example.com");

        for (var iteration = 0; iteration < 2_000; iteration++)
        {
            var input = new byte[random.Next(0, 513)];
            random.NextBytes(input);

            AssertProtocolBoundary(() => ServerHelloParser.Parse(input, offer));
            AssertProtocolBoundary(() =>
                EncryptedExtensionsParser.Parse(input, offer.Configuration));
            AssertProtocolBoundary(() =>
            {
                using var certificates = CertificateMessageParser.Parse(input, TlsLimits.Default);
            });
            AssertProtocolBoundary(() => ExerciseDeframer(input));
            AssertCaptureBoundary(() => ClientHelloCapture.Import(input));
            AssertJsonBoundary(() => ClientHelloSpecJson.Deserialize(input));
        }
    }

    private static void ExerciseDeframer(byte[] input)
    {
        var deframer = new HandshakeDeframer(maximumMessageSize: 1_024);
        var offset = 0;
        while (offset < input.Length)
        {
            var length = Math.Min((offset % 17) + 1, input.Length - offset);
            deframer.Append(input.AsSpan(offset, length));
            while (deframer.TryRead(out _))
            {
            }
            offset += length;
        }

        deframer.EnsureEmptyAtEndOfStream();
    }

    private static void AssertProtocolBoundary(Action action)
    {
        try
        {
            action();
        }
        catch (TlsProtocolException)
        {
            // Rejection is the expected outcome for almost every corpus member.
        }
    }

    private static void AssertCaptureBoundary(Action action)
    {
        try
        {
            action();
        }
        catch (TlsProtocolException)
        {
            // Structurally invalid TLS wire data.
        }
        catch (TlsQuicTransportException)
        {
            // Invalid QUIC transport parameters embedded in a captured ClientHello.
        }
        catch (NotSupportedException)
        {
            // Structurally valid fields outside the currently executable feature set.
        }
    }

    private static void AssertJsonBoundary(Action action)
    {
        try
        {
            action();
        }
        catch (InvalidDataException)
        {
            // Invalid or unsupported interchange data must stay at this API boundary.
        }
    }
}
