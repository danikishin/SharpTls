using System.Text;

namespace SharpTls.Tests.Diagnostics;

public sealed class NssKeyLogTests
{
    [Fact]
    public async Task SinkWritesExactNssLineAndSerializesConcurrentWriters()
    {
        using var output = new MemoryStream();
        using var sink = new TlsNssKeyLogSink(
            output,
            acknowledgeSecretExposure: true);
        var clientRandom = Enumerable.Range(0, 32).Select(value => (byte)value).ToArray();

        await sink.WriteSecretAsync(
            "CLIENT_RANDOM",
            clientRandom,
            new byte[] { 0xAB, 0xCD },
            CancellationToken.None);
        await Task.WhenAll(Enumerable.Range(0, 16).Select(index =>
            sink.WriteSecretAsync(
                "EXPORTER_SECRET",
                clientRandom,
                new byte[] { (byte)index },
                CancellationToken.None).AsTask()));

        var lines = Encoding.ASCII.GetString(output.ToArray())
            .Split('\n', StringSplitOptions.RemoveEmptyEntries);
        Assert.Equal(
            "CLIENT_RANDOM 000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f abcd",
            lines[0]);
        Assert.Equal(17, lines.Length);
        Assert.All(lines[1..], line =>
        {
            var fields = line.Split(' ');
            Assert.Equal(3, fields.Length);
            Assert.Equal("EXPORTER_SECRET", fields[0]);
            Assert.Equal(64, fields[1].Length);
            Assert.Equal(2, fields[2].Length);
        });
    }

    [Fact]
    public async Task SinkRequiresExplicitAcknowledgementWritableOutputAndValidKeys()
    {
        using var writable = new MemoryStream();
        Assert.Throws<ArgumentException>(() =>
            new TlsNssKeyLogSink(writable, acknowledgeSecretExposure: false));
        using var readOnly = new MemoryStream(new byte[1], writable: false);
        Assert.Throws<ArgumentException>(() =>
            new TlsNssKeyLogSink(readOnly, acknowledgeSecretExposure: true));

        using var sink = new TlsNssKeyLogSink(writable, acknowledgeSecretExposure: true);
        await Assert.ThrowsAsync<ArgumentException>(async () => await sink.WriteSecretAsync(
            "bad-label",
            new byte[32],
            new byte[32],
            CancellationToken.None));
    }

    [Fact]
    public async Task DisposedSinkRejectsWritesWithoutOwningCallerStreamByDefault()
    {
        using var output = new MemoryStream();
        var sink = new TlsNssKeyLogSink(output, acknowledgeSecretExposure: true);
        sink.Dispose();

        await Assert.ThrowsAsync<ObjectDisposedException>(async () =>
            await sink.WriteSecretAsync(
                "CLIENT_RANDOM",
                new byte[32],
                new byte[32],
                CancellationToken.None));
        output.WriteByte(1);
    }
}
