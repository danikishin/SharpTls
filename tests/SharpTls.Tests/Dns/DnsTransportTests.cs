using System.Net;
using System.Net.Sockets;
using SharpTls.Dns;

namespace SharpTls.Tests.Dns;

public sealed class DnsTransportTests
{
    [Fact]
    public async Task TruncatedUdpAnswerFallsBackToTcpAndHandlesFragmentedTcpResponse()
    {
        using var cancellation = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        using var udp = new UdpClient(new IPEndPoint(IPAddress.Loopback, port));

        var udpServer = Task.Run(async () =>
        {
            var request = await udp.ReceiveAsync(cancellation.Token);
            var truncated = DnsTestMessages.CreateNoDataResponse(request.Buffer);
            truncated[2] |= 0x02; // TC
            await udp.SendAsync(truncated, request.RemoteEndPoint, cancellation.Token);
        }, cancellation.Token);
        var tcpServer = Task.Run(async () =>
        {
            using var client = await listener.AcceptTcpClientAsync(cancellation.Token);
            await using var stream = client.GetStream();
            var prefix = new byte[2];
            await ReadExactlyAsync(stream, prefix, cancellation.Token);
            var queryLength = (prefix[0] << 8) | prefix[1];
            var query = new byte[queryLength];
            await ReadExactlyAsync(stream, query, cancellation.Token);
            var response = DnsTestMessages.CreateNoDataResponse(query);
            var encodedLength = new byte[]
            {
                (byte)(response.Length >> 8),
                (byte)response.Length,
            };

            await stream.WriteAsync(encodedLength.AsMemory(0, 1), cancellation.Token);
            await stream.WriteAsync(encodedLength.AsMemory(1, 1), cancellation.Token);
            for (var offset = 0; offset < response.Length; offset += 3)
            {
                await stream.WriteAsync(
                    response.AsMemory(offset, Math.Min(3, response.Length - offset)),
                    cancellation.Token);
            }
        }, cancellation.Token);

        var query = DnsMessageWriter.CreateHttpsQuery(7, "example.com", 1232, false);
        var transport = new SocketDnsQueryTransport();
        var result = await transport.QueryAsync(
            new IPEndPoint(IPAddress.Loopback, port),
            query,
            ushort.MaxValue,
            cancellation.Token);

        await Task.WhenAll(udpServer, tcpServer);
        var parsed = DnsMessageParser.ParseHttpsResponse(
            result.Message,
            7,
            "example.com",
            ushort.MaxValue,
            8);
        Assert.False(parsed.IsTruncated);
        Assert.Equal(0, parsed.ResponseCode);
        listener.Stop();
    }

    [Fact]
    public async Task TcpFallbackRejectsAdvertisedResponseBeyondTheConfiguredLimit()
    {
        using var cancellation = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        using var udp = new UdpClient(new IPEndPoint(IPAddress.Loopback, port));

        var udpServer = Task.Run(async () =>
        {
            var request = await udp.ReceiveAsync(cancellation.Token);
            var truncated = DnsTestMessages.CreateNoDataResponse(request.Buffer);
            truncated[2] |= 0x02;
            await udp.SendAsync(truncated, request.RemoteEndPoint, cancellation.Token);
        }, cancellation.Token);
        var tcpServer = Task.Run(async () =>
        {
            using var client = await listener.AcceptTcpClientAsync(cancellation.Token);
            await using var stream = client.GetStream();
            var prefix = new byte[2];
            await ReadExactlyAsync(stream, prefix, cancellation.Token);
            var query = new byte[(prefix[0] << 8) | prefix[1]];
            await ReadExactlyAsync(stream, query, cancellation.Token);
            await stream.WriteAsync(new byte[] { 0x02, 0x01 }, cancellation.Token);
        }, cancellation.Token);

        var transport = new SocketDnsQueryTransport();
        await Assert.ThrowsAsync<TlsEchDnsException>(() => transport.QueryAsync(
            new IPEndPoint(IPAddress.Loopback, port),
            DnsMessageWriter.CreateHttpsQuery(7, "example.com", 1232, false),
            512,
            cancellation.Token));
        await Task.WhenAll(udpServer, tcpServer);
        listener.Stop();
    }

    private static async Task ReadExactlyAsync(
        Stream stream,
        Memory<byte> destination,
        CancellationToken cancellationToken)
    {
        var offset = 0;
        while (offset < destination.Length)
        {
            var read = await stream.ReadAsync(destination[offset..], cancellationToken);
            if (read == 0)
            {
                throw new EndOfStreamException();
            }
            offset += read;
        }
    }
}
