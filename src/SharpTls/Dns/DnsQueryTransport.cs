using System.Buffers;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;

namespace SharpTls.Dns;

internal interface IDnsQueryTransport
{
    Task<DnsTransportResponse> QueryAsync(
        IPEndPoint server,
        ReadOnlyMemory<byte> query,
        int maximumResponseSize,
        CancellationToken cancellationToken);
}

internal sealed record DnsTransportResponse(
    byte[] Message,
    uint CacheAgeSeconds = 0,
    uint? TtlCapSeconds = null);

internal sealed class SocketDnsQueryTransport : IDnsQueryTransport
{
    public async Task<DnsTransportResponse> QueryAsync(
        IPEndPoint server,
        ReadOnlyMemory<byte> query,
        int maximumResponseSize,
        CancellationToken cancellationToken)
    {
        var udpResponse = await QueryUdpAsync(
            server,
            query,
            maximumResponseSize,
            cancellationToken).ConfigureAwait(false);
        if (!DnsMessageParser.HasTruncatedFlag(udpResponse))
        {
            return new DnsTransportResponse(udpResponse);
        }

        var tcpResponse = await QueryTcpAsync(
            server,
            query,
            maximumResponseSize,
            cancellationToken).ConfigureAwait(false);
        return new DnsTransportResponse(tcpResponse);
    }

    private static async Task<byte[]> QueryUdpAsync(
        IPEndPoint server,
        ReadOnlyMemory<byte> query,
        int maximumResponseSize,
        CancellationToken cancellationToken)
    {
        using var socket = new Socket(server.AddressFamily, SocketType.Dgram, ProtocolType.Udp);
        await socket.ConnectAsync(server, cancellationToken).ConfigureAwait(false);
        var sent = await socket.SendAsync(query, SocketFlags.None, cancellationToken).ConfigureAwait(false);
        if (sent != query.Length)
        {
            throw new IOException("The DNS UDP query was only partially sent.");
        }

        var buffer = ArrayPool<byte>.Shared.Rent(maximumResponseSize + 1);
        try
        {
            var received = await socket.ReceiveAsync(
                buffer.AsMemory(0, maximumResponseSize + 1),
                SocketFlags.None,
                cancellationToken).ConfigureAwait(false);
            if (received > maximumResponseSize)
            {
                throw TlsEchDnsException.Malformed(
                    "The DNS UDP response exceeds the configured receive limit.");
            }
            return buffer.AsSpan(0, received).ToArray();
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(buffer);
        }
    }

    private static async Task<byte[]> QueryTcpAsync(
        IPEndPoint server,
        ReadOnlyMemory<byte> query,
        int maximumResponseSize,
        CancellationToken cancellationToken)
    {
        using var socket = new Socket(server.AddressFamily, SocketType.Stream, ProtocolType.Tcp);
        await socket.ConnectAsync(server, cancellationToken).ConfigureAwait(false);
        await using var stream = new NetworkStream(socket, ownsSocket: false);

        var prefix = new byte[2]
        {
            (byte)(query.Length >> 8),
            (byte)query.Length,
        };
        await stream.WriteAsync(prefix, cancellationToken).ConfigureAwait(false);
        await stream.WriteAsync(query, cancellationToken).ConfigureAwait(false);

        await ReadExactlyAsync(stream, prefix, cancellationToken).ConfigureAwait(false);
        var responseLength = (prefix[0] << 8) | prefix[1];
        if (responseLength < 12 || responseLength > maximumResponseSize)
        {
            throw TlsEchDnsException.Malformed(
                "The DNS TCP response length is outside the configured bounds.");
        }

        var response = new byte[responseLength];
        await ReadExactlyAsync(stream, response, cancellationToken).ConfigureAwait(false);
        return response;
    }

    private static async Task ReadExactlyAsync(
        Stream stream,
        Memory<byte> destination,
        CancellationToken cancellationToken)
    {
        var offset = 0;
        while (offset < destination.Length)
        {
            var read = await stream.ReadAsync(destination[offset..], cancellationToken).ConfigureAwait(false);
            if (read == 0)
            {
                throw new EndOfStreamException("The DNS TCP response ended before its advertised length.");
            }
            offset += read;
        }
    }
}

internal static class DnsNameServerDiscovery
{
    internal static IPEndPoint[] GetSystemNameServers()
    {
        var result = new List<IPEndPoint>();
        foreach (var networkInterface in NetworkInterface.GetAllNetworkInterfaces())
        {
            if (networkInterface.OperationalStatus != OperationalStatus.Up)
            {
                continue;
            }

            IPInterfaceProperties properties;
            try
            {
                properties = networkInterface.GetIPProperties();
            }
            catch (NetworkInformationException)
            {
                continue;
            }

            foreach (var address in properties.DnsAddresses)
            {
                if (address.AddressFamily is not (
                        AddressFamily.InterNetwork or AddressFamily.InterNetworkV6) ||
                    address.Equals(IPAddress.Any) || address.Equals(IPAddress.IPv6Any) ||
                    address.IsIPv6Multicast)
                {
                    continue;
                }
                result.Add(new IPEndPoint(address, 53));
            }
        }

        return result.Distinct().Take(32).ToArray();
    }
}
