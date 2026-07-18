using System.Globalization;
using System.Net;
using System.Net.Sockets;
using System.Text;

namespace SharpTls.Dns;

internal static class DnsQueryTransportFactory
{
    internal static IDnsQueryTransport Create(TlsEchDnsResolverConfiguration configuration) =>
        configuration.ProtectedTransport switch
        {
            null => new SocketDnsQueryTransport(),
            DnsOverTlsConfiguration dnsOverTls => new TlsDnsQueryTransport(dnsOverTls),
            DnsOverHttpsConfiguration dnsOverHttps =>
                new HttpsDnsQueryTransport(dnsOverHttps),
            _ => throw new NotSupportedException("The protected DNS transport is unsupported."),
        };
}

internal sealed class TlsDnsQueryTransport : IDnsQueryTransport
{
    private readonly DnsOverTlsConfiguration _configuration;

    internal TlsDnsQueryTransport(DnsOverTlsConfiguration configuration)
    {
        _configuration = configuration ?? throw new ArgumentNullException(nameof(configuration));
    }

    public async Task<DnsTransportResponse> QueryAsync(
        IPEndPoint server,
        ReadOnlyMemory<byte> query,
        int maximumResponseSize,
        CancellationToken cancellationToken)
    {
        DnsTransportIo.ValidateQuery(query, maximumResponseSize);
        using var socket = new Socket(server.AddressFamily, SocketType.Stream, ProtocolType.Tcp)
        {
            NoDelay = true,
        };
        await socket.ConnectAsync(server, cancellationToken).ConfigureAwait(false);
        await using var network = new NetworkStream(socket, ownsSocket: false);
        await using var client = CreateClient(
            _configuration.ResolverName,
            _configuration.ClientHello,
            _configuration.CertificateValidation);
        await client.AuthenticateAsync(
            network,
            _configuration.ResolverName,
            leaveOpen: true,
            cancellationToken).ConfigureAwait(false);
        await using var application = client.OpenApplicationStream(leaveClientOpen: true);

        var request = DnsTransportIo.FrameDnsMessage(query.Span);
        try
        {
            await application.WriteAsync(request, cancellationToken).ConfigureAwait(false);
            var response = await DnsTransportIo.ReadFramedDnsMessageAsync(
                application,
                maximumResponseSize,
                cancellationToken).ConfigureAwait(false);
            return new DnsTransportResponse(response);
        }
        finally
        {
            Array.Clear(request);
        }
    }

    private static CustomTlsClient CreateClient(
        string resolverName,
        ClientHelloProfile profile,
        DnsCertificateValidationConfiguration certificateValidation)
    {
        var validation = certificateValidation.CreateOptions(out var temporaryRoots);
        try
        {
            return new CustomTlsClient(new CustomTlsClientOptions
            {
                ServerName = resolverName,
                ClientHello = profile,
                CertificateValidation = validation,
            });
        }
        finally
        {
            foreach (var root in temporaryRoots)
            {
                root.Dispose();
            }
        }
    }
}

internal sealed class HttpsDnsQueryTransport : IDnsQueryTransport
{
    private readonly DnsOverHttpsConfiguration _configuration;

    internal HttpsDnsQueryTransport(DnsOverHttpsConfiguration configuration)
    {
        _configuration = configuration ?? throw new ArgumentNullException(nameof(configuration));
    }

    public async Task<DnsTransportResponse> QueryAsync(
        IPEndPoint server,
        ReadOnlyMemory<byte> query,
        int maximumResponseSize,
        CancellationToken cancellationToken)
    {
        DnsTransportIo.ValidateQuery(query, maximumResponseSize);
        using var socket = new Socket(server.AddressFamily, SocketType.Stream, ProtocolType.Tcp)
        {
            NoDelay = true,
        };
        await socket.ConnectAsync(server, cancellationToken).ConfigureAwait(false);
        await using var network = new NetworkStream(socket, ownsSocket: false);
        await using var client = CreateClient();
        await client.AuthenticateAsync(
            network,
            _configuration.ResolverName,
            leaveOpen: true,
            cancellationToken).ConfigureAwait(false);
        if (client.NegotiatedApplicationProtocol is not (null or "http/1.1"))
        {
            throw new TlsEchDnsException(
                TlsEchDnsErrorKind.TransportFailure,
                "The DoH server selected an unsupported application protocol.");
        }
        await using var application = client.OpenApplicationStream(leaveClientOpen: true);

        var request = CreateRequest(query.Span);
        try
        {
            await application.WriteAsync(request, cancellationToken).ConfigureAwait(false);
            return await DnsHttp11ResponseReader.ReadAsync(
                application,
                maximumResponseSize,
                _configuration.MaximumResponseHeaderSize,
                cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            Array.Clear(request);
        }
    }

    private byte[] CreateRequest(ReadOnlySpan<byte> query)
    {
        var header = Encoding.ASCII.GetBytes(
            $"POST {_configuration.PathAndQuery} HTTP/1.1\r\n" +
            $"Host: {_configuration.Authority}\r\n" +
            "Accept: application/dns-message\r\n" +
            "Content-Type: application/dns-message\r\n" +
            $"Content-Length: {query.Length.ToString(CultureInfo.InvariantCulture)}\r\n" +
            "Connection: close\r\n\r\n");
        var request = new byte[checked(header.Length + query.Length)];
        header.CopyTo(request, 0);
        query.CopyTo(request.AsSpan(header.Length));
        Array.Clear(header);
        return request;
    }

    private CustomTlsClient CreateClient()
    {
        var validation = _configuration.CertificateValidation.CreateOptions(
            out var temporaryRoots);
        try
        {
            return new CustomTlsClient(new CustomTlsClientOptions
            {
                ServerName = _configuration.ResolverName,
                ClientHello = _configuration.ClientHello,
                CertificateValidation = validation,
            });
        }
        finally
        {
            foreach (var root in temporaryRoots)
            {
                root.Dispose();
            }
        }
    }
}

internal static class DnsTransportIo
{
    internal static void ValidateQuery(ReadOnlyMemory<byte> query, int maximumResponseSize)
    {
        if (query.Length is < 12 or > ushort.MaxValue)
        {
            throw new ArgumentOutOfRangeException(nameof(query));
        }
        if (maximumResponseSize is < 12 or > ushort.MaxValue)
        {
            throw new ArgumentOutOfRangeException(nameof(maximumResponseSize));
        }
    }

    internal static byte[] FrameDnsMessage(ReadOnlySpan<byte> message)
    {
        var framed = new byte[checked(message.Length + 2)];
        framed[0] = (byte)(message.Length >> 8);
        framed[1] = (byte)message.Length;
        message.CopyTo(framed.AsSpan(2));
        return framed;
    }

    internal static async Task<byte[]> ReadFramedDnsMessageAsync(
        Stream stream,
        int maximumResponseSize,
        CancellationToken cancellationToken)
    {
        var prefix = new byte[2];
        await ReadExactlyAsync(stream, prefix, cancellationToken).ConfigureAwait(false);
        var length = (prefix[0] << 8) | prefix[1];
        if (length < 12 || length > maximumResponseSize)
        {
            throw TlsEchDnsException.Malformed(
                "The protected DNS response length is outside the configured bounds.");
        }
        var response = new byte[length];
        await ReadExactlyAsync(stream, response, cancellationToken).ConfigureAwait(false);
        return response;
    }

    internal static async Task ReadExactlyAsync(
        Stream stream,
        Memory<byte> destination,
        CancellationToken cancellationToken)
    {
        var offset = 0;
        while (offset < destination.Length)
        {
            var read = await stream.ReadAsync(destination[offset..], cancellationToken)
                .ConfigureAwait(false);
            if (read == 0)
            {
                throw new EndOfStreamException(
                    "The protected DNS response ended before its advertised length.");
            }
            offset += read;
        }
    }
}

internal static class DnsHttp11ResponseReader
{
    private static readonly byte[] HeaderTerminator = "\r\n\r\n"u8.ToArray();

    internal static async Task<DnsTransportResponse> ReadAsync(
        Stream stream,
        int maximumResponseSize,
        int maximumHeaderSize,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(stream);
        if (maximumResponseSize is < 12 or > ushort.MaxValue)
        {
            throw new ArgumentOutOfRangeException(nameof(maximumResponseSize));
        }
        if (maximumHeaderSize is < 1024 or > 64 * 1024)
        {
            throw new ArgumentOutOfRangeException(nameof(maximumHeaderSize));
        }

        var received = new List<byte>(Math.Min(maximumHeaderSize, 4096));
        var scratch = new byte[4096];
        int terminatorIndex;
        while (true)
        {
            var read = await stream.ReadAsync(scratch, cancellationToken).ConfigureAwait(false);
            if (read == 0)
            {
                throw new EndOfStreamException("The DoH response ended before its HTTP headers.");
            }
            for (var index = 0; index < read; index++)
            {
                received.Add(scratch[index]);
            }
            terminatorIndex = IndexOf(received, HeaderTerminator);
            if (terminatorIndex >= 0)
            {
                if (terminatorIndex + HeaderTerminator.Length > maximumHeaderSize)
                {
                    throw TlsEchDnsException.Malformed(
                        "The DoH response headers exceed the configured limit.");
                }
                break;
            }
            if (received.Count > maximumHeaderSize)
            {
                throw TlsEchDnsException.Malformed(
                    "The DoH response headers exceed the configured limit.");
            }
        }

        var headerLength = terminatorIndex + HeaderTerminator.Length;
        var headerBytes = received.GetRange(0, headerLength).ToArray();
        var initialBody = received.Skip(headerLength).ToArray();
        received.Clear();
        var headers = ParseHeaders(headerBytes);
        Array.Clear(headerBytes);
        using var bodyReader = new BufferedHttpBodyReader(stream, initialBody);

        var body = headers.TransferEncodingChunked
            ? await ReadChunkedAsync(
                bodyReader,
                maximumResponseSize,
                maximumHeaderSize,
                cancellationToken).ConfigureAwait(false)
            : headers.ContentLength.HasValue
                ? await ReadContentLengthAsync(
                    bodyReader,
                    headers.ContentLength.Value,
                    maximumResponseSize,
                    cancellationToken).ConfigureAwait(false)
                : await ReadToEndAsync(
                    bodyReader,
                    maximumResponseSize,
                    cancellationToken).ConfigureAwait(false);
        if (body.Length < 12)
        {
            throw TlsEchDnsException.Malformed("The DoH response body is not a DNS message.");
        }

        var ttlCap = headers.CacheMaximumAgeSeconds.HasValue
            ? headers.CacheMaximumAgeSeconds.Value > headers.AgeSeconds
                ? headers.CacheMaximumAgeSeconds.Value - headers.AgeSeconds
                : 0
            : (uint?)null;
        return new DnsTransportResponse(body, headers.AgeSeconds, ttlCap);
    }

    private static DnsHttpResponseHeaders ParseHeaders(ReadOnlySpan<byte> encoded)
    {
        foreach (var value in encoded)
        {
            if (value is not (9 or 10 or 13) && (value < 0x20 || value > 0x7E))
            {
                throw TlsEchDnsException.Malformed(
                    "The DoH response contains a non-ASCII or control header byte.");
            }
        }
        var lines = Encoding.ASCII.GetString(encoded).Split("\r\n", StringSplitOptions.None);
        var status = lines[0].Split(' ', StringSplitOptions.RemoveEmptyEntries);
        if (status.Length < 2 || status[0] != "HTTP/1.1" ||
            status[1].Length != 3 || !int.TryParse(
                status[1],
                NumberStyles.None,
                CultureInfo.InvariantCulture,
                out var statusCode))
        {
            throw TlsEchDnsException.Malformed("The DoH HTTP status line is malformed.");
        }
        if (statusCode is < 200 or > 299)
        {
            throw new TlsEchDnsException(
                TlsEchDnsErrorKind.TransportFailure,
                $"The DoH server returned HTTP status {statusCode}.");
        }

        var values = new Dictionary<string, List<string>>(StringComparer.OrdinalIgnoreCase);
        for (var index = 1; index < lines.Length - 2; index++)
        {
            var line = lines[index];
            if (line.Length == 0 || char.IsWhiteSpace(line[0]))
            {
                throw TlsEchDnsException.Malformed(
                    "The DoH response contains an empty or folded HTTP header.");
            }
            var colon = line.IndexOf(':');
            if (colon <= 0 || line.AsSpan(0, colon).Contains(' ') ||
                line.AsSpan(0, colon).Contains('\t'))
            {
                throw TlsEchDnsException.Malformed("A DoH response header is malformed.");
            }
            var name = line[..colon];
            if (name.Any(character => !IsTokenCharacter(character)))
            {
                throw TlsEchDnsException.Malformed("A DoH response header name is invalid.");
            }
            if (!values.TryGetValue(name, out var list))
            {
                list = [];
                values.Add(name, list);
            }
            list.Add(line[(colon + 1)..].Trim(' ', '\t'));
        }

        var contentType = GetRequiredSingleton(values, "content-type");
        if (!string.Equals(
                contentType,
                "application/dns-message",
                StringComparison.OrdinalIgnoreCase))
        {
            throw TlsEchDnsException.Malformed(
                "The DoH response Content-Type is not application/dns-message.");
        }

        var contentLengthText = GetOptionalSingleton(values, "content-length");
        int? contentLength = null;
        if (contentLengthText is not null)
        {
            if (!int.TryParse(
                    contentLengthText,
                    NumberStyles.None,
                    CultureInfo.InvariantCulture,
                    out var parsedLength) || parsedLength < 0)
            {
                throw TlsEchDnsException.Malformed(
                    "The DoH response Content-Length is invalid.");
            }
            contentLength = parsedLength;
        }

        var transferEncoding = GetOptionalSingleton(values, "transfer-encoding");
        var chunked = transferEncoding is not null;
        if (chunked && (!string.Equals(
                transferEncoding,
                "chunked",
                StringComparison.OrdinalIgnoreCase) || contentLength.HasValue))
        {
            throw TlsEchDnsException.Malformed(
                "The DoH response uses ambiguous or unsupported HTTP body framing.");
        }

        var age = ParseOptionalUInt32(GetOptionalSingleton(values, "age"), "Age");
        var maxAge = ParseCacheMaximumAge(values);
        return new DnsHttpResponseHeaders(contentLength, chunked, age, maxAge);
    }

    private static async Task<byte[]> ReadContentLengthAsync(
        BufferedHttpBodyReader reader,
        int contentLength,
        int maximumResponseSize,
        CancellationToken cancellationToken)
    {
        if (contentLength < 12 || contentLength > maximumResponseSize)
        {
            throw TlsEchDnsException.Malformed(
                "The DoH Content-Length is outside the configured DNS bounds.");
        }
        var body = new byte[contentLength];
        await reader.ReadExactlyAsync(body, cancellationToken).ConfigureAwait(false);
        return body;
    }

    private static async Task<byte[]> ReadChunkedAsync(
        BufferedHttpBodyReader reader,
        int maximumResponseSize,
        int maximumTrailerSize,
        CancellationToken cancellationToken)
    {
        var output = new List<byte>();
        while (true)
        {
            var line = await reader.ReadAsciiLineAsync(4096, cancellationToken)
                .ConfigureAwait(false);
            var extension = line.IndexOf(';');
            var sizeText = (extension >= 0 ? line[..extension] : line).Trim();
            if (sizeText.Length is 0 or > 8 || !uint.TryParse(
                    sizeText,
                    NumberStyles.AllowHexSpecifier,
                    CultureInfo.InvariantCulture,
                    out var chunkSize))
            {
                throw TlsEchDnsException.Malformed("A DoH chunk size is invalid.");
            }
            if (chunkSize == 0)
            {
                var trailerBytes = 0;
                while (true)
                {
                    var trailer = await reader.ReadAsciiLineAsync(
                        maximumTrailerSize,
                        cancellationToken).ConfigureAwait(false);
                    trailerBytes = checked(trailerBytes + trailer.Length + 2);
                    if (trailerBytes > maximumTrailerSize ||
                        (trailer.Length != 0 &&
                         (char.IsWhiteSpace(trailer[0]) || trailer.IndexOf(':') <= 0)))
                    {
                        throw TlsEchDnsException.Malformed("The DoH trailers are malformed or oversized.");
                    }
                    if (trailer.Length == 0)
                    {
                        return output.ToArray();
                    }
                }
            }
            if (chunkSize > int.MaxValue ||
                output.Count + (long)chunkSize > maximumResponseSize)
            {
                throw TlsEchDnsException.Malformed(
                    "The chunked DoH body exceeds the configured DNS limit.");
            }
            var chunk = new byte[(int)chunkSize];
            await reader.ReadExactlyAsync(chunk, cancellationToken).ConfigureAwait(false);
            output.AddRange(chunk);
            Array.Clear(chunk);
            var terminator = new byte[2];
            await reader.ReadExactlyAsync(terminator, cancellationToken).ConfigureAwait(false);
            if (!terminator.AsSpan().SequenceEqual("\r\n"u8))
            {
                throw TlsEchDnsException.Malformed("A DoH chunk lacks its CRLF terminator.");
            }
        }
    }

    private static async Task<byte[]> ReadToEndAsync(
        BufferedHttpBodyReader reader,
        int maximumResponseSize,
        CancellationToken cancellationToken)
    {
        var output = new List<byte>();
        var buffer = new byte[4096];
        while (true)
        {
            var read = await reader.ReadAsync(buffer, cancellationToken).ConfigureAwait(false);
            if (read == 0)
            {
                return output.ToArray();
            }
            if (output.Count + (long)read > maximumResponseSize)
            {
                throw TlsEchDnsException.Malformed(
                    "The close-delimited DoH body exceeds the configured DNS limit.");
            }
            for (var index = 0; index < read; index++)
            {
                output.Add(buffer[index]);
            }
        }
    }

    private static uint ParseOptionalUInt32(string? value, string headerName)
    {
        if (value is null)
        {
            return 0;
        }
        if (!uint.TryParse(value, NumberStyles.None, CultureInfo.InvariantCulture, out var parsed))
        {
            throw TlsEchDnsException.Malformed($"The DoH {headerName} header is invalid.");
        }
        return parsed;
    }

    private static uint? ParseCacheMaximumAge(Dictionary<string, List<string>> headers)
    {
        if (!headers.TryGetValue("cache-control", out var values))
        {
            return null;
        }
        uint? result = null;
        foreach (var directive in values.SelectMany(value => value.Split(',')))
        {
            var trimmed = directive.Trim();
            if (!trimmed.StartsWith("max-age=", StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }
            var encoded = trimmed[8..].Trim();
            if (encoded.Length >= 2 && encoded[0] == '"' && encoded[^1] == '"')
            {
                encoded = encoded[1..^1];
            }
            if (!uint.TryParse(
                    encoded,
                    NumberStyles.None,
                    CultureInfo.InvariantCulture,
                    out var maxAge))
            {
                throw TlsEchDnsException.Malformed(
                    "The DoH Cache-Control max-age directive is invalid.");
            }
            if (result.HasValue && result.Value != maxAge)
            {
                throw TlsEchDnsException.Malformed(
                    "The DoH response contains conflicting max-age directives.");
            }
            result = maxAge;
        }
        return result;
    }

    private static string GetRequiredSingleton(
        Dictionary<string, List<string>> headers,
        string name) => GetOptionalSingleton(headers, name) ??
        throw TlsEchDnsException.Malformed($"The DoH response omits {name}.");

    private static string? GetOptionalSingleton(
        Dictionary<string, List<string>> headers,
        string name)
    {
        if (!headers.TryGetValue(name, out var values))
        {
            return null;
        }
        if (values.Count != 1)
        {
            throw TlsEchDnsException.Malformed(
                $"The DoH response contains duplicate {name} headers.");
        }
        return values[0];
    }

    private static bool IsTokenCharacter(char value) =>
        char.IsAsciiLetterOrDigit(value) || value is
            '!' or '#' or '$' or '%' or '&' or '\'' or '*' or '+' or '-' or '.' or
            '^' or '_' or '`' or '|' or '~';

    private static int IndexOf(List<byte> value, ReadOnlySpan<byte> pattern)
    {
        for (var offset = Math.Max(0, value.Count - pattern.Length - 4096);
             offset <= value.Count - pattern.Length;
             offset++)
        {
            var matches = true;
            for (var index = 0; index < pattern.Length; index++)
            {
                if (value[offset + index] != pattern[index])
                {
                    matches = false;
                    break;
                }
            }
            if (matches)
            {
                return offset;
            }
        }
        return -1;
    }

    private sealed record DnsHttpResponseHeaders(
        int? ContentLength,
        bool TransferEncodingChunked,
        uint AgeSeconds,
        uint? CacheMaximumAgeSeconds);

    private sealed class BufferedHttpBodyReader : IDisposable
    {
        private readonly Stream _stream;
        private readonly byte[] _singleByte = new byte[1];
        private byte[]? _initial;
        private int _initialOffset;

        internal BufferedHttpBodyReader(Stream stream, byte[] initial)
        {
            _stream = stream;
            _initial = initial;
        }

        internal async ValueTask<int> ReadAsync(
            Memory<byte> destination,
            CancellationToken cancellationToken)
        {
            if (_initial is not null)
            {
                var available = _initial.Length - _initialOffset;
                if (available > 0)
                {
                    var count = Math.Min(available, destination.Length);
                    _initial.AsMemory(_initialOffset, count).CopyTo(destination);
                    _initialOffset += count;
                    if (_initialOffset == _initial.Length)
                    {
                        Array.Clear(_initial);
                        _initial = null;
                    }
                    return count;
                }
            }
            return await _stream.ReadAsync(destination, cancellationToken).ConfigureAwait(false);
        }

        internal async Task ReadExactlyAsync(
            Memory<byte> destination,
            CancellationToken cancellationToken)
        {
            var offset = 0;
            while (offset < destination.Length)
            {
                var read = await ReadAsync(destination[offset..], cancellationToken)
                    .ConfigureAwait(false);
                if (read == 0)
                {
                    throw new EndOfStreamException("The DoH response body ended prematurely.");
                }
                offset += read;
            }
        }

        internal async Task<string> ReadAsciiLineAsync(
            int maximumLength,
            CancellationToken cancellationToken)
        {
            var bytes = new List<byte>();
            while (true)
            {
                if (await ReadAsync(_singleByte, cancellationToken).ConfigureAwait(false) == 0)
                {
                    throw new EndOfStreamException("The DoH chunked body ended in a line.");
                }
                if (_singleByte[0] == '\r')
                {
                    if (await ReadAsync(_singleByte, cancellationToken).ConfigureAwait(false) == 0 ||
                        _singleByte[0] != '\n')
                    {
                        throw TlsEchDnsException.Malformed("A DoH line has invalid termination.");
                    }
                    return Encoding.ASCII.GetString(bytes.ToArray());
                }
                if (_singleByte[0] < 0x20 || _singleByte[0] > 0x7E ||
                    bytes.Count == maximumLength)
                {
                    throw TlsEchDnsException.Malformed("A DoH line is invalid or oversized.");
                }
                bytes.Add(_singleByte[0]);
            }
        }

        public void Dispose()
        {
            if (_initial is not null)
            {
                Array.Clear(_initial);
                _initial = null;
            }
        }
    }
}
