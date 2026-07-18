using System.Buffers.Binary;
using System.Globalization;
using System.Net;
using System.Text;

namespace SharpTls.Dns;

internal enum DnsRecordType : ushort
{
    Cname = 5,
    Opt = 41,
    Https = 65,
}

internal readonly record struct DnsSvcParameter(ushort Key, byte[] Value);

internal sealed record DnsHttpsRecord(
    string Owner,
    uint TimeToLive,
    ushort Priority,
    string TargetName,
    DnsSvcParameter[] Parameters);

internal sealed record DnsCnameRecord(
    string Owner,
    uint TimeToLive,
    string CanonicalName);

internal sealed record DnsParsedResponse(
    bool IsTruncated,
    bool IsAuthenticatedData,
    int ResponseCode,
    DnsHttpsRecord[] HttpsRecords,
    DnsCnameRecord[] CnameRecords);

internal static class DnsNames
{
    internal static string NormalizeOrigin(string name)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(name);
        var withoutRoot = name.EndsWith(".", StringComparison.Ordinal)
            ? name[..^1]
            : name;
        if (withoutRoot.Length == 0)
        {
            throw new ArgumentException("A DNS origin cannot be the root name.", nameof(name));
        }

        string ascii;
        try
        {
            ascii = new IdnMapping().GetAscii(withoutRoot).ToLowerInvariant();
        }
        catch (ArgumentException exception)
        {
            throw new ArgumentException("The origin is not a valid IDNA DNS name.", nameof(name), exception);
        }

        ValidateHostName(ascii, nameof(name));
        if (IPAddress.TryParse(ascii, out _))
        {
            throw new ArgumentException(
                "RFC 9848 HTTPS discovery requires a DNS origin rather than an IP literal.",
                nameof(name));
        }
        return ascii;
    }

    internal static string GetHttpsQueryName(string origin, int port)
    {
        if (port is < 1 or > ushort.MaxValue)
        {
            throw new ArgumentOutOfRangeException(nameof(port));
        }

        return port == 443 ? origin : $"_{port}._https.{origin}";
    }

    internal static void ValidateHostName(string name, string parameterName)
    {
        if (name.Length is 0 or > 253 || name[0] == '.' || name[^1] == '.')
        {
            throw new ArgumentException("The DNS name has an invalid length or root marker.", parameterName);
        }

        foreach (var label in name.Split('.'))
        {
            if (label.Length is 0 or > 63 ||
                !IsAlphaNumeric(label[0]) ||
                !IsAlphaNumeric(label[^1]) ||
                label.Any(character => !IsAlphaNumeric(character) && character != '-'))
            {
                throw new ArgumentException("The DNS name contains an invalid LDH label.", parameterName);
            }
        }
    }

    private static bool IsAlphaNumeric(char value) => value is
        >= 'a' and <= 'z' or >= 'A' and <= 'Z' or >= '0' and <= '9';
}

internal static class DnsMessageWriter
{
    internal static byte[] CreateHttpsQuery(
        ushort identifier,
        string queryName,
        ushort udpPayloadSize,
        bool requestDnsSec)
    {
        if (udpPayloadSize is < 512 or > 4096)
        {
            throw new ArgumentOutOfRangeException(nameof(udpPayloadSize));
        }

        var output = new List<byte>(512);
        WriteUInt16(output, identifier);
        WriteUInt16(output, 0x0100); // RD
        WriteUInt16(output, 1); // QDCOUNT
        WriteUInt16(output, 0); // ANCOUNT
        WriteUInt16(output, 0); // NSCOUNT
        WriteUInt16(output, 1); // ARCOUNT (EDNS(0))
        WriteName(output, queryName);
        WriteUInt16(output, (ushort)DnsRecordType.Https);
        WriteUInt16(output, 1); // IN

        output.Add(0); // OPT owner is the root name.
        WriteUInt16(output, (ushort)DnsRecordType.Opt);
        WriteUInt16(output, udpPayloadSize);
        WriteUInt32(output, requestDnsSec ? 0x0000_8000u : 0u); // EDNS DO bit.
        WriteUInt16(output, 0);
        return output.ToArray();
    }

    private static void WriteName(List<byte> output, string name)
    {
        if (name.Length is 0 or > 253 || name.EndsWith(".", StringComparison.Ordinal))
        {
            throw new ArgumentException("The DNS query name is invalid.", nameof(name));
        }

        var encodedLength = 1;
        foreach (var label in name.Split('.'))
        {
            if (label.Length is 0 or > 63 || label.Any(character =>
                    character > 0x7F ||
                    !(char.IsAsciiLetterOrDigit(character) || character is '-' or '_')))
            {
                throw new ArgumentException("The DNS query name contains an invalid label.", nameof(name));
            }

            encodedLength += 1 + label.Length;
            if (encodedLength > byte.MaxValue)
            {
                throw new ArgumentException("The DNS query name exceeds the wire-format limit.", nameof(name));
            }

            output.Add((byte)label.Length);
            foreach (var character in label)
            {
                output.Add((byte)character);
            }
        }
        output.Add(0);
    }

    private static void WriteUInt16(List<byte> output, ushort value)
    {
        output.Add((byte)(value >> 8));
        output.Add((byte)value);
    }

    private static void WriteUInt32(List<byte> output, uint value)
    {
        output.Add((byte)(value >> 24));
        output.Add((byte)(value >> 16));
        output.Add((byte)(value >> 8));
        output.Add((byte)value);
    }
}

internal static class DnsMessageParser
{
    private const int HeaderLength = 12;
    private const int MaximumCompressionPointers = 32;

    internal static DnsParsedResponse ParseHttpsResponse(
        ReadOnlySpan<byte> message,
        ushort expectedIdentifier,
        string expectedQueryName,
        int maximumResponseSize,
        int maximumRecords,
        uint cacheAgeSeconds = 0,
        uint? ttlCapSeconds = null)
    {
        if (maximumResponseSize is < HeaderLength or > ushort.MaxValue ||
            message.Length > maximumResponseSize)
        {
            throw TlsEchDnsException.Malformed("The DNS response exceeds the configured size limit.");
        }
        if (maximumRecords is < 1 or > 4096)
        {
            throw new ArgumentOutOfRangeException(nameof(maximumRecords));
        }
        if (message.Length < HeaderLength)
        {
            throw TlsEchDnsException.Malformed("The DNS response header is truncated.");
        }

        var offset = 0;
        var identifier = ReadUInt16(message, ref offset);
        var flags = ReadUInt16(message, ref offset);
        var questionCount = ReadUInt16(message, ref offset);
        var answerCount = ReadUInt16(message, ref offset);
        var authorityCount = ReadUInt16(message, ref offset);
        var additionalCount = ReadUInt16(message, ref offset);

        if (identifier != expectedIdentifier)
        {
            throw TlsEchDnsException.Malformed("The DNS response transaction identifier does not match the query.");
        }
        if ((flags & 0x8000) == 0 || (flags & 0x7800) != 0 || (flags & 0x0040) != 0)
        {
            throw TlsEchDnsException.Malformed("The DNS message is not a valid standard query response.");
        }
        if (questionCount != 1)
        {
            throw TlsEchDnsException.Malformed("The DNS response must repeat exactly one question.");
        }

        var totalRecordCount = (long)answerCount + authorityCount + additionalCount;
        if (totalRecordCount > maximumRecords)
        {
            throw TlsEchDnsException.Malformed("The DNS response exceeds the configured record-count limit.");
        }

        var questionName = ReadName(message, ref offset, message.Length, allowCompression: true);
        var questionType = ReadUInt16(message, ref offset);
        var questionClass = ReadUInt16(message, ref offset);
        if (!string.Equals(questionName, expectedQueryName, StringComparison.OrdinalIgnoreCase) ||
            questionType != (ushort)DnsRecordType.Https || questionClass != 1)
        {
            throw TlsEchDnsException.Malformed("The DNS response question does not match the HTTPS query.");
        }

        var httpsRecords = new List<DnsHttpsRecord>();
        var cnameRecords = new List<DnsCnameRecord>();
        byte extendedResponseCode = 0;
        var sawOpt = false;
        ParseRecords(
            message,
            ref offset,
            answerCount,
            isAnswerSection: true,
            isAdditionalSection: false,
            httpsRecords,
            cnameRecords,
            ref extendedResponseCode,
            ref sawOpt,
            cacheAgeSeconds,
            ttlCapSeconds);
        ParseRecords(
            message,
            ref offset,
            authorityCount,
            isAnswerSection: false,
            isAdditionalSection: false,
            httpsRecords,
            cnameRecords,
            ref extendedResponseCode,
            ref sawOpt,
            cacheAgeSeconds,
            ttlCapSeconds);
        ParseRecords(
            message,
            ref offset,
            additionalCount,
            isAnswerSection: false,
            isAdditionalSection: true,
            httpsRecords,
            cnameRecords,
            ref extendedResponseCode,
            ref sawOpt,
            cacheAgeSeconds,
            ttlCapSeconds);
        if (offset != message.Length)
        {
            throw TlsEchDnsException.Malformed("The DNS response contains trailing bytes.");
        }

        var responseCode = (extendedResponseCode << 4) | (flags & 0x000F);
        return new DnsParsedResponse(
            (flags & 0x0200) != 0,
            (flags & 0x0020) != 0,
            responseCode,
            httpsRecords.ToArray(),
            cnameRecords.ToArray());
    }

    internal static bool HasTruncatedFlag(ReadOnlySpan<byte> message)
    {
        if (message.Length < HeaderLength)
        {
            throw TlsEchDnsException.Malformed("The DNS response header is truncated.");
        }
        return (BinaryPrimitives.ReadUInt16BigEndian(message[2..]) & 0x0200) != 0;
    }

    private static void ParseRecords(
        ReadOnlySpan<byte> message,
        ref int offset,
        ushort count,
        bool isAnswerSection,
        bool isAdditionalSection,
        List<DnsHttpsRecord> httpsRecords,
        List<DnsCnameRecord> cnameRecords,
        ref byte extendedResponseCode,
        ref bool sawOpt,
        uint cacheAgeSeconds,
        uint? ttlCapSeconds)
    {
        for (var index = 0; index < count; index++)
        {
            var owner = ReadName(message, ref offset, message.Length, allowCompression: true);
            var type = ReadUInt16(message, ref offset);
            var recordClass = ReadUInt16(message, ref offset);
            var ttl = ReadUInt32(message, ref offset);
            var dataLength = ReadUInt16(message, ref offset);
            var dataOffset = offset;
            var dataEnd = checked(dataOffset + dataLength);
            if (dataEnd > message.Length)
            {
                throw TlsEchDnsException.Malformed("A DNS resource record is truncated.");
            }

            if (type == (ushort)DnsRecordType.Opt)
            {
                var ednsVersion = (byte)(ttl >> 16);
                if (owner != "." || !isAdditionalSection || sawOpt || ednsVersion != 0)
                {
                    throw TlsEchDnsException.Malformed(
                        "An EDNS OPT record has an invalid owner, section, version, or duplicate.");
                }
                sawOpt = true;
                extendedResponseCode = (byte)(ttl >> 24);
            }
            else if (isAnswerSection && recordClass == 1 && type == (ushort)DnsRecordType.Cname)
            {
                var nameOffset = dataOffset;
                var canonicalName = ReadName(message, ref nameOffset, dataEnd, allowCompression: true);
                if (nameOffset != dataEnd)
                {
                    throw TlsEchDnsException.Malformed("A CNAME record contains trailing bytes.");
                }
                cnameRecords.Add(new DnsCnameRecord(
                    owner,
                    NormalizeTtl(ttl, cacheAgeSeconds, ttlCapSeconds),
                    canonicalName));
            }
            else if (isAnswerSection && recordClass == 1 && type == (ushort)DnsRecordType.Https)
            {
                httpsRecords.Add(ParseHttpsRecord(
                    message,
                    owner,
                    NormalizeTtl(ttl, cacheAgeSeconds, ttlCapSeconds),
                    dataOffset,
                    dataEnd));
            }

            offset = dataEnd;
        }
    }

    private static uint NormalizeTtl(
        uint ttl,
        uint cacheAgeSeconds,
        uint? ttlCapSeconds)
    {
        var remaining = ttl > cacheAgeSeconds ? ttl - cacheAgeSeconds : 0;
        return ttlCapSeconds.HasValue
            ? Math.Min(remaining, ttlCapSeconds.Value)
            : remaining;
    }

    private static DnsHttpsRecord ParseHttpsRecord(
        ReadOnlySpan<byte> message,
        string owner,
        uint ttl,
        int dataOffset,
        int dataEnd)
    {
        try
        {
            return ParseHttpsRecordCore(message, owner, ttl, dataOffset, dataEnd);
        }
        catch (TlsEchDnsException exception) when (
            exception.ErrorKind == TlsEchDnsErrorKind.MalformedResponse)
        {
            throw new TlsEchDnsException(
                TlsEchDnsErrorKind.MalformedServiceBinding,
                "The HTTPS/SVCB RDATA is malformed.",
                exception);
        }
    }

    private static DnsHttpsRecord ParseHttpsRecordCore(
        ReadOnlySpan<byte> message,
        string owner,
        uint ttl,
        int dataOffset,
        int dataEnd)
    {
        var offset = dataOffset;
        var priority = ReadUInt16(message, ref offset, dataEnd);
        var targetName = ReadName(message, ref offset, dataEnd, allowCompression: false);
        var parameters = new List<DnsSvcParameter>();
        var previousKey = -1;
        while (offset < dataEnd)
        {
            var key = ReadUInt16(message, ref offset, dataEnd);
            var length = ReadUInt16(message, ref offset, dataEnd);
            if (key <= previousKey)
            {
                throw TlsEchDnsException.MalformedServiceBinding(
                    "SVCB parameters must be encoded in strictly increasing key order.");
            }
            if (dataEnd - offset < length)
            {
                throw TlsEchDnsException.MalformedServiceBinding(
                    "An SVCB parameter value is truncated.");
            }

            parameters.Add(new DnsSvcParameter(key, message.Slice(offset, length).ToArray()));
            previousKey = key;
            offset += length;
        }

        return new DnsHttpsRecord(owner, ttl, priority, targetName, parameters.ToArray());
    }

    private static string ReadName(
        ReadOnlySpan<byte> message,
        ref int offset,
        int inlineEnd,
        bool allowCompression)
    {
        if ((uint)offset >= (uint)inlineEnd || inlineEnd > message.Length)
        {
            throw TlsEchDnsException.Malformed("A DNS name is truncated.");
        }

        var labels = new List<string>();
        var visitedPointers = new HashSet<int>();
        var cursor = offset;
        var returnOffset = -1;
        var pointerCount = 0;
        var expandedLength = 1;
        while (true)
        {
            if ((uint)cursor >= (uint)message.Length)
            {
                throw TlsEchDnsException.Malformed("A DNS name extends beyond the message.");
            }

            var length = message[cursor];
            if ((length & 0xC0) == 0xC0)
            {
                if (!allowCompression || cursor + 2 > inlineEnd && returnOffset < 0 ||
                    cursor + 2 > message.Length)
                {
                    throw TlsEchDnsException.Malformed("DNS name compression is invalid in this field.");
                }

                var pointer = ((length & 0x3F) << 8) | message[cursor + 1];
                if (pointer >= cursor || !visitedPointers.Add(pointer) ||
                    ++pointerCount > MaximumCompressionPointers)
                {
                    throw TlsEchDnsException.Malformed("A DNS compression pointer is cyclic or forward-pointing.");
                }
                if (returnOffset < 0)
                {
                    returnOffset = cursor + 2;
                }
                cursor = pointer;
                continue;
            }
            if ((length & 0xC0) != 0)
            {
                throw TlsEchDnsException.Malformed("A DNS name uses a reserved label encoding.");
            }

            cursor++;
            if (length == 0)
            {
                if (returnOffset < 0)
                {
                    if (cursor > inlineEnd)
                    {
                        throw TlsEchDnsException.Malformed("A DNS name extends beyond its field.");
                    }
                    returnOffset = cursor;
                }
                offset = returnOffset;
                return labels.Count == 0 ? "." : string.Join('.', labels);
            }
            if (length > 63 || cursor + length > message.Length ||
                returnOffset < 0 && cursor + length > inlineEnd)
            {
                throw TlsEchDnsException.Malformed("A DNS label is truncated or exceeds 63 octets.");
            }

            expandedLength += length + 1;
            if (expandedLength > byte.MaxValue)
            {
                throw TlsEchDnsException.Malformed("A decompressed DNS name exceeds 255 octets.");
            }

            var labelBytes = message.Slice(cursor, length);
            var validLabel = true;
            foreach (var value in labelBytes)
            {
                if (value > 0x7F ||
                    !(char.IsAsciiLetterOrDigit((char)value) || value is (byte)'-' or (byte)'_'))
                {
                    validLabel = false;
                    break;
                }
            }
            if (!validLabel)
            {
                throw TlsEchDnsException.Malformed("A DNS name contains a non-host label octet.");
            }
            labels.Add(Encoding.ASCII.GetString(labelBytes).ToLowerInvariant());
            cursor += length;
        }
    }

    private static ushort ReadUInt16(ReadOnlySpan<byte> message, ref int offset) =>
        ReadUInt16(message, ref offset, message.Length);

    private static ushort ReadUInt16(ReadOnlySpan<byte> message, ref int offset, int end)
    {
        if (end - offset < 2)
        {
            throw TlsEchDnsException.Malformed("A DNS 16-bit integer is truncated.");
        }
        var result = BinaryPrimitives.ReadUInt16BigEndian(message.Slice(offset, 2));
        offset += 2;
        return result;
    }

    private static uint ReadUInt32(ReadOnlySpan<byte> message, ref int offset)
    {
        if (message.Length - offset < 4)
        {
            throw TlsEchDnsException.Malformed("A DNS 32-bit integer is truncated.");
        }
        var result = BinaryPrimitives.ReadUInt32BigEndian(message.Slice(offset, 4));
        offset += 4;
        return result;
    }
}
