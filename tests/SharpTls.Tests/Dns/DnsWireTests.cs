using System.Net;
using SharpTls.Dns;

namespace SharpTls.Tests.Dns;

public sealed class DnsWireTests
{
    [Fact]
    public void HttpsQueryCarriesExactQuestionAndBoundedEdnsDnsSecRequest()
    {
        var query = DnsMessageWriter.CreateHttpsQuery(
            0x1234,
            "_8443._https.example.com",
            1232,
            requestDnsSec: true);

        Assert.Equal((ushort)0x1234, DnsTestMessages.ReadUInt16(query, 0));
        Assert.Equal((ushort)0x0100, DnsTestMessages.ReadUInt16(query, 2));
        Assert.Equal((ushort)1, DnsTestMessages.ReadUInt16(query, 4));
        Assert.Equal((ushort)1, DnsTestMessages.ReadUInt16(query, 10));
        Assert.Equal("_8443._https.example.com", DnsTestMessages.ReadQueryName(query));
        var questionEnd = DnsTestMessages.GetQuestionEnd(query);
        Assert.Equal((ushort)65, DnsTestMessages.ReadUInt16(query, questionEnd - 4));
        Assert.Equal((ushort)1, DnsTestMessages.ReadUInt16(query, questionEnd - 2));
        Assert.Equal(0, query[questionEnd]);
        Assert.Equal((ushort)41, DnsTestMessages.ReadUInt16(query, questionEnd + 1));
        Assert.Equal((ushort)1232, DnsTestMessages.ReadUInt16(query, questionEnd + 3));
        Assert.Equal(new byte[] { 0, 0, 0x80, 0 }, query[(questionEnd + 5)..(questionEnd + 9)]);
    }

    [Fact]
    public void HttpsRecordParsesKnownParametersAndExactEchConfigList()
    {
        var query = DnsMessageWriter.CreateHttpsQuery(9, "example.com", 1232, false);
        var ech = DnsTestMessages.CreateEchConfigList();
        var response = DnsTestMessages.CreateHttpsResponse(
            query,
            (300, DnsTestMessages.CreateServiceRData(
                1,
                "edge.example",
                (0, new byte[] { 0, 1, 0, 5 }),
                (1, DnsTestMessages.EncodeAlpn("h2", "http/1.1")),
                (2, Array.Empty<byte>()),
                (3, new byte[] { 0x20, 0xFB }),
                (4, new byte[] { 192, 0, 2, 1 }),
                (5, ech),
                (6, IPAddress.Parse("2001:db8::1").GetAddressBytes()))));

        var parsed = DnsMessageParser.ParseHttpsResponse(
            response,
            9,
            "example.com",
            ushort.MaxValue,
            16);
        var binding = DnsServiceBindingParser.ParseService(
            Assert.Single(parsed.HttpsRecords),
            443);

        Assert.True(parsed.IsAuthenticatedData);
        Assert.Equal(0, parsed.ResponseCode);
        Assert.True(binding.IsCompatible);
        Assert.Equal("edge.example", binding.TargetName);
        Assert.Equal(8443, binding.Port);
        Assert.Equal(new[] { "h2", "http/1.1" }, binding.AlpnProtocols);
        Assert.True(binding.HasNoDefaultAlpn);
        Assert.Equal(IPAddress.Parse("192.0.2.1"), Assert.Single(binding.Ipv4Hints));
        Assert.Equal(IPAddress.Parse("2001:db8::1"), Assert.Single(binding.Ipv6Hints));
        Assert.True(binding.HasExecutableEch);
        Assert.Equal(ech, binding.EchConfigList!.GetEncodedList());
    }

    [Fact]
    public void Rfc9460AppendixDFigure9WireVectorParsesExactly()
    {
        var rdata = Convert.FromHexString(
            "0010" +
            "03666F6F076578616D706C65036F726700" +
            "0000000400010004" +
            "000100090268320568332D3139" +
            "00040004C0000201");
        var query = DnsMessageWriter.CreateHttpsQuery(12, "example.com", 1232, false);
        var response = DnsTestMessages.CreateHttpsResponse(query, (300, rdata));

        var wire = Assert.Single(DnsMessageParser.ParseHttpsResponse(
            response,
            12,
            "example.com",
            ushort.MaxValue,
            8).HttpsRecords);
        var binding = DnsServiceBindingParser.ParseService(wire, 443);

        Assert.True(binding.IsCompatible);
        Assert.Equal((ushort)16, wire.Priority);
        Assert.Equal("foo.example.org", binding.TargetName);
        Assert.Equal(new[] { "h2", "h3-19", "http/1.1" }, binding.AlpnProtocols);
        Assert.Equal(IPAddress.Parse("192.0.2.1"), Assert.Single(binding.Ipv4Hints));
    }

    [Fact]
    public void UnknownMandatoryKeyMakesRecordIncompatibleWithoutMisparsingIt()
    {
        var wire = new DnsHttpsRecord(
            "example.com",
            60,
            1,
            ".",
            [
                new DnsSvcParameter(0, new byte[] { 0xFE, 0x00 }),
                new DnsSvcParameter(0xFE00, new byte[] { 1, 2, 3 }),
            ]);

        var parsed = DnsServiceBindingParser.ParseService(wire, 443);

        Assert.False(parsed.IsCompatible);
        Assert.Equal("example.com", parsed.TargetName);
    }

    [Fact]
    public void AliasModeIgnoresParametersAndPreservesRootUnavailableSignal()
    {
        var valid = new DnsHttpsRecord(
            "example.com",
            30,
            0,
            "alias.example",
            [new DnsSvcParameter(1, new byte[] { 0 })]);
        var root = valid with { TargetName = "." };

        Assert.Equal("alias.example", DnsServiceBindingParser.ParseAliasTarget(valid));
        Assert.Equal(".", DnsServiceBindingParser.ParseAliasTarget(root));
    }

    [Fact]
    public void NoDefaultAlpnWithoutAlpnIsIncompatible()
    {
        var wire = new DnsHttpsRecord(
            "example.com",
            30,
            1,
            ".",
            [new DnsSvcParameter(2, [])]);

        Assert.False(DnsServiceBindingParser.ParseService(
            wire,
            443).IsCompatible);
    }

    [Fact]
    public void DuplicateAlpnAndIpHintsAreSetValuesWhilePortZeroIsIncompatible()
    {
        var wire = new DnsHttpsRecord(
            "example.com",
            30,
            1,
            ".",
            [
                new DnsSvcParameter(1, DnsTestMessages.EncodeAlpn("h2", "h2")),
                new DnsSvcParameter(3, new byte[] { 0, 0 }),
                new DnsSvcParameter(4, new byte[]
                {
                    192, 0, 2, 1,
                    192, 0, 2, 1,
                }),
            ]);

        var binding = DnsServiceBindingParser.ParseService(wire, 443);

        Assert.False(binding.IsCompatible);
        Assert.Equal(new[] { "h2", "http/1.1" }, binding.AlpnProtocols);
        Assert.Equal(2, binding.Ipv4Hints.Length);
    }

    [Fact]
    public void CompressedSvcTargetAndUnsortedParametersAreRejected()
    {
        var query = DnsMessageWriter.CreateHttpsQuery(1, "example.com", 1232, false);
        var compressedTarget = DnsTestMessages.CreateHttpsResponse(
            query,
            (30, new byte[] { 0, 1, 0xC0, 0x0C }));
        var unsorted = DnsTestMessages.CreateHttpsResponse(
            query,
            (30, DnsTestMessages.CreateServiceRData(
                1,
                ".",
                (2, Array.Empty<byte>()),
                (1, DnsTestMessages.EncodeAlpn("h2")))));

        Assert.Throws<TlsEchDnsException>(() => DnsMessageParser.ParseHttpsResponse(
            compressedTarget,
            1,
            "example.com",
            ushort.MaxValue,
            8));
        Assert.Throws<TlsEchDnsException>(() => DnsMessageParser.ParseHttpsResponse(
            unsorted,
            1,
            "example.com",
            ushort.MaxValue,
            8));
    }

    [Fact]
    public void WrongIdForwardPointerTruncationTrailingBytesAndRecordFloodAreRejected()
    {
        var query = DnsMessageWriter.CreateHttpsQuery(1, "example.com", 1232, false);
        var response = DnsTestMessages.CreateHttpsResponse(
            query,
            (30, DnsTestMessages.CreateServiceRData(1, ".")),
            (30, DnsTestMessages.CreateServiceRData(2, ".")));
        var answerOffset = DnsTestMessages.GetQuestionEnd(query);

        Assert.Throws<TlsEchDnsException>(() => DnsMessageParser.ParseHttpsResponse(
            response,
            2,
            "example.com",
            ushort.MaxValue,
            8));

        var forwardPointer = (byte[])response.Clone();
        forwardPointer[answerOffset] = 0xC0;
        forwardPointer[answerOffset + 1] = checked((byte)(answerOffset + 2));
        Assert.Throws<TlsEchDnsException>(() => DnsMessageParser.ParseHttpsResponse(
            forwardPointer,
            1,
            "example.com",
            ushort.MaxValue,
            8));

        Assert.Throws<TlsEchDnsException>(() => DnsMessageParser.ParseHttpsResponse(
            response[..^1],
            1,
            "example.com",
            ushort.MaxValue,
            8));
        Assert.Throws<TlsEchDnsException>(() => DnsMessageParser.ParseHttpsResponse(
            [.. response, 0],
            1,
            "example.com",
            ushort.MaxValue,
            8));
        Assert.Throws<TlsEchDnsException>(() => DnsMessageParser.ParseHttpsResponse(
            response,
            1,
            "example.com",
            ushort.MaxValue,
            1));
    }

    [Fact]
    public void MalformedKnownParameterValuesAreRejected()
    {
        var malformedMandatory = new DnsHttpsRecord(
            "example.com",
            30,
            1,
            ".",
            [
                new DnsSvcParameter(0, new byte[] { 0, 1 }),
            ]);
        var malformedAlpn = new DnsHttpsRecord(
            "example.com",
            30,
            1,
            ".",
            [new DnsSvcParameter(1, new byte[] { 2, (byte)'h' })]);
        var malformedPort = new DnsHttpsRecord(
            "example.com",
            30,
            1,
            ".",
            [new DnsSvcParameter(3, new byte[] { 0 })]);
        var malformedHint = new DnsHttpsRecord(
            "example.com",
            30,
            1,
            ".",
            [new DnsSvcParameter(4, new byte[] { 1, 2, 3 })]);

        Assert.Throws<TlsEchDnsException>(() => DnsServiceBindingParser.ParseService(
            malformedMandatory,
            443));
        Assert.Throws<TlsEchDnsException>(() => DnsServiceBindingParser.ParseService(
            malformedAlpn,
            443));
        Assert.Throws<TlsEchDnsException>(() => DnsServiceBindingParser.ParseService(
            malformedPort,
            443));
        Assert.Throws<TlsEchDnsException>(() => DnsServiceBindingParser.ParseService(
            malformedHint,
            443));
    }
}
