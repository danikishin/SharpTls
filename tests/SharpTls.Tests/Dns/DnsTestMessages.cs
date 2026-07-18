using System.Text;
using SharpTls.IO;
using SharpTls.Protocol;

namespace SharpTls.Tests.Dns;

internal static class DnsTestMessages
{
    internal static byte[] CreateHttpsResponse(
        ReadOnlySpan<byte> query,
        params (uint Ttl, byte[] RData)[] answers)
    {
        var questionEnd = GetQuestionEnd(query);
        var output = new List<byte>();
        WriteUInt16(output, ReadUInt16(query, 0));
        WriteUInt16(output, 0x81A0); // QR, RD, RA, AD
        WriteUInt16(output, 1);
        WriteUInt16(output, (ushort)answers.Length);
        WriteUInt16(output, 0);
        WriteUInt16(output, 0);
        output.AddRange(query[12..questionEnd].ToArray());
        foreach (var answer in answers)
        {
            output.Add(0xC0);
            output.Add(0x0C);
            WriteUInt16(output, 65);
            WriteUInt16(output, 1);
            WriteUInt32(output, answer.Ttl);
            WriteUInt16(output, checked((ushort)answer.RData.Length));
            output.AddRange(answer.RData);
        }
        return output.ToArray();
    }

    internal static byte[] CreateNoDataResponse(
        ReadOnlySpan<byte> query,
        int responseCode = 0,
        bool authenticated = true)
    {
        var questionEnd = GetQuestionEnd(query);
        var output = new List<byte>();
        WriteUInt16(output, ReadUInt16(query, 0));
        WriteUInt16(output, (ushort)(0x8180 | (authenticated ? 0x20 : 0) | responseCode));
        WriteUInt16(output, 1);
        WriteUInt16(output, 0);
        WriteUInt16(output, 0);
        WriteUInt16(output, 0);
        output.AddRange(query[12..questionEnd].ToArray());
        return output.ToArray();
    }

    internal static byte[] CreateServiceRData(
        ushort priority,
        string targetName,
        params (ushort Key, byte[] Value)[] parameters)
    {
        var output = new List<byte>();
        WriteUInt16(output, priority);
        WriteName(output, targetName);
        foreach (var parameter in parameters)
        {
            WriteUInt16(output, parameter.Key);
            WriteUInt16(output, checked((ushort)parameter.Value.Length));
            output.AddRange(parameter.Value);
        }
        return output.ToArray();
    }

    internal static byte[] EncodeAlpn(params string[] protocols)
    {
        var result = new List<byte>();
        foreach (var protocol in protocols)
        {
            var bytes = Encoding.ASCII.GetBytes(protocol);
            result.Add(checked((byte)bytes.Length));
            result.AddRange(bytes);
        }
        return result.ToArray();
    }

    internal static byte[] CreateEchConfigList(string publicName = "public.example")
    {
        var suites = new TlsBinaryWriter();
        suites.WriteUInt16((ushort)TlsHpkeKdfId.HkdfSha256);
        suites.WriteUInt16((ushort)TlsHpkeAeadId.Aes128Gcm);

        var contents = new TlsBinaryWriter();
        contents.WriteUInt8(7);
        contents.WriteUInt16((ushort)TlsHpkeKemId.DhkemX25519HkdfSha256);
        contents.WriteVector16(Enumerable.Repeat((byte)1, 32).ToArray());
        contents.WriteVector16(suites.WrittenSpan);
        contents.WriteUInt8(0);
        contents.WriteVector8(Encoding.ASCII.GetBytes(publicName));
        contents.WriteVector16([]);

        var config = new TlsBinaryWriter();
        config.WriteUInt16((ushort)TlsExtensionType.EncryptedClientHello);
        config.WriteVector16(contents.WrittenSpan);
        var list = new TlsBinaryWriter();
        list.WriteVector16(config.WrittenSpan);
        return list.ToArray();
    }

    internal static string ReadQueryName(ReadOnlySpan<byte> query)
    {
        var labels = new List<string>();
        for (var offset = 12; query[offset] != 0;)
        {
            var length = query[offset++];
            labels.Add(Encoding.ASCII.GetString(query.Slice(offset, length)));
            offset += length;
        }
        return string.Join('.', labels);
    }

    internal static int GetQuestionEnd(ReadOnlySpan<byte> query)
    {
        var offset = 12;
        while (true)
        {
            var length = query[offset++];
            if (length == 0)
            {
                return offset + 4;
            }
            offset += length;
        }
    }

    internal static void WriteName(List<byte> output, string name)
    {
        if (name == ".")
        {
            output.Add(0);
            return;
        }
        foreach (var label in name.Split('.'))
        {
            output.Add(checked((byte)label.Length));
            output.AddRange(Encoding.ASCII.GetBytes(label));
        }
        output.Add(0);
    }

    internal static ushort ReadUInt16(ReadOnlySpan<byte> value, int offset) =>
        (ushort)((value[offset] << 8) | value[offset + 1]);

    internal static void WriteUInt16(List<byte> output, ushort value)
    {
        output.Add((byte)(value >> 8));
        output.Add((byte)value);
    }

    internal static void WriteUInt32(List<byte> output, uint value)
    {
        output.Add((byte)(value >> 24));
        output.Add((byte)(value >> 16));
        output.Add((byte)(value >> 8));
        output.Add((byte)value);
    }
}
