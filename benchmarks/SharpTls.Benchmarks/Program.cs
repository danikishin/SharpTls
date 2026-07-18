using System.Diagnostics;
using System.Globalization;
using System.Security.Cryptography;
using SharpTls;
using SharpTls.Cryptography;
using SharpTls.Handshake;
using SharpTls.Protocol;
using SharpTls.Quic;
using SharpTls.Records;

CultureInfo.CurrentCulture = CultureInfo.InvariantCulture;
CultureInfo.CurrentUICulture = CultureInfo.InvariantCulture;

var verify = args.Contains("--verify", StringComparer.Ordinal);
if (args.Any(argument => argument is not "--verify"))
{
    throw new ArgumentException("Supported option: --verify");
}

var profile = ClientHelloProfiles.UTlsFirefox120;
var handshake = profile.BuildDeterministicForTesting("benchmark.invalid", [2, 9, 2, 0, 2, 6]);
var clientHelloBody = handshake.AsSpan(4).ToArray();
var json = ClientHelloSpecJson.SerializeUtf8(profile.Spec);
var quicParameters = new TlsQuicTransportParameters(
[
    TlsQuicTransportParameter.VariableInteger(
        TlsQuicTransportParameterId.MaxUdpPayloadSize,
        1200),
    TlsQuicTransportParameter.VariableInteger(
        TlsQuicTransportParameterId.InitialMaxData,
        1_048_576),
    TlsQuicTransportParameter.VariableInteger(
        TlsQuicTransportParameterId.InitialMaxStreamsBidi,
        100),
]).Encode();

var cases = new BenchmarkCase[]
{
    new("clienthello-parse", 20_000, () =>
    {
        var parsed = Tls13ClientHelloParser.Parse(clientHelloBody);
        Consume(parsed.ExtensionTypes.Length);
    }, MaximumNanosecondsPerOperation: 1_000_000, MaximumAllocatedBytesPerOperation: 64_000),
    new("json-v6-deserialize", 2_000, () =>
    {
        var parsed = ClientHelloSpecJson.Deserialize(json);
        Consume(parsed.Extensions.Count);
    }, MaximumNanosecondsPerOperation: 5_000_000, MaximumAllocatedBytesPerOperation: 256_000),
    new("quic-transport-parameters", 50_000, () =>
    {
        var parsed = TlsQuicTransportParameters.Parse(quicParameters);
        Consume(parsed.Parameters.Count);
    }, MaximumNanosecondsPerOperation: 500_000, MaximumAllocatedBytesPerOperation: 32_000),
    new("hkdf-expand-label", 20_000, () =>
    {
        var output = Tls13Hkdf.ExpandLabel(
            HashAlgorithmName.SHA256,
            new byte[32],
            "benchmark",
            new byte[32],
            32);
        Consume(output[0]);
        CryptographicOperations.ZeroMemory(output);
    }, MaximumNanosecondsPerOperation: 1_000_000, MaximumAllocatedBytesPerOperation: 16_000),
    new("handshake-deframe", 10_000, () =>
    {
        var deframer = new HandshakeDeframer(64 * 1024);
        var midpoint = handshake.Length / 2;
        deframer.Append(handshake.AsSpan(0, midpoint));
        deframer.Append(handshake.AsSpan(midpoint));
        if (!deframer.TryRead(out var message) || message is null)
        {
            throw new InvalidOperationException("Benchmark seed did not deframe.");
        }
        Consume(message.Body.Length);
    }, MaximumNanosecondsPerOperation: 1_000_000, MaximumAllocatedBytesPerOperation: 64_000),
    new("aes128gcm-record-roundtrip", 20_000, MeasureRecordRoundTrip,
        MaximumNanosecondsPerOperation: 1_000_000,
        MaximumAllocatedBytesPerOperation: 32_000),
};

var failed = false;
Console.WriteLine("scenario,iterations,ns/op,bytes/op,status");
foreach (var benchmark in cases)
{
    for (var warmup = 0; warmup < Math.Min(1000, benchmark.Iterations / 10); warmup++)
    {
        benchmark.Action();
    }

    GC.Collect();
    GC.WaitForPendingFinalizers();
    GC.Collect();
    var allocatedBefore = GC.GetAllocatedBytesForCurrentThread();
    var stopwatch = Stopwatch.StartNew();
    for (var iteration = 0; iteration < benchmark.Iterations; iteration++)
    {
        benchmark.Action();
    }
    stopwatch.Stop();
    var allocated = GC.GetAllocatedBytesForCurrentThread() - allocatedBefore;
    var nanosecondsPerOperation = stopwatch.Elapsed.TotalNanoseconds / benchmark.Iterations;
    var bytesPerOperation = (double)allocated / benchmark.Iterations;
    var passed = nanosecondsPerOperation <= benchmark.MaximumNanosecondsPerOperation &&
                 bytesPerOperation <= benchmark.MaximumAllocatedBytesPerOperation;
    failed |= !passed;
    Console.WriteLine(
        $"{benchmark.Name},{benchmark.Iterations},{nanosecondsPerOperation:F1},{bytesPerOperation:F1},{(passed ? "pass" : "FAIL")}");
}

GC.KeepAlive(BenchmarkConsumer.Value);
if (verify && failed)
{
    Console.Error.WriteLine("One or more SharpTls benchmark budgets were exceeded.");
    Environment.ExitCode = 1;
}

void MeasureRecordRoundTrip()
{
    var suite = CipherSuiteInfo.Get(TlsCipherSuite.TlsAes128GcmSha256);
    Span<byte> key = stackalloc byte[16];
    Span<byte> iv = stackalloc byte[12];
    using var writer = new Tls13RecordCipher(suite, key, iv, maximumRecords: 1);
    using var reader = new Tls13RecordCipher(suite, key, iv, maximumRecords: 1);
    Span<byte> plaintext = stackalloc byte[1024];
    var encrypted = writer.Encrypt(TlsContentType.ApplicationData, plaintext);
    var decrypted = reader.Decrypt(encrypted);
    Consume(decrypted.Content.Length);
    CryptographicOperations.ZeroMemory(encrypted);
    CryptographicOperations.ZeroMemory(decrypted.Content);
}

static void Consume(int value) => BenchmarkConsumer.Consume(value);

internal sealed record BenchmarkCase(
    string Name,
    int Iterations,
    Action Action,
    double MaximumNanosecondsPerOperation,
    double MaximumAllocatedBytesPerOperation);

internal static class BenchmarkConsumer
{
    private static int _value;

    internal static int Value => Volatile.Read(ref _value);

    internal static void Consume(int value) => Volatile.Write(ref _value, value);
}
