using System.Diagnostics;
using System.Globalization;
using System.Security.Cryptography;
using SharpTls.Fuzzing;

var options = FuzzOptions.Parse(args);
using var targets = new ProtocolFuzzTargets();

if (options.ListTargets)
{
    Console.WriteLine("all");
    foreach (var targetName in ProtocolFuzzTargets.TargetNames)
    {
        Console.WriteLine(targetName);
    }
    return;
}

if (options.ExportCorpusPath is not null)
{
    var names = string.Equals(options.Target, "all", StringComparison.Ordinal)
        ? ProtocolFuzzTargets.TargetNames
        : [options.Target];
    var exported = 0;
    foreach (var name in names)
    {
        var seeds = targets.CreateSeedCorpus(name);
        var directory = Path.Combine(options.ExportCorpusPath, name);
        Directory.CreateDirectory(directory);
        for (var index = 0; index < seeds.Count; index++)
        {
            var hash = Convert.ToHexString(SHA256.HashData(seeds[index]))[..16];
            File.WriteAllBytes(
                Path.Combine(directory, $"{index:D3}-{hash}.bin"),
                seeds[index]);
        }
        exported += seeds.Count;
    }
    Console.WriteLine(
        $"Exported {exported} bounded target-specific seed(s) for {names.Count} target(s) under {Path.GetFullPath(options.ExportCorpusPath)}.");
    return;
}

var executed = 0;
try
{
    if (options.InputPath is not null)
    {
        RunOne(ReadBoundedFile(options.InputPath));
    }
    else if (options.ReadStandardInput)
    {
        RunOne(ReadBoundedStream(Console.OpenStandardInput()));
    }
    else if (options.CorpusPath is not null)
    {
        foreach (var path in Directory.EnumerateFiles(options.CorpusPath)
            .Order(StringComparer.Ordinal))
        {
            RunOne(ReadBoundedFile(path));
        }
    }
    else
    {
        RunMutations();
    }
}
catch (Exception exception)
{
    Console.Error.WriteLine(exception);
    Environment.ExitCode = 1;
    return;
}

Console.WriteLine(
    $"SharpTls fuzz smoke completed: target={options.Target}, inputs={executed}, seed={options.Seed}.");

void RunMutations()
{
    var random = new Random(options.Seed);
    var seeds = targets.CreateSeedCorpus(options.Target);
    foreach (var seed in seeds)
    {
        RunOne(seed);
    }
    for (var iteration = 0; iteration < options.Iterations; iteration++)
    {
        var source = seeds[random.Next(seeds.Count)];
        RunOne(Mutate(source, random, options.MaximumGeneratedLength));
    }
}

void RunOne(byte[] input)
{
    try
    {
        var targetCount = string.Equals(options.Target, "all", StringComparison.Ordinal)
            ? ProtocolFuzzTargets.TargetNames.Count
            : 1;
        var maximumDuration = options.MaximumInputDuration * targetCount;
        var maximumAllocatedBytes = checked(options.MaximumAllocatedBytesPerInput * targetCount);
        var allocatedBefore = GC.GetAllocatedBytesForCurrentThread();
        var started = Stopwatch.GetTimestamp();
        targets.Run(options.Target, input);
        var elapsed = Stopwatch.GetElapsedTime(started);
        var allocated = GC.GetAllocatedBytesForCurrentThread() - allocatedBefore;
        if (elapsed > maximumDuration)
        {
            throw new TimeoutException(
                $"Fuzz input exceeded the {maximumDuration.TotalMilliseconds:F0} ms " +
                $"wall budget for {targetCount} target(s) ({elapsed.TotalMilliseconds:F1} ms).");
        }
        if (allocated > maximumAllocatedBytes)
        {
            throw new InvalidOperationException(
                $"Fuzz input allocated {allocated} bytes, exceeding the " +
                $"{maximumAllocatedBytes}-byte budget for {targetCount} target(s).");
        }
        executed++;
    }
    catch (Exception exception)
    {
        var hash = Convert.ToHexString(SHA256.HashData(input));
        Console.Error.WriteLine(
            $"Unexpected fuzz failure: target={options.Target}, length={input.Length}, sha256={hash}, base64={Convert.ToBase64String(input)}");
        throw new InvalidOperationException("Fuzz target escaped its documented rejection boundary.", exception);
    }
}

static byte[] Mutate(byte[] source, Random random, int maximumLength)
{
    var result = (byte[])source.Clone();
    var operations = random.Next(1, 9);
    for (var operation = 0; operation < operations; operation++)
    {
        switch (random.Next(6))
        {
            case 0 when result.Length != 0:
                result[random.Next(result.Length)] ^= (byte)(1 << random.Next(8));
                break;
            case 1 when result.Length != 0:
                result[random.Next(result.Length)] = (byte)random.Next(256);
                break;
            case 2 when result.Length < maximumLength:
                result = Insert(result, random.Next(result.Length + 1), (byte)random.Next(256));
                break;
            case 3 when result.Length != 0:
                result = Remove(result, random.Next(result.Length));
                break;
            case 4:
                result = new byte[random.Next(maximumLength + 1)];
                random.NextBytes(result);
                break;
            case 5 when result.Length >= 2:
                var first = random.Next(result.Length);
                var second = random.Next(result.Length);
                (result[first], result[second]) = (result[second], result[first]);
                break;
        }
    }
    return result;
}

static byte[] Insert(byte[] source, int offset, byte value)
{
    var result = new byte[source.Length + 1];
    source.AsSpan(0, offset).CopyTo(result);
    result[offset] = value;
    source.AsSpan(offset).CopyTo(result.AsSpan(offset + 1));
    return result;
}

static byte[] Remove(byte[] source, int offset)
{
    var result = new byte[source.Length - 1];
    source.AsSpan(0, offset).CopyTo(result);
    source.AsSpan(offset + 1).CopyTo(result.AsSpan(offset));
    return result;
}

static byte[] ReadBoundedFile(string path)
{
    using var stream = File.OpenRead(path);
    return ReadBoundedStream(stream);
}

static byte[] ReadBoundedStream(Stream stream)
{
    using var buffer = new MemoryStream();
    var chunk = new byte[8192];
    while (true)
    {
        var read = stream.Read(chunk);
        if (read == 0) break;
        if (buffer.Length + read > ProtocolFuzzTargets.MaximumInputLength)
        {
            throw new InvalidDataException(
                $"Fuzz input exceeds {ProtocolFuzzTargets.MaximumInputLength} bytes.");
        }
        buffer.Write(chunk, 0, read);
    }
    return buffer.ToArray();
}

internal sealed record FuzzOptions(
    string Target,
    int Iterations,
    int Seed,
    int MaximumGeneratedLength,
    TimeSpan MaximumInputDuration,
    long MaximumAllocatedBytesPerInput,
    string? InputPath,
    string? CorpusPath,
    string? ExportCorpusPath,
    bool ReadStandardInput,
    bool ListTargets)
{
    internal static FuzzOptions Parse(string[] args)
    {
        var target = "all";
        var iterations = 10_000;
        var seed = 0x5A17_2026;
        var maximumLength = 4096;
        var maximumInputMilliseconds = 2000;
        var maximumAllocatedBytes = 64L * 1024 * 1024;
        string? input = null;
        string? corpus = null;
        string? exportCorpus = null;
        var stdin = false;
        var list = false;

        for (var index = 0; index < args.Length; index++)
        {
            var argument = args[index];
            switch (argument)
            {
                case "--target": target = ReadValue(args, ref index, argument); break;
                case "--iterations": iterations = ParseInt(ReadValue(args, ref index, argument), 0, 100_000_000, argument); break;
                case "--seed": seed = int.Parse(ReadValue(args, ref index, argument), CultureInfo.InvariantCulture); break;
                case "--max-length": maximumLength = ParseInt(ReadValue(args, ref index, argument), 0, ProtocolFuzzTargets.MaximumInputLength, argument); break;
                case "--max-input-ms": maximumInputMilliseconds = ParseInt(ReadValue(args, ref index, argument), 1, 60_000, argument); break;
                case "--max-allocated-bytes": maximumAllocatedBytes = ParseLong(ReadValue(args, ref index, argument), 1024, 1024L * 1024 * 1024, argument); break;
                case "--input": input = ReadValue(args, ref index, argument); break;
                case "--corpus": corpus = ReadValue(args, ref index, argument); break;
                case "--export-corpus": exportCorpus = ReadValue(args, ref index, argument); break;
                case "--stdin": stdin = true; break;
                case "--list-targets": list = true; break;
                default: throw new ArgumentException($"Unknown option '{argument}'.");
            }
        }

        var sources = (input is null ? 0 : 1) + (corpus is null ? 0 : 1) +
                      (exportCorpus is null ? 0 : 1) + (stdin ? 1 : 0);
        if (sources > 1)
        {
            throw new ArgumentException(
                "Choose only one of --input, --corpus, --export-corpus, or --stdin.");
        }
        if (!string.Equals(target, "all", StringComparison.Ordinal) &&
            !ProtocolFuzzTargets.TargetNames.Contains(target, StringComparer.Ordinal))
        {
            throw new ArgumentException($"Unknown fuzz target '{target}'.");
        }
        if (corpus is not null && !Directory.Exists(corpus))
        {
            throw new DirectoryNotFoundException(corpus);
        }

        return new FuzzOptions(
            target,
            iterations,
            seed,
            maximumLength,
            TimeSpan.FromMilliseconds(maximumInputMilliseconds),
            maximumAllocatedBytes,
            input,
            corpus,
            exportCorpus,
            stdin,
            list);
    }

    private static string ReadValue(string[] args, ref int index, string option)
    {
        if (++index >= args.Length)
        {
            throw new ArgumentException($"Option {option} requires a value.");
        }
        return args[index];
    }

    private static int ParseInt(string value, int minimum, int maximum, string option)
    {
        if (!int.TryParse(value, NumberStyles.Integer, CultureInfo.InvariantCulture, out var parsed) ||
            parsed < minimum || parsed > maximum)
        {
            throw new ArgumentOutOfRangeException(option, $"Expected an integer from {minimum} through {maximum}.");
        }
        return parsed;
    }

    private static long ParseLong(string value, long minimum, long maximum, string option)
    {
        if (!long.TryParse(value, NumberStyles.Integer, CultureInfo.InvariantCulture, out var parsed) ||
            parsed < minimum || parsed > maximum)
        {
            throw new ArgumentOutOfRangeException(
                option,
                $"Expected an integer from {minimum} through {maximum}.");
        }
        return parsed;
    }
}
