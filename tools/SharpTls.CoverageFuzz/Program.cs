using SharpFuzz;
using SharpTls.Fuzzing;

var target = Environment.GetEnvironmentVariable("SHARPTLS_COVERAGE_FUZZ_TARGET") ??
             "clienthello";
if (!ProtocolFuzzTargets.TargetNames.Contains(target, StringComparer.Ordinal))
{
    throw new ArgumentException(
        $"SHARPTLS_COVERAGE_FUZZ_TARGET must be one of: {string.Join(", ", ProtocolFuzzTargets.TargetNames)}.");
}

ProtocolFuzzTargets? targets = null;
try
{
    Fuzzer.LibFuzzer.Run(input =>
    {
        // SharpFuzz initializes its native coverage map before invoking this callback.
        // Constructing an instrumented type earlier writes through an uninitialized map.
        targets ??= new ProtocolFuzzTargets();
        targets.Run(target, input);
    });
}
finally
{
    targets?.Dispose();
}
