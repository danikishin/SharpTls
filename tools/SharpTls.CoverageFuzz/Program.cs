using SharpFuzz;
using SharpTls.Fuzzing;

var target = Environment.GetEnvironmentVariable("SHARPTLS_COVERAGE_FUZZ_TARGET") ??
             "clienthello";
if (!ProtocolFuzzTargets.TargetNames.Contains(target, StringComparer.Ordinal))
{
    throw new ArgumentException(
        $"SHARPTLS_COVERAGE_FUZZ_TARGET must be one of: {string.Join(", ", ProtocolFuzzTargets.TargetNames)}.");
}

using var targets = new ProtocolFuzzTargets();
Fuzzer.LibFuzzer.Run(input => targets.Run(target, input));
