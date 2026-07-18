# Release hardening

Phase 29 separates locally reproducible engineering gates from evidence that can only
come from hosted platforms or independent reviewers. No local command is represented
as a substitute for the latter.

## Local deterministic gates

Run the complete release-quality sequence from the repository root:

```shell
dotnet restore SharpTls.slnx
dotnet test SharpTls.slnx -c Release --no-restore
dotnet run --project tools/SharpTls.Fuzz/SharpTls.Fuzz.csproj -c Release --no-build -- --iterations 2000 --max-length 4096
dotnet run --project benchmarks/SharpTls.Benchmarks/SharpTls.Benchmarks.csproj -c Release --no-build -- --verify
dotnet pack src/SharpTls/SharpTls.csproj -c Release --no-build -o artifacts/raw-a -p:ContinuousIntegrationBuild=true
dotnet pack src/SharpTls/SharpTls.csproj -c Release --no-build -o artifacts/raw-b -p:ContinuousIntegrationBuild=true
dotnet run --project tools/SharpTls.PackageReproducibility -c Release --no-build -- artifacts/raw-a/SharpTls.VERSION.nupkg artifacts/pack-a/SharpTls.VERSION.nupkg
dotnet run --project tools/SharpTls.PackageReproducibility -c Release --no-build -- artifacts/raw-b/SharpTls.VERSION.nupkg artifacts/pack-b/SharpTls.VERSION.nupkg
```

Repeat the normalizer for the two `.snupkg` files as well. The SDK's NuGet pack task
generates random OPC core-property names/relationship IDs and current ZIP timestamps,
even when compiler output is deterministic. `tools/SharpTls.PackageReproducibility`
strictly parses the bounded archive, rejects unsafe/duplicate paths, replaces only that
packaging metadata with canonical values, sorts entries and writes a fixed timestamp.
It does not modify the assembly, PDB, XML docs, nuspec, README, notices or security
policy. Both normalized directories must contain an ordinary `.nupkg` and portable-
symbol `.snupkg`; corresponding files must be byte-for-byte identical. CI enforces this,
then restores the package into a clean consumer before publishing the first directory
as a workflow artifact.

`tools/SharpTls.ApiCompat` emits the canonical exported API, including signatures,
nullability, generic constraints, defaults and visible members. The test suite compares
that output with `tests/SharpTls.Tests/Api/PublicApi.Shipped.txt`. Any change requires an
intentional baseline review and an appropriate semantic-version decision; silently
regenerating the baseline is not a fix.

## Managed fuzz/stress harness

`tools/SharpTls.Fuzz` is a bounded, dependency-free mutation and corpus runner for the
ClientHello import/JSON paths, TLS 1.2/1.3 peer-flight parsers, certificate framing,
record/handshake deframing, tickets, ECH, QUIC transport parameters, DNS wire parsing,
QUIC CRYPTO reassembly, TLS 1.2/1.3 AEAD record rejection, and strict client/server state
machines. Rejections must remain inside their documented
public protocol/data exception boundary; an escaping runtime exception prints the exact
target, length, SHA-256 and base64 reproducer and exits non-zero. Each input also has
configurable elapsed-time and current-thread allocation ceilings (`--max-input-ms` and
`--max-allocated-bytes`) so accidental CPU/allocation explosions become retained failures.
The ceilings are per target; `--target all` scales the aggregate ceiling by the exact
number of dispatched targets. State-machine inputs execute at most 512 actions because
their finite transition coverage saturates well before unbounded exception-heavy tails.
The corpus exporter produces deterministic target-specific directories: 79 entries
across the seven directories and 39 unique seeds in the combined runner. Every target
starts with common framing boundaries, then adds successful structural paths for its own
parsers (including TLS 1.2/1.3 certificates, tickets, AEAD records, ECH/QUIC/DNS and
complete state-machine paths). Unit tests prove those seeds reach successful paths and
that two exports are byte-for-byte identical.

Useful commands:

```shell
dotnet run --project tools/SharpTls.Fuzz -- --list-targets
dotnet run --project tools/SharpTls.Fuzz -- --target clienthello --iterations 100000 --seed 1511464998
dotnet run --project tools/SharpTls.Fuzz -- --target all --corpus path/to/regression-corpus
dotnet run --project tools/SharpTls.Fuzz -- --target records --stdin < input.bin
dotnet run --project tools/SharpTls.Fuzz -- --target all --export-corpus artifacts/fuzz-seeds
```

The ordinary test suite links the same target registry and runs a bounded deterministic
smoke corpus on every platform. Long-running campaigns use the standalone runner so a
crash reproducer can be retained as a focused regression test.

For actual edge-coverage feedback, `tools/SharpTls.CoverageFuzz` links the same targets
to SharpFuzz 2.3.0's `Fuzzer.LibFuzzer.Run` entry point. Select exactly one target with
`SHARPTLS_COVERAGE_FUZZ_TARGET`, publish/instrument the harness with the pinned
`SharpFuzz.CommandLine` tool, and invoke it with a pinned libfuzzer-dotnet driver and a
retained corpus. This external campaign setup is intentionally not downloaded or
executed by the library or normal unit-test job. The exact driver binary hash,
instrumenter version, duration, corpus-before/after hashes, coverage report and crash
disposition belong in the hosted campaign record.

The scheduled/manual/tag `coverage-fuzz` job performs this setup on Linux with the
pinned SharpFuzz CLI and a source-commit-pinned, SHA-256-verified libfuzzer-dotnet
driver. It instruments both the library and harness, runs every target in an independent
retained corpus with timeout/RSS/input limits, and uploads corpora plus crash artifacts
even when a target fails. Its bounded 60-second-per-target run is a continuous regression
gate; it is not represented as the required multi-day qualification campaign.

The upstream runner and instrumentation procedure are documented by
[SharpFuzz](https://github.com/Metalnem/sharpfuzz) and its
[libFuzzer integration](https://github.com/Metalnem/sharpfuzz/blob/master/docs/libFuzzer.md).

## Benchmarks

`benchmarks/SharpTls.Benchmarks` measures ClientHello parsing, JSON v6 import, QUIC
transport-parameter parsing, HKDF label expansion, handshake deframing and AES-128-GCM
record round trips. `--verify` applies deliberately conservative per-operation CPU and
allocation ceilings suitable for shared CI machines; the CSV output is invariant-culture
and can be archived for trend analysis.

## Hosted and external evidence

The exact primitive ownership, capability probes and operating-system qualification
rules are maintained in [PLATFORM-PROVIDERS.md](PLATFORM-PROVIDERS.md).

The three-OS job must succeed on GitHub-hosted Linux, macOS and Windows runners. The
commit-pinned workflow also runs the opt-in public interoperability matrix on its weekly
schedule, manual dispatch and release tags; the tag provenance job cannot start unless
that matrix succeeds. A
`v*` tag is packaged only after the platform and release-quality jobs pass; GitHub's
OIDC-backed build-provenance attestation is attached to both package artifacts. The
workflow intentionally does not publish to NuGet because publication credentials and
the release decision belong to the package owner.

Multi-day campaigns, multi-stack qualification and any independent cryptographic or
protocol review remain external evidence. Record their immutable run IDs, tool versions,
corpus hashes, package hashes and disposition in the release record. They must never be
marked complete solely because deterministic local tests pass.

The engineering threat-model baseline is [THREAT-MODEL.md](THREAT-MODEL.md). Its
residual-risk list is an input to independent review, not evidence that review occurred.
