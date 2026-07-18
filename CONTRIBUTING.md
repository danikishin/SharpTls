# Contributing to SharpTls

SharpTls welcomes focused bug fixes, protocol tests, interoperability evidence,
documentation improvements and standards-based features that preserve its TLS-library
boundary. This is security-sensitive protocol code, so changes are reviewed for wire
correctness, state transitions, memory bounds and failure behavior as well as the happy
path.

## Before opening an issue

- Search existing issues and the [roadmap](docs/ROADMAP.md).
- Use a private channel for vulnerabilities; follow [SECURITY.md](SECURITY.md).
- Keep HTTP clients, HTTP/2, HTTP/3 and full QUIC transport features out of scope.
- Include the .NET SDK/runtime, operating system, target server and a minimal reproducer.
- Redact packet captures. Never attach private keys, session secrets or decrypted traffic.

## Local setup

The repository pins the .NET SDK through `global.json`.

```shell
dotnet --info
dotnet restore SharpTls.slnx
dotnet test SharpTls.slnx --configuration Release
```

For parser, framing, handshake-state or crypto-provider changes, also run:

```shell
dotnet run --project tools/SharpTls.Fuzz --configuration Release -- --iterations 10000
dotnet run --project benchmarks/SharpTls.Benchmarks --configuration Release -- --verify
```

Real-server tests are opt-in because they use public network services:

```shell
SHARPTLS_RUN_INTEROP=1 dotnet test tests/SharpTls.Tests/SharpTls.Tests.csproj \
  --configuration Release --filter "Category=Interop"
```

## Change rules

1. Add the smallest explicit protocol component that owns the new responsibility.
2. Cite the relevant RFC section in code documentation or the focused design document.
3. Add positive vectors and malformed/hostile negative tests.
4. Enforce lengths before allocation and consume parser inputs completely.
5. Preserve exact transcript bytes and reject illegal state transitions.
6. Use .NET cryptographic primitives whenever the runtime exposes the needed primitive.
7. Zero caller-independent secret buffers on every success and failure path.
8. Never turn a wire-fidelity feature into an authentication-policy bypass.
9. Update the relevant documentation and the `Unreleased` changelog section.

Deterministic entropy and fixed keys belong only in explicitly named test/snapshot APIs.
Production paths must continue to use secure runtime entropy.

## Pull requests

Keep a pull request narrowly scoped and explain:

- the protocol behavior and RFC sections changed;
- the security invariants affected;
- positive, negative and interoperability evidence;
- any provider or platform limitations;
- whether the public API or serialized ClientHello JSON schema changes.

All CI jobs must pass. Maintainers may ask for a protocol vector, packet capture summary,
allocation bound or additional hostile-input test before merging.

By contributing, you agree that your contribution is licensed under the repository's
[MIT License](LICENSE), while preserving applicable third-party notices.
