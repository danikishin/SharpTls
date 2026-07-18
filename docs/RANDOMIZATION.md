# Coherent profile randomization and rolling

`ClientHelloProfileRandomizer` creates only profiles that pass the same executable
specification validation as hand-built profiles. It filters AEAD suites and NIST
ECDHE groups against runtime provider availability, then shuffles suite, group,
signature and extension order; chooses a bounded initial key-share prefix; selects a
weighted ALPN variant; and applies configured GREASE and padding probabilities. Generated
profiles include conditional TLS 1.3 resumption/0-RTT slots by default and can independently
randomize ALPS and semantic GREASE ECH. The
default GREASE policy generates distinct values per semantic slot; custom equality
patterns are available through `ClientHelloGreasePolicy`.

```csharp
var profile = ClientHelloProfileRandomizer.CreateSecure(
    new ClientHelloRandomizationOptions
    {
        AlpnVariants =
        [
            new ClientHelloAlpnVariant(4, "h2", "http/1.1"),
            new ClientHelloAlpnVariant(1, "http/1.1"),
        ],
        GreaseProbabilityPercent = 75,
        GreaseEchProbabilityPercent = 25,
        ApplicationSettingsProbabilityPercent = 33,
        MaximumPaddingLength = 64,
    });
```

Production generation uses runtime cryptographic entropy. The explicitly named
`CreateDeterministicForTesting` API makes profile policy reproducible for tests; a
normal connection created from that profile still generates its ClientHello random,
session ID, GREASE value, and ECDHE keys securely. The separate deterministic wire
builder remains test-only and must not be transmitted.

## Bounded Roller

`ClientHelloProfileRoller` first uses an origin's previously successful profile and
otherwise securely shuffles the current Chrome Auto, Firefox Auto, iOS Auto and one
fresh coherent randomized profile, matching the upstream uTLS Roller family set. The
pinned pool and randomized member are configurable. Successful profiles are
stored in a thread-safe, capacity-bounded LRU keyed by transport host, port, and
reference identity.

All `CustomTlsClientOptions` are carried to every candidate, including record policy,
session caches, external PSK/0-RTT, ECH/ECH-GREASE, ALPS payloads, client credentials,
certificate evidence policy, pre-send inspection, key logging and handshake observers.
The caller's original options are validated once; candidates that cannot satisfy those
features are discarded before network I/O rather than weakening or dropping a policy.

```csharp
var roller = new ClientHelloProfileRoller(new ClientHelloRollerOptions
{
    MaximumAttempts = 3,
    CacheCapacity = 256,
});

await using var client = await roller.ConnectAsync(
    new CustomTlsClientOptions { ServerName = "example.com" },
    "example.com",
    443,
    cancellationToken);
```

The default pinned browser profiles intentionally offer `h2` before `http/1.1` where
their captured fingerprint does. A caller that implements only HTTP/1.1 can set
`CandidateProfiles = []` and configure the randomized ALPN variants to only
`"http/1.1"`; otherwise it must honor `NegotiatedApplicationProtocol`. Roller does not
rewrite a pinned profile's ALPN because doing so would destroy its exact fingerprint.

Retries use bounded exponential delay and occur only after explicit peer alerts that
can represent offer negotiation failure: `handshake_failure`, `protocol_version`,
`missing_extension`, `unsupported_extension`, or `no_application_protocol`.
Certificate, chain, hostname, signature, Finished, AEAD, malformed-message, local
validation, cancellation, socket, and generic I/O failures are never converted into
profile retries. The Roller cannot relax or replace certificate policy.

Phase 17 is complete: a 4,096-seed distribution gate checks configured weights and
order entropy, a 250-seed executable-property corpus checks every generated offer,
bounded retry/cache-isolation tests cover Roller policy, and public-server TLS/HTTP
interoperability covers secure randomized and cached profiles.
