# Pinned uTLS ClientHello profiles

SharpTls profile data is derived from the official uTLS `UTLSIdToSpec` table at commit
`880e27d8b0e5daafd2a39bb3fb2e0c29211c0d40`. The license and attribution are retained
in [THIRD-PARTY-NOTICES.md](../THIRD-PARTY-NOTICES.md).

| SharpTls property | uTLS source ID | Negotiation evidence |
|---|---|---|
| `UTlsChrome58` | `HelloChrome_58` | Pinned full-wire/JSON round trip; legacy TLS 1.2 |
| `UTlsChrome62` | `HelloChrome_62` | Same pinned wire table as Chrome 58 |
| `UTlsChrome70` | `HelloChrome_70` | Pinned full-wire/JSON round trip; executable TLS 1.3 shape |
| `UTlsChrome72` | `HelloChrome_72` | Pinned full-wire/JSON round trip; executable TLS 1.3 shape |
| `UTlsChrome83` | `HelloChrome_83` | TLS 1.3/X25519 public-server pass |
| `UTlsChrome87` | `HelloChrome_87` | Same pinned wire table as Chrome 83 |
| `UTlsChrome96` | `HelloChrome_96` | TLS 1.3/X25519 public-server pass; legacy ALPS 17513 |
| `UTlsChrome100` | `HelloChrome_100` | TLS 1.3/X25519 public-server pass; legacy ALPS 17513 |
| `UTlsChrome100Psk` | `HelloChrome_100_PSK` | Conditional real ticket/binder; pinned no-padding wire shape |
| `UTlsChrome102` | `HelloChrome_102` | Same pinned wire table as Chrome 100 |
| `UTlsChrome106Shuffle` | `HelloChrome_106_Shuffle` | Secure per-connection shuffle; deterministic/HRR order tests |
| `UTlsChrome112PskShuffle` | `HelloChrome_112_PSK_Shuf` | Conditional real ticket/binder; secure shuffle; no padding |
| `UTlsChrome114PaddingPskShuffle` | `HelloChrome_114_Padding_PSK_Shuf` | Conditional real ticket/binder; secure shuffle and Boring padding |
| `UTlsChrome115Pq` | `HelloChrome_115_PQ` | Executable X25519Kyber768Draft00; secure shuffle and draft-order tests |
| `UTlsChrome115PqPsk` | `HelloChrome_115_PQ_PSK` | Draft hybrid plus conditional real ticket/binder |
| `UTlsChrome120` | `HelloChrome_120` | BoringSSL GREASE ECH and secure extension shuffle |
| `UTlsChrome120Pq` | `HelloChrome_120_PQ` | Draft hybrid plus BoringSSL GREASE ECH |
| `UTlsChrome131` | `HelloChrome_131` | Executable X25519MLKEM768 plus BoringSSL GREASE ECH |
| `UTlsChrome133` | `HelloChrome_133` | X25519MLKEM768, GREASE ECH and ALPS 17613 |
| `UTlsEdge85` | `HelloEdge_85` | Same pinned wire table as Chrome 83 |
| `UTlsEdge106` | `HelloEdge_106` | Same pinned wire table as Chrome 100 |
| `UTlsFirefox55` | `HelloFirefox_55` | Pinned full-wire/JSON round trip; legacy TLS 1.2 |
| `UTlsFirefox56` | `HelloFirefox_56` | Same pinned wire table as Firefox 55 |
| `UTlsFirefox63` | `HelloFirefox_63` | Pinned full-wire/JSON round trip; executable TLS 1.3 shape |
| `UTlsFirefox65` | `HelloFirefox_65` | Same pinned wire table as Firefox 63 |
| `UTlsFirefox99` | `HelloFirefox_99` | TLS 1.3/X25519 public-server pass |
| `UTlsFirefox102` | `HelloFirefox_102` | TLS 1.3/X25519 public-server pass; h2-only ALPN |
| `UTlsFirefox105` | `HelloFirefox_105` | TLS 1.3/X25519 public-server pass |
| `UTlsFirefox120` | `HelloFirefox_120` | Semantic 223+16-byte GREASE ECH; deterministic and option-integration tests |
| `UTlsFirefox148` | `HelloFirefox_148` | X25519MLKEM768 with reused X25519 component; exact ordered extensions |
| `UTlsIOS11_1` | `HelloIOS_11_1` | Pinned full-wire/JSON round trip; legacy TLS 1.2 |
| `UTlsIOS12_1` | `HelloIOS_12_1` | Pinned full-wire/JSON round trip; legacy TLS 1.2 |
| `UTlsIOS13` | `HelloIOS_13` | TLS 1.3/X25519 public-server pass |
| `UTlsIOS14` | `HelloIOS_14` | TLS 1.3/X25519 public-server pass |
| `UTlsSafari16` | `HelloSafari_16_0` | TLS 1.3/X25519/Zlib public-server pass |
| `UTlsSafari263` | `HelloSafari_26_3` | X25519MLKEM768 and historical Apple duplicate-signature wire shape |
| `UTlsAndroid11OkHttp` | `HelloAndroid_11_OkHttp` | TLS 1.2/X25519 public-server pass |
| `UTls360_7_5` | `Hello360_7_5` | Pinned wire-only legacy profile; weak suites are non-executable |
| `UTls360_11_0` | `Hello360_11_0` | Pinned full-wire/JSON round trip; executable TLS 1.3 shape |
| `UTlsQQ11_1` | `HelloQQ_11_1` | Pinned full-wire/JSON round trip; legacy ALPS 17513 |

Version-bound aliases select the newest executable profile included in the installed
SharpTls package: `UTlsChromeAuto` → `UTlsChrome133`, `UTlsFirefoxAuto` →
`UTlsFirefox148`, `UTlsEdgeAuto` → `UTlsEdge106`, `UTlsIOSAuto` → `UTlsIOS14`,
`UTlsSafariAuto` → `UTlsSafari263`, and `UTlsAndroidAuto` →
`UTlsAndroid11OkHttp`. Application-family aliases also expose `UTls360Auto` →
`UTls360_11_0` and `UTlsQQAuto` → `UTlsQQ11_1`. The historical 360/7.5 image remains
available only through its explicit pinned property. “Auto” means newest securely
executable profile shipped and verified by that SharpTls
version; it does not claim to match the browser currently installed on the machine.
Applications requiring a stable fingerprint should use the pinned property directly.

The mixed-version profiles preserve their older cipher-suite and supported-version
offers exactly and dispatch the same original transcript to the selected TLS 1.3 or
TLS 1.2 engine. The TLS 1.2 engine executes only the authenticated ECDHE/AEAD subset;
legacy fingerprint suites remain visible on the wire but fail closed if selected.
Android 11 OkHttp is connection-capable through this restricted TLS 1.2 path.

Profile tests pin suite, version, group, key-share, signature and extension ordering;
GREASE values and ephemeral keys remain fresh. The added Chrome 96/100/106/112/114,
Firefox 102/105/120, iOS 13, and every added legacy upstream family also carry fixed
deterministic full-wire SHA-256 snapshots and exact
capture/JSON round trips. Chrome-family and GREASE-era Apple profiles pin the two GREASE
extension bodies, the shared group/key-share GREASE slot, and BoringSSL's dynamic
512-byte padding behavior.

Chrome 106 and later profiles securely shuffle every extension except semantic GREASE,
padding and `pre_shared_key`; the chosen order is retained across HelloRetryRequest.
Chrome 120+ and Firefox 120/148 automatically emit their pinned GREASE-ECH policy.
Generated config IDs, X25519 encapsulations and payload bytes remain fresh per connection.

Chrome 131/133, Firefox 148 and Safari 26.3 use standards-track X25519MLKEM768. The
client share is `ML-KEM public key || X25519 public key`, the server share is
`ML-KEM ciphertext || X25519 public key`, and the derived secret follows the same order.
Where upstream reuses a hybrid X25519 component in a separate classical key share,
SharpTls does too. Chrome 115/120 PQ instead use obsolete X25519Kyber768Draft00 with
the reversed component order and Kyber Round-3 final SHAKE derivation; it is retained
only for historical interoperability and is never substituted for the standard group.

The pinned Chrome PSK variants use the same authenticated session cache and binder
calculation as every resumable SharpTls profile. Chrome 100/112 PSK omit Boring
padding exactly as upstream; Chrome 114 retains it. Chrome 112/114 shuffle only the
movable extensions, while `pre_shared_key` remains the mandatory final extension.

Chrome 96/100/102/106 and Edge 106 retain uTLS's experimental legacy
`application_settings` code point 17513 with `h2` as its protocol dependency. Firefox
102 intentionally offers only `h2`; callers selecting that exact profile must provide
an HTTP/2 application path after ALPN negotiation. These are TLS-visible profiles, not
claims that SharpTls automatically imitates the corresponding browser's HTTP behavior.

Only pinned PSK variants contain a conditional semantic `pre_shared_key` slot. It emits
no bytes without a caller-owned cache ticket; with a ticket, SharpTls preserves the
profile order and emits `pre_shared_key` last. General early-data-capable custom profiles
must explicitly include the semantic `early_data` slot. TLS-1.2-only profiles can use
caller-owned session-ID/RFC 5077 resumption
when they carry the relevant session-ticket slot; this does not change their initial wire snapshots.

Legacy profile support never enables legacy cryptography. CBC, RC4, 3DES, finite-field
DHE, static RSA and DSA values needed for byte-faithful older ClientHellos are explicitly
fingerprint-only enum values. SharpTls has no record cipher or signature implementation
for them and rejects the handshake if a peer selects one. `UTls360_7_5` also lacks the
mandatory modern EMS policy and is therefore intentionally buildable/serializable but
not connection-capable.

Exact profiles may advertise ALPN `h2`. SharpTls exposes the negotiated ALPN value,
but implementing the selected HTTP/2 protocol belongs to the caller or a separate
integration package. The built-in HTTP/1.1 executable remains only an interop example.
