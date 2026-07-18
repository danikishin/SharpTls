## What changed?

<!-- Describe the smallest user-visible and protocol-visible change. -->

## Protocol and security impact

<!-- Cite relevant RFC sections and affected invariants from SECURITY.md. -->

- RFC section(s):
- State-machine/transcript impact:
- New allocation or input bounds:
- Secret-lifetime impact:

## Verification

- [ ] Focused positive tests added or updated
- [ ] Malformed/hostile negative tests added or updated
- [ ] `dotnet test SharpTls.slnx --configuration Release` passes
- [ ] Fuzz smoke run when parsing/framing/state changed
- [ ] Interoperability evidence supplied when wire behavior changed
- [ ] Documentation and `CHANGELOG.md` updated
- [ ] No live secrets, private keys or unredacted captures are included

## Compatibility

<!-- Note public API, ClientHello JSON schema, profile wire image, platform/provider, or package impact. -->
