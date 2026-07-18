# Releasing SharpTls

SharpTls uses one tag-driven release path. A `v<SemVer>` tag builds the matching NuGet
version only after the platform tests, release-quality checks, public interoperability
and coverage-guided fuzz jobs pass.

## One-time repository setup

1. Create the GitHub repository and push the default branch.
2. In nuget.org, create a Trusted Publishing policy for the GitHub repository and the
   workflow file `ci.yml`. Enter only that filename, not `.github/workflows/ci.yml`.
3. Add the nuget.org profile name—not an email address—as the GitHub Actions repository
   secret `NUGET_USER`. The workflow exchanges GitHub OIDC identity for a one-hour,
   single-exchange NuGet key immediately before publishing.
4. If Trusted Publishing is not available for the account, create a short-lived API key
   scoped to package ID `SharpTls` and store it as `NUGET_API_KEY`. This is a fallback,
   not the preferred path.
5. Enable GitHub private vulnerability reporting and branch protection for the default
   branch. Require the `test` matrix and `release-quality` checks before merging.
6. Optionally protect a GitHub environment used for releases with required reviewers.

The workflow does not require NuGet credentials to build a release. Without either
publishing configuration it
still creates, normalizes, attests and uploads `.nupkg` and `.snupkg` assets to the
GitHub Release; only the NuGet.org push is skipped.

If the fallback is needed, use a short-lived, package-scoped NuGet key and rotate it
according to the project's credential policy. Never store it in a repository file,
command transcript or issue.

## Prepare a release

1. Confirm the version does not already exist on NuGet.org.
2. Move the intended entries from `Unreleased` into a dated version in `CHANGELOG.md`.
3. Update the default preview `<Version>` in `src/SharpTls/SharpTls.csproj` for normal
   branch package artifacts.
4. Run the local deterministic gates:

   ```shell
   dotnet restore SharpTls.slnx
   dotnet test SharpTls.slnx --configuration Release
   dotnet run --project tools/SharpTls.Fuzz --configuration Release -- --iterations 10000
   dotnet run --project benchmarks/SharpTls.Benchmarks --configuration Release -- --verify
   dotnet pack src/SharpTls/SharpTls.csproj --configuration Release --output artifacts/local
   ```

5. Inspect the package metadata and contents, then merge the release preparation.

## Publish

Create an annotated SemVer tag with a leading `v`:

```shell
git tag -a v0.9.0-preview.2 -m "SharpTls v0.9.0-preview.2"
git push origin v0.9.0-preview.2
```

The `provenance` job:

1. waits for every release gate;
2. validates the tag and maps it to `PackageVersion`;
3. creates deterministic package and symbol archives twice;
4. requires byte-for-byte equality after package normalization;
5. attests the release assets;
6. creates or updates the GitHub Release and uploads the assets;
7. exchanges OIDC identity through Trusted Publishing and publishes the package and
   matching symbols, or uses the explicitly configured API-key fallback.

Preview tags containing `-` are marked as prereleases. Re-running a release uploads the
same normalized assets with `--clobber`; NuGet publication uses `--skip-duplicate`.

## Verify after publication

- Confirm the GitHub Release contains both files and provenance attestations.
- Confirm NuGet.org finishes package validation and indexes the symbol package.
- Restore into a new project using only nuget.org.
- Run the HTTP/1.1 sample against at least two public TLS 1.3 endpoints.
- Record hosted evidence in the release notes and update the release-hardening document.

Do not delete and reuse a published version. Fix forward with a new SemVer tag.
