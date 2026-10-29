# Releasing

This guide is for maintainers. Public setup remains in the README. The initial
release version is **0.1.0**. Preparing a release does not publish it.

## Check a candidate

After the release preparation has merged, run the **Release** workflow from
`main`, with version `0.1.0` and **publish unchecked**:

```sh
gh workflow run release.yml --ref main -f version=0.1.0 -F publish=false
```

The workflow runs CI, builds the distributions and retains reviewable artifacts
for 14 days. Open its run in Actions, check every job, and download the artifacts.
These artifacts are temporary review downloads, not public releases.

## Before publishing

Complete the connected release checks, confirm the exact main commit and tested
sidecar/SDK combination, and obtain the owner's release approval. Create only
that approved `v0.1.0` tag; never move a published tag. The publish workflow
requires the tag to point to the exact main commit being run. An intervening
main commit requires reviewing the release identity again.

Configure the GitHub environment below with the owner as a required reviewer
and deployment branches restricted to `main`. Publishing is a separate manual
Release workflow run with **publish checked**. A pull request, ordinary push
or check-only run cannot publish.

## Sidecar setup

Use GitHub environment **release**. The approved registry is
`ghcr.io/authrail/authrail-sidecar`. Publishing uses the repository's short-lived
GitHub token with package-write permission, not a stored registry password.

The candidate run builds native archives for Linux/macOS, amd64/arm64, and Docker
images for Linux amd64/arm64. Native runtime/restart tests run on the CI host
platforms; the additional native targets are cross-compiled. Both container
architectures run the container checks, with arm64 emulation on the hosted runner.
Each binary reports its version/revision through `--version`.

The publish job downloads and verifies the checked artifacts, pushes the saved
images with versioned architecture tags, assembles the versioned multi-platform
image, then creates a GitHub release containing native archives and checksums.
It does not rebuild the images while holding registry credentials or overwrite
an existing version. A partial publication requires review before retrying.

After first publication, check the GHCR package's visibility is **Public** and
verify anonymous pulls. Use the published image digest for deployment. Check
native archive checksums and binary/manifest identity, install from an empty
setup, and verify the exact SDK/package combination before updating public docs.
The check-only image archives are review artifacts, not published registry images.
