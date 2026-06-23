# SLSA Supply Chain Security

Signatory implements [SLSA Level 3](https://slsa.dev/spec/v1.0/levels) supply chain security for container images. This provides verifiable build provenance during development and production releases.

## Overview

All Signatory builds automatically include:

1. **SLSA Level 3 Provenance**: Verifiable attestations about how container images were built
2. **Multi-Architecture Support**: Provenance generated for amd64, arm64, and armv7 architectures
3. **Reproducible Builds**: All builds run in isolated GitHub-hosted runners
4. **Automated Verification**: SLSA attestations are verified after generation

### Build and Deployment Strategy

- **Pull Requests & Main Branch**: Preview images pushed to GitHub Container Registry (GHCR) with branch/PR name tags
- **Tagged Releases** (`v*`, `rc*`): Production images pushed to Docker Hub
- **Provenance**: Generated for all non-tagged builds (PRs and main branch) for GHCR images

## What is SLSA?

SLSA (Supply chain Levels for Software Artifacts) is a security framework that helps prevent supply chain attacks. SLSA Level 3 provides:

- **Build integrity**: Builds run on isolated, ephemeral, hosted build platforms
- **Provenance generation**: Automated, non-falsifiable metadata about the build
- **Source integrity**: Strong guarantee about the source code being built

## Verification

### Verifying Container Images with SLSA Provenance

All preview images pushed to GHCR include SLSA Level 3 provenance attestations. You can verify these before testing.

#### Install SLSA Verifier

Install the official SLSA verifier from the [slsa-verifier releases page](https://github.com/slsa-framework/slsa-verifier/releases).

```bash
# Example: Download and install slsa-verifier (replace VERSION and PLATFORM as needed)
VERSION=v2.5.1  # Check releases page for latest version
PLATFORM=linux-amd64  # Options: linux-amd64, linux-arm64, darwin-amd64, darwin-arm64, etc.

curl -Lo slsa-verifier https://github.com/slsa-framework/slsa-verifier/releases/download/${VERSION}/slsa-verifier-${PLATFORM}
chmod +x slsa-verifier
sudo mv slsa-verifier /usr/local/bin/

# Verify installation
slsa-verifier version
```

#### Verify Container Image Provenance

```bash
# Verify a PR preview image by digest (replace branch-name and digest)
slsa-verifier verify-image \
  --source-uri github.com/ecadlabs/signatory \
  ghcr.io/ecadlabs/signatory@sha256:DIGEST_HERE

# Example for a specific branch
slsa-verifier verify-image \
  --source-uri github.com/ecadlabs/signatory \
  ghcr.io/ecadlabs/signatory@sha256:abc123...

# Verify all architectures
slsa-verifier verify-image \
  --source-uri github.com/ecadlabs/signatory \
  ghcr.io/ecadlabs/signatory@sha256:DIGEST_AMD64

slsa-verifier verify-image \
  --source-uri github.com/ecadlabs/signatory \
  ghcr.io/ecadlabs/signatory@sha256:DIGEST_ARM64

slsa-verifier verify-image \
  --source-uri github.com/ecadlabs/signatory \
  ghcr.io/ecadlabs/signatory@sha256:DIGEST_ARMV7
```

Expected successful verification output:

```
Verified signature against tlog entry index XXXXX at URL: https://rekor.sigstore.dev/api/v1/log/entries/...
Verified build using builder "https://github.com/slsa-framework/slsa-github-generator/.github/workflows/generator_container_slsa3.yml@refs/tags/v2.1.0" at commit COMMIT_SHA
Verifying artifact ghcr.io/ecadlabs/signatory@sha256:... : PASSED

PASSED: Verified SLSA provenance
```

#### Getting Image Digests

To find the digest for a specific image tag:

```bash
# Using Docker
docker pull ghcr.io/ecadlabs/signatory:branch-name-amd64
docker inspect ghcr.io/ecadlabs/signatory:branch-name-amd64 | grep Digest

# Using crane (install from https://github.com/google/go-containerregistry/releases)
crane digest ghcr.io/ecadlabs/signatory:branch-name-amd64
```

## Local Testing

Local testing of SLSA provenance generation requires GitHub Actions. However, you can test the container build process locally.

### Building Images Locally

```bash
# Build preview images using goreleaser
make release-preview

# This builds multi-architecture images using Docker Buildx
# Images are tagged with the git commit SHA
```

### Testing with Local Images

```bash
# Pull a preview image from GHCR
docker pull ghcr.io/ecadlabs/signatory:branch-name-amd64

# Run the image
docker run -p 6732:6732 ghcr.io/ecadlabs/signatory:branch-name-amd64
```

### Verifying Local Builds

SLSA provenance is only generated in GitHub Actions CI/CD pipeline. To verify a local build matches what will be built in CI:

1. Ensure your local environment matches the CI environment (Go version, dependencies)
2. Build using the same `make release-preview` command
3. Compare image digests with what's produced in CI

## Technical Implementation

### Architecture

The SLSA implementation uses:

- **GitHub Actions**: Hosted build platform providing isolation
- **[goreleaser](https://goreleaser.com/)**: Multi-platform binary and container builds
- **[SLSA GitHub Generator](https://github.com/slsa-framework/slsa-github-generator)**: Official SLSA container provenance generator
  - `generator_container_slsa3.yml@v2.1.0` for container images (version tracked in workflow)
- **[slsa-verifier](https://github.com/slsa-framework/slsa-verifier)**: Official verification tool for SLSA attestations (v2.5.1 used in CI)

### Workflow

The build workflow (`.github/workflows/build.yaml`) executes:

1. **Test**: Run unit tests with coverage collection
2. **Publish**: Build multi-architecture images using goreleaser
   - For PRs/main: Push to GHCR with branch name tags
   - For tagged releases: Push to Docker Hub
3. **Generate Provenance**: Create SLSA Level 3 attestations for each architecture:
   - Separate job for amd64, arm64, and armv7
   - Uses official SLSA container generator
4. **Verify**: Automatically verify all generated attestations using slsa-verifier
5. **Deploy**: Optional EC2 deployment and integration tests for preview builds

### Security Properties

#### SLSA Level 3 Guarantees

✅ **Source integrity**: Builds track exact git commit and repository source  
✅ **Build isolation**: Each build runs in a fresh, ephemeral GitHub-hosted runner  
✅ **Provenance availability**: Attestations generated for all preview builds (PRs and main branch)  
✅ **Non-falsifiable provenance**: Generated by trusted SLSA builder service  
✅ **Tamper resistance**: Attestations signed and stored in immutable Rekor transparency log  
✅ **Automated verification**: All attestations verified immediately after generation

#### Multi-Architecture Coverage

All three supported architectures receive SLSA attestations:

- **amd64**: Standard 64-bit x86 platforms
- **arm64**: 64-bit ARM platforms (Apple Silicon, modern ARM servers)
- **armv7**: 32-bit ARM platforms (Raspberry Pi, embedded devices)

Each architecture's image is independently attested and verified.

### Transparency

All SLSA provenance attestations are recorded in the public Rekor transparency log maintained by Sigstore:

- **Rekor**: https://rekor.sigstore.dev/

The SLSA generator automatically submits attestations to Rekor during the build process. You can search for Signatory container image attestations in the transparency log using the image digest.

## FAQ

### Why SLSA Level 3?

SLSA Level 3 provides strong supply chain security without requiring two-party review of all changes (Level 4). It ensures:
- Builds run on isolated, trusted infrastructure
- Provenance cannot be forged by the repository owner
- Complete build metadata is cryptographically verifiable

### Does this protect against compromised dependencies?

Partially. SLSA provenance shows exactly what source code was built and how, but doesn't verify dependency integrity. Additional security measures:

- Review `go.sum` for dependency changes in PRs
- Use `go mod verify` to check downloaded modules
- Scan dependencies with security tools (e.g., Dependabot, Snyk)
- Monitor for supply chain vulnerabilities

### Which builds get SLSA provenance?

Currently, SLSA provenance is generated for:
- Pull request preview builds (pushed to GHCR)
- Main branch builds (pushed to GHCR)

Tagged releases (`v*`, `rc*`) pushed to Docker Hub do not currently have SLSA provenance but may be added in future updates.

### What if verification fails?

**Do not use the image.** Verification failure indicates:

- The image was modified after attestation
- The provenance was tampered with
- The image doesn't match the claimed source

Pull the image again from GHCR. If verification still fails, report it as a security issue to security@ecadlabs.com.

### How do I get the digest for verification?

Image digests are required for SLSA verification. Get them from:

1. **CI artifacts**: Download `image-digests.txt` from workflow artifacts
2. **Docker inspect**: After pulling the image locally
3. **Registry API**: Query GHCR directly

See the "Getting Image Digests" section above for detailed commands.

### How does this relate to GitHub's artifact attestations?

GitHub's native artifact attestations (via `actions/attest-build-provenance`) provide similar functionality. We use the official SLSA GitHub Generator for:
- Explicit SLSA Level 3 certification
- Broader ecosystem compatibility
- Standardized verification tooling

## Resources

### Official Documentation

- [SLSA Specification](https://slsa.dev/) - Complete SLSA framework documentation
- [SLSA GitHub Generator](https://github.com/slsa-framework/slsa-github-generator) - Official SLSA v1.0 generator
- [Container Generator Documentation](https://github.com/slsa-framework/slsa-github-generator/tree/main/internal/builders/container) - Specific docs for container builds

### Tools

- [SLSA Verifier](https://github.com/slsa-framework/slsa-verifier) - Official verification tool ([releases](https://github.com/slsa-framework/slsa-verifier/releases))
- [GoReleaser](https://goreleaser.com/) - Multi-platform build automation ([docs](https://goreleaser.com/install/))
- [Crane](https://github.com/google/go-containerregistry/tree/main/cmd/crane) - Container registry utility ([releases](https://github.com/google/go-containerregistry/releases))
- [Docker](https://docs.docker.com/get-docker/) - Container runtime

### Infrastructure

- [Rekor Transparency Log](https://rekor.sigstore.dev/) - Public ledger for attestations
- [Sigstore](https://www.sigstore.dev/) - Infrastructure for signing and verification

## Security Reporting

To report security issues related to supply chain security, please contact security@ecadlabs.com.

