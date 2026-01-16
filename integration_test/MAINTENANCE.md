# Integration Test Maintenance

## Octez Version Update Playbook

When a new Octez version is released, follow these steps:

### 1. Check Release Notes

Review the [Octez releases page](https://octez.tezos.com/releases/) and [changelog](https://octez.tezos.com/docs/CHANGES.html) for:
- Breaking changes
- Deprecated features (e.g., protocol-specific bakers removed in v25)
- New protocol support
- RPC changes that might affect tests

### 2. Update Version Files

**For stable releases**, update `.env.current`:
```bash
export OCTEZ_VERSION=octez-v24.0  # Update to new version
export PROTOCOL=PtSeouLo          # Update if protocol changed
```

**For release candidates**, update `.env.next`:
```bash
export OCTEZ_VERSION=octez-v25.0-rc1  # Update to new RC
export PROTOCOL=PtNewProto            # Update if testing new protocol
```

### 3. Protocol Hash Reference

Current mainnet protocol hashes:
- `PtSeouLo` - Seoul (current mainnet as of 2025)
- `PtTALLiN` - Tallinn (next)

Find protocol hashes at: https://tzkt.io/

### 4. Test Locally

```bash
# Clean and rebuild
cd integration_test
docker system prune -f
./run-tests.sh build
./run-tests.sh
```

### 5. Common Issues

| Issue | Solution |
|-------|----------|
| Image not found | Check Docker Hub for correct tag: `docker pull tezos/tezos:octez-vX.Y` |
| Protocol mismatch | Verify protocol hash matches octez version support |
| Deprecated baker | v24+ uses unified `octez-baker`, not `octez-baker-<protocol>` |
| New RPC format | Check if test assertions need updating for changed RPC responses |

### 6. CI Verification

After updating, ensure the GitHub Actions workflow passes:
- The CI uses the same `.env.current` values
- Check workflow run for any new failures

## Automated Version Checking

A GitHub Action runs nightly to check for new Octez releases. When a new version is detected, it creates an issue to notify maintainers.

See: `.github/workflows/check-octez-version.yml`
