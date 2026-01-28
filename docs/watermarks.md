---
id: watermarks
title: Watermarks
---

# Understanding Watermarks in Signatory

## What Are Watermarks?

Watermarks in Signatory are a critical security feature that prevent **double signing** of operations at the same block level or round. Double signing is a serious issue in the Tezos network that can result in penalties including loss of staked tokens (slashing).

Think of watermarks as checkpoints that track the highest block level and round number that has been signed by each key. When a new signing request arrives, Signatory checks if it's for a higher level or round than what's recorded in the watermark - only allowing the signature if it passes this check.

## Why Watermarks Are Essential

Watermarks provide three critical benefits:

1. **Prevention of Stake Slashing**: Double signing the same block level on the Tezos network results in penalties that can include loss of staked tokens.

2. **Protection Against Accidental Double Baking**: Even with a single baker instance, watermarks ensure that system restarts or errors don't result in re-signing operations that were already signed.

3. **Support for High-Availability Setups**: When running multiple Signatory instances for redundancy, watermarks prevent multiple instances from simultaneously signing the same operation.

## How Watermarks Work

Here's the basic flow of how watermarks operate:

1. When Signatory receives a signing request (block, attestation, etc.), it extracts the operation's level and round number
2. Signatory checks the stored watermark for the corresponding key and operation type
3. If the new operation has a higher level or round, it's allowed to proceed
4. After successful signing, the watermark is updated to the new level/round
5. Any future request at the same or lower level/round will be rejected

## Choosing a Watermark Backend

Signatory supports three watermark backend types, each suited for different deployment scenarios:

### File System (`file`) - Default
- **Best for**: Standalone, single-instance bakers
- **Pros**: Simple setup, persistent across restarts
- **Cons**: Not suitable for distributed environments or high-availability setups
- **Configuration**: [See documentation](#file-backend-configuration)

### Memory (`mem`)
- **Best for**: Testing and development only
- **Pros**: Simple, no configuration needed
- **Cons**: Watermarks are lost when Signatory is restarted, making it unsuitable for production
- **Configuration**: [See documentation](#memory-backend-configuration)

### AWS DynamoDB (`aws`)
- **Best for**: Production environments, especially cloud-based or high-availability setups
- **Pros**:
  - Persistent storage independent of the Signatory instance
  - Supports concurrent access with strong consistency
  - Enables multiple Signatory instances to safely share signing keys
- **Configuration**: [See detailed documentation](aws_dynamodb.md)

### Google Firestore (`gcp`)
- **Best for**: Production environments, especially cloud-based or high-availability setups
- **Pros**:
  - Persistent storage independent of the Signatory instance
  - Supports concurrent access with strong consistency
  - Enables multiple Signatory instances to safely share signing keys
- **Configuration**: [See detailed documentation](gcp_firestore.md)

## Configuration Examples

### Basic Configuration

The watermark section is optional in your configuration file. If omitted, the `file` driver is used as the default.

```yaml
watermark:
  driver: file  # Options: file, mem, aws
```

### File Backend Configuration

The file watermark backend stores watermark data in JSON files in the local filesystem. It uses the `base_dir` from the main configuration to determine where to store the files.

```yaml
# Main configuration
base_dir: /var/lib/signatory  # Default if not specified

watermark:
  driver: file
  # No additional configuration needed for the file driver itself
```

Watermark files are stored in the `watermark_v2` subdirectory under the specified `base_dir`. For example, with the default configuration, watermarks would be stored in:

```
/var/lib/signatory/watermark_v2/
```

Each chain ID gets its own JSON file within this directory, containing watermarks for all keys on that chain. There is no additional configuration specific to the file watermark backend - it simply uses the global `base_dir` setting.

### Memory Backend Configuration

```yaml
watermark:
  driver: mem
  # No additional configuration needed
```

### AWS DynamoDB Backend Configuration

See the [AWS DynamoDB Watermark Backend](aws_dynamodb.md) documentation for detailed configuration options.

## High-Availability Considerations

When setting up multiple Signatory instances for high availability:

1. **Choose the right backend**: The AWS DynamoDB backend is specifically designed for this scenario
2. **Ensure consistent configuration**: All instances must use the same watermark backend configuration
3. **Monitor performance**: Watch for potential latency when accessing remote watermark storage
4. **Test failover scenarios**: Validate that watermark protection works when instances fail

## Troubleshooting

### Common Errors

**"watermark validation failed" error**:
- This is a safety mechanism indicating Signatory blocked a potential double signing attempt
- If you're seeing this unexpectedly, check if:
  - Multiple Signatory instances are configured with different watermark backends
  - Your watermark storage has been lost or reset
  - The same key is being used by different bakers

### Diagnosing Issues

Enable debug logs to see more information about watermark checks.

```bash
signatory serve --log debug -c /path/to/config.yaml
```

Valid log levels are: `error`, `warn`, `info`, `debug`, `trace`

In debug mode, Signatory logs each watermark check and update, making it easier to diagnose potential issues.

## Prometheus Metrics

Signatory exposes Prometheus metrics for monitoring watermark operations. These metrics help operators track performance, detect issues, and analyze behavior across different backend implementations.

### Core Metrics (All Backends)

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `watermark_operations_total` | Counter | `result`, `backend`, `request_type` | Total number of watermark operations |
| `watermark_operation_duration_seconds` | Histogram | `backend` | Watermark operation duration in seconds |
| `watermark_rejection_total` | Counter | `address`, `operation_type`, `chain_id`, `reason` | Total count of operations rejected due to watermark protection |

**Label values:**
- `result`: `success`, `rejected`
- `backend`: `file`, `mem`, `aws`, `gcp`, `ignore`
- `request_type`: The type of signing request (e.g., `block`, `attestation`, `preendorsement`)

### File Backend Metrics

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `watermark_file_operations_total` | Counter | `operation`, `result` | Total number of file I/O operations |
| `watermark_file_latency_seconds` | Histogram | `operation` | File I/O latency in seconds |

**Label values:**
- `operation`: `read`, `write`
- `result`: `success`, `error`

### AWS DynamoDB Backend Metrics

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `watermark_aws_dynamodb_operations_total` | Counter | `operation`, `table_name`, `result` | Total number of DynamoDB operations |
| `watermark_aws_dynamodb_latency_seconds` | Histogram | `operation`, `table_name` | DynamoDB operation latency in seconds |
| `watermark_aws_dynamodb_errors_total` | Counter | `error_type`, `table_name`, `operation` | Total number of DynamoDB errors |

**Label values:**
- `operation`: `put`, `create_table`
- `result`: `success`, `error`
- `error_type`: AWS error code (e.g., `ConditionalCheckFailedException`)

### Example Prometheus Queries

**Watermark rejection rate:**
```promql
rate(watermark_operations_total{result="rejected"}[5m])
```

**Average watermark operation duration by backend:**
```promql
histogram_quantile(0.95, rate(watermark_operation_duration_seconds_bucket[5m]))
```

**DynamoDB error rate:**
```promql
rate(watermark_aws_dynamodb_errors_total[5m])
```