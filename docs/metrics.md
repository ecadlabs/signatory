# Signatory Prometheus Metrics

Signatory exposes several Prometheus metrics to help operators monitor the health, performance, and usage of the service.

## API Handler Metrics

These metrics track requests at the HTTP handler level, providing a high-level view of the signing API's performance and status.

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `sign_handler_requests_total` | Counter | `address`, `status` | Total number of sign handler requests |
| `sign_handler_request_duration_milliseconds` | Histogram | `address`, `status` | Total processing time for sign handler requests in milliseconds |

**Label values:**
- `address`: The Tezos public key hash of the key being used for signing.
- `status`: The HTTP status code returned to the client (e.g., `200` for success, `403` for policy rejection, `400` for bad requests).

## Vault Metrics

These metrics track interactions with the underlying cryptographic vaults (e.g., AWS KMS, YubiHSM, File).

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `signing_ops_total` | Counter | `address`, `vault`, `op`, `kind`, `chain_id` | Total number of signing operations completed |
| `vault_sign_request_duration_milliseconds` | Histogram | `vault`, `address`, `op`, `chain_id` | Vault signing request latencies in milliseconds |
| `vault_sign_request_error_total` | Counter | `vault`, `code`, `chain_id` | Total number of errors returned by the vault |

**Label values:**
- `op`: The sign request kind (e.g., `generic`, `block`, `attestation`, `preattestation`).
- `kind`: The operation kind extracted from request contents (e.g., `transaction`, `delegation`, `reveal`). For non-generic requests, this usually matches `op`.
- `chain_id`: The Tezos chain identifier.

## Consensus Metrics

Metrics for monitoring Tezos consensus round behavior. Round 0 is normal; round > 0 signals consensus delays.

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `consensus_round_total` | Counter | `address`, `operation_type`, `chain_id`, `round` | Total consensus signing operations by round |

**Example queries:**

Non-zero round rate (indicates consensus delays):
```promql
rate(consensus_round_total{round!="0"}[5m])
```

Round distribution by address:
```promql
sum by (address, round)(rate(consensus_round_total[5m]))
```

## Policy and Security Metrics

Metrics related to authorization and policy enforcement.

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `policy_violation_total` | Counter | `violation_type`, `address`, `operation_type` | Total count of operations rejected due to policy violations |
| `watermark_rejection_total` | Counter | `address`, `operation_type`, `chain_id`, `reason` | Total count of operations rejected due to watermark protection |
| `authentication_failure_total` | Counter | `status`, `auth_method`, `client_ip` | Total count of failed authentication attempts |

## Watermark Metrics

For detailed information on watermark-related metrics, see [Watermarks Documentation](./watermarks.md#prometheus-metrics).
