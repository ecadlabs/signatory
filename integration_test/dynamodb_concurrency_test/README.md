# DynamoDB Concurrency Test

This test validates Signatory's watermark protection against double signing in a concurrent environment. It specifically tests the fix for a critical bug where two Signatory instances could both sign the same block.

## The Bug

The original watermark validation logic had a special case that allowed signing operations with the same hash, level and round. While this might have been intended to allow re-signing the same operation after a restart, it created a security issue in high-availability setups.

In a multi-instance Signatory deployment:
1. Two Signatory instances would read the watermark from DynamoDB
2. Both would validate against the old watermark and decide it's safe to sign
3. The first would update the watermark successfully
4. The second would fail to update (due to conditional check)
5. The second would retry and read the updated watermark
6. With the bug: The second instance would still sign because the hash matched
7. With the fix: The second instance rejects because level/round is equal

## Running the Test

### 1. Start a local DynamoDB instance

First, start a local DynamoDB instance using Docker:

```sh
docker run -p 8000:8000 amazon/dynamodb-local
```

This will start a local DynamoDB service that listens on port 8000.

### 2. Run the test without caching

To ensure the test runs properly and doesn't use cached results:

```sh
cd integration_test/dynamodb_concurrency_test
go test -v -count=1 .
```

The `-count=1` flag ensures the test runs afresh without using cached results.

## Test Results Interpretation

- On the **original code** without the fix (main branch), the first test case should **fail** because it allows signing when hash, level and round are the same.
- On the **fixed code** (watermark_updates branch), the test should **pass** because it properly rejects signing requests with the same level/round regardless of hash.

## Implementation Details

The key change in the fix is removing the special condition:

```go
// Original code with bug
func (l *Watermark) Validate(stored *Watermark) bool {
    if l.Hash.IsSome() && stored.Hash.IsSome() && l.Hash.Unwrap() == stored.Hash.Unwrap() {
        return true // THIS IS THE BUG - allows double signing
    }
    var diff int32
    if d := l.Level - stored.Level; d == 0 {
        diff = l.Round - stored.Round
    } else {
        diff = d
    }
    return diff > 0
}

// Fixed code
func (l *Watermark) Validate(stored *Watermark) bool {
    var diff int32
    if d := l.Level - stored.Level; d == 0 {
        diff = l.Round - stored.Round
    } else {
        diff = d
    }
    return diff > 0
}
```

This ensures that watermarks are only accepted when level or round is strictly higher, preventing double signing even in high-availability deployments.
