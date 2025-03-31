# DynamoDB Concurrency Test

This test validates Signatory's watermark protection against double signing in a concurrent environment. It focuses specifically on testing the fix for the watermark validation logic by creating two watermarks with the same level/round but different hashes.

## Prerequisites

- Docker installed on your system
- Go testing environment

## Running the Test

### 1. Start a local DynamoDB instance

First, start a local DynamoDB instance using Docker:

```sh
docker run -p 8000:8000 amazon/dynamodb-local
```

This will start a local DynamoDB service that listens on port 8000.

### 2. Run the test

With the local DynamoDB instance running, you can execute the test:

```sh
cd integration_test/dynamodb_concurrency_test
go test -v .
```

## What This Test Validates

This test verifies that Signatory's watermark mechanism correctly prevents double signing by:

1. Creating two watermarks with the same level and round but different hashes
2. Verifying that the validation logic rejects the second watermark (preventing double signing)
3. Confirming that watermarks with higher levels or rounds are correctly accepted

The test ensures that the bug fix in the watermark validation logic is working correctly. Without this fix, Signatory could potentially allow double signing of operations at the same level/round, which would lead to slashing penalties on the Tezos network.

## Implementation Details

The test doesn't require a real DynamoDB instance or actual AWS credentials, as it only tests the validation logic within the watermark feature. The test specifically targets the `Validate` method in the `Watermark` struct that was fixed to prevent double signing.

If you want to test the actual AWS DynamoDB integration with concurrent Signatory instances, you would need a more complex test setup with multiple Signatory processes connecting to the local DynamoDB. 