---
id: aws_dynamodb
title: AWS DynamoDB Watermark Backend
---

# AWS DynamoDB Watermark Backend

## Overview

The AWS DynamoDB watermark backend provides a distributed, highly available solution for tracking watermarks in Signatory. This backend is ideal for environments where multiple Signatory instances need to coordinate to prevent double-signing operations.

As explained in the [Watermarks](./watermarks.md) documentation, watermarks are essential for preventing double signing of operations at the same block level or round.

## When to Choose DynamoDB

DynamoDB is the recommended watermark backend when:

- **Running multiple Signatory instances** - Using a shared watermark store ensures that all instances are synchronized
- **Deploying in AWS** - Native integration with AWS services provides better reliability
- **High availability is critical** - DynamoDB offers strong consistency for watermark operations
- **Scalability is required** - DynamoDB can handle high throughput with minimal configuration

## Configuration

Below is the minimum configuration required:

```yaml
watermark:
  driver: aws
  config:
    region: us-east-1
    # Optional: override default table name
    table: my_custom_watermark_table
```

### Configuration Parameters

| Name              | Type   | Required | Description                                                         |
|-------------------|--------|:--------:|---------------------------------------------------------------------|
| access_key_id     | string | OPTIONAL | IAM user credential for accessing DynamoDB                          |
| secret_access_key | string | OPTIONAL | IAM user credential for accessing DynamoDB                          |
| region            | string | ✅       | AWS region where the DynamoDB table is located                      |
| table             | string | OPTIONAL | Name of the DynamoDB table (default: `watermark`)                   |

### Environment Variables Support

The AWS credentials and region can also be provided through standard AWS environment variables:

- `AWS_ACCESS_KEY_ID`
- `AWS_SECRET_ACCESS_KEY`
- `AWS_REGION`

This is the recommended approach for production deployments.

## Table Design

When Signatory initializes the AWS backend, it automatically creates the DynamoDB table if it doesn't already exist. The table is created with:

- Partition key: `idx` (combination of chain ID and public key hash)
- Sort key: `request` (type of request: block, endorsement, etc.)
- Provisioned capacity: 5 read and 5 write capacity units

When Signatory starts up, it will log one of these messages to confirm which table is being used:
- `DynamoDB watermark backend created table 'table_name'` - when creating a new table
- `DynamoDB watermark backend using existing table 'table_name'` - when using an existing table

This allows operators to verify that Signatory is using the expected DynamoDB table.

### Data Structure

Each watermark record contains:
- The chain ID and public key hash (combined as the partition key)
- The request type
- The block level
- The round number
- The operation digest

This structure ensures that:
1. Lookups are efficient (by using the composite key)
2. Each key's watermarks are separated by operation type
3. Different chains maintain separate watermarks

## Verifying and Managing the DynamoDB Table

You can use the AWS CLI to verify and manage your watermark table. Here are some useful commands:

### List Tables

To verify that the watermark table has been created:

```bash
aws dynamodb list-tables --region us-east-1
```

Example output:
```json
{
    "TableNames": [
        "watermark"
    ]
}
```

### Inspect Watermark Records

To view the watermark records stored in the table:

```bash
aws dynamodb scan --table-name watermark --region us-east-1
```

Example output:
```json
{
    "Items": [
        {
            "idx": {
                "S": "NetXdQprcVkpaWU/tz1aKTCPZHZRzNBrucPp8WTiAMzaYh84NZkC"
            },
            "request": {
                "S": "block"
            },
            "lvl": {
                "N": "2495866"
            },
            "round": {
                "N": "0"
            },
            "digest": {
                "S": "vh2g3Wz8zrL8J7qXEFykT7BbzCwW6LsyWvxvfssnhAVzw1uXfCJf"
            }
        }
    ],
    "Count": 1,
    "ScannedCount": 1
}
```

For a specific key, you can use a query:

```bash
aws dynamodb query --table-name watermark \
  --key-condition-expression "idx = :idx" \
  --expression-attribute-values '{":idx":{"S":"NetXdQprcVkpaWU/tz1aKTCPZHZRzNBrucPp8WTiAMzaYh84NZkC"}}' \
  --region us-east-1
```

### Reset Watermarks

If you need to reset your watermarks (use with caution!), you can delete the table:

```bash
aws dynamodb delete-table --table-name watermark --region us-east-1
```

Signatory will automatically recreate the table on the next startup.

## Operational Notes

- The DynamoDB backend uses a conditional write operation that succeeds only if the new watermark has a higher level or equal level with higher round
- No explicit reads are performed, making the operation more efficient
- Table creation happens at startup and waits for the table to be active before proceeding

## Troubleshooting

If you encounter issues with the DynamoDB watermark backend:

1. Verify AWS credentials are correctly configured
2. Check that the IAM policy allows the necessary DynamoDB actions:
   - `dynamodb:CreateTable`
   - `dynamodb:DescribeTable`
   - `dynamodb:PutItem`
3. For watermark validation failures, enable debug logs:
   ```bash
   signatory serve --log debug -c /path/to/config.yaml
   ```