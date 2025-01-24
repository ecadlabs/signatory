---
id: aws_dynamodb
title: AWS Watermark Backend
---

# AWS DynamoDB Watermark Backend Configuration

Signatory supports using AWS DynamoDB for watermark tracking. This allows for reliable and scalable management of watermarks in distributed environments.

## AWS DynamoDB Watermark Backend

Below is the minimum configuration required:

```yaml
watermark:
  driver: aws
  config:
    access_key_id: <aws_access_key_id>
    secret_access_key: <aws_secret_access_key>
    region: <aws_region>
```
When the backend is initialized, it will create a table named `watermark` if it doesn't exist.

### Configuration Parameters

| Name              | Type   | Required | Description                                                         |
|-------------------|--------|:--------:|---------------------------------------------------------------------|
| access_key_id     | string | OPTIONAL | IAM user detail for accessing DynamoDB                              |
| secret_access_key | string | OPTIONAL | IAM user detail for accessing DynamoDB                              |
| region            | string | ✅       | AWS region where the DynamoDB table is located                      |
| table             | string | OPTIONAL | Name of the DynamoDB table to use for watermark tracking (default: `watermark`) |

### Environment Variables Support

The `access_key_id`, `secret_access_key`, and `region` fields can also be set using the following environment variables:

- `AWS_ACCESS_KEY_ID`
- `AWS_SECRET_ACCESS_KEY`
- `AWS_REGION`

The `table` parameter defaults to `watermark` but can be overridden in the configuration file.