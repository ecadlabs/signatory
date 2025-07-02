---
id: gcp_firestore
title: GCP Firestore Watermark Backend
---

# GCP Firestore Watermark Backend

## Overview

The GCP Firestore watermark backend provides a distributed, highly available solution for tracking watermarks in Signatory. This backend is ideal for environments where multiple Signatory instances need to coordinate to prevent double-signing operations.

As explained in the [Watermarks](./watermarks.md) documentation, watermarks are essential for preventing double signing of operations at the same block level or round.

## When to Choose Firestore

Firestore is the recommended watermark backend when:

- **Running multiple Signatory instances** - Using a shared watermark store ensures that all instances are synchronized
- **Deploying in Google Cloud Platform** - Native integration with GCP services provides better reliability
- **High availability is critical** - Firestore offers strong consistency for watermark operations
- **Scalability is required** - Firestore can handle high throughput with automatic scaling
- **Real-time synchronization is needed** - Firestore provides real-time updates across multiple instances

## Configuration

Below is the minimum configuration required:

```yaml
watermark:
  driver: gcp
  config:
    database: my-gcp-database
    file: /path/to/service-credentials-file.json
    # Optional: in case no project id in credential file
    project_id: my-gcp-project
    # Optional: override default collection name
    collection: my_custom_watermark_collection
```

### Configuration Parameters

| Name            | Type   | Required | Description                                                         |
|-----------------|--------|:--------:|---------------------------------------------------------------------|
| file            | string | ✅ | Path to GCP service account credentials JSON file                   |
| database        | string | ✅ | Firestore database name            |
| project_id      | string | OPTIONAL       | GCP project ID where Firestore is located (default: uses project id in credentials file)  |
| collection      | string | OPTIONAL | Name of the Firestore collection (default: `watermark`)             |
<!-- 
### Environment Variables Support

The GCP credentials can also be provided through standard GCP environment variables:

- `GOOGLE_APPLICATION_CREDENTIALS` - Path to service account key file
- `GOOGLE_CLOUD_PROJECT` - GCP project ID

This is the recommended approach for production deployments. -->

## Collection Design

When Signatory initializes the GCP backend, it automatically uses the specified Firestore collection. The collection structure is organized as:

- **Document ID**: Chain ID (e.g., `NetXdQprcVkpaWU`)
- **Subcollection**: Request type
- **Document ID**: Public key hash

This hierarchical structure ensures that:
1. Each chain maintains separate watermarks
2. Each operation type is isolated
3. Each public key has its own watermark document

### Data Structure

Each watermark document contains:
- `request`: The type of request (block, endorsement, etc.)
- `lvl`: The block level
- `round`: The round number
- `digest`: The operation digest hash

This structure ensures that:
1. Lookups are efficient (using the hierarchical document structure)
2. Each key's watermarks are separated by operation type
3. Different chains maintain separate watermarks

## Verifying and Managing the Firestore Collection

You can use the Google Cloud Console or gcloud CLI to verify and manage your watermark collection. Here are some useful commands:

### List Collections

To verify that the watermark collection exists:

```bash
gcloud firestore collections list --project=my-gcp-project
```

### Inspect Watermark Documents

To view the watermark documents stored in the collection:

```bash
gcloud firestore documents list watermark --project=my-gcp-project
```

For a specific chain and operation type:

```bash
gcloud firestore documents list watermark/NetXdQprcVkpaWU/block --project=my-gcp-project
```

### View Specific Watermark Document

To view a specific watermark document:

```bash
gcloud firestore documents describe watermark/NetXdQprcVkpaWU/block/tz1aKTCPZHZRzNBrucPp8WTiAMzaYh84NZkC --project=my-gcp-project
```

Example output:
```json
{
  "name": "projects/my-gcp-project/databases/(default)/documents/watermark/NetXdQprcVkpaWU/block/tz1aKTCPZHZRzNBrucPp8WTiAMzaYh84NZkC",
  "fields": {
    "request": {
      "stringValue": "block"
    },
    "lvl": {
      "integerValue": "2495866"
    },
    "round": {
      "integerValue": "0"
    },
    "digest": {
      "stringValue": "vh2g3Wz8zrL8J7qXEFykT7BbzCwW6LsyWvxvfssnhAVzw1uXfCJf"
    }
  },
  "createTime": "2024-01-15T10:30:00.000000Z",
  "updateTime": "2024-01-15T10:30:00.000000Z"
}
```

### Reset Watermarks

If you need to reset your watermarks (use with caution!), you can delete the collection:

```bash
gcloud firestore collections delete watermark --project=my-gcp-project
```

Signatory will automatically use the collection on the next startup.

## Service Account Setup

To use the GCP Firestore watermark backend, you need to set up a service account with appropriate permissions:

### 1. Create a Service Account

```bash
gcloud iam service-accounts create signatory-watermark \
  --display-name="Signatory Watermark Service Account" \
  --project=my-gcp-project
```

### 2. Grant Firestore Permissions

```bash
gcloud projects add-iam-policy-binding my-gcp-project \
  --member="serviceAccount:signatory-watermark@my-gcp-project.iam.gserviceaccount.com" \
  --role="roles/datastore.user"
```

### 3. Create and Download Key

```bash
gcloud iam service-accounts keys create signatory-key.json \
  --iam-account=signatory-watermark@my-gcp-project.iam.gserviceaccount.com \
  --project=my-gcp-project
```

### 4. Configure Signatory

```yaml
watermark:
  driver: gcp
  config:
    project_id: my-gcp-project
    file: /path/to/signatory-key.json
```

## Operational Notes

- The Firestore backend uses transactions to ensure atomic read-write operations
- Each watermark check involves a transaction that reads the current watermark and conditionally updates it
- The backend supports both the default Firestore database and named databases
- Collection creation is automatic - Firestore creates collections when the first document is added

## Troubleshooting

If you encounter issues with the Firestore watermark backend:

1. Verify GCP credentials are correctly configured
2. Check that the service account has the necessary Firestore permissions:
   - `datastore.documents.get`
   - `datastore.documents.create`
   - `datastore.documents.update`
3. Ensure the project ID is correct and the project has Firestore enabled
4. For watermark validation failures, enable debug logs:
   ```bash
   signatory serve --log debug -c /path/to/config.yaml
   ```

### Common Issues

**"Failed to create Firestore client" error**:
- Check that the service account key file path is correct
- Verify the project ID is valid
- Ensure the service account has the necessary permissions

**"Permission denied" errors**:
- Verify the service account has `datastore.user` role
- Check that Firestore is enabled in the project
- Ensure the collection path is accessible

**Transaction failures**:
- These may indicate concurrent access issues
- Check if multiple Signatory instances are properly configured
- Verify network connectivity to Firestore 