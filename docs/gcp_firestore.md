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
    project: my-gcp-project
    database: my-gcp-database
    application_credentials: /path/to/service-credentials-file.json
    # Optional: override default collection name
    collection: my_custom_watermark_collection
```

### Configuration Parameters

| Name                        | Type   | Required | Description                                                         |
|-----------------------------|--------|:--------:|---------------------------------------------------------------------|
| project                     | string | ✅ | GCP project ID where Firestore is located                           |
| database                    | string | ✅ | Firestore database name                                             |
| application_credentials     | string | OPTIONAL | Path to GCP service account credentials JSON file                   |
| application_credentials_data| string | OPTIONAL | GCP service account credentials JSON data (inline)                  |
| collection                  | string | OPTIONAL | Name of the Firestore collection (default: `watermark`)             |

### Environment Variables Support

The GCP credentials can also be provided through standard GCP environment variables:

- `GOOGLE_APPLICATION_CREDENTIALS` - Path to service account key file
- `GOOGLE_CLOUD_PROJECT` - GCP project ID

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

## Operational Notes

- The Firestore backend uses transactions to ensure atomic read-write operations
- Each watermark check involves a transaction that reads the current watermark and conditionally updates it
- The backend supports both the default Firestore database and named databases
- Collection creation is automatic - Firestore creates collections when the first document is added
- If no database is specified, the default Firestore database is used

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

**"Project field is required" error**:
- Ensure the `project` field is set in your configuration
- Verify the project ID is correct and accessible with your credentials 
