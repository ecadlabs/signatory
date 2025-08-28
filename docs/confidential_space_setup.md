---
id: confidential_space_setup
title: Setup
sidebar_label: Setup
---

# Google Cloud Platform Setup for Confidential Space

This guide provides step-by-step instructions for setting up Google Cloud Platform (GCP) resources required to use the Confidential Space backend with Signatory.

## Overview

Confidential Space is Google Cloud's confidential computing solution that provides hardware-based memory encryption and integrity verification. To use it with Signatory, you need to set up several GCP resources:

1. **Workload Identity Pool and Provider** - For secure authentication
2. **Cloud KMS Key** - For encrypting/decrypting private keys
3. **Confidential Space Environment** - Where the enclave-signer runs
4. **Network Configuration** - For communication between Signatory and the enclave

## Prerequisites

- Google Cloud SDK (`gcloud`) installed and configured
- Appropriate permissions to create and manage GCP resources
- A GCP project with billing enabled

## Step 1: Enable Required APIs

First, enable the necessary Google Cloud APIs:

```bash
# Enable required APIs
gcloud services enable \
  iamcredentials.googleapis.com \
  cloudkms.googleapis.com \
  compute.googleapis.com \
  artifactregistry.googleapis.com
```

## Step 2: Create Workload Identity Pool

Workload Identity allows workloads running outside of Google Cloud to access Google Cloud resources using short-lived credentials.

```bash
# Set up variables (replace with your actual values)
WIP_NAME=signatory-pool
WIP_PROVIDER_NAME=signatory-provider
ARTIFACT_REGISTRY_REPO_NAME=<from Artifact Registry>
ARTIFACT_REGISTRY_IMAGE=<from Artifact Registry>
ARTIFACT_REGISTRY_IMAGE_DIGEST=<from Artifact Registry>
SERVICE_ACCOUNT=<WORKLOAD_SERVICE_ACCOUNT_NAME>@<PROJECT_ID>.iam.gserviceaccount.com
```

```bash
# Create a Workload Identity Pool
gcloud iam workload-identity-pools create $WIP_NAME \
  --location="global"

# Create a Workload Identity Provider within the pool
gcloud iam workload-identity-pools providers create-oidc $WIP_PROVIDER_NAME \
    --location=global \
    --workload-identity-pool=$WIP_NAME \
    --issuer-uri="https://confidentialcomputing.googleapis.com/" \
    --allowed-audiences="https://sts.googleapis.com" \
    --attribute-mapping="google.subject=\"gcpcs::\"+assertion.submods.container.image_digest+\"::\"+assertion.submods.gce.project_number+\"::\"+assertion.submods.gce.instance_id,attribute.image_digest=assertion.submods.container.image_digest" \
    --attribute-condition="assertion.swname == 'CONFIDENTIAL_SPACE' \
        && 'STABLE' in assertion.submods.confidential_space.support_attributes"

# Grant Artifact Registry permissions to the service account
gcloud artifacts repositories add-iam-policy-binding $ARTIFACT_REGISTRY_REPO_NAME \
    --location=us \
    --member=serviceAccount:$SERVICE_ACCOUNT \
    --role=roles/artifactregistry.reader
```

## Step 3: Create Cloud KMS Key

Create a symmetric encryption key for encrypting and decrypting private keys:

```bash
# Create a KeyRing (if it doesn't exist)
gcloud kms keyrings create "signatory-confidential-space" \
  --location="us-west1"

# Create a symmetric encryption key
gcloud kms keys create "confidential-space-encryption" \
  --keyring="signatory-confidential-space" \
  --location="us-west1" \
  --purpose="encryption" \
  --protection-level="software" \
  --default-algorithm="google-symmetric-encryption"
```

## Step 4: Configure Key Permissions

Grant the necessary permissions for the Confidential Space environment to use the KMS key:

```bash
# Get the Workload Identity Pool resource name
WIP_RESOURCE_NAME=$(gcloud iam workload-identity-pools describe $WIP_NAME \
  --location="global" \
  --format="value(name)")

# Grant KMS permissions to the Workload Identity Provider
gcloud kms keys add-iam-policy-binding \
    projects/signatory-testing/locations/us-west1/keyRings/signatory-confidential-space/cryptoKeys/confidential-space-encryption \
    --member="principalSet://iam.googleapis.com/${WIP_RESOURCE_NAME}/attribute.image_digest/${ARTIFACT_REGISTRY_IMAGE_DIGEST}" \
    --role=roles/cloudkms.cryptoKeyEncrypterDecrypter
```

## Step 5: Deploy Confidential Space Environment

Deploy the enclave-signer in a Confidential Space environment. 

### Release
```bash
# Create a Confidential Space VM instance
gcloud compute instances create confidential-signer-instance \
    --confidential-compute-type=SEV \
    --shielded-secure-boot \
    --scopes=cloud-platform \
    --zone=us-west1-b \
    --maintenance-policy=MIGRATE \
    --image-project=confidential-space-images \
    --image-family=confidential-space \
    --service-account=$SERVICE_ACCOUNT \
    --metadata="^~^tee-restart-policy=Always~tee-image-reference=${ARTIFACT_REGISTRY_IMAGE}"
```
### Debug
```bash
# Use debug mode to see detailed logs in Logs Explorer
gcloud compute instances create confidential-signer-instance \
    --confidential-compute-type=SEV \
    --shielded-secure-boot \
    --scopes=cloud-platform \
    --zone=us-west1-b \
    --maintenance-policy=MIGRATE \
    --image-project=confidential-space-images \
    --image-family=confidential-space-debug \
    --service-account=$SERVICE_ACCOUNT \
    --metadata="^~^tee-restart-policy=Always~tee-image-reference=${ARTIFACT_REGISTRY_IMAGE}~tee-container-log-redirect=true"
```

## Step 6: Get Configuration Values

Get the necessary configuration values for Signatory:

```bash
# Get the instance IP address
gcloud compute instances describe confidential-signer-instance \
    --zone=us-west1-b \
    --format="value(networkInterfaces[0].accessConfigs[0].natIP)"

# Get WIP provider path
gcloud iam workload-identity-pools providers describe $WIP_PROVIDER_NAME \
  --workload-identity-pool=$WIP_NAME \
  --location=global \
  --format="value(name)"

# Get KMS key path
gcloud kms keys describe confidential-space-encryption \
  --keyring=signatory-confidential-space \
  --location=us-west1 \
  --format="value(name)"
```

## Step 7: Configure Signatory

Update your Signatory configuration with the values from the previous step:

```yaml
vaults:
  confidentialspace:
    driver: confidentialspace
    config:
      host: "YOUR_ENCLAVE_IP_ADDRESS"  # Replace with the IP from the previous step
      port: "2000"
      wip_provider_path: "<WIP_PROVIDER_PATH_FROM_ABOVE_COMMAND>"           # Replace with the output from the gcloud command above
      encryption_key_path: "<KMS_KEY_PATH_FROM_ABOVE_COMMAND>"              # Replace with the output from the gcloud command above
```

## Troubleshooting

### Common Issues

1. **Permission Denied Errors**
   - Ensure the Workload Identity Provider has the correct IAM roles
   - Ensure you have granted the Confidential Space environment permission to access the KMS key by binding the correct image digest to the `cloudkms.cryptoKeyEncrypterDecrypter` role. This allows the enclave to use the KMS key for encryption and decryption operations.

2. **Network Connectivity Issues**
   - Check firewall rules allow traffic on port 2000
   - Verify the enclave IP address is correct
   - Ensure the Confidential Space environment is running

3. **Authentication Failures**
   - Verify the Workload Identity Provider path is correct
   - Check that the enclave-signer is properly configured with the WIP provider path
   - Ensure the image digest in the KMS policy binding matches the actual container image digest


