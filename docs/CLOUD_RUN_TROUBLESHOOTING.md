# Cloud Run Deployment Troubleshooting

Issues encountered deploying Mindful Money to Google Cloud Run (2026-10-11).

## Secret Manager API not enabled

**Symptom:**
```
ERROR: (gcloud.secrets.create) Secret Manager API has not been used in project
[...] before or it is disabled.
```

**Fix:**
```bash
gcloud services enable secretmanager.googleapis.com
```
Wait 2-3 minutes for propagation before retrying.

## Cloud Build API not enabled

**Symptom:**
```
ERROR: (gcloud.run.deploy) INVALID_ARGUMENT: Invalid build request.
could not resolve source: ... does not have storage.objects.get access ...
```

**Fix:**
```bash
gcloud services enable cloudbuild.googleapis.com
```
If still failing after propagation, grant the Compute service account
explicit Storage Object Viewer:
```bash
gcloud projects add-iam-policy-binding PROJECT_ID \
  --member="serviceAccount:PROJECT_NUMBER-compute@developer.gserviceaccount.com" \
  --role="roles/storage.objectViewer"
```

## Service account key creation blocked

**Symptom:** GCP Console shows "Service account key creation is disabled"
with `iam.disableServiceAccountKeyCreation` organization policy.

**Cause:** Google Advanced Protection mode enforces this policy.

**Workaround:** Do not use JSON keys. Options:
1. Run `gcloud` commands directly from Cloud Shell (already authenticated)
2. Use Workload Identity Federation for CI/CD (no long-lived secrets)

## Build log not found

**Symptom:**
```
(gcloud.builds.log) NOT_FOUND: Requested entity was not found.
```

**Cause:** Build ID from a previous (cleaned up) attempt, or the build
failed before logging started.

**Fix:** Rerun the deploy and use the fresh build ID from the output URL.

## VAULT_RP_ID / VAULT_ORIGIN placeholder

The initial deploy uses `placeholder` values because the Cloud Run URL
is not known until after first deploy. After getting the URL:

```bash
gcloud run deploy mindful-money \
  --region us-central1 \
  --update-env-vars "VAULT_RP_ID=actual-host.run.app,VAULT_ORIGIN=https://actual-host.run.app"
```

WebAuthn will not work until these match the real URL.

## Private service access

Deploy without `--allow-unauthenticated`, then grant invoker access:

```bash
gcloud run services add-iam-policy-binding mindful-money \
  --region us-central1 \
  --member="user:YOUR_EMAIL@gmail.com" \
  --role="roles/run.invoker"
```

## Docker build succeeds but deploy fails

**Symptom:** `gcloud builds describe` shows the `gcr.io/cloud-builders/docker`
step as SUCCESS, but overall build status is FAILURE with empty logs.

**Cause:** The failure is in the push to Artifact Registry or the Cloud Run
deployment phase, not the Docker build itself. The Dockerfile is fine.

**Diagnosis:**
```bash
# Get the latest build ID
BUILD_ID=$(gcloud builds list --region us-central1 --limit 1 --format="value(id)")

# Check step statuses
gcloud builds describe $BUILD_ID --region us-central1 --format="json(steps[].name, steps[].status)"

# Check if the service was created despite the failure
gcloud run services list --region us-central1
```

**Common causes:**
- Artifact Registry API not enabled: `gcloud services enable artifactregistry.googleapis.com`
- Insufficient permissions for the Cloud Build service account to push images
- The `--source .` upload succeeded but the image push failed silently
