# Bootstrap Token Process

## Purpose

The `VAULT_BOOTSTRAP_TOKEN` protects first-passkey enrollment on new deployments.
Without it, anyone who reaches the vault URL before the owner could enroll the
first passkey and claim the vault.

## Lifecycle

### 1. Generate

From Cloud Shell or any terminal:

```bash
openssl rand -hex 32
```

This produces a 64-character hex string. Store it in your password manager.
Do not commit it to git. Do not paste it in chat.

### 2. Set

**Recommended: Secret Manager**

```bash
# Create the secret (one-time)
echo -n "YOUR_TOKEN_HERE" | gcloud secrets create mindful-money-bootstrap-token \
  --data-file=- \
  --project=project-c89a7f58-b865-4112-bf8

# Grant the Cloud Run service account access
gcloud secrets add-iam-policy-binding mindful-money-bootstrap-token \
  --member="serviceAccount:31393284277-compute@developer.gserviceaccount.com" \
  --role="roles/secretmanager.secretAccessor" \
  --project=project-c89a7f58-b865-4112-bf8

# Mount it on the Cloud Run service
gcloud run services update mindful-money \
  --region=us-central1 \
  --project=project-c89a7f58-b865-4112-bf8 \
  --set-secrets="VAULT_BOOTSTRAP_TOKEN=mindful-money-bootstrap-token:latest"
```

Note: the app currently reads `VAULT_BOOTSTRAP_TOKEN` from env vars. If using
Secret Manager, the secret is exposed as an env var by Cloud Run automatically.

**Alternative: plain env var** (simpler, less secure)

```bash
gcloud run services update mindful-money \
  --region=us-central1 \
  --project=project-c89a7f58-b865-4112-bf8 \
  --update-env-vars="VAULT_BOOTSTRAP_TOKEN=YOUR_TOKEN_HERE"
```

Use `--update-env-vars` (not `--set-env-vars`). The `--set-` variant replaces
ALL env vars, wiping any not listed. The `--update-` variant only changes the
ones you specify. See "Vercel vs Cloud Run" lesson in RUNBOOK.md.

### 3. Deploy safely

The CI workflow uses `--update-env-vars`, which preserves manually-set variables
like `VAULT_BOOTSTRAP_TOKEN` across deployments. If it used `--set-env-vars`,
every deploy would wipe the token.

Verify after deploy:

```bash
gcloud run services describe mindful-money \
  --region=us-central1 \
  --project=project-c89a7f58-b865-4112-bf8 \
  --format="value(spec.template.spec.containers[0].env)"
```

### 4. Bootstrap

1. Visit the vault URL
2. Click "Create passkey"
3. When prompted, paste the bootstrap token
4. Complete the WebAuthn ceremony

The server verifies the token with constant-time comparison before allowing
enrollment. In production (`VAULT_ENV=production`), bootstrap is refused
entirely (HTTP 503) if no token is configured. This is fail-closed.

### 5. Remove after use

Once the first passkey is enrolled, bootstrap is blocked (HTTP 403) regardless
of the token. The token is no longer needed. Remove it:

```bash
gcloud run services update mindful-money \
  --region=us-central1 \
  --project=project-c89a7f58-b865-4112-bf8 \
  --remove-env-vars="VAULT_BOOTSTRAP_TOKEN"
```

Or if using Secret Manager, remove the secret mount:

```bash
gcloud run services update mindful-money \
  --region=us-central1 \
  --project=project-c89a7f58-b865-4112-bf8 \
  --remove-secrets="VAULT_BOOTSTRAP_TOKEN"
```

Leaving it set is not a vulnerability (bootstrap 403s after enrollment), but
removing it reduces the secret's exposure window.

## Failure modes

| Situation | Behavior |
|---|---|
| Production, no token configured | HTTP 503 "Bootstrap not configured" |
| Token configured, wrong token provided | HTTP 403 "Invalid bootstrap token", event logged |
| Token configured, correct token, passkeys exist | HTTP 403 "already enrolled" |
| Development, no token configured | Bootstrap allowed (dev convenience) |

## Rotation

If the token is compromised before bootstrap completes:

```bash
NEW_TOKEN=$(openssl rand -hex 32)
gcloud run services update mindful-money \
  --region=us-central1 \
  --project=project-c89a7f58-b865-4112-bf8 \
  --update-env-vars="VAULT_BOOTSTRAP_TOKEN=$NEW_TOKEN"
```

No restart needed; Cloud Run picks up the new revision automatically.
