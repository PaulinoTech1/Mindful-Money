# Neon Backup Restore Procedure

## Overview

Neon provides point-in-time recovery (PITR) and branching. This document
covers how to restore the Mindful Money database from a Neon backup.

**Critical privacy note:** Neon stores ciphertext only. A database restore
does not expose plaintext. However, the restore process involves database
credentials and should be done carefully.

## Prerequisites

- Access to the Neon console (console.neon.tech)
- The production database connection string (unpooled, for verification)
- `psql` or equivalent Postgres client

## Procedure: Branch restore (recommended)

Neon branches are copy-on-write clones. They are instant and don't affect
production.

### Step 1: Create a branch from a point in time

1. Go to console.neon.tech → your project → Branches
2. Click "New Branch"
3. Select "Restore from a point in time"
4. Choose the timestamp to restore from
5. Name the branch (e.g., `restore-2026-10-12`)
6. Click Create

The branch is ready in seconds. It contains the database as it was at the
selected timestamp.

### Step 2: Get the branch connection string

1. In the branch view, go to Connection Details
2. Copy the **unpooled** connection string
3. Format for psql: `postgresql://user:pass@host/db?sslmode=require`

### Step 3: Verify ciphertext integrity

Connect to the branch and verify the data is intact:

```bash
# Connect to the restore branch
psql "postgresql://user:pass@branch-host/db?sslmode=require"

-- Check table counts
SELECT 'records' as tbl, COUNT(*) FROM records
UNION ALL
SELECT 'vault_identity', COUNT(*) FROM vault_identity
UNION ALL
SELECT 'audit_events', COUNT(*) FROM audit_events;

-- Verify ciphertext format (should be hex, even length)
SELECT blind_index, LENGTH(sealed) as sealed_len
FROM records LIMIT 5;
-- sealed_len should be even numbers (hex encoding)
-- blind_index should be 64 chars (32 bytes hex)

-- Verify no plaintext leaked (spot check)
SELECT sealed FROM records LIMIT 1;
-- Should be hex ciphertext, NOT readable JSON
```

### Step 4: Verify client-side decryptability

**This is the critical privacy verification.** The ciphertext must be
decryptable ONLY with the user's passphrase (in the browser), not with
database access.

1. Note a `blind_index` from the branch
2. In the Mindful Money app (connected to PRODUCTION, not the branch),
   verify you can see and decrypt the corresponding record
3. The branch ciphertext should match production for that record
   (unless the branch is from an earlier point in time)

**You cannot verify decryption from psql.** Decryption requires the
user's passphrase-derived key, which never leaves the browser. If you
can read plaintext from the database directly, something is catastrophically
wrong.

### Step 5: Promote branch to production (if needed)

**WARNING:** This replaces production data. Only do this if production
is corrupted and the branch contains good data.

1. In Neon console, go to the branch
2. Click "Restore to production" or "Promote"
3. Confirm the destructive action
4. Update the `VAULT_DATABASE_URL` secret if the connection string changed
5. Redeploy Cloud Run to pick up the new connection (if changed)
6. Verify `/ready` returns 200
7. Verify `/api/version` matches the deployed commit

### Alternative: Point-in-time restore (destructive)

Neon also supports direct PITR on the production branch. This is
destructive (overwrites current data). Prefer the branch approach above
unless you are certain.

## What is NOT backed up

- **User passphrases:** Never stored, cannot be restored. Users must
  remember their passphrase or use their recovery key.
- **Recovery keys:** The 32-word mnemonic is never stored. If lost,
  and the passphrase is also lost, the data is unrecoverable.
- **Browser-local data:** Anything in localStorage or sessionStorage
  is not backed up.

## Recovery Time Objective (RTO)

- Branch creation: < 1 minute
- Verification: 5-10 minutes
- Promotion (if needed): < 5 minutes
- **Total:** ~15 minutes for a tested operator

## Recovery Point Objective (RPO)

Neon PITR granularity is typically seconds to minutes, depending on
the plan. Check your Neon plan for the exact PITR window.

## Testing

This procedure has not been exercised against production data as of
2026-10-12. To test:

1. Create a Neon branch from production
2. Insert synthetic test records into the branch (not production)
3. Verify the ciphertext format
4. Delete the branch

Do NOT test restore procedures against production data without
a maintenance window and user notification.

## Residual risks

- **Neon operator access:** Neon (the company) has infrastructure-level
  access to the ciphertext. They cannot decrypt it (no keys), but they
  could delete it or deny access.
- **Backup retention:** If the PITR window expires, old data is unrecoverable.
  Verify your Neon's plan's retention period.
- **No client-side backup:** If Neon loses the data AND the user has no
  local backup (via the app's export feature), the data is gone.
  Users should periodically export encrypted backups via the app.
