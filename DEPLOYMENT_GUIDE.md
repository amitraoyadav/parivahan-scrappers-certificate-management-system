# Parivahan Scrappers — Independent Production Deployment Guide

This application has **zero runtime dependency on Google AI Studio** and **zero historical certificate data**. It is structured for independent GitHub source control, Vercel hosting (static frontend + stateless Node.js APIs), and your own fresh Google Cloud Firestore database on the **Firebase Spark (Free) plan**.

---

## 1. Create a Fresh Firebase / Google Cloud Firestore Database (Spark Free Plan Compatible)

1. Open the [Firebase Console](https://console.firebase.google.com/) and create a **brand-new Firebase project** (for example, `crm-certificates` — do not connect to your old certificate project).
2. Enable **Cloud Firestore** in **Production Mode** using the **`(default)`** database ID.
   - *Spark (Free) Plan note:* Keeping the database ID as `(default)` and hosting API routes on Vercel avoids requiring the paid Blaze plan.
3. Publish the included zero-trust `firestore.rules` file (`allow read, write: if false;` on all client paths — all authorized access runs exclusively through your server-side Vercel API).
4. In **Google Cloud Console -> IAM & Admin -> Service Accounts** (for your new project):
   - Create a dedicated service account (e.g. `parivahan-vercel-api`).
   - Grant it only the **Cloud Datastore User** (`roles/datastore.user`) role.
   - Generate a JSON key and extract `client_email` and `private_key` (never commit the JSON key file to GitHub).

Required collections (created automatically as fresh empty collections on first write):
- `certificates`
- `reserved_certificate_numbers`
- `reserved_scrapping_numbers`
- `settings`
- `admins`
- `audit_logs`
- `idempotency_keys`
- `database_backups` (lightweight metadata snapshots)
- `database_backup_chunks` (gzip-compressed backup chunks kept safely below Firestore's 1 MiB document limit)
- `system_errors`
- `drive_sync_logs`

---

## 2. Verify Read-Only Firestore Connection Before Deploying (Zero Writes)

Before deploying to Vercel, you can test your Service Account credentials against your new Firestore database without creating or modifying any records:

```bash
FIREBASE_PROJECT_ID="crm-certificates" \
FIREBASE_DATABASE_ID="(default)" \
FIREBASE_CLIENT_EMAIL="your-service-account@crm-certificates.iam.gserviceaccount.com" \
FIREBASE_PRIVATE_KEY="-----BEGIN ...-----" \
npm run test:firestore
```

This strictly read-only check verifies OAuth2 JWT token exchange, IAM `roles/datastore.user` read access, and confirms all collections start at `0` documents.

---

## 3. Push to a New GitHub Repository

Create a **new** repository (for example, `parivahan-certificate-fresh`) without overwriting your existing repository:

```bash
npm run scan:predeploy
npm run lint
npm run build
npm run test:security

git init
git add .
git commit -m "Initial fresh Parivahan Scrappers certificate management system"
git branch -M main
git remote add origin https://github.com/<your-username>/parivahan-certificate-fresh.git
git push -u origin main
```

---

## 4. Configure Vercel Production Environment Variables

Create a **new Vercel project** connected to `parivahan-certificate-fresh`, then add the following environment variables in **Vercel -> Project Settings -> Environment Variables** (Production & Preview):

| Variable | Description |
| --- | --- |
| `FIREBASE_PROJECT_ID` | Your new Firebase / Google Cloud project ID (e.g. `crm-certificates`) |
| `FIREBASE_DATABASE_ID` | `(default)` (required on Firebase Spark Free plan) |
| `FIREBASE_CLIENT_EMAIL` | Service account email (`...@crm-certificates.iam.gserviceaccount.com`) |
| `FIREBASE_PRIVATE_KEY` | Service account PEM private key (keep `\n` newlines intact) |
| `ADMIN_USERNAME` | Certificate Maker login username (set to `user-pscrappers`) |
| `ADMIN_PASSWORD` | Private Maker password (plain or salted `scrypt$...` hash via `npm run hash:password`) |
| `MAIN_ADMIN_PASSWORD` | Separate Main Core Admin unlock password (plain or salted `scrypt$...` hash) |
| `ADMIN_PROTECTED_PASSWORD` | Separate password for protected edits, cancellations, and restores (or `scrypt$...` hash) |
| `ADMIN_DELETE_PASSWORD` | Separate password for protected soft/permanent deletion (or `scrypt$...` hash) |
| `ADMIN_SESSION_SECRET` | High-entropy random 64-char hex string (`openssl rand -hex 32`) |
| `CRON_SECRET` | Random secret authorizing Vercel daily backup cron (`/api/cron/backup`) |
| `PUBLIC_APP_URL` | Your new production URL (e.g. `https://parivahan-fresh.vercel.app`) |
| `GOOGLE_DRIVE_FOLDER_ID` | *(Optional)* Dedicated new Google Drive folder ID for background PDF/JSON archival |
| `GOOGLE_DRIVE_CLIENT_EMAIL` | *(Optional)* Service account email with access to the new Drive folder |
| `GOOGLE_DRIVE_PRIVATE_KEY` | *(Optional)* Service account private key for Drive sync |

> **Security Tip**: Run `npm run hash:password` locally to pre-hash `ADMIN_PASSWORD`, `MAIN_ADMIN_PASSWORD`, `ADMIN_PROTECTED_PASSWORD`, and `ADMIN_DELETE_PASSWORD` with salted `scrypt` before pasting them into Vercel. The server automatically recognizes `scrypt$...` hashes. Rotating any password environment variable or `ADMIN_SESSION_SECRET` in Vercel and redeploying immediately invalidates all previously issued Maker and Main Core Admin sessions.

---

## 5. Spark Free Plan Quota Notes & Production Safety Guard

The backend uses indexed `:runQuery` requests for Maker recent certificates and logs, `:runAggregationQuery` (`COUNT`) for reserved-number counts, and metadata-only `database_backups` with gzip-compressed chunks in `database_backup_chunks` so daily usage stays well within Firebase Spark's free tier (50,000 reads/day, 20,000 writes/day, 1 GiB storage, 10 GiB/month egress).

When deployed on Vercel (`VERCEL=1`), the backend **strictly refuses to fall back to ephemeral in-memory storage** if `FIREBASE_PROJECT_ID`, `FIREBASE_CLIENT_EMAIL`, or `FIREBASE_PRIVATE_KEY` are missing. Configure those variables first, then redeploy and verify:
- `GET /api/health` returns `"storageMode": "firestore"` and `"firestoreConnected": true`
- Total certificates starts at `0`
- Maker login opens the Make Certificate form with latest-5 visibility only
- Main Core Admin unlock opens the full registry
- Public `/verify?certificateNumber=...` works without login
