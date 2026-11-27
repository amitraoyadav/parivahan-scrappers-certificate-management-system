# Parivahan Scrappers — Certificate Management System

Independent vehicle scrapping certificate issuance, cryptographic registry, official A4 PDF generation, and public QR verification platform built for standalone Vercel hosting and a fresh Google Cloud Firestore database.

## Core Capabilities

- **Two-Tier Access Control**:
  - **Certificate Maker (`user-pscrappers`)**: Creates new certificates and views only the latest five active certificates. Blocked server-side (`403`) from the full registry, analytics, audit logs, backups, and settings.
  - **Main Core Admin**: Separate unlock password granting access to the complete searchable certificate registry, dashboard statistics, protected edits/cancellations/restorations/deletions, audit logs, encrypted-checksum backups, and settings.
- **Official A4 Certificate PDF & QR Verification**: Generates single-page A4 portrait PDFs matching the master Parivahan Scrappers certificate layout with per-certificate SHA-256 canonical hashes, unique QR verification URLs, and privacy-masked public verification (`/verify`).
- **Fresh Independent Firestore Architecture**: Authoritative server-side Firestore REST persistence with strict default-deny client `firestore.rules` (`allow read, write: if false;`), permanent reservation of issued certificate and scrapping registration numbers, and zero historical records.

## Local Development & Verification

```bash
npm install
npm run dev
```

Verification commands:

```bash
npm run build
npx tsc --noEmit
npm run test:security
npm run scan:predeploy
npm run test:firestore
```

## Production Deployment

See [`DEPLOYMENT_GUIDE.md`](./DEPLOYMENT_GUIDE.md) for the complete Firebase Spark setup, GitHub push workflow, and private Vercel environment variable configuration (`ADMIN_USERNAME=user-pscrappers`, `ADMIN_PASSWORD`, `MAIN_ADMIN_PASSWORD`, `ADMIN_PROTECTED_PASSWORD`, `ADMIN_DELETE_PASSWORD`, `ADMIN_SESSION_SECRET`, `FIREBASE_PROJECT_ID`, `FIREBASE_DATABASE_ID`, `FIREBASE_CLIENT_EMAIL`, `FIREBASE_PRIVATE_KEY`, `CRON_SECRET`, `PUBLIC_APP_URL`).
