import fs from 'node:fs';
import path from 'node:path';
import dotenv from 'dotenv';
import { getStore } from '../src/server/store.js';
import { runReadOnlyIntegrityAudit } from '../src/server/integrity.js';

dotenv.config();

async function main(): Promise<void> {
  const requireFirestore = process.argv.includes('--require-firestore');
  const rootDir = process.cwd();

  // 1. Verify zero-trust firestore.rules lock
  const rulesPath = path.join(rootDir, 'firestore.rules');
  if (!fs.existsSync(rulesPath)) {
    console.error('[FAIL] firestore.rules file is missing.');
    process.exit(1);
  }
  const rulesText = fs.readFileSync(rulesPath, 'utf8');
  if (!/allow\s+read\s*,\s*write\s*:\s*if\s+false\s*;/.test(rulesText)) {
    console.error('[FAIL] firestore.rules does not enforce strict zero-trust `allow read, write: if false;`.');
    process.exit(1);
  }
  console.log('✓ firestore.rules zero-trust client lock verified (`allow read, write: if false;`).');

  // 2. Check Firestore environment configuration (without ever printing secret values)
  const hasProject = Boolean(process.env.FIREBASE_PROJECT_ID?.trim());
  const hasEmail = Boolean(process.env.FIREBASE_CLIENT_EMAIL?.trim());
  const hasKey = Boolean(process.env.FIREBASE_PRIVATE_KEY?.trim());

  if (!hasProject || !hasEmail || !hasKey) {
    console.log(
      'ℹ Firestore production credentials are not configured in this shell environment (FIREBASE_PROJECT_ID / FIREBASE_CLIENT_EMAIL / FIREBASE_PRIVATE_KEY).'
    );
    console.log(
      '  No database was modified. Run `npm run audit:db -- --require-firestore` with production env vars loaded to audit live Firestore counts and integrity.'
    );
    if (requireFirestore) {
      console.error('[FAIL] --require-firestore was specified, but Firestore credentials are missing.');
      process.exit(1);
    }
    return;
  }

  // 3. Strictly READ-ONLY connection & integrity audit
  const store = getStore();
  if (store.mode !== 'firestore') {
    console.error(`[FAIL] Expected store.mode="firestore", received "${store.mode}".`);
    process.exit(1);
  }

  const report = await runReadOnlyIntegrityAudit(store);

  console.log('\n=== READ-ONLY PRODUCTION FIRESTORE INTEGRITY AUDIT ===');
  console.log(`Audited At:                 ${report.auditedAt}`);
  console.log(`Firestore Project / DB:     ${report.firestoreProjectId} / ${report.firestoreDatabaseId}`);
  console.log(`Firestore Connected:        ${report.firestoreConnected}`);
  console.log(`Total Certificates:         ${report.counts.totalCertificates}`);
  console.log(`  - Parivahan Scrappers:    ${report.counts.parivahanCertificates}`);
  console.log(`  - Scrap Route:            ${report.counts.scrapRouteCertificates}`);
  console.log(`  - Active:                 ${report.counts.activeCertificates}`);
  console.log(`  - Archived (Soft-Del):    ${report.counts.archivedCertificates}`);
  console.log(`  - Cancelled:              ${report.counts.cancelledCertificates}`);
  console.log(`Reserved Cert / Reg Pools:  ${report.counts.reservedCertNumbers} / ${report.counts.reservedRegNumbers}`);
  console.log(`Modified Certificates:      ${report.counts.modifiedCertificates}`);
  console.log(`Failed Issuance Attempts:   ${report.counts.failedIssuanceAttempts}`);
  console.log(`Integrity Mismatches:       ${report.counts.integrityMismatches}`);
  console.log(`Missing/Failed Drive PDFs:  ${report.counts.missingDrivePdfs}`);
  console.log(`Verified Backups Total:     ${report.backupHealth.totalBackups}`);
  console.log(`Last Successful Backup:     ${report.backupHealth.lastSuccessfulBackupAt ?? 'None'}`);
  console.log(`Recent Backup Failures:     ${report.backupHealth.recentBackupFailures}`);
  console.log(`Overall Integrity Status:   ${report.healthy ? 'HEALTHY' : 'DISCREPANCIES DETECTED'}`);

  if (report.discrepancies.length > 0) {
    console.log('\nDiscrepancies (Read-Only Report — Zero Records Modified):');
    for (const d of report.discrepancies) {
      console.log(
        `  - [${d.severity}] ${d.code}${d.certificateNumber ? ` (${d.certificateNumber})` : ''}: ${d.message}`
      );
    }
  }

  if (!report.firestoreConnected || !report.healthy) {
    console.error('\n[FAIL] Database audit detected connectivity failure or critical integrity discrepancies.');
    process.exit(1);
  }

  console.log('\n✓ Read-only Firestore audit PASSED with 0 critical discrepancies and 0 writes.\n');
}

main().catch((err) => {
  console.error('[FAIL] Read-only database audit failed:', err instanceof Error ? err.message : String(err));
  process.exit(1);
});
