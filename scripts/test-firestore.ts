import 'dotenv/config';
import { FirestoreRestStore, normalizePrivateKey } from '../src/server/store.js';

/**
 * Strictly READ-ONLY Firebase / Cloud Firestore connection verifier.
 * Performs ZERO writes, creates, updates, or deletes on your database.
 * Compatible with Firebase Spark (Free) plan on the (default) database.
 */
async function main(): Promise<void> {
  const projectId = process.env.FIREBASE_PROJECT_ID?.trim() || '';
  const databaseId = process.env.FIREBASE_DATABASE_ID?.trim() || '(default)';
  const clientEmail = process.env.FIREBASE_CLIENT_EMAIL?.trim() || '';
  const rawPrivateKey = process.env.FIREBASE_PRIVATE_KEY?.trim() || '';

  const missing: string[] = [];
  if (!projectId) missing.push('FIREBASE_PROJECT_ID');
  if (!clientEmail) missing.push('FIREBASE_CLIENT_EMAIL');
  if (!rawPrivateKey) missing.push('FIREBASE_PRIVATE_KEY');

  if (missing.length > 0) {
    console.error('\n[FAILED] Missing required Firestore environment variables:\n');
    for (const key of missing) {
      console.error(`  - ${key}`);
    }
    console.error(
      '\nSet these in your local shell (or temporary untracked .env file—never commit .env to GitHub) and re-run:\n' +
        '  npm run test:firestore\n'
    );
    process.exit(1);
  }

  const normalizedKey = normalizePrivateKey(rawPrivateKey);
  if (!normalizedKey.includes('BEGIN') || !normalizedKey.includes('PRIVATE KEY')) {
    console.error(
      '\n[FAILED] FIREBASE_PRIVATE_KEY does not look like a valid PEM private key.\n' +
        'Copy the exact "private_key" value from your Firebase Service Account JSON file.\n'
    );
    process.exit(1);
  }

  console.log('\nParivahan Scrappers — Read-Only Firestore Connection Check');
  console.log('----------------------------------------------------------');
  console.log(`Project ID    : ${projectId}`);
  console.log(`Database ID   : ${databaseId}`);
  console.log(`Service Acct  : ${clientEmail}`);
  console.log('Write Mode    : STRICTLY READ-ONLY (0 writes will be made)\n');

  const store = new FirestoreRestStore({
    projectId,
    databaseId,
    clientEmail,
    privateKey: normalizedKey,
  });

  // 1. Read-only ping (OAuth2 token exchange + GET settings/global)
  const ping = await store.ping();
  if (!ping.ok) {
    console.error(`[FAILED] Firestore connectivity probe failed (${ping.latencyMs} ms):`);
    console.error(`  ${ping.message}\n`);
    console.error('Troubleshooting:');
    console.error('  1. Verify FIREBASE_PROJECT_ID matches your new Firebase project (e.g. crm-certificates).');
    console.error('  2. Verify FIREBASE_DATABASE_ID is (default) on the Spark free plan.');
    console.error('  3. Verify the Service Account has the IAM role "Cloud Datastore User" (roles/datastore.user).');
    console.error('  4. Verify Cloud Firestore is created and enabled in Native mode for this project.\n');
    process.exit(1);
  }

  console.log(`✓ OAuth2 Service Account authentication & read probe succeeded (${ping.latencyMs} ms)`);

  // 2. Read-only aggregation counts (uses Spark-friendly COUNT queries, 0 writes)
  const [certCount, reservedCertCount, reservedRegCount, backupCount, auditCount] = await Promise.all([
    store.countCollection('certificates'),
    store.countCollection('reserved_certificate_numbers'),
    store.countCollection('reserved_scrapping_numbers'),
    store.countCollection('database_backups'),
    store.countCollection('audit_logs'),
  ]);

  console.log('✓ Read-only collection COUNT checks succeeded:');
  console.log(`    - certificates                 : ${certCount}`);
  console.log(`    - reserved_certificate_numbers : ${reservedCertCount}`);
  console.log(`    - reserved_scrapping_numbers   : ${reservedRegCount}`);
  console.log(`    - database_backups             : ${backupCount}`);
  console.log(`    - audit_logs                   : ${auditCount}`);

  if (certCount === 0 && reservedCertCount === 0 && reservedRegCount === 0 && backupCount === 0) {
    console.log('\n✓ Fresh empty database confirmed (0 certificates, 0 reserved numbers, 0 backups).');
  } else {
    console.log('\n! Notice: This Firestore database already contains existing documents.');
  }

  console.log('\n[PASSED] Read-only Firestore connection verified with ZERO database writes.\n');
}

main().catch((err) => {
  console.error('\n[FAILED] Unexpected error during read-only Firestore check:');
  console.error(err instanceof Error ? err.message : String(err));
  process.exit(1);
});
