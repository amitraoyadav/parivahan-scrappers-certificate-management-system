import 'dotenv/config';
import readline from 'node:readline';
import { Writable } from 'node:stream';
import {
  generateRecordId,
  hashPassword,
  timingSafeStringEqual,
  verifyPassword,
} from '../src/server/crypto.js';
import { FirestoreRestStore, normalizePrivateKey } from '../src/server/store.js';

/**
 * Secure Maker-Only Password Rotation CLI for Firestore `admins/primary_credentials`.
 *
 * Guarantees:
 * - Never deletes or resets `admins/primary_credentials`.
 * - Never changes `makerUsername` or `mainAdminPasswordHash` or protected/delete hashes.
 * - Verifies the current Main Core Admin password before writing.
 * - Never prints any password, private key, or hash to stdout/stderr.
 * - Re-hashes with salted scrypt, increments `sessionVersion`, and verifies immediately.
 */

function promptHidden(promptText: string): Promise<string> {
  return new Promise((resolve) => {
    const muted = new Writable({
      write(_chunk, _encoding, callback) {
        callback();
      },
    });
    process.stdout.write(promptText);
    const rl = readline.createInterface({
      input: process.stdin,
      output: muted,
      terminal: true,
    });
    rl.question('', (answer) => {
      rl.close();
      process.stdout.write('\n');
      resolve(answer);
    });
  });
}

function normalizeEnvValue(val: string | undefined): string {
  if (!val) return '';
  let t = val.trim();
  if (
    (t.startsWith('"') && t.endsWith('"') && t.length >= 2) ||
    (t.startsWith("'") && t.endsWith("'") && t.length >= 2)
  ) {
    t = t.slice(1, -1).trim();
  }
  return t;
}

function verifyMainAdmin(plain: string, storedHash: string): boolean {
  const envMain = normalizeEnvValue(process.env.MAIN_ADMIN_PASSWORD);
  if (envMain) {
    return envMain.startsWith('scrypt$')
      ? verifyPassword(plain, envMain)
      : timingSafeStringEqual(plain, envMain);
  }
  return verifyPassword(plain, storedHash);
}

async function main(): Promise<void> {
  const projectId = process.env.FIREBASE_PROJECT_ID?.trim() || '';
  const databaseId = process.env.FIREBASE_DATABASE_ID?.trim() || '(default)';
  const clientEmail = process.env.FIREBASE_CLIENT_EMAIL?.trim() || '';
  const rawPrivateKey = process.env.FIREBASE_PRIVATE_KEY?.trim() || '';

  if (!projectId || !clientEmail || !rawPrivateKey) {
    console.error(
      '\n[FAILED] Missing FIREBASE_PROJECT_ID, FIREBASE_CLIENT_EMAIL, or FIREBASE_PRIVATE_KEY.\n' +
        'Export your private Firebase service-account env vars in your shell and re-run.\n'
    );
    process.exit(1);
  }

  if (normalizeEnvValue(process.env.ADMIN_PASSWORD)) {
    console.warn(
      '\n[NOTICE] ADMIN_PASSWORD is set in your current environment.\n' +
        'Remember: in Vercel production, if ADMIN_PASSWORD is set in Project Settings,\n' +
        'it takes precedence over Firestore admins/primary_credentials.makerPasswordHash.\n'
    );
  }

  const store = new FirestoreRestStore({
    projectId,
    databaseId,
    clientEmail,
    privateKey: normalizePrivateKey(rawPrivateKey),
  });

  const existing = await store.getCredentials();
  if (!existing) {
    console.error(
      '\n[FAILED] Firestore document admins/primary_credentials was not found.\n' +
        'This tool only rotates an existing Maker password hash and will not create or reset credentials.\n'
    );
    process.exit(1);
  }

  console.log('\nParivahan Scrappers — Secure Maker-Only Password Rotation');
  console.log('---------------------------------------------------------');
  console.log(`Firebase Project : ${projectId} (${databaseId})`);
  console.log(`Maker Username   : ${existing.makerUsername} (will NOT be modified)`);
  console.log('Main Core Admin  : unchanged (preserved intact)\n');

  const currentMainPassword = await promptHidden('Enter current Main Core Admin password to authorize: ');
  if (!verifyMainAdmin(currentMainPassword, existing.mainAdminPasswordHash)) {
    console.error('\n[DENIED] Main Core Admin password verification failed. No changes were written.\n');
    process.exit(1);
  }

  const newMakerPassword = await promptHidden('Enter new Maker password (minimum 8 characters): ');
  if (newMakerPassword.length < 8) {
    console.error('\n[FAILED] New Maker password must be at least 8 characters. No changes were written.\n');
    process.exit(1);
  }

  const confirmMakerPassword = await promptHidden('Confirm new Maker password: ');
  if (!timingSafeStringEqual(newMakerPassword, confirmMakerPassword)) {
    console.error('\n[FAILED] Passwords do not match. No changes were written.\n');
    process.exit(1);
  }

  const now = new Date().toISOString();
  const nextHash = hashPassword(newMakerPassword);
  const nextVersion = existing.sessionVersion + 1;

  if (!verifyPassword(newMakerPassword, nextHash)) {
    console.error('\n[FAILED] Internal scrypt self-check failed. Aborting without writes.\n');
    process.exit(1);
  }

  await store.saveCredentials({
    ...existing,
    makerPasswordHash: nextHash,
    sessionVersion: nextVersion,
    updatedAt: now,
  });

  await store.addAuditLog({
    id: generateRecordId('aud'),
    timestamp: now,
    actor: 'Main Core Admin (CLI)',
    actorRole: 'main_admin',
    action: 'PASSWORD_ROTATED',
    reason: 'Rotated Maker password hash only via secure CLI (username and Main Core Admin unchanged)',
    metadata: { scope: 'maker_only', newSessionVersion: nextVersion },
  });

  // Read back and verify without ever printing the password or hash
  const reloaded = await store.getCredentials();
  const verified = Boolean(reloaded && verifyPassword(newMakerPassword, reloaded.makerPasswordHash));
  if (!verified || reloaded?.makerUsername !== existing.makerUsername) {
    console.error('\n[FAILED] Post-write verification failed.\n');
    process.exit(1);
  }

  console.log('\n[PASSED] Maker password hash rotated and verified in Firestore admins/primary_credentials.');
  console.log(`         Maker username preserved: ${reloaded.makerUsername}`);
  console.log(`         Main Core Admin password: unchanged`);
  console.log(`         New sessionVersion      : ${reloaded.sessionVersion} (previous sessions invalidated)\n`);
}

main().catch((err) => {
  console.error('\n[FAILED] Unexpected error during Maker password rotation:');
  console.error(err instanceof Error ? err.message : String(err));
  process.exit(1);
});
