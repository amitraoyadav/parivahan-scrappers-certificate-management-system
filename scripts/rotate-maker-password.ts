import 'dotenv/config';
import http from 'node:http';
import readline from 'node:readline';
import { Writable } from 'node:stream';
import { createApiApp } from '../src/server/app.js';
import {
  generateRecordId,
  hashPassword,
  timingSafeStringEqual,
  validateScryptHashFormat,
  verifyPassword,
} from '../src/server/crypto.js';
import { FirestoreRestStore, normalizePrivateKey, resetStoreForTesting } from '../src/server/store.js';

/**
 * Secure Maker-Only Password Rotation & Live Verification CLI for Firestore `admins/primary_credentials`.
 *
 * Guarantees:
 * - Never deletes or recreates `admins/primary_credentials`.
 * - Keeps `makerUsername` (`pscrappers`) unchanged.
 * - Keeps `mainAdminPasswordHash`, `protectedPasswordHash`, and `deletePasswordHash` untouched.
 * - Never modifies any certificate records.
 * - Never prints any password, private key, session token, or hash to stdout/stderr.
 * - Uses the exact same scrypt implementation (`hashPassword` / `verifyPassword`) as login.
 * - After updating Firestore, verifies real login, logout, re-login, Main Core Admin unlock,
 *   and unchanged certificate count against the actual configured Firebase project.
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

async function runLiveEndToEndAuthVerification(params: {
  makerUsername: string;
  makerPassword: string;
  mainAdminPassword: string;
}): Promise<{ certCount: number }> {
  resetStoreForTesting();
  const app = createApiApp();
  const server = http.createServer(app);
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const addr = server.address();
  if (!addr || typeof addr === 'string') {
    throw new Error('Failed to start local verification listener');
  }
  const origin = `http://127.0.0.1:${addr.port}`;

  const call = async (
    path: string,
    opts: { method?: string; token?: string; body?: unknown } = {}
  ) => {
    const headers: Record<string, string> = { 'X-Requested-With': 'XMLHttpRequest' };
    if (opts.body !== undefined) headers['Content-Type'] = 'application/json';
    if (opts.token) headers['Authorization'] = `Bearer ${opts.token}`;
    const res = await fetch(`${origin}${path}`, {
      method: opts.method ?? 'GET',
      headers,
      body: opts.body !== undefined ? JSON.stringify(opts.body) : undefined,
    });
    const json = (await res.json()) as Record<string, unknown>;
    return { status: res.status, json };
  };

  try {
    // 1. First Maker login
    const login1 = await call('/api/auth/login', {
      method: 'POST',
      body: { username: params.makerUsername, password: params.makerPassword },
    });
    if (login1.status !== 200 || typeof login1.json.token !== 'string') {
      throw new Error(`Real Maker login #1 failed (HTTP ${login1.status})`);
    }
    const token1 = login1.json.token;

    // 2. Verify Maker authenticated route works
    const recentRes = await call('/api/certificates/recent', { token: token1 });
    if (recentRes.status !== 200) {
      throw new Error(`Maker /api/certificates/recent failed (HTTP ${recentRes.status})`);
    }

    // 3. Logout
    const logoutRes = await call('/api/auth/logout', { method: 'POST', token: token1 });
    if (logoutRes.status !== 200) {
      throw new Error(`Maker logout failed (HTTP ${logoutRes.status})`);
    }

    // 4. Login again after logout
    const login2 = await call('/api/auth/login', {
      method: 'POST',
      body: { username: params.makerUsername, password: params.makerPassword },
    });
    if (login2.status !== 200 || typeof login2.json.token !== 'string') {
      throw new Error(`Real Maker login #2 (after logout) failed (HTTP ${login2.status})`);
    }

    // 5. Verify Main Core Admin unlock still works unchanged & read certificate count
    const adminRes = await call('/api/auth/admin-unlock', {
      method: 'POST',
      body: { password: params.mainAdminPassword },
    });
    if (adminRes.status !== 200 || typeof adminRes.json.token !== 'string') {
      throw new Error(`Main Core Admin unlock check failed (HTTP ${adminRes.status})`);
    }
    const statsRes = await call('/api/admin/stats', { token: adminRes.json.token });
    if (statsRes.status !== 200) {
      throw new Error(`Main Core Admin stats check failed (HTTP ${statsRes.status})`);
    }
    const certCount = Number(statsRes.json.totalCertificates ?? 0);
    return { certCount };
  } finally {
    await new Promise<void>((resolve) => server.close(() => resolve()));
  }
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

  const beforeCertCount = await store.countCollection('certificates');
  const existingHashCheck = validateScryptHashFormat(existing.makerPasswordHash);

  console.log('\nParivahan Scrappers — Secure Maker-Only Password Rotation');
  console.log('---------------------------------------------------------');
  console.log(`Firebase Project       : ${projectId} (${databaseId})`);
  console.log(`Maker Username         : ${existing.makerUsername} (preserved untouched)`);
  console.log(`Existing Hash Format   : ${existingHashCheck.valid ? 'valid scrypt$salt$key' : `INVALID (${existingHashCheck.reason})`}`);
  console.log(`Main Core Admin        : unchanged (preserved intact)`);
  console.log(`Existing Certificates  : ${beforeCertCount} (will NOT be modified)\n`);

  if (normalizeEnvValue(process.env.ADMIN_PASSWORD)) {
    console.log(
      '[INFO] ADMIN_PASSWORD is present in your environment. Firestore admins/primary_credentials\n' +
        '       is now authoritative for Maker login, so stale ADMIN_PASSWORD env values are ignored.\n'
    );
  }

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

  if (!validateScryptHashFormat(nextHash).valid || !verifyPassword(newMakerPassword, nextHash)) {
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
    metadata: { scope: 'maker_only', authSource: 'firestore', newSessionVersion: nextVersion },
  });

  // Read back and verify hash integrity without printing any password or hash
  const reloaded = await store.getCredentials();
  const verified = Boolean(reloaded && verifyPassword(newMakerPassword, reloaded.makerPasswordHash));
  if (
    !verified ||
    reloaded?.makerUsername !== existing.makerUsername ||
    reloaded?.mainAdminPasswordHash !== existing.mainAdminPasswordHash
  ) {
    console.error('\n[FAILED] Post-write Firestore verification failed.\n');
    process.exit(1);
  }

  console.log('\n[PASSED] Firestore admins/primary_credentials updated (makerPasswordHash only).');
  console.log('Running real end-to-end authentication test against configured Firebase project...');

  const e2e = await runLiveEndToEndAuthVerification({
    makerUsername: reloaded.makerUsername,
    makerPassword: newMakerPassword,
    mainAdminPassword: currentMainPassword,
  });

  if (e2e.certCount !== beforeCertCount) {
    console.error(
      `\n[WARNING] Certificate count changed during check (${beforeCertCount} -> ${e2e.certCount}).\n`
    );
    process.exit(1);
  }

  console.log(`[PASSED] Real Maker login succeeded for username: ${reloaded.makerUsername}`);
  console.log('[PASSED] Maker logout and re-login succeeded.');
  console.log('[PASSED] Main Core Admin authentication verified unchanged.');
  console.log(`[PASSED] Certificate records intact (${e2e.certCount} records untouched).`);
  console.log(`[PASSED] New sessionVersion: ${reloaded.sessionVersion} (prior sessions invalidated).\n`);
}

main().catch((err) => {
  console.error('\n[FAILED] Unexpected error during Maker password rotation:');
  console.error(err instanceof Error ? err.message : String(err));
  process.exit(1);
});

