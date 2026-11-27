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
import {
  FirestoreRestStore,
  normalizePrivateKey,
  resetStoreForTesting,
  type StoredCredentials,
} from '../src/server/store.js';

/**
 * Secure Local Authentication Recovery & Live Verification CLI
 * for Parivahan Scrappers Certificate Management System.
 *
 * Security Guarantees:
 * - Strictly local CLI authorized via private Firebase service-account credentials.
 * - Does NOT expose any public HTTP password-reset endpoint.
 * - Never deletes or recreates `admins/primary_credentials` (updates only selected fields).
 * - Never modifies certificate records, reserved numbers, or existing audit history.
 * - Never prints passwords, private keys, session tokens, or scrypt hashes to stdout/stderr.
 * - Uses the exact same scrypt implementation (`hashPassword`, `verifyPassword`, `validateScryptHashFormat`) as login.
 * - After recovery, immediately executes real end-to-end API authentication tests
 *   (login/unlock, dashboard/settings access, RBAC check, logout, re-login, certificate count check)
 *   against the configured Firebase project.
 *
 * Usage:
 *   npm run recover:auth -- --inspect   (read-only diagnostics, zero writes)
 *   npm run recover:auth                (interactive recovery menu)
 */

const INTENDED_MAKER_USERNAME = 'user-pscrappers';

function promptLine(promptText: string): Promise<string> {
  return new Promise((resolve) => {
    const rl = readline.createInterface({
      input: process.stdin,
      output: process.stdout,
    });
    rl.question(promptText, (answer) => {
      rl.close();
      resolve(answer.trim());
    });
  });
}

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

async function promptNewPassword(label: string): Promise<string> {
  const first = await promptHidden(`Enter new ${label} password (minimum 8 characters): `);
  if (first.length < 8) {
    throw new Error(`${label} password must be at least 8 characters. No changes were written.`);
  }
  const confirm = await promptHidden(`Confirm new ${label} password: `);
  if (!timingSafeStringEqual(first, confirm)) {
    throw new Error(`${label} passwords do not match. No changes were written.`);
  }
  return first;
}

function describeHashHealth(hash: string | undefined): string {
  if (!hash) return 'MISSING';
  const check = validateScryptHashFormat(hash);
  return check.valid ? 'VALID (scrypt$salt$key)' : `INVALID (${check.reason})`;
}

function printEnvWarnings(): void {
  const staleVars = [
    'ADMIN_USERNAME',
    'ADMIN_PASSWORD',
    'MAIN_ADMIN_PASSWORD',
    'ADMIN_PROTECTED_PASSWORD',
    'ADMIN_DELETE_PASSWORD',
  ].filter((name) => Boolean(process.env[name]?.trim()));

  if (staleVars.length > 0) {
    console.log(
      `[INFO] Legacy credential env var(s) detected in shell: ${staleVars.join(', ')}.\n` +
        '       Firestore admins/primary_credentials is the single authoritative credential source;\n' +
        '       remove stale password env vars in Vercel after recovery to keep configuration clean.\n'
    );
  }
}

async function runLiveEndToEndVerification(params: {
  makerUsername?: string;
  makerPassword?: string;
  mainAdminPassword?: string;
}): Promise<{ certCount?: number; checks: string[] }> {
  resetStoreForTesting();
  const app = createApiApp();
  const server = http.createServer(app);
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const addr = server.address();
  if (!addr || typeof addr === 'string') {
    throw new Error('Failed to start local verification server');
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

  const checks: string[] = [];
  let certCount: number | undefined;

  try {
    if (params.mainAdminPassword) {
      // 1. Main Core Admin unlock #1
      const unlock1 = await call('/api/auth/admin-unlock', {
        method: 'POST',
        body: { password: params.mainAdminPassword },
      });
      if (unlock1.status !== 200 || typeof unlock1.json.token !== 'string') {
        throw new Error(`Main Core Admin unlock #1 failed (HTTP ${unlock1.status})`);
      }
      const adminToken1 = unlock1.json.token;
      checks.push('Main Core Admin unlock succeeded');

      // 2. Main Core Admin settings & stats access
      const settingsRes = await call('/api/admin/settings', { token: adminToken1 });
      if (settingsRes.status !== 200) {
        throw new Error(`Main Core Admin /api/admin/settings failed (HTTP ${settingsRes.status})`);
      }
      const statsRes = await call('/api/admin/stats', { token: adminToken1 });
      if (statsRes.status !== 200) {
        throw new Error(`Main Core Admin /api/admin/stats failed (HTTP ${statsRes.status})`);
      }
      certCount = Number(statsRes.json.totalCertificates ?? 0);
      checks.push('Main Core Admin settings & dashboard stats access succeeded');

      // 3. Main Core Admin logout & re-login
      const logoutRes = await call('/api/auth/logout', { method: 'POST', token: adminToken1 });
      if (logoutRes.status !== 200) {
        throw new Error(`Main Core Admin logout failed (HTTP ${logoutRes.status})`);
      }
      const unlock2 = await call('/api/auth/admin-unlock', {
        method: 'POST',
        body: { password: params.mainAdminPassword },
      });
      if (unlock2.status !== 200 || typeof unlock2.json.token !== 'string') {
        throw new Error(`Main Core Admin re-login after logout failed (HTTP ${unlock2.status})`);
      }
      checks.push('Main Core Admin logout and re-login succeeded');
    }

    if (params.makerUsername && params.makerPassword) {
      // 4. Maker login #1
      const login1 = await call('/api/auth/login', {
        method: 'POST',
        body: { username: params.makerUsername, password: params.makerPassword },
      });
      if (login1.status !== 200 || typeof login1.json.token !== 'string') {
        throw new Error(`Certificate Maker login #1 failed (HTTP ${login1.status})`);
      }
      const makerToken1 = login1.json.token;
      checks.push(`Certificate Maker login succeeded for username: ${params.makerUsername}`);

      // 5. Maker dashboard access & Admin RBAC isolation
      const recentRes = await call('/api/certificates/recent', { token: makerToken1 });
      if (recentRes.status !== 200) {
        throw new Error(`Maker /api/certificates/recent failed (HTTP ${recentRes.status})`);
      }
      const rbacRes = await call('/api/admin/settings', { token: makerToken1 });
      if (rbacRes.status !== 403) {
        throw new Error(`Expected Maker /api/admin/settings to return 403, got HTTP ${rbacRes.status}`);
      }
      checks.push('Certificate Maker dashboard access & Admin isolation (403) verified');

      // 6. Maker logout & re-login
      const makerLogout = await call('/api/auth/logout', { method: 'POST', token: makerToken1 });
      if (makerLogout.status !== 200) {
        throw new Error(`Certificate Maker logout failed (HTTP ${makerLogout.status})`);
      }
      const login2 = await call('/api/auth/login', {
        method: 'POST',
        body: { username: params.makerUsername, password: params.makerPassword },
      });
      if (login2.status !== 200 || typeof login2.json.token !== 'string') {
        throw new Error(`Certificate Maker re-login after logout failed (HTTP ${login2.status})`);
      }
      checks.push('Certificate Maker logout and re-login succeeded');
    }

    return { certCount, checks };
  } finally {
    await new Promise<void>((resolve) => server.close(() => resolve()));
    resetStoreForTesting();
  }
}

async function main(): Promise<void> {
  const inspectOnly = process.argv.includes('--inspect');
  const projectId = process.env.FIREBASE_PROJECT_ID?.trim() || '';
  const databaseId = process.env.FIREBASE_DATABASE_ID?.trim() || '(default)';
  const clientEmail = process.env.FIREBASE_CLIENT_EMAIL?.trim() || '';
  const rawPrivateKey = process.env.FIREBASE_PRIVATE_KEY?.trim() || '';

  if (!projectId || !clientEmail || !rawPrivateKey) {
    console.error(
      '\n[FAILED] Missing FIREBASE_PROJECT_ID, FIREBASE_CLIENT_EMAIL, or FIREBASE_PRIVATE_KEY.\n' +
        'Export your private Firebase service-account credentials in your local terminal and re-run:\n' +
        '  npm run recover:auth -- --inspect   (read-only inspection)\n' +
        '  npm run recover:auth                (interactive recovery)\n'
    );
    process.exit(1);
  }

  const store = new FirestoreRestStore({
    projectId,
    databaseId,
    clientEmail,
    privateKey: normalizePrivateKey(rawPrivateKey),
  });

  const ping = await store.ping();
  if (!ping.ok) {
    console.error(`\n[FAILED] Firestore connectivity check failed: ${ping.message}\n`);
    process.exit(1);
  }

  const existing = await store.getCredentials();
  const beforeCertCount = await store.countCollection('certificates');

  console.log('\nParivahan Scrappers — Secure Local Authentication Recovery');
  console.log('==========================================================');
  console.log(`Firebase Project       : ${projectId} (${databaseId})`);
  console.log(`Firestore Connectivity : OK (${ping.latencyMs}ms)`);
  console.log(`Existing Certificates  : ${beforeCertCount} (preserved untouched)`);

  if (!existing) {
    console.log('Credentials Document   : MISSING (admins/primary_credentials does not exist)');
    console.log('==========================================================\n');
    printEnvWarnings();

    if (inspectOnly) {
      console.log('[INSPECT] Read-only check complete. No changes were written.\n');
      return;
    }

    const confirmInit = await promptLine(
      'admins/primary_credentials does not exist. Type INIT to create initial credentials atomically (or anything else to cancel): '
    );
    if (confirmInit !== 'INIT') {
      console.log('\nCancelled. No changes were written.\n');
      return;
    }

    const mainAdminPassword = await promptNewPassword('Main Core Admin');
    const makerPassword = await promptNewPassword(`Certificate Maker (${INTENDED_MAKER_USERNAME})`);
    const protectedPassword = await promptNewPassword('Protected Actions (Edit/Delete/Restore)');

    const now = new Date().toISOString();
    const initialCreds: StoredCredentials = {
      makerUsername: INTENDED_MAKER_USERNAME,
      makerPasswordHash: hashPassword(makerPassword),
      mainAdminPasswordHash: hashPassword(mainAdminPassword),
      protectedPasswordHash: hashPassword(protectedPassword),
      deletePasswordHash: hashPassword(protectedPassword),
      sessionVersion: 1,
      bootstrappedAt: now,
      updatedAt: now,
    };

    const selfChecks = [
      validateScryptHashFormat(initialCreds.mainAdminPasswordHash).valid &&
        verifyPassword(mainAdminPassword, initialCreds.mainAdminPasswordHash),
      validateScryptHashFormat(initialCreds.makerPasswordHash).valid &&
        verifyPassword(makerPassword, initialCreds.makerPasswordHash),
      validateScryptHashFormat(initialCreds.protectedPasswordHash).valid &&
        verifyPassword(protectedPassword, initialCreds.protectedPasswordHash),
    ];
    if (selfChecks.some((ok) => !ok)) {
      throw new Error('Internal scrypt self-check failed before write. Aborting.');
    }

    const created = await store.createCredentialsIfAbsent(initialCreds);
    if (!created) {
      throw new Error('admins/primary_credentials was created concurrently. Re-run to inspect.');
    }

    await store.addAuditLog({
      id: generateRecordId('aud'),
      timestamp: now,
      actor: 'System Owner (Local Recovery CLI)',
      actorRole: 'main_admin',
      action: 'BOOTSTRAP_SECURITY',
      reason: 'Initialized admins/primary_credentials atomically via secure local recovery CLI',
      metadata: { scope: 'local_recovery_init', makerUsername: INTENDED_MAKER_USERNAME },
    });

    console.log('\n[PASSED] Initialized admins/primary_credentials atomically.');
    const e2e = await runLiveEndToEndVerification({
      makerUsername: INTENDED_MAKER_USERNAME,
      makerPassword,
      mainAdminPassword,
    });
    for (const check of e2e.checks) {
      console.log(`[PASSED] ${check}`);
    }
    console.log(`[PASSED] Certificate records intact (${e2e.certCount ?? beforeCertCount} records untouched).\n`);
    return;
  }

  console.log(`Credentials Document   : PRESENT (admins/primary_credentials)`);
  console.log(
    `Authoritative Maker    : ${existing.makerUsername}${
      existing.makerUsername !== INTENDED_MAKER_USERNAME
        ? ` (MISMATCH: intended is ${INTENDED_MAKER_USERNAME})`
        : ' (matches intended username)'
    }`
  );
  console.log(`Maker Hash Format      : ${describeHashHealth(existing.makerPasswordHash)}`);
  console.log(`Main Admin Hash Format : ${describeHashHealth(existing.mainAdminPasswordHash)}`);
  console.log(`Protected Hash Format  : ${describeHashHealth(existing.protectedPasswordHash)}`);
  console.log(`Delete Hash Format     : ${describeHashHealth(existing.deletePasswordHash)}`);
  console.log(`Session Version        : ${existing.sessionVersion}`);
  console.log(`Last Updated           : ${existing.updatedAt}`);
  console.log('==========================================================\n');
  printEnvWarnings();

  if (inspectOnly) {
    console.log('[INSPECT] Read-only check complete. No changes were written.\n');
    return;
  }

  console.log('Select recovery action:');
  console.log(`  1) Recover BOTH Main Core Admin + Certificate Maker (recommended)`);
  console.log('  2) Recover Main Core Admin password ONLY');
  console.log('  3) Recover Certificate Maker password / username ONLY');
  console.log('  4) Exit (no changes)\n');

  const choice = await promptLine('Enter choice [1-4]: ');
  if (choice !== '1' && choice !== '2' && choice !== '3') {
    console.log('\nNo changes were written.\n');
    return;
  }

  const recoverMainAdmin = choice === '1' || choice === '2';
  const recoverMaker = choice === '1' || choice === '3';

  let nextMakerUsername = existing.makerUsername;
  let newMainAdminPassword: string | undefined;
  let newMakerPassword: string | undefined;
  let newProtectedPassword: string | undefined;

  if (recoverMaker && existing.makerUsername !== INTENDED_MAKER_USERNAME) {
    const alignAns = await promptLine(
      `Stored Maker username is "${existing.makerUsername}". Update authoritative username to "${INTENDED_MAKER_USERNAME}"? (Y/n): `
    );
    if (!alignAns || alignAns.toLowerCase().startsWith('y')) {
      nextMakerUsername = INTENDED_MAKER_USERNAME;
    }
  }

  if (recoverMainAdmin) {
    newMainAdminPassword = await promptNewPassword('Main Core Admin');
  }

  if (recoverMaker) {
    newMakerPassword = await promptNewPassword(`Certificate Maker (${nextMakerUsername})`);
  }

  if (choice === '1') {
    const updateProt = await promptLine(
      'Also reset Protected Action (Edit/Delete/Restore) password? (y/N): '
    );
    if (updateProt.toLowerCase().startsWith('y')) {
      newProtectedPassword = await promptNewPassword('Protected Actions');
    }
  }

  const now = new Date().toISOString();
  const nextVersion = existing.sessionVersion + 1;
  const updatedFields: string[] = [];

  const nextCreds: StoredCredentials = {
    ...existing,
    sessionVersion: nextVersion,
    updatedAt: now,
  };

  if (newMainAdminPassword) {
    const nextMainHash = hashPassword(newMainAdminPassword);
    if (!validateScryptHashFormat(nextMainHash).valid || !verifyPassword(newMainAdminPassword, nextMainHash)) {
      throw new Error('Main Core Admin scrypt self-check failed. Aborting without writes.');
    }
    nextCreds.mainAdminPasswordHash = nextMainHash;
    updatedFields.push('mainAdminPasswordHash');
  }

  if (nextMakerUsername !== existing.makerUsername) {
    nextCreds.makerUsername = nextMakerUsername;
    updatedFields.push('makerUsername');
  }

  if (newMakerPassword) {
    const nextMakerHash = hashPassword(newMakerPassword);
    if (!validateScryptHashFormat(nextMakerHash).valid || !verifyPassword(newMakerPassword, nextMakerHash)) {
      throw new Error('Certificate Maker scrypt self-check failed. Aborting without writes.');
    }
    nextCreds.makerPasswordHash = nextMakerHash;
    updatedFields.push('makerPasswordHash');
  }

  if (newProtectedPassword) {
    const nextProtHash = hashPassword(newProtectedPassword);
    if (!validateScryptHashFormat(nextProtHash).valid || !verifyPassword(newProtectedPassword, nextProtHash)) {
      throw new Error('Protected Action scrypt self-check failed. Aborting without writes.');
    }
    nextCreds.protectedPasswordHash = nextProtHash;
    nextCreds.deletePasswordHash = nextProtHash;
    updatedFields.push('protectedPasswordHash', 'deletePasswordHash');
  }

  // Update existing document in-place (never delete or recreate)
  await store.saveCredentials(nextCreds);

  await store.addAuditLog({
    id: generateRecordId('aud'),
    timestamp: now,
    actor: 'System Owner (Local Recovery CLI)',
    actorRole: 'main_admin',
    action: 'PASSWORD_ROTATED',
    reason: `Local credential recovery updated: ${updatedFields.join(', ')}`,
    metadata: {
      scope: 'local_recovery',
      updatedFields: updatedFields.join(','),
      makerUsername: nextCreds.makerUsername,
      newSessionVersion: nextVersion,
    },
  });

  // Reload from Firestore and verify persisted fields + untouched fields
  const reloaded = await store.getCredentials();
  if (!reloaded) {
    throw new Error('Post-write check failed: admins/primary_credentials could not be reloaded.');
  }
  if (reloaded.bootstrappedAt !== existing.bootstrappedAt) {
    throw new Error('Post-write check failed: bootstrappedAt changed unexpectedly.');
  }
  if (reloaded.makerUsername !== nextCreds.makerUsername) {
    throw new Error('Post-write check failed: makerUsername mismatch.');
  }
  if (newMainAdminPassword && !verifyPassword(newMainAdminPassword, reloaded.mainAdminPasswordHash)) {
    throw new Error('Post-write check failed: Main Core Admin hash verification failed.');
  }
  if (!newMainAdminPassword && reloaded.mainAdminPasswordHash !== existing.mainAdminPasswordHash) {
    throw new Error('Post-write check failed: untouched mainAdminPasswordHash changed.');
  }
  if (newMakerPassword && !verifyPassword(newMakerPassword, reloaded.makerPasswordHash)) {
    throw new Error('Post-write check failed: Maker hash verification failed.');
  }
  if (!newMakerPassword && reloaded.makerPasswordHash !== existing.makerPasswordHash) {
    throw new Error('Post-write check failed: untouched makerPasswordHash changed.');
  }
  if (!newProtectedPassword) {
    if (
      reloaded.protectedPasswordHash !== existing.protectedPasswordHash ||
      reloaded.deletePasswordHash !== existing.deletePasswordHash
    ) {
      throw new Error('Post-write check failed: untouched protected/delete hashes changed.');
    }
  }

  console.log(`\n[PASSED] Firestore admins/primary_credentials updated (${updatedFields.join(', ')}).`);
  console.log(`[PASSED] New sessionVersion: ${reloaded.sessionVersion} (prior sessions invalidated).`);
  console.log('Running real end-to-end authentication tests against live Firebase...\n');

  const e2e = await runLiveEndToEndVerification({
    makerUsername: newMakerPassword ? reloaded.makerUsername : undefined,
    makerPassword: newMakerPassword,
    mainAdminPassword: newMainAdminPassword,
  });

  const afterCertCount = await store.countCollection('certificates');
  if (afterCertCount !== beforeCertCount || (e2e.certCount !== undefined && e2e.certCount !== beforeCertCount)) {
    throw new Error(`Certificate count mismatch (${beforeCertCount} -> ${afterCertCount}).`);
  }

  for (const check of e2e.checks) {
    console.log(`[PASSED] ${check}`);
  }
  console.log(`[PASSED] Certificate records intact (${afterCertCount} records untouched).\n`);
}

main().catch((err) => {
  console.error('\n[FAILED] Authentication recovery error:');
  console.error(err instanceof Error ? err.message : String(err));
  process.exit(1);
});
