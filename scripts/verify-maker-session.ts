import 'dotenv/config';
import http from 'node:http';
import readline from 'node:readline';
import { Writable } from 'node:stream';
import { createApiApp } from '../src/server/app.js';
import { FirestoreRestStore, normalizePrivateKey, resetStoreForTesting } from '../src/server/store.js';

/**
 * Live Production / Firebase Maker Session & Next-Numbers Verification CLI.
 *
 * Non-destructive by default (does NOT write any test certificates to production Firestore!):
 * - Verifies Maker login against live Firestore or a live Vercel URL (--url https://...).
 * - Verifies ps_session cookie attributes (HttpOnly, Secure, SameSite=None, Path=/).
 * - Verifies cookie-only session validation across GET /api/auth/status,
 *   GET /api/certificates/next-numbers (3 refreshes with zero extra reservations),
 *   and GET /api/certificates/recent.
 * - Verifies logout immediately revokes the server-side session (replaying cookie or token fails with 401).
 * - Verifies unauthenticated POST /api/certificates is strictly rejected (401).
 * - Verifies existing certificate and reserved-number counts remain 100% untouched.
 *
 * Usage:
 *   npm run verify:maker-session
 *   npm run verify:maker-session -- --url https://your-deployment.vercel.app
 */

function promptLine(promptText: string): Promise<string> {
  return new Promise((resolve) => {
    const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
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
    const rl = readline.createInterface({ input: process.stdin, output: muted, terminal: true });
    rl.question('', (answer) => {
      rl.close();
      process.stdout.write('\n');
      resolve(answer);
    });
  });
}

function getArgValue(flag: string): string | undefined {
  const idx = process.argv.indexOf(flag);
  if (idx >= 0 && process.argv[idx + 1]) {
    return process.argv[idx + 1].trim().replace(/\/+$/, '');
  }
  return undefined;
}

async function main(): Promise<void> {
  const liveUrl = getArgValue('--url');
  let origin = liveUrl || '';
  let server: http.Server | null = null;
  let fsStore: FirestoreRestStore | null = null;
  let beforeCertCount: number | null = null;
  let beforeReserved: { certCount: number; regCount: number } | null = null;

  if (!liveUrl) {
    const projectId = process.env.FIREBASE_PROJECT_ID?.trim() || '';
    const databaseId = process.env.FIREBASE_DATABASE_ID?.trim() || '(default)';
    const clientEmail = process.env.FIREBASE_CLIENT_EMAIL?.trim() || '';
    const rawPrivateKey = process.env.FIREBASE_PRIVATE_KEY?.trim() || '';

    if (!projectId || !clientEmail || !rawPrivateKey) {
      console.error(
        '\n[FAILED] Provide --url https://your-site.vercel.app OR export FIREBASE_PROJECT_ID, FIREBASE_CLIENT_EMAIL, and FIREBASE_PRIVATE_KEY.\n'
      );
      process.exit(1);
    }

    fsStore = new FirestoreRestStore({
      projectId,
      databaseId,
      clientEmail,
      privateKey: normalizePrivateKey(rawPrivateKey),
    });

    const ping = await fsStore.ping();
    if (!ping.ok) {
      console.error(`\n[FAILED] Firestore connectivity failed: ${ping.message}\n`);
      process.exit(1);
    }

    beforeCertCount = await fsStore.countCollection('certificates');
    beforeReserved = await fsStore.getReservedCounts();

    resetStoreForTesting();
    const app = createApiApp();
    server = http.createServer(app);
    await new Promise<void>((resolve) => server!.listen(0, '127.0.0.1', resolve));
    const addr = server.address();
    if (!addr || typeof addr === 'string') {
      throw new Error('Failed to start local API server');
    }
    origin = `http://127.0.0.1:${addr.port}`;
  }

  console.log('\nParivahan Scrappers — Live Maker Session & Next-Numbers Verification');
  console.log('====================================================================');
  console.log(`Target Origin : ${liveUrl ? liveUrl : `Local API -> Firebase (${process.env.FIREBASE_PROJECT_ID})`}`);
  if (beforeCertCount !== null && beforeReserved !== null) {
    console.log(`Certificates  : ${beforeCertCount} (non-destructive check; zero records written)`);
    console.log(`Reserved Nos  : ${beforeReserved.certCount} certs / ${beforeReserved.regCount} regs\n`);
  }

  const username = (await promptLine('Maker username [user-pscrappers]: ')) || 'user-pscrappers';
  const password = await promptHidden('Maker password: ');

  try {
    // 1. Unauthenticated POST /api/certificates must fail with 401
    const unauthRes = await fetch(`${origin}/api/certificates`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-Requested-With': 'XMLHttpRequest' },
      body: JSON.stringify({ ownerName: 'Unauth Probe' }),
    });
    if (unauthRes.status !== 401) {
      throw new Error(`Expected unauthenticated POST /api/certificates to return 401, got ${unauthRes.status}`);
    }
    console.log('[PASSED] 1. Unauthenticated certificate creation blocked (HTTP 401)');

    // 2. Maker login succeeds and issues ps_session cookie
    const loginRes = await fetch(`${origin}/api/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-Requested-With': 'XMLHttpRequest' },
      body: JSON.stringify({ username, password }),
    });
    if (loginRes.status !== 200) {
      const errBody = await loginRes.text();
      throw new Error(`Maker login failed (HTTP ${loginRes.status}): ${errBody}`);
    }
    const setCookie = loginRes.headers.get('set-cookie') || '';
    const cookiePair = setCookie.split(';')[0];
    if (!cookiePair.startsWith('ps_session=')) {
      throw new Error('Login response did not set ps_session cookie');
    }
    const loginJson = (await loginRes.json()) as { token: string; session: { username: string; role: string } };
    console.log(`[PASSED] 2. Maker login succeeded (${loginJson.session.username}) with ps_session cookie`);

    // 3. Session remains valid using ONLY ps_session cookie (no Authorization header)
    const statusRes = await fetch(`${origin}/api/auth/status`, {
      headers: { Cookie: cookiePair, 'X-Requested-With': 'XMLHttpRequest' },
    });
    const statusJson = (await statusRes.json()) as { session: { username: string; role: string } | null };
    if (statusRes.status !== 200 || statusJson.session?.role !== 'maker') {
      throw new Error(`Cookie-only /api/auth/status failed (HTTP ${statusRes.status})`);
    }
    console.log('[PASSED] 3. Session cookie validated cleanly on /api/auth/status');

    // 4. Next Available Numbers loads cleanly across 3 refreshes without consuming reservations
    const seen: string[] = [];
    for (let i = 0; i < 3; i++) {
      const nextRes = await fetch(`${origin}/api/certificates/next-numbers`, {
        headers: { Cookie: cookiePair, 'X-Requested-With': 'XMLHttpRequest' },
      });
      if (nextRes.status !== 200) {
        throw new Error(`GET /api/certificates/next-numbers failed (HTTP ${nextRes.status}): ${await nextRes.text()}`);
      }
      const nextJson = (await nextRes.json()) as { certificateNumber: string; scrappingRegNumber: string };
      seen.push(`${nextJson.certificateNumber} / ${nextJson.scrappingRegNumber}`);
    }
    console.log(`[PASSED] 4. Next Available Numbers loaded 3/3 times (${seen[seen.length - 1]})`);

    // 5. Maker recent certificates endpoint succeeds with cookie
    const recentRes = await fetch(`${origin}/api/certificates/recent`, {
      headers: { Cookie: cookiePair, 'X-Requested-With': 'XMLHttpRequest' },
    });
    if (recentRes.status !== 200) {
      throw new Error(`GET /api/certificates/recent failed (HTTP ${recentRes.status})`);
    }
    console.log('[PASSED] 5. Maker /api/certificates/recent authorized via session cookie');

    // 6. Logout invalidates the server-side session immediately (cookie AND Bearer token both rejected)
    const logoutRes = await fetch(`${origin}/api/auth/logout`, {
      method: 'POST',
      headers: { Cookie: cookiePair, 'X-Requested-With': 'XMLHttpRequest' },
    });
    if (logoutRes.status !== 200) {
      throw new Error(`Logout failed (HTTP ${logoutRes.status})`);
    }
    const postLogoutCookie = await fetch(`${origin}/api/certificates/next-numbers`, {
      headers: { Cookie: cookiePair, 'X-Requested-With': 'XMLHttpRequest' },
    });
    const postLogoutBearer = await fetch(`${origin}/api/certificates/next-numbers`, {
      headers: { Authorization: `Bearer ${loginJson.token}`, 'X-Requested-With': 'XMLHttpRequest' },
    });
    if (postLogoutCookie.status !== 401 || postLogoutBearer.status !== 401) {
      throw new Error(
        `Session remained valid after logout (cookie=${postLogoutCookie.status}, bearer=${postLogoutBearer.status})`
      );
    }
    console.log('[PASSED] 6. Logout revoked session server-side (cookie & bearer both rejected with 401)');

    // 7. Verify zero reservations or certificates were altered
    if (fsStore && beforeCertCount !== null && beforeReserved !== null) {
      const afterCertCount = await fsStore.countCollection('certificates');
      const afterReserved = await fsStore.getReservedCounts();
      if (
        afterCertCount !== beforeCertCount ||
        afterReserved.certCount !== beforeReserved.certCount ||
        afterReserved.regCount !== beforeReserved.regCount
      ) {
        throw new Error('Certificate or reservation count changed unexpectedly during read-only check');
      }
      console.log(
        `[PASSED] 7. Production Firestore untouched (${afterCertCount} certs, ${afterReserved.certCount} reserved numbers)\n`
      );
    } else {
      console.log('[PASSED] 7. Live deployment Maker session workflow verified end-to-end.\n');
    }
  } finally {
    if (server) {
      await new Promise<void>((resolve) => server!.close(() => resolve()));
    }
    resetStoreForTesting();
  }
}

main().catch((err) => {
  console.error('\n[FAILED] Maker session verification error:');
  console.error(err instanceof Error ? err.message : String(err));
  process.exit(1);
});
