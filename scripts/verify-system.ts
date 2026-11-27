import assert from 'node:assert/strict';
import http from 'node:http';
import { createApiApp } from '../src/server/app.js';

async function runTests(): Promise<void> {
  const app = createApiApp();
  const server = http.createServer(app);

  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const address = server.address();
  if (!address || typeof address === 'string') {
    throw new Error('Failed to bind test server');
  }
  const baseUrl = `http://127.0.0.1:${address.port}`;

  async function req(
    path: string,
    options: { method?: string; body?: unknown; token?: string; headers?: Record<string, string> } = {}
  ): Promise<{ status: number; json: Record<string, unknown> }> {
    const headers: Record<string, string> = {
      'X-Requested-With': 'XMLHttpRequest',
      ...(options.headers ?? {}),
    };
    if (options.body !== undefined) {
      headers['Content-Type'] = 'application/json';
    }
    if (options.token) {
      headers['Authorization'] = `Bearer ${options.token}`;
    }
    const res = await fetch(`${baseUrl}${path}`, {
      method: options.method ?? 'GET',
      headers,
      body: options.body !== undefined ? JSON.stringify(options.body) : undefined,
    });
    const json = (await res.json()) as Record<string, unknown>;
    return { status: res.status, json };
  }

  try {
    // 1. Fresh empty database & bootstrap state
    const status1 = await req('/api/auth/status');
    assert.equal(status1.status, 200);
    assert.equal(status1.json.requiresBootstrap, true, 'Fresh database should require first-run bootstrap');
    console.log('✓ 1. Fresh empty registry state verified (0 historical credentials/records)');

    // 2. First-run bootstrap & lock check
    const boot = await req('/api/auth/bootstrap', {
      method: 'POST',
      body: {
        makerUsername: 'maker_operator',
        makerPassword: 'MakerPassword#2026',
        mainAdminPassword: 'MainAdmin#2026Secure',
        protectedPassword: 'ProtectedAction#2026',
      },
    });
    assert.equal(boot.status, 201);

    const bootAgain = await req('/api/auth/bootstrap', {
      method: 'POST',
      body: {
        makerUsername: 'attacker',
        makerPassword: 'Password1234',
        mainAdminPassword: 'Password1234',
        protectedPassword: 'Password1234',
      },
    });
    assert.equal(bootAgain.status, 403, 'Bootstrap must lock permanently after initial setup');
    console.log('✓ 2. First-run salted scrypt bootstrap & permanent lock verified');

    // 3. Invalid Maker login & valid Maker login
    const badMaker = await req('/api/auth/login', {
      method: 'POST',
      body: { username: 'maker_operator', password: 'WrongPassword' },
    });
    assert.equal(badMaker.status, 401);

    const goodMaker = await req('/api/auth/login', {
      method: 'POST',
      body: { username: 'maker_operator', password: 'MakerPassword#2026' },
    });
    assert.equal(goodMaker.status, 200);
    const makerToken = String(goodMaker.json.token);
    console.log('✓ 3. Maker authentication (invalid rejected, valid accepted) verified');

    // 4. Maker blocked from full registry, stats, audit logs, backups, settings
    for (const forbiddenPath of [
      '/api/certificates',
      '/api/admin/certificates',
      '/api/admin/stats',
      '/api/admin/audit-logs',
      '/api/admin/backups',
      '/api/admin/settings',
    ]) {
      const blocked = await req(forbiddenPath, { token: makerToken });
      assert.equal(blocked.status, 403, `Maker must be blocked from ${forbiddenPath}`);
    }
    console.log('✓ 4. Maker RBAC isolation verified (403 on all admin & full-registry routes)');

    // 5. Concurrent random certificate creation (7 certificates) + format uniqueness + latest-5 restriction
    const makePayload = (idx: number) => ({
      issueDate: '2026-11-24',
      handoverDate: '2026-11-23',
      ownerName: `Test Owner ${idx}`,
      // Test optional address & optional ID proof omitted on odd indices, provided on even indices
      ownerAddress: idx % 2 === 0 ? `Plot ${idx}, Sector 14, Gurugram, Haryana` : '',
      idProofType: idx % 2 === 0 ? 'Aadhaar Card' : '',
      idProofNumber: idx % 2 === 0 ? `99998888777${idx}` : '',
      vehicleRegNumber: `HR26DK100${idx}`,
      make: idx % 2 === 0 ? 'Honda Scooter (Activa / Dio)' : 'Hero MotoCorp',
      model: idx % 2 === 0 ? 'Activa 6G' : 'Splendor Plus',
      manufactureYear: 2012,
      chassisNumber: `MA3EJKD1S0012345${idx}`,
      engineNumber: `K12MN456789${idx}`,
      unhideChassisEngine: false,
      rtoAuthority: 'RTO Gurugram (HR-26)',
      remarks: 'Verified scrap test',
    });

    const createdList = await Promise.all(
      [1, 2, 3, 4, 5, 6, 7].map((i) =>
        req('/api/certificates', {
          method: 'POST',
          token: makerToken,
          headers: { 'Idempotency-Key': `concurrent_test_${i}` },
          body: makePayload(i),
        })
      )
    );
    const certNums = new Set<string>();
    const regNums = new Set<string>();
    const certIds: string[] = [];
    for (const item of createdList) {
      assert.equal(item.status, 201);
      const cert = item.json.certificate as Record<string, unknown>;
      const cNo = String(cert.certificateNumber);
      const rNo = String(cert.scrappingRegNumber);
      assert.match(cNo, /^PS\/26\/R\d{7}$/);
      assert.match(rNo, /^REG-C\d{6}$/);
      assert.equal(certNums.has(cNo), false, 'Duplicate certificate number detected');
      assert.equal(regNums.has(rNo), false, 'Duplicate scrapping registration number detected');
      certNums.add(cNo);
      regNums.add(rNo);
      certIds.push(String(cert.id));
    }
    console.log('✓ 5. Concurrent cryptographic allocation (7/7 unique PS/26/R[7] & REG-C[6]) verified');

    // 6. Idempotency replay protection
    const replay = await req('/api/certificates', {
      method: 'POST',
      token: makerToken,
      headers: { 'Idempotency-Key': 'concurrent_test_1' },
      body: makePayload(1),
    });
    assert.equal(replay.status, 200);
    assert.equal(replay.json.idempotentReplay, true);
    assert.equal((replay.json.certificate as Record<string, unknown>).id, certIds[0]);
    console.log('✓ 6. Idempotency double-click/retry protection verified');

    // 7. Maker latest-five restriction
    const recent = await req('/api/certificates/recent', { token: makerToken });
    assert.equal(recent.status, 200);
    const recentCerts = recent.json.certificates as Array<Record<string, unknown>>;
    assert.equal(recentCerts.length, 5, 'Maker must only receive 5 most recent certificates');
    // 7b. Maker blocked from retrieving certificate #1 or #2 directly by ID once outside latest 5
    const recentIds = new Set(recentCerts.map((c) => String(c.id)));
    const olderId = certIds.find((id) => !recentIds.has(id));
    assert.ok(olderId, 'Expected at least one certificate older than the latest five');
    const olderDirect = await req(`/api/certificates/${olderId}`, { token: makerToken });
    assert.equal(olderDirect.status, 403, 'Maker must be blocked from fetching certificates outside latest 5');
    console.log('✓ 7. Maker latest-five restriction & direct-ID boundary verified (5 of 7 returned, older ID 403)');

    // 8. Public QR verification (no login, masked chassis/engine, no ID proof leaked, SHA-256 verified)
    const firstCert = (createdList[0].json.certificate as Record<string, unknown>);
    const verifyRes = await req(
      `/api/verify?certificateNumber=${encodeURIComponent(String(firstCert.certificateNumber))}&token=${encodeURIComponent(String(firstCert.qrToken))}`
    );
    assert.equal(verifyRes.status, 200);
    assert.equal(verifyRes.json.verified, true);
    assert.equal(verifyRes.json.integrityMatch, true);
    assert.equal(verifyRes.json.tokenMatch, true);
    assert.ok(
      String(verifyRes.json.maskedChassisNumber).startsWith('XXXX') &&
        String(verifyRes.json.maskedChassisNumber).endsWith('XX'),
      'Chassis number must be masked with XXXX at start and XX at end'
    );
    assert.ok(
      String(verifyRes.json.maskedEngineNumber).startsWith('XXXX') &&
        String(verifyRes.json.maskedEngineNumber).endsWith('XX'),
      'Engine number must be masked with XXXX at start and XX at end'
    );
    assert.equal('idProofNumber' in verifyRes.json, false, 'Public verify must never expose ID proof number');
    console.log('✓ 8. Public QR verification, SHA-256 integrity, and XXXX...XX masking verified');

    // 9. Main Core Admin invalid & valid unlock, full registry, search, filter, and dashboard stats
    const badAdmin = await req('/api/auth/admin-unlock', {
      method: 'POST',
      body: { password: 'WrongAdminPassword' },
    });
    assert.equal(badAdmin.status, 401);

    const goodAdmin = await req('/api/auth/admin-unlock', {
      method: 'POST',
      body: { password: 'MainAdmin#2026Secure' },
    });
    assert.equal(goodAdmin.status, 200);
    const adminToken = String(goodAdmin.json.token);

    const fullRegistry = await req('/api/admin/certificates', { token: adminToken });
    assert.equal(fullRegistry.status, 200);
    assert.equal(fullRegistry.json.total, 7, 'Main Core Admin should view all 7 certificates');

    const searchRes = await req(
      `/api/admin/certificates?search=${encodeURIComponent(String(firstCert.certificateNumber))}&status=ACTIVE`,
      { token: adminToken }
    );
    assert.equal(searchRes.status, 200);
    assert.equal(searchRes.json.total, 1, 'Admin search + status filter should locate exact certificate');

    const statsRes = await req('/api/admin/stats', { token: adminToken });
    assert.equal(statsRes.status, 200);
    assert.equal(statsRes.json.totalCertificates, 7);
    assert.equal(statsRes.json.activeCertificates, 7);
    console.log('✓ 9. Main Core Admin unlock, full registry, search/filter, and KPI stats verified');

    // 10. Protected Edit (preserves history, updates hash & QR token)
    const badEdit = await req(`/api/admin/certificates/${certIds[0]}`, {
      method: 'PUT',
      token: adminToken,
      body: {
        protectedPassword: 'WrongProtectedPassword',
        reason: 'Correcting spelling typo',
        updates: { ownerName: 'Updated Owner 1' },
      },
    });
    assert.equal(badEdit.status, 403);

    const goodEdit = await req(`/api/admin/certificates/${certIds[0]}`, {
      method: 'PUT',
      token: adminToken,
      body: {
        protectedPassword: 'ProtectedAction#2026',
        reason: 'Correcting owner name per RC copy',
        updates: { ownerName: 'Updated Owner 1' },
      },
    });
    assert.equal(goodEdit.status, 200);
    const editedCert = goodEdit.json.certificate as Record<string, unknown>;
    assert.equal(editedCert.version, 2);
    assert.notEqual(editedCert.canonicalHash, firstCert.canonicalHash);
    assert.notEqual(editedCert.qrToken, firstCert.qrToken);
    assert.equal((editedCert.versionHistory as unknown[]).length, 1);
    console.log('✓ 10. Protected edit (version history preserved, SHA-256 & QR token rotated) verified');

    // 11. Protected Cancel, Soft Delete, Restore & Permanent Delete (with non-reuse of numbers)
    const cancelRes = await req(`/api/admin/certificates/${certIds[1]}/cancel`, {
      method: 'POST',
      token: adminToken,
      body: {
        protectedPassword: 'ProtectedAction#2026',
        reason: 'Duplicate chassis submission cancelled by authority',
      },
    });
    assert.equal(cancelRes.status, 200);
    assert.equal((cancelRes.json.certificate as Record<string, unknown>).status, 'CANCELLED');

    const softDel = await req(`/api/admin/certificates/${certIds[2]}`, {
      method: 'DELETE',
      token: adminToken,
      body: {
        deletePassword: 'ProtectedAction#2026',
        reason: 'Test soft deletion with recovery support',
        permanent: false,
      },
    });
    assert.equal(softDel.status, 200);
    assert.equal(softDel.json.permanent, false);

    // Restore soft-deleted record
    const restoreSoft = await req(`/api/admin/certificates/${certIds[2]}/restore`, {
      method: 'POST',
      token: adminToken,
      body: {
        protectedPassword: 'ProtectedAction#2026',
        reason: 'Verifying soft-delete restoration safeguard',
      },
    });
    assert.equal(restoreSoft.status, 200);
    assert.equal((restoreSoft.json.certificate as Record<string, unknown>).status, 'ACTIVE');

    // Permanent delete requires exact phrase + protected delete password and never frees reserved numbers
    const badPermPhrase = await req(`/api/admin/certificates/${certIds[3]}`, {
      method: 'DELETE',
      token: adminToken,
      body: {
        deletePassword: 'ProtectedAction#2026',
        reason: 'Testing permanent deletion confirmation phrase',
        permanent: true,
        confirmPhrase: 'DELETE',
      },
    });
    assert.equal(badPermPhrase.status, 400);

    const deletedCertSnapshot = createdList[3].json.certificate as Record<string, unknown>;
    const permDel = await req(`/api/admin/certificates/${certIds[3]}`, {
      method: 'DELETE',
      token: adminToken,
      body: {
        deletePassword: 'ProtectedAction#2026',
        reason: 'Authorized permanent purge with safety backup',
        permanent: true,
        confirmPhrase: 'PERMANENT DELETE',
      },
    });
    assert.equal(permDel.status, 200);
    assert.equal(permDel.json.permanent, true);
    assert.ok(typeof permDel.json.safetyBackupId === 'string', 'Permanent delete must create safety backup');

    // Verify deleted certificate number can NEVER be reused when creating a new certificate
    const reuseAttempt = await req('/api/certificates', {
      method: 'POST',
      token: adminToken,
      headers: { 'Idempotency-Key': 'reuse_deleted_number_test' },
      body: {
        ...makePayload(9),
        certificateNumber: String(deletedCertSnapshot.certificateNumber),
        scrappingRegNumber: String(deletedCertSnapshot.scrappingRegNumber),
      },
    });
    assert.equal(reuseAttempt.status, 201);
    const reissuedCert = reuseAttempt.json.certificate as Record<string, unknown>;
    assert.notEqual(
      reissuedCert.certificateNumber,
      deletedCertSnapshot.certificateNumber,
      'Deleted certificate number must remain permanently reserved and never be reused'
    );
    assert.notEqual(
      reissuedCert.scrappingRegNumber,
      deletedCertSnapshot.scrappingRegNumber,
      'Deleted scrapping registration number must remain permanently reserved and never be reused'
    );
    console.log('✓ 11. Protected cancel, soft-delete, restore, permanent purge & number non-reuse verified');

    // 12. Backup creation, JSON download with SHA-256 header, and Restore Dry-Run
    const bkp = await req('/api/admin/backups/create', { method: 'POST', token: adminToken });
    assert.equal(bkp.status, 201);
    const backupId = String((bkp.json.backup as Record<string, unknown>).id);
    const backupChecksum = String((bkp.json.backup as Record<string, unknown>).sha256Checksum);

    const downloadRes = await fetch(`${baseUrl}/api/admin/backups/${backupId}/download`, {
      headers: { Authorization: `Bearer ${adminToken}`, 'X-Requested-With': 'XMLHttpRequest' },
    });
    assert.equal(downloadRes.status, 200);
    assert.equal(downloadRes.headers.get('x-backup-sha256'), backupChecksum);

    const dryRun = await req(`/api/admin/backups/${backupId}/dry-run`, {
      method: 'POST',
      token: adminToken,
    });
    assert.equal(dryRun.status, 200);
    assert.equal((dryRun.json.dryRun as Record<string, unknown>).checksumValid, true);
    console.log('✓ 12. Verified backup snapshot, JSON checksum export & SHA-256 restore dry-run verified');

    // 13. Official PDF & QR Code generation verification
    const { buildCertificatePdfDoc } = await import('../src/lib/pdfGenerator.js');
    const pdfBuilt = await buildCertificatePdfDoc(editedCert as never, {
      customDomain: 'https://parivahan-certificate-fresh.vercel.app',
      authorizedSignatory: 'Authorized RVSF Officer',
      signatoryDesignation: 'Facility Compliance Head',
    });
    const pdfBytes = Buffer.from(pdfBuilt.doc.output('arraybuffer'));
    assert.ok(pdfBytes.subarray(0, 5).toString('utf8') === '%PDF-', 'Generated file must be a valid PDF stream');
    assert.ok(pdfBytes.length > 5000, 'Generated PDF must contain full layout and embedded QR image');
    assert.ok(
      pdfBuilt.verifyUrl.startsWith('https://parivahan-certificate-fresh.vercel.app/verify?certificateNumber='),
      'QR verification URL must use configured custom production domain'
    );
    console.log(`✓ 13. Official PDF (${pdfBytes.length} bytes) & QR verification URL generation verified`);

    // 14. Password rotation & immediate old-session invalidation
    const rotate = await req('/api/admin/rotate-passwords', {
      method: 'POST',
      token: adminToken,
      body: {
        currentMainPassword: 'MainAdmin#2026Secure',
        newMakerPassword: 'NewMakerPassword#2027',
      },
    });
    assert.equal(rotate.status, 200);
    const oldMakerCheck = await req('/api/certificates/recent', { token: makerToken });
    assert.equal(oldMakerCheck.status, 401, 'Old Maker token must be immediately invalidated after password rotation');
    const newAdminToken = String(rotate.json.token);
    const logs = await req('/api/admin/audit-logs', { token: newAdminToken });
    assert.equal(logs.status, 200);
    assert.ok((logs.json.logs as unknown[]).length >= 12, 'Audit logs must capture all operations');
    console.log('✓ 14. Password rotation, immediate session invalidation, and audit log generation verified');

    // 15. Full Backup Restore & Reserved-Number Preservation (Staging Isolation)
    const beforeRestoreExtra = await req('/api/certificates', {
      method: 'POST',
      token: newAdminToken,
      headers: { 'Idempotency-Key': 'post_backup_extra_cert' },
      body: makePayload(8),
    });
    assert.equal(beforeRestoreExtra.status, 201);
    const extraCert = beforeRestoreExtra.json.certificate as Record<string, unknown>;

    const preRestoreDryRun = await req(`/api/admin/backups/${backupId}/dry-run`, {
      method: 'POST',
      token: newAdminToken,
    });
    assert.equal(preRestoreDryRun.status, 200);
    assert.equal((preRestoreDryRun.json.dryRun as Record<string, unknown>).certificatesOnlyInCurrent, 1);

    const execRestore = await req(`/api/admin/backups/${backupId}/restore`, {
      method: 'POST',
      token: newAdminToken,
      body: {
        protectedPassword: 'ProtectedAction#2026',
        confirmPhrase: 'CONFIRM RESTORE',
      },
    });
    assert.equal(execRestore.status, 200);
    assert.equal(execRestore.json.success, true);
    assert.ok(typeof execRestore.json.safetyBackupId === 'string', 'Restore must create PRE_RESTORE_SAFETY snapshot');

    const postRestoreRegistry = await req('/api/admin/certificates', { token: newAdminToken });
    assert.equal(postRestoreRegistry.status, 200);
    assert.equal(
      postRestoreRegistry.json.total,
      Number((preRestoreDryRun.json.dryRun as Record<string, unknown>).snapshotCertificateCount),
      'Registry count must match restored snapshot count'
    );

    // Ensure the superseded certificate's numbers remain permanently reserved after restore
    const reusePostRestore = await req('/api/certificates', {
      method: 'POST',
      token: newAdminToken,
      headers: { 'Idempotency-Key': 'reuse_after_restore_test' },
      body: {
        ...makePayload(10),
        certificateNumber: String(extraCert.certificateNumber),
        scrappingRegNumber: String(extraCert.scrappingRegNumber),
      },
    });
    assert.equal(reusePostRestore.status, 201);
    const reissuedPostRestore = reusePostRestore.json.certificate as Record<string, unknown>;
    assert.notEqual(reissuedPostRestore.certificateNumber, extraCert.certificateNumber);
    assert.notEqual(reissuedPostRestore.scrappingRegNumber, extraCert.scrappingRegNumber);
    console.log('✓ 15. End-to-end backup restore, safety backup creation & reserved-number union verified');

    // 16. Isolated FirestoreRestStore Spark-Hardening & Multi-Chunk Gzip Backup/Restore Test (Local Mock HTTP)
    await runMockFirestoreSparkTests();
    console.log(
      '✓ 16. FirestoreRestStore Spark queries (:runQuery, :runAggregationQuery COUNT), PEM normalization & multi-chunk gzip backup/restore verified'
    );

    // 17. Rate Limiting (429 Lockout), CSRF Protection (403) & HttpOnly/Secure/SameSite Cookie Flags
    await runSecurityControlsTests(baseUrl);
    console.log(
      '✓ 17. Login rate limiting (429 lockout) and CSRF guard (403) verified'
    );

    // 18. Env-Var Auth (user-pscrappers + salted scrypt hashes + cookie flags + env password rotation session invalidation)
    await runEnvManagedAuthTests();
    console.log(
      '✓ 18. Env-managed auth (user-pscrappers, salted scrypt env hashes, HttpOnly/Secure/SameSite cookies, bootstrap lock, zero secret leak, instant rotation invalidation) verified'
    );

    // 19. Vercel Production Firestore Safety Guard (VERCEL=1 refuses ephemeral memory fallback)
    await runProductionGuardTests();
    console.log(
      '✓ 19. Production Vercel guard (VERCEL=1 refuses ephemeral memory when Firestore env vars missing) verified'
    );

    console.log('\nALL 19 ISOLATED STAGING, AUTH, SPARK-FIRESTORE, BACKUP/RESTORE, PDF & SECURITY CHECKS PASSED.\n');
  } finally {
    await new Promise<void>((resolve) => server.close(() => resolve()));
  }
}

async function runMockFirestoreSparkTests(): Promise<void> {
  const crypto = await import('node:crypto');
  const {
    FirestoreRestStore,
    decodeBackupPayloadChunks,
    encodeBackupPayloadChunks,
    normalizePrivateKey,
  } = await import('../src/server/store.js');

  // Generate an ephemeral RSA keypair strictly at runtime (zero static credentials)
  const { privateKey } = crypto.generateKeyPairSync('rsa', {
    modulusLength: 2048,
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
    publicKeyEncoding: { type: 'spki', format: 'pem' },
  });

  // Verify quoted + escaped-\n PEM normalization (common Vercel paste format)
  const quotedEscapedKey = `"${privateKey.replace(/\n/g, '\\n')}"`;
  assert.equal(normalizePrivateKey(quotedEscapedKey), privateKey.trim());

  // Verify gzip chunk encoding/decoding round-trip with small chunk size
  const sampleJson = JSON.stringify({ rows: Array.from({ length: 40 }, (_, i) => ({ i, text: `row-${i}-${'x'.repeat(80)}` })) });
  const encoded = encodeBackupPayloadChunks(sampleJson, 200);
  assert.ok(encoded.chunks.length >= 2, 'Expected multiple chunks when maxChunkChars is 200');
  assert.equal(decodeBackupPayloadChunks(encoded.chunks), sampleJson);

  // Build an in-memory mock Firestore REST + OAuth2 HTTP server
  type MockDoc = { name: string; fields: Record<string, unknown> };
  const collections = new Map<string, Map<string, MockDoc>>();
  const getCol = (col: string): Map<string, MockDoc> => {
    let map = collections.get(col);
    if (!map) {
      map = new Map<string, MockDoc>();
      collections.set(col, map);
    }
    return map;
  };
  const extractStrField = (doc: MockDoc, field: string): string => {
    const val = doc.fields[field] as { stringValue?: string } | undefined;
    return val?.stringValue ?? '';
  };

  let runQueryCount = 0;
  let runAggregationCount = 0;
  let listCollectionCount = 0;
  const docPrefix = '/v1/projects/crm-certificates/databases/(default)/documents';

  const mockServer = http.createServer(async (req, res) => {
    const chunks: Buffer[] = [];
    for await (const c of req) chunks.push(c as Buffer);
    const rawBody = Buffer.concat(chunks).toString('utf8');
    const url = new URL(req.url || '/', 'http://127.0.0.1');

    if (url.pathname === '/oauth2/token' && req.method === 'POST') {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ access_token: 'mock-access-token', expires_in: 3600 }));
      return;
    }

    if (req.headers.authorization !== 'Bearer mock-access-token') {
      res.writeHead(401, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Unauthorized' }));
      return;
    }

    if (url.pathname === `${docPrefix}:runQuery` && req.method === 'POST') {
      runQueryCount++;
      const body = JSON.parse(rawBody) as {
        structuredQuery: {
          from: Array<{ collectionId: string }>;
          where?: { fieldFilter?: { field: { fieldPath: string }; value: { stringValue: string } } };
          orderBy?: Array<{ field: { fieldPath: string }; direction: string }>;
          limit?: number;
        };
      };
      const colId = body.structuredQuery.from[0].collectionId;
      let docs = Array.from(getCol(colId).values());
      const filter = body.structuredQuery.where?.fieldFilter;
      if (filter) {
        docs = docs.filter((d) => extractStrField(d, filter.field.fieldPath) === filter.value.stringValue);
      }
      const order = body.structuredQuery.orderBy?.[0];
      if (order) {
        docs.sort((a, b) => {
          const av = extractStrField(a, order.field.fieldPath);
          const bv = extractStrField(b, order.field.fieldPath);
          return order.direction === 'DESCENDING' ? bv.localeCompare(av) : av.localeCompare(bv);
        });
      }
      if (typeof body.structuredQuery.limit === 'number') {
        docs = docs.slice(0, body.structuredQuery.limit);
      }
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify(docs.map((document) => ({ document }))));
      return;
    }

    if (url.pathname === `${docPrefix}:runAggregationQuery` && req.method === 'POST') {
      runAggregationCount++;
      const body = JSON.parse(rawBody) as {
        structuredAggregationQuery: { structuredQuery: { from: Array<{ collectionId: string }> } };
      };
      const colId = body.structuredAggregationQuery.structuredQuery.from[0].collectionId;
      const count = getCol(colId).size;
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify([{ result: { aggregateFields: { total: { integerValue: String(count) } } } }]));
      return;
    }

    if (url.pathname === `${docPrefix}:commit` && req.method === 'POST') {
      const body = JSON.parse(rawBody) as {
        writes: Array<{
          update?: { name: string; fields: Record<string, unknown> };
          delete?: string;
          currentDocument?: { exists: boolean };
        }>;
      };
      // Check preconditions first
      for (const w of body.writes) {
        if (w.update && w.currentDocument?.exists === false) {
          const rel = w.update.name.replace(/^projects\/crm-certificates\/databases\/\(default\)\/documents\//, '');
          const [col, id] = rel.split('/');
          if (getCol(col).has(id)) {
            res.writeHead(409, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ error: { status: 'ALREADY_EXISTS' } }));
            return;
          }
        }
      }
      for (const w of body.writes) {
        if (w.update) {
          const rel = w.update.name.replace(/^projects\/crm-certificates\/databases\/\(default\)\/documents\//, '');
          const [col, id] = rel.split('/');
          getCol(col).set(id, { name: w.update.name, fields: w.update.fields });
        } else if (w.delete) {
          const rel = w.delete.replace(/^projects\/crm-certificates\/databases\/\(default\)\/documents\//, '');
          const [col, id] = rel.split('/');
          getCol(col).delete(id);
        }
      }
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ writeResults: body.writes.map(() => ({})) }));
      return;
    }

    if (url.pathname.startsWith(`${docPrefix}/`)) {
      const rest = url.pathname.slice(`${docPrefix}/`.length);
      const parts = rest.split('/').map(decodeURIComponent);
      if (parts.length === 1 && req.method === 'GET') {
        listCollectionCount++;
        const docs = Array.from(getCol(parts[0]).values());
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ documents: docs }));
        return;
      }
      if (parts.length === 2) {
        const [col, id] = parts;
        if (req.method === 'GET') {
          const doc = collections.get(col)?.get(id);
          if (!doc) {
            res.writeHead(404, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ error: 'Not found' }));
            return;
          }
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify(doc));
          return;
        }
        if (req.method === 'PATCH') {
          const body = JSON.parse(rawBody) as { fields: Record<string, unknown> };
          getCol(col).set(id, {
            name: `projects/crm-certificates/databases/(default)/documents/${col}/${id}`,
            fields: body.fields,
          });
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ ok: true }));
          return;
        }
        if (req.method === 'DELETE') {
          getCol(col).delete(id);
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({}));
          return;
        }
      }
    }

    res.writeHead(404, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ error: `Unhandled mock route: ${req.method} ${url.pathname}` }));
  });

  await new Promise<void>((resolve) => mockServer.listen(0, '127.0.0.1', resolve));
  const addr = mockServer.address();
  if (!addr || typeof addr === 'string') throw new Error('Failed to start mock Firestore server');
  const mockOrigin = `http://127.0.0.1:${addr.port}`;

  try {
    const fsStore = new FirestoreRestStore({
      projectId: 'crm-certificates',
      databaseId: '(default)',
      clientEmail: 'test-sa@crm-certificates.iam.gserviceaccount.com',
      privateKey: quotedEscapedKey,
      apiOrigin: mockOrigin,
      tokenUrl: `${mockOrigin}/oauth2/token`,
      maxChunkChars: 300, // force multi-chunk gzipped backups even with small test data
    });

    // 1. Read-only ping works on empty DB (0 writes)
    const ping = await fsStore.ping();
    assert.equal(ping.ok, true);
    assert.equal(collections.size, 0, 'Read-only ping must not write any documents');

    // 2. Create 6 certificates atomically
    const makeCert = (i: number) => ({
      id: `cert_mock_${i}`,
      certificateNumber: `PS/26/R100000${i}`,
      scrappingRegNumber: `REG-C20000${i}`,
      status: 'ACTIVE' as const,
      version: 1,
      issueDate: '2026-11-25',
      handoverDate: '2026-11-24',
      ownerName: `Spark Test Owner ${i}`,
      ownerAddress: `Plot ${i}, Industrial Area, Gurugram`,
      idProofType: '' as const,
      idProofNumber: '',
      vehicleRegNumber: `HR26AB100${i}`,
      make: 'Hero MotoCorp',
      model: 'Splendor',
      manufactureYear: 2011,
      chassisNumber: `MAT600000000000${i}`,
      engineNumber: `475IDI00000${i}`,
      unhideChassisEngine: false,
      rtoAuthority: 'RTO Gurugram',
      facilityName: 'Parivahan Scrappers Authorized RVSF',
      facilityRvsfCode: 'RVSF-IND-2026-001',
      facilityAddress: 'Industrial Area Phase II',
      remarks: 'Mock Spark test record',
      canonicalHash: `hash_${i}`,
      qrToken: `token_${i}`,
      createdAt: `2026-11-25T01:0${i}:00.000Z`,
      updatedAt: `2026-11-25T01:0${i}:00.000Z`,
      createdBy: 'maker_operator',
      createdByRole: 'maker' as const,
      versionHistory: [],
      driveSyncStatus: 'NOT_CONFIGURED' as const,
    });

    for (let i = 1; i <= 6; i++) {
      await fsStore.createCertificateAtomic({
        certificate: makeCert(i),
        idempotencyKey: `fs_idemp_${i}`,
        auditLog: {
          id: `aud_mock_${i}`,
          timestamp: `2026-11-25T01:0${i}:00.000Z`,
          actor: 'maker_operator',
          actorRole: 'maker',
          action: 'CERTIFICATE_CREATED',
          certificateId: `cert_mock_${i}`,
          certificateNumber: `PS/26/R100000${i}`,
        },
      });
    }

    // 3. Verify Maker recent-5, audit logs, and reserved counts use :runQuery and :runAggregationQuery (NOT listCollection!)
    const listBefore = listCollectionCount;
    const recent = await fsStore.getRecentActiveCertificates(5);
    assert.equal(recent.length, 5);
    assert.equal(recent[0].id, 'cert_mock_6');
    const logs = await fsStore.getAuditLogs(10);
    assert.equal(logs.length, 6);
    const counts = await fsStore.getReservedCounts();
    assert.equal(counts.certCount, 6);
    assert.equal(counts.regCount, 6);
    assert.equal(listCollectionCount, listBefore, 'Maker recent, audit logs & reserved counts must NOT scan full collections');
    assert.ok(runQueryCount >= 2, 'Expected :runQuery calls for recent certificates and audit logs');
    assert.ok(runAggregationCount >= 2, 'Expected :runAggregationQuery COUNT calls for reserved numbers');

    // 4. Verify multi-chunk gzipped backup stores metadata-only in database_backups and chunks in database_backup_chunks
    const snap = await fsStore.createBackup('Main Core Admin', 'MANUAL');
    const rawMetaDoc = getCol('database_backups').get(snap.id);
    assert.ok(rawMetaDoc, 'Backup metadata document must exist');
    assert.equal('payloadJson' in rawMetaDoc.fields, false, 'Metadata doc must NOT embed raw payloadJson');
    assert.ok(getCol('database_backup_chunks').size >= 2, 'Expected multiple gzipped backup chunks in database_backup_chunks');

    const listedBackups = await fsStore.listBackups();
    assert.equal(listedBackups.length, 1);
    assert.equal(listedBackups[0].id, snap.id);

    const downloaded = await fsStore.getBackupDownload(snap.id);
    assert.equal(downloaded.sha256Checksum, snap.sha256Checksum);
    const parsedDownload = JSON.parse(downloaded.payloadJson) as { certificates: unknown[] };
    assert.equal(parsedDownload.certificates.length, 6);

    // 5. Add a 7th certificate after backup, run dry-run, execute restore, and verify rollback + reserved-number union
    await fsStore.createCertificateAtomic({
      certificate: makeCert(7),
      idempotencyKey: 'fs_idemp_7',
      auditLog: {
        id: 'aud_mock_7',
        timestamp: '2026-11-25T01:07:00.000Z',
        actor: 'maker_operator',
        actorRole: 'maker',
        action: 'CERTIFICATE_CREATED',
        certificateId: 'cert_mock_7',
        certificateNumber: 'PS/26/R1000007',
      },
    });
    assert.equal(getCol('certificates').size, 7);

    const dryRun = await fsStore.dryRunRestoreBackup(snap.id);
    assert.equal(dryRun.checksumValid, true);
    assert.equal(dryRun.certificatesOnlyInCurrent, 1);

    const restored = await fsStore.restoreBackup(snap.id, 'Main Core Admin');
    assert.equal(restored.restoredCount, 6);
    assert.ok(restored.safetyBackupId.startsWith('bkp_'));
    assert.equal(getCol('certificates').size, 6, 'Superseded 7th certificate must be removed on restore');
    assert.equal(
      await fsStore.isCertNumberReserved('PS/26/R1000007'),
      true,
      'Superseded certificate number must remain permanently reserved after Firestore restore'
    );
    assert.equal(
      await fsStore.isScrappingRegReserved('REG-C200007'),
      true,
      'Superseded registration number must remain permanently reserved after Firestore restore'
    );
  } finally {
    await new Promise<void>((resolve) => mockServer.close(() => resolve()));
  }
}

async function runEnvManagedAuthTests(): Promise<void> {
  const crypto = await import('node:crypto');
  const { hashPassword } = await import('../src/server/crypto.js');
  const { resetStoreForTesting } = await import('../src/server/store.js');

  const savedEnv = {
    ADMIN_USERNAME: process.env.ADMIN_USERNAME,
    ADMIN_PASSWORD: process.env.ADMIN_PASSWORD,
    MAIN_ADMIN_PASSWORD: process.env.MAIN_ADMIN_PASSWORD,
    ADMIN_PROTECTED_PASSWORD: process.env.ADMIN_PROTECTED_PASSWORD,
    ADMIN_DELETE_PASSWORD: process.env.ADMIN_DELETE_PASSWORD,
    ADMIN_SESSION_SECRET: process.env.ADMIN_SESSION_SECRET,
  };

  // Generate ephemeral runtime-only test credentials (never stored or hardcoded)
  const makerPass = `Maker_${crypto.randomBytes(8).toString('hex')}`;
  const adminPass = `Admin_${crypto.randomBytes(8).toString('hex')}`;
  const protectedPass = `Prot_${crypto.randomBytes(8).toString('hex')}`;
  const sessionSecret = crypto.randomBytes(32).toString('hex');

  process.env.ADMIN_USERNAME = 'user-pscrappers';
  process.env.ADMIN_PASSWORD = hashPassword(makerPass);
  process.env.MAIN_ADMIN_PASSWORD = hashPassword(adminPass);
  process.env.ADMIN_PROTECTED_PASSWORD = hashPassword(protectedPass);
  process.env.ADMIN_DELETE_PASSWORD = hashPassword(protectedPass);
  process.env.ADMIN_SESSION_SECRET = sessionSecret;
  resetStoreForTesting();

  const envApp = createApiApp();
  const envServer = http.createServer(envApp);
  await new Promise<void>((resolve) => envServer.listen(0, '127.0.0.1', resolve));
  const addr = envServer.address();
  if (!addr || typeof addr === 'string') throw new Error('Failed to bind env auth test server');
  const origin = `http://127.0.0.1:${addr.port}`;

  try {
    // Status reports envConfigured=true, requiresBootstrap=false, and leaks zero secrets
    const statusRes = await fetch(`${origin}/api/auth/status`);
    assert.equal(statusRes.status, 200);
    const statusText = await statusRes.text();
    assert.equal(statusText.includes(makerPass), false);
    assert.equal(statusText.includes(adminPass), false);
    assert.equal(statusText.includes(sessionSecret), false);
    assert.equal(statusText.includes('scrypt$'), false);
    const statusJson = JSON.parse(statusText) as Record<string, unknown>;
    assert.equal(statusJson.envConfigured, true);
    assert.equal(statusJson.requiresBootstrap, false);

    // Bootstrap is strictly blocked when env passwords are set
    const bootRes = await fetch(`${origin}/api/auth/bootstrap`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-Requested-With': 'XMLHttpRequest' },
      body: JSON.stringify({
        makerUsername: 'attacker',
        makerPassword: 'Password1234',
        mainAdminPassword: 'Password1234',
        protectedPassword: 'Password1234',
      }),
    });
    assert.equal(bootRes.status, 403);

    // Maker login succeeds with user-pscrappers and salted scrypt env hash
    const makerRes = await fetch(`${origin}/api/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-Requested-With': 'XMLHttpRequest' },
      body: JSON.stringify({ username: 'user-pscrappers', password: makerPass }),
    });
    assert.equal(makerRes.status, 200);
    const setCookieHeader = makerRes.headers.get('set-cookie') || '';
    assert.ok(setCookieHeader.includes('HttpOnly'), 'Session cookie must set HttpOnly');
    assert.ok(setCookieHeader.includes('Secure'), 'Session cookie must set Secure');
    assert.ok(setCookieHeader.includes('SameSite=None'), 'Session cookie must set SameSite=None');
    const makerJson = (await makerRes.json()) as { token: string; session: { username: string; role: string } };
    assert.equal(makerJson.session.username, 'user-pscrappers');
    assert.equal(makerJson.session.role, 'maker');

    // Maker is blocked from Admin routes
    const forbiddenAdmin = await fetch(`${origin}/api/admin/certificates`, {
      headers: { Authorization: `Bearer ${makerJson.token}` },
    });
    assert.equal(forbiddenAdmin.status, 403);

    // Main Core Admin unlock succeeds with separate env password
    const adminRes = await fetch(`${origin}/api/auth/admin-unlock`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-Requested-With': 'XMLHttpRequest' },
      body: JSON.stringify({ password: adminPass }),
    });
    assert.equal(adminRes.status, 200);
    const adminJson = (await adminRes.json()) as { token: string };

    // Rotating ADMIN_PASSWORD in env immediately invalidates previously issued tokens
    process.env.ADMIN_PASSWORD = hashPassword(`Rotated_${crypto.randomBytes(8).toString('hex')}`);
    const invalidatedMaker = await fetch(`${origin}/api/certificates/recent`, {
      headers: { Authorization: `Bearer ${makerJson.token}` },
    });
    assert.equal(invalidatedMaker.status, 401, 'Rotating env password must invalidate prior Maker sessions');
    const invalidatedAdmin = await fetch(`${origin}/api/admin/stats`, {
      headers: { Authorization: `Bearer ${adminJson.token}` },
    });
    assert.equal(invalidatedAdmin.status, 401, 'Rotating env password must invalidate prior Admin sessions');
  } finally {
    await new Promise<void>((resolve) => envServer.close(() => resolve()));
    for (const [k, v] of Object.entries(savedEnv)) {
      if (v === undefined) delete process.env[k];
      else process.env[k] = v;
    }
    resetStoreForTesting();
  }
}

async function runSecurityControlsTests(baseUrl: string): Promise<void> {
  // 1. CSRF rejection when POST lacks X-Requested-With and has mismatched Origin
  const csrfBlocked = await fetch(`${baseUrl}/api/auth/login`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Origin: 'https://untrusted-site.example',
    },
    body: JSON.stringify({ username: 'user-pscrappers', password: 'InvalidPassword1' }),
  });
  assert.equal(csrfBlocked.status, 403, 'Cross-site POST without X-Requested-With must be rejected with 403');

  // 2. Login rate limiting triggers HTTP 429 lockout after 5 consecutive failures
  const rateTestUser = 'ratelimit-probe-user';
  for (let i = 0; i < 5; i++) {
    const attempt = await fetch(`${baseUrl}/api/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-Requested-With': 'XMLHttpRequest' },
      body: JSON.stringify({ username: rateTestUser, password: `WrongPass_${i}` }),
    });
    assert.equal(attempt.status, 401);
  }
  const lockedAttempt = await fetch(`${baseUrl}/api/auth/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'X-Requested-With': 'XMLHttpRequest' },
    body: JSON.stringify({ username: rateTestUser, password: 'WrongPass_6' }),
  });
  assert.equal(lockedAttempt.status, 429, '6th failed login attempt must trigger HTTP 429 rate-limit lockout');
}

async function runProductionGuardTests(): Promise<void> {
  const { resetStoreForTesting } = await import('../src/server/store.js');
  const saved = {
    VERCEL: process.env.VERCEL,
    FIREBASE_PROJECT_ID: process.env.FIREBASE_PROJECT_ID,
    FIREBASE_CLIENT_EMAIL: process.env.FIREBASE_CLIENT_EMAIL,
    FIREBASE_PRIVATE_KEY: process.env.FIREBASE_PRIVATE_KEY,
  };

  process.env.VERCEL = '1';
  delete process.env.FIREBASE_PROJECT_ID;
  delete process.env.FIREBASE_CLIENT_EMAIL;
  delete process.env.FIREBASE_PRIVATE_KEY;
  resetStoreForTesting();

  const prodApp = createApiApp();
  const prodServer = http.createServer(prodApp);
  await new Promise<void>((resolve) => prodServer.listen(0, '127.0.0.1', resolve));
  const addr = prodServer.address();
  if (!addr || typeof addr === 'string') throw new Error('Failed to bind prod guard server');
  const origin = `http://127.0.0.1:${addr.port}`;

  try {
    const health = await fetch(`${origin}/api/health`);
    assert.equal(health.status, 503);
    const healthJson = (await health.json()) as {
      storageMode: string;
      firestoreConnected: boolean;
      missingFirestoreEnvVars: string[];
    };
    assert.equal(healthJson.storageMode, 'firestore_unconfigured');
    assert.equal(healthJson.firestoreConnected, false);
    assert.deepEqual(healthJson.missingFirestoreEnvVars, [
      'FIREBASE_PROJECT_ID',
      'FIREBASE_CLIENT_EMAIL',
      'FIREBASE_PRIVATE_KEY',
    ]);
  } finally {
    await new Promise<void>((resolve) => prodServer.close(() => resolve()));
    for (const [k, v] of Object.entries(saved)) {
      if (v === undefined) delete process.env[k];
      else process.env[k] = v;
    }
    resetStoreForTesting();
  }
}

runTests().catch((err) => {
  console.error('Verification failed:', err);
  process.exit(1);
});
