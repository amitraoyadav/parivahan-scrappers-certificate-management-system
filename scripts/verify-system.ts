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
    // Note: RTO field is completely removed from new creations (idx 1..6 omit rtoAuthority; idx 7 tests backward compatibility if legacy rtoAuthority exists)
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
      ...(idx === 7 ? { rtoAuthority: 'Legacy RTO Gurugram (HR-26)' } : {}),
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

    // Permanent delete requires fresh Main Core Admin password + Protected Delete password + exact cert number + exact phrase
    const deletedCertSnapshot = createdList[3].json.certificate as Record<string, unknown>;
    const badPermPhrase = await req(`/api/admin/certificates/${certIds[3]}`, {
      method: 'DELETE',
      token: adminToken,
      body: {
        mainAdminPassword: 'MainAdmin#2026Secure',
        deletePassword: 'ProtectedAction#2026',
        confirmCertificateNumber: String(deletedCertSnapshot.certificateNumber),
        reason: 'Testing permanent deletion confirmation phrase',
        permanent: true,
        confirmPhrase: 'DELETE',
      },
    });
    assert.equal(badPermPhrase.status, 400);

    const missingMainPass = await req(`/api/admin/certificates/${certIds[3]}`, {
      method: 'DELETE',
      token: adminToken,
      body: {
        deletePassword: 'ProtectedAction#2026',
        confirmCertificateNumber: String(deletedCertSnapshot.certificateNumber),
        reason: 'Testing missing fresh Main Core Admin password',
        permanent: true,
        confirmPhrase: 'PERMANENT DELETE',
      },
    });
    assert.equal(missingMainPass.status, 403);

    const wrongCertNumber = await req(`/api/admin/certificates/${certIds[3]}`, {
      method: 'DELETE',
      token: adminToken,
      body: {
        mainAdminPassword: 'MainAdmin#2026Secure',
        deletePassword: 'ProtectedAction#2026',
        confirmCertificateNumber: 'PS/26/R0000000',
        reason: 'Testing mismatched certificate number confirmation',
        permanent: true,
        confirmPhrase: 'PERMANENT DELETE',
      },
    });
    assert.equal(wrongCertNumber.status, 400);

    const permDel = await req(`/api/admin/certificates/${certIds[3]}`, {
      method: 'DELETE',
      token: adminToken,
      body: {
        mainAdminPassword: 'MainAdmin#2026Secure',
        deletePassword: 'ProtectedAction#2026',
        confirmCertificateNumber: String(deletedCertSnapshot.certificateNumber),
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

    // 13. Official PDF & QR Code generation verification (exact certificate-number filename)
    const { buildCertificatePdfDoc, getCertificatePdfFilename } = await import('../src/lib/pdfGenerator.js');
    const pdfBuilt = await buildCertificatePdfDoc(editedCert as never, {
      customDomain: 'https://parivahan-certificate-fresh.vercel.app',
      authorizedSignatory: 'Authorized RVSF Officer',
      signatoryDesignation: 'Facility Compliance Head',
    });
    const expectedFileName = getCertificatePdfFilename(String(editedCert.certificateNumber));
    assert.match(expectedFileName, /^PS-26-R\d{7}\.pdf$/);
    assert.equal(
      pdfBuilt.fileName,
      expectedFileName,
      'PDF filename must strictly match certificate number (PS-26-Rxxxxxxx.pdf) with no vehicle reg suffix'
    );
    const pdfBytes = Buffer.from(pdfBuilt.doc.output('arraybuffer'));
    assert.ok(pdfBytes.subarray(0, 5).toString('utf8') === '%PDF-', 'Generated file must be a valid PDF stream');
    assert.ok(pdfBytes.length > 5000, 'Generated PDF must contain full layout and embedded QR image');
    assert.ok(
      pdfBuilt.verifyUrl.startsWith('https://parivahan-certificate-fresh.vercel.app/verify?certificateNumber='),
      'QR verification URL must use configured custom production domain'
    );
    console.log(
      `✓ 13. Official PDF (${pdfBytes.length} bytes, exact filename ${pdfBuilt.fileName}) & QR verification URL generation verified`
    );

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

    // 18. Firestore-Authoritative Precedence & One-Time Env Bootstrap (stale ADMIN_PASSWORD/ADMIN_USERNAME ignored once Firestore exists)
    await runEnvManagedAuthTests();
    console.log(
      '✓ 18. Single-source-of-truth Maker precedence (one-time env bootstrap, Firestore authoritative, stale ADMIN_PASSWORD/ADMIN_USERNAME ignored, rotation invalidates sessions) verified'
    );

    // 19. Vercel Production Firestore Safety Guard (VERCEL=1 refuses ephemeral memory fallback)
    await runProductionGuardTests();
    console.log(
      '✓ 19. Production Vercel guard (VERCEL=1 refuses ephemeral memory when Firestore env vars missing) verified'
    );

    // 20. Maker-Only Password Rotation (updates only makerPasswordHash; preserves pscrappers username & Main Core Admin password)
    await runMakerOnlyRotationTests();
    console.log(
      '✓ 20. Maker-only password rotation (/api/admin/rotate-maker-password) verified (pscrappers & Main Core Admin preserved, new Maker login succeeds)'
    );

    // 21. Maker Direct Edit & Password-Free Soft Delete, Legacy RTO SHA-256 Compatibility, Scope Isolation & Public Rejection
    await runMakerEditDeleteAndVerifyTests();
    console.log(
      '✓ 21. Maker edit & password-free soft-delete, RTO-free creation, legacy RTO SHA-256 compatibility, latest-5 isolation & public 401/404 checks verified'
    );

    // 22. Safe Auth Diagnostics (distinguishes username, password, missing creds, invalid hash format, Firebase error; zero secret leakage)
    await runAuthDiagnosticsTests();
    console.log(
      '✓ 22. Safe server-side auth diagnostics (INCORRECT_USERNAME, INCORRECT_PASSWORD, MISSING_FIRESTORE_CREDENTIALS, INVALID_PASSWORD_HASH_FORMAT, FIREBASE_CONNECTION_FAILURE; zero secret leak) verified'
    );

    // 23. Maker Session Cookie, Cross-Instance Signing, Next-Numbers Non-Consumption, Issuance, Logout Revocation & System Diagnostics
    await runMakerSessionAndNextNumbersTests();
    console.log(
      '✓ 23. Maker cookie session, serverless cross-instance signing, /api/certificates/next-numbers non-consumption, certificate issuance, PDF filename, logout revocation & secret-free diagnostics verified'
    );

    // 24. Optional Address & ID Proof PDF Layout (6 Scenarios), Issuing Facility Removal & Simplified Manufacturer List
    await runPdfOptionalFieldsAndManufacturersTests();
    console.log(
      '✓ 24. Optional Address/ID PDF layout (all 6 scenarios), Issuing Facility removal & simplified manufacturer list verified'
    );

    // 25. Two-Brand Certificate System (Parivahan Scrappers + PIN-Protected Scrap Route) & Remember Me Sessions
    await runTwoBrandScrapRouteAndRememberMeTests();
    console.log(
      '✓ 25. Two-brand issuance (Parivahan & Scrap Route), server-side PIN + rate limit, PDF branding isolation, QR verification, brand immutability & 30-day Remember Me verified'
    );

    // 26. Permanent Data Protection, Immutable Version History, Archive/Restore, Integrity Gate, Staging Backup Verification & Owner Export
    await runDataProtectionIntegrityAndRecoveryTests();
    console.log(
      '✓ 26. Permanent data protection (read-back verification, immutable v1 & append-only history, Maker archive-only, integrity-gated permanent delete, staging restore verification, owner JSON export & read-only integrity monitor) verified'
    );

    console.log('\nALL 26 ISOLATED STAGING, DATA PROTECTION, INTEGRITY, RECOVERY, SESSION, AUTH, SPARK-FIRESTORE, PDF, TWO-BRAND & SECURITY CHECKS PASSED.\n');
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

    // 1b. Atomic createCredentialsIfAbsent creates once and NEVER overwrites an existing valid doc
    const firstCreate = await fsStore.createCredentialsIfAbsent({
      makerUsername: 'pscrappers',
      makerPasswordHash: 'scrypt$00112233445566778899aabbccddeeff$' + 'a'.repeat(128),
      mainAdminPasswordHash: 'scrypt$00112233445566778899aabbccddeeff$' + 'b'.repeat(128),
      protectedPasswordHash: 'scrypt$00112233445566778899aabbccddeeff$' + 'c'.repeat(128),
      deletePasswordHash: 'scrypt$00112233445566778899aabbccddeeff$' + 'd'.repeat(128),
      sessionVersion: 1,
      bootstrappedAt: '2026-11-27T00:00:00.000Z',
      updatedAt: '2026-11-27T00:00:00.000Z',
    });
    assert.equal(firstCreate, true, 'First createCredentialsIfAbsent should succeed');

    const overwriteAttempt = await fsStore.createCredentialsIfAbsent({
      makerUsername: 'attacker_overwrite',
      makerPasswordHash: 'scrypt$ffeeddccbbaa99887766554433221100$' + 'f'.repeat(128),
      mainAdminPasswordHash: 'scrypt$ffeeddccbbaa99887766554433221100$' + 'f'.repeat(128),
      protectedPasswordHash: 'scrypt$ffeeddccbbaa99887766554433221100$' + 'f'.repeat(128),
      deletePasswordHash: 'scrypt$ffeeddccbbaa99887766554433221100$' + 'f'.repeat(128),
      sessionVersion: 99,
      bootstrappedAt: '2026-11-27T01:00:00.000Z',
      updatedAt: '2026-11-27T01:00:00.000Z',
    });
    assert.equal(overwriteAttempt, false, 'Second createCredentialsIfAbsent must never overwrite existing Firestore credentials');
    const keptCreds = await fsStore.getCredentials();
    assert.equal(keptCreds?.makerUsername, 'pscrappers', 'Existing Firestore credentials must remain intact');

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
  const makerPass = `Maker@${crypto.randomBytes(6).toString('hex')}`;
  const adminPass = `Admin@${crypto.randomBytes(6).toString('hex')}`;
  const protectedPass = `Prot@${crypto.randomBytes(6).toString('hex')}`;
  const sessionSecret = crypto.randomBytes(32).toString('hex');

  // Verify quoted salted scrypt env var AND omitted ADMIN_USERNAME fallback to user-pscrappers
  delete process.env.ADMIN_USERNAME;
  process.env.ADMIN_PASSWORD = `"${hashPassword(makerPass)}"`;
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

    // Maker login succeeds with user-pscrappers and quoted salted scrypt env hash (one-time bootstrap into Firestore)
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

    // Main Core Admin unlock succeeds with separate env password (bootstrapped into Firestore)
    const adminRes = await fetch(`${origin}/api/auth/admin-unlock`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-Requested-With': 'XMLHttpRequest' },
      body: JSON.stringify({ password: adminPass }),
    });
    assert.equal(adminRes.status, 200);
    const adminJson = (await adminRes.json()) as { token: string };

    // CRITICAL PRECEDENCE CHECK: Changing ADMIN_PASSWORD, ADMIN_USERNAME, AND MAIN_ADMIN_PASSWORD in env
    // AFTER Firestore credentials exist MUST NOT overwrite or override Firestore credentials for EITHER account!
    const staleEnvPassword = `StaleEnv@${crypto.randomBytes(6).toString('hex')}`;
    const staleAdminEnvPassword = `StaleAdmin@${crypto.randomBytes(6).toString('hex')}`;
    process.env.ADMIN_USERNAME = 'stale_wrong_username';
    process.env.ADMIN_PASSWORD = hashPassword(staleEnvPassword);
    process.env.MAIN_ADMIN_PASSWORD = hashPassword(staleAdminEnvPassword);

    // Existing Firestore Maker credentials (user-pscrappers + makerPass) STILL succeed!
    const stillValidMaker = await fetch(`${origin}/api/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-Requested-With': 'XMLHttpRequest' },
      body: JSON.stringify({ username: 'user-pscrappers', password: makerPass }),
    });
    assert.equal(
      stillValidMaker.status,
      200,
      'Firestore Maker credentials must remain authoritative even when stale ADMIN_PASSWORD/ADMIN_USERNAME env vars exist'
    );

    // Stale env Maker password MUST be rejected
    const staleRejected = await fetch(`${origin}/api/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-Requested-With': 'XMLHttpRequest' },
      body: JSON.stringify({ username: 'user-pscrappers', password: staleEnvPassword }),
    });
    assert.equal(staleRejected.status, 401, 'Stale env ADMIN_PASSWORD must not authenticate once Firestore credentials exist');

    // Existing Firestore Main Core Admin credentials STILL succeed and stale MAIN_ADMIN_PASSWORD is rejected!
    const stillValidAdmin = await fetch(`${origin}/api/auth/admin-unlock`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-Requested-With': 'XMLHttpRequest' },
      body: JSON.stringify({ password: adminPass }),
    });
    assert.equal(
      stillValidAdmin.status,
      200,
      'Firestore Main Core Admin credentials must remain authoritative even when stale MAIN_ADMIN_PASSWORD env var exists'
    );

    const staleAdminRejected = await fetch(`${origin}/api/auth/admin-unlock`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-Requested-With': 'XMLHttpRequest' },
      body: JSON.stringify({ password: staleAdminEnvPassword }),
    });
    assert.equal(
      staleAdminRejected.status,
      401,
      'Stale env MAIN_ADMIN_PASSWORD must not authenticate once Firestore credentials exist'
    );

    // Rotating Maker password via /api/admin/rotate-maker-password succeeds EVEN WITH stale env vars
    const rotatedMakerPass = `FreshMaker@${crypto.randomBytes(6).toString('hex')}`;
    const rotMaker = await fetch(`${origin}/api/admin/rotate-maker-password`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Requested-With': 'XMLHttpRequest',
        Authorization: `Bearer ${adminJson.token}`,
      },
      body: JSON.stringify({ currentMainPassword: adminPass, newMakerPassword: rotatedMakerPass }),
    });
    assert.equal(rotMaker.status, 200);
    const rotMakerJson = (await rotMaker.json()) as { token: string };

    const invalidatedMaker = await fetch(`${origin}/api/certificates/recent`, {
      headers: { Authorization: `Bearer ${makerJson.token}` },
    });
    assert.equal(invalidatedMaker.status, 401, 'Rotating Maker password in Firestore must invalidate prior Maker sessions');

    // Rotating Main Core Admin password via /api/admin/rotate-passwords succeeds EVEN WITH stale MAIN_ADMIN_PASSWORD in env
    const rotatedAdminPass = `FreshAdmin@${crypto.randomBytes(6).toString('hex')}`;
    const rotAdmin = await fetch(`${origin}/api/admin/rotate-passwords`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Requested-With': 'XMLHttpRequest',
        Authorization: `Bearer ${rotMakerJson.token}`,
      },
      body: JSON.stringify({ currentMainPassword: adminPass, newMainAdminPassword: rotatedAdminPass }),
    });
    assert.equal(rotAdmin.status, 200, 'Main Core Admin password rotation must update Firestore even if stale env vars exist');

    // Old Main Core Admin password fails; new Main Core Admin password succeeds + accesses settings + logout + re-login
    const oldAdminFails = await fetch(`${origin}/api/auth/admin-unlock`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-Requested-With': 'XMLHttpRequest' },
      body: JSON.stringify({ password: adminPass }),
    });
    assert.equal(oldAdminFails.status, 401);

    const newAdminLogin = await fetch(`${origin}/api/auth/admin-unlock`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-Requested-With': 'XMLHttpRequest' },
      body: JSON.stringify({ password: rotatedAdminPass }),
    });
    assert.equal(newAdminLogin.status, 200);
    const newAdminToken = ((await newAdminLogin.json()) as { token: string }).token;

    const settingsRes = await fetch(`${origin}/api/admin/settings`, {
      headers: { Authorization: `Bearer ${newAdminToken}` },
    });
    assert.equal(settingsRes.status, 200);

    const adminLogout = await fetch(`${origin}/api/auth/logout`, {
      method: 'POST',
      headers: { 'X-Requested-With': 'XMLHttpRequest', Authorization: `Bearer ${newAdminToken}` },
    });
    assert.equal(adminLogout.status, 200);

    const adminRelogin = await fetch(`${origin}/api/auth/admin-unlock`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-Requested-With': 'XMLHttpRequest' },
      body: JSON.stringify({ password: rotatedAdminPass }),
    });
    assert.equal(adminRelogin.status, 200, 'Main Core Admin re-login after logout must succeed');

    // Maker login with user-pscrappers + newly rotated password -> dashboard -> logout -> re-login
    const newMakerLogin = await fetch(`${origin}/api/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-Requested-With': 'XMLHttpRequest' },
      body: JSON.stringify({ username: 'user-pscrappers', password: rotatedMakerPass }),
    });
    assert.equal(newMakerLogin.status, 200, 'Login with newly rotated Firestore Maker password must succeed');
    const freshMakerToken = ((await newMakerLogin.json()) as { token: string }).token;

    const makerDash = await fetch(`${origin}/api/certificates/recent`, {
      headers: { Authorization: `Bearer ${freshMakerToken}` },
    });
    assert.equal(makerDash.status, 200);

    const makerLogout = await fetch(`${origin}/api/auth/logout`, {
      method: 'POST',
      headers: { 'X-Requested-With': 'XMLHttpRequest', Authorization: `Bearer ${freshMakerToken}` },
    });
    assert.equal(makerLogout.status, 200);

    const makerRelogin = await fetch(`${origin}/api/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-Requested-With': 'XMLHttpRequest' },
      body: JSON.stringify({ username: 'user-pscrappers', password: rotatedMakerPass }),
    });
    assert.equal(makerRelogin.status, 200, 'Maker re-login after logout must succeed');
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
    body: JSON.stringify({ username: 'pscrappers', password: 'InvalidPassword1' }),
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

async function runMakerOnlyRotationTests(): Promise<void> {
  const crypto = await import('node:crypto');
  const { getStore, resetStoreForTesting } = await import('../src/server/store.js');
  resetStoreForTesting();

  const rotApp = createApiApp();
  const rotServer = http.createServer(rotApp);
  await new Promise<void>((resolve) => rotServer.listen(0, '127.0.0.1', resolve));
  const addr = rotServer.address();
  if (!addr || typeof addr === 'string') throw new Error('Failed to bind rotation test server');
  const origin = `http://127.0.0.1:${addr.port}`;

  const oldMakerPass = `OldMaker@${crypto.randomBytes(4).toString('hex')}`;
  const newMakerPass = `NewMaker@${crypto.randomBytes(4).toString('hex')}`;
  const mainAdminPass = `MainAdmin@${crypto.randomBytes(6).toString('hex')}`;
  const protectedPass = `Protected@${crypto.randomBytes(6).toString('hex')}`;

  try {
    // 1. Bootstrap primary_credentials with makerUsername = pscrappers
    const bootRes = await fetch(`${origin}/api/auth/bootstrap`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-Requested-With': 'XMLHttpRequest' },
      body: JSON.stringify({
        makerUsername: 'pscrappers',
        makerPassword: oldMakerPass,
        mainAdminPassword: mainAdminPass,
        protectedPassword: protectedPass,
      }),
    });
    assert.equal(bootRes.status, 201);

    const beforeCreds = await getStore().getCredentials();
    assert.ok(beforeCreds);
    assert.equal(beforeCreds.makerUsername, 'pscrappers');

    // 2. Old Maker login succeeds before rotation; new password fails before rotation
    const preLoginOk = await fetch(`${origin}/api/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-Requested-With': 'XMLHttpRequest' },
      body: JSON.stringify({ username: 'pscrappers', password: oldMakerPass }),
    });
    assert.equal(preLoginOk.status, 200);
    const oldMakerToken = ((await preLoginOk.json()) as { token: string }).token;

    const preLoginMismatch = await fetch(`${origin}/api/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-Requested-With': 'XMLHttpRequest' },
      body: JSON.stringify({ username: 'pscrappers', password: newMakerPass }),
    });
    assert.equal(preLoginMismatch.status, 401);

    // 3. Unlock Main Core Admin and verify wrong admin password is rejected on rotation
    const adminUnlock = await fetch(`${origin}/api/auth/admin-unlock`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-Requested-With': 'XMLHttpRequest' },
      body: JSON.stringify({ password: mainAdminPass }),
    });
    assert.equal(adminUnlock.status, 200);
    const adminToken = ((await adminUnlock.json()) as { token: string }).token;

    const deniedRot = await fetch(`${origin}/api/admin/rotate-maker-password`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Requested-With': 'XMLHttpRequest',
        Authorization: `Bearer ${adminToken}`,
      },
      body: JSON.stringify({ currentMainPassword: 'WrongMainPassword', newMakerPassword: newMakerPass }),
    });
    assert.equal(deniedRot.status, 403);

    // 4. Rotate ONLY Maker password via dedicated endpoint
    const okRot = await fetch(`${origin}/api/admin/rotate-maker-password`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Requested-With': 'XMLHttpRequest',
        Authorization: `Bearer ${adminToken}`,
      },
      body: JSON.stringify({ currentMainPassword: mainAdminPass, newMakerPassword: newMakerPass }),
    });
    assert.equal(okRot.status, 200);
    const rotBody = (await okRot.json()) as { makerUsername: string; token: string };
    assert.equal(rotBody.makerUsername, 'pscrappers');

    // 5. Confirm ONLY makerPasswordHash, sessionVersion, and updatedAt changed
    const afterCreds = await getStore().getCredentials();
    assert.ok(afterCreds);
    assert.equal(afterCreds.makerUsername, 'pscrappers');
    assert.equal(afterCreds.mainAdminPasswordHash, beforeCreds.mainAdminPasswordHash);
    assert.equal(afterCreds.protectedPasswordHash, beforeCreds.protectedPasswordHash);
    assert.equal(afterCreds.deletePasswordHash, beforeCreds.deletePasswordHash);
    assert.equal(afterCreds.bootstrappedAt, beforeCreds.bootstrappedAt);
    assert.notEqual(afterCreds.makerPasswordHash, beforeCreds.makerPasswordHash);
    assert.equal(afterCreds.sessionVersion, beforeCreds.sessionVersion + 1);

    // 6. Old Maker session invalidated, old password rejected, new Maker login succeeds, Main Core Admin unchanged
    const oldSessionCheck = await fetch(`${origin}/api/certificates/recent`, {
      headers: { Authorization: `Bearer ${oldMakerToken}` },
    });
    assert.equal(oldSessionCheck.status, 401);

    const oldPassLogin = await fetch(`${origin}/api/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-Requested-With': 'XMLHttpRequest' },
      body: JSON.stringify({ username: 'pscrappers', password: oldMakerPass }),
    });
    assert.equal(oldPassLogin.status, 401);

    const newPassLogin = await fetch(`${origin}/api/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-Requested-With': 'XMLHttpRequest' },
      body: JSON.stringify({ username: 'pscrappers', password: newMakerPass }),
    });
    assert.equal(newPassLogin.status, 200);
    const newMakerJson = (await newPassLogin.json()) as { session: { username: string; role: string } };
    assert.equal(newMakerJson.session.username, 'pscrappers');
    assert.equal(newMakerJson.session.role, 'maker');

    const adminStillWorks = await fetch(`${origin}/api/auth/admin-unlock`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-Requested-With': 'XMLHttpRequest' },
      body: JSON.stringify({ password: mainAdminPass }),
    });
    assert.equal(adminStillWorks.status, 200);
  } finally {
    await new Promise<void>((resolve) => rotServer.close(() => resolve()));
    resetStoreForTesting();
  }
}

async function runMakerEditDeleteAndVerifyTests(): Promise<void> {
  const crypto = await import('node:crypto');
  const { resetStoreForTesting } = await import('../src/server/store.js');
  resetStoreForTesting();

  const app = createApiApp();
  const srv = http.createServer(app);
  await new Promise<void>((resolve) => srv.listen(0, '127.0.0.1', resolve));
  const addr = srv.address();
  if (!addr || typeof addr === 'string') throw new Error('Failed to bind Maker edit/delete test server');
  const origin = `http://127.0.0.1:${addr.port}`;

  const makerPass = `MakerEdit@${crypto.randomBytes(4).toString('hex')}`;
  const mainAdminPass = `AdminEdit@${crypto.randomBytes(4).toString('hex')}`;
  const protectedPass = `ProtEdit@${crypto.randomBytes(4).toString('hex')}`;

  async function callApi(
    path: string,
    opts: { method?: string; token?: string; body?: unknown; skipCsrf?: boolean; headers?: Record<string, string> } = {}
  ) {
    const headers: Record<string, string> = { ...(opts.headers ?? {}) };
    if (!opts.skipCsrf) headers['X-Requested-With'] = 'XMLHttpRequest';
    if (opts.body !== undefined) headers['Content-Type'] = 'application/json';
    if (opts.token) headers['Authorization'] = `Bearer ${opts.token}`;
    const res = await fetch(`${origin}${path}`, {
      method: opts.method ?? 'GET',
      headers,
      body: opts.body !== undefined ? JSON.stringify(opts.body) : undefined,
    });
    const json = (await res.json()) as Record<string, unknown>;
    return { status: res.status, json };
  }

  try {
    // 1. Bootstrap & log in as Maker
    const boot = await callApi('/api/auth/bootstrap', {
      method: 'POST',
      body: {
        makerUsername: 'pscrappers',
        makerPassword: makerPass,
        mainAdminPassword: mainAdminPass,
        protectedPassword: protectedPass,
      },
    });
    assert.equal(boot.status, 201);

    const login = await callApi('/api/auth/login', {
      method: 'POST',
      body: { username: 'pscrappers', password: makerPass },
    });
    assert.equal(login.status, 200);
    const makerToken = String(login.json.token);

    const adminUnlock = await callApi('/api/auth/admin-unlock', {
      method: 'POST',
      body: { password: mainAdminPass },
    });
    assert.equal(adminUnlock.status, 200);
    const adminToken = String(adminUnlock.json.token);

    // 2. Create 6 certificates (1..5 omit rtoAuthority; #6 simulates an existing legacy record with rtoAuthority)
    const created: Array<Record<string, unknown>> = [];
    for (let i = 1; i <= 6; i++) {
      const res = await callApi('/api/certificates', {
        method: 'POST',
        token: makerToken,
        headers: { 'Idempotency-Key': `maker_ed_cert_${i}` },
        body: {
          issueDate: '2026-11-27',
          handoverDate: '2026-11-26',
          ownerName: `Maker Owner ${i}`,
          ownerAddress: i % 2 === 0 ? `Sector ${i}, Faridabad` : '',
          vehicleRegNumber: `HR51AB200${i}`,
          make: 'Maruti Suzuki',
          model: 'Alto K10',
          manufactureYear: 2011,
          chassisNumber: `MA3EJKD1S0098765${i}`,
          engineNumber: `K10BN654321${i}`,
          unhideChassisEngine: false,
          ...(i === 6 ? { rtoAuthority: 'Legacy RTO Faridabad (HR-51)' } : {}),
          remarks: 'Test record',
        },
      });
      assert.equal(res.status, 201);
      created.push(res.json.certificate as Record<string, unknown>);
      // Small delay so createdAt ordering is strictly deterministic across all 6 records
      await new Promise((r) => setTimeout(r, 5));
    }

    const oldestCert = created[0]; // outside Maker latest-5
    const recentNoRtoCert = created[4]; // within Maker latest-5, no RTO
    const recentLegacyRtoCert = created[5]; // within Maker latest-5, has legacy RTO

    // 3. Public verification succeeds for BOTH RTO-free certificate and legacy-RTO certificate, and fails cleanly for invalid cert
    const verifyNoRto = await callApi(
      `/api/verify?certificateNumber=${encodeURIComponent(String(recentNoRtoCert.certificateNumber))}&token=${encodeURIComponent(String(recentNoRtoCert.qrToken))}`
    );
    assert.equal(verifyNoRto.status, 200);
    assert.equal(verifyNoRto.json.found, true);
    assert.equal(verifyNoRto.json.verified, true);
    assert.equal(verifyNoRto.json.integrityMatch, true);

    const verifyLegacyRto = await callApi(
      `/api/verify?certificateNumber=${encodeURIComponent(String(recentLegacyRtoCert.certificateNumber))}&token=${encodeURIComponent(String(recentLegacyRtoCert.qrToken))}`
    );
    assert.equal(verifyLegacyRto.status, 200);
    assert.equal(verifyLegacyRto.json.found, true);
    assert.equal(verifyLegacyRto.json.verified, true);
    assert.equal(verifyLegacyRto.json.integrityMatch, true);

    const verifyInvalid = await callApi('/api/verify?certificateNumber=PS%2F26%2FR0000000');
    assert.equal(verifyInvalid.status, 404);
    assert.equal(verifyInvalid.json.found, false);
    assert.equal(verifyInvalid.json.verified, false);
    assert.equal(verifyInvalid.json.integrityMatch, false);

    // 4. Unauthenticated public users are strictly rejected on PUT and DELETE
    const unauthPut = await callApi(`/api/certificates/${recentNoRtoCert.id}`, {
      method: 'PUT',
      body: { ownerName: 'Hacked Owner' },
    });
    assert.equal(unauthPut.status, 401, 'Unauthenticated PUT /api/certificates/:id must return 401');

    const unauthDelete = await callApi(`/api/certificates/${recentNoRtoCert.id}`, {
      method: 'DELETE',
    });
    assert.equal(unauthDelete.status, 401, 'Unauthenticated DELETE /api/certificates/:id must return 401');

    const csrfBlockedDelete = await callApi(`/api/certificates/${recentNoRtoCert.id}`, {
      method: 'DELETE',
      skipCsrf: true,
      headers: { Origin: 'https://evil.example' },
    });
    assert.equal(csrfBlockedDelete.status, 403, 'Cross-site DELETE without CSRF header must return 403');

    // 5. Maker cannot edit or delete older certificates outside latest-5 scope (403)
    const makerEditOld = await callApi(`/api/certificates/${oldestCert.id}`, {
      method: 'PUT',
      token: makerToken,
      body: { ownerName: 'Should Fail' },
    });
    assert.equal(makerEditOld.status, 403, 'Maker must receive 403 when editing outside latest-5');

    const makerDeleteOld = await callApi(`/api/certificates/${oldestCert.id}`, {
      method: 'DELETE',
      token: makerToken,
    });
    assert.equal(makerDeleteOld.status, 403, 'Maker must receive 403 when deleting outside latest-5');

    // 6. Authenticated Maker edits a recent certificate (and legacy-RTO certificate) cleanly without password re-entry
    const makerEdit = await callApi(`/api/certificates/${recentLegacyRtoCert.id}`, {
      method: 'PUT',
      token: makerToken,
      body: {
        ownerName: 'Corrected Maker Owner 6',
        vehicleRegNumber: 'HR51AB9996',
        reason: 'Corrected typo in owner name and registration number',
      },
    });
    assert.equal(makerEdit.status, 200);
    const updatedCert = makerEdit.json.certificate as Record<string, unknown>;
    assert.equal(updatedCert.certificateNumber, recentLegacyRtoCert.certificateNumber, 'Certificate number must be preserved');
    assert.equal(updatedCert.scrappingRegNumber, recentLegacyRtoCert.scrappingRegNumber, 'Scrapping reg number must be preserved');
    assert.equal(updatedCert.ownerName, 'Corrected Maker Owner 6');
    assert.equal(updatedCert.vehicleRegNumber, 'HR51AB9996');
    assert.equal(updatedCert.version, 2);
    assert.equal((updatedCert.versionHistory as unknown[]).length, 1);
    assert.notEqual(updatedCert.canonicalHash, recentLegacyRtoCert.canonicalHash);
    assert.notEqual(updatedCert.qrToken, recentLegacyRtoCert.qrToken);

    // Public verification passes with the updated certificate and rotated QR token
    const verifyAfterEdit = await callApi(
      `/api/verify?certificateNumber=${encodeURIComponent(String(updatedCert.certificateNumber))}&token=${encodeURIComponent(String(updatedCert.qrToken))}`
    );
    assert.equal(verifyAfterEdit.status, 200);
    assert.equal(verifyAfterEdit.json.verified, true);
    assert.equal(verifyAfterEdit.json.integrityMatch, true);
    assert.equal(verifyAfterEdit.json.tokenMatch, true);
    assert.equal(verifyAfterEdit.json.ownerName, 'Corrected Maker Owner 6');

    // 7. Authenticated Maker deletes a recent certificate WITHOUT password re-entry
    const makerDel = await callApi(`/api/certificates/${recentNoRtoCert.id}`, {
      method: 'DELETE',
      token: makerToken,
    });
    assert.equal(makerDel.status, 200);
    assert.equal(makerDel.json.success, true);
    assert.equal(makerDel.json.deletedId, recentNoRtoCert.id);
    assert.equal(makerDel.json.certificateNumber, recentNoRtoCert.certificateNumber);
    assert.equal(makerDel.json.deletedBy, 'pscrappers');
    assert.ok(typeof makerDel.json.deletedAt === 'string' && makerDel.json.deletedAt.length > 0);

    // Confirm record is SOFT_DELETED in admin registry (preserving auditability & number reservations)
    const adminCheckDeleted = await callApi(
      `/api/admin/certificates?search=${encodeURIComponent(String(recentNoRtoCert.certificateNumber))}&status=SOFT_DELETED`,
      { token: adminToken }
    );
    assert.equal(adminCheckDeleted.status, 200);
    assert.equal(adminCheckDeleted.json.total, 1, 'Maker-deleted certificate should remain soft-deleted in admin ledger');

    // Deleted certificate no longer appears in Maker's recent list or passes public verification
    const recentAfterDel = await callApi('/api/certificates/recent', { token: makerToken });
    assert.equal(recentAfterDel.status, 200);
    const recentIds = (recentAfterDel.json.certificates as Array<Record<string, unknown>>).map((c) => String(c.id));
    assert.equal(recentIds.includes(String(recentNoRtoCert.id)), false, 'Deleted cert must not appear in recent list');

    const verifyDeleted = await callApi(
      `/api/verify?certificateNumber=${encodeURIComponent(String(recentNoRtoCert.certificateNumber))}`
    );
    assert.equal(verifyDeleted.status, 404);
    assert.equal(verifyDeleted.json.found, false);
    assert.equal(verifyDeleted.json.verified, false);

    // Verify audit logs captured both CERTIFICATE_EDITED and CERTIFICATE_SOFT_DELETED
    const auditLogs = await callApi('/api/admin/audit-logs?limit=25', { token: adminToken });
    assert.equal(auditLogs.status, 200);
    const actions = (auditLogs.json.logs as Array<Record<string, unknown>>).map((l) => String(l.action));
    assert.ok(actions.includes('CERTIFICATE_EDITED'), 'Audit log must record Maker edit');
    assert.ok(actions.includes('CERTIFICATE_SOFT_DELETED'), 'Audit log must record Maker soft delete');
  } finally {
    await new Promise<void>((resolve) => srv.close(() => resolve()));
    resetStoreForTesting();
  }
}

async function runAuthDiagnosticsTests(): Promise<void> {
  const crypto = await import('node:crypto');
  const { getStore, resetStoreForTesting } = await import('../src/server/store.js');
  const { hashPassword } = await import('../src/server/crypto.js');
  resetStoreForTesting();

  const capturedLogs: string[] = [];
  const origWarn = console.warn;
  console.warn = (...args: unknown[]) => {
    capturedLogs.push(args.map(String).join(' '));
  };

  const diagApp = createApiApp();
  const diagServer = http.createServer(diagApp);
  await new Promise<void>((resolve) => diagServer.listen(0, '127.0.0.1', resolve));
  const addr = diagServer.address();
  if (!addr || typeof addr === 'string') throw new Error('Failed to bind diagnostics test server');
  const origin = `http://127.0.0.1:${addr.port}`;

  const secretMakerPass = `DiagSecret@${crypto.randomBytes(4).toString('hex')}`;
  const secretAdminPass = `DiagAdmin@${crypto.randomBytes(4).toString('hex')}`;

  try {
    // 1. MISSING_FIRESTORE_CREDENTIALS on empty store
    const missingRes = await fetch(`${origin}/api/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-Requested-With': 'XMLHttpRequest' },
      body: JSON.stringify({ username: 'pscrappers', password: secretMakerPass }),
    });
    assert.equal(missingRes.status, 503);
    assert.ok(
      capturedLogs.some((l) => l.includes('MISSING_FIRESTORE_CREDENTIALS')),
      'Expected MISSING_FIRESTORE_CREDENTIALS diagnostic'
    );

    // 2. INVALID_PASSWORD_HASH_FORMAT when stored makerPasswordHash is corrupted
    const store = getStore();
    await store.saveCredentials({
      makerUsername: 'pscrappers',
      makerPasswordHash: 'scrypt$bad_salt$not_valid_hex',
      mainAdminPasswordHash: hashPassword(secretAdminPass),
      protectedPasswordHash: hashPassword(secretAdminPass),
      deletePasswordHash: hashPassword(secretAdminPass),
      sessionVersion: 1,
      bootstrappedAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
    });
    const invalidFmtRes = await fetch(`${origin}/api/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-Requested-With': 'XMLHttpRequest' },
      body: JSON.stringify({ username: 'pscrappers', password: secretMakerPass }),
    });
    assert.equal(invalidFmtRes.status, 500);
    const invalidFmtText = await invalidFmtRes.text();
    assert.equal(invalidFmtText.includes('scrypt$'), false, 'Public response must never expose hash');
    assert.ok(
      capturedLogs.some((l) => l.includes('INVALID_PASSWORD_HASH_FORMAT')),
      'Expected INVALID_PASSWORD_HASH_FORMAT diagnostic'
    );

    // 3. Valid hash saved -> test INCORRECT_USERNAME vs INCORRECT_PASSWORD
    const validHash = hashPassword(secretMakerPass);
    await store.saveCredentials({
      makerUsername: 'pscrappers',
      makerPasswordHash: validHash,
      mainAdminPasswordHash: hashPassword(secretAdminPass),
      protectedPasswordHash: hashPassword(secretAdminPass),
      deletePasswordHash: hashPassword(secretAdminPass),
      sessionVersion: 1,
      bootstrappedAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
    });

    const wrongUserRes = await fetch(`${origin}/api/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-Requested-With': 'XMLHttpRequest' },
      body: JSON.stringify({ username: 'wrong_user', password: secretMakerPass }),
    });
    assert.equal(wrongUserRes.status, 401);
    assert.ok(
      capturedLogs.some((l) => l.includes('INCORRECT_USERNAME')),
      'Expected INCORRECT_USERNAME diagnostic'
    );

    const wrongPassRes = await fetch(`${origin}/api/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-Requested-With': 'XMLHttpRequest' },
      body: JSON.stringify({ username: 'pscrappers', password: 'WrongPassword#99' }),
    });
    assert.equal(wrongPassRes.status, 401);
    assert.ok(
      capturedLogs.some((l) => l.includes('INCORRECT_PASSWORD')),
      'Expected INCORRECT_PASSWORD diagnostic'
    );

    // 4. Main Core Admin diagnostics: INVALID_PASSWORD_HASH_FORMAT and INCORRECT_PASSWORD
    await store.saveCredentials({
      makerUsername: 'user-pscrappers',
      makerPasswordHash: validHash,
      mainAdminPasswordHash: 'corrupted_non_scrypt_hash',
      protectedPasswordHash: hashPassword(secretAdminPass),
      deletePasswordHash: hashPassword(secretAdminPass),
      sessionVersion: 2,
      bootstrappedAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
    });
    const invalidAdminFmt = await fetch(`${origin}/api/auth/admin-unlock`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-Requested-With': 'XMLHttpRequest' },
      body: JSON.stringify({ password: secretAdminPass }),
    });
    assert.equal(invalidAdminFmt.status, 500);

    // 5. Simulate local recovery aligning makerUsername -> user-pscrappers & repairing both hashes
    const recoveredAdminPass = `RecovAdmin@${crypto.randomBytes(4).toString('hex')}`;
    const recoveredMakerPass = `RecovMaker@${crypto.randomBytes(4).toString('hex')}`;
    const recoveredAdminHash = hashPassword(recoveredAdminPass);
    const recoveredMakerHash = hashPassword(recoveredMakerPass);
    const currentCreds = await store.getCredentials();
    assert.ok(currentCreds);
    await store.saveCredentials({
      ...currentCreds,
      makerUsername: 'user-pscrappers',
      makerPasswordHash: recoveredMakerHash,
      mainAdminPasswordHash: recoveredAdminHash,
      sessionVersion: currentCreds.sessionVersion + 1,
      updatedAt: new Date().toISOString(),
    });

    // Wrong Main Core Admin password logs INCORRECT_PASSWORD
    const wrongAdminRes = await fetch(`${origin}/api/auth/admin-unlock`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-Requested-With': 'XMLHttpRequest' },
      body: JSON.stringify({ password: 'WrongAdminPass#99' }),
    });
    assert.equal(wrongAdminRes.status, 401);

    // 6. Both Main Core Admin and Maker (user-pscrappers) login + logout + re-login succeed cleanly
    const adminOk1 = await fetch(`${origin}/api/auth/admin-unlock`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-Requested-With': 'XMLHttpRequest' },
      body: JSON.stringify({ password: recoveredAdminPass }),
    });
    assert.equal(adminOk1.status, 200);
    const { token: adminTok1 } = (await adminOk1.json()) as { token: string };
    const adminLogout = await fetch(`${origin}/api/auth/logout`, {
      method: 'POST',
      headers: { 'X-Requested-With': 'XMLHttpRequest', Authorization: `Bearer ${adminTok1}` },
    });
    assert.equal(adminLogout.status, 200);
    const adminOk2 = await fetch(`${origin}/api/auth/admin-unlock`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-Requested-With': 'XMLHttpRequest' },
      body: JSON.stringify({ password: recoveredAdminPass }),
    });
    assert.equal(adminOk2.status, 200);

    const okLogin1 = await fetch(`${origin}/api/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-Requested-With': 'XMLHttpRequest' },
      body: JSON.stringify({ username: 'user-pscrappers', password: recoveredMakerPass }),
    });
    assert.equal(okLogin1.status, 200);
    const { token: tok1 } = (await okLogin1.json()) as { token: string };

    const logoutRes = await fetch(`${origin}/api/auth/logout`, {
      method: 'POST',
      headers: { 'X-Requested-With': 'XMLHttpRequest', Authorization: `Bearer ${tok1}` },
    });
    assert.equal(logoutRes.status, 200);

    const okLogin2 = await fetch(`${origin}/api/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-Requested-With': 'XMLHttpRequest' },
      body: JSON.stringify({ username: 'user-pscrappers', password: recoveredMakerPass }),
    });
    assert.equal(okLogin2.status, 200);

    // 7. Verify ZERO secrets, plaintext passwords, or scrypt hashes leaked into diagnostic logs
    const joinedLogs = capturedLogs.join('\n');
    assert.equal(joinedLogs.includes(secretMakerPass), false, 'Logs must never contain plaintext Maker password');
    assert.equal(joinedLogs.includes(secretAdminPass), false, 'Logs must never contain plaintext Admin password');
    assert.equal(joinedLogs.includes(recoveredAdminPass), false, 'Logs must never contain recovered Admin password');
    assert.equal(joinedLogs.includes(recoveredMakerPass), false, 'Logs must never contain recovered Maker password');
    assert.equal(joinedLogs.includes(validHash), false, 'Logs must never contain scrypt hashes');
    assert.equal(joinedLogs.includes(recoveredAdminHash), false, 'Logs must never contain recovered hashes');
    assert.equal(joinedLogs.includes('WrongPassword#99'), false, 'Logs must never contain attempted passwords');
    assert.equal(joinedLogs.includes('WrongAdminPass#99'), false, 'Logs must never contain attempted admin passwords');
  } finally {
    console.warn = origWarn;
    await new Promise<void>((resolve) => diagServer.close(() => resolve()));
    resetStoreForTesting();
  }
}

async function runMakerSessionAndNextNumbersTests(): Promise<void> {
  const crypto = await import('node:crypto');
  const { getStore, resetStoreForTesting } = await import('../src/server/store.js');
  const { buildCertificatePdfDoc, getCertificatePdfFilename } = await import('../src/lib/pdfGenerator.js');
  const { hashPassword } = await import('../src/server/crypto.js');

  const savedEnv = {
    ADMIN_SESSION_SECRET: process.env.ADMIN_SESSION_SECRET,
    FIREBASE_PROJECT_ID: process.env.FIREBASE_PROJECT_ID,
    FIREBASE_CLIENT_EMAIL: process.env.FIREBASE_CLIENT_EMAIL,
    FIREBASE_PRIVATE_KEY: process.env.FIREBASE_PRIVATE_KEY,
  };

  // Simulate Vercel production where ADMIN_SESSION_SECRET is omitted so getSessionSecret()
  // must derive a consistent key from private Firebase env vars across serverless instances
  delete process.env.ADMIN_SESSION_SECRET;
  const { privateKey } = crypto.generateKeyPairSync('rsa', {
    modulusLength: 2048,
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
    publicKeyEncoding: { type: 'spki', format: 'pem' },
  });
  // Keep StagingMemoryStore active first by initializing store BEFORE setting fake Firebase env vars for signing derivation
  resetStoreForTesting();
  const sharedStore = getStore();
  process.env.FIREBASE_PROJECT_ID = 'crm-certificates';
  process.env.FIREBASE_CLIENT_EMAIL = 'sa@crm-certificates.iam.gserviceaccount.com';
  process.env.FIREBASE_PRIVATE_KEY = privateKey;

  const capturedLogs: string[] = [];
  const origWarn = console.warn;
  console.warn = (...args: unknown[]) => {
    capturedLogs.push(args.map(String).join(' '));
  };

  // Start TWO separate Express instances simulating two Vercel serverless containers
  const appA = createApiApp();
  const appB = createApiApp();
  const serverA = http.createServer(appA);
  const serverB = http.createServer(appB);
  await new Promise<void>((resolve) => serverA.listen(0, '127.0.0.1', resolve));
  await new Promise<void>((resolve) => serverB.listen(0, '127.0.0.1', resolve));
  const addrA = serverA.address();
  const addrB = serverB.address();
  if (!addrA || typeof addrA === 'string' || !addrB || typeof addrB === 'string') {
    throw new Error('Failed to start dual-instance session test servers');
  }
  const originA = `http://127.0.0.1:${addrA.port}`;
  const originB = `http://127.0.0.1:${addrB.port}`;

  const makerPass = `SessMaker@${crypto.randomBytes(5).toString('hex')}`;
  const adminPass = `SessAdmin@${crypto.randomBytes(5).toString('hex')}`;

  try {
    await sharedStore.saveCredentials({
      makerUsername: 'user-pscrappers',
      makerPasswordHash: hashPassword(makerPass),
      mainAdminPasswordHash: hashPassword(adminPass),
      protectedPasswordHash: hashPassword(adminPass),
      deletePasswordHash: hashPassword(adminPass),
      sessionVersion: 2,
      bootstrappedAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
    });

    // 1. Unauthenticated request to /api/certificates/next-numbers & POST /api/certificates fails (401 + SESSION_COOKIE_MISSING)
    const unauthNext = await fetch(`${originA}/api/certificates/next-numbers`, {
      headers: { 'X-Requested-With': 'XMLHttpRequest' },
    });
    assert.equal(unauthNext.status, 401);
    const unauthNextJson = (await unauthNext.json()) as { code?: string };
    assert.equal(unauthNextJson.code, 'SESSION_COOKIE_MISSING');

    const unauthCreate = await fetch(`${originA}/api/certificates`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-Requested-With': 'XMLHttpRequest' },
      body: JSON.stringify({ ownerName: 'Unauthorized' }),
    });
    assert.equal(unauthCreate.status, 401);

    // 2. Maker logs in on Instance A -> receives HttpOnly Secure SameSite=None Partitioned Path=/ cookie
    const loginRes = await fetch(`${originA}/api/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-Requested-With': 'XMLHttpRequest' },
      body: JSON.stringify({ username: 'user-pscrappers', password: makerPass }),
    });
    assert.equal(loginRes.status, 200);
    const setCookie = loginRes.headers.get('set-cookie') || '';
    assert.ok(setCookie.includes('ps_session='), 'Expected ps_session cookie');
    assert.ok(setCookie.includes('HttpOnly'), 'Expected HttpOnly attribute');
    assert.ok(setCookie.includes('Secure'), 'Expected Secure attribute');
    assert.ok(setCookie.includes('SameSite=None'), 'Expected SameSite=None attribute');
    assert.ok(setCookie.includes('Path=/'), 'Expected Path=/ attribute');
    const cookiePair = setCookie.split(';')[0];
    const loginJson = (await loginRes.json()) as { token: string; session: { sid?: string; username: string } };
    assert.ok(loginJson.session.sid, 'Server-side session ID (sid) must be issued');

    // 3. Using ONLY Cookie (NO Authorization header!) on Instance B -> session remains valid!
    const statusB = await fetch(`${originB}/api/auth/status`, {
      headers: { Cookie: cookiePair, 'X-Requested-With': 'XMLHttpRequest' },
    });
    assert.equal(statusB.status, 200);
    const statusBJson = (await statusB.json()) as { session: { username: string; role: string } | null };
    assert.equal(statusBJson.session?.username, 'user-pscrappers');
    assert.equal(statusBJson.session?.role, 'maker');

    // 4. Refreshing GET /api/certificates/next-numbers 3 times on Instance B succeeds and reserves ZERO numbers!
    const reservedBefore = await sharedStore.getReservedCounts();
    assert.equal(reservedBefore.certCount, 0);
    let lastCandidate: { certificateNumber: string; scrappingRegNumber: string } | null = null;
    for (let i = 0; i < 3; i++) {
      const nextRes = await fetch(`${originB}/api/certificates/next-numbers?issueDate=2026-11-27`, {
        headers: { Cookie: cookiePair, 'X-Requested-With': 'XMLHttpRequest' },
      });
      assert.equal(nextRes.status, 200);
      lastCandidate = (await nextRes.json()) as { certificateNumber: string; scrappingRegNumber: string };
      assert.match(lastCandidate.certificateNumber, /^PS\/26\/R\d{7}$/);
      assert.match(lastCandidate.scrappingRegNumber, /^REG-C\d{6}$/);
    }
    const reservedAfterRefresh = await sharedStore.getReservedCounts();
    assert.equal(reservedAfterRefresh.certCount, 0, 'Refreshing next-numbers must NOT create reservations');
    assert.equal(reservedAfterRefresh.regCount, 0, 'Refreshing next-numbers must NOT create reg reservations');

    // 5. Generate certificate on Instance B using ONLY Cookie + displayed candidate number
    const idempKey = `sess_idemp_${crypto.randomBytes(6).toString('hex')}`;
    const createRes = await fetch(`${originB}/api/certificates`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Requested-With': 'XMLHttpRequest',
        'Idempotency-Key': idempKey,
        Cookie: cookiePair,
      },
      body: JSON.stringify({
        certificateNumber: lastCandidate!.certificateNumber,
        scrappingRegNumber: lastCandidate!.scrappingRegNumber,
        issueDate: '2026-11-27',
        handoverDate: '2026-11-26',
        ownerName: 'Session Test Owner',
        ownerAddress: 'Dwarka, New Delhi',
        vehicleRegNumber: 'DL01AB7788',
        make: 'Honda',
        model: 'Activa 6G',
        manufactureYear: 2014,
        chassisNumber: 'ME4JF505AG7123456',
        engineNumber: 'JF50E7123456',
        unhideChassisEngine: false,
        remarks: 'Verified session issuance test',
      }),
    });
    assert.equal(createRes.status, 201);
    const createdJson = (await createRes.json()) as {
      certificate: { id: string; certificateNumber: string; scrappingRegNumber: string };
      idempotentReplay: boolean;
    };
    assert.equal(createdJson.idempotentReplay, false);
    assert.equal(
      createdJson.certificate.certificateNumber,
      lastCandidate!.certificateNumber,
      'Issued certificate number must match displayed Next Available Number'
    );
    assert.equal(
      createdJson.certificate.scrappingRegNumber,
      lastCandidate!.scrappingRegNumber,
      'Issued scrapping reg number must match displayed Next Available Number'
    );

    // 6. Duplicate submission with same Idempotency-Key replays cleanly without creating a second certificate
    const dupRes = await fetch(`${originB}/api/certificates`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Requested-With': 'XMLHttpRequest',
        'Idempotency-Key': idempKey,
        Cookie: cookiePair,
      },
      body: JSON.stringify({
        certificateNumber: lastCandidate!.certificateNumber,
        scrappingRegNumber: lastCandidate!.scrappingRegNumber,
        issueDate: '2026-11-27',
        handoverDate: '2026-11-26',
        ownerName: 'Session Test Owner',
        vehicleRegNumber: 'DL01AB7788',
        make: 'Honda',
        model: 'Activa 6G',
        manufactureYear: 2014,
        chassisNumber: 'ME4JF505AG7123456',
        engineNumber: 'JF50E7123456',
      }),
    });
    assert.equal(dupRes.status, 200);
    const dupJson = (await dupRes.json()) as {
      certificate: { id: string };
      idempotentReplay: boolean;
    };
    assert.equal(dupJson.idempotentReplay, true);
    assert.equal(dupJson.certificate.id, createdJson.certificate.id);
    assert.equal((await sharedStore.getAllCertificates()).length, 1, 'Duplicate submission must not create 2nd cert');

    // 7. PDF generation succeeds and filename strictly matches certificate number
    const pdfOut = await buildCertificatePdfDoc(createdJson.certificate as never, {
      customDomain: 'https://parivahan.example.test',
    });
    const expectedFileName = getCertificatePdfFilename(createdJson.certificate.certificateNumber);
    assert.equal(pdfOut.fileName, expectedFileName, 'PDF filename must match certificate number');
    const pdfBytes = Buffer.from(pdfOut.doc.output('arraybuffer'));
    assert.ok(pdfBytes.subarray(0, 5).toString('utf8') === '%PDF-');
    assert.ok(pdfBytes.length > 10_000);

    // 8. Authenticated PDF failure diagnostic endpoint logs PDF_GENERATION_FAILURE cleanly
    const pdfDiag = await fetch(`${originB}/api/diagnostics/pdf-failure`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Requested-With': 'XMLHttpRequest',
        Cookie: cookiePair,
      },
      body: JSON.stringify({ certificateId: createdJson.certificate.id, reason: 'simulated_test_error' }),
    });
    assert.equal(pdfDiag.status, 200);

    // 9. Logout on Instance A revokes server-side session -> BOTH Cookie AND Bearer token rejected on Instance B!
    const logoutRes = await fetch(`${originA}/api/auth/logout`, {
      method: 'POST',
      headers: { 'X-Requested-With': 'XMLHttpRequest', Cookie: cookiePair },
    });
    assert.equal(logoutRes.status, 200);

    const cookieAfterLogout = await fetch(`${originB}/api/certificates/next-numbers`, {
      headers: { Cookie: cookiePair, 'X-Requested-With': 'XMLHttpRequest' },
    });
    assert.equal(cookieAfterLogout.status, 401, 'Logged-out session cookie must be rejected across instances');

    const bearerAfterLogout = await fetch(`${originB}/api/certificates/next-numbers`, {
      headers: { Authorization: `Bearer ${loginJson.token}`, 'X-Requested-With': 'XMLHttpRequest' },
    });
    assert.equal(bearerAfterLogout.status, 401, 'Logged-out Bearer token must be rejected across instances');

    // 10. Verify secret-free diagnostics captured expected codes without leaking cookies, tokens, or passwords
    const joined = capturedLogs.join('\n');
    assert.ok(joined.includes('SESSION_COOKIE_MISSING'), 'Expected SESSION_COOKIE_MISSING diagnostic');
    assert.ok(joined.includes('SESSION_VALIDATION_FAILED'), 'Expected SESSION_VALIDATION_FAILED diagnostic');
    assert.ok(joined.includes('PDF_GENERATION_FAILURE'), 'Expected PDF_GENERATION_FAILURE diagnostic');
    assert.equal(joined.includes(loginJson.token), false, 'Logs must never expose session token');
    assert.equal(joined.includes(cookiePair), false, 'Logs must never expose session cookie');
    assert.equal(joined.includes(makerPass), false, 'Logs must never expose Maker password');
  } finally {
    console.warn = origWarn;
    await new Promise<void>((resolve) => serverA.close(() => resolve()));
    await new Promise<void>((resolve) => serverB.close(() => resolve()));
    for (const [k, v] of Object.entries(savedEnv)) {
      if (v === undefined) delete process.env[k];
      else process.env[k] = v;
    }
    resetStoreForTesting();
  }
}

async function runPdfOptionalFieldsAndManufacturersTests(): Promise<void> {
  const { buildCertificatePdfDoc } = await import('../src/lib/pdfGenerator.js');
  const { COMMON_MANUFACTURERS, OTHER_MANUFACTURER_VALUE } = await import(
    '../src/shared/vehicleData.js'
  );

  // Verify exact simplified manufacturer list
  assert.deepEqual([...COMMON_MANUFACTURERS], [
    'Hero MotoCorp',
    'Yamaha',
    'Bajaj',
    'HERO',
    'HERO HONDA',
    'TVS',
    'Royal Enfield',
    'Suzuki',
  ]);
  assert.equal(OTHER_MANUFACTURER_VALUE, '__OTHER__');

  const extractPdfPageText = (doc: { internal: { pages: string[][] } }): string =>
    (doc.internal.pages[1] ?? []).join('\n');

  const baseCert = {
    id: 'cert-pdf-test',
    certificateNumber: 'PS-26-TEST0001',
    scrappingRegNumber: 'SCR-26-TEST0001',
    issueDate: '2026-11-27',
    handoverDate: '2026-11-26',
    ownerName: 'Rajesh Sharma',
    ownerAddress: '',
    idProofType: '' as const,
    idProofNumber: '',
    vehicleRegNumber: 'DL01AB1234',
    make: 'Hero MotoCorp',
    model: 'Splendor Plus',
    manufactureYear: 2013,
    chassisNumber: 'MBLHA10EYD9A12345',
    engineNumber: 'HA10EJD9A12345',
    unhideChassisEngine: false,
    facilityName: 'Parivahan Scrappers Authorized RVSF',
    facilityRvsfCode: 'PS-RVSF-DEL-01',
    facilityAddress: 'B12, Dwarka, New Delhi.',
    remarks: '',
    status: 'ACTIVE' as const,
    version: 1,
    canonicalHash: 'a'.repeat(64),
    qrToken: 'tok_test_123456',
    createdAt: '2026-11-27T00:00:00.000Z',
    updatedAt: '2026-11-27T00:00:00.000Z',
    createdBy: 'test-maker',
    createdByRole: 'maker' as const,
    driveSyncStatus: 'NOT_CONFIGURED' as const,
    versionHistory: [],
  };

  const assertCommonPdfInvariants = (
    doc: { getNumberOfPages: () => number; output: (type: 'arraybuffer') => ArrayBuffer },
    pageStream: string
  ) => {
    assert.equal(doc.getNumberOfPages(), 1, 'Certificate PDF must remain a single A4 page');
    const bytes = Buffer.from(doc.output('arraybuffer'));
    assert.equal(bytes.subarray(0, 5).toString('utf8'), '%PDF-');
    assert.equal(pageStream.includes('Issuing Facility'), false, 'PDF must not include Issuing Facility');
    assert.equal(
      pageStream.includes('Parivahan Scrappers Authorized RVSF'),
      false,
      'PDF must not include Parivahan Scrappers Authorized RVSF'
    );
    assert.equal(pageStream.includes('Not Provided'), false, 'PDF must never print Not Provided');
    assert.equal(pageStream.includes('(N/A)'), false, 'PDF must never print N/A');
  };

  // Case 1: Address and ID both provided
  const case1 = await buildCertificatePdfDoc(
    {
      ...baseCert,
      ownerAddress: '45 Green Park Extension, New Delhi 110016',
      idProofType: 'Aadhaar Card',
      idProofNumber: 'XXXX-XXXX-9012',
    },
    { customDomain: 'https://parivahan.example.test' }
  );
  const stream1 = extractPdfPageText(case1.doc as unknown as { internal: { pages: string[][] } });
  assertCommonPdfInvariants(case1.doc, stream1);
  assert.ok(stream1.includes('(Address)'), 'Case 1 must include Address label');
  assert.ok(stream1.includes('45 Green Park Extension'), 'Case 1 must include address value');
  assert.ok(stream1.includes('(ID Proof Number)'), 'Case 1 must include ID Proof Number label');
  assert.ok(stream1.includes('Aadhaar Card: XXXX-XXXX-9012'), 'Case 1 must include ID value');

  // Case 2: Address and ID both blank
  const case2 = await buildCertificatePdfDoc(
    {
      ...baseCert,
      ownerAddress: '   ',
      idProofType: '',
      idProofNumber: '',
    },
    { customDomain: 'https://parivahan.example.test' }
  );
  const stream2 = extractPdfPageText(case2.doc as unknown as { internal: { pages: string[][] } });
  assertCommonPdfInvariants(case2.doc, stream2);
  assert.equal(stream2.includes('(Address)'), false, 'Case 2 must hide Address label when blank');
  assert.equal(
    stream2.includes('(ID Proof Number)'),
    false,
    'Case 2 must hide ID Proof Number label when blank'
  );

  // Case 3: Only Address provided (ID blank)
  const case3 = await buildCertificatePdfDoc(
    {
      ...baseCert,
      ownerAddress: 'Plot 19, Sector 14, Gurugram',
      idProofType: 'PAN Card',
      idProofNumber: '   ',
    },
    { customDomain: 'https://parivahan.example.test' }
  );
  const stream3 = extractPdfPageText(case3.doc as unknown as { internal: { pages: string[][] } });
  assertCommonPdfInvariants(case3.doc, stream3);
  assert.ok(stream3.includes('(Address)'), 'Case 3 must show Address label');
  assert.ok(stream3.includes('Plot 19, Sector 14, Gurugram'), 'Case 3 must show address value');
  assert.equal(
    stream3.includes('(ID Proof Number)'),
    false,
    'Case 3 must hide ID Proof Number when ID number is blank'
  );

  // Case 4: Only ID provided (Address blank)
  const case4 = await buildCertificatePdfDoc(
    {
      ...baseCert,
      ownerAddress: '',
      idProofType: 'PAN Card',
      idProofNumber: 'ABCDE1234F',
    },
    { customDomain: 'https://parivahan.example.test' }
  );
  const stream4 = extractPdfPageText(case4.doc as unknown as { internal: { pages: string[][] } });
  assertCommonPdfInvariants(case4.doc, stream4);
  assert.equal(stream4.includes('(Address)'), false, 'Case 4 must hide Address label when blank');
  assert.ok(stream4.includes('(ID Proof Number)'), 'Case 4 must show ID Proof Number label');
  assert.ok(stream4.includes('PAN Card: ABCDE1234F'), 'Case 4 must show ID proof value');

  // Case 5: Manufacturer selected from preset dropdown
  const case5 = await buildCertificatePdfDoc(
    {
      ...baseCert,
      make: 'Hero MotoCorp',
    },
    { customDomain: 'https://parivahan.example.test' }
  );
  const stream5 = extractPdfPageText(case5.doc as unknown as { internal: { pages: string[][] } });
  assertCommonPdfInvariants(case5.doc, stream5);
  assert.ok(stream5.includes('(Hero MotoCorp)'), 'Case 5 must print selected dropdown manufacturer');

  // Case 6: Other selected with custom manufacturer name
  const case6 = await buildCertificatePdfDoc(
    {
      ...baseCert,
      make: 'Kawasaki Custom Motors',
    },
    { customDomain: 'https://parivahan.example.test' }
  );
  const stream6 = extractPdfPageText(case6.doc as unknown as { internal: { pages: string[][] } });
  assertCommonPdfInvariants(case6.doc, stream6);
  assert.ok(
    stream6.includes('(Kawasaki Custom Motors)'),
    'Case 6 must print exact custom manufacturer name'
  );
  assert.equal(stream6.includes('__OTHER__'), false, 'Case 6 must never print __OTHER__');
}

async function runTwoBrandScrapRouteAndRememberMeTests(): Promise<void> {
  const crypto = await import('node:crypto');
  const { getStore, resetStoreForTesting } = await import('../src/server/store.js');
  const { computeCanonicalHash, generateQrToken, hashPassword } = await import('../src/server/crypto.js');
  const { buildCertificatePdfDoc } = await import('../src/lib/pdfGenerator.js');

  const savedEnv = {
    SCRAP_ROUTE_PIN: process.env.SCRAP_ROUTE_PIN,
    SCRAP_ROUTE_PIN_HASH: process.env.SCRAP_ROUTE_PIN_HASH,
  };

  resetStoreForTesting();
  const store = getStore();

  const makerPass = `TwoBrandMaker@${crypto.randomBytes(5).toString('hex')}`;
  const adminPass = `TwoBrandAdmin@${crypto.randomBytes(5).toString('hex')}`;
  const scrapRoutePin = `SR-${crypto.randomBytes(3).toString('hex').toUpperCase()}`;

  // Configure SCRAP_ROUTE_PIN dynamically for test (never hardcoded)
  process.env.SCRAP_ROUTE_PIN = scrapRoutePin;
  delete process.env.SCRAP_ROUTE_PIN_HASH;

  const app = createApiApp();
  const srv = http.createServer(app);
  await new Promise<void>((resolve) => srv.listen(0, '127.0.0.1', resolve));
  const addr = srv.address();
  if (!addr || typeof addr === 'string') throw new Error('Failed to start two-brand test server');
  const origin = `http://127.0.0.1:${addr.port}`;

  const extractPdfPageText = (doc: { internal: { pages: string[][] } }): string =>
    (doc.internal.pages[1] ?? []).join('\n');

  const extractCookies = (res: Response): string[] => {
    const hdrs = res.headers as unknown as { getSetCookie?: () => string[] };
    if (typeof hdrs.getSetCookie === 'function') return hdrs.getSetCookie();
    const raw = res.headers.get('set-cookie');
    return raw ? [raw] : [];
  };

  try {
    await store.saveCredentials({
      makerUsername: 'user-pscrappers',
      makerPasswordHash: hashPassword(makerPass),
      mainAdminPasswordHash: hashPassword(adminPass),
      protectedPasswordHash: hashPassword(adminPass),
      deletePasswordHash: hashPassword(adminPass),
      sessionVersion: 1,
      bootstrappedAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
    });

    // 1. Seed a legacy Parivahan certificate WITHOUT `brand` field to confirm 100% backward compatibility
    const legacyToken = generateQrToken();
    const legacyBase = {
      certificateNumber: 'PS/26/R9991111',
      scrappingRegNumber: 'REG-C991111',
      issueDate: '2026-10-15',
      handoverDate: '2026-10-14',
      ownerName: 'Legacy Parivahan Owner',
      ownerAddress: 'Rohini Sector 8, Delhi',
      idProofType: 'PAN Card' as const,
      idProofNumber: 'ABCDE1234F',
      vehicleRegNumber: 'DL08CD4321',
      make: 'Hero MotoCorp',
      model: 'Splendor',
      manufactureYear: 2012,
      chassisNumber: 'MBLHA10EYC9A54321',
      engineNumber: 'HA10EJC9A54321',
      unhideChassisEngine: false,
      facilityName: 'Parivahan Scrappers Authorized RVSF',
      facilityRvsfCode: 'PS-RVSF-DEL-01',
      facilityAddress: 'Industrial Area Phase II',
      remarks: 'Legacy pre-two-brand record',
      version: 1,
      status: 'ACTIVE' as const,
      qrToken: legacyToken,
    };
    const legacyHash = computeCanonicalHash(legacyBase);
    await store.createCertificateAtomic({
      certificate: {
        ...legacyBase,
        id: 'cert_legacy_no_brand',
        canonicalHash: legacyHash,
        qrToken: legacyToken,
        createdAt: '2026-10-15T08:00:00.000Z',
        updatedAt: '2026-10-15T08:00:00.000Z',
        createdBy: 'user-pscrappers',
        createdByRole: 'maker',
        versionHistory: [],
        driveSyncStatus: 'NOT_CONFIGURED',
      },
      idempotencyKey: 'legacy_seed_1',
      auditLog: {
        id: 'aud_legacy_seed_1',
        timestamp: '2026-10-15T08:00:00.000Z',
        actor: 'user-pscrappers',
        actorRole: 'maker',
        action: 'CERTIFICATE_CREATED',
        certificateId: 'cert_legacy_no_brand',
        certificateNumber: legacyBase.certificateNumber,
      },
    });

    const verifyLegacy = await fetch(
      `${origin}/api/verify?certificateNumber=${encodeURIComponent(legacyBase.certificateNumber)}&token=${encodeURIComponent(legacyToken)}`
    );
    assert.equal(verifyLegacy.status, 200);
    const verifyLegacyJson = (await verifyLegacy.json()) as Record<string, unknown>;
    assert.equal(verifyLegacyJson.verified, true, 'Legacy record without brand must still pass verification');
    assert.equal(verifyLegacyJson.integrityMatch, true, 'Legacy SHA-256 hash must remain identical');
    assert.equal(verifyLegacyJson.tokenMatch, true);
    assert.equal(verifyLegacyJson.brand, 'parivahan');
    assert.equal(verifyLegacyJson.brandDisplayName, 'Parivahan Scrappers');

    // 2. Maker login with rememberMe: true creates a 30-day persistent cookie session
    const loginRes = await fetch(`${origin}/api/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-Requested-With': 'XMLHttpRequest' },
      body: JSON.stringify({ username: 'user-pscrappers', password: makerPass, rememberMe: true }),
    });
    assert.equal(loginRes.status, 200);
    const loginCookies = extractCookies(loginRes);
    const sessionSetCookie = loginCookies.find((c) => c.startsWith('ps_session=')) || '';
    assert.ok(sessionSetCookie.includes('HttpOnly'), 'Remember Me cookie must be HttpOnly');
    assert.ok(sessionSetCookie.includes('Secure'), 'Remember Me cookie must be Secure');
    assert.ok(sessionSetCookie.includes('SameSite=None'), 'Remember Me cookie must be SameSite=None');
    assert.ok(sessionSetCookie.includes('Max-Age=2592000'), 'Remember Me cookie must have 30-day Max-Age');
    const sessionCookiePair = sessionSetCookie.split(';')[0];
    const loginJson = (await loginRes.json()) as {
      token: string;
      session: {
        sid: string;
        rememberMe?: boolean;
        expiresAt: string;
      };
    };
    assert.equal(loginJson.session.rememberMe, true);
    const ttlMs = new Date(loginJson.session.expiresAt).getTime() - Date.now();
    assert.ok(ttlMs > 29 * 24 * 60 * 60 * 1000, 'Remember Me session expiry must exceed 29 days');

    // Confirm cookie-only automatic sign-in via /api/auth/status returns active session & Scrap Route PIN status
    const statusRes = await fetch(`${origin}/api/auth/status`, {
      headers: { Cookie: sessionCookiePair, 'X-Requested-With': 'XMLHttpRequest' },
    });
    assert.equal(statusRes.status, 200);
    const statusJson = (await statusRes.json()) as {
      session: { username: string; rememberMe?: boolean } | null;
      scrapRouteAuthorized?: boolean;
      scrapRoutePinConfigured?: boolean;
    };
    assert.equal(statusJson.session?.username, 'user-pscrappers');
    assert.equal(statusJson.session?.rememberMe, true);
    assert.equal(statusJson.scrapRouteAuthorized, false);
    assert.equal(statusJson.scrapRoutePinConfigured, true);

    // 3. Parivahan issuance works without Scrap Route PIN & PDF matches updated Parivahan branding
    const psNextRes = await fetch(`${origin}/api/certificates/next-numbers?brand=parivahan&issueDate=2026-11-27`, {
      headers: { Cookie: sessionCookiePair, 'X-Requested-With': 'XMLHttpRequest' },
    });
    assert.equal(psNextRes.status, 200);
    const psNext = (await psNextRes.json()) as {
      brand: string;
      certificateNumber: string;
      scrappingRegNumber: string;
    };
    assert.equal(psNext.brand, 'parivahan');
    assert.match(psNext.certificateNumber, /^PS\/26\/R\d{7}$/);
    assert.match(psNext.scrappingRegNumber, /^REG-C\d{6}$/);

    const psCreateRes = await fetch(`${origin}/api/certificates`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Requested-With': 'XMLHttpRequest',
        'Idempotency-Key': `ps_brand_${crypto.randomBytes(5).toString('hex')}`,
        Cookie: sessionCookiePair,
      },
      body: JSON.stringify({
        brand: 'parivahan',
        certificateNumber: psNext.certificateNumber,
        scrappingRegNumber: psNext.scrappingRegNumber,
        issueDate: '2026-11-27',
        handoverDate: '2026-11-26',
        ownerName: 'Parivahan TwoBrand Owner',
        ownerAddress: 'Janakpuri, New Delhi',
        vehicleRegNumber: 'DL09PQ1122',
        make: 'Bajaj',
        model: 'Pulsar 150',
        manufactureYear: 2014,
        chassisNumber: 'MD2A11CZ0ECA11223',
        engineNumber: 'DHYCE11223',
        unhideChassisEngine: false,
      }),
    });
    assert.equal(psCreateRes.status, 201);
    const psCert = ((await psCreateRes.json()) as { certificate: Record<string, unknown> }).certificate;
    assert.equal(psCert.brand, 'parivahan');

    const psPdf = await buildCertificatePdfDoc(psCert as never, {
      customDomain: 'https://verify.example.test',
    });
    assert.equal(psPdf.doc.getNumberOfPages(), 1);
    const psStream = extractPdfPageText(psPdf.doc as unknown as { internal: { pages: string[][] } });
    assert.ok(psStream.includes('PARIVAHAN SCRAPPERS'), 'Parivahan PDF must show PARIVAHAN SCRAPPERS');
    assert.ok(psStream.includes('A UNIT OF SCRAP ROUTE'), 'Parivahan PDF bottom must show A UNIT OF SCRAP ROUTE');
    assert.ok(
      psStream.includes('https://parivahanscrappers.netlify.app/'),
      'Parivahan PDF must show https://parivahanscrappers.netlify.app/'
    );
    assert.equal(
      psStream.toLowerCase().includes('scrapping yard'),
      false,
      'Parivahan PDF must never mention Scrapping Yard Ltd.'
    );
    assert.equal(
      psStream.includes('parivahan-scrappers.netlify.app'),
      false,
      'Parivahan PDF must not use the old hyphenated URL'
    );

    // 4. Unverified Scrap Route access is strictly rejected (403 SCRAP_ROUTE_PIN_REQUIRED)
    const srNextBlocked = await fetch(
      `${origin}/api/certificates/next-numbers?brand=scrap_route&issueDate=2026-11-27`,
      { headers: { Cookie: sessionCookiePair, 'X-Requested-With': 'XMLHttpRequest' } }
    );
    assert.equal(srNextBlocked.status, 403);
    assert.equal(((await srNextBlocked.json()) as { code?: string }).code, 'SCRAP_ROUTE_PIN_REQUIRED');

    const srCreateBlocked = await fetch(`${origin}/api/certificates`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Requested-With': 'XMLHttpRequest',
        Cookie: sessionCookiePair,
      },
      body: JSON.stringify({
        brand: 'scrap_route',
        issueDate: '2026-11-27',
        handoverDate: '2026-11-26',
        ownerName: 'Blocked Scrap Route Owner',
        vehicleRegNumber: 'DL01SR0001',
        make: 'TVS',
        model: 'Jupiter',
        manufactureYear: 2015,
        chassisNumber: 'MD626BG4XF1A00001',
        engineNumber: 'BG4F1A00001',
      }),
    });
    assert.equal(srCreateBlocked.status, 403);
    assert.equal(((await srCreateBlocked.json()) as { code?: string }).code, 'SCRAP_ROUTE_PIN_REQUIRED');

    // 5. Scrap Route PIN verification: rejects wrong PIN (401) and rate limits after 5 failures (429)
    // Use a separate client IP header is ignored unless trust proxy, so test wrong PIN attempts first then verify with hash mode
    const wrongPin1 = await fetch(`${origin}/api/auth/scrap-route/verify-pin`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Requested-With': 'XMLHttpRequest',
        Cookie: sessionCookiePair,
      },
      body: JSON.stringify({ pin: 'WRONG-PIN-000' }),
    });
    assert.equal(wrongPin1.status, 401);

    // Verify valid PIN succeeds with salted scrypt hash env var too!
    delete process.env.SCRAP_ROUTE_PIN;
    process.env.SCRAP_ROUTE_PIN_HASH = hashPassword(scrapRoutePin);

    const okPinRes = await fetch(`${origin}/api/auth/scrap-route/verify-pin`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Requested-With': 'XMLHttpRequest',
        Cookie: sessionCookiePair,
      },
      body: JSON.stringify({ pin: scrapRoutePin }),
    });
    assert.equal(okPinRes.status, 200);
    const srCookies = extractCookies(okPinRes);
    const srSetCookie = srCookies.find((c) => c.startsWith('ps_sr_auth=')) || '';
    assert.ok(srSetCookie.includes('HttpOnly'), 'ps_sr_auth cookie must be HttpOnly');
    assert.ok(srSetCookie.includes('Secure'), 'ps_sr_auth cookie must be Secure');
    assert.ok(srSetCookie.includes('SameSite=None'), 'ps_sr_auth cookie must be SameSite=None');
    const srCookiePair = srSetCookie.split(';')[0];
    const okPinJson = (await okPinRes.json()) as {
      authorized: boolean;
      scrapRouteToken: string;
      expiresAt: string;
    };
    assert.equal(okPinJson.authorized, true);
    assert.ok(okPinJson.scrapRouteToken.length > 20);

    const combinedCookie = `${sessionCookiePair}; ${srCookiePair}`;

    // 6. Scrap Route candidate numbers & atomic issuance succeed with disjoint SR numbering
    const srNextRes = await fetch(`${origin}/api/certificates/next-numbers?brand=scrap_route&issueDate=2026-11-27`, {
      headers: { Cookie: combinedCookie, 'X-Requested-With': 'XMLHttpRequest' },
    });
    assert.equal(srNextRes.status, 200);
    const srNext = (await srNextRes.json()) as {
      brand: string;
      certificateNumber: string;
      scrappingRegNumber: string;
    };
    assert.equal(srNext.brand, 'scrap_route');
    assert.match(srNext.certificateNumber, /^SR\/26\/R\d{7}$/);
    assert.match(srNext.scrappingRegNumber, /^SR-REG-\d{6}$/);

    const srCreateRes = await fetch(`${origin}/api/certificates`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Requested-With': 'XMLHttpRequest',
        'Idempotency-Key': `sr_brand_${crypto.randomBytes(5).toString('hex')}`,
        Cookie: combinedCookie,
      },
      body: JSON.stringify({
        brand: 'scrap_route',
        certificateNumber: srNext.certificateNumber,
        scrappingRegNumber: srNext.scrappingRegNumber,
        issueDate: '2026-11-27',
        handoverDate: '2026-11-26',
        ownerName: 'Scrap Route Official Owner',
        ownerAddress: 'Sector 21, Gurugram, Haryana',
        vehicleRegNumber: 'HR26SR8899',
        make: 'Yamaha',
        model: 'FZ-S',
        manufactureYear: 2015,
        chassisNumber: 'ME1RG0627F0088991',
        engineNumber: 'G3C8E0088991',
        unhideChassisEngine: false,
      }),
    });
    assert.equal(srCreateRes.status, 201);
    const srCert = ((await srCreateRes.json()) as { certificate: Record<string, unknown> }).certificate;
    assert.equal(srCert.brand, 'scrap_route');
    assert.equal(srCert.certificateNumber, srNext.certificateNumber);
    assert.equal(srCert.scrappingRegNumber, srNext.scrappingRegNumber);

    // 7. Scrap Route PDF must show SCRAP ROUTE ONLY and ZERO Parivahan Scrappers / ZERO website
    const srPdf = await buildCertificatePdfDoc(srCert as never, {
      customDomain: 'https://verify.example.test',
    });
    assert.equal(srPdf.doc.getNumberOfPages(), 1);
    const srStream = extractPdfPageText(srPdf.doc as unknown as { internal: { pages: string[][] } });
    assert.ok(srStream.includes('SCRAP ROUTE'), 'Scrap Route PDF must include SCRAP ROUTE');
    assert.ok(srStream.includes(String(srCert.certificateNumber)), 'Scrap Route PDF must include SR certificate number');
    assert.ok(srStream.includes(String(srCert.scrappingRegNumber)), 'Scrap Route PDF must include SR-REG number');
    assert.equal(
      srStream.toLowerCase().includes('parivahan'),
      false,
      'Scrap Route PDF must NEVER contain Parivahan anywhere'
    );
    assert.equal(
      srStream.toLowerCase().includes('a unit of'),
      false,
      'Scrap Route PDF must NEVER contain "A Unit Of"'
    );
    assert.equal(
      srStream.toLowerCase().includes('scrapping yard'),
      false,
      'Scrap Route PDF must NEVER contain "Scrapping Yard"'
    );
    assert.equal(
      srStream.toLowerCase().includes('netlify.app'),
      false,
      'Scrap Route PDF must NEVER display any website URL'
    );
    assert.equal(
      srStream.includes('https://'),
      false,
      'Scrap Route PDF must NEVER print an https:// website in the PDF text'
    );

    // 8. Public QR Verification for BOTH brands returns verified: true, integrityMatch: true, and accurate brand
    const verifyPs = await fetch(
      `${origin}/api/verify?certificateNumber=${encodeURIComponent(String(psCert.certificateNumber))}&token=${encodeURIComponent(String(psCert.qrToken))}`
    );
    assert.equal(verifyPs.status, 200);
    const verifyPsJson = (await verifyPs.json()) as Record<string, unknown>;
    assert.equal(verifyPsJson.verified, true);
    assert.equal(verifyPsJson.integrityMatch, true);
    assert.equal(verifyPsJson.tokenMatch, true);
    assert.equal(verifyPsJson.brand, 'parivahan');
    assert.equal(verifyPsJson.brandDisplayName, 'Parivahan Scrappers');

    const verifySr = await fetch(
      `${origin}/api/verify?certificateNumber=${encodeURIComponent(String(srCert.certificateNumber))}&token=${encodeURIComponent(String(srCert.qrToken))}`
    );
    assert.equal(verifySr.status, 200);
    const verifySrJson = (await verifySr.json()) as Record<string, unknown>;
    assert.equal(verifySrJson.verified, true);
    assert.equal(verifySrJson.integrityMatch, true);
    assert.equal(verifySrJson.tokenMatch, true);
    assert.equal(verifySrJson.brand, 'scrap_route');
    assert.equal(verifySrJson.brandDisplayName, 'SCRAP ROUTE');

    // 9. Brand immutability on Maker Edit AND Admin Edit (HTTP 403 if brand switch attempted)
    const makerBrandSwitch = await fetch(`${origin}/api/certificates/${srCert.id}`, {
      method: 'PUT',
      headers: {
        'Content-Type': 'application/json',
        'X-Requested-With': 'XMLHttpRequest',
        Cookie: combinedCookie,
      },
      body: JSON.stringify({ brand: 'parivahan', ownerName: 'Attempt Switch' }),
    });
    assert.equal(makerBrandSwitch.status, 403, 'Maker must not be able to change certificate brand on edit');

    const makerValidSrEdit = await fetch(`${origin}/api/certificates/${srCert.id}`, {
      method: 'PUT',
      headers: {
        'Content-Type': 'application/json',
        'X-Requested-With': 'XMLHttpRequest',
        Cookie: combinedCookie,
      },
      body: JSON.stringify({ ownerName: 'Scrap Route Updated Owner' }),
    });
    assert.equal(makerValidSrEdit.status, 200);
    const updatedSr = ((await makerValidSrEdit.json()) as { certificate: Record<string, unknown> }).certificate;
    assert.equal(updatedSr.brand, 'scrap_route', 'Edited Scrap Route certificate must preserve brand');

    // Admin unlock still works and Admin edit also blocks brand switching
    const adminUnlock = await fetch(`${origin}/api/auth/admin-unlock`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-Requested-With': 'XMLHttpRequest' },
      body: JSON.stringify({ password: adminPass }),
    });
    assert.equal(adminUnlock.status, 200);
    const adminToken = ((await adminUnlock.json()) as { token: string }).token;

    const adminBrandSwitch = await fetch(`${origin}/api/admin/certificates/${psCert.id}`, {
      method: 'PUT',
      headers: {
        'Content-Type': 'application/json',
        'X-Requested-With': 'XMLHttpRequest',
        Authorization: `Bearer ${adminToken}`,
      },
      body: JSON.stringify({
        updates: { brand: 'scrap_route', ownerName: 'Admin Switch Attempt' },
        reason: 'Testing brand immutability guard',
        protectedPassword: adminPass,
      }),
    });
    assert.equal(adminBrandSwitch.status, 403, 'Admin edit must not allow switching certificate brand');

    // 10. Locking Scrap Route revokes Scrap Route access immediately WITHOUT logging out Maker
    const lockRes = await fetch(`${origin}/api/auth/scrap-route/lock`, {
      method: 'POST',
      headers: { 'X-Requested-With': 'XMLHttpRequest', Cookie: combinedCookie },
    });
    assert.equal(lockRes.status, 200);

    const srAfterLock = await fetch(
      `${origin}/api/certificates/next-numbers?brand=scrap_route&issueDate=2026-11-27`,
      { headers: { Cookie: sessionCookiePair, 'X-Requested-With': 'XMLHttpRequest' } }
    );
    assert.equal(srAfterLock.status, 403, 'Locked Scrap Route must reject SR requests');

    const psStillWorks = await fetch(
      `${origin}/api/certificates/next-numbers?brand=parivahan&issueDate=2026-11-27`,
      { headers: { Cookie: sessionCookiePair, 'X-Requested-With': 'XMLHttpRequest' } }
    );
    assert.equal(psStillWorks.status, 200, 'Locking Scrap Route must NOT log out the Maker session');

    // 11. Brute-force rate limiting on /api/auth/scrap-route/verify-pin (429 after 5 failed attempts)
    let rateLimited = false;
    for (let i = 0; i < 6; i++) {
      const attempt = await fetch(`${origin}/api/auth/scrap-route/verify-pin`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-Requested-With': 'XMLHttpRequest',
          Cookie: sessionCookiePair,
        },
        body: JSON.stringify({ pin: `BAD-${i}` }),
      });
      if (attempt.status === 429) {
        rateLimited = true;
        break;
      }
      assert.equal(attempt.status, 401);
    }
    assert.equal(rateLimited, true, 'Scrap Route PIN endpoint must rate-limit repeated failed attempts (429)');

    // 12. Logout immediately invalidates the Remember Me 30-day session cookie server-side
    const logoutRes = await fetch(`${origin}/api/auth/logout`, {
      method: 'POST',
      headers: { 'X-Requested-With': 'XMLHttpRequest', Cookie: sessionCookiePair },
    });
    assert.equal(logoutRes.status, 200);
    const logoutCookies = extractCookies(logoutRes).join('\n');
    assert.ok(logoutCookies.includes('ps_session='), 'Logout must clear ps_session cookie');
    assert.ok(logoutCookies.includes('ps_sr_auth='), 'Logout must clear ps_sr_auth cookie');

    const afterLogout = await fetch(`${origin}/api/certificates/next-numbers?brand=parivahan`, {
      headers: { Cookie: sessionCookiePair, 'X-Requested-With': 'XMLHttpRequest' },
    });
    assert.equal(afterLogout.status, 401, 'Logged-out Remember Me cookie must be immediately rejected');
  } finally {
    await new Promise<void>((resolve) => srv.close(() => resolve()));
    for (const [k, v] of Object.entries(savedEnv)) {
      if (v === undefined) delete process.env[k];
      else process.env[k] = v;
    }
    resetStoreForTesting();
  }
}

async function runDataProtectionIntegrityAndRecoveryTests(): Promise<void> {
  const crypto = await import('node:crypto');
  const { resetStoreForTesting, getStore } = await import('../src/server/store.js');
  const { runReadOnlyIntegrityAudit } = await import('../src/server/integrity.js');
  const { clearAllAuthFailures } = await import('../src/server/rateLimit.js');

  const savedEnv = {
    SCRAP_ROUTE_PIN: process.env.SCRAP_ROUTE_PIN,
    SCRAP_ROUTE_PIN_HASH: process.env.SCRAP_ROUTE_PIN_HASH,
    ADMIN_SESSION_SECRET: process.env.ADMIN_SESSION_SECRET,
  };

  const srPin = `SR-${crypto.randomBytes(4).toString('hex')}`;
  process.env.SCRAP_ROUTE_PIN = srPin;
  delete process.env.SCRAP_ROUTE_PIN_HASH;
  process.env.ADMIN_SESSION_SECRET = crypto.randomBytes(32).toString('hex');
  resetStoreForTesting();
  clearAllAuthFailures();

  const app = createApiApp();
  const srv = http.createServer(app);
  await new Promise<void>((resolve) => srv.listen(0, '127.0.0.1', resolve));
  const addr = srv.address();
  if (!addr || typeof addr === 'string') throw new Error('Failed to bind data protection test server');
  const origin = `http://127.0.0.1:${addr.port}`;

  const reqJson = async (
    p: string,
    opts: { method?: string; body?: unknown; token?: string; headers?: Record<string, string> } = {}
  ) => {
    const headers: Record<string, string> = {
      'X-Requested-With': 'XMLHttpRequest',
      ...(opts.headers ?? {}),
    };
    if (opts.body !== undefined) headers['Content-Type'] = 'application/json';
    if (opts.token) headers['Authorization'] = `Bearer ${opts.token}`;
    const res = await fetch(`${origin}${p}`, {
      method: opts.method ?? 'GET',
      headers,
      body: opts.body !== undefined ? JSON.stringify(opts.body) : undefined,
    });
    const text = await res.text();
    let json: Record<string, unknown> = {};
    try {
      json = text ? (JSON.parse(text) as Record<string, unknown>) : {};
    } catch {
      json = { raw: text };
    }
    return { status: res.status, headers: res.headers, json, raw: text };
  };

  try {
    // 1. Bootstrap credentials
    const makerPass = 'MakerProtect#2026';
    const adminPass = 'AdminProtect#2026';
    const protPass = 'DeleteProtect#2026';
    const boot = await reqJson('/api/auth/bootstrap', {
      method: 'POST',
      body: {
        makerUsername: 'user-pscrappers',
        makerPassword: makerPass,
        mainAdminPassword: adminPass,
        protectedPassword: protPass,
      },
    });
    assert.equal(boot.status, 201);

    // 2. Login Maker (device A) + Login Maker (device B) to verify cross-device persistence
    const loginA = await reqJson('/api/auth/login', {
      method: 'POST',
      body: { username: 'user-pscrappers', password: makerPass },
    });
    assert.equal(loginA.status, 200);
    const makerTokenA = String(loginA.json.token);

    const loginB = await reqJson('/api/auth/login', {
      method: 'POST',
      body: { username: 'user-pscrappers', password: makerPass },
    });
    assert.equal(loginB.status, 200);
    const makerTokenB = String(loginB.json.token);

    // Unlock Scrap Route PIN for Maker A
    const pinRes = await reqJson('/api/auth/scrap-route/verify-pin', {
      method: 'POST',
      token: makerTokenA,
      body: { pin: srPin },
    });
    assert.equal(pinRes.status, 200);
    const srToken = String(pinRes.json.scrapRouteToken);

    // 3. Create Parivahan + Scrap Route certificates with post-write read-back verification
    const psCreate = await reqJson('/api/certificates', {
      method: 'POST',
      token: makerTokenA,
      headers: { 'Idempotency-Key': 'dp_ps_1' },
      body: {
        brand: 'parivahan',
        issueDate: '2026-11-27',
        handoverDate: '2026-11-26',
        ownerName: 'Original Parivahan Owner',
        ownerAddress: 'Sector 18, Gurugram',
        vehicleRegNumber: 'HR26DP1001',
        make: 'Hero MotoCorp',
        model: 'Splendor',
        manufactureYear: 2013,
        chassisNumber: 'MBLHA10DP00001001',
        engineNumber: 'HA10EDP0001001',
        unhideChassisEngine: false,
      },
    });
    assert.equal(psCreate.status, 201);
    assert.equal(psCreate.json.verifiedReadBack, true, 'Issuance must confirm post-write read-back verification');
    const psCert = psCreate.json.certificate as Record<string, unknown>;
    assert.ok(psCert.originalRecord, 'Immutable originalRecord (v1) must be stored on creation');

    // Network retry with same Idempotency-Key returns exact same record with zero duplicates
    const psRetry = await reqJson('/api/certificates', {
      method: 'POST',
      token: makerTokenA,
      headers: { 'Idempotency-Key': 'dp_ps_1' },
      body: {
        brand: 'parivahan',
        issueDate: '2026-11-27',
        handoverDate: '2026-11-26',
        ownerName: 'Original Parivahan Owner',
        vehicleRegNumber: 'HR26DP1001',
        make: 'Hero MotoCorp',
        model: 'Splendor',
        manufactureYear: 2013,
        chassisNumber: 'MBLHA10DP00001001',
        engineNumber: 'HA10EDP0001001',
      },
    });
    assert.equal(psRetry.status, 200);
    assert.equal(psRetry.json.idempotentReplay, true);
    assert.equal((psRetry.json.certificate as Record<string, unknown>).id, psCert.id);

    const srCreate = await reqJson('/api/certificates', {
      method: 'POST',
      token: makerTokenA,
      headers: { 'Idempotency-Key': 'dp_sr_1', 'X-Scrap-Route-Auth': srToken },
      body: {
        brand: 'scrap_route',
        issueDate: '2026-11-27',
        handoverDate: '2026-11-26',
        ownerName: 'Original Scrap Route Owner',
        vehicleRegNumber: 'HR26SR2002',
        make: 'Honda',
        model: 'Activa',
        manufactureYear: 2014,
        chassisNumber: 'ME4JF50DP00002002',
        engineNumber: 'JF50EDP0002002',
      },
    });
    assert.equal(srCreate.status, 201);
    assert.equal(srCreate.json.verifiedReadBack, true);
    const srCert = srCreate.json.certificate as Record<string, unknown>;

    // Cross-device persistence: Maker B sees both authoritative records immediately
    const recentB = await reqJson('/api/certificates/recent', { token: makerTokenB });
    assert.equal(recentB.status, 200);
    assert.equal((recentB.json.certificates as unknown[]).length, 2);

    // 4. Modify certificate -> preserves immutable v1 originalRecord, logs changedFields & append-only version doc
    const editRes = await reqJson(`/api/certificates/${psCert.id}`, {
      method: 'PUT',
      token: makerTokenA,
      body: {
        ownerName: 'Corrected Parivahan Owner',
        reason: 'Spelling correction from verified RC document',
      },
    });
    assert.equal(editRes.status, 200);
    const editedPs = editRes.json.certificate as Record<string, unknown>;
    assert.equal(editedPs.version, 2);
    const origSnap = editedPs.originalRecord as { version: number; data: { ownerName: string } };
    assert.equal(origSnap.version, 1);
    assert.equal(origSnap.data.ownerName, 'Original Parivahan Owner', 'Original v1 ownerName must remain immutable');

    // Public QR verification reflects v2 + originalIssuedAt + versionHistoryCount
    const verifyV2 = await reqJson(
      `/api/verify?certificateNumber=${encodeURIComponent(String(editedPs.certificateNumber))}&token=${encodeURIComponent(String(editedPs.qrToken))}`
    );
    assert.equal(verifyV2.status, 200);
    assert.equal(verifyV2.json.verified, true);
    assert.equal(verifyV2.json.version, 2);
    assert.equal(verifyV2.json.versionHistoryCount, 1);
    assert.ok(typeof verifyV2.json.originalIssuedAt === 'string');

    // 5. Maker CANNOT permanently delete (blocked 403), CAN only Archive (reversible)
    const makerPermBlock = await reqJson(`/api/certificates/${psCert.id}`, {
      method: 'DELETE',
      token: makerTokenA,
      body: { permanent: true, reason: 'Maker attempting permanent delete' },
    });
    assert.equal(makerPermBlock.status, 403, 'Maker must NEVER be able to permanently delete a certificate');

    const makerArchive = await reqJson(`/api/certificates/${psCert.id}`, {
      method: 'DELETE',
      token: makerTokenA,
      body: { reason: 'Archiving test certificate' },
    });
    assert.equal(makerArchive.status, 200);

    // Main Core Admin unlocks & inspects history, integrity monitor, archive restore, staging verify & export
    const adminUnlock = await reqJson('/api/auth/admin-unlock', {
      method: 'POST',
      body: { password: adminPass },
    });
    assert.equal(adminUnlock.status, 200);
    const adminToken = String(adminUnlock.json.token);

    // Owner-only version history endpoint returns immutable v1 + modification snapshot + append-only lifecycle events
    const historyRes = await reqJson(`/api/admin/certificates/${psCert.id}/history`, { token: adminToken });
    assert.equal(historyRes.status, 200);
    assert.equal((historyRes.json.originalRecord as { version: number }).version, 1);
    assert.equal((historyRes.json.versionHistory as unknown[]).length, 1);
    const appendOnly = historyRes.json.appendOnlyVersions as Array<{ event: string }>;
    assert.ok(appendOnly.some((e) => e.event === 'ISSUED'), 'Append-only versions must include ISSUED');
    assert.ok(appendOnly.some((e) => e.event === 'MODIFIED'), 'Append-only versions must include MODIFIED');
    assert.ok(appendOnly.some((e) => e.event === 'ARCHIVED'), 'Append-only versions must include ARCHIVED');

    // Restore archived certificate
    const restoreRes = await reqJson(`/api/admin/certificates/${psCert.id}/restore`, {
      method: 'POST',
      token: adminToken,
      body: { protectedPassword: protPass, reason: 'Restoring archived certificate' },
    });
    assert.equal(restoreRes.status, 200);
    assert.equal((restoreRes.json.certificate as Record<string, unknown>).status, 'ACTIVE');

    // 6. Bulk deletion payload is strictly rejected (400)
    const bulkBlock = await reqJson(`/api/admin/certificates/${srCert.id}`, {
      method: 'DELETE',
      token: adminToken,
      body: {
        ids: [psCert.id, srCert.id],
        deletePassword: protPass,
        reason: 'Bulk delete attempt must fail',
      },
    });
    assert.equal(bulkBlock.status, 400, 'Bulk delete payloads must be strictly rejected');

    // 7. Create verified backup -> run Isolated Staging Restore Verification -> run Owner JSON Export
    const bkpRes = await reqJson('/api/admin/backups/create', { method: 'POST', token: adminToken });
    assert.equal(bkpRes.status, 201);
    const backup = bkpRes.json.backup as { id: string; verified: boolean };
    assert.equal(backup.verified, true, 'Backup must pass post-write read-back verification');

    const stagingRes = await reqJson(`/api/admin/backups/${backup.id}/staging-verify`, {
      method: 'POST',
      token: adminToken,
    });
    assert.equal(stagingRes.status, 200);
    const staging = stagingRes.json.stagingResult as Record<string, unknown>;
    assert.equal(staging.checksumValid, true);
    assert.equal(staging.stagingRestoredCount, 2);
    assert.equal(staging.stagingParivahanCount, 1);
    assert.equal(staging.stagingScrapRouteCount, 1);
    assert.equal(staging.stagingIntegrityHealthy, true);
    assert.equal(staging.safeForProductionRecovery, true);

    const exportRes = await reqJson('/api/admin/export', { token: adminToken });
    assert.equal(exportRes.status, 200);
    assert.ok(exportRes.headers.get('x-export-sha256'), 'Owner export must include X-Export-SHA256 checksum header');
    assert.equal((exportRes.json.certificates as unknown[]).length, 2);

    // Maker blocked from integrity monitor & owner export (403)
    const makerMonitorBlock = await reqJson('/api/admin/integrity-monitor', { token: makerTokenA });
    assert.equal(makerMonitorBlock.status, 403);
    const makerExportBlock = await reqJson('/api/admin/export', { token: makerTokenA });
    assert.equal(makerExportBlock.status, 403);

    // 8. Read-Only Integrity Monitor reports healthy counts before corruption
    const monitorHealthy = await reqJson('/api/admin/integrity-monitor', { token: adminToken });
    assert.equal(monitorHealthy.status, 200);
    const reportHealthy = monitorHealthy.json.report as {
      healthy: boolean;
      readOnly: boolean;
      counts: {
        parivahanCertificates: number;
        scrapRouteCertificates: number;
        activeCertificates: number;
        modifiedCertificates: number;
        integrityMismatches: number;
      };
    };
    assert.equal(reportHealthy.readOnly, true);
    assert.equal(reportHealthy.healthy, true);
    assert.equal(reportHealthy.counts.parivahanCertificates, 1);
    assert.equal(reportHealthy.counts.scrapRouteCertificates, 1);
    assert.equal(reportHealthy.counts.activeCertificates, 2);
    assert.equal(reportHealthy.counts.modifiedCertificates, 1);
    assert.equal(reportHealthy.counts.integrityMismatches, 0);

    // 9. Integrity gate blocks permanent deletion when corruption exists, and read-only audit NEVER mutates the corrupted record
    const store = getStore();
    const srDoc = await store.getCertificateById(String(srCert.id));
    assert.ok(srDoc);
    const originalHash = srDoc.canonicalHash;
    await store.saveCertificate({ ...srDoc, canonicalHash: '0'.repeat(64) });

    const auditCorrupt = await runReadOnlyIntegrityAudit(store);
    assert.equal(auditCorrupt.healthy, false, 'Integrity audit must detect SHA-256 mismatch');
    assert.equal(auditCorrupt.counts.integrityMismatches, 1);
    const afterAuditDoc = await store.getCertificateById(String(srCert.id));
    assert.equal(
      afterAuditDoc?.canonicalHash,
      '0'.repeat(64),
      'Read-only integrity audit must NEVER automatically repair or mutate any record'
    );

    const blockedPermDelete = await reqJson(`/api/admin/certificates/${srCert.id}`, {
      method: 'DELETE',
      token: adminToken,
      body: {
        mainAdminPassword: adminPass,
        deletePassword: protPass,
        confirmCertificateNumber: String(srCert.certificateNumber),
        confirmPhrase: 'PERMANENT DELETE',
        reason: 'Testing integrity health gate on permanent delete',
        permanent: true,
      },
    });
    assert.equal(
      blockedPermDelete.status,
      409,
      'Permanent deletion must be blocked (409) when database integrity health check fails'
    );

    // Restore hash so integrity is healthy again, then verify permanent delete succeeds with verified safety backup
    await store.saveCertificate({ ...srDoc, canonicalHash: originalHash });
    const allowedPermDelete = await reqJson(`/api/admin/certificates/${srCert.id}`, {
      method: 'DELETE',
      token: adminToken,
      body: {
        mainAdminPassword: adminPass,
        deletePassword: protPass,
        confirmCertificateNumber: String(srCert.certificateNumber),
        confirmPhrase: 'PERMANENT DELETE',
        reason: 'Owner-authorized permanent delete after integrity verified healthy',
        permanent: true,
      },
    });
    assert.equal(allowedPermDelete.status, 200);
    assert.equal(allowedPermDelete.json.permanent, true);
    assert.ok(typeof allowedPermDelete.json.safetyBackupId === 'string');

    // Verify Scrap Route deleted number stays permanently reserved
    assert.equal(await store.isCertNumberReserved(String(srCert.certificateNumber)), true);
    assert.equal(await store.isScrappingRegReserved(String(srCert.scrappingRegNumber)), true);
  } finally {
    await new Promise<void>((resolve) => srv.close(() => resolve()));
    for (const [k, v] of Object.entries(savedEnv)) {
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
