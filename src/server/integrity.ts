import type {
  CertificateCoreFields,
  CertificateRecord,
  DatabaseIntegrityReport,
  IntegrityDiscrepancy,
  StagingRestoreVerificationResult,
} from '../shared/types.js';
import {
  computeCanonicalHash,
  computeSha256,
  resolveCertificateBrand,
  timingSafeStringEqual,
} from './crypto.js';
import { StagingMemoryStore, type RegistryStore } from './store.js';

export function extractCertificateCoreFields(cert: CertificateRecord): CertificateCoreFields {
  return {
    ownerName: cert.ownerName,
    ownerAddress: cert.ownerAddress,
    idProofType: cert.idProofType,
    idProofNumber: cert.idProofNumber,
    vehicleRegNumber: cert.vehicleRegNumber,
    make: cert.make,
    model: cert.model,
    manufactureYear: cert.manufactureYear,
    chassisNumber: cert.chassisNumber,
    engineNumber: cert.engineNumber,
    unhideChassisEngine: cert.unhideChassisEngine,
    rtoAuthority: cert.rtoAuthority,
    issueDate: cert.issueDate,
    handoverDate: cert.handoverDate,
    facilityName: cert.facilityName,
    facilityAddress: cert.facilityAddress,
    remarks: cert.remarks,
  };
}

export function computeChangedCertificateFields(
  previous: CertificateCoreFields,
  next: CertificateCoreFields
): string[] {
  const keys: Array<keyof CertificateCoreFields> = [
    'ownerName',
    'ownerAddress',
    'idProofType',
    'idProofNumber',
    'vehicleRegNumber',
    'make',
    'model',
    'manufactureYear',
    'chassisNumber',
    'engineNumber',
    'unhideChassisEngine',
    'rtoAuthority',
    'issueDate',
    'handoverDate',
    'facilityName',
    'facilityAddress',
    'remarks',
  ];
  const changed: string[] = [];
  for (const key of keys) {
    const prevVal = previous[key] ?? '';
    const nextVal = next[key] ?? '';
    if (String(prevVal) !== String(nextVal)) {
      changed.push(key);
    }
  }
  return changed;
}

/**
 * STRICTLY READ-ONLY DATABASE INTEGRITY AUDIT.
 * Never repairs, modifies, deletes, overwrites, or normalizes any document.
 */
export async function runReadOnlyIntegrityAudit(
  store: RegistryStore
): Promise<DatabaseIntegrityReport> {
  const auditedAt = new Date().toISOString();
  const [probe, certs, reserved, backups, auditLogs, systemErrors] = await Promise.all([
    store.ping(),
    store.getAllCertificates(),
    store.getAllReservedNumbers(),
    store.listBackups(),
    store.getAuditLogs(500),
    store.getSystemErrors(200),
  ]);

  const discrepancies: IntegrityDiscrepancy[] = [];
  const seenCertNumbers = new Map<string, string>();
  const seenRegNumbers = new Map<string, string>();
  const reservedCertSet = new Set(
    reserved.certNumbers.map((r) => r.certificateNumber.trim().toUpperCase())
  );
  const reservedRegSet = new Set(
    reserved.regNumbers.map((r) => r.scrappingRegNumber.trim().toUpperCase())
  );

  let parivahanCertificates = 0;
  let scrapRouteCertificates = 0;
  let activeCertificates = 0;
  let archivedCertificates = 0;
  let cancelledCertificates = 0;
  let modifiedCertificates = 0;
  let integrityMismatches = 0;
  let missingDrivePdfs = 0;

  for (const cert of certs) {
    const brand = resolveCertificateBrand(cert);
    if (brand === 'scrap_route') {
      scrapRouteCertificates++;
    } else {
      parivahanCertificates++;
    }

    if (cert.status === 'ACTIVE') activeCertificates++;
    else if (cert.status === 'SOFT_DELETED') archivedCertificates++;
    else if (cert.status === 'CANCELLED') cancelledCertificates++;

    if (cert.version > 1 || (cert.versionHistory && cert.versionHistory.length > 0)) {
      modifiedCertificates++;
    }

    // 1. Required fields check
    const requiredTextFields: Array<[string, unknown]> = [
      ['id', cert.id],
      ['certificateNumber', cert.certificateNumber],
      ['scrappingRegNumber', cert.scrappingRegNumber],
      ['ownerName', cert.ownerName],
      ['vehicleRegNumber', cert.vehicleRegNumber],
      ['make', cert.make],
      ['model', cert.model],
      ['chassisNumber', cert.chassisNumber],
      ['engineNumber', cert.engineNumber],
      ['issueDate', cert.issueDate],
      ['handoverDate', cert.handoverDate],
      ['qrToken', cert.qrToken],
      ['canonicalHash', cert.canonicalHash],
      ['createdAt', cert.createdAt],
    ];
    for (const [field, val] of requiredTextFields) {
      if (typeof val !== 'string' || !val.trim()) {
        integrityMismatches++;
        discrepancies.push({
          severity: 'CRITICAL',
          code: 'MISSING_REQUIRED_FIELD',
          certificateId: cert.id,
          certificateNumber: cert.certificateNumber,
          message: `Missing required field "${field}" on certificate ${cert.certificateNumber || cert.id}.`,
        });
      }
    }

    const normalizedCertNo = (cert.certificateNumber || '').trim().toUpperCase();
    const normalizedRegNo = (cert.scrappingRegNumber || '').trim().toUpperCase();

    // 2. Duplicate certificate & scrapping reg number detection
    if (normalizedCertNo) {
      const existingOwnerId = seenCertNumbers.get(normalizedCertNo);
      if (existingOwnerId) {
        integrityMismatches++;
        discrepancies.push({
          severity: 'CRITICAL',
          code: 'DUPLICATE_CERTIFICATE_NUMBER',
          certificateId: cert.id,
          certificateNumber: normalizedCertNo,
          message: `Duplicate certificate number ${normalizedCertNo} detected across documents ${existingOwnerId} and ${cert.id}.`,
        });
      } else {
        seenCertNumbers.set(normalizedCertNo, cert.id);
      }
    }

    if (normalizedRegNo) {
      const existingRegOwnerId = seenRegNumbers.get(normalizedRegNo);
      if (existingRegOwnerId) {
        integrityMismatches++;
        discrepancies.push({
          severity: 'CRITICAL',
          code: 'DUPLICATE_SCRAPPING_REG_NUMBER',
          certificateId: cert.id,
          certificateNumber: normalizedCertNo,
          message: `Duplicate scrapping registration number ${normalizedRegNo} detected across documents ${existingRegOwnerId} and ${cert.id}.`,
        });
      } else {
        seenRegNumbers.set(normalizedRegNo, cert.id);
      }
    }

    // 3. Brand identity vs certificate number prefix consistency
    const isSrPrefix = normalizedCertNo.startsWith('SR/');
    const isPsPrefix = normalizedCertNo.startsWith('PS/');
    if (
      (brand === 'scrap_route' && !isSrPrefix) ||
      (brand === 'parivahan' && isSrPrefix) ||
      (!isSrPrefix && !isPsPrefix && normalizedCertNo.length > 0)
    ) {
      integrityMismatches++;
      discrepancies.push({
        severity: 'CRITICAL',
        code: 'BRAND_PREFIX_MISMATCH',
        certificateId: cert.id,
        certificateNumber: normalizedCertNo,
        message: `Brand "${brand}" does not match certificate number prefix "${normalizedCertNo}".`,
      });
    }

    // 4. SHA-256 canonical integrity hash verification (against current version)
    if (cert.canonicalHash) {
      const recomputed = computeCanonicalHash(cert);
      if (!timingSafeStringEqual(recomputed, cert.canonicalHash)) {
        integrityMismatches++;
        discrepancies.push({
          severity: 'CRITICAL',
          code: 'SHA256_HASH_MISMATCH',
          certificateId: cert.id,
          certificateNumber: normalizedCertNo,
          message: `SHA-256 canonical hash mismatch on ${normalizedCertNo} (v${cert.version}).`,
          details: `Stored=${cert.canonicalHash.slice(0, 16)}..., Recomputed=${recomputed.slice(0, 16)}...`,
        });
      }
    }

    // 5. Version history consistency check
    if (cert.version > 1 && (!cert.versionHistory || cert.versionHistory.length === 0)) {
      discrepancies.push({
        severity: 'WARNING',
        code: 'VERSION_HISTORY_MISMATCH',
        certificateId: cert.id,
        certificateNumber: normalizedCertNo,
        message: `Certificate ${normalizedCertNo} is at version ${cert.version} but has an empty versionHistory array.`,
      });
    }

    // 6. Reserved number cross-check (ensures issued numbers are permanently locked)
    if (normalizedCertNo && !reservedCertSet.has(normalizedCertNo)) {
      discrepancies.push({
        severity: 'WARNING',
        code: 'MISSING_RESERVED_CERT_NUMBER',
        certificateId: cert.id,
        certificateNumber: normalizedCertNo,
        message: `Issued certificate number ${normalizedCertNo} is missing from reserved_certificate_numbers.`,
      });
    }
    if (normalizedRegNo && !reservedRegSet.has(normalizedRegNo)) {
      discrepancies.push({
        severity: 'WARNING',
        code: 'MISSING_RESERVED_REG_NUMBER',
        certificateId: cert.id,
        certificateNumber: normalizedCertNo,
        message: `Issued registration number ${normalizedRegNo} is missing from reserved_scrapping_numbers.`,
      });
    }

    // 7. Missing Drive PDF detection (NEVER deletes or modifies Firestore record)
    if (cert.driveSyncStatus === 'FAILED') {
      missingDrivePdfs++;
      discrepancies.push({
        severity: 'WARNING',
        code: 'MISSING_DRIVE_PDF',
        certificateId: cert.id,
        certificateNumber: normalizedCertNo,
        message: `Google Drive PDF copy failed for ${normalizedCertNo}. Authoritative Firestore record is intact and PDF can be regenerated anytime.`,
        details: cert.driveLastError,
      });
    }
  }

  // 8. Compare counts against audit logs & failed issuance tracking
  const failedIssuanceFromAudit = auditLogs.filter(
    (l) => l.action === 'CERTIFICATE_ISSUANCE_FAILED'
  ).length;
  const failedIssuanceFromErrors = systemErrors.filter(
    (e) => e.route.includes('/certificates') && e.method === 'POST'
  ).length;
  const failedIssuanceAttempts = Math.max(failedIssuanceFromAudit, failedIssuanceFromErrors);

  const createdEventsInRecentAudit = auditLogs.filter(
    (l) => l.action === 'CERTIFICATE_CREATED'
  ).length;
  const permanentDeleteEventsInRecentAudit = auditLogs.filter(
    (l) => l.action === 'CERTIFICATE_PERMANENTLY_DELETED'
  ).length;

  // Backup health analysis
  const verifiedBackups = backups.filter((b) => b.verified);
  const latestBackup = backups[0] ?? null;
  const latestVerifiedBackup = verifiedBackups[0] ?? null;
  const backupFailureLogs = auditLogs.filter((l) => l.action === 'BACKUP_FAILED');
  const lastBackupFailure = backupFailureLogs[0] ?? null;

  if (certs.length > 0 && verifiedBackups.length === 0) {
    discrepancies.push({
      severity: 'WARNING',
      code: 'BACKUP_UNVERIFIED_OR_MISSING',
      message: 'No verified database backup snapshot exists yet for the current certificate registry.',
    });
  } else if (latestBackup && !latestBackup.verified) {
    discrepancies.push({
      severity: 'WARNING',
      code: 'BACKUP_UNVERIFIED_OR_MISSING',
      message: `Latest backup snapshot (${latestBackup.id}) is marked unverified. Last verified backup: ${latestVerifiedBackup?.id ?? 'none'}.`,
    });
  }

  if (
    latestVerifiedBackup &&
    latestVerifiedBackup.certificateCount > certs.length + permanentDeleteEventsInRecentAudit
  ) {
    discrepancies.push({
      severity: 'WARNING',
      code: 'COUNT_AUDIT_DISCREPANCY',
      message: `Current certificate count (${certs.length}) is lower than latest verified backup (${latestVerifiedBackup.certificateCount}) beyond recent permanent deletions (${permanentDeleteEventsInRecentAudit}).`,
    });
  }

  const criticalCount = discrepancies.filter((d) => d.severity === 'CRITICAL').length;
  const healthy = probe.ok && criticalCount === 0 && integrityMismatches === 0;

  return {
    auditedAt,
    readOnly: true,
    healthy,
    storageMode: store.mode,
    firestoreConnected: store.mode === 'firestore' ? probe.ok : probe.ok,
    firestoreProjectId: store.projectId,
    firestoreDatabaseId: store.databaseId,
    counts: {
      totalCertificates: certs.length,
      parivahanCertificates,
      scrapRouteCertificates,
      activeCertificates,
      archivedCertificates,
      cancelledCertificates,
      reservedCertNumbers: reserved.certNumbers.length,
      reservedRegNumbers: reserved.regNumbers.length,
      failedIssuanceAttempts,
      modifiedCertificates,
      integrityMismatches,
      missingDrivePdfs,
    },
    auditComparison: {
      createdEventsInRecentAudit,
      permanentDeleteEventsInRecentAudit,
      latestBackupCertificateCount: latestVerifiedBackup?.certificateCount ?? null,
      latestBackupId: latestVerifiedBackup?.id ?? null,
    },
    backupHealth: {
      totalBackups: backups.length,
      lastSuccessfulBackupAt: latestVerifiedBackup?.createdAt ?? null,
      lastBackupVerified: Boolean(latestVerifiedBackup?.verified),
      recentBackupFailures: backupFailureLogs.length,
      lastBackupFailureAt: lastBackupFailure?.timestamp ?? null,
      lastBackupFailureMessage: lastBackupFailure?.reason ?? null,
    },
    lastIntegrityAuditAt: auditedAt,
    discrepancies,
    firebasePlanNotes: {
      managedScheduledBackupsRequireBlaze: true,
      pitrRequiresBlaze: true,
      activeProtectionStrategy:
        'Verified daily automated backups via Vercel Cron (/api/cron/backup) + chunked gzipped SHA-256 Firestore snapshots + owner JSON export & isolated staging restore verification (compatible with Firebase Spark free plan without upgrading billing).',
    },
  };
}

/**
 * Restores a backup snapshot into a completely isolated ephemeral staging database
 * and runs a full read-only integrity audit on the restored staging data BEFORE
 * any production recovery is permitted. Never modifies production data.
 */
export async function verifyBackupInStaging(
  productionStore: RegistryStore,
  backupId: string
): Promise<StagingRestoreVerificationResult> {
  const verifiedAt = new Date().toISOString();
  const warnings: string[] = [];

  const [downloaded, allBackups] = await Promise.all([
    productionStore.getBackupDownload(backupId),
    productionStore.listBackups(),
  ]);

  const meta = allBackups.find((b) => b.id === backupId);
  const computedChecksum = computeSha256(downloaded.payloadJson);
  const checksumValid =
    computedChecksum === downloaded.sha256Checksum &&
    (!meta || meta.sha256Checksum === computedChecksum);

  if (!checksumValid) {
    warnings.push('Backup payload SHA-256 checksum failed verification. Do NOT restore to production.');
  }

  // Restore into a completely isolated separate staging store
  const stagingStore = new StagingMemoryStore();
  const { restoredCount } = stagingStore.importBackupIntoStaging(downloaded.payloadJson);

  // Run full read-only integrity audit inside staging
  const stagingAudit = await runReadOnlyIntegrityAudit(stagingStore);

  if (meta && restoredCount !== meta.certificateCount) {
    warnings.push(
      `Restored staging count (${restoredCount}) differs from snapshot metadata count (${meta.certificateCount}).`
    );
  }
  if (stagingAudit.counts.integrityMismatches > 0) {
    warnings.push(
      `Staging integrity audit detected ${stagingAudit.counts.integrityMismatches} integrity mismatch(es).`
    );
  }

  // Filter out the expected "no backups inside fresh staging store" warning
  const relevantDiscrepancies = stagingAudit.discrepancies.filter(
    (d) => d.code !== 'BACKUP_UNVERIFIED_OR_MISSING'
  );
  const criticalDiscrepancies = relevantDiscrepancies.filter((d) => d.severity === 'CRITICAL');
  const stagingIntegrityHealthy =
    criticalDiscrepancies.length === 0 && stagingAudit.counts.integrityMismatches === 0;
  const safeForProductionRecovery = checksumValid && stagingIntegrityHealthy;

  return {
    backupId,
    verifiedAt,
    stagingEnvironment: 'isolated_ephemeral_staging_store',
    checksumValid,
    stagingRestoredCount: restoredCount,
    stagingParivahanCount: stagingAudit.counts.parivahanCertificates,
    stagingScrapRouteCount: stagingAudit.counts.scrapRouteCertificates,
    stagingActiveCount: stagingAudit.counts.activeCertificates,
    stagingArchivedCount: stagingAudit.counts.archivedCertificates,
    stagingReservedCertCount: stagingAudit.counts.reservedCertNumbers,
    stagingIntegrityHealthy,
    stagingIntegrityMismatches: stagingAudit.counts.integrityMismatches,
    safeForProductionRecovery,
    warnings,
    discrepancies: relevantDiscrepancies,
  };
}
