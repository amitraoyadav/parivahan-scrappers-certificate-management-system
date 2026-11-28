import crypto from 'node:crypto';
import { gunzipSync, gzipSync } from 'node:zlib';
import type {
  AuditLogEntry,
  BackupDryRunResult,
  BackupSnapshot,
  CertificateBrand,
  CertificateRecord,
  CertificateVersionDocument,
  DriveSyncLog,
  SystemErrorLog,
  SystemSettings,
  UserRole,
} from '../shared/types.js';
import { computeSha256, generateRecordId, resolveCertificateBrand } from './crypto.js';

export interface ReservedCertNumberRecord {
  certificateNumber: string;
  brand?: CertificateBrand;
  status?: 'RESERVED' | 'ISSUED' | 'CANCELLED' | 'ARCHIVED';
  reservedAt: string;
  issuedAt?: string;
  certificateId: string;
}

export interface ReservedRegNumberRecord {
  scrappingRegNumber: string;
  brand?: CertificateBrand;
  status?: 'RESERVED' | 'ISSUED' | 'CANCELLED' | 'ARCHIVED';
  reservedAt: string;
  issuedAt?: string;
  certificateId: string;
}

export interface StoredCredentials {
  makerUsername: string;
  makerPasswordHash: string;
  mainAdminPasswordHash: string;
  protectedPasswordHash: string;
  deletePasswordHash: string;
  sessionVersion: number;
  bootstrappedAt: string;
  updatedAt: string;
}

export interface StoredSession {
  id: string;
  username: string;
  role: UserRole;
  sessionVersion: number;
  issuedAt: number;
  expiresAt: number;
  rememberMe?: boolean;
  scrapRouteAuthorizedUntil?: number;
  revoked: boolean;
  revokedAt?: string;
}

export interface IdempotencyRecord {
  key: string;
  certificateId: string;
  certificateNumber: string;
  createdAt: string;
}

interface StoredBackupDocument extends BackupSnapshot {
  payloadJson: string;
}

export const DEFAULT_SETTINGS: SystemSettings = {
  facilityName: 'Parivahan Scrappers Authorized RVSF',
  facilityRvsfCode: 'RVSF-IND-2026-001',
  facilityAddress: 'Authorized Vehicle Scrapping Yard, Industrial Area Phase II, India',
  facilityPhone: '+91-1800-000-0000',
  facilityEmail: 'compliance@parivahanscrappers.in',
  authorizedSignatory: 'Authorized RVSF Officer',
  signatoryDesignation: 'Facility Compliance Head',
  publicDomain: '',
  backupRetentionDays: 90,
  driveSyncEnabled: false,
  driveFolderId: '',
  updatedAt: new Date().toISOString(),
  updatedBy: 'system',
};

export interface RegistryStore {
  readonly mode: 'firestore' | 'staging_memory' | 'firestore_unconfigured';
  readonly projectId: string | null;
  readonly databaseId: string | null;
  readonly missingEnvVars?: string[];

  // Connectivity probe
  ping(): Promise<{ ok: boolean; latencyMs: number; message: string }>;

  // Credentials, Sessions & Settings
  getCredentials(): Promise<StoredCredentials | null>;
  saveCredentials(creds: StoredCredentials): Promise<void>;
  createCredentialsIfAbsent(creds: StoredCredentials): Promise<boolean>;
  createSession(session: StoredSession): Promise<void>;
  getSession(sessionId: string): Promise<StoredSession | null>;
  updateSessionScrapRouteAuth(sessionId: string, authorizedUntil: number | null): Promise<void>;
  revokeSession(sessionId: string): Promise<void>;
  getSettings(): Promise<SystemSettings>;
  saveSettings(settings: SystemSettings): Promise<void>;

  // Reserved Numbers
  isCertNumberReserved(certNumber: string): Promise<boolean>;
  isScrappingRegReserved(regNumber: string): Promise<boolean>;
  getReservedCounts(): Promise<{ certCount: number; regCount: number }>;
  getAllReservedNumbers(): Promise<{
    certNumbers: ReservedCertNumberRecord[];
    regNumbers: ReservedRegNumberRecord[];
  }>;

  // Idempotency
  getIdempotencyRecord(key: string): Promise<IdempotencyRecord | null>;

  // Atomic Certificate Creation (certificate + cert reservation + reg reservation + idempotency + initial version + audit)
  createCertificateAtomic(params: {
    certificate: CertificateRecord;
    idempotencyKey: string;
    auditLog: AuditLogEntry;
    initialVersionDoc?: CertificateVersionDocument;
  }): Promise<CertificateRecord>;

  // Append-Only Certificate Version History
  appendCertificateVersion(versionDoc: CertificateVersionDocument): Promise<void>;
  getCertificateVersions(certificateId: string): Promise<CertificateVersionDocument[]>;

  // Certificate Reads & Mutations
  getCertificateById(id: string): Promise<CertificateRecord | null>;
  getCertificateByNumber(certNumber: string): Promise<CertificateRecord | null>;
  getRecentActiveCertificates(limit: number): Promise<CertificateRecord[]>;
  getAllCertificates(): Promise<CertificateRecord[]>;
  saveCertificate(cert: CertificateRecord): Promise<void>;
  permanentlyDeleteCertificate(id: string): Promise<void>;

  // Audit Logs
  addAuditLog(entry: AuditLogEntry): Promise<void>;
  getAuditLogs(limit?: number): Promise<AuditLogEntry[]>;

  // Backups
  createBackup(createdBy: string, trigger: BackupSnapshot['trigger']): Promise<BackupSnapshot>;
  listBackups(): Promise<BackupSnapshot[]>;
  getBackupDownload(backupId: string): Promise<{ filename: string; sha256Checksum: string; payloadJson: string }>;
  dryRunRestoreBackup(backupId: string): Promise<BackupDryRunResult>;
  restoreBackup(backupId: string, actor: string): Promise<{ restoredCount: number; safetyBackupId: string }>;

  // Drive Sync Logs
  addDriveSyncLog(log: DriveSyncLog): Promise<void>;
  getDriveSyncLogs(limit?: number): Promise<DriveSyncLog[]>;

  // System Errors
  addSystemError(err: SystemErrorLog): Promise<void>;
  getSystemErrors(limit?: number): Promise<SystemErrorLog[]>;
}

function encodeDocKey(value: string): string {
  return value.replace(/[^a-zA-Z0-9_-]/g, '_');
}

// ============================================================================
// 1. STAGING / PREVIEW IN-MEMORY STORE (Starts at 0 certificates, zero disk IO)
// ============================================================================
export class StagingMemoryStore implements RegistryStore {
  readonly mode = 'staging_memory' as const;
  readonly projectId = null;
  readonly databaseId = null;

  private credentials: StoredCredentials | null = null;
  private sessions = new Map<string, StoredSession>();
  private settings: SystemSettings = { ...DEFAULT_SETTINGS };
  private certificates = new Map<string, CertificateRecord>();
  private certificateVersions = new Map<string, CertificateVersionDocument>();
  private reservedCertNumbers = new Map<string, ReservedCertNumberRecord>();
  private reservedRegNumbers = new Map<string, ReservedRegNumberRecord>();
  private idempotencyKeys = new Map<string, IdempotencyRecord>();
  private auditLogs: AuditLogEntry[] = [];
  private backups = new Map<string, StoredBackupDocument>();
  private driveSyncLogs: DriveSyncLog[] = [];
  private systemErrors: SystemErrorLog[] = [];

  // Serialized mutex chain to guarantee atomic transactions under concurrent requests
  private txChain: Promise<unknown> = Promise.resolve();

  private runAtomic<T>(fn: () => T): Promise<T> {
    const next = this.txChain.then(() => fn());
    this.txChain = next.catch(() => undefined);
    return next;
  }

  async ping(): Promise<{ ok: boolean; latencyMs: number; message: string }> {
    return {
      ok: true,
      latencyMs: 1,
      message: 'Local staging memory store active (zero historical data). Set FIREBASE_* env vars in Vercel for production Firestore.',
    };
  }

  async getCredentials(): Promise<StoredCredentials | null> {
    return this.credentials ? { ...this.credentials } : null;
  }

  async saveCredentials(creds: StoredCredentials): Promise<void> {
    this.credentials = { ...creds };
  }

  async createCredentialsIfAbsent(creds: StoredCredentials): Promise<boolean> {
    return this.runAtomic(() => {
      if (this.credentials !== null) return false;
      this.credentials = { ...creds };
      return true;
    });
  }

  async createSession(session: StoredSession): Promise<void> {
    this.sessions.set(session.id, { ...session });
  }

  async getSession(sessionId: string): Promise<StoredSession | null> {
    const found = this.sessions.get(sessionId);
    return found ? { ...found } : null;
  }

  async updateSessionScrapRouteAuth(
    sessionId: string,
    authorizedUntil: number | null
  ): Promise<void> {
    const existing = this.sessions.get(sessionId);
    if (!existing) return;
    const next: StoredSession = { ...existing };
    if (authorizedUntil && authorizedUntil > 0) {
      next.scrapRouteAuthorizedUntil = authorizedUntil;
    } else {
      delete next.scrapRouteAuthorizedUntil;
    }
    this.sessions.set(sessionId, next);
  }

  async revokeSession(sessionId: string): Promise<void> {
    const existing = this.sessions.get(sessionId);
    if (existing) {
      this.sessions.set(sessionId, {
        ...existing,
        revoked: true,
        revokedAt: new Date().toISOString(),
        scrapRouteAuthorizedUntil: undefined,
      });
    }
  }

  async getSettings(): Promise<SystemSettings> {
    return {
      ...this.settings,
      publicDomain: this.settings.publicDomain || process.env.PUBLIC_APP_URL?.trim() || '',
    };
  }

  async saveSettings(settings: SystemSettings): Promise<void> {
    this.settings = { ...settings };
  }

  async isCertNumberReserved(certNumber: string): Promise<boolean> {
    const normalized = certNumber.trim().toUpperCase();
    return this.reservedCertNumbers.has(normalized);
  }

  async isScrappingRegReserved(regNumber: string): Promise<boolean> {
    const normalized = regNumber.trim().toUpperCase();
    return this.reservedRegNumbers.has(normalized);
  }

  async getReservedCounts(): Promise<{ certCount: number; regCount: number }> {
    return {
      certCount: this.reservedCertNumbers.size,
      regCount: this.reservedRegNumbers.size,
    };
  }

  async getAllReservedNumbers(): Promise<{
    certNumbers: ReservedCertNumberRecord[];
    regNumbers: ReservedRegNumberRecord[];
  }> {
    return {
      certNumbers: Array.from(this.reservedCertNumbers.values()).map((r) => ({ ...r })),
      regNumbers: Array.from(this.reservedRegNumbers.values()).map((r) => ({ ...r })),
    };
  }

  async getIdempotencyRecord(key: string): Promise<IdempotencyRecord | null> {
    return this.idempotencyKeys.get(key) ?? null;
  }

  async createCertificateAtomic(params: {
    certificate: CertificateRecord;
    idempotencyKey: string;
    auditLog: AuditLogEntry;
    initialVersionDoc?: CertificateVersionDocument;
  }): Promise<CertificateRecord> {
    return this.runAtomic(() => {
      const existingIdemp = this.idempotencyKeys.get(params.idempotencyKey);
      if (existingIdemp) {
        const existingCert = this.certificates.get(existingIdemp.certificateId);
        if (existingCert) return structuredClone(existingCert);
      }

      const certNo = params.certificate.certificateNumber.toUpperCase();
      const regNo = params.certificate.scrappingRegNumber.toUpperCase();
      const brand = resolveCertificateBrand(params.certificate);

      if (this.certificates.has(params.certificate.id)) {
        const err = new Error(`Certificate ID already exists: ${params.certificate.id}`);
        (err as NodeJS.ErrnoException).code = 'NUMBER_COLLISION';
        throw err;
      }
      if (this.reservedCertNumbers.has(certNo)) {
        const err = new Error(`Certificate number collision: ${certNo}`);
        (err as NodeJS.ErrnoException).code = 'NUMBER_COLLISION';
        throw err;
      }
      if (this.reservedRegNumbers.has(regNo)) {
        const err = new Error(`Scrapping registration number collision: ${regNo}`);
        (err as NodeJS.ErrnoException).code = 'NUMBER_COLLISION';
        throw err;
      }

      const stored = structuredClone(params.certificate);
      this.certificates.set(stored.id, stored);
      this.reservedCertNumbers.set(certNo, {
        certificateNumber: certNo,
        brand,
        status: 'ISSUED',
        reservedAt: stored.createdAt,
        issuedAt: stored.createdAt,
        certificateId: stored.id,
      });
      this.reservedRegNumbers.set(regNo, {
        scrappingRegNumber: regNo,
        brand,
        status: 'ISSUED',
        reservedAt: stored.createdAt,
        issuedAt: stored.createdAt,
        certificateId: stored.id,
      });
      this.idempotencyKeys.set(params.idempotencyKey, {
        key: params.idempotencyKey,
        certificateId: stored.id,
        certificateNumber: certNo,
        createdAt: stored.createdAt,
      });
      if (params.initialVersionDoc) {
        this.certificateVersions.set(
          params.initialVersionDoc.id,
          structuredClone(params.initialVersionDoc)
        );
      }
      this.auditLogs.unshift(structuredClone(params.auditLog));
      return structuredClone(stored);
    });
  }

  async appendCertificateVersion(versionDoc: CertificateVersionDocument): Promise<void> {
    if (this.certificateVersions.has(versionDoc.id)) {
      throw new Error(`Immutable certificate version already exists: ${versionDoc.id}`);
    }
    this.certificateVersions.set(versionDoc.id, structuredClone(versionDoc));
  }

  async getCertificateVersions(certificateId: string): Promise<CertificateVersionDocument[]> {
    return Array.from(this.certificateVersions.values())
      .filter((v) => v.certificateId === certificateId)
      .sort((a, b) => b.version - a.version || b.recordedAt.localeCompare(a.recordedAt))
      .map((v) => structuredClone(v));
  }

  /**
   * Loads a backup payload directly into this isolated staging instance for
   * pre-recovery verification without ever touching production data.
   */
  importBackupIntoStaging(payloadJson: string): { restoredCount: number } {
    const parsed = JSON.parse(payloadJson) as {
      certificates?: CertificateRecord[];
      reservedCertNumbers?: ReservedCertNumberRecord[];
      reservedRegNumbers?: ReservedRegNumberRecord[];
      certificateVersions?: CertificateVersionDocument[];
      settings?: SystemSettings;
    };
    this.certificates.clear();
    this.reservedCertNumbers.clear();
    this.reservedRegNumbers.clear();
    this.certificateVersions.clear();

    const certs = parsed.certificates ?? [];
    for (const cert of certs) {
      this.certificates.set(cert.id, structuredClone(cert));
    }
    for (const r of parsed.reservedCertNumbers ?? []) {
      this.reservedCertNumbers.set(r.certificateNumber.toUpperCase(), structuredClone(r));
    }
    for (const r of parsed.reservedRegNumbers ?? []) {
      this.reservedRegNumbers.set(r.scrappingRegNumber.toUpperCase(), structuredClone(r));
    }
    for (const v of parsed.certificateVersions ?? []) {
      this.certificateVersions.set(v.id, structuredClone(v));
    }
    if (parsed.settings) {
      this.settings = structuredClone(parsed.settings);
    }
    return { restoredCount: certs.length };
  }

  async getCertificateById(id: string): Promise<CertificateRecord | null> {
    const found = this.certificates.get(id);
    return found ? structuredClone(found) : null;
  }

  async getCertificateByNumber(certNumber: string): Promise<CertificateRecord | null> {
    const target = certNumber.trim().toUpperCase();
    for (const cert of this.certificates.values()) {
      if (cert.certificateNumber.toUpperCase() === target) {
        return structuredClone(cert);
      }
    }
    return null;
  }

  async getRecentActiveCertificates(limit: number): Promise<CertificateRecord[]> {
    const capped = Math.min(Math.max(1, limit), 5);
    return Array.from(this.certificates.values())
      .filter((c) => c.status !== 'SOFT_DELETED')
      .sort((a, b) => b.createdAt.localeCompare(a.createdAt))
      .slice(0, capped)
      .map((c) => structuredClone(c));
  }

  async getAllCertificates(): Promise<CertificateRecord[]> {
    return Array.from(this.certificates.values())
      .sort((a, b) => b.createdAt.localeCompare(a.createdAt))
      .map((c) => structuredClone(c));
  }

  async saveCertificate(cert: CertificateRecord): Promise<void> {
    this.certificates.set(cert.id, structuredClone(cert));
  }

  async permanentlyDeleteCertificate(id: string): Promise<void> {
    // Note: reservedCertNumbers and reservedRegNumbers are intentionally NEVER removed
    this.certificates.delete(id);
  }

  async addAuditLog(entry: AuditLogEntry): Promise<void> {
    this.auditLogs.unshift(structuredClone(entry));
    if (this.auditLogs.length > 2000) {
      this.auditLogs.length = 2000;
    }
  }

  async getAuditLogs(limit = 200): Promise<AuditLogEntry[]> {
    return this.auditLogs.slice(0, Math.min(limit, 500)).map((a) => structuredClone(a));
  }

  async createBackup(
    createdBy: string,
    trigger: BackupSnapshot['trigger']
  ): Promise<BackupSnapshot> {
    const certs = await this.getAllCertificates();
    const payloadObj = {
      schemaVersion: 2,
      exportedAt: new Date().toISOString(),
      certificates: certs,
      reservedCertNumbers: Array.from(this.reservedCertNumbers.values()),
      reservedRegNumbers: Array.from(this.reservedRegNumbers.values()),
      certificateVersions: Array.from(this.certificateVersions.values()),
      settings: this.settings,
    };
    const payloadJson = JSON.stringify(payloadObj);
    const sha256Checksum = computeSha256(payloadJson);
    const doc: StoredBackupDocument = {
      id: generateRecordId('bkp'),
      createdAt: payloadObj.exportedAt,
      createdBy,
      trigger,
      certificateCount: certs.length,
      reservedCertCount: this.reservedCertNumbers.size,
      reservedRegCount: this.reservedRegNumbers.size,
      auditLogCount: this.auditLogs.length,
      sha256Checksum,
      verified: false,
      sizeBytes: Buffer.byteLength(payloadJson, 'utf8'),
      storageTarget: 'Staging Memory Snapshot (Configure Firestore for Production)',
      payloadJson,
    };
    this.backups.set(doc.id, doc);
    // Read-back verification before marking snapshot verified
    const readBack = this.backups.get(doc.id);
    const verified = Boolean(readBack && computeSha256(readBack.payloadJson) === sha256Checksum);
    if (!verified) {
      this.backups.delete(doc.id);
      throw new Error('Backup read-back SHA-256 verification failed. Previous good backups preserved.');
    }
    doc.verified = true;
    const { payloadJson: _omitted, ...meta } = doc;
    return meta;
  }

  async listBackups(): Promise<BackupSnapshot[]> {
    return Array.from(this.backups.values())
      .sort((a, b) => b.createdAt.localeCompare(a.createdAt))
      .map(({ payloadJson: _omitted, ...meta }) => meta);
  }

  async getBackupDownload(backupId: string): Promise<{
    filename: string;
    sha256Checksum: string;
    payloadJson: string;
  }> {
    const doc = this.backups.get(backupId);
    if (!doc) throw new Error('Backup snapshot not found');
    return {
      filename: `parivahan_backup_${doc.id}.json`,
      sha256Checksum: doc.sha256Checksum,
      payloadJson: doc.payloadJson,
    };
  }

  async dryRunRestoreBackup(backupId: string): Promise<BackupDryRunResult> {
    const doc = this.backups.get(backupId);
    if (!doc) {
      throw new Error('Backup snapshot not found');
    }
    const computedChecksum = computeSha256(doc.payloadJson);
    const checksumValid = computedChecksum === doc.sha256Checksum;
    const parsed = JSON.parse(doc.payloadJson) as {
      certificates: CertificateRecord[];
      reservedCertNumbers: Array<{ certificateNumber: string }>;
      reservedRegNumbers: Array<{ scrappingRegNumber: string }>;
    };
    const snapshotIds = new Set(parsed.certificates.map((c) => c.id));
    let onlyInCurrent = 0;
    for (const id of this.certificates.keys()) {
      if (!snapshotIds.has(id)) onlyInCurrent++;
    }
    const warnings: string[] = [];
    if (!checksumValid) {
      warnings.push('SHA-256 checksum mismatch detected. Restore is blocked.');
    }
    if (onlyInCurrent > 0) {
      warnings.push(
        `${onlyInCurrent} certificate(s) issued after this backup will be superseded. Reserved numbers remain permanently protected.`
      );
    }
    return {
      backupId,
      checksumValid,
      computedChecksum,
      storedChecksum: doc.sha256Checksum,
      currentCertificateCount: this.certificates.size,
      snapshotCertificateCount: parsed.certificates.length,
      certificatesToRestore: parsed.certificates.length,
      certificatesOnlyInCurrent: onlyInCurrent,
      reservedNumbersPreserved: this.reservedCertNumbers.size,
      safeToRestore: checksumValid,
      warnings,
    };
  }

  async restoreBackup(
    backupId: string,
    actor: string
  ): Promise<{ restoredCount: number; safetyBackupId: string }> {
    const dryRun = await this.dryRunRestoreBackup(backupId);
    if (!dryRun.checksumValid) {
      throw new Error('Cannot restore corrupted backup: SHA-256 verification failed');
    }
    const safetyBackup = await this.createBackup(actor, 'PRE_RESTORE_SAFETY');
    const doc = this.backups.get(backupId)!;
    const parsed = JSON.parse(doc.payloadJson) as {
      certificates: CertificateRecord[];
      reservedCertNumbers: Array<{ certificateNumber: string; reservedAt: string; certificateId: string }>;
      reservedRegNumbers: Array<{ scrappingRegNumber: string; reservedAt: string; certificateId: string }>;
    };

    this.certificates.clear();
    for (const cert of parsed.certificates) {
      this.certificates.set(cert.id, structuredClone(cert));
    }
    // Union reserved numbers so previously issued numbers are NEVER freed for reuse
    for (const r of parsed.reservedCertNumbers) {
      this.reservedCertNumbers.set(r.certificateNumber.toUpperCase(), r);
    }
    for (const r of parsed.reservedRegNumbers) {
      this.reservedRegNumbers.set(r.scrappingRegNumber.toUpperCase(), r);
    }
    return {
      restoredCount: parsed.certificates.length,
      safetyBackupId: safetyBackup.id,
    };
  }

  async addDriveSyncLog(log: DriveSyncLog): Promise<void> {
    this.driveSyncLogs.unshift(structuredClone(log));
    if (this.driveSyncLogs.length > 500) this.driveSyncLogs.length = 500;
  }

  async getDriveSyncLogs(limit = 100): Promise<DriveSyncLog[]> {
    return this.driveSyncLogs.slice(0, limit).map((l) => structuredClone(l));
  }

  async addSystemError(err: SystemErrorLog): Promise<void> {
    this.systemErrors.unshift(structuredClone(err));
    if (this.systemErrors.length > 300) this.systemErrors.length = 300;
  }

  async getSystemErrors(limit = 100): Promise<SystemErrorLog[]> {
    return this.systemErrors.slice(0, limit).map((e) => structuredClone(e));
  }
}

// ============================================================================
// 2. PRODUCTION STATELESS FIRESTORE REST STORE (Google Service Account OAuth2)
// Compatible with Firebase Spark (Free) plan on the (default) database.
// Activated automatically when FIREBASE_PROJECT_ID, FIREBASE_CLIENT_EMAIL, and
// FIREBASE_PRIVATE_KEY are configured in Vercel / Server Environment Variables.
// ============================================================================
export const BACKUP_CHUNK_MAX_CHARS = 450_000; // <= 450 KB base64 per doc (well below Firestore's 1 MiB limit)

export function normalizePrivateKey(raw: string): string {
  let key = raw.trim();
  if (
    (key.startsWith('"') && key.endsWith('"')) ||
    (key.startsWith("'") && key.endsWith("'"))
  ) {
    key = key.slice(1, -1);
  }
  return key.replace(/\\r\\n/g, '\n').replace(/\\n/g, '\n').replace(/\r\n/g, '\n').trim();
}

export function encodeBackupPayloadChunks(
  payloadJson: string,
  maxChunkChars = BACKUP_CHUNK_MAX_CHARS
): { chunks: string[]; compressedBytes: number } {
  const compressed = gzipSync(Buffer.from(payloadJson, 'utf8'));
  const b64 = compressed.toString('base64');
  const chunks: string[] = [];
  for (let i = 0; i < b64.length; i += maxChunkChars) {
    chunks.push(b64.slice(i, i + maxChunkChars));
  }
  if (chunks.length === 0) {
    chunks.push('');
  }
  return { chunks, compressedBytes: compressed.length };
}

export function decodeBackupPayloadChunks(chunks: string[]): string {
  const b64 = chunks.join('');
  const compressed = Buffer.from(b64, 'base64');
  return gunzipSync(compressed).toString('utf8');
}

interface FirestoreBackupMetadataDoc extends BackupSnapshot {
  payloadEncoding?: 'gzip-base64-chunks';
  chunkCount?: number;
  compressedBytes?: number;
  // Optional legacy fallback if an older single-doc backup exists
  payloadJson?: string;
}

interface FirestoreBackupChunkDoc {
  backupId: string;
  chunkIndex: number;
  chunkCount: number;
  data: string;
}

type FirestoreValue =
  | { nullValue: null }
  | { booleanValue: boolean }
  | { integerValue: string }
  | { doubleValue: number }
  | { stringValue: string }
  | { arrayValue: { values?: FirestoreValue[] } }
  | { mapValue: { fields?: Record<string, FirestoreValue> } };

function toFirestoreValue(val: unknown): FirestoreValue {
  if (val === null || val === undefined) return { nullValue: null };
  if (typeof val === 'boolean') return { booleanValue: val };
  if (typeof val === 'number') {
    return Number.isInteger(val) ? { integerValue: String(val) } : { doubleValue: val };
  }
  if (typeof val === 'string') return { stringValue: val };
  if (Array.isArray(val)) {
    return { arrayValue: { values: val.map((item) => toFirestoreValue(item)) } };
  }
  if (typeof val === 'object') {
    const fields: Record<string, FirestoreValue> = {};
    for (const [k, v] of Object.entries(val as Record<string, unknown>)) {
      if (v !== undefined) {
        fields[k] = toFirestoreValue(v);
      }
    }
    return { mapValue: { fields } };
  }
  return { stringValue: String(val) };
}

function fromFirestoreValue(val: FirestoreValue | undefined): unknown {
  if (!val) return undefined;
  if ('nullValue' in val) return null;
  if ('booleanValue' in val) return val.booleanValue;
  if ('integerValue' in val) return Number(val.integerValue);
  if ('doubleValue' in val) return Number(val.doubleValue);
  if ('stringValue' in val) return val.stringValue;
  if ('arrayValue' in val) {
    return (val.arrayValue.values ?? []).map((item) => fromFirestoreValue(item));
  }
  if ('mapValue' in val) {
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(val.mapValue.fields ?? {})) {
      out[k] = fromFirestoreValue(v);
    }
    return out;
  }
  return undefined;
}

function toFirestoreFields(obj: Record<string, unknown>): Record<string, FirestoreValue> {
  const fields: Record<string, FirestoreValue> = {};
  for (const [k, v] of Object.entries(obj)) {
    if (v !== undefined) {
      fields[k] = toFirestoreValue(v);
    }
  }
  return fields;
}

function fromFirestoreDoc<T>(doc: { fields?: Record<string, FirestoreValue> }): T {
  const out: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(doc.fields ?? {})) {
    out[k] = fromFirestoreValue(v);
  }
  return out as T;
}

export interface FirestoreRestStoreConfig {
  projectId: string;
  databaseId: string;
  clientEmail: string;
  privateKey: string;
  // Optional overrides for isolated unit testing against a local mock server
  apiOrigin?: string;
  tokenUrl?: string;
  maxChunkChars?: number;
}

export class FirestoreRestStore implements RegistryStore {
  readonly mode = 'firestore' as const;
  readonly projectId: string;
  readonly databaseId: string;
  private readonly clientEmail: string;
  private readonly privateKey: string;
  private readonly apiOrigin: string;
  private readonly tokenUrl: string;
  private readonly maxChunkChars: number;
  private cachedToken: { token: string; expiresAt: number } | null = null;

  constructor(config: FirestoreRestStoreConfig) {
    this.projectId = config.projectId;
    this.databaseId = config.databaseId || '(default)';
    this.clientEmail = config.clientEmail;
    this.privateKey = normalizePrivateKey(config.privateKey);
    this.apiOrigin = (config.apiOrigin ?? 'https://firestore.googleapis.com').replace(/\/+$/, '');
    this.tokenUrl = config.tokenUrl ?? 'https://oauth2.googleapis.com/token';
    this.maxChunkChars = config.maxChunkChars ?? BACKUP_CHUNK_MAX_CHARS;
  }

  private get docRoot(): string {
    return `projects/${this.projectId}/databases/${this.databaseId}/documents`;
  }

  private get apiBase(): string {
    return `${this.apiOrigin}/v1/${this.docRoot}`;
  }

  private async getAccessToken(): Promise<string> {
    if (this.cachedToken && Date.now() < this.cachedToken.expiresAt - 60_000) {
      return this.cachedToken.token;
    }

    const now = Math.floor(Date.now() / 1000);
    const header = Buffer.from(JSON.stringify({ alg: 'RS256', typ: 'JWT' })).toString('base64url');
    const claim = Buffer.from(
      JSON.stringify({
        iss: this.clientEmail,
        scope: 'https://www.googleapis.com/auth/datastore',
        aud: this.tokenUrl,
        iat: now,
        exp: now + 3600,
      })
    ).toString('base64url');

    const unsigned = `${header}.${claim}`;
    const signer = crypto.createSign('RSA-SHA256');
    signer.update(unsigned);
    const signature = signer.sign(this.privateKey, 'base64url');

    const res = await fetch(this.tokenUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        grant_type: 'urn:ietf:params:oauth:grant-type:jwt-bearer',
        assertion: `${unsigned}.${signature}`,
      }),
    });

    if (!res.ok) {
      const txt = await res.text();
      throw new Error(`Google Service Account OAuth2 error (${res.status}): ${txt}`);
    }

    const data = (await res.json()) as { access_token: string; expires_in: number };
    this.cachedToken = {
      token: data.access_token,
      expiresAt: Date.now() + (data.expires_in ?? 3600) * 1000,
    };
    return data.access_token;
  }

  private async fsFetch(url: string, init?: RequestInit): Promise<Response> {
    const token = await this.getAccessToken();
    return fetch(url, {
      ...init,
      headers: {
        Authorization: `Bearer ${token}`,
        'Content-Type': 'application/json',
        ...(init?.headers ?? {}),
      },
    });
  }

  private async getDoc<T>(collection: string, docId: string): Promise<T | null> {
    const res = await this.fsFetch(`${this.apiBase}/${collection}/${encodeURIComponent(docId)}`);
    if (res.status === 404) return null;
    if (!res.ok) throw new Error(`Firestore GET ${collection}/${docId} failed: ${await res.text()}`);
    const data = (await res.json()) as { fields?: Record<string, FirestoreValue> };
    return fromFirestoreDoc<T>(data);
  }

  private async setDoc(collection: string, docId: string, value: object): Promise<void> {
    const res = await this.fsFetch(`${this.apiBase}/${collection}/${encodeURIComponent(docId)}`, {
      method: 'PATCH',
      body: JSON.stringify({ fields: toFirestoreFields(value as Record<string, unknown>) }),
    });
    if (!res.ok) throw new Error(`Firestore PATCH ${collection}/${docId} failed: ${await res.text()}`);
  }

  private async deleteDoc(collection: string, docId: string): Promise<void> {
    const res = await this.fsFetch(`${this.apiBase}/${collection}/${encodeURIComponent(docId)}`, {
      method: 'DELETE',
    });
    if (!res.ok && res.status !== 404) {
      throw new Error(`Firestore DELETE ${collection}/${docId} failed: ${await res.text()}`);
    }
  }

  private async listCollection<T>(collection: string, pageSize = 500): Promise<T[]> {
    const items: T[] = [];
    let pageToken = '';
    let pages = 0;
    do {
      const qs = new URLSearchParams({ pageSize: String(pageSize) });
      if (pageToken) qs.set('pageToken', pageToken);
      const res = await this.fsFetch(`${this.apiBase}/${collection}?${qs.toString()}`);
      if (res.status === 404) return [];
      if (!res.ok) throw new Error(`Firestore LIST ${collection} failed: ${await res.text()}`);
      const data = (await res.json()) as {
        documents?: Array<{ fields?: Record<string, FirestoreValue> }>;
        nextPageToken?: string;
      };
      for (const doc of data.documents ?? []) {
        items.push(fromFirestoreDoc<T>(doc));
      }
      pageToken = data.nextPageToken ?? '';
      pages++;
    } while (pageToken && pages < 1000);
    return items;
  }

  // Spark-efficient indexed query using automatic single-field descending indexes (no composite index required)
  private async runOrderedQuery<T>(
    collection: string,
    orderByField: string,
    limit: number
  ): Promise<T[]> {
    const res = await this.fsFetch(`${this.apiBase}:runQuery`, {
      method: 'POST',
      body: JSON.stringify({
        structuredQuery: {
          from: [{ collectionId: collection }],
          orderBy: [{ field: { fieldPath: orderByField }, direction: 'DESCENDING' }],
          limit,
        },
      }),
    });
    if (!res.ok) {
      throw new Error(`Firestore ordered query on ${collection} failed: ${await res.text()}`);
    }
    const rows = (await res.json()) as Array<{ document?: { fields?: Record<string, FirestoreValue> } }>;
    const items: T[] = [];
    for (const row of rows) {
      if (row.document) {
        items.push(fromFirestoreDoc<T>(row.document));
      }
    }
    return items;
  }

  // Spark-efficient aggregation COUNT (1 read per 1,000 index entries instead of downloading all docs)
  async countCollection(collection: string): Promise<number> {
    const res = await this.fsFetch(`${this.apiBase}:runAggregationQuery`, {
      method: 'POST',
      body: JSON.stringify({
        structuredAggregationQuery: {
          structuredQuery: {
            from: [{ collectionId: collection }],
          },
          aggregations: [{ alias: 'total', count: {} }],
        },
      }),
    });
    if (!res.ok) {
      throw new Error(`Firestore COUNT aggregation on ${collection} failed: ${await res.text()}`);
    }
    const rows = (await res.json()) as Array<{
      result?: { aggregateFields?: { total?: { integerValue?: string } } };
    }>;
    const rawCount = rows.find((r) => r.result?.aggregateFields?.total)?.result?.aggregateFields?.total?.integerValue;
    return rawCount ? Number(rawCount) : 0;
  }

  private async commitWritesInBatches(
    writes: Array<Record<string, unknown>>,
    batchSize = 350
  ): Promise<void> {
    for (let i = 0; i < writes.length; i += batchSize) {
      const slice = writes.slice(i, i + batchSize);
      const res = await this.fsFetch(`${this.apiBase}:commit`, {
        method: 'POST',
        body: JSON.stringify({ writes: slice }),
      });
      if (!res.ok) {
        throw new Error(`Firestore batch commit failed (${res.status}): ${await res.text()}`);
      }
    }
  }

  private async loadBackupPayloadJson(doc: FirestoreBackupMetadataDoc): Promise<string> {
    if (doc.payloadEncoding === 'gzip-base64-chunks' && typeof doc.chunkCount === 'number' && doc.chunkCount > 0) {
      const chunks: string[] = new Array<string>(doc.chunkCount);
      const concurrency = 10;
      for (let start = 0; start < doc.chunkCount; start += concurrency) {
        const indices: number[] = [];
        for (let idx = start; idx < Math.min(start + concurrency, doc.chunkCount); idx++) {
          indices.push(idx);
        }
        const loaded = await Promise.all(
          indices.map((idx) =>
            this.getDoc<FirestoreBackupChunkDoc>('database_backup_chunks', `${doc.id}_chunk_${idx}`)
          )
        );
        for (let j = 0; j < indices.length; j++) {
          const chunkDoc = loaded[j];
          if (!chunkDoc || typeof chunkDoc.data !== 'string') {
            throw new Error(`Backup chunk ${indices[j]} missing for snapshot ${doc.id}`);
          }
          chunks[indices[j]] = chunkDoc.data;
        }
      }
      return decodeBackupPayloadChunks(chunks);
    }

    if (typeof doc.payloadJson === 'string') {
      return doc.payloadJson;
    }

    throw new Error(`Backup snapshot ${doc.id} has no readable payload`);
  }

  private toPublicBackupSnapshot(doc: FirestoreBackupMetadataDoc): BackupSnapshot {
    const {
      payloadJson: _legacyPayload,
      payloadEncoding: _enc,
      chunkCount: _chunks,
      compressedBytes: _comp,
      ...meta
    } = doc;
    return meta;
  }

  async ping(): Promise<{ ok: boolean; latencyMs: number; message: string }> {
    const start = Date.now();
    try {
      await this.getDoc<SystemSettings>('settings', 'global');
      return {
        ok: true,
        latencyMs: Date.now() - start,
        message: `Connected to Google Cloud Firestore (${this.projectId} / ${this.databaseId})`,
      };
    } catch (err) {
      return {
        ok: false,
        latencyMs: Date.now() - start,
        message: err instanceof Error ? err.message : 'Firestore connection failed',
      };
    }
  }

  async getCredentials(): Promise<StoredCredentials | null> {
    return this.getDoc<StoredCredentials>('admins', 'primary_credentials');
  }

  async saveCredentials(creds: StoredCredentials): Promise<void> {
    await this.setDoc('admins', 'primary_credentials', creds);
  }

  async createCredentialsIfAbsent(creds: StoredCredentials): Promise<boolean> {
    // Atomic precondition exists: false guarantees bootstrap can NEVER overwrite existing credentials
    const writes = [
      {
        update: {
          name: `${this.docRoot}/admins/primary_credentials`,
          fields: toFirestoreFields(creds as unknown as Record<string, unknown>),
        },
        currentDocument: { exists: false },
      },
    ];
    const res = await this.fsFetch(`${this.apiBase}:commit`, {
      method: 'POST',
      body: JSON.stringify({ writes }),
    });
    if (res.ok) return true;
    const text = await res.text();
    if (res.status === 409 || text.includes('ALREADY_EXISTS') || text.includes('FAILED_PRECONDITION')) {
      return false;
    }
    throw new Error(`Firestore atomic createCredentialsIfAbsent failed (${res.status}): ${text}`);
  }

  async createSession(session: StoredSession): Promise<void> {
    await this.setDoc('auth_sessions', encodeDocKey(session.id), session);
  }

  async getSession(sessionId: string): Promise<StoredSession | null> {
    return this.getDoc<StoredSession>('auth_sessions', encodeDocKey(sessionId));
  }

  async updateSessionScrapRouteAuth(
    sessionId: string,
    authorizedUntil: number | null
  ): Promise<void> {
    const existing = await this.getSession(sessionId);
    if (!existing) return;
    const next: StoredSession = { ...existing };
    if (authorizedUntil && authorizedUntil > 0) {
      next.scrapRouteAuthorizedUntil = authorizedUntil;
    } else {
      delete next.scrapRouteAuthorizedUntil;
    }
    await this.setDoc('auth_sessions', encodeDocKey(sessionId), next);
  }

  async revokeSession(sessionId: string): Promise<void> {
    const existing = await this.getSession(sessionId);
    if (!existing) return;
    const next: StoredSession = {
      ...existing,
      revoked: true,
      revokedAt: new Date().toISOString(),
    };
    delete next.scrapRouteAuthorizedUntil;
    await this.setDoc('auth_sessions', encodeDocKey(sessionId), next);
  }

  async getSettings(): Promise<SystemSettings> {
    const existing = await this.getDoc<SystemSettings>('settings', 'global');
    const merged = existing ? { ...DEFAULT_SETTINGS, ...existing } : { ...DEFAULT_SETTINGS };
    return {
      ...merged,
      publicDomain: merged.publicDomain || process.env.PUBLIC_APP_URL?.trim() || '',
    };
  }

  async saveSettings(settings: SystemSettings): Promise<void> {
    await this.setDoc('settings', 'global', settings);
  }

  async isCertNumberReserved(certNumber: string): Promise<boolean> {
    const doc = await this.getDoc('reserved_certificate_numbers', encodeDocKey(certNumber.toUpperCase()));
    return doc !== null;
  }

  async isScrappingRegReserved(regNumber: string): Promise<boolean> {
    const doc = await this.getDoc('reserved_scrapping_numbers', encodeDocKey(regNumber.toUpperCase()));
    return doc !== null;
  }

  async getReservedCounts(): Promise<{ certCount: number; regCount: number }> {
    const [certCount, regCount] = await Promise.all([
      this.countCollection('reserved_certificate_numbers'),
      this.countCollection('reserved_scrapping_numbers'),
    ]);
    return { certCount, regCount };
  }

  async getAllReservedNumbers(): Promise<{
    certNumbers: ReservedCertNumberRecord[];
    regNumbers: ReservedRegNumberRecord[];
  }> {
    const [certNumbers, regNumbers] = await Promise.all([
      this.listCollection<ReservedCertNumberRecord>('reserved_certificate_numbers'),
      this.listCollection<ReservedRegNumberRecord>('reserved_scrapping_numbers'),
    ]);
    return { certNumbers, regNumbers };
  }

  async getIdempotencyRecord(key: string): Promise<IdempotencyRecord | null> {
    return this.getDoc<IdempotencyRecord>('idempotency_keys', encodeDocKey(key));
  }

  async createCertificateAtomic(params: {
    certificate: CertificateRecord;
    idempotencyKey: string;
    auditLog: AuditLogEntry;
    initialVersionDoc?: CertificateVersionDocument;
  }): Promise<CertificateRecord> {
    const existingIdemp = await this.getIdempotencyRecord(params.idempotencyKey);
    if (existingIdemp) {
      const existingCert = await this.getCertificateById(existingIdemp.certificateId);
      if (existingCert) return existingCert;
    }

    const certKey = encodeDocKey(params.certificate.certificateNumber.toUpperCase());
    const regKey = encodeDocKey(params.certificate.scrappingRegNumber.toUpperCase());
    const idempKey = encodeDocKey(params.idempotencyKey);
    const brand = resolveCertificateBrand(params.certificate);

    // Atomic Firestore commit with precondition exists: false on certificate, reservations, idempotency key & initial version
    const writes: Array<Record<string, unknown>> = [
      {
        update: {
          name: `${this.docRoot}/certificates/${params.certificate.id}`,
          fields: toFirestoreFields(params.certificate as unknown as Record<string, unknown>),
        },
        currentDocument: { exists: false },
      },
      {
        update: {
          name: `${this.docRoot}/reserved_certificate_numbers/${certKey}`,
          fields: toFirestoreFields({
            certificateNumber: params.certificate.certificateNumber.toUpperCase(),
            brand,
            status: 'ISSUED',
            reservedAt: params.certificate.createdAt,
            issuedAt: params.certificate.createdAt,
            certificateId: params.certificate.id,
          }),
        },
        currentDocument: { exists: false },
      },
      {
        update: {
          name: `${this.docRoot}/reserved_scrapping_numbers/${regKey}`,
          fields: toFirestoreFields({
            scrappingRegNumber: params.certificate.scrappingRegNumber.toUpperCase(),
            brand,
            status: 'ISSUED',
            reservedAt: params.certificate.createdAt,
            issuedAt: params.certificate.createdAt,
            certificateId: params.certificate.id,
          }),
        },
        currentDocument: { exists: false },
      },
      {
        update: {
          name: `${this.docRoot}/idempotency_keys/${idempKey}`,
          fields: toFirestoreFields({
            key: params.idempotencyKey,
            certificateId: params.certificate.id,
            certificateNumber: params.certificate.certificateNumber.toUpperCase(),
            createdAt: params.certificate.createdAt,
          }),
        },
        currentDocument: { exists: false },
      },
      {
        update: {
          name: `${this.docRoot}/audit_logs/${params.auditLog.id}`,
          fields: toFirestoreFields(params.auditLog as unknown as Record<string, unknown>),
        },
      },
    ];

    if (params.initialVersionDoc) {
      writes.push({
        update: {
          name: `${this.docRoot}/certificate_versions/${encodeDocKey(params.initialVersionDoc.id)}`,
          fields: toFirestoreFields(params.initialVersionDoc as unknown as Record<string, unknown>),
        },
        currentDocument: { exists: false },
      });
    }

    const res = await this.fsFetch(`${this.apiBase}:commit`, {
      method: 'POST',
      body: JSON.stringify({ writes }),
    });

    if (!res.ok) {
      const text = await res.text();
      if (
        res.status === 409 ||
        text.includes('ALREADY_EXISTS') ||
        text.includes('FAILED_PRECONDITION')
      ) {
        // Check if this was an idempotent retry race
        const raceIdemp = await this.getIdempotencyRecord(params.idempotencyKey);
        if (raceIdemp) {
          const raceCert = await this.getCertificateById(raceIdemp.certificateId);
          if (raceCert) return raceCert;
        }
        const err = new Error('Certificate or registration number collision');
        (err as NodeJS.ErrnoException).code = 'NUMBER_COLLISION';
        throw err;
      }
      throw new Error(`Firestore atomic commit failed (${res.status}): ${text}`);
    }

    return params.certificate;
  }

  async appendCertificateVersion(versionDoc: CertificateVersionDocument): Promise<void> {
    // Append-only write with exists: false precondition so historical versions can NEVER be overwritten
    const writes = [
      {
        update: {
          name: `${this.docRoot}/certificate_versions/${encodeDocKey(versionDoc.id)}`,
          fields: toFirestoreFields(versionDoc as unknown as Record<string, unknown>),
        },
        currentDocument: { exists: false },
      },
    ];
    const res = await this.fsFetch(`${this.apiBase}:commit`, {
      method: 'POST',
      body: JSON.stringify({ writes }),
    });
    if (!res.ok) {
      throw new Error(`Firestore appendCertificateVersion failed (${res.status}): ${await res.text()}`);
    }
  }

  async getCertificateVersions(certificateId: string): Promise<CertificateVersionDocument[]> {
    const res = await this.fsFetch(`${this.apiBase}:runQuery`, {
      method: 'POST',
      body: JSON.stringify({
        structuredQuery: {
          from: [{ collectionId: 'certificate_versions' }],
          where: {
            fieldFilter: {
              field: { fieldPath: 'certificateId' },
              op: 'EQUAL',
              value: { stringValue: certificateId },
            },
          },
        },
      }),
    });
    if (!res.ok) {
      throw new Error(`Firestore query certificate_versions failed: ${await res.text()}`);
    }
    const rows = (await res.json()) as Array<{ document?: { fields?: Record<string, FirestoreValue> } }>;
    const items: CertificateVersionDocument[] = [];
    for (const row of rows) {
      if (row.document) {
        items.push(fromFirestoreDoc<CertificateVersionDocument>(row.document));
      }
    }
    return items.sort((a, b) => b.version - a.version || b.recordedAt.localeCompare(a.recordedAt));
  }

  async getCertificateById(id: string): Promise<CertificateRecord | null> {
    return this.getDoc<CertificateRecord>('certificates', id);
  }

  async getCertificateByNumber(certNumber: string): Promise<CertificateRecord | null> {
    const target = certNumber.trim().toUpperCase();
    const res = await this.fsFetch(`${this.apiBase}:runQuery`, {
      method: 'POST',
      body: JSON.stringify({
        structuredQuery: {
          from: [{ collectionId: 'certificates' }],
          where: {
            fieldFilter: {
              field: { fieldPath: 'certificateNumber' },
              op: 'EQUAL',
              value: { stringValue: target },
            },
          },
          limit: 1,
        },
      }),
    });
    if (!res.ok) throw new Error(`Firestore query failed: ${await res.text()}`);
    const rows = (await res.json()) as Array<{ document?: { fields?: Record<string, FirestoreValue> } }>;
    const doc = rows.find((r) => r.document)?.document;
    return doc ? fromFirestoreDoc<CertificateRecord>(doc) : null;
  }

  async getRecentActiveCertificates(limit: number): Promise<CertificateRecord[]> {
    const capped = Math.min(Math.max(1, limit), 5);
    const windowSize = 25;
    const recentBatch = await this.runOrderedQuery<CertificateRecord>('certificates', 'createdAt', windowSize);
    const active = recentBatch.filter((c) => c.status !== 'SOFT_DELETED');
    if (active.length >= capped || recentBatch.length < windowSize) {
      return active.slice(0, capped);
    }
    // Fallback only if 25 newest records were almost all soft-deleted
    const all = await this.listCollection<CertificateRecord>('certificates');
    return all
      .filter((c) => c.status !== 'SOFT_DELETED')
      .sort((a, b) => b.createdAt.localeCompare(a.createdAt))
      .slice(0, capped);
  }

  async getAllCertificates(): Promise<CertificateRecord[]> {
    const all = await this.listCollection<CertificateRecord>('certificates');
    return all.sort((a, b) => b.createdAt.localeCompare(a.createdAt));
  }

  async saveCertificate(cert: CertificateRecord): Promise<void> {
    await this.setDoc('certificates', cert.id, cert);
  }

  async permanentlyDeleteCertificate(id: string): Promise<void> {
    // Note: reserved_certificate_numbers and reserved_scrapping_numbers are intentionally NEVER deleted
    await this.deleteDoc('certificates', id);
  }

  async addAuditLog(entry: AuditLogEntry): Promise<void> {
    await this.setDoc('audit_logs', entry.id, entry);
  }

  async getAuditLogs(limit = 200): Promise<AuditLogEntry[]> {
    const capped = Math.min(Math.max(1, limit), 500);
    return this.runOrderedQuery<AuditLogEntry>('audit_logs', 'timestamp', capped);
  }

  async createBackup(
    createdBy: string,
    trigger: BackupSnapshot['trigger']
  ): Promise<BackupSnapshot> {
    const [certs, reservedCerts, reservedRegs, settings, auditLogCount] = await Promise.all([
      this.getAllCertificates(),
      this.listCollection<ReservedCertNumberRecord>('reserved_certificate_numbers'),
      this.listCollection<ReservedRegNumberRecord>('reserved_scrapping_numbers'),
      this.getSettings(),
      this.countCollection('audit_logs'),
    ]);

    const payloadObj = {
      schemaVersion: 2,
      exportedAt: new Date().toISOString(),
      certificates: certs,
      reservedCertNumbers: reservedCerts,
      reservedRegNumbers: reservedRegs,
      settings,
    };
    const payloadJson = JSON.stringify(payloadObj);
    const sha256Checksum = computeSha256(payloadJson);
    const { chunks, compressedBytes } = encodeBackupPayloadChunks(payloadJson, this.maxChunkChars);
    const backupId = generateRecordId('bkp');

    // Store gzip-compressed base64 chunks in database_backup_chunks (each <= 450 KB, safe under 1 MiB limit)
    const chunkWrites = chunks.map((data, chunkIndex) => ({
      update: {
        name: `${this.docRoot}/database_backup_chunks/${backupId}_chunk_${chunkIndex}`,
        fields: toFirestoreFields({
          backupId,
          chunkIndex,
          chunkCount: chunks.length,
          data,
        }),
      },
    }));
    // Batch up to 10 chunks per commit (~4.5 MB max request, well below Firestore's 10 MiB request limit)
    await this.commitWritesInBatches(chunkWrites, 10);

    // Post-write read-back verification of chunks BEFORE publishing backup metadata
    // Ensures an incomplete/corrupted backup NEVER becomes the latest backup snapshot
    const verifyMetaDraft: FirestoreBackupMetadataDoc = {
      id: backupId,
      createdAt: payloadObj.exportedAt,
      createdBy,
      trigger,
      certificateCount: certs.length,
      reservedCertCount: reservedCerts.length,
      reservedRegCount: reservedRegs.length,
      auditLogCount,
      sha256Checksum,
      verified: false,
      sizeBytes: Buffer.byteLength(payloadJson, 'utf8'),
      storageTarget: `Firestore (${this.projectId}/${this.databaseId})`,
      payloadEncoding: 'gzip-base64-chunks',
      chunkCount: chunks.length,
      compressedBytes,
    };

    const readBackPayload = await this.loadBackupPayloadJson(verifyMetaDraft);
    const readBackHash = computeSha256(readBackPayload);
    if (readBackHash !== sha256Checksum) {
      throw new Error(
        `Backup post-write SHA-256 verification failed for ${backupId}. Previous good backups remain untouched.`
      );
    }

    const metaDoc: FirestoreBackupMetadataDoc = {
      ...verifyMetaDraft,
      verified: true,
    };

    // Store lightweight metadata ONLY in database_backups so listBackups() never drains Spark egress
    await this.setDoc('database_backups', metaDoc.id, metaDoc);
    return this.toPublicBackupSnapshot(metaDoc);
  }

  async listBackups(): Promise<BackupSnapshot[]> {
    const docs = await this.runOrderedQuery<FirestoreBackupMetadataDoc>('database_backups', 'createdAt', 100);
    return docs.map((doc) => this.toPublicBackupSnapshot(doc));
  }

  async getBackupDownload(backupId: string): Promise<{
    filename: string;
    sha256Checksum: string;
    payloadJson: string;
  }> {
    const doc = await this.getDoc<FirestoreBackupMetadataDoc>('database_backups', backupId);
    if (!doc) throw new Error('Backup snapshot not found');
    const payloadJson = await this.loadBackupPayloadJson(doc);
    return {
      filename: `parivahan_backup_${doc.id}.json`,
      sha256Checksum: doc.sha256Checksum,
      payloadJson,
    };
  }

  async dryRunRestoreBackup(backupId: string): Promise<BackupDryRunResult> {
    const doc = await this.getDoc<FirestoreBackupMetadataDoc>('database_backups', backupId);
    if (!doc) throw new Error('Backup snapshot not found');
    const payloadJson = await this.loadBackupPayloadJson(doc);
    const computedChecksum = computeSha256(payloadJson);
    const checksumValid = computedChecksum === doc.sha256Checksum;
    const parsed = JSON.parse(payloadJson) as { certificates: CertificateRecord[] };
    const [currentCerts, reserved] = await Promise.all([
      this.getAllCertificates(),
      this.getReservedCounts(),
    ]);
    const snapshotIds = new Set(parsed.certificates.map((c) => c.id));
    const onlyInCurrent = currentCerts.filter((c) => !snapshotIds.has(c.id)).length;
    const warnings: string[] = [];
    if (!checksumValid) warnings.push('SHA-256 checksum mismatch detected. Restore is blocked.');
    if (onlyInCurrent > 0) {
      warnings.push(
        `${onlyInCurrent} certificate(s) issued after this snapshot will be superseded. Reserved numbers remain locked.`
      );
    }
    return {
      backupId,
      checksumValid,
      computedChecksum,
      storedChecksum: doc.sha256Checksum,
      currentCertificateCount: currentCerts.length,
      snapshotCertificateCount: parsed.certificates.length,
      certificatesToRestore: parsed.certificates.length,
      certificatesOnlyInCurrent: onlyInCurrent,
      reservedNumbersPreserved: reserved.certCount,
      safeToRestore: checksumValid,
      warnings,
    };
  }

  async restoreBackup(
    backupId: string,
    actor: string
  ): Promise<{ restoredCount: number; safetyBackupId: string }> {
    const dryRun = await this.dryRunRestoreBackup(backupId);
    if (!dryRun.checksumValid) {
      throw new Error('Cannot restore corrupted backup: SHA-256 verification failed');
    }
    const safetyBackup = await this.createBackup(actor, 'PRE_RESTORE_SAFETY');
    const doc = await this.getDoc<FirestoreBackupMetadataDoc>('database_backups', backupId);
    if (!doc) throw new Error('Backup snapshot not found');
    const payloadJson = await this.loadBackupPayloadJson(doc);
    const parsed = JSON.parse(payloadJson) as {
      certificates: CertificateRecord[];
      reservedCertNumbers?: Array<{ certificateNumber: string; reservedAt: string; certificateId: string }>;
      reservedRegNumbers?: Array<{ scrappingRegNumber: string; reservedAt: string; certificateId: string }>;
    };

    const currentCerts = await this.getAllCertificates();
    const snapshotIds = new Set(parsed.certificates.map((c) => c.id));

    const writes: Array<Record<string, unknown>> = [];

    // 1. Upsert all certificates from snapshot
    for (const cert of parsed.certificates) {
      writes.push({
        update: {
          name: `${this.docRoot}/certificates/${cert.id}`,
          fields: toFirestoreFields(cert as unknown as Record<string, unknown>),
        },
      });
    }

    // 2. Remove certificates created after the snapshot (matching dry-run & safety backup semantics)
    for (const existingCert of currentCerts) {
      if (!snapshotIds.has(existingCert.id)) {
        writes.push({
          delete: `${this.docRoot}/certificates/${existingCert.id}`,
        });
      }
    }

    // 3. Union reserved numbers so previously issued numbers are NEVER freed for reuse
    for (const r of parsed.reservedCertNumbers ?? []) {
      const normalized = r.certificateNumber.toUpperCase();
      writes.push({
        update: {
          name: `${this.docRoot}/reserved_certificate_numbers/${encodeDocKey(normalized)}`,
          fields: toFirestoreFields({
            certificateNumber: normalized,
            reservedAt: r.reservedAt,
            certificateId: r.certificateId,
          }),
        },
      });
    }
    for (const r of parsed.reservedRegNumbers ?? []) {
      const normalized = r.scrappingRegNumber.toUpperCase();
      writes.push({
        update: {
          name: `${this.docRoot}/reserved_scrapping_numbers/${encodeDocKey(normalized)}`,
          fields: toFirestoreFields({
            scrappingRegNumber: normalized,
            reservedAt: r.reservedAt,
            certificateId: r.certificateId,
          }),
        },
      });
    }

    if (writes.length > 0) {
      await this.commitWritesInBatches(writes, 350);
    }

    return { restoredCount: parsed.certificates.length, safetyBackupId: safetyBackup.id };
  }

  async addDriveSyncLog(log: DriveSyncLog): Promise<void> {
    await this.setDoc('drive_sync_logs', log.id, log);
  }

  async getDriveSyncLogs(limit = 100): Promise<DriveSyncLog[]> {
    const capped = Math.min(Math.max(1, limit), 500);
    return this.runOrderedQuery<DriveSyncLog>('drive_sync_logs', 'attemptedAt', capped);
  }

  async addSystemError(err: SystemErrorLog): Promise<void> {
    await this.setDoc('system_errors', err.id, err);
  }

  async getSystemErrors(limit = 100): Promise<SystemErrorLog[]> {
    const capped = Math.min(Math.max(1, limit), 500);
    return this.runOrderedQuery<SystemErrorLog>('system_errors', 'timestamp', capped);
  }
}

// ============================================================================
// 3. PRODUCTION SAFETY GUARD (Blocks ephemeral memory writes on Vercel if
//    FIREBASE_PROJECT_ID / CLIENT_EMAIL / PRIVATE_KEY are missing)
// ============================================================================
class UnconfiguredProductionStore implements RegistryStore {
  readonly mode = 'firestore_unconfigured' as const;
  readonly projectId = null;
  readonly databaseId = null;
  readonly missingEnvVars: string[];

  constructor(missingEnvVars: string[]) {
    this.missingEnvVars = missingEnvVars;
  }

  private fail(): never {
    const err = new Error(
      `Production Firestore database is not configured. Add ${this.missingEnvVars.join(', ')} in Vercel Environment Variables.`
    );
    (err as NodeJS.ErrnoException).code = 'FIRESTORE_UNCONFIGURED';
    throw err;
  }

  async ping() {
    return {
      ok: false,
      latencyMs: 0,
      message: `Missing Vercel Firestore environment variables: ${this.missingEnvVars.join(', ')}`,
    };
  }
  async getCredentials() { return null; }
  async saveCredentials() { this.fail(); }
  async createCredentialsIfAbsent(): Promise<boolean> { this.fail(); }
  async createSession() { this.fail(); }
  async getSession() { return null; }
  async updateSessionScrapRouteAuth() { /* no-op while unconfigured */ }
  async revokeSession() { /* no-op while unconfigured */ }
  async getSettings() {
    return {
      ...DEFAULT_SETTINGS,
      publicDomain: process.env.PUBLIC_APP_URL?.trim() || '',
    };
  }
  async saveSettings() { this.fail(); }
  async isCertNumberReserved(): Promise<boolean> { return this.fail(); }
  async isScrappingRegReserved(): Promise<boolean> { return this.fail(); }
  async getReservedCounts() { return { certCount: 0, regCount: 0 }; }
  async getAllReservedNumbers() { return this.fail(); }
  async getIdempotencyRecord(): Promise<IdempotencyRecord | null> { return this.fail(); }
  async createCertificateAtomic(): Promise<CertificateRecord> { return this.fail(); }
  async appendCertificateVersion() { this.fail(); }
  async getCertificateVersions(): Promise<CertificateVersionDocument[]> { return this.fail(); }
  async getCertificateById(): Promise<CertificateRecord | null> { return this.fail(); }
  async getCertificateByNumber(): Promise<CertificateRecord | null> { return this.fail(); }
  async getRecentActiveCertificates(): Promise<CertificateRecord[]> { return this.fail(); }
  async getAllCertificates(): Promise<CertificateRecord[]> { return this.fail(); }
  async saveCertificate() { this.fail(); }
  async permanentlyDeleteCertificate() { this.fail(); }
  async addAuditLog() { /* no-op while unconfigured */ }
  async getAuditLogs() { return []; }
  async createBackup(): Promise<BackupSnapshot> { this.fail(); }
  async listBackups() { return []; }
  async getBackupDownload(): Promise<{ filename: string; sha256Checksum: string; payloadJson: string }> { this.fail(); }
  async dryRunRestoreBackup(): Promise<BackupDryRunResult> { this.fail(); }
  async restoreBackup(): Promise<{ restoredCount: number; safetyBackupId: string }> { this.fail(); }
  async addDriveSyncLog() { /* no-op while unconfigured */ }
  async getDriveSyncLogs() { return []; }
  async addSystemError() { /* no-op while unconfigured */ }
  async getSystemErrors() { return []; }
}

let singletonStore: RegistryStore | null = null;

export function resetStoreForTesting(): void {
  singletonStore = null;
}

export function getStore(): RegistryStore {
  if (singletonStore) return singletonStore;

  const projectId = process.env.FIREBASE_PROJECT_ID?.trim();
  const databaseId = process.env.FIREBASE_DATABASE_ID?.trim() || '(default)';
  const clientEmail = process.env.FIREBASE_CLIENT_EMAIL?.trim();
  const privateKey = process.env.FIREBASE_PRIVATE_KEY?.trim();

  if (projectId && clientEmail && privateKey) {
    singletonStore = new FirestoreRestStore({
      projectId,
      databaseId,
      clientEmail,
      privateKey,
    });
    return singletonStore;
  }

  // On Vercel production, strictly prevent falling back to ephemeral in-memory storage
  const isVercelDeployment = process.env.VERCEL === '1' || process.env.REQUIRE_FIRESTORE === 'true';
  if (isVercelDeployment) {
    const missing: string[] = [];
    if (!projectId) missing.push('FIREBASE_PROJECT_ID');
    if (!clientEmail) missing.push('FIREBASE_CLIENT_EMAIL');
    if (!privateKey) missing.push('FIREBASE_PRIVATE_KEY');
    singletonStore = new UnconfiguredProductionStore(missing);
    return singletonStore;
  }

  singletonStore = new StagingMemoryStore();
  return singletonStore;
}
