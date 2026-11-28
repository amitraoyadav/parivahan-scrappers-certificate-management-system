export type UserRole = 'maker' | 'main_admin';

export type CertificateBrand = 'parivahan' | 'scrap_route';

export type CertificateStatus = 'ACTIVE' | 'CANCELLED' | 'SOFT_DELETED';

export type DriveSyncState = 'NOT_CONFIGURED' | 'PENDING' | 'SYNCED' | 'FAILED';

export type IdProofType =
  | ''
  | 'Aadhaar Card'
  | 'PAN Card'
  | 'Driving License'
  | 'Passport'
  | 'Voter ID';

export interface CertificateCoreFields {
  ownerName: string;
  ownerAddress?: string;
  idProofType?: IdProofType;
  idProofNumber?: string;
  vehicleRegNumber: string;
  make: string;
  model: string;
  manufactureYear: number;
  chassisNumber: string;
  engineNumber: string;
  unhideChassisEngine?: boolean;
  rtoAuthority?: string;
  issueDate: string;
  handoverDate: string;
  facilityName: string;
  facilityAddress: string;
  remarks: string;
}

export interface OriginalCertificateSnapshot {
  version: 1;
  issuedAt: string;
  issuedBy: string;
  issuedByRole: UserRole;
  brand: CertificateBrand;
  certificateNumber: string;
  scrappingRegNumber: string;
  canonicalHash: string;
  qrToken: string;
  data: CertificateCoreFields;
}

export interface CertificateVersionSnapshot {
  version: number;
  editedAt: string;
  editedBy: string;
  actorRole?: UserRole;
  reason: string;
  changedFields?: string[];
  previousCanonicalHash: string;
  newCanonicalHash?: string;
  previousData: CertificateCoreFields;
}

export interface CertificateVersionDocument {
  id: string;
  certificateId: string;
  certificateNumber: string;
  brand: CertificateBrand;
  version: number;
  recordedAt: string;
  actor: string;
  actorRole: UserRole;
  event: 'ISSUED' | 'MODIFIED' | 'CANCELLED' | 'ARCHIVED' | 'RESTORED';
  reason?: string;
  changedFields: string[];
  previousCanonicalHash?: string;
  canonicalHash: string;
  data: CertificateCoreFields;
}

export interface CertificateRecord {
  id: string;
  brand?: CertificateBrand;
  certificateNumber: string;
  scrappingRegNumber: string;
  status: CertificateStatus;
  version: number;

  // Dates
  issueDate: string;
  handoverDate: string;

  // Owner Particulars
  ownerName: string;
  ownerAddress: string;
  idProofType: IdProofType;
  idProofNumber: string;

  // Vehicle Particulars
  vehicleRegNumber: string; // RC Number / Vehicle Number
  make: string;
  model: string;
  manufactureYear: number;
  chassisNumber: string;
  engineNumber: string;
  unhideChassisEngine: boolean;
  rtoAuthority?: string;

  // Scrapping Facility Particulars
  facilityName: string;
  facilityRvsfCode: string;
  facilityAddress: string;
  remarks: string;

  // Cryptographic & Integrity Fields
  qrToken: string;
  canonicalHash: string;

  // Lifecycle & Governance Metadata
  createdAt: string;
  updatedAt: string;
  createdBy: string;
  createdByRole: UserRole;
  cancelledAt?: string;
  cancelledBy?: string;
  cancelReason?: string;
  deletedAt?: string;
  deletedBy?: string;
  deleteReason?: string;
  originalRecord?: OriginalCertificateSnapshot;
  versionHistory: CertificateVersionSnapshot[];

  // Optional Google Drive Backup Tracking
  driveSyncStatus: DriveSyncState;
  driveFileId?: string;
  driveSyncedAt?: string;
  driveLastError?: string;
}

export interface CreateCertificateInput {
  brand?: CertificateBrand;
  certificateNumber?: string;
  scrappingRegNumber?: string;
  issueDate: string;
  handoverDate: string;
  ownerName: string;
  ownerAddress?: string;
  idProofType?: IdProofType;
  idProofNumber?: string;
  vehicleRegNumber: string; // RC Number / Vehicle Number
  make: string;
  model: string;
  manufactureYear: number;
  chassisNumber: string;
  engineNumber: string;
  unhideChassisEngine?: boolean;
  rtoAuthority?: string;
  remarks?: string;
}

export interface PublicVerificationResult {
  found: boolean;
  verified: boolean;
  integrityMatch: boolean;
  tokenMatch: boolean | null;
  status?: CertificateStatus;
  brand?: CertificateBrand;
  brandDisplayName?: string;
  certificateNumber?: string;
  scrappingRegNumber?: string;
  ownerName?: string;
  vehicleRegNumber?: string;
  make?: string;
  model?: string;
  manufactureYear?: number;
  issueDate?: string;
  handoverDate?: string;
  maskedChassisNumber?: string;
  maskedEngineNumber?: string;
  facilityName?: string;
  facilityRvsfCode?: string;
  canonicalHash?: string;
  recomputedHash?: string;
  version?: number;
  originalIssuedAt?: string;
  lastModifiedAt?: string;
  versionHistoryCount?: number;
  cancelledAt?: string;
  cancelReason?: string;
  checkedAt: string;
  message: string;
}

export interface AuditLogEntry {
  id: string;
  timestamp: string;
  actor: string;
  actorRole: UserRole | 'system';
  action:
    | 'BOOTSTRAP_SECURITY'
    | 'LOGIN_SUCCESS'
    | 'LOGIN_FAILED'
    | 'ADMIN_UNLOCK_SUCCESS'
    | 'ADMIN_UNLOCK_FAILED'
    | 'LOGOUT'
    | 'CERTIFICATE_CREATED'
    | 'CERTIFICATE_ISSUANCE_FAILED'
    | 'CERTIFICATE_EDITED'
    | 'CERTIFICATE_CANCELLED'
    | 'CERTIFICATE_SOFT_DELETED'
    | 'CERTIFICATE_RESTORED'
    | 'CERTIFICATE_PERMANENTLY_DELETED'
    | 'BACKUP_CREATED'
    | 'BACKUP_FAILED'
    | 'BACKUP_DRY_RUN'
    | 'BACKUP_STAGING_VERIFIED'
    | 'BACKUP_RESTORED'
    | 'INTEGRITY_AUDIT_RUN'
    | 'REGISTRY_EXPORTED'
    | 'SETTINGS_UPDATED'
    | 'PASSWORD_ROTATED'
    | 'SCRAP_ROUTE_PIN_VERIFIED'
    | 'SCRAP_ROUTE_PIN_FAILED'
    | 'SCRAP_ROUTE_LOCKED'
    | 'DRIVE_SYNC_SUCCESS'
    | 'DRIVE_SYNC_FAILED';
  certificateId?: string;
  certificateNumber?: string;
  reason?: string;
  ipAddress?: string;
  metadata?: Record<string, string | number | boolean>;
}

export interface BackupSnapshot {
  id: string;
  createdAt: string;
  createdBy: string;
  trigger: 'MANUAL' | 'SCHEDULED' | 'PRE_RESTORE_SAFETY';
  certificateCount: number;
  reservedCertCount: number;
  reservedRegCount: number;
  auditLogCount: number;
  sha256Checksum: string;
  verified: boolean;
  sizeBytes: number;
  storageTarget: string;
}

export interface BackupDryRunResult {
  backupId: string;
  checksumValid: boolean;
  computedChecksum: string;
  storedChecksum: string;
  currentCertificateCount: number;
  snapshotCertificateCount: number;
  certificatesToRestore: number;
  certificatesOnlyInCurrent: number;
  reservedNumbersPreserved: number;
  safeToRestore: boolean;
  warnings: string[];
}

export interface IntegrityDiscrepancy {
  severity: 'CRITICAL' | 'WARNING';
  code:
    | 'DUPLICATE_CERTIFICATE_NUMBER'
    | 'DUPLICATE_SCRAPPING_REG_NUMBER'
    | 'BRAND_PREFIX_MISMATCH'
    | 'MISSING_REQUIRED_FIELD'
    | 'SHA256_HASH_MISMATCH'
    | 'MISSING_RESERVED_CERT_NUMBER'
    | 'MISSING_RESERVED_REG_NUMBER'
    | 'MISSING_DRIVE_PDF'
    | 'VERSION_HISTORY_MISMATCH'
    | 'COUNT_AUDIT_DISCREPANCY'
    | 'BACKUP_UNVERIFIED_OR_MISSING';
  certificateId?: string;
  certificateNumber?: string;
  message: string;
  details?: string;
}

export interface DatabaseIntegrityReport {
  auditedAt: string;
  readOnly: true;
  healthy: boolean;
  storageMode: 'firestore' | 'staging_memory' | 'firestore_unconfigured';
  firestoreConnected: boolean;
  firestoreProjectId: string | null;
  firestoreDatabaseId: string | null;
  counts: {
    totalCertificates: number;
    parivahanCertificates: number;
    scrapRouteCertificates: number;
    activeCertificates: number;
    archivedCertificates: number;
    cancelledCertificates: number;
    reservedCertNumbers: number;
    reservedRegNumbers: number;
    failedIssuanceAttempts: number;
    modifiedCertificates: number;
    integrityMismatches: number;
    missingDrivePdfs: number;
  };
  auditComparison: {
    createdEventsInRecentAudit: number;
    permanentDeleteEventsInRecentAudit: number;
    latestBackupCertificateCount: number | null;
    latestBackupId: string | null;
  };
  backupHealth: {
    totalBackups: number;
    lastSuccessfulBackupAt: string | null;
    lastBackupVerified: boolean;
    recentBackupFailures: number;
    lastBackupFailureAt: string | null;
    lastBackupFailureMessage: string | null;
  };
  lastIntegrityAuditAt: string;
  discrepancies: IntegrityDiscrepancy[];
  firebasePlanNotes: {
    managedScheduledBackupsRequireBlaze: true;
    pitrRequiresBlaze: true;
    activeProtectionStrategy: string;
  };
}

export interface StagingRestoreVerificationResult {
  backupId: string;
  verifiedAt: string;
  stagingEnvironment: 'isolated_ephemeral_staging_store';
  checksumValid: boolean;
  stagingRestoredCount: number;
  stagingParivahanCount: number;
  stagingScrapRouteCount: number;
  stagingActiveCount: number;
  stagingArchivedCount: number;
  stagingReservedCertCount: number;
  stagingIntegrityHealthy: boolean;
  stagingIntegrityMismatches: number;
  safeForProductionRecovery: boolean;
  warnings: string[];
  discrepancies: IntegrityDiscrepancy[];
}

export interface DriveSyncLog {
  id: string;
  certificateId: string;
  certificateNumber: string;
  attemptedAt: string;
  status: DriveSyncState;
  driveFileId?: string;
  errorMessage?: string;
  attemptCount: number;
}

export interface SystemErrorLog {
  id: string;
  timestamp: string;
  route: string;
  method: string;
  message: string;
  code?: string;
}

export interface SystemSettings {
  facilityName: string;
  facilityRvsfCode: string;
  facilityAddress: string;
  facilityPhone: string;
  facilityEmail: string;
  authorizedSignatory: string;
  signatoryDesignation: string;
  publicDomain: string;
  backupRetentionDays: number;
  driveSyncEnabled: boolean;
  driveFolderId: string;
  updatedAt: string;
  updatedBy: string;
}

export interface DashboardStats {
  totalCertificates: number;
  parivahanCertificates: number;
  scrapRouteCertificates: number;
  activeCertificates: number;
  cancelledCertificates: number;
  softDeletedCertificates: number;
  modifiedCertificates: number;
  failedIssuanceAttempts: number;
  issuedToday: number;
  issuedThisMonth: number;
  reservedCertNumbers: number;
  reservedRegNumbers: number;
  totalBackups: number;
  lastBackupAt: string | null;
  driveSyncedCount: number;
  driveFailedCount: number;
  storageMode: 'firestore' | 'staging_memory' | 'firestore_unconfigured';
}

export interface AuthStatusResponse {
  requiresBootstrap: boolean;
  envConfigured: boolean;
  storageMode: 'firestore' | 'staging_memory' | 'firestore_unconfigured';
  missingFirestoreEnvVars?: string[];
  firestoreProjectId: string | null;
  firestoreDatabaseId: string | null;
  session: SessionInfo | null;
  scrapRoutePinConfigured?: boolean;
  scrapRouteAuthorized?: boolean;
  facilityName: string;
  publicDomain: string;
  authorizedSignatory: string;
  signatoryDesignation: string;
}

export interface SessionInfo {
  sid?: string;
  username: string;
  role: UserRole;
  issuedAt: number;
  expiresAt: number;
  sessionVersion: number;
  rememberMe?: boolean;
  scrapRouteAuthorizedUntil?: number;
}

export interface CandidateNumbers {
  brand: CertificateBrand;
  certificateNumber: string;
  scrappingRegNumber: string;
  issueYearShort: string;
}
