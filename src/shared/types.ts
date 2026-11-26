export type UserRole = 'maker' | 'main_admin';

export type CertificateStatus = 'ACTIVE' | 'CANCELLED' | 'SOFT_DELETED';

export type DriveSyncState = 'NOT_CONFIGURED' | 'PENDING' | 'SYNCED' | 'FAILED';

export type IdProofType =
  | ''
  | 'Aadhaar Card'
  | 'PAN Card'
  | 'Driving License'
  | 'Passport'
  | 'Voter ID';

export interface CertificateVersionSnapshot {
  version: number;
  editedAt: string;
  editedBy: string;
  reason: string;
  previousCanonicalHash: string;
  previousData: {
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
    rtoAuthority: string;
    issueDate: string;
    handoverDate: string;
    facilityName: string;
    facilityAddress: string;
    remarks: string;
  };
}

export interface CertificateRecord {
  id: string;
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
  rtoAuthority: string;

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
  versionHistory: CertificateVersionSnapshot[];

  // Optional Google Drive Backup Tracking
  driveSyncStatus: DriveSyncState;
  driveFileId?: string;
  driveSyncedAt?: string;
  driveLastError?: string;
}

export interface CreateCertificateInput {
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
  rtoAuthority: string;
  remarks?: string;
}

export interface PublicVerificationResult {
  found: boolean;
  verified: boolean;
  integrityMatch: boolean;
  tokenMatch: boolean | null;
  status?: CertificateStatus;
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
    | 'CERTIFICATE_EDITED'
    | 'CERTIFICATE_CANCELLED'
    | 'CERTIFICATE_SOFT_DELETED'
    | 'CERTIFICATE_RESTORED'
    | 'CERTIFICATE_PERMANENTLY_DELETED'
    | 'BACKUP_CREATED'
    | 'BACKUP_DRY_RUN'
    | 'BACKUP_RESTORED'
    | 'SETTINGS_UPDATED'
    | 'PASSWORD_ROTATED'
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
  activeCertificates: number;
  cancelledCertificates: number;
  softDeletedCertificates: number;
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
  facilityName: string;
  publicDomain: string;
  authorizedSignatory: string;
  signatoryDesignation: string;
}

export interface SessionInfo {
  username: string;
  role: UserRole;
  issuedAt: number;
  expiresAt: number;
  sessionVersion: number;
}

export interface CandidateNumbers {
  certificateNumber: string;
  scrappingRegNumber: string;
  issueYearShort: string;
}
