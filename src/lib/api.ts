import type {
  AuditLogEntry,
  AuthStatusResponse,
  BackupDryRunResult,
  BackupSnapshot,
  CandidateNumbers,
  CertificateRecord,
  CreateCertificateInput,
  DashboardStats,
  DriveSyncLog,
  PublicVerificationResult,
  SessionInfo,
  SystemErrorLog,
  SystemSettings,
} from '../shared/types';

// In-memory bearer token (never written to localStorage or sessionStorage)
let memoryBearerToken: string | null = null;

export function setMemoryToken(token: string | null): void {
  memoryBearerToken = token;
}

export class ApiError extends Error {
  status: number;
  constructor(message: string, status: number) {
    super(message);
    this.status = status;
  }
}

async function apiRequest<T>(
  path: string,
  options: RequestInit & { idempotencyKey?: string } = {}
): Promise<T> {
  const headers = new Headers(options.headers);
  headers.set('X-Requested-With', 'XMLHttpRequest');
  if (options.body && !headers.has('Content-Type')) {
    headers.set('Content-Type', 'application/json');
  }
  if (memoryBearerToken) {
    headers.set('Authorization', `Bearer ${memoryBearerToken}`);
  }
  if (options.idempotencyKey) {
    headers.set('Idempotency-Key', options.idempotencyKey);
  }

  const res = await fetch(path, {
    ...options,
    credentials: 'include',
    headers,
  });

  const text = await res.text();
  let parsed: Record<string, unknown> = {};
  if (text) {
    try {
      parsed = JSON.parse(text) as Record<string, unknown>;
    } catch {
      parsed = { error: text };
    }
  }

  if (!res.ok) {
    const msg =
      typeof parsed.error === 'string'
        ? parsed.error
        : `Request failed with status ${res.status}`;
    throw new ApiError(msg, res.status);
  }

  return parsed as T;
}

export const api = {
  // Public & Auth
  getAuthStatus(): Promise<AuthStatusResponse> {
    return apiRequest<AuthStatusResponse>('/api/auth/status');
  },

  bootstrapSecurity(payload: {
    makerUsername: string;
    makerPassword: string;
    mainAdminPassword: string;
    protectedPassword: string;
  }): Promise<{ success: boolean; makerUsername: string; message: string }> {
    return apiRequest('/api/auth/bootstrap', {
      method: 'POST',
      body: JSON.stringify(payload),
    });
  },

  async loginMaker(username: string, password: string): Promise<SessionInfo> {
    const data = await apiRequest<{ session: SessionInfo; token: string }>('/api/auth/login', {
      method: 'POST',
      body: JSON.stringify({ username, password }),
    });
    setMemoryToken(data.token);
    return data.session;
  },

  async unlockMainAdmin(password: string): Promise<SessionInfo> {
    const data = await apiRequest<{ session: SessionInfo; token: string }>('/api/auth/admin-unlock', {
      method: 'POST',
      body: JSON.stringify({ password }),
    });
    setMemoryToken(data.token);
    return data.session;
  },

  async logout(): Promise<void> {
    try {
      await apiRequest('/api/auth/logout', { method: 'POST' });
    } finally {
      setMemoryToken(null);
    }
  },

  // Public Verification (never throws on 404 — returns structured verification result)
  async verifyPublicCertificate(
    certificateNumber: string,
    token?: string
  ): Promise<PublicVerificationResult> {
    const qs = new URLSearchParams({ certificateNumber: certificateNumber.trim() });
    if (token?.trim()) qs.set('token', token.trim());
    const res = await fetch(`/api/verify?${qs.toString()}`, {
      headers: { 'X-Requested-With': 'XMLHttpRequest' },
    });
    return (await res.json()) as PublicVerificationResult;
  },

  // Maker & Issuance
  getCandidateNumbers(issueDate?: string): Promise<CandidateNumbers> {
    const qs = issueDate ? `?issueDate=${encodeURIComponent(issueDate)}` : '';
    return apiRequest<CandidateNumbers>(`/api/certificates/candidate-numbers${qs}`);
  },

  getRecentCertificates(): Promise<{ certificates: CertificateRecord[]; maxAllowed: number }> {
    return apiRequest('/api/certificates/recent');
  },

  createCertificate(
    payload: CreateCertificateInput,
    idempotencyKey: string
  ): Promise<{
    certificate: CertificateRecord;
    idempotentReplay: boolean;
    persistenceMs: number;
  }> {
    return apiRequest('/api/certificates', {
      method: 'POST',
      idempotencyKey,
      body: JSON.stringify({ ...payload, idempotencyKey }),
    });
  },

  // Main Core Admin
  getAdminStats(): Promise<DashboardStats> {
    return apiRequest<DashboardStats>('/api/admin/stats');
  },

  getAdminCertificates(params?: {
    search?: string;
    status?: string;
  }): Promise<{ certificates: CertificateRecord[]; total: number; registryTotal: number }> {
    const qs = new URLSearchParams();
    if (params?.search) qs.set('search', params.search);
    if (params?.status && params.status !== 'ALL') qs.set('status', params.status);
    const suffix = qs.toString() ? `?${qs.toString()}` : '';
    return apiRequest(`/api/admin/certificates${suffix}`);
  },

  editCertificateProtected(
    id: string,
    payload: {
      protectedPassword: string;
      reason: string;
      updates: Partial<CreateCertificateInput>;
    }
  ): Promise<{ certificate: CertificateRecord }> {
    return apiRequest(`/api/admin/certificates/${encodeURIComponent(id)}`, {
      method: 'PUT',
      body: JSON.stringify(payload),
    });
  },

  cancelCertificateProtected(
    id: string,
    payload: { protectedPassword: string; reason: string }
  ): Promise<{ certificate: CertificateRecord }> {
    return apiRequest(`/api/admin/certificates/${encodeURIComponent(id)}/cancel`, {
      method: 'POST',
      body: JSON.stringify(payload),
    });
  },

  deleteCertificateProtected(
    id: string,
    payload: {
      deletePassword: string;
      reason: string;
      permanent?: boolean;
      confirmPhrase?: string;
    }
  ): Promise<{
    deleted: boolean;
    permanent: boolean;
    safetyBackupId?: string;
    certificate?: CertificateRecord;
  }> {
    return apiRequest(`/api/admin/certificates/${encodeURIComponent(id)}`, {
      method: 'DELETE',
      body: JSON.stringify(payload),
    });
  },

  restoreCertificateProtected(
    id: string,
    payload: { protectedPassword: string; reason: string }
  ): Promise<{ certificate: CertificateRecord }> {
    return apiRequest(`/api/admin/certificates/${encodeURIComponent(id)}/restore`, {
      method: 'POST',
      body: JSON.stringify(payload),
    });
  },

  getAuditLogs(): Promise<{ logs: AuditLogEntry[] }> {
    return apiRequest('/api/admin/audit-logs');
  },

  getBackups(): Promise<{ backups: BackupSnapshot[] }> {
    return apiRequest('/api/admin/backups');
  },

  createBackup(): Promise<{ backup: BackupSnapshot }> {
    return apiRequest('/api/admin/backups/create', { method: 'POST' });
  },

  async downloadBackupJson(id: string): Promise<void> {
    const headers = new Headers({ 'X-Requested-With': 'XMLHttpRequest' });
    if (memoryBearerToken) {
      headers.set('Authorization', `Bearer ${memoryBearerToken}`);
    }
    const res = await fetch(`/api/admin/backups/${encodeURIComponent(id)}/download`, {
      credentials: 'include',
      headers,
    });
    if (!res.ok) {
      throw new ApiError('Unable to download verified backup snapshot.', res.status);
    }
    const blob = await res.blob();
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `parivahan_backup_${id}.json`;
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
  },

  dryRunBackup(id: string): Promise<{ dryRun: BackupDryRunResult }> {
    return apiRequest(`/api/admin/backups/${encodeURIComponent(id)}/dry-run`, {
      method: 'POST',
    });
  },

  restoreBackup(
    id: string,
    payload: { protectedPassword: string; confirmPhrase: string }
  ): Promise<{ success: boolean; restoredCount: number; safetyBackupId: string }> {
    return apiRequest(`/api/admin/backups/${encodeURIComponent(id)}/restore`, {
      method: 'POST',
      body: JSON.stringify(payload),
    });
  },

  getSettings(): Promise<{
    settings: SystemSettings;
    envManagedCredentials: boolean;
    driveEnvConfigured: boolean;
    storageMode: 'firestore' | 'staging_memory' | 'firestore_unconfigured';
    firestoreProjectId: string | null;
    firestoreDatabaseId: string | null;
  }> {
    return apiRequest('/api/admin/settings');
  },

  updateSettings(settings: Partial<SystemSettings>): Promise<{ settings: SystemSettings }> {
    return apiRequest('/api/admin/settings', {
      method: 'PUT',
      body: JSON.stringify(settings),
    });
  },

  async rotatePasswords(payload: {
    currentMainPassword: string;
    makerUsername?: string;
    newMakerPassword?: string;
    newMainAdminPassword?: string;
    newProtectedPassword?: string;
  }): Promise<{ success: boolean; session: SessionInfo; message: string }> {
    const data = await apiRequest<{
      success: boolean;
      session: SessionInfo;
      token: string;
      message: string;
    }>('/api/admin/rotate-passwords', {
      method: 'POST',
      body: JSON.stringify(payload),
    });
    setMemoryToken(data.token);
    return { success: data.success, session: data.session, message: data.message };
  },

  getAdminHealth(): Promise<{
    status: string;
    storageMode: 'firestore' | 'staging_memory' | 'firestore_unconfigured';
    firestoreConnected: boolean;
    storageLatencyMs: number;
    storageMessage: string;
    firestoreProjectId: string | null;
    firestoreDatabaseId: string | null;
    nodeVersion: string;
    uptimeSeconds: number;
    reservedCertNumbers: number;
    reservedRegNumbers: number;
    driveConfigured: boolean;
    recentErrors: SystemErrorLog[];
    driveLogs: DriveSyncLog[];
  }> {
    return apiRequest('/api/admin/health');
  },

  retryDriveSync(id: string): Promise<{ queued: boolean; certificateNumber: string }> {
    return apiRequest(`/api/admin/drive-sync/${encodeURIComponent(id)}/retry`, {
      method: 'POST',
    });
  },
};
