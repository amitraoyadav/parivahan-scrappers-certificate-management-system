import type {
  AuditLogEntry,
  AuthStatusResponse,
  BackupDryRunResult,
  BackupSnapshot,
  CandidateNumbers,
  CertificateBrand,
  CertificateRecord,
  CertificateVersionDocument,
  CertificateVersionSnapshot,
  CreateCertificateInput,
  DashboardStats,
  DatabaseIntegrityReport,
  DriveSyncLog,
  OriginalCertificateSnapshot,
  PublicVerificationResult,
  SessionInfo,
  StagingRestoreVerificationResult,
  SystemErrorLog,
  SystemSettings,
} from '../shared/types';

// In-memory tokens (never written to localStorage or sessionStorage)
let memoryBearerToken: string | null = null;
let memoryScrapRouteToken: string | null = null;

export function setMemoryToken(token: string | null): void {
  memoryBearerToken = token;
}

export function setMemoryScrapRouteToken(token: string | null): void {
  memoryScrapRouteToken = token;
}

export class ApiError extends Error {
  status: number;
  code?: string;
  constructor(message: string, status: number, code?: string) {
    super(message);
    this.status = status;
    this.code = code;
  }
}

const DEFAULT_API_TIMEOUT_MS = 20_000;
const RETRY_DELAYS_MS = [350, 800];

function isRetryableStatus(status: number): boolean {
  return status === 0 || status === 408 || status === 502 || status === 503 || status === 504;
}

function delay(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function apiRequestOnce<T>(
  path: string,
  options: RequestInit & { idempotencyKey?: string; timeoutMs?: number } = {}
): Promise<T> {
  const headers = new Headers(options.headers);
  headers.set('X-Requested-With', 'XMLHttpRequest');
  if (options.body && !headers.has('Content-Type')) {
    headers.set('Content-Type', 'application/json');
  }
  if (memoryBearerToken) {
    headers.set('Authorization', `Bearer ${memoryBearerToken}`);
  }
  if (memoryScrapRouteToken) {
    headers.set('X-Scrap-Route-Auth', memoryScrapRouteToken);
  }
  if (options.idempotencyKey) {
    headers.set('Idempotency-Key', options.idempotencyKey);
  }

  const controller = new AbortController();
  const timeoutMs = options.timeoutMs ?? DEFAULT_API_TIMEOUT_MS;
  const timer = setTimeout(() => controller.abort(), timeoutMs);

  let res: Response;
  try {
    res = await fetch(path, {
      ...options,
      signal: options.signal ?? controller.signal,
      credentials: 'include',
      headers,
    });
  } catch (err) {
    if (err instanceof Error && err.name === 'AbortError') {
      throw new ApiError('Request timed out while contacting the server. Please retry.', 408, 'REQUEST_TIMEOUT');
    }
    throw new ApiError('Network error while contacting the server. Please check your connection and retry.', 0, 'NETWORK_ERROR');
  } finally {
    clearTimeout(timer);
  }

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
    const code = typeof parsed.code === 'string' ? parsed.code : undefined;
    throw new ApiError(msg, res.status, code);
  }

  return parsed as T;
}

async function apiRequest<T>(
  path: string,
  options: RequestInit & { idempotencyKey?: string; timeoutMs?: number } = {}
): Promise<T> {
  const method = (options.method || 'GET').toUpperCase();
  const canRetry = method === 'GET' || (method === 'POST' && Boolean(options.idempotencyKey));
  const maxAttempts = canRetry ? RETRY_DELAYS_MS.length + 1 : 1;

  let lastError: unknown;
  for (let attempt = 0; attempt < maxAttempts; attempt++) {
    try {
      return await apiRequestOnce<T>(path, options);
    } catch (err) {
      lastError = err;
      const retryable = err instanceof ApiError && isRetryableStatus(err.status);
      if (!canRetry || !retryable || attempt >= maxAttempts - 1) {
        throw err;
      }
      await delay(RETRY_DELAYS_MS[attempt] ?? 800);
    }
  }
  throw lastError;
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

  async loginMaker(
    username: string,
    password: string,
    rememberMe = false
  ): Promise<SessionInfo> {
    const data = await apiRequest<{ session: SessionInfo; token: string }>('/api/auth/login', {
      method: 'POST',
      body: JSON.stringify({ username, password, rememberMe }),
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
      setMemoryScrapRouteToken(null);
    }
  },

  async verifyScrapRoutePin(
    pin: string
  ): Promise<{ authorized: boolean; expiresAt: number }> {
    const data = await apiRequest<{
      authorized: boolean;
      expiresAt: number;
      scrapRouteToken?: string;
    }>('/api/auth/scrap-route/verify-pin', {
      method: 'POST',
      body: JSON.stringify({ pin }),
    });
    if (data.scrapRouteToken) {
      setMemoryScrapRouteToken(data.scrapRouteToken);
    }
    return { authorized: data.authorized, expiresAt: data.expiresAt };
  },

  async lockScrapRoute(): Promise<{ authorized: boolean }> {
    try {
      return await apiRequest<{ authorized: boolean }>('/api/auth/scrap-route/lock', {
        method: 'POST',
      });
    } finally {
      setMemoryScrapRouteToken(null);
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
  getCandidateNumbers(
    issueDate?: string,
    brand: CertificateBrand = 'parivahan'
  ): Promise<CandidateNumbers> {
    const qs = new URLSearchParams();
    if (issueDate) qs.set('issueDate', issueDate);
    if (brand !== 'parivahan') qs.set('brand', brand);
    const suffix = qs.toString() ? `?${qs.toString()}` : '';
    return apiRequest<CandidateNumbers>(`/api/certificates/next-numbers${suffix}`);
  },

  reportPdfFailure(certificateId: string, reason: string): Promise<{ logged: boolean }> {
    return apiRequest('/api/diagnostics/pdf-failure', {
      method: 'POST',
      body: JSON.stringify({ certificateId, reason }),
    });
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
    verifiedReadBack?: boolean;
  }> {
    return apiRequest('/api/certificates', {
      method: 'POST',
      idempotencyKey,
      body: JSON.stringify({ ...payload, idempotencyKey }),
    });
  },

  editCertificateMaker(
    id: string,
    payload: { updates: Partial<CreateCertificateInput>; reason?: string }
  ): Promise<{ certificate: CertificateRecord }> {
    return apiRequest(`/api/certificates/${encodeURIComponent(id)}`, {
      method: 'PUT',
      body: JSON.stringify(payload),
    });
  },

  deleteCertificateMaker(
    id: string,
    reason?: string
  ): Promise<{
    success: boolean;
    deletedId: string;
    certificateNumber: string;
    deletedAt: string;
    deletedBy: string;
  }> {
    return apiRequest(`/api/certificates/${encodeURIComponent(id)}`, {
      method: 'DELETE',
      body: JSON.stringify({ reason }),
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
      mainAdminPassword?: string;
      confirmCertificateNumber?: string;
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

  verifyBackupInStaging(id: string): Promise<{ stagingResult: StagingRestoreVerificationResult }> {
    return apiRequest(`/api/admin/backups/${encodeURIComponent(id)}/staging-verify`, {
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

  getIntegrityMonitor(): Promise<{ report: DatabaseIntegrityReport }> {
    return apiRequest('/api/admin/integrity-monitor');
  },

  getCertificateHistory(id: string): Promise<{
    certificate: CertificateRecord;
    originalRecord: OriginalCertificateSnapshot;
    versionHistory: CertificateVersionSnapshot[];
    appendOnlyVersions: CertificateVersionDocument[];
  }> {
    return apiRequest(`/api/admin/certificates/${encodeURIComponent(id)}/history`);
  },

  async exportFullRegistryJson(): Promise<void> {
    const headers = new Headers({ 'X-Requested-With': 'XMLHttpRequest' });
    if (memoryBearerToken) {
      headers.set('Authorization', `Bearer ${memoryBearerToken}`);
    }
    const res = await fetch('/api/admin/export', {
      credentials: 'include',
      headers,
    });
    if (!res.ok) {
      let message = 'Unable to export verified registry snapshot.';
      try {
        const parsed = (await res.json()) as { error?: string };
        if (parsed.error) message = parsed.error;
      } catch {
        // use default message
      }
      throw new ApiError(message, res.status);
    }
    const blob = await res.blob();
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    const stamp = new Date().toISOString().replace(/[:.]/g, '-');
    a.download = `parivahan_full_registry_export_${stamp}.json`;
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
  },

  getSettings(): Promise<{
    settings: SystemSettings;
    envManagedCredentials: boolean;
    makerPasswordEnvManaged: boolean;
    makerAuthSource: 'firestore' | 'env_bootstrap_pending' | 'unconfigured';
    staleMakerEnvIgnored: boolean;
    makerUsername: string;
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

  async rotateMakerPassword(payload: {
    currentMainPassword: string;
    newMakerPassword: string;
  }): Promise<{ success: boolean; session: SessionInfo; makerUsername: string; message: string }> {
    const data = await apiRequest<{
      success: boolean;
      session: SessionInfo;
      token: string;
      makerUsername: string;
      message: string;
    }>('/api/admin/rotate-maker-password', {
      method: 'POST',
      body: JSON.stringify(payload),
    });
    setMemoryToken(data.token);
    return {
      success: data.success,
      session: data.session,
      makerUsername: data.makerUsername,
      message: data.message,
    };
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
