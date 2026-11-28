import express, { type NextFunction, type Request, type Response } from 'express';
import cookieParser from 'cookie-parser';
import type {
  AuthStatusResponse,
  CertificateBrand,
  CertificateRecord,
  CertificateVersionDocument,
  CreateCertificateInput,
  DashboardStats,
  IdProofType,
  OriginalCertificateSnapshot,
  PublicVerificationResult,
  SessionInfo,
  SystemSettings,
  UserRole,
} from '../shared/types.js';
import {
  computeCanonicalHash,
  computeSha256,
  generateQrToken,
  generateRandomCertificateNumber,
  generateRandomScrappingRegNumber,
  generateRecordId,
  hashPassword,
  isValidCertificateNumberFormat,
  isValidScrappingRegFormat,
  maskSensitiveNumber,
  resolveCertificateBrand,
  signScrapRouteAuthToken,
  signSessionToken,
  timingSafeStringEqual,
  validateScryptHashFormat,
  verifyPassword,
  verifyScrapRouteAuthToken,
  verifySessionTokenDetailed,
} from './crypto.js';
import { isDriveConfigured, syncCertificateToDriveInBackground } from './driveSync.js';
import {
  computeChangedCertificateFields,
  extractCertificateCoreFields,
  runReadOnlyIntegrityAudit,
  verifyBackupInStaging,
} from './integrity.js';
import {
  checkRateLimit,
  clearAllAuthFailures,
  clearAuthFailures,
  recordAuthFailure,
} from './rateLimit.js';
import {
  getStore,
  type RegistryStore,
  type StoredCredentials,
  type StoredSession,
} from './store.js';

const SESSION_COOKIE_NAME = 'ps_session';
const SCRAP_ROUTE_COOKIE_NAME = 'ps_sr_auth';
const SCRAP_ROUTE_AUTH_TTL_SECONDS = 2 * 60 * 60; // 2 hours
const REMEMBER_ME_TTL_SECONDS = 30 * 24 * 60 * 60; // 30 days

const VALID_ID_PROOFS = new Set<IdProofType>([
  '',
  'Aadhaar Card',
  'PAN Card',
  'Driving License',
  'Passport',
  'Voter ID',
]);

interface AuthedRequest extends Request {
  session?: SessionInfo;
}

function getClientIp(req: Request): string {
  const xff = req.headers['x-forwarded-for'];
  if (typeof xff === 'string' && xff.trim()) {
    return xff.split(',')[0].trim();
  }
  return req.socket.remoteAddress || 'unknown';
}

const DEFAULT_MAKER_USERNAME = 'user-pscrappers';

function normalizeEnvCredentialValue(value: string | undefined): string {
  if (!value) return '';
  let trimmed = value.trim();
  if (
    (trimmed.startsWith('"') && trimmed.endsWith('"') && trimmed.length >= 2) ||
    (trimmed.startsWith("'") && trimmed.endsWith("'") && trimmed.length >= 2)
  ) {
    trimmed = trimmed.slice(1, -1).trim();
  }
  return trimmed;
}

function hasEnvCredentialsConfigured(): boolean {
  return Boolean(
    normalizeEnvCredentialValue(process.env.ADMIN_PASSWORD) &&
      normalizeEnvCredentialValue(process.env.MAIN_ADMIN_PASSWORD)
  );
}

function hasAnyEnvPasswordConfigured(): boolean {
  return Boolean(
    normalizeEnvCredentialValue(process.env.ADMIN_PASSWORD) ||
      normalizeEnvCredentialValue(process.env.MAIN_ADMIN_PASSWORD)
  );
}

type AuthDiagnosticCode =
  | 'INCORRECT_USERNAME'
  | 'INCORRECT_PASSWORD'
  | 'MISSING_FIRESTORE_CREDENTIALS'
  | 'FIREBASE_CONNECTION_FAILURE'
  | 'INVALID_PASSWORD_HASH_FORMAT'
  | 'SESSION_CREATION_FAILURE';

type SystemDiagnosticCode =
  | 'SESSION_COOKIE_MISSING'
  | 'SESSION_VALIDATION_FAILED'
  | 'SESSION_VERSION_MISMATCH'
  | 'NEXT_NUMBER_API_FAILURE'
  | 'FIRESTORE_READ_FAILURE'
  | 'CERTIFICATE_RESERVATION_FAILURE'
  | 'CERTIFICATE_SAVE_FAILURE'
  | 'PDF_GENERATION_FAILURE';

function sanitizeDiagnosticDetail(detail: string | undefined): string | undefined {
  if (!detail) return undefined;
  // Strip any accidental key/hash/token/cookie-like fragments before logging
  return detail
    .replace(/scrypt\$[^\s"'`]+/gi, '[REDACTED_HASH]')
    .replace(/Bearer\s+[A-Za-z0-9._-]+/gi, 'Bearer [REDACTED]')
    .replace(/ps_session=[^;\s]+/gi, 'ps_session=[REDACTED]')
    .replace(/ps_sr_auth=[^;\s]+/gi, 'ps_sr_auth=[REDACTED]')
    .replace(/sess_[0-9a-f]{12,}/gi, 'sess_[REDACTED]')
    .replace(/-----BEGIN [A-Z ]+-----[\s\S]*?-----END [A-Z ]+-----/g, '[REDACTED_KEY]')
    .slice(0, 220);
}

function logAuthDiagnostic(params: {
  role: UserRole;
  code: AuthDiagnosticCode;
  source?: 'firestore' | 'env' | 'env_bootstrap' | 'none';
  ip: string;
  detail?: string;
}): void {
  const payload = {
    event: 'AUTH_FAILURE',
    timestamp: new Date().toISOString(),
    role: params.role,
    code: params.code,
    source: params.source ?? 'none',
    ip: params.ip,
    ...(params.detail ? { detail: sanitizeDiagnosticDetail(params.detail) } : {}),
  };
  console.warn(`[AUTH_DIAGNOSTIC] ${JSON.stringify(payload)}`);
}

function logSystemDiagnostic(params: {
  code: SystemDiagnosticCode;
  route: string;
  ip: string;
  role?: UserRole;
  detail?: string;
}): void {
  const payload = {
    event: 'SYSTEM_DIAGNOSTIC',
    timestamp: new Date().toISOString(),
    code: params.code,
    route: params.route,
    ip: params.ip,
    ...(params.role ? { role: params.role } : {}),
    ...(params.detail ? { detail: sanitizeDiagnosticDetail(params.detail) } : {}),
  };
  console.warn(`[SYSTEM_DIAGNOSTIC] ${JSON.stringify(payload)}`);
}

function convertEnvSecretToScryptHash(rawEnv: string, varName: string): { ok: true; hash: string } | { ok: false; detail: string } {
  const normalized = normalizeEnvCredentialValue(rawEnv);
  if (!normalized) {
    return { ok: false, detail: `${varName}_empty` };
  }
  if (normalized.startsWith('scrypt$')) {
    const check = validateScryptHashFormat(normalized);
    if (!check.valid) {
      return { ok: false, detail: `${varName}_${check.reason}` };
    }
    return { ok: true, hash: normalized };
  }
  return { ok: true, hash: hashPassword(normalized) };
}

type AuthoritativeCredentialsResult =
  | { ok: true; creds: StoredCredentials | null; bootstrappedFromEnv: boolean }
  | { ok: false; code: 'FIREBASE_CONNECTION_FAILURE' | 'INVALID_PASSWORD_HASH_FORMAT'; detail: string };

/**
 * Single source of truth for Maker authentication:
 * 1. Firestore `admins/primary_credentials` is authoritative whenever present.
 * 2. Environment variables (`ADMIN_PASSWORD`, `MAIN_ADMIN_PASSWORD`, etc.) are used ONLY
 *    for one-time initial bootstrap when `admins/primary_credentials` does not yet exist.
 * 3. Bootstrap uses atomic `createCredentialsIfAbsent` so it can NEVER overwrite an existing
 *    valid Firestore credentials document, and stale env vars can NEVER override Firestore.
 */
async function resolveAuthoritativeCredentials(
  store: RegistryStore
): Promise<AuthoritativeCredentialsResult> {
  let existing: StoredCredentials | null = null;
  try {
    existing = await store.getCredentials();
  } catch (err) {
    return {
      ok: false,
      code: 'FIREBASE_CONNECTION_FAILURE',
      detail: err instanceof Error ? err.message : 'Unable to read admins/primary_credentials',
    };
  }

  if (existing) {
    return { ok: true, creds: existing, bootstrappedFromEnv: false };
  }

  // No Firestore credentials document exists yet.
  // If env credentials are provided and storage is writable, perform a one-time atomic seed.
  if (store.mode === 'firestore_unconfigured' || !hasEnvCredentialsConfigured()) {
    return { ok: true, creds: null, bootstrappedFromEnv: false };
  }

  const makerHashRes = convertEnvSecretToScryptHash(process.env.ADMIN_PASSWORD || '', 'ADMIN_PASSWORD');
  if (!makerHashRes.ok) {
    return { ok: false, code: 'INVALID_PASSWORD_HASH_FORMAT', detail: makerHashRes.detail };
  }

  const mainHashRes = convertEnvSecretToScryptHash(process.env.MAIN_ADMIN_PASSWORD || '', 'MAIN_ADMIN_PASSWORD');
  if (!mainHashRes.ok) {
    return { ok: false, code: 'INVALID_PASSWORD_HASH_FORMAT', detail: mainHashRes.detail };
  }

  const rawProtected =
    normalizeEnvCredentialValue(process.env.ADMIN_PROTECTED_PASSWORD) ||
    normalizeEnvCredentialValue(process.env.ADMIN_DELETE_PASSWORD) ||
    normalizeEnvCredentialValue(process.env.MAIN_ADMIN_PASSWORD);
  const rawDelete =
    normalizeEnvCredentialValue(process.env.ADMIN_DELETE_PASSWORD) ||
    normalizeEnvCredentialValue(process.env.ADMIN_PROTECTED_PASSWORD) ||
    normalizeEnvCredentialValue(process.env.MAIN_ADMIN_PASSWORD);

  const protHashRes = convertEnvSecretToScryptHash(rawProtected, 'ADMIN_PROTECTED_PASSWORD');
  if (!protHashRes.ok) {
    return { ok: false, code: 'INVALID_PASSWORD_HASH_FORMAT', detail: protHashRes.detail };
  }
  const delHashRes = convertEnvSecretToScryptHash(rawDelete, 'ADMIN_DELETE_PASSWORD');
  if (!delHashRes.ok) {
    return { ok: false, code: 'INVALID_PASSWORD_HASH_FORMAT', detail: delHashRes.detail };
  }

  const now = new Date().toISOString();
  const seedCreds: StoredCredentials = {
    makerUsername: normalizeEnvCredentialValue(process.env.ADMIN_USERNAME) || DEFAULT_MAKER_USERNAME,
    makerPasswordHash: makerHashRes.hash,
    mainAdminPasswordHash: mainHashRes.hash,
    protectedPasswordHash: protHashRes.hash,
    deletePasswordHash: delHashRes.hash,
    sessionVersion: 1,
    bootstrappedAt: now,
    updatedAt: now,
  };

  try {
    const created = await store.createCredentialsIfAbsent(seedCreds);
    if (created) {
      await store.addAuditLog({
        id: generateRecordId('aud'),
        timestamp: now,
        actor: 'system-bootstrap',
        actorRole: 'main_admin',
        action: 'BOOTSTRAP_SECURITY',
        reason: 'One-time initial credentials seeded into Firestore from server environment variables',
      });
      return { ok: true, creds: seedCreds, bootstrappedFromEnv: true };
    }
    // Another concurrent request created the document first; read the authoritative doc
    const reloaded = await store.getCredentials();
    return { ok: true, creds: reloaded, bootstrappedFromEnv: false };
  } catch (err) {
    return {
      ok: false,
      code: 'FIREBASE_CONNECTION_FAILURE',
      detail: err instanceof Error ? err.message : 'Failed to initialize credentials in Firestore',
    };
  }
}

function formatCooldownText(retryAfterSeconds: number): string {
  if (retryAfterSeconds < 90) {
    return `${Math.max(1, retryAfterSeconds)} second(s)`;
  }
  return `${Math.ceil(retryAfterSeconds / 60)} minute(s)`;
}

let cachedScrapRoutePin: { raw: string; hash: string } | null = null;

function getConfiguredScrapRoutePinHash():
  | { configured: false }
  | { configured: true; valid: false; reason: string }
  | { configured: true; valid: true; hash: string } {
  const raw =
    normalizeEnvCredentialValue(process.env.SCRAP_ROUTE_PIN) ||
    normalizeEnvCredentialValue(process.env.SCRAP_ROUTE_PIN_HASH);
  if (!raw) {
    cachedScrapRoutePin = null;
    return { configured: false };
  }
  if (raw.startsWith('scrypt$')) {
    const check = validateScryptHashFormat(raw);
    if (!check.valid) {
      return { configured: true, valid: false, reason: check.reason };
    }
    return { configured: true, valid: true, hash: raw };
  }
  if (!cachedScrapRoutePin || cachedScrapRoutePin.raw !== raw) {
    cachedScrapRoutePin = { raw, hash: hashPassword(raw) };
  }
  return { configured: true, valid: true, hash: cachedScrapRoutePin.hash };
}

function setSessionCookie(res: Response, token: string, maxAgeMs: number): void {
  res.cookie(SESSION_COOKIE_NAME, token, {
    httpOnly: true,
    secure: true,
    sameSite: 'none',
    partitioned: true,
    maxAge: maxAgeMs,
    path: '/',
  });
}

function clearSessionCookie(res: Response): void {
  res.clearCookie(SESSION_COOKIE_NAME, {
    httpOnly: true,
    secure: true,
    sameSite: 'none',
    partitioned: true,
    path: '/',
  });
}

function setScrapRouteCookie(res: Response, token: string, maxAgeMs: number): void {
  res.cookie(SCRAP_ROUTE_COOKIE_NAME, token, {
    httpOnly: true,
    secure: true,
    sameSite: 'none',
    partitioned: true,
    maxAge: maxAgeMs,
    path: '/',
  });
}

function clearScrapRouteCookie(res: Response): void {
  res.clearCookie(SCRAP_ROUTE_COOKIE_NAME, {
    httpOnly: true,
    secure: true,
    sameSite: 'none',
    partitioned: true,
    path: '/',
  });
}

function isScrapRouteAuthorized(req: Request, session: SessionInfo): boolean {
  if (
    typeof session.scrapRouteAuthorizedUntil === 'number' &&
    Date.now() < session.scrapRouteAuthorizedUntil
  ) {
    return true;
  }

  const candidates: string[] = [];
  const headerToken = req.headers['x-scrap-route-auth'];
  if (typeof headerToken === 'string' && headerToken.trim()) {
    candidates.push(headerToken.trim());
  }
  const cookieToken = req.cookies?.[SCRAP_ROUTE_COOKIE_NAME];
  if (typeof cookieToken === 'string' && cookieToken.trim()) {
    candidates.push(cookieToken.trim());
  }

  for (const token of candidates) {
    const check = verifyScrapRouteAuthToken(token, {
      sid: session.sid ?? '',
      username: session.username,
      sessionVersion: session.sessionVersion,
    });
    if (check.ok) return true;
  }
  return false;
}

async function issueServerSession(
  store: RegistryStore,
  res: Response,
  params: {
    username: string;
    role: UserRole;
    sessionVersion: number;
    ttlSeconds?: number;
    rememberMe?: boolean;
  }
): Promise<{ token: string; session: SessionInfo }> {
  const { token, session } = signSessionToken({
    username: params.username,
    role: params.role,
    sessionVersion: params.sessionVersion,
    ttlSeconds: params.ttlSeconds,
    rememberMe: params.rememberMe,
  });

  if (session.sid) {
    const record: StoredSession = {
      id: session.sid,
      username: session.username,
      role: session.role,
      sessionVersion: session.sessionVersion,
      issuedAt: session.issuedAt,
      expiresAt: session.expiresAt,
      revoked: false,
      rememberMe: Boolean(params.rememberMe),
    };
    await store.createSession(record);
  }

  setSessionCookie(res, token, session.expiresAt - session.issuedAt);
  return { token, session };
}

function extractSessionCandidates(req: Request): Array<{ source: 'bearer' | 'cookie'; token: string }> {
  const out: Array<{ source: 'bearer' | 'cookie'; token: string }> = [];
  const authHeader = req.headers.authorization;
  if (typeof authHeader === 'string' && authHeader.startsWith('Bearer ')) {
    const bearer = authHeader.slice(7).trim();
    if (bearer) out.push({ source: 'bearer', token: bearer });
  }
  const cookieToken = req.cookies?.[SESSION_COOKIE_NAME];
  if (typeof cookieToken === 'string' && cookieToken.trim()) {
    const trimmed = cookieToken.trim();
    if (!out.some((c) => c.token === trimmed)) {
      out.push({ source: 'cookie', token: trimmed });
    }
  }
  return out;
}

type SessionResolutionResult =
  | { ok: true; session: SessionInfo }
  | {
      ok: false;
      code:
        | 'SESSION_COOKIE_MISSING'
        | 'SESSION_VALIDATION_FAILED'
        | 'SESSION_VERSION_MISMATCH'
        | 'FIRESTORE_READ_FAILURE';
      httpStatus: 401 | 503;
      detail: string;
    };

async function resolveSessionDetailed(req: Request): Promise<SessionResolutionResult> {
  const candidates = extractSessionCandidates(req);
  if (candidates.length === 0) {
    return {
      ok: false,
      code: 'SESSION_COOKIE_MISSING',
      httpStatus: 401,
      detail: 'missing_session_cookie_and_bearer_header',
    };
  }

  const store = getStore();
  let expectedVersion = 1;
  try {
    const creds = await store.getCredentials();
    expectedVersion = creds?.sessionVersion ?? 1;
  } catch (err) {
    return {
      ok: false,
      code: 'FIRESTORE_READ_FAILURE',
      httpStatus: 503,
      detail: err instanceof Error ? err.message : 'Unable to read sessionVersion from Firestore',
    };
  }

  let lastFailure: SessionResolutionResult = {
    ok: false,
    code: 'SESSION_VALIDATION_FAILED',
    httpStatus: 401,
    detail: 'invalid_session_token',
  };

  for (const candidate of candidates) {
    const verified = verifySessionTokenDetailed(candidate.token, expectedVersion);
    if (!verified.ok) {
      if (verified.reason === 'VERSION_MISMATCH') {
        lastFailure = {
          ok: false,
          code: 'SESSION_VERSION_MISMATCH',
          httpStatus: 401,
          detail: `${candidate.source}_session_version_mismatch`,
        };
      } else {
        lastFailure = {
          ok: false,
          code: 'SESSION_VALIDATION_FAILED',
          httpStatus: 401,
          detail: `${candidate.source}_${verified.reason.toLowerCase()}`,
        };
      }
      continue;
    }

    const session = verified.session;
    if (session.sid) {
      let stored: StoredSession | null = null;
      try {
        stored = await store.getSession(session.sid);
      } catch (err) {
        return {
          ok: false,
          code: 'FIRESTORE_READ_FAILURE',
          httpStatus: 503,
          detail: err instanceof Error ? err.message : 'Unable to verify session record in Firestore',
        };
      }

      if (!stored) {
        lastFailure = {
          ok: false,
          code: 'SESSION_VALIDATION_FAILED',
          httpStatus: 401,
          detail: `${candidate.source}_server_session_not_found`,
        };
        continue;
      }
      if (stored.revoked) {
        lastFailure = {
          ok: false,
          code: 'SESSION_VALIDATION_FAILED',
          httpStatus: 401,
          detail: `${candidate.source}_server_session_revoked`,
        };
        continue;
      }
      if (Date.now() >= stored.expiresAt) {
        lastFailure = {
          ok: false,
          code: 'SESSION_VALIDATION_FAILED',
          httpStatus: 401,
          detail: `${candidate.source}_server_session_expired`,
        };
        continue;
      }
      if (stored.sessionVersion !== expectedVersion) {
        lastFailure = {
          ok: false,
          code: 'SESSION_VERSION_MISMATCH',
          httpStatus: 401,
          detail: `${candidate.source}_stored_session_version_mismatch`,
        };
        continue;
      }
      if (stored.role !== session.role || stored.username !== session.username) {
        lastFailure = {
          ok: false,
          code: 'SESSION_VALIDATION_FAILED',
          httpStatus: 401,
          detail: `${candidate.source}_server_session_principal_mismatch`,
        };
        continue;
      }
      if (stored.rememberMe !== undefined) {
        session.rememberMe = stored.rememberMe;
      }
      if (
        typeof stored.scrapRouteAuthorizedUntil === 'number' &&
        stored.scrapRouteAuthorizedUntil > Date.now()
      ) {
        session.scrapRouteAuthorizedUntil = stored.scrapRouteAuthorizedUntil;
      }
    }

    return { ok: true, session };
  }

  return lastFailure;
}

async function resolveSession(req: Request): Promise<SessionInfo | null> {
  const res = await resolveSessionDetailed(req);
  return res.ok ? res.session : null;
}

function csrfGuard(req: Request, res: Response, next: NextFunction): void {
  if (req.method === 'GET' || req.method === 'HEAD' || req.method === 'OPTIONS') {
    next();
    return;
  }
  // Allow cron route authenticated via Bearer CRON_SECRET
  if (req.path === '/cron/backup') {
    next();
    return;
  }

  const xrw = req.headers['x-requested-with'];
  if (typeof xrw === 'string' && xrw.toLowerCase() === 'xmlhttprequest') {
    next();
    return;
  }

  const origin = req.headers.origin;
  const host = (req.headers['x-forwarded-host'] as string | undefined) || req.headers.host;
  if (origin && host) {
    try {
      const originHost = new URL(origin).host;
      if (originHost === host) {
        next();
        return;
      }
    } catch {
      // fall through to rejection
    }
  }

  res.status(403).json({ error: 'Cross-site request validation failed.' });
}

async function requireAuth(req: AuthedRequest, res: Response, next: NextFunction): Promise<void> {
  const resolved = await resolveSessionDetailed(req);
  if (!resolved.ok) {
    logSystemDiagnostic({
      code: resolved.code,
      route: req.originalUrl,
      ip: getClientIp(req),
      detail: resolved.detail,
    });
    res.status(resolved.httpStatus).json({
      error:
        resolved.httpStatus === 503
          ? 'Unable to verify session with the database. Please retry.'
          : 'Authentication required. Please sign in.',
      code: resolved.code,
    });
    return;
  }
  req.session = resolved.session;
  next();
}

async function requireMainAdmin(req: AuthedRequest, res: Response, next: NextFunction): Promise<void> {
  const resolved = await resolveSessionDetailed(req);
  if (!resolved.ok) {
    logSystemDiagnostic({
      code: resolved.code,
      route: req.originalUrl,
      ip: getClientIp(req),
      detail: resolved.detail,
    });
    res.status(resolved.httpStatus).json({
      error:
        resolved.httpStatus === 503
          ? 'Unable to verify session with the database. Please retry.'
          : 'Authentication required.',
      code: resolved.code,
    });
    return;
  }
  if (resolved.session.role !== 'main_admin') {
    res.status(403).json({
      error: 'Forbidden: Main Core Admin authorization is required for this resource.',
    });
    return;
  }
  req.session = resolved.session;
  next();
}

function sanitizeText(val: unknown, maxLen: number): string {
  if (typeof val !== 'string') return '';
  return val.trim().replace(/\s+/g, ' ').slice(0, maxLen);
}

function parseBrandParam(raw: unknown): CertificateBrand | null {
  if (raw === undefined || raw === null || raw === '') return 'parivahan';
  if (raw === 'parivahan' || raw === 'scrap_route') return raw;
  return null;
}

function validateCertificatePayload(
  body: unknown,
  forcedBrand?: CertificateBrand
): { ok: true; data: CreateCertificateInput & { brand: CertificateBrand } } | { ok: false; error: string } {
  if (!body || typeof body !== 'object') {
    return { ok: false, error: 'Invalid request payload.' };
  }
  const b = body as Record<string, unknown>;

  let brand: CertificateBrand;
  if (forcedBrand) {
    brand = forcedBrand;
  } else {
    const parsedBrand = parseBrandParam(b.brand);
    if (!parsedBrand) {
      return { ok: false, error: 'Invalid certificate brand specified.' };
    }
    brand = parsedBrand;
  }

  const issueDate = sanitizeText(b.issueDate, 20);
  const handoverDate = sanitizeText(b.handoverDate, 20);
  const ownerName = sanitizeText(b.ownerName, 120);
  const ownerAddress = sanitizeText(b.ownerAddress, 300);
  const idProofType = sanitizeText(b.idProofType, 40) as IdProofType;
  const idProofNumber = sanitizeText(b.idProofNumber, 40).toUpperCase();
  const vehicleRegNumber = sanitizeText(b.vehicleRegNumber, 25).toUpperCase().replace(/\s+/g, '');
  const make = sanitizeText(b.make, 80);
  const model = sanitizeText(b.model, 80);
  const manufactureYear = Number(b.manufactureYear);
  const chassisNumber = sanitizeText(b.chassisNumber, 40).toUpperCase().replace(/\s+/g, '');
  const engineNumber = sanitizeText(b.engineNumber, 40).toUpperCase().replace(/\s+/g, '');
  const unhideChassisEngine = b.unhideChassisEngine === true;
  const rtoAuthority = sanitizeText(b.rtoAuthority, 100);
  const remarks = sanitizeText(b.remarks, 400);
  const certificateNumber = b.certificateNumber ? sanitizeText(b.certificateNumber, 30).toUpperCase() : undefined;
  const scrappingRegNumber = b.scrappingRegNumber ? sanitizeText(b.scrappingRegNumber, 30).toUpperCase() : undefined;

  if (!/^\d{4}-\d{2}-\d{2}$/.test(issueDate)) {
    return { ok: false, error: 'Valid issue date (YYYY-MM-DD) is required.' };
  }
  if (!/^\d{4}-\d{2}-\d{2}$/.test(handoverDate)) {
    return { ok: false, error: 'Valid handover date (YYYY-MM-DD) is required.' };
  }
  if (ownerName.length < 2) {
    return { ok: false, error: 'Owner full name must be at least 2 characters.' };
  }
  if (idProofType && !VALID_ID_PROOFS.has(idProofType)) {
    return { ok: false, error: 'Please select a valid ID proof type or leave blank.' };
  }
  if (idProofNumber && idProofNumber.length < 4) {
    return { ok: false, error: 'If provided, ID proof number must be at least 4 characters.' };
  }
  if (vehicleRegNumber.length < 4) {
    return { ok: false, error: 'Valid RC Number / Vehicle Number is required.' };
  }
  if (make.length < 2 || model.length < 1) {
    return { ok: false, error: 'Make / Manufacturer and Model are required.' };
  }
  const currentYear = new Date().getFullYear();
  if (!Number.isInteger(manufactureYear) || manufactureYear < 1950 || manufactureYear > currentYear + 1) {
    return { ok: false, error: `Manufacture year must be between 1950 and ${currentYear + 1}.` };
  }
  if (chassisNumber.length < 6) {
    return { ok: false, error: 'Chassis number must be at least 6 characters.' };
  }
  if (engineNumber.length < 5) {
    return { ok: false, error: 'Engine number must be at least 5 characters.' };
  }
  if (certificateNumber && !isValidCertificateNumberFormat(certificateNumber, brand)) {
    return {
      ok: false,
      error:
        brand === 'scrap_route'
          ? 'Invalid Scrap Route certificate number format. Expected SR/YY/R[7 digits].'
          : 'Invalid certificate number format. Expected PS/YY/R[7 digits].',
    };
  }
  if (scrappingRegNumber && !isValidScrappingRegFormat(scrappingRegNumber, brand)) {
    return {
      ok: false,
      error:
        brand === 'scrap_route'
          ? 'Invalid Scrap Route scrapping registration number format. Expected SR-REG-[6 digits].'
          : 'Invalid scrapping registration number format. Expected REG-C[6 digits].',
    };
  }

  return {
    ok: true,
    data: {
      brand,
      certificateNumber,
      scrappingRegNumber,
      issueDate,
      handoverDate,
      ownerName,
      ownerAddress,
      idProofType: idProofNumber ? (idProofType || 'Aadhaar Card') : idProofType,
      idProofNumber,
      vehicleRegNumber,
      make,
      model,
      manufactureYear,
      chassisNumber,
      engineNumber,
      unhideChassisEngine,
      rtoAuthority,
      remarks,
    },
  };
}

async function generateAvailableCandidateNumbers(
  issueDate?: string,
  brand: CertificateBrand = 'parivahan'
): Promise<{
  brand: CertificateBrand;
  certificateNumber: string;
  scrappingRegNumber: string;
  issueYearShort: string;
}> {
  const store = getStore();
  for (let attempt = 0; attempt < 25; attempt++) {
    const certGen = generateRandomCertificateNumber(issueDate, brand);
    const regNo = generateRandomScrappingRegNumber(brand);
    const [certTaken, regTaken] = await Promise.all([
      store.isCertNumberReserved(certGen.certificateNumber),
      store.isScrappingRegReserved(regNo),
    ]);
    if (!certTaken && !regTaken) {
      return {
        brand,
        certificateNumber: certGen.certificateNumber,
        scrappingRegNumber: regNo,
        issueYearShort: certGen.issueYearShort,
      };
    }
  }
  throw new Error('Unable to allocate unique candidate numbers. Please retry.');
}

async function verifyProtectedPassword(password: string, mode: 'edit' | 'delete'): Promise<boolean> {
  const store = getStore();
  const credRes = await resolveAuthoritativeCredentials(store);
  if (!credRes.ok || !credRes.creds) return false;
  const creds = credRes.creds;
  const targetHash =
    mode === 'delete'
      ? creds.deletePasswordHash || creds.protectedPasswordHash
      : creds.protectedPasswordHash || creds.deletePasswordHash;
  if (!targetHash) return false;
  return verifyPassword(password, targetHash);
}

export function createApiApp(): express.Express {
  const app = express();
  app.set('trust proxy', 1);
  app.disable('x-powered-by');

  // Security headers (iframe-compatible for AI Studio preview, strict everywhere else)
  app.use((_req, res, next) => {
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
    res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
    next();
  });

  app.use(cookieParser());
  app.use(express.json({ limit: '512kb' }));

  const router = express.Router();

  // Express 4 does not catch rejected promises from async handlers automatically.
  // Wrap router registration methods so every async handler/middleware forwards errors to next(err).
  const wrapAsyncHandler = (fn: unknown): unknown => {
    if (typeof fn !== 'function' || fn.length >= 4) return fn;
    return function wrappedHandler(req: Request, res: Response, next: NextFunction) {
      try {
        const result = (fn as (r: Request, s: Response, n: NextFunction) => unknown)(req, res, next);
        if (result && typeof (result as Promise<unknown>).catch === 'function') {
          (result as Promise<unknown>).catch(next);
        }
      } catch (err) {
        next(err);
      }
    };
  };

  for (const method of ['get', 'post', 'put', 'patch', 'delete', 'all'] as const) {
    const orig = router[method].bind(router) as (...args: unknown[]) => unknown;
    (router as unknown as Record<string, (...args: unknown[]) => unknown>)[method] = (
      path: unknown,
      ...handlers: unknown[]
    ) => orig(path, ...handlers.map(wrapAsyncHandler));
  }

  // No-store caching on all API routes
  router.use((_req, res, next) => {
    res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, private');
    next();
  });

  router.use(csrfGuard);

  // ==========================================================================
  // PUBLIC ENDPOINTS
  // ==========================================================================
  router.get('/health', async (_req, res) => {
    const store = getStore();
    const probe = await store.ping();
    res.status(probe.ok ? 200 : 503).json({
      status: probe.ok ? 'ok' : 'degraded',
      timestamp: new Date().toISOString(),
      storageMode: store.mode,
      firestoreConnected: store.mode === 'firestore' ? probe.ok : false,
      latencyMs: probe.latencyMs,
      storageMessage: probe.message,
      missingFirestoreEnvVars: store.missingEnvVars ?? [],
      envCredentialsConfigured: hasEnvCredentialsConfigured(),
      sessionSecretConfigured: Boolean(
        process.env.ADMIN_SESSION_SECRET && process.env.ADMIN_SESSION_SECRET.trim().length >= 16
      ),
      driveConfigured: isDriveConfigured(),
    });
  });

  router.get('/auth/status', async (req, res) => {
    const store = getStore();
    const [creds, settings, session] = await Promise.all([
      store.getCredentials(),
      store.getSettings(),
      resolveSession(req),
    ]);
    const envConfigured = hasEnvCredentialsConfigured();
    const requiresBootstrap =
      store.mode !== 'firestore_unconfigured' && !hasAnyEnvPasswordConfigured() && !creds;

    const payload: AuthStatusResponse = {
      requiresBootstrap,
      envConfigured,
      storageMode: store.mode,
      missingFirestoreEnvVars: store.missingEnvVars,
      firestoreProjectId: store.projectId,
      firestoreDatabaseId: store.databaseId,
      session,
      facilityName: settings.facilityName,
      publicDomain: settings.publicDomain,
      authorizedSignatory: settings.authorizedSignatory,
      signatoryDesignation: settings.signatoryDesignation,
      scrapRoutePinConfigured: getConfiguredScrapRoutePinHash().configured,
      scrapRouteAuthorized: session ? isScrapRouteAuthorized(req, session) : false,
    };
    res.json(payload);
  });

  // One-time secure first-run credential initialization (locked immediately once claimed or when env vars exist)
  router.post('/auth/bootstrap', async (req, res) => {
    const store = getStore();
    if (hasEnvCredentialsConfigured() || hasAnyEnvPasswordConfigured()) {
      res.status(403).json({
        error: 'Credentials are managed via server environment variables. First-run setup is disabled.',
      });
      return;
    }

    const existing = await store.getCredentials();
    if (existing) {
      res.status(403).json({ error: 'System security credentials have already been initialized.' });
      return;
    }

    const body = (req.body ?? {}) as Record<string, unknown>;
    const makerUsername = sanitizeText(body.makerUsername, 60);
    const makerPassword = typeof body.makerPassword === 'string' ? body.makerPassword : '';
    const mainAdminPassword = typeof body.mainAdminPassword === 'string' ? body.mainAdminPassword : '';
    const protectedPassword = typeof body.protectedPassword === 'string' ? body.protectedPassword : '';
    const deletePassword =
      typeof body.deletePassword === 'string' && body.deletePassword.length > 0
        ? body.deletePassword
        : protectedPassword;

    if (makerUsername.length < 3 || !/^[a-zA-Z0-9._-]+$/.test(makerUsername)) {
      res.status(400).json({
        error: 'Maker username must be 3–60 characters (letters, numbers, dot, underscore, hyphen).',
      });
      return;
    }
    if (makerPassword.length < 8 || mainAdminPassword.length < 8 || protectedPassword.length < 8) {
      res.status(400).json({
        error: 'All security passwords (Maker, Main Core Admin, Protected Action) must be at least 8 characters.',
      });
      return;
    }

    const now = new Date().toISOString();
    const creds: StoredCredentials = {
      makerUsername,
      makerPasswordHash: hashPassword(makerPassword),
      mainAdminPasswordHash: hashPassword(mainAdminPassword),
      protectedPasswordHash: hashPassword(protectedPassword),
      deletePasswordHash: hashPassword(deletePassword),
      sessionVersion: 1,
      bootstrappedAt: now,
      updatedAt: now,
    };

    const created = await store.createCredentialsIfAbsent(creds);
    if (!created) {
      res.status(403).json({ error: 'System security credentials have already been initialized.' });
      return;
    }

    await store.addAuditLog({
      id: generateRecordId('aud'),
      timestamp: now,
      actor: makerUsername,
      actorRole: 'main_admin',
      action: 'BOOTSTRAP_SECURITY',
      ipAddress: getClientIp(req),
      reason: 'Initial security credentials initialized with salted scrypt hashes',
    });

    res.status(201).json({
      success: true,
      makerUsername,
      message: 'Security credentials initialized. You may now sign in.',
    });
  });

  // Certificate Maker Login (Authoritative Source: Firestore admins/primary_credentials)
  router.post('/auth/login', async (req, res) => {
    const store = getStore();
    const ip = getClientIp(req);
    const body = (req.body ?? {}) as Record<string, unknown>;
    const username = sanitizeText(body.username, 60);
    const password = typeof body.password === 'string' ? body.password : '';
    const rememberMe = body.rememberMe === true;

    const rateKey = `maker:${ip}:${username.toLowerCase()}`;
    const limit = checkRateLimit(rateKey);
    if (!limit.allowed) {
      res.status(429).json({
        error: `Too many failed login attempts. Please wait ${formatCooldownText(limit.retryAfterSeconds)} before trying again.`,
        retryAfterSeconds: limit.retryAfterSeconds,
      });
      return;
    }

    const credResult = await resolveAuthoritativeCredentials(store);
    if (!credResult.ok) {
      logAuthDiagnostic({
        role: 'maker',
        code: credResult.code,
        source: 'firestore',
        ip,
        detail: credResult.detail,
      });
      res.status(credResult.code === 'FIREBASE_CONNECTION_FAILURE' ? 503 : 500).json({
        error:
          credResult.code === 'FIREBASE_CONNECTION_FAILURE'
            ? 'Unable to reach the authentication database. Please retry or contact your administrator.'
            : 'Authentication configuration error. Please contact your administrator.',
      });
      return;
    }

    const creds = credResult.creds;
    if (!creds || !creds.makerUsername || !creds.makerPasswordHash) {
      logAuthDiagnostic({
        role: 'maker',
        code: 'MISSING_FIRESTORE_CREDENTIALS',
        source: 'firestore',
        ip,
        detail: !creds ? 'admins/primary_credentials_not_found' : 'maker_credential_field_missing',
      });
      res.status(503).json({
        error: 'System credentials are not initialized yet. Complete first-run setup first.',
      });
      return;
    }

    // Validate stored scrypt hash format before verifying password
    const hashCheck = validateScryptHashFormat(creds.makerPasswordHash);
    if (!hashCheck.valid) {
      logAuthDiagnostic({
        role: 'maker',
        code: 'INVALID_PASSWORD_HASH_FORMAT',
        source: 'firestore',
        ip,
        detail: `firestore_makerPasswordHash_${hashCheck.reason}`,
      });
      res.status(500).json({
        error: 'Authentication credential verification error. Please contact your administrator.',
      });
      return;
    }

    // Authoritative check strictly against Firestore admins/primary_credentials
    // (never silently overridden by a stale ADMIN_PASSWORD or ADMIN_USERNAME env var)
    const expectedUsername = creds.makerUsername.trim();
    const usernameMatches = timingSafeStringEqual(
      username.toLowerCase(),
      expectedUsername.toLowerCase()
    );
    const passwordMatches = verifyPassword(password, creds.makerPasswordHash);

    if (!usernameMatches || !passwordMatches) {
      const failureCode: AuthDiagnosticCode = !usernameMatches
        ? 'INCORRECT_USERNAME'
        : 'INCORRECT_PASSWORD';
      logAuthDiagnostic({
        role: 'maker',
        code: failureCode,
        source: 'firestore',
        ip,
        detail: !usernameMatches
          ? `providedLen=${username.length},expectedLen=${expectedUsername.length}`
          : 'scrypt_digest_mismatch',
      });
      const failState = recordAuthFailure(rateKey);
      try {
        await store.addAuditLog({
          id: generateRecordId('aud'),
          timestamp: new Date().toISOString(),
          actor: username || 'unknown',
          actorRole: 'maker',
          action: 'LOGIN_FAILED',
          ipAddress: ip,
          reason:
            failureCode === 'INCORRECT_USERNAME'
              ? 'Invalid Certificate Maker username'
              : 'Invalid Certificate Maker password',
          metadata: { diagnosticCode: failureCode, authSource: 'firestore' },
        });
      } catch {
        // Do not mask auth failure with an audit write error
      }
      res.status(401).json({
        error: failState.locked
          ? 'Account login temporarily locked due to multiple failed attempts.'
          : `Invalid username or password. (${failState.remainingAttempts} attempt(s) remaining)`,
      });
      return;
    }

    let token: string;
    let session: SessionInfo;
    try {
      const sessionVersion = creds.sessionVersion ?? 1;
      const issued = await issueServerSession(store, res, {
        username: expectedUsername,
        role: 'maker',
        sessionVersion,
        ttlSeconds: rememberMe ? REMEMBER_ME_TTL_SECONDS : undefined,
        rememberMe,
      });
      token = issued.token;
      session = issued.session;
    } catch (err) {
      logAuthDiagnostic({
        role: 'maker',
        code: 'SESSION_CREATION_FAILURE',
        source: 'firestore',
        ip,
        detail: err instanceof Error ? err.message : 'Unable to create session token',
      });
      res.status(500).json({
        error: 'Unable to establish an authenticated session. Please try again.',
      });
      return;
    }

    clearAuthFailures(rateKey);
    try {
      await store.addAuditLog({
        id: generateRecordId('aud'),
        timestamp: new Date().toISOString(),
        actor: expectedUsername,
        actorRole: 'maker',
        action: 'LOGIN_SUCCESS',
        ipAddress: ip,
        metadata: { authSource: 'firestore', rememberMe },
      });
    } catch (err) {
      logAuthDiagnostic({
        role: 'maker',
        code: 'FIREBASE_CONNECTION_FAILURE',
        source: 'firestore',
        ip,
        detail: `audit_log_write_warning:${err instanceof Error ? err.message : 'unknown'}`,
      });
    }

    res.json({ session, token });
  });

  // Main Core Admin Separate Unlock (Authoritative Source: Firestore admins/primary_credentials)
  router.post('/auth/admin-unlock', async (req, res) => {
    const store = getStore();
    const ip = getClientIp(req);
    const rateKey = `main_admin:${ip}`;
    const limit = checkRateLimit(rateKey);
    if (!limit.allowed) {
      res.status(429).json({
        error: `Main Core Admin unlock throttled. Try again in ${formatCooldownText(limit.retryAfterSeconds)}.`,
        retryAfterSeconds: limit.retryAfterSeconds,
      });
      return;
    }

    const body = (req.body ?? {}) as Record<string, unknown>;
    const password = typeof body.password === 'string' ? body.password : '';

    const credResult = await resolveAuthoritativeCredentials(store);
    if (!credResult.ok) {
      logAuthDiagnostic({
        role: 'main_admin',
        code: credResult.code,
        source: 'firestore',
        ip,
        detail: credResult.detail,
      });
      res.status(credResult.code === 'FIREBASE_CONNECTION_FAILURE' ? 503 : 500).json({
        error:
          credResult.code === 'FIREBASE_CONNECTION_FAILURE'
            ? 'Unable to reach the authentication database. Please retry.'
            : 'Authentication configuration error. Please contact your administrator.',
      });
      return;
    }

    const creds = credResult.creds;
    if (!creds || !creds.mainAdminPasswordHash) {
      logAuthDiagnostic({
        role: 'main_admin',
        code: 'MISSING_FIRESTORE_CREDENTIALS',
        source: 'firestore',
        ip,
        detail: !creds ? 'admins/primary_credentials_not_found' : 'mainAdminPasswordHash_missing',
      });
      res.status(503).json({
        error: 'Main Core Admin password is not configured yet. Complete first-run setup or run local auth recovery.',
      });
      return;
    }

    const hashCheck = validateScryptHashFormat(creds.mainAdminPasswordHash);
    if (!hashCheck.valid) {
      logAuthDiagnostic({
        role: 'main_admin',
        code: 'INVALID_PASSWORD_HASH_FORMAT',
        source: 'firestore',
        ip,
        detail: `firestore_mainAdminPasswordHash_${hashCheck.reason}`,
      });
      res.status(500).json({
        error: 'Main Core Admin credential format error. Please run secure local recovery.',
      });
      return;
    }

    // Authoritative check strictly against Firestore admins/primary_credentials.mainAdminPasswordHash
    // (never silently overridden by stale MAIN_ADMIN_PASSWORD or ADMIN_PROTECTED_PASSWORD env vars)
    const passwordMatches = verifyPassword(password, creds.mainAdminPasswordHash);
    if (!passwordMatches) {
      logAuthDiagnostic({
        role: 'main_admin',
        code: 'INCORRECT_PASSWORD',
        source: 'firestore',
        ip,
        detail: 'main_admin_scrypt_digest_mismatch',
      });
      const failState = recordAuthFailure(rateKey);
      try {
        await store.addAuditLog({
          id: generateRecordId('aud'),
          timestamp: new Date().toISOString(),
          actor: 'Main Core Admin',
          actorRole: 'main_admin',
          action: 'ADMIN_UNLOCK_FAILED',
          ipAddress: ip,
          reason: 'Invalid Main Core Admin unlock password',
          metadata: { diagnosticCode: 'INCORRECT_PASSWORD', authSource: 'firestore' },
        });
      } catch {
        // non-fatal
      }
      res.status(401).json({
        error: failState.locked
          ? `Main Core Admin unlock paused for ${formatCooldownText(failState.retryAfterSeconds)} due to repeated failed attempts.`
          : `Invalid Main Core Admin password. (${failState.remainingAttempts} attempt(s) remaining)`,
      });
      return;
    }

    let token: string;
    let session: SessionInfo;
    try {
      const sessionVersion = creds.sessionVersion ?? 1;
      const issued = await issueServerSession(store, res, {
        username: 'Main Core Admin',
        role: 'main_admin',
        sessionVersion,
      });
      token = issued.token;
      session = issued.session;
    } catch (err) {
      logAuthDiagnostic({
        role: 'main_admin',
        code: 'SESSION_CREATION_FAILURE',
        source: 'firestore',
        ip,
        detail: err instanceof Error ? err.message : 'Unable to create admin session token',
      });
      res.status(500).json({
        error: 'Unable to establish an authenticated session. Please try again.',
      });
      return;
    }

    clearAuthFailures(rateKey);
    try {
      await store.addAuditLog({
        id: generateRecordId('aud'),
        timestamp: new Date().toISOString(),
        actor: 'Main Core Admin',
        actorRole: 'main_admin',
        action: 'ADMIN_UNLOCK_SUCCESS',
        ipAddress: ip,
        metadata: { authSource: 'firestore' },
      });
    } catch {
      // non-fatal
    }

    res.json({ session, token });
  });

  router.post('/auth/logout', async (req, res) => {
    const store = getStore();
    const resolved = await resolveSessionDetailed(req);
    clearSessionCookie(res);
    clearScrapRouteCookie(res);
    if (resolved.ok) {
      const session = resolved.session;
      if (session.sid) {
        try {
          await store.revokeSession(session.sid);
        } catch (err) {
          logSystemDiagnostic({
            code: 'FIRESTORE_READ_FAILURE',
            route: req.originalUrl,
            ip: getClientIp(req),
            role: session.role,
            detail: `logout_revoke_failed:${err instanceof Error ? err.message : 'unknown'}`,
          });
        }
      }
      try {
        await store.addAuditLog({
          id: generateRecordId('aud'),
          timestamp: new Date().toISOString(),
          actor: session.username,
          actorRole: session.role,
          action: 'LOGOUT',
          ipAddress: getClientIp(req),
        });
      } catch {
        // non-fatal
      }
    }
    res.json({ success: true });
  });

  // Server-side Scrap Route Private PIN Verification (Salted Scrypt + Rate Limited)
  router.post('/auth/scrap-route/verify-pin', requireAuth, async (req: AuthedRequest, res) => {
    const store = getStore();
    const session = req.session!;
    const ip = getClientIp(req);
    const rateKey = `scrap_route_pin:${ip}:${session.username.toLowerCase()}`;

    const limit = checkRateLimit(rateKey);
    if (!limit.allowed) {
      res.status(429).json({
        error: `Too many failed Scrap Route PIN attempts. Please wait ${formatCooldownText(limit.retryAfterSeconds)} before trying again.`,
        retryAfterSeconds: limit.retryAfterSeconds,
      });
      return;
    }

    const pinConfig = getConfiguredScrapRoutePinHash();
    if (!pinConfig.configured) {
      res.status(503).json({
        error: 'Scrap Route PIN is not configured on this server. Set SCRAP_ROUTE_PIN in server environment variables.',
        code: 'SCRAP_ROUTE_PIN_UNCONFIGURED',
      });
      return;
    }
    if (!pinConfig.valid) {
      res.status(500).json({
        error: 'Scrap Route PIN configuration format is invalid. Please contact your administrator.',
        code: 'SCRAP_ROUTE_PIN_INVALID_CONFIG',
      });
      return;
    }

    const body = (req.body ?? {}) as Record<string, unknown>;
    const pin = typeof body.pin === 'string' ? body.pin.trim() : '';
    if (!pin) {
      res.status(400).json({ error: 'Please enter the Scrap Route PIN.' });
      return;
    }

    const matches = verifyPassword(pin, pinConfig.hash);
    if (!matches) {
      const failState = recordAuthFailure(rateKey);
      try {
        await store.addAuditLog({
          id: generateRecordId('aud'),
          timestamp: new Date().toISOString(),
          actor: session.username,
          actorRole: session.role,
          action: 'SCRAP_ROUTE_PIN_FAILED',
          ipAddress: ip,
          reason: 'Invalid Scrap Route PIN provided',
        });
      } catch {
        // non-fatal
      }
      res.status(401).json({
        error: failState.locked
          ? `Scrap Route PIN verification paused for ${formatCooldownText(failState.retryAfterSeconds)} due to multiple failed attempts.`
          : `Invalid Scrap Route PIN. (${failState.remainingAttempts} attempt(s) remaining)`,
      });
      return;
    }

    clearAuthFailures(rateKey);
    const { token, expiresAt } = signScrapRouteAuthToken({
      sid: session.sid ?? '',
      username: session.username,
      sessionVersion: session.sessionVersion,
      ttlSeconds: SCRAP_ROUTE_AUTH_TTL_SECONDS,
    });

    if (session.sid) {
      try {
        await store.updateSessionScrapRouteAuth(session.sid, expiresAt);
      } catch {
        // HMAC-signed HttpOnly cookie + header token remains valid even if session doc update encounters a transient issue
      }
    }

    setScrapRouteCookie(res, token, Math.max(1000, expiresAt - Date.now()));
    try {
      await store.addAuditLog({
        id: generateRecordId('aud'),
        timestamp: new Date().toISOString(),
        actor: session.username,
        actorRole: session.role,
        action: 'SCRAP_ROUTE_PIN_VERIFIED',
        ipAddress: ip,
        metadata: { brand: 'scrap_route' },
      });
    } catch {
      // non-fatal
    }

    res.json({
      authorized: true,
      expiresAt,
      scrapRouteToken: token,
    });
  });

  // Lock Scrap Route issuance mode without signing out of the Maker session
  router.post('/auth/scrap-route/lock', requireAuth, async (req: AuthedRequest, res) => {
    const store = getStore();
    const session = req.session!;
    clearScrapRouteCookie(res);
    if (session.sid) {
      try {
        await store.updateSessionScrapRouteAuth(session.sid, null);
      } catch {
        // non-fatal
      }
    }
    try {
      await store.addAuditLog({
        id: generateRecordId('aud'),
        timestamp: new Date().toISOString(),
        actor: session.username,
        actorRole: session.role,
        action: 'SCRAP_ROUTE_LOCKED',
        ipAddress: getClientIp(req),
        metadata: { brand: 'scrap_route' },
      });
    } catch {
      // non-fatal
    }
    res.json({ authorized: false });
  });

  // Public QR & Certificate Number Verification (No Login Required, Strictly Masked PII)
  router.get('/verify', async (req, res) => {
    const store = getStore();
    const certNumber = sanitizeText(req.query.certificateNumber, 40).toUpperCase();
    const qrToken = sanitizeText(req.query.token, 128);
    const checkedAt = new Date().toISOString();

    if (!certNumber) {
      res.status(400).json({
        found: false,
        verified: false,
        integrityMatch: false,
        tokenMatch: null,
        checkedAt,
        message: 'Certificate number query parameter is required.',
      } satisfies PublicVerificationResult);
      return;
    }

    const cert = await store.getCertificateByNumber(certNumber);
    if (!cert || cert.status === 'SOFT_DELETED') {
      res.status(404).json({
        found: false,
        verified: false,
        integrityMatch: false,
        tokenMatch: null,
        certificateNumber: certNumber,
        checkedAt,
        message: 'No active or archived certificate record matches this certificate number.',
      } satisfies PublicVerificationResult);
      return;
    }

    const recomputedHash = computeCanonicalHash(cert);
    const integrityMatch = timingSafeStringEqual(recomputedHash, cert.canonicalHash);
    const tokenMatch = qrToken ? timingSafeStringEqual(qrToken, cert.qrToken) : null;
    const isVerified = integrityMatch && cert.status === 'ACTIVE' && (tokenMatch === null || tokenMatch);

    const brand = resolveCertificateBrand(cert);
    const brandDisplayName = brand === 'scrap_route' ? 'SCRAP ROUTE' : 'Parivahan Scrappers';

    const result: PublicVerificationResult = {
      found: true,
      verified: isVerified,
      integrityMatch,
      tokenMatch,
      status: cert.status,
      brand,
      brandDisplayName,
      certificateNumber: cert.certificateNumber,
      scrappingRegNumber: cert.scrappingRegNumber,
      ownerName: cert.ownerName,
      vehicleRegNumber: cert.vehicleRegNumber,
      make: cert.make,
      model: cert.model,
      manufactureYear: cert.manufactureYear,
      issueDate: cert.issueDate,
      handoverDate: cert.handoverDate,
      maskedChassisNumber: maskSensitiveNumber(cert.chassisNumber),
      maskedEngineNumber: maskSensitiveNumber(cert.engineNumber),
      facilityName: cert.facilityName,
      facilityRvsfCode: cert.facilityRvsfCode,
      canonicalHash: cert.canonicalHash,
      recomputedHash,
      version: cert.version,
      originalIssuedAt: cert.originalRecord?.issuedAt ?? cert.createdAt,
      lastModifiedAt: cert.updatedAt,
      versionHistoryCount: (cert.versionHistory ?? []).length,
      cancelledAt: cert.cancelledAt,
      cancelReason: cert.cancelReason,
      checkedAt,
      message: !integrityMatch
        ? 'Integrity Alert: Canonical SHA-256 hash mismatch.'
        : tokenMatch === false
          ? 'QR Token Mismatch: This QR code token does not match the current official version.'
          : cert.status === 'CANCELLED'
            ? 'This certificate has been officially CANCELLED by the issuing authority.'
            : 'Authentic Certificate Verified — Canonical SHA-256 Digest Matches Authoritative Registry.',
    };

    res.json(result);
  });

  // ==========================================================================
  // MAKER & MAIN ADMIN CERTIFICATE ISSUANCE ROUTES
  // ==========================================================================
  const handleNextAvailableNumbers = async (req: AuthedRequest, res: Response) => {
    const issueDate = sanitizeText(req.query.issueDate, 20);
    const parsedBrand = parseBrandParam(req.query.brand);
    if (!parsedBrand) {
      res.status(400).json({ error: 'Invalid certificate brand requested.' });
      return;
    }
    if (parsedBrand === 'scrap_route' && !isScrapRouteAuthorized(req, req.session!)) {
      res.status(403).json({
        error: 'Scrap Route PIN verification is required before generating Scrap Route numbers.',
        code: 'SCRAP_ROUTE_PIN_REQUIRED',
      });
      return;
    }
    const ip = getClientIp(req);
    try {
      const candidate = await generateAvailableCandidateNumbers(issueDate || undefined, parsedBrand);
      res.json(candidate);
    } catch (err) {
      const detail = err instanceof Error ? err.message : 'next_number_generation_failed';
      if (detail.toLowerCase().includes('firestore') || detail.toLowerCase().includes('fetch')) {
        logSystemDiagnostic({
          code: 'FIRESTORE_READ_FAILURE',
          route: req.originalUrl,
          ip,
          role: req.session?.role,
          detail,
        });
      }
      logSystemDiagnostic({
        code: 'NEXT_NUMBER_API_FAILURE',
        route: req.originalUrl,
        ip,
        role: req.session?.role,
        detail,
      });
      res.status(503).json({
        error: 'Unable to load next available certificate numbers from the registry. Please retry.',
        code: 'NEXT_NUMBER_API_FAILURE',
      });
    }
  };

  router.get('/certificates/next-numbers', requireAuth, handleNextAvailableNumbers);
  router.get('/certificates/candidate-numbers', requireAuth, handleNextAvailableNumbers);

  // Authenticated secret-free diagnostic endpoint for client-side PDF generation failures
  router.post('/diagnostics/pdf-failure', requireAuth, (req: AuthedRequest, res: Response) => {
    const body = (req.body ?? {}) as Record<string, unknown>;
    const certId = sanitizeText(body.certificateId, 80);
    const reason = sanitizeText(body.reason, 180) || 'client_pdf_generation_error';
    logSystemDiagnostic({
      code: 'PDF_GENERATION_FAILURE',
      route: req.originalUrl,
      ip: getClientIp(req),
      role: req.session?.role,
      detail: `certId=${certId || 'unknown'}:${reason}`,
    });
    res.json({ logged: true });
  });

  // Maker Latest Five Only (Server-Side Hard Limit = 5)
  router.get('/certificates/recent', requireAuth, async (_req, res) => {
    const store = getStore();
    const recent = await store.getRecentActiveCertificates(5);
    res.json({
      certificates: recent,
      maxAllowed: 5,
    });
  });

  // Get single certificate — Maker strictly restricted to the latest 5 recent certificates!
  router.get('/certificates/:id', requireAuth, async (req: AuthedRequest, res) => {
    const store = getStore();
    const id = sanitizeText(req.params.id, 100);
    const cert = await store.getCertificateById(id);
    if (!cert) {
      res.status(404).json({ error: 'Certificate not found.' });
      return;
    }

    if (req.session!.role === 'maker') {
      const recentFive = await store.getRecentActiveCertificates(5);
      const isAllowed = recentFive.some((c) => c.id === cert.id);
      if (!isAllowed) {
        res.status(403).json({
          error: 'Forbidden: Certificate Maker access is restricted to the latest five certificates only.',
        });
        return;
      }
    }

    res.json({ certificate: cert });
  });

  // Authenticated Maker Edit (within Maker's permitted latest-5 scope; preserves certificate number, updates SHA-256 & audit history)
  router.put('/certificates/:id', requireAuth, async (req: AuthedRequest, res) => {
    const store = getStore();
    const id = sanitizeText(req.params.id, 100);
    const existing = await store.getCertificateById(id);
    if (!existing) {
      res.status(404).json({ error: 'Certificate not found.' });
      return;
    }

    if (req.session!.role === 'maker') {
      if (existing.status !== 'ACTIVE') {
        res.status(400).json({ error: 'Only active certificates can be edited by a Certificate Maker.' });
        return;
      }
      const recentFive = await store.getRecentActiveCertificates(5);
      const isAllowed = recentFive.some((c) => c.id === existing.id);
      if (!isAllowed) {
        res.status(403).json({
          error: 'Forbidden: Certificate Maker editing is restricted to the latest five active certificates.',
        });
        return;
      }
    }

    const body = (req.body ?? {}) as Record<string, unknown>;
    const rawUpdates = body.updates && typeof body.updates === 'object' ? (body.updates as Record<string, unknown>) : body;
    const reason = sanitizeText(body.reason, 300) || `Updated by ${req.session!.role === 'main_admin' ? 'Main Core Admin' : 'Certificate Maker'}`;

    const existingBrand = resolveCertificateBrand(existing);
    if (
      rawUpdates.brand !== undefined &&
      rawUpdates.brand !== null &&
      rawUpdates.brand !== '' &&
      rawUpdates.brand !== existingBrand
    ) {
      res.status(403).json({ error: 'Certificate brand identity is permanent and cannot be changed.' });
      return;
    }

    const validated = validateCertificatePayload(
      {
        ...existing,
        ...rawUpdates,
        // Always preserve immutable identifiers, brand, and existing rtoAuthority
        brand: existingBrand,
        certificateNumber: existing.certificateNumber,
        scrappingRegNumber: existing.scrappingRegNumber,
        rtoAuthority: existing.rtoAuthority ?? '',
      },
      existingBrand
    );
    if (!validated.ok) {
      res.status(400).json({ error: validated.error });
      return;
    }

    const now = new Date().toISOString();
    const previousFields = extractCertificateCoreFields(existing);
    const preservedOriginal: OriginalCertificateSnapshot = existing.originalRecord ?? {
      version: 1,
      issuedAt: existing.createdAt,
      issuedBy: existing.createdBy,
      issuedByRole: existing.createdByRole,
      brand: existingBrand,
      certificateNumber: existing.certificateNumber,
      scrappingRegNumber: existing.scrappingRegNumber,
      canonicalHash:
        existing.versionHistory && existing.versionHistory.length > 0
          ? existing.versionHistory[existing.versionHistory.length - 1].previousCanonicalHash
          : existing.canonicalHash,
      qrToken: existing.qrToken,
      data:
        existing.versionHistory && existing.versionHistory.length > 0
          ? existing.versionHistory[existing.versionHistory.length - 1].previousData
          : previousFields,
    };

    const updates = validated.data;
    const nextCertBase: Omit<CertificateRecord, 'canonicalHash'> = {
      ...existing,
      brand: existingBrand,
      issueDate: updates.issueDate,
      handoverDate: updates.handoverDate,
      ownerName: updates.ownerName,
      ownerAddress: updates.ownerAddress ?? '',
      idProofType: updates.idProofType ?? '',
      idProofNumber: updates.idProofNumber ?? '',
      vehicleRegNumber: updates.vehicleRegNumber,
      make: updates.make,
      model: updates.model,
      manufactureYear: updates.manufactureYear,
      chassisNumber: updates.chassisNumber,
      engineNumber: updates.engineNumber,
      unhideChassisEngine: updates.unhideChassisEngine === true,
      rtoAuthority: existing.rtoAuthority ?? '',
      remarks: updates.remarks ?? '',
      version: existing.version + 1,
      qrToken: generateQrToken(),
      updatedAt: now,
      originalRecord: preservedOriginal,
      versionHistory: existing.versionHistory ?? [],
    };

    const nextCanonicalHash = computeCanonicalHash(nextCertBase);
    const nextFields = extractCertificateCoreFields({
      ...nextCertBase,
      canonicalHash: nextCanonicalHash,
    });
    const changedFields = computeChangedCertificateFields(previousFields, nextFields);

    const snapshot = {
      version: existing.version,
      editedAt: now,
      editedBy: req.session!.username,
      actorRole: req.session!.role,
      reason,
      changedFields,
      previousCanonicalHash: existing.canonicalHash,
      newCanonicalHash: nextCanonicalHash,
      previousData: previousFields,
    };

    const updated: CertificateRecord = {
      ...nextCertBase,
      versionHistory: [snapshot, ...(existing.versionHistory ?? [])],
      canonicalHash: nextCanonicalHash,
    };

    await store.saveCertificate(updated);
    const versionDoc: CertificateVersionDocument = {
      id: `${updated.id}_v${updated.version}_${generateRecordId('ver')}`,
      certificateId: updated.id,
      certificateNumber: updated.certificateNumber,
      brand: existingBrand,
      version: updated.version,
      recordedAt: now,
      actor: req.session!.username,
      actorRole: req.session!.role,
      event: 'MODIFIED',
      reason,
      changedFields,
      previousCanonicalHash: existing.canonicalHash,
      canonicalHash: nextCanonicalHash,
      data: nextFields,
    };
    try {
      await store.appendCertificateVersion(versionDoc);
    } catch {
      // Embedded versionHistory on certificate remains complete even if secondary collection write retries
    }
    await store.addAuditLog({
      id: generateRecordId('aud'),
      timestamp: now,
      actor: req.session!.username,
      actorRole: req.session!.role,
      action: 'CERTIFICATE_EDITED',
      certificateId: updated.id,
      certificateNumber: updated.certificateNumber,
      reason,
      ipAddress: getClientIp(req),
      metadata: {
        brand: existingBrand,
        previousVersion: existing.version,
        newVersion: updated.version,
        changedFieldsCount: changedFields.length,
        changedFields: changedFields.join(', '),
      },
    });

    res.json({ certificate: updated });
  });

  // Authenticated Maker Archive (STRICTLY reversible soft-archive only; permanent deletion is forbidden for Maker)
  router.delete('/certificates/:id', requireAuth, async (req: AuthedRequest, res) => {
    const store = getStore();
    const id = sanitizeText(req.params.id, 100);
    const body = (req.body ?? {}) as Record<string, unknown>;

    if (body.permanent === true) {
      res.status(403).json({
        error:
          'Forbidden: Permanent deletion is strictly restricted to Main Core Admin owner authorization. Use Archive instead.',
      });
      return;
    }

    const existing = await store.getCertificateById(id);
    if (!existing) {
      res.status(404).json({ error: 'Certificate not found.' });
      return;
    }
    if (existing.status === 'SOFT_DELETED') {
      res.status(400).json({ error: 'Certificate has already been archived.' });
      return;
    }

    if (req.session!.role === 'maker') {
      const recentFive = await store.getRecentActiveCertificates(5);
      const isAllowed = recentFive.some((c) => c.id === existing.id);
      if (!isAllowed) {
        res.status(403).json({
          error: 'Forbidden: Certificate Maker archiving is restricted to the latest five active certificates.',
        });
        return;
      }
    }

    const reason =
      sanitizeText(body.reason, 300) ||
      `Archived by authenticated ${req.session!.role === 'main_admin' ? 'Main Core Admin' : 'Certificate Maker'}`;

    const now = new Date().toISOString();
    const existingBrand = resolveCertificateBrand(existing);
    const softDeletedBase: Omit<CertificateRecord, 'canonicalHash'> = {
      ...existing,
      status: 'SOFT_DELETED',
      deletedAt: now,
      deletedBy: req.session!.username,
      deleteReason: reason,
      updatedAt: now,
    };
    const updated: CertificateRecord = {
      ...softDeletedBase,
      canonicalHash: computeCanonicalHash(softDeletedBase),
    };

    await store.saveCertificate(updated);
    try {
      await store.appendCertificateVersion({
        id: `${updated.id}_archive_${generateRecordId('ver')}`,
        certificateId: updated.id,
        certificateNumber: updated.certificateNumber,
        brand: existingBrand,
        version: updated.version,
        recordedAt: now,
        actor: req.session!.username,
        actorRole: req.session!.role,
        event: 'ARCHIVED',
        reason,
        changedFields: ['status'],
        previousCanonicalHash: existing.canonicalHash,
        canonicalHash: updated.canonicalHash,
        data: extractCertificateCoreFields(updated),
      });
    } catch {
      // non-fatal
    }
    await store.addAuditLog({
      id: generateRecordId('aud'),
      timestamp: now,
      actor: req.session!.username,
      actorRole: req.session!.role,
      action: 'CERTIFICATE_SOFT_DELETED',
      certificateId: updated.id,
      certificateNumber: updated.certificateNumber,
      reason,
      ipAddress: getClientIp(req),
      metadata: {
        brand: existingBrand,
        archived: true,
        permanent: false,
        reservedNumbersRetained: true,
      },
    });

    res.json({
      success: true,
      archived: true,
      permanent: false,
      deletedId: updated.id,
      certificateNumber: updated.certificateNumber,
      deletedAt: now,
      deletedBy: req.session!.username,
    });
  });

  // Atomic Certificate Creation with Idempotency Key & Collision Protection
  router.post('/certificates', requireAuth, async (req: AuthedRequest, res) => {
    const startMs = Date.now();
    const store = getStore();
    const ip = getClientIp(req);

    const requestedBrand = parseBrandParam((req.body as Record<string, unknown>)?.brand);
    if (!requestedBrand) {
      res.status(400).json({ error: 'Invalid certificate brand specified.' });
      return;
    }

    if (requestedBrand === 'scrap_route' && !isScrapRouteAuthorized(req, req.session!)) {
      res.status(403).json({
        error: 'Scrap Route PIN verification is required to issue Scrap Route certificates.',
        code: 'SCRAP_ROUTE_PIN_REQUIRED',
      });
      return;
    }

    const validated = validateCertificatePayload(req.body, requestedBrand);
    if (!validated.ok) {
      res.status(400).json({ error: validated.error });
      return;
    }

    const headerKey = sanitizeText(req.headers['idempotency-key'], 128);
    const bodyKey = sanitizeText((req.body as Record<string, unknown>)?.idempotencyKey, 128);
    const idempotencyKey = headerKey || bodyKey || generateRecordId('idemp');

    // Fast path: return existing certificate if this exact submission was already committed
    let settings: SystemSettings;
    try {
      const existingIdemp = await store.getIdempotencyRecord(idempotencyKey);
      if (existingIdemp) {
        const existingCert = await store.getCertificateById(existingIdemp.certificateId);
        if (existingCert) {
          res.status(200).json({
            certificate: existingCert,
            idempotentReplay: true,
            persistenceMs: Date.now() - startMs,
          });
          return;
        }
      }
      settings = await store.getSettings();
    } catch (err) {
      logSystemDiagnostic({
        code: 'FIRESTORE_READ_FAILURE',
        route: req.originalUrl,
        ip,
        role: req.session?.role,
        detail: err instanceof Error ? err.message : 'Unable to read idempotency/settings',
      });
      res.status(503).json({
        error: 'Unable to communicate with the certificate database. Please retry.',
        code: 'FIRESTORE_READ_FAILURE',
      });
      return;
    }

    const input = validated.data;
    const now = new Date().toISOString();
    const driveReady = settings.driveSyncEnabled && isDriveConfigured(settings.driveFolderId);

    // Retry up to 8 times if a random number collides concurrently
    let candidateCertNo = input.certificateNumber;
    let candidateRegNo = input.scrappingRegNumber;

    for (let attempt = 0; attempt < 8; attempt++) {
      if (!candidateCertNo || !candidateRegNo || attempt > 0) {
        try {
          const fresh = await generateAvailableCandidateNumbers(input.issueDate, requestedBrand);
          candidateCertNo = fresh.certificateNumber;
          candidateRegNo = fresh.scrappingRegNumber;
        } catch (err) {
          logSystemDiagnostic({
            code: 'CERTIFICATE_RESERVATION_FAILURE',
            route: req.originalUrl,
            ip,
            role: req.session?.role,
            detail: err instanceof Error ? err.message : 'Candidate number allocation failed',
          });
          try {
            await store.addAuditLog({
              id: generateRecordId('aud'),
              timestamp: new Date().toISOString(),
              actor: req.session!.username,
              actorRole: req.session!.role,
              action: 'CERTIFICATE_ISSUANCE_FAILED',
              ipAddress: ip,
              reason: 'Number reservation failed before issuance; no fallback number invented',
              metadata: { brand: requestedBrand, stage: 'number_reservation' },
            });
          } catch {
            // non-fatal
          }
          res.status(503).json({
            error: 'Unable to reserve a unique certificate number. Issuance stopped safely — please retry.',
            code: 'CERTIFICATE_RESERVATION_FAILURE',
          });
          return;
        }
      }

      const certId = generateRecordId('cert');
      const qrToken = generateQrToken();
      const baseCert: Omit<CertificateRecord, 'canonicalHash'> = {
        id: certId,
        brand: requestedBrand,
        certificateNumber: candidateCertNo,
        scrappingRegNumber: candidateRegNo,
        status: 'ACTIVE',
        version: 1,
        issueDate: input.issueDate,
        handoverDate: input.handoverDate,
        ownerName: input.ownerName,
        ownerAddress: input.ownerAddress ?? '',
        idProofType: input.idProofType ?? '',
        idProofNumber: input.idProofNumber ?? '',
        vehicleRegNumber: input.vehicleRegNumber,
        make: input.make,
        model: input.model,
        manufactureYear: input.manufactureYear,
        chassisNumber: input.chassisNumber,
        engineNumber: input.engineNumber,
        unhideChassisEngine: input.unhideChassisEngine === true,
        rtoAuthority: input.rtoAuthority ?? '',
        facilityName: requestedBrand === 'scrap_route' ? 'Scrap Route' : settings.facilityName,
        facilityRvsfCode: settings.facilityRvsfCode,
        facilityAddress: settings.facilityAddress,
        remarks: input.remarks ?? '',
        qrToken,
        createdAt: now,
        updatedAt: now,
        createdBy: req.session!.username,
        createdByRole: req.session!.role,
        versionHistory: [],
        driveSyncStatus: driveReady ? 'PENDING' : 'NOT_CONFIGURED',
      };

      const canonicalHash = computeCanonicalHash(baseCert);
      const initialFields = extractCertificateCoreFields({ ...baseCert, canonicalHash });
      const originalRecord: OriginalCertificateSnapshot = {
        version: 1,
        issuedAt: now,
        issuedBy: req.session!.username,
        issuedByRole: req.session!.role,
        brand: requestedBrand,
        certificateNumber: candidateCertNo,
        scrappingRegNumber: candidateRegNo,
        canonicalHash,
        qrToken,
        data: initialFields,
      };

      const certificate: CertificateRecord = {
        ...baseCert,
        originalRecord,
        canonicalHash,
      };

      const initialVersionDoc: CertificateVersionDocument = {
        id: `${certificate.id}_v1`,
        certificateId: certificate.id,
        certificateNumber: certificate.certificateNumber,
        brand: requestedBrand,
        version: 1,
        recordedAt: now,
        actor: req.session!.username,
        actorRole: req.session!.role,
        event: 'ISSUED',
        reason: 'Original certificate issuance',
        changedFields: [],
        canonicalHash,
        data: initialFields,
      };

      try {
        const committed = await store.createCertificateAtomic({
          certificate,
          idempotencyKey,
          initialVersionDoc,
          auditLog: {
            id: generateRecordId('aud'),
            timestamp: now,
            actor: req.session!.username,
            actorRole: req.session!.role,
            action: 'CERTIFICATE_CREATED',
            certificateId: certificate.id,
            certificateNumber: certificate.certificateNumber,
            ipAddress: ip,
            metadata: {
              brand: requestedBrand,
              scrappingRegNumber: certificate.scrappingRegNumber,
              vehicleRegNumber: certificate.vehicleRegNumber,
            },
          },
        });

        // Post-write durability read-back check before confirming issuance to client
        const verifiedReadBack = await store.getCertificateById(committed.id);
        if (
          !verifiedReadBack ||
          verifiedReadBack.certificateNumber !== committed.certificateNumber ||
          verifiedReadBack.canonicalHash !== committed.canonicalHash
        ) {
          throw new Error('Post-write database read-back verification failed for newly issued certificate.');
        }

        // Fire-and-forget optional Google Drive sync (never blocks issuance response)
        if (driveReady) {
          void syncCertificateToDriveInBackground(store, verifiedReadBack, 1);
        }

        res.status(201).json({
          certificate: verifiedReadBack,
          idempotentReplay: false,
          verifiedReadBack: true,
          persistenceMs: Date.now() - startMs,
        });
        return;
      } catch (err) {
        if ((err as NodeJS.ErrnoException)?.code === 'NUMBER_COLLISION') {
          logSystemDiagnostic({
            code: 'CERTIFICATE_RESERVATION_FAILURE',
            route: req.originalUrl,
            ip,
            role: req.session?.role,
            detail: `number_collision_retry_attempt_${attempt + 1}`,
          });
          candidateCertNo = undefined;
          candidateRegNo = undefined;
          continue;
        }
        logSystemDiagnostic({
          code: 'CERTIFICATE_SAVE_FAILURE',
          route: req.originalUrl,
          ip,
          role: req.session?.role,
          detail: err instanceof Error ? err.message : 'Atomic Firestore certificate save failed',
        });
        try {
          await store.addAuditLog({
            id: generateRecordId('aud'),
            timestamp: new Date().toISOString(),
            actor: req.session!.username,
            actorRole: req.session!.role,
            action: 'CERTIFICATE_ISSUANCE_FAILED',
            certificateNumber: candidateCertNo,
            ipAddress: ip,
            reason: 'Atomic Firestore persistence or read-back verification failed',
            metadata: { brand: requestedBrand, stage: 'atomic_commit' },
          });
        } catch {
          // non-fatal
        }
        res.status(503).json({
          error: 'Failed to save certificate to Firestore. Please retry — idempotency prevents duplicates.',
          code: 'CERTIFICATE_SAVE_FAILURE',
        });
        return;
      }
    }

    logSystemDiagnostic({
      code: 'CERTIFICATE_RESERVATION_FAILURE',
      route: req.originalUrl,
      ip,
      role: req.session?.role,
      detail: 'exhausted_8_collision_retries',
    });
    try {
      await store.addAuditLog({
        id: generateRecordId('aud'),
        timestamp: new Date().toISOString(),
        actor: req.session!.username,
        actorRole: req.session!.role,
        action: 'CERTIFICATE_ISSUANCE_FAILED',
        ipAddress: ip,
        reason: 'Exhausted 8 atomic number collision retries; no fallback number invented',
        metadata: { brand: requestedBrand, stage: 'collision_exhausted' },
      });
    } catch {
      // non-fatal
    }
    res.status(503).json({
      error: 'Unable to reserve unique certificate numbers due to high concurrency. Please try again.',
      code: 'CERTIFICATE_RESERVATION_FAILURE',
    });
  });

  // Explicitly deny Maker attempts to list all certificates on base route
  router.get('/certificates', requireMainAdmin, async (_req, res) => {
    const certificates = await getStore().getAllCertificates();
    res.json({ certificates, total: certificates.length });
  });

  // ==========================================================================
  // MAIN CORE ADMIN PROTECTED ROUTES
  // ==========================================================================
  router.get('/admin/stats', requireMainAdmin, async (_req, res) => {
    const store = getStore();
    const [certs, reserved, backups, auditLogs] = await Promise.all([
      store.getAllCertificates(),
      store.getReservedCounts(),
      store.listBackups(),
      store.getAuditLogs(500),
    ]);

    const todayPrefix = new Date().toISOString().slice(0, 10);
    const monthPrefix = new Date().toISOString().slice(0, 7);

    const parivahanCertificates = certs.filter(
      (c) => resolveCertificateBrand(c) === 'parivahan'
    ).length;
    const scrapRouteCertificates = certs.filter(
      (c) => resolveCertificateBrand(c) === 'scrap_route'
    ).length;
    const modifiedCertificates = certs.filter(
      (c) => c.version > 1 || (c.versionHistory && c.versionHistory.length > 0)
    ).length;
    const failedIssuanceAttempts = auditLogs.filter(
      (l) => l.action === 'CERTIFICATE_ISSUANCE_FAILED'
    ).length;

    const stats: DashboardStats = {
      totalCertificates: certs.length,
      parivahanCertificates,
      scrapRouteCertificates,
      activeCertificates: certs.filter((c) => c.status === 'ACTIVE').length,
      cancelledCertificates: certs.filter((c) => c.status === 'CANCELLED').length,
      softDeletedCertificates: certs.filter((c) => c.status === 'SOFT_DELETED').length,
      modifiedCertificates,
      failedIssuanceAttempts,
      issuedToday: certs.filter((c) => c.createdAt.startsWith(todayPrefix)).length,
      issuedThisMonth: certs.filter((c) => c.createdAt.startsWith(monthPrefix)).length,
      reservedCertNumbers: reserved.certCount,
      reservedRegNumbers: reserved.regCount,
      totalBackups: backups.length,
      lastBackupAt: backups.find((b) => b.verified)?.createdAt ?? backups[0]?.createdAt ?? null,
      driveSyncedCount: certs.filter((c) => c.driveSyncStatus === 'SYNCED').length,
      driveFailedCount: certs.filter((c) => c.driveSyncStatus === 'FAILED').length,
      storageMode: store.mode,
    };

    res.json(stats);
  });

  router.get('/admin/certificates', requireMainAdmin, async (req, res) => {
    const store = getStore();
    const search = sanitizeText(req.query.search, 120).toLowerCase();
    const status = sanitizeText(req.query.status, 30).toUpperCase();
    const all = await store.getAllCertificates();

    const filtered = all.filter((c) => {
      if (status && status !== 'ALL' && c.status !== status) return false;
      if (!search) return true;
      return (
        c.certificateNumber.toLowerCase().includes(search) ||
        c.scrappingRegNumber.toLowerCase().includes(search) ||
        c.ownerName.toLowerCase().includes(search) ||
        c.vehicleRegNumber.toLowerCase().includes(search) ||
        c.chassisNumber.toLowerCase().includes(search) ||
        c.engineNumber.toLowerCase().includes(search) ||
        c.make.toLowerCase().includes(search) ||
        c.model.toLowerCase().includes(search)
      );
    });

    res.json({ certificates: filtered, total: filtered.length, registryTotal: all.length });
  });

  // Protected Edit (preserves version history, recomputes SHA-256 & rotates QR token)
  router.put('/admin/certificates/:id', requireMainAdmin, async (req: AuthedRequest, res) => {
    const store = getStore();
    const id = sanitizeText(req.params.id, 100);
    const body = (req.body ?? {}) as Record<string, unknown>;
    const protectedPassword = typeof body.protectedPassword === 'string' ? body.protectedPassword : '';
    const reason = sanitizeText(body.reason, 300);

    if (!reason || reason.length < 5) {
      res.status(400).json({ error: 'A mandatory edit reason (at least 5 characters) is required.' });
      return;
    }

    const authorized = await verifyProtectedPassword(protectedPassword, 'edit');
    if (!authorized) {
      res.status(403).json({ error: 'Invalid protected-action authorization password.' });
      return;
    }

    const existing = await store.getCertificateById(id);
    if (!existing) {
      res.status(404).json({ error: 'Certificate not found.' });
      return;
    }

    const existingBrand = resolveCertificateBrand(existing);
    const adminRawUpdates =
      body.updates && typeof body.updates === 'object'
        ? (body.updates as Record<string, unknown>)
        : {};
    const requestedAdminBrand = adminRawUpdates.brand ?? body.brand;
    if (
      requestedAdminBrand !== undefined &&
      requestedAdminBrand !== null &&
      requestedAdminBrand !== '' &&
      requestedAdminBrand !== existingBrand
    ) {
      res.status(403).json({ error: 'Certificate brand identity is permanent and cannot be changed.' });
      return;
    }

    const validated = validateCertificatePayload(
      {
        ...existing,
        ...adminRawUpdates,
        brand: existingBrand,
        certificateNumber: existing.certificateNumber,
        scrappingRegNumber: existing.scrappingRegNumber,
      },
      existingBrand
    );
    if (!validated.ok) {
      res.status(400).json({ error: validated.error });
      return;
    }

    const now = new Date().toISOString();
    const previousFields = extractCertificateCoreFields(existing);
    const preservedOriginal: OriginalCertificateSnapshot = existing.originalRecord ?? {
      version: 1,
      issuedAt: existing.createdAt,
      issuedBy: existing.createdBy,
      issuedByRole: existing.createdByRole,
      brand: existingBrand,
      certificateNumber: existing.certificateNumber,
      scrappingRegNumber: existing.scrappingRegNumber,
      canonicalHash:
        existing.versionHistory && existing.versionHistory.length > 0
          ? existing.versionHistory[existing.versionHistory.length - 1].previousCanonicalHash
          : existing.canonicalHash,
      qrToken: existing.qrToken,
      data:
        existing.versionHistory && existing.versionHistory.length > 0
          ? existing.versionHistory[existing.versionHistory.length - 1].previousData
          : previousFields,
    };

    const updates = validated.data;
    const nextCertBase: Omit<CertificateRecord, 'canonicalHash'> = {
      ...existing,
      brand: existingBrand,
      issueDate: updates.issueDate,
      handoverDate: updates.handoverDate,
      ownerName: updates.ownerName,
      ownerAddress: updates.ownerAddress ?? '',
      idProofType: updates.idProofType ?? '',
      idProofNumber: updates.idProofNumber ?? '',
      vehicleRegNumber: updates.vehicleRegNumber,
      make: updates.make,
      model: updates.model,
      manufactureYear: updates.manufactureYear,
      chassisNumber: updates.chassisNumber,
      engineNumber: updates.engineNumber,
      unhideChassisEngine: updates.unhideChassisEngine === true,
      rtoAuthority: existing.rtoAuthority ?? '',
      remarks: updates.remarks ?? '',
      version: existing.version + 1,
      qrToken: generateQrToken(),
      updatedAt: now,
      originalRecord: preservedOriginal,
      versionHistory: existing.versionHistory ?? [],
    };

    const nextCanonicalHash = computeCanonicalHash(nextCertBase);
    const nextFields = extractCertificateCoreFields({
      ...nextCertBase,
      canonicalHash: nextCanonicalHash,
    });
    const changedFields = computeChangedCertificateFields(previousFields, nextFields);

    const snapshot = {
      version: existing.version,
      editedAt: now,
      editedBy: req.session!.username,
      actorRole: req.session!.role,
      reason,
      changedFields,
      previousCanonicalHash: existing.canonicalHash,
      newCanonicalHash: nextCanonicalHash,
      previousData: previousFields,
    };

    const updated: CertificateRecord = {
      ...nextCertBase,
      versionHistory: [snapshot, ...(existing.versionHistory ?? [])],
      canonicalHash: nextCanonicalHash,
    };

    await store.saveCertificate(updated);
    try {
      await store.appendCertificateVersion({
        id: `${updated.id}_v${updated.version}_${generateRecordId('ver')}`,
        certificateId: updated.id,
        certificateNumber: updated.certificateNumber,
        brand: existingBrand,
        version: updated.version,
        recordedAt: now,
        actor: req.session!.username,
        actorRole: req.session!.role,
        event: 'MODIFIED',
        reason,
        changedFields,
        previousCanonicalHash: existing.canonicalHash,
        canonicalHash: nextCanonicalHash,
        data: nextFields,
      });
    } catch {
      // Embedded versionHistory remains complete
    }
    await store.addAuditLog({
      id: generateRecordId('aud'),
      timestamp: now,
      actor: req.session!.username,
      actorRole: req.session!.role,
      action: 'CERTIFICATE_EDITED',
      certificateId: updated.id,
      certificateNumber: updated.certificateNumber,
      reason,
      ipAddress: getClientIp(req),
      metadata: {
        brand: existingBrand,
        previousVersion: existing.version,
        newVersion: updated.version,
        changedFieldsCount: changedFields.length,
        changedFields: changedFields.join(', '),
      },
    });

    res.json({ certificate: updated });
  });

  // Owner-Only Full Immutable Version History & Original Record Viewer
  router.get('/admin/certificates/:id/history', requireMainAdmin, async (req, res) => {
    const store = getStore();
    const id = sanitizeText(req.params.id, 100);
    const cert = await store.getCertificateById(id);
    if (!cert) {
      res.status(404).json({ error: 'Certificate not found.' });
      return;
    }
    let appendOnlyVersions: CertificateVersionDocument[] = [];
    try {
      appendOnlyVersions = await store.getCertificateVersions(cert.id);
    } catch {
      appendOnlyVersions = [];
    }
    const existingBrand = resolveCertificateBrand(cert);
    const originalRecord: OriginalCertificateSnapshot = cert.originalRecord ?? {
      version: 1,
      issuedAt: cert.createdAt,
      issuedBy: cert.createdBy,
      issuedByRole: cert.createdByRole,
      brand: existingBrand,
      certificateNumber: cert.certificateNumber,
      scrappingRegNumber: cert.scrappingRegNumber,
      canonicalHash:
        cert.versionHistory && cert.versionHistory.length > 0
          ? cert.versionHistory[cert.versionHistory.length - 1].previousCanonicalHash
          : cert.canonicalHash,
      qrToken: cert.qrToken,
      data:
        cert.versionHistory && cert.versionHistory.length > 0
          ? cert.versionHistory[cert.versionHistory.length - 1].previousData
          : extractCertificateCoreFields(cert),
    };
    res.json({
      certificate: cert,
      originalRecord,
      versionHistory: cert.versionHistory ?? [],
      appendOnlyVersions,
    });
  });

  // Protected Cancel (mandatory reason + protected password; reserved numbers remain locked forever)
  router.post('/admin/certificates/:id/cancel', requireMainAdmin, async (req: AuthedRequest, res) => {
    const store = getStore();
    const id = sanitizeText(req.params.id, 100);
    const body = (req.body ?? {}) as Record<string, unknown>;
    const protectedPassword = typeof body.protectedPassword === 'string' ? body.protectedPassword : '';
    const reason = sanitizeText(body.reason, 300);

    if (!reason || reason.length < 5) {
      res.status(400).json({ error: 'A mandatory cancellation reason (at least 5 characters) is required.' });
      return;
    }

    const authorized = await verifyProtectedPassword(protectedPassword, 'edit');
    if (!authorized) {
      res.status(403).json({ error: 'Invalid protected-action authorization password.' });
      return;
    }

    const existing = await store.getCertificateById(id);
    if (!existing) {
      res.status(404).json({ error: 'Certificate not found.' });
      return;
    }

    const now = new Date().toISOString();
    const cancelledBase: Omit<CertificateRecord, 'canonicalHash'> = {
      ...existing,
      status: 'CANCELLED',
      cancelledAt: now,
      cancelledBy: req.session!.username,
      cancelReason: reason,
      updatedAt: now,
    };
    const updated: CertificateRecord = {
      ...cancelledBase,
      canonicalHash: computeCanonicalHash(cancelledBase),
    };

    await store.saveCertificate(updated);
    try {
      await store.appendCertificateVersion({
        id: `${updated.id}_cancel_${generateRecordId('ver')}`,
        certificateId: updated.id,
        certificateNumber: updated.certificateNumber,
        brand: resolveCertificateBrand(updated),
        version: updated.version,
        recordedAt: now,
        actor: req.session!.username,
        actorRole: req.session!.role,
        event: 'CANCELLED',
        reason,
        changedFields: ['status'],
        previousCanonicalHash: existing.canonicalHash,
        canonicalHash: updated.canonicalHash,
        data: extractCertificateCoreFields(updated),
      });
    } catch {
      // non-fatal
    }
    await store.addAuditLog({
      id: generateRecordId('aud'),
      timestamp: now,
      actor: req.session!.username,
      actorRole: req.session!.role,
      action: 'CERTIFICATE_CANCELLED',
      certificateId: updated.id,
      certificateNumber: updated.certificateNumber,
      reason,
      ipAddress: getClientIp(req),
    });

    res.json({ certificate: updated });
  });

  // Protected Archive & Owner-Authorized Permanent Deletion
  // Default: Archive (SOFT_DELETED), permanently retained and restorable.
  // Permanent Deletion: Requires fresh Main Core Admin password + Protected Delete password +
  // explicit certificate number confirmation + PERMANENT DELETE phrase + healthy audit/backup gate + safety backup.
  router.delete('/admin/certificates/:id', requireMainAdmin, async (req: AuthedRequest, res) => {
    const store = getStore();
    const id = sanitizeText(req.params.id, 100);
    const body = (req.body ?? {}) as Record<string, unknown>;

    if (Array.isArray(body.ids) || body.bulk === true) {
      res.status(400).json({ error: 'Bulk deletion is strictly prohibited.' });
      return;
    }

    const deletePassword = typeof body.deletePassword === 'string' ? body.deletePassword : '';
    const mainAdminPassword = typeof body.mainAdminPassword === 'string' ? body.mainAdminPassword : '';
    const reason = sanitizeText(body.reason, 300);
    const permanent = body.permanent === true;
    const confirmPhrase = sanitizeText(body.confirmPhrase, 60);
    const confirmCertificateNumber = sanitizeText(body.confirmCertificateNumber, 40).toUpperCase();

    if (!reason || reason.length < 5) {
      res.status(400).json({ error: 'A mandatory deletion reason (at least 5 characters) is required.' });
      return;
    }

    const authorized = await verifyProtectedPassword(deletePassword, 'delete');
    if (!authorized) {
      res.status(403).json({ error: 'Invalid protected deletion password.' });
      return;
    }

    const existing = await store.getCertificateById(id);
    if (!existing) {
      res.status(404).json({ error: 'Certificate not found.' });
      return;
    }

    const now = new Date().toISOString();
    const existingBrand = resolveCertificateBrand(existing);

    if (permanent) {
      // 1. Fresh Main Core Admin owner authentication required for permanent deletion
      const credRes = await resolveAuthoritativeCredentials(store);
      if (
        !credRes.ok ||
        !credRes.creds ||
        !mainAdminPassword ||
        !verifyPassword(mainAdminPassword, credRes.creds.mainAdminPasswordHash)
      ) {
        res.status(403).json({
          error:
            'Permanent deletion requires fresh Main Core Admin password verification in addition to the protected deletion password.',
        });
        return;
      }

      // 2. Explicit certificate-number confirmation + exact confirmation phrase required
      if (
        !confirmCertificateNumber ||
        confirmCertificateNumber !== existing.certificateNumber.toUpperCase()
      ) {
        res.status(400).json({
          error: `Permanent deletion requires typing the exact certificate number (${existing.certificateNumber}) to confirm.`,
        });
        return;
      }

      if (confirmPhrase !== 'PERMANENT DELETE') {
        res.status(400).json({
          error: 'Permanent deletion requires typing exact confirmation phrase: PERMANENT DELETE',
        });
        return;
      }

      // 3. Health & Integrity Gate: Prevent permanent deletion if database or integrity checks are unhealthy
      const preDeleteAudit = await runReadOnlyIntegrityAudit(store);
      if (!preDeleteAudit.healthy) {
        res.status(409).json({
          error:
            'Permanent deletion is blocked because database health or integrity audit checks detected critical issues. Resolve integrity alerts first.',
          code: 'INTEGRITY_HEALTH_GATE_BLOCKED',
        });
        return;
      }

      // 4. Recovery safeguard: create & verify a pre-delete safety snapshot BEFORE permanent removal
      let safetyBackup;
      try {
        safetyBackup = await store.createBackup(req.session!.username, 'PRE_RESTORE_SAFETY');
        if (!safetyBackup.verified) {
          throw new Error('Safety backup could not be verified');
        }
      } catch {
        res.status(503).json({
          error:
            'Permanent deletion aborted because the mandatory pre-deletion safety backup failed. Existing record has been preserved.',
          code: 'BACKUP_HEALTH_GATE_BLOCKED',
        });
        return;
      }

      await store.permanentlyDeleteCertificate(existing.id);
      await store.addAuditLog({
        id: generateRecordId('aud'),
        timestamp: now,
        actor: req.session!.username,
        actorRole: req.session!.role,
        action: 'CERTIFICATE_PERMANENTLY_DELETED',
        certificateId: existing.id,
        certificateNumber: existing.certificateNumber,
        reason,
        ipAddress: getClientIp(req),
        metadata: {
          brand: existingBrand,
          ownerName: existing.ownerName,
          vehicleRegNumber: existing.vehicleRegNumber,
          deletedCanonicalHash: existing.canonicalHash,
          safetyBackupId: safetyBackup.id,
          reservedNumbersRetained: true,
        },
      });

      res.json({
        deleted: true,
        permanent: true,
        safetyBackupId: safetyBackup.id,
        certificateNumber: existing.certificateNumber,
      });
      return;
    }

    // Default: Archive (SOFT_DELETED — permanently stored in Firestore archive, restorable anytime, never auto-deleted)
    const softDeletedBase: Omit<CertificateRecord, 'canonicalHash'> = {
      ...existing,
      status: 'SOFT_DELETED',
      deletedAt: now,
      deletedBy: req.session!.username,
      deleteReason: reason,
      updatedAt: now,
    };
    const updated: CertificateRecord = {
      ...softDeletedBase,
      canonicalHash: computeCanonicalHash(softDeletedBase),
    };

    await store.saveCertificate(updated);
    try {
      await store.appendCertificateVersion({
        id: `${updated.id}_archive_${generateRecordId('ver')}`,
        certificateId: updated.id,
        certificateNumber: updated.certificateNumber,
        brand: existingBrand,
        version: updated.version,
        recordedAt: now,
        actor: req.session!.username,
        actorRole: req.session!.role,
        event: 'ARCHIVED',
        reason,
        changedFields: ['status'],
        previousCanonicalHash: existing.canonicalHash,
        canonicalHash: updated.canonicalHash,
        data: extractCertificateCoreFields(updated),
      });
    } catch {
      // non-fatal
    }
    await store.addAuditLog({
      id: generateRecordId('aud'),
      timestamp: now,
      actor: req.session!.username,
      actorRole: req.session!.role,
      action: 'CERTIFICATE_SOFT_DELETED',
      certificateId: updated.id,
      certificateNumber: updated.certificateNumber,
      reason,
      ipAddress: getClientIp(req),
      metadata: {
        brand: existingBrand,
        archived: true,
        permanent: false,
        reservedNumbersRetained: true,
      },
    });

    res.json({ deleted: true, archived: true, permanent: false, certificate: updated });
  });

  router.post('/admin/certificates/:id/restore', requireMainAdmin, async (req: AuthedRequest, res) => {
    const store = getStore();
    const id = sanitizeText(req.params.id, 100);
    const body = (req.body ?? {}) as Record<string, unknown>;
    const protectedPassword = typeof body.protectedPassword === 'string' ? body.protectedPassword : '';
    const reason = sanitizeText(body.reason, 300);

    if (!reason || reason.length < 5) {
      res.status(400).json({ error: 'A restoration reason (at least 5 characters) is required.' });
      return;
    }

    const authorized = await verifyProtectedPassword(protectedPassword, 'edit');
    if (!authorized) {
      res.status(403).json({ error: 'Invalid protected-action authorization password.' });
      return;
    }

    const existing = await store.getCertificateById(id);
    if (!existing) {
      res.status(404).json({ error: 'Certificate not found.' });
      return;
    }

    const now = new Date().toISOString();
    const restoredBase: Omit<CertificateRecord, 'canonicalHash'> = {
      ...existing,
      status: existing.cancelledAt ? 'CANCELLED' : 'ACTIVE',
      deletedAt: undefined,
      deletedBy: undefined,
      deleteReason: undefined,
      updatedAt: now,
    };
    const updated: CertificateRecord = {
      ...restoredBase,
      canonicalHash: computeCanonicalHash(restoredBase),
    };

    await store.saveCertificate(updated);
    try {
      await store.appendCertificateVersion({
        id: `${updated.id}_restore_${generateRecordId('ver')}`,
        certificateId: updated.id,
        certificateNumber: updated.certificateNumber,
        brand: resolveCertificateBrand(updated),
        version: updated.version,
        recordedAt: now,
        actor: req.session!.username,
        actorRole: req.session!.role,
        event: 'RESTORED',
        reason,
        changedFields: ['status'],
        previousCanonicalHash: existing.canonicalHash,
        canonicalHash: updated.canonicalHash,
        data: extractCertificateCoreFields(updated),
      });
    } catch {
      // non-fatal
    }
    await store.addAuditLog({
      id: generateRecordId('aud'),
      timestamp: now,
      actor: req.session!.username,
      actorRole: req.session!.role,
      action: 'CERTIFICATE_RESTORED',
      certificateId: updated.id,
      certificateNumber: updated.certificateNumber,
      reason,
      ipAddress: getClientIp(req),
    });

    res.json({ certificate: updated });
  });

  // Read-Only Database Integrity & Backup Monitor (Main Core Admin / Owner Only)
  router.get('/admin/integrity-monitor', requireMainAdmin, async (req: AuthedRequest, res) => {
    const store = getStore();
    const report = await runReadOnlyIntegrityAudit(store);
    try {
      await store.addAuditLog({
        id: generateRecordId('aud'),
        timestamp: report.auditedAt,
        actor: req.session!.username,
        actorRole: req.session!.role,
        action: 'INTEGRITY_AUDIT_RUN',
        ipAddress: getClientIp(req),
        metadata: {
          readOnly: true,
          healthy: report.healthy,
          totalCertificates: report.counts.totalCertificates,
          parivahanCertificates: report.counts.parivahanCertificates,
          scrapRouteCertificates: report.counts.scrapRouteCertificates,
          integrityMismatches: report.counts.integrityMismatches,
          discrepancyCount: report.discrepancies.length,
        },
      });
    } catch {
      // non-fatal
    }
    res.json({ report });
  });

  // Owner-Only Full Authoritative Registry JSON Export
  router.get('/admin/export', requireMainAdmin, async (req: AuthedRequest, res) => {
    const store = getStore();
    const [certificates, reserved, settings] = await Promise.all([
      store.getAllCertificates(),
      store.getAllReservedNumbers(),
      store.getSettings(),
    ]);
    const exportedAt = new Date().toISOString();
    const payload = {
      schemaVersion: 2,
      exportedAt,
      exportedBy: req.session!.username,
      storageMode: store.mode,
      counts: {
        totalCertificates: certificates.length,
        parivahanCertificates: certificates.filter((c) => resolveCertificateBrand(c) === 'parivahan')
          .length,
        scrapRouteCertificates: certificates.filter(
          (c) => resolveCertificateBrand(c) === 'scrap_route'
        ).length,
        reservedCertNumbers: reserved.certNumbers.length,
        reservedRegNumbers: reserved.regNumbers.length,
      },
      certificates,
      reservedCertNumbers: reserved.certNumbers,
      reservedRegNumbers: reserved.regNumbers,
      settings,
    };
    const json = JSON.stringify(payload, null, 2);
    const sha256 = computeSha256(json);
    await store.addAuditLog({
      id: generateRecordId('aud'),
      timestamp: exportedAt,
      actor: req.session!.username,
      actorRole: req.session!.role,
      action: 'REGISTRY_EXPORTED',
      ipAddress: getClientIp(req),
      metadata: {
        certificateCount: certificates.length,
        sha256Checksum: sha256,
      },
    });
    res.setHeader('Content-Type', 'application/json; charset=utf-8');
    res.setHeader(
      'Content-Disposition',
      `attachment; filename="certificate_registry_export_${exportedAt.slice(0, 10)}.json"`
    );
    res.setHeader('X-Export-SHA256', sha256);
    res.send(json);
  });

  // Audit Logs
  router.get('/admin/audit-logs', requireMainAdmin, async (_req, res) => {
    const logs = await getStore().getAuditLogs(250);
    res.json({ logs });
  });

  // Backups & Disaster Recovery
  router.get('/admin/backups', requireMainAdmin, async (_req, res) => {
    const backups = await getStore().listBackups();
    res.json({ backups });
  });

  router.post('/admin/backups/create', requireMainAdmin, async (req: AuthedRequest, res) => {
    const store = getStore();
    try {
      const snapshot = await store.createBackup(req.session!.username, 'MANUAL');
      await store.addAuditLog({
        id: generateRecordId('aud'),
        timestamp: snapshot.createdAt,
        actor: req.session!.username,
        actorRole: req.session!.role,
        action: 'BACKUP_CREATED',
        ipAddress: getClientIp(req),
        metadata: {
          backupId: snapshot.id,
          certificateCount: snapshot.certificateCount,
          verified: snapshot.verified,
          sha256Checksum: snapshot.sha256Checksum,
        },
      });
      res.status(201).json({ backup: snapshot });
    } catch (err) {
      const msg = err instanceof Error ? err.message : 'Manual backup failed';
      await store.addAuditLog({
        id: generateRecordId('aud'),
        timestamp: new Date().toISOString(),
        actor: req.session!.username,
        actorRole: req.session!.role,
        action: 'BACKUP_FAILED',
        ipAddress: getClientIp(req),
        reason: msg,
        metadata: { trigger: 'MANUAL' },
      });
      res.status(503).json({
        error: `Backup failed: ${msg}. Previous verified backups have been preserved.`,
      });
    }
  });

  router.get('/admin/backups/:id/download', requireMainAdmin, async (req, res) => {
    const store = getStore();
    const id = sanitizeText(req.params.id, 100);
    const data = await store.getBackupDownload(id);
    res.setHeader('Content-Type', 'application/json; charset=utf-8');
    res.setHeader('Content-Disposition', `attachment; filename="${data.filename}"`);
    res.setHeader('X-Backup-SHA256', data.sha256Checksum);
    res.send(data.payloadJson);
  });

  router.post('/admin/backups/:id/dry-run', requireMainAdmin, async (req: AuthedRequest, res) => {
    const store = getStore();
    const id = sanitizeText(req.params.id, 100);
    const result = await store.dryRunRestoreBackup(id);
    await store.addAuditLog({
      id: generateRecordId('aud'),
      timestamp: new Date().toISOString(),
      actor: req.session!.username,
      actorRole: req.session!.role,
      action: 'BACKUP_DRY_RUN',
      ipAddress: getClientIp(req),
      metadata: { backupId: id, checksumValid: result.checksumValid },
    });
    res.json({ dryRun: result });
  });

  // Isolated Staging Restore Verification (restores into a separate staging database first & audits integrity)
  router.post('/admin/backups/:id/staging-verify', requireMainAdmin, async (req: AuthedRequest, res) => {
    const store = getStore();
    const id = sanitizeText(req.params.id, 100);
    const stagingResult = await verifyBackupInStaging(store, id);
    await store.addAuditLog({
      id: generateRecordId('aud'),
      timestamp: stagingResult.verifiedAt,
      actor: req.session!.username,
      actorRole: req.session!.role,
      action: 'BACKUP_STAGING_VERIFIED',
      ipAddress: getClientIp(req),
      metadata: {
        backupId: id,
        checksumValid: stagingResult.checksumValid,
        stagingRestoredCount: stagingResult.stagingRestoredCount,
        stagingIntegrityHealthy: stagingResult.stagingIntegrityHealthy,
        safeForProductionRecovery: stagingResult.safeForProductionRecovery,
      },
    });
    res.json({ stagingResult });
  });

  router.post('/admin/backups/:id/restore', requireMainAdmin, async (req: AuthedRequest, res) => {
    const store = getStore();
    const id = sanitizeText(req.params.id, 100);
    const body = (req.body ?? {}) as Record<string, unknown>;
    const protectedPassword = typeof body.protectedPassword === 'string' ? body.protectedPassword : '';
    const confirmPhrase = sanitizeText(body.confirmPhrase, 60);

    if (confirmPhrase !== 'CONFIRM RESTORE') {
      res.status(400).json({ error: 'Type exact phrase CONFIRM RESTORE to execute restore.' });
      return;
    }

    const authorized = await verifyProtectedPassword(protectedPassword, 'delete');
    if (!authorized) {
      res.status(403).json({ error: 'Invalid protected authorization password.' });
      return;
    }

    // Automatically verify backup integrity inside an isolated staging store BEFORE mutating production
    const stagingCheck = await verifyBackupInStaging(store, id);
    if (!stagingCheck.safeForProductionRecovery) {
      res.status(409).json({
        error:
          'Production restore blocked: isolated staging verification detected checksum or integrity discrepancies. Production database was NOT modified.',
        stagingResult: stagingCheck,
      });
      return;
    }

    const result = await store.restoreBackup(id, req.session!.username);
    await store.addAuditLog({
      id: generateRecordId('aud'),
      timestamp: new Date().toISOString(),
      actor: req.session!.username,
      actorRole: req.session!.role,
      action: 'BACKUP_RESTORED',
      ipAddress: getClientIp(req),
      metadata: {
        backupId: id,
        restoredCount: result.restoredCount,
        safetyBackupId: result.safetyBackupId,
        stagingVerified: true,
      },
    });

    res.json({ success: true, ...result, stagingResult: stagingCheck });
  });

  // Scheduled Cron Backup Route (Protected via CRON_SECRET, verifies integrity & alerts owner on failure)
  router.all('/cron/backup', async (req, res) => {
    const configuredSecret = process.env.CRON_SECRET?.trim();
    if (!configuredSecret) {
      res.status(503).json({ error: 'CRON_SECRET is not configured on this server.' });
      return;
    }
    const authHeader = req.headers.authorization || '';
    const provided = authHeader.startsWith('Bearer ') ? authHeader.slice(7).trim() : '';
    if (!provided || !timingSafeStringEqual(provided, configuredSecret)) {
      res.status(401).json({ error: 'Unauthorized cron trigger.' });
      return;
    }
    const store = getStore();
    try {
      const snapshot = await store.createBackup('cron-scheduler', 'SCHEDULED');
      await store.addAuditLog({
        id: generateRecordId('aud'),
        timestamp: snapshot.createdAt,
        actor: 'cron-scheduler',
        actorRole: 'system',
        action: 'BACKUP_CREATED',
        metadata: {
          trigger: 'SCHEDULED',
          backupId: snapshot.id,
          certificateCount: snapshot.certificateCount,
          verified: snapshot.verified,
          sha256Checksum: snapshot.sha256Checksum,
        },
      });
      res.json({ success: true, backup: snapshot });
    } catch (err) {
      const msg = err instanceof Error ? err.message : 'Scheduled backup failed';
      try {
        await store.addAuditLog({
          id: generateRecordId('aud'),
          timestamp: new Date().toISOString(),
          actor: 'cron-scheduler',
          actorRole: 'system',
          action: 'BACKUP_FAILED',
          reason: msg,
          metadata: { trigger: 'SCHEDULED' },
        });
        await store.addSystemError({
          id: generateRecordId('err'),
          timestamp: new Date().toISOString(),
          route: '/api/cron/backup',
          method: req.method,
          code: 'BACKUP_FAILED',
          message: `Scheduled daily backup failed (previous good backups preserved): ${msg}`,
        });
      } catch {
        // avoid cascading failure
      }
      res.status(503).json({
        success: false,
        error: `Scheduled backup failed: ${msg}. Previous verified backups remain preserved.`,
      });
    }
  });

  // Settings & Password Rotation
  router.get('/admin/settings', requireMainAdmin, async (_req, res) => {
    const store = getStore();
    const [settings, credRes] = await Promise.all([
      store.getSettings(),
      resolveAuthoritativeCredentials(store),
    ]);
    const creds = credRes.ok ? credRes.creds : null;
    const envUsername = normalizeEnvCredentialValue(process.env.ADMIN_USERNAME);
    const staleMakerEnvIgnored = Boolean(
      creds &&
        (normalizeEnvCredentialValue(process.env.ADMIN_PASSWORD) ||
          normalizeEnvCredentialValue(process.env.MAIN_ADMIN_PASSWORD) ||
          (envUsername && envUsername.toLowerCase() !== creds.makerUsername.toLowerCase()))
    );
    res.json({
      settings,
      envManagedCredentials: false,
      makerPasswordEnvManaged: false,
      makerAuthSource: creds ? 'firestore' : hasEnvCredentialsConfigured() ? 'env_bootstrap_pending' : 'unconfigured',
      staleMakerEnvIgnored,
      makerUsername:
        creds?.makerUsername ||
        envUsername ||
        (hasAnyEnvPasswordConfigured() ? DEFAULT_MAKER_USERNAME : ''),
      driveEnvConfigured: Boolean(
        process.env.GOOGLE_DRIVE_CLIENT_EMAIL?.trim() &&
          process.env.GOOGLE_DRIVE_PRIVATE_KEY?.trim()
      ),
      storageMode: store.mode,
      firestoreProjectId: store.projectId,
      firestoreDatabaseId: store.databaseId,
    });
  });

  router.put('/admin/settings', requireMainAdmin, async (req: AuthedRequest, res) => {
    const store = getStore();
    const current = await store.getSettings();
    const body = (req.body ?? {}) as Record<string, unknown>;
    const now = new Date().toISOString();

    const retention = Number(body.backupRetentionDays ?? current.backupRetentionDays);
    const updated: SystemSettings = {
      facilityName: sanitizeText(body.facilityName, 140) || current.facilityName,
      facilityRvsfCode: sanitizeText(body.facilityRvsfCode, 60) || current.facilityRvsfCode,
      facilityAddress: sanitizeText(body.facilityAddress, 250) || current.facilityAddress,
      facilityPhone: sanitizeText(body.facilityPhone, 40) || current.facilityPhone,
      facilityEmail: sanitizeText(body.facilityEmail, 120) || current.facilityEmail,
      authorizedSignatory: sanitizeText(body.authorizedSignatory, 100) || current.authorizedSignatory,
      signatoryDesignation: sanitizeText(body.signatoryDesignation, 100) || current.signatoryDesignation,
      publicDomain: sanitizeText(body.publicDomain, 160),
      backupRetentionDays: Number.isFinite(retention) && retention >= 7 && retention <= 3650 ? Math.round(retention) : 90,
      driveSyncEnabled: Boolean(body.driveSyncEnabled),
      driveFolderId: sanitizeText(body.driveFolderId, 160),
      updatedAt: now,
      updatedBy: req.session!.username,
    };

    await store.saveSettings(updated);
    await store.addAuditLog({
      id: generateRecordId('aud'),
      timestamp: now,
      actor: req.session!.username,
      actorRole: req.session!.role,
      action: 'SETTINGS_UPDATED',
      ipAddress: getClientIp(req),
    });

    res.json({ settings: updated });
  });

  // Password rotation + immediate global session invalidation (Firestore authoritative for all roles)
  router.post('/admin/rotate-passwords', requireMainAdmin, async (req: AuthedRequest, res) => {
    const store = getStore();
    const credRes = await resolveAuthoritativeCredentials(store);
    if (!credRes.ok || !credRes.creds) {
      res.status(400).json({ error: 'Stored credentials not found.' });
      return;
    }
    const creds = credRes.creds;

    const body = (req.body ?? {}) as Record<string, unknown>;
    const currentMainPassword = typeof body.currentMainPassword === 'string' ? body.currentMainPassword : '';
    if (!verifyPassword(currentMainPassword, creds.mainAdminPasswordHash)) {
      res.status(403).json({ error: 'Current Main Core Admin password is incorrect.' });
      return;
    }

    const nextMakerUsername = sanitizeText(body.makerUsername, 60) || creds.makerUsername;
    const newMakerPassword = typeof body.newMakerPassword === 'string' ? body.newMakerPassword : '';
    const newMainAdminPassword = typeof body.newMainAdminPassword === 'string' ? body.newMainAdminPassword : '';
    const newProtectedPassword = typeof body.newProtectedPassword === 'string' ? body.newProtectedPassword : '';

    if (
      (newMakerPassword && newMakerPassword.length < 8) ||
      (newMainAdminPassword && newMainAdminPassword.length < 8) ||
      (newProtectedPassword && newProtectedPassword.length < 8)
    ) {
      res.status(400).json({ error: 'Any new password must be at least 8 characters long.' });
      return;
    }

    const nextMakerHash = newMakerPassword ? hashPassword(newMakerPassword) : creds.makerPasswordHash;
    const nextMainHash = newMainAdminPassword ? hashPassword(newMainAdminPassword) : creds.mainAdminPasswordHash;
    const nextProtectedHash = newProtectedPassword ? hashPassword(newProtectedPassword) : creds.protectedPasswordHash;

    if (
      (newMakerPassword && !verifyPassword(newMakerPassword, nextMakerHash)) ||
      (newMainAdminPassword && !verifyPassword(newMainAdminPassword, nextMainHash)) ||
      (newProtectedPassword && !verifyPassword(newProtectedPassword, nextProtectedHash))
    ) {
      res.status(500).json({ error: 'Internal password hash self-check failed. No changes were written.' });
      return;
    }

    const now = new Date().toISOString();
    const nextVersion = creds.sessionVersion + 1;
    const updatedCreds: StoredCredentials = {
      ...creds,
      makerUsername: nextMakerUsername,
      makerPasswordHash: nextMakerHash,
      mainAdminPasswordHash: nextMainHash,
      protectedPasswordHash: nextProtectedHash,
      deletePasswordHash: newProtectedPassword ? nextProtectedHash : creds.deletePasswordHash,
      sessionVersion: nextVersion,
      updatedAt: now,
    };

    await store.saveCredentials(updatedCreds);
    clearAllAuthFailures();

    // Issue fresh server-side session on new sessionVersion so current admin stays signed in while all prior sessions terminate
    const { token, session } = await issueServerSession(store, res, {
      username: 'Main Core Admin',
      role: 'main_admin',
      sessionVersion: nextVersion,
    });

    await store.addAuditLog({
      id: generateRecordId('aud'),
      timestamp: now,
      actor: req.session!.username,
      actorRole: req.session!.role,
      action: 'PASSWORD_ROTATED',
      ipAddress: getClientIp(req),
      reason: 'Rotated server-side scrypt credentials in Firestore and incremented sessionVersion',
      metadata: { newSessionVersion: nextVersion, authSource: 'firestore' },
    });

    res.json({
      success: true,
      session,
      token,
      message: 'Credentials rotated in Firestore. All previous Maker and Admin sessions have been invalidated.',
    });
  });

  // Dedicated Maker-Only Password Rotation (Firestore is authoritative; updates ONLY makerPasswordHash, preserves username & Main Core Admin)
  router.post('/admin/rotate-maker-password', requireMainAdmin, async (req: AuthedRequest, res) => {
    const store = getStore();
    const credRes = await resolveAuthoritativeCredentials(store);
    if (!credRes.ok) {
      logAuthDiagnostic({
        role: 'main_admin',
        code: credRes.code,
        source: 'firestore',
        ip: getClientIp(req),
        detail: credRes.detail,
      });
      res.status(credRes.code === 'FIREBASE_CONNECTION_FAILURE' ? 503 : 500).json({
        error: 'Unable to read stored credentials from Firestore.',
      });
      return;
    }

    const creds = credRes.creds;
    if (!creds) {
      res.status(404).json({ error: 'Stored primary_credentials document not found.' });
      return;
    }

    const body = (req.body ?? {}) as Record<string, unknown>;
    const currentMainPassword = typeof body.currentMainPassword === 'string' ? body.currentMainPassword : '';
    const newMakerPassword = typeof body.newMakerPassword === 'string' ? body.newMakerPassword : '';

    if (!verifyPassword(currentMainPassword, creds.mainAdminPasswordHash)) {
      res.status(403).json({ error: 'Current Main Core Admin password is incorrect.' });
      return;
    }

    if (newMakerPassword.length < 8) {
      res.status(400).json({ error: 'New Maker password must be at least 8 characters long.' });
      return;
    }

    const nextHash = hashPassword(newMakerPassword);
    const selfCheck = validateScryptHashFormat(nextHash);
    if (!selfCheck.valid || !verifyPassword(newMakerPassword, nextHash)) {
      res.status(500).json({ error: 'Internal password hash self-check failed. No changes were written.' });
      return;
    }

    const now = new Date().toISOString();
    const nextVersion = creds.sessionVersion + 1;
    const updatedCreds: StoredCredentials = {
      ...creds,
      // Explicitly update ONLY makerPasswordHash, sessionVersion, and updatedAt
      makerPasswordHash: nextHash,
      sessionVersion: nextVersion,
      updatedAt: now,
    };

    await store.saveCredentials(updatedCreds);

    // Read back from Firestore to verify persisted hash integrity before returning success
    const reloaded = await store.getCredentials();
    if (!reloaded || !verifyPassword(newMakerPassword, reloaded.makerPasswordHash)) {
      res.status(500).json({ error: 'Post-write credential verification failed. Please retry.' });
      return;
    }

    clearAllAuthFailures();

    const { token, session } = await issueServerSession(store, res, {
      username: 'Main Core Admin',
      role: 'main_admin',
      sessionVersion: nextVersion,
    });

    await store.addAuditLog({
      id: generateRecordId('aud'),
      timestamp: now,
      actor: req.session!.username,
      actorRole: req.session!.role,
      action: 'PASSWORD_ROTATED',
      ipAddress: getClientIp(req),
      reason: 'Rotated Maker password hash only in Firestore (username and Main Core Admin password unchanged)',
      metadata: { scope: 'maker_only', authSource: 'firestore', newSessionVersion: nextVersion },
    });

    res.json({
      success: true,
      session,
      token,
      makerUsername: reloaded.makerUsername,
      message: 'Maker password updated in Firestore with a new salted scrypt hash. Previous sessions have been invalidated.',
    });
  });

  // Platform Health, Drive Sync Logs & Retry
  router.get('/admin/health', requireMainAdmin, async (_req, res) => {
    const store = getStore();
    const [probe, errors, driveLogs, reserved] = await Promise.all([
      store.ping(),
      store.getSystemErrors(50),
      store.getDriveSyncLogs(50),
      store.getReservedCounts(),
    ]);

    res.json({
      status: probe.ok ? 'healthy' : 'degraded',
      storageMode: store.mode,
      firestoreConnected: store.mode === 'firestore' ? probe.ok : false,
      storageLatencyMs: probe.latencyMs,
      storageMessage: probe.message,
      firestoreProjectId: store.projectId,
      firestoreDatabaseId: store.databaseId,
      nodeVersion: process.version,
      uptimeSeconds: Math.round(process.uptime()),
      reservedCertNumbers: reserved.certCount,
      reservedRegNumbers: reserved.regCount,
      driveConfigured: isDriveConfigured(),
      recentErrors: errors,
      driveLogs,
    });
  });

  router.post('/admin/drive-sync/:id/retry', requireMainAdmin, async (req, res) => {
    const store = getStore();
    const id = sanitizeText(req.params.id, 100);
    const cert = await store.getCertificateById(id);
    if (!cert) {
      res.status(404).json({ error: 'Certificate not found.' });
      return;
    }
    const settings = await store.getSettings();
    if (!settings.driveSyncEnabled || !isDriveConfigured(settings.driveFolderId)) {
      res.status(400).json({
        error: 'Google Drive integration is not enabled or service account environment variables are not configured.',
      });
      return;
    }
    void syncCertificateToDriveInBackground(store, cert, 2);
    res.json({ queued: true, certificateNumber: cert.certificateNumber });
  });

  app.use('/api', router);

  // Centralized API Error Handler
  app.use(async (err: unknown, req: Request, res: Response, _next: NextFunction) => {
    const errObj = err as NodeJS.ErrnoException;
    if (errObj?.code === 'FIRESTORE_UNCONFIGURED') {
      res.status(503).json({ error: errObj.message });
      return;
    }
    const message = err instanceof Error ? err.message : 'Internal server error';
    try {
      await getStore().addSystemError({
        id: generateRecordId('err'),
        timestamp: new Date().toISOString(),
        route: req.originalUrl,
        method: req.method,
        message,
      });
    } catch {
      // avoid cascading failure during error reporting
    }
    res.status(500).json({ error: 'An unexpected server error occurred. Please retry.' });
  });

  return app;
}
