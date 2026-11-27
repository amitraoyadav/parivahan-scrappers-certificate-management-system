import express, { type NextFunction, type Request, type Response } from 'express';
import cookieParser from 'cookie-parser';
import type {
  AuthStatusResponse,
  CertificateRecord,
  CreateCertificateInput,
  DashboardStats,
  IdProofType,
  PublicVerificationResult,
  SessionInfo,
  SystemSettings,
  UserRole,
} from '../shared/types.js';
import {
  computeCanonicalHash,
  generateQrToken,
  generateRandomCertificateNumber,
  generateRandomScrappingRegNumber,
  generateRecordId,
  hashPassword,
  isValidCertificateNumberFormat,
  isValidScrappingRegFormat,
  maskSensitiveNumber,
  signSessionToken,
  timingSafeStringEqual,
  validateScryptHashFormat,
  verifyPassword,
  verifySessionToken,
} from './crypto.js';
import { isDriveConfigured, syncCertificateToDriveInBackground } from './driveSync.js';
import {
  checkRateLimit,
  clearAllAuthFailures,
  clearAuthFailures,
  recordAuthFailure,
} from './rateLimit.js';
import { getStore, type RegistryStore, type StoredCredentials } from './store.js';

const SESSION_COOKIE_NAME = 'ps_session';

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

function sanitizeDiagnosticDetail(detail: string | undefined): string | undefined {
  if (!detail) return undefined;
  // Strip any accidental key/hash-like fragments before logging
  return detail
    .replace(/scrypt\$[^\s"'`]+/gi, '[REDACTED_HASH]')
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

async function getSessionVersion(): Promise<number> {
  const store = getStore();
  const creds = await store.getCredentials();
  return creds?.sessionVersion ?? 1;
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

function extractSessionToken(req: Request): string | null {
  const authHeader = req.headers.authorization;
  if (typeof authHeader === 'string' && authHeader.startsWith('Bearer ')) {
    const token = authHeader.slice(7).trim();
    if (token) return token;
  }
  const cookieToken = req.cookies?.[SESSION_COOKIE_NAME];
  if (typeof cookieToken === 'string' && cookieToken.trim()) {
    return cookieToken.trim();
  }
  return null;
}

async function resolveSession(req: Request): Promise<SessionInfo | null> {
  const token = extractSessionToken(req);
  if (!token) return null;
  const version = await getSessionVersion();
  return verifySessionToken(token, version);
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
  const session = await resolveSession(req);
  if (!session) {
    res.status(401).json({ error: 'Authentication required. Please sign in.' });
    return;
  }
  req.session = session;
  next();
}

async function requireMainAdmin(req: AuthedRequest, res: Response, next: NextFunction): Promise<void> {
  const session = await resolveSession(req);
  if (!session) {
    res.status(401).json({ error: 'Authentication required.' });
    return;
  }
  if (session.role !== 'main_admin') {
    res.status(403).json({
      error: 'Forbidden: Main Core Admin authorization is required for this resource.',
    });
    return;
  }
  req.session = session;
  next();
}

function sanitizeText(val: unknown, maxLen: number): string {
  if (typeof val !== 'string') return '';
  return val.trim().replace(/\s+/g, ' ').slice(0, maxLen);
}

function validateCertificatePayload(
  body: unknown
): { ok: true; data: CreateCertificateInput } | { ok: false; error: string } {
  if (!body || typeof body !== 'object') {
    return { ok: false, error: 'Invalid request payload.' };
  }
  const b = body as Record<string, unknown>;

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
  if (certificateNumber && !isValidCertificateNumberFormat(certificateNumber)) {
    return { ok: false, error: 'Invalid certificate number format. Expected PS/YY/R[7 digits].' };
  }
  if (scrappingRegNumber && !isValidScrappingRegFormat(scrappingRegNumber)) {
    return { ok: false, error: 'Invalid scrapping registration number format. Expected REG-C[6 digits].' };
  }

  return {
    ok: true,
    data: {
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

async function generateAvailableCandidateNumbers(issueDate?: string): Promise<{
  certificateNumber: string;
  scrappingRegNumber: string;
  issueYearShort: string;
}> {
  const store = getStore();
  for (let attempt = 0; attempt < 25; attempt++) {
    const certGen = generateRandomCertificateNumber(issueDate);
    const regNo = generateRandomScrappingRegNumber();
    const [certTaken, regTaken] = await Promise.all([
      store.isCertNumberReserved(certGen.certificateNumber),
      store.isScrappingRegReserved(regNo),
    ]);
    if (!certTaken && !regTaken) {
      return {
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
      const signed = signSessionToken({
        username: expectedUsername,
        role: 'maker',
        sessionVersion,
      });
      token = signed.token;
      session = signed.session;
      setSessionCookie(res, token, session.expiresAt - session.issuedAt);
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
        metadata: { authSource: 'firestore' },
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
      const signed = signSessionToken({
        username: 'Main Core Admin',
        role: 'main_admin',
        sessionVersion,
      });
      token = signed.token;
      session = signed.session;
      setSessionCookie(res, token, session.expiresAt - session.issuedAt);
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
    const session = await resolveSession(req);
    clearSessionCookie(res);
    if (session) {
      await getStore().addAuditLog({
        id: generateRecordId('aud'),
        timestamp: new Date().toISOString(),
        actor: session.username,
        actorRole: session.role,
        action: 'LOGOUT',
        ipAddress: getClientIp(req),
      });
    }
    res.json({ success: true });
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

    const result: PublicVerificationResult = {
      found: true,
      verified: isVerified,
      integrityMatch,
      tokenMatch,
      status: cert.status,
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
  router.get('/certificates/candidate-numbers', requireAuth, async (req, res) => {
    const issueDate = sanitizeText(req.query.issueDate, 20);
    const candidate = await generateAvailableCandidateNumbers(issueDate || undefined);
    res.json(candidate);
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

    const validated = validateCertificatePayload({
      ...existing,
      ...rawUpdates,
      // Always preserve immutable identifiers and existing rtoAuthority (no longer edited)
      certificateNumber: existing.certificateNumber,
      scrappingRegNumber: existing.scrappingRegNumber,
      rtoAuthority: existing.rtoAuthority ?? '',
    });
    if (!validated.ok) {
      res.status(400).json({ error: validated.error });
      return;
    }

    const now = new Date().toISOString();
    const snapshot = {
      version: existing.version,
      editedAt: now,
      editedBy: req.session!.username,
      reason,
      previousCanonicalHash: existing.canonicalHash,
      previousData: {
        ownerName: existing.ownerName,
        ownerAddress: existing.ownerAddress,
        idProofType: existing.idProofType,
        idProofNumber: existing.idProofNumber,
        vehicleRegNumber: existing.vehicleRegNumber,
        make: existing.make,
        model: existing.model,
        manufactureYear: existing.manufactureYear,
        chassisNumber: existing.chassisNumber,
        engineNumber: existing.engineNumber,
        unhideChassisEngine: existing.unhideChassisEngine,
        rtoAuthority: existing.rtoAuthority ?? '',
        issueDate: existing.issueDate,
        handoverDate: existing.handoverDate,
        facilityName: existing.facilityName,
        facilityAddress: existing.facilityAddress,
        remarks: existing.remarks,
      },
    };

    const updates = validated.data;
    const nextCertBase: Omit<CertificateRecord, 'canonicalHash'> = {
      ...existing,
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
      versionHistory: [snapshot, ...(existing.versionHistory ?? [])],
    };

    const updated: CertificateRecord = {
      ...nextCertBase,
      canonicalHash: computeCanonicalHash(nextCertBase),
    };

    await store.saveCertificate(updated);
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
        previousVersion: existing.version,
        newVersion: updated.version,
      },
    });

    res.json({ certificate: updated });
  });

  // Authenticated Maker Delete (soft-delete with active session, no password re-entry; preserves reserved numbers & audit log)
  router.delete('/certificates/:id', requireAuth, async (req: AuthedRequest, res) => {
    const store = getStore();
    const id = sanitizeText(req.params.id, 100);
    const existing = await store.getCertificateById(id);
    if (!existing) {
      res.status(404).json({ error: 'Certificate not found.' });
      return;
    }
    if (existing.status === 'SOFT_DELETED') {
      res.status(400).json({ error: 'Certificate has already been deleted.' });
      return;
    }

    if (req.session!.role === 'maker') {
      const recentFive = await store.getRecentActiveCertificates(5);
      const isAllowed = recentFive.some((c) => c.id === existing.id);
      if (!isAllowed) {
        res.status(403).json({
          error: 'Forbidden: Certificate Maker deletion is restricted to the latest five active certificates.',
        });
        return;
      }
    }

    const body = (req.body ?? {}) as Record<string, unknown>;
    const reason =
      sanitizeText(body.reason, 300) ||
      `Deleted by authenticated ${req.session!.role === 'main_admin' ? 'Main Core Admin' : 'Certificate Maker'}`;

    const now = new Date().toISOString();
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
    });

    res.json({
      success: true,
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
    const validated = validateCertificatePayload(req.body);
    if (!validated.ok) {
      res.status(400).json({ error: validated.error });
      return;
    }

    const headerKey = sanitizeText(req.headers['idempotency-key'], 128);
    const bodyKey = sanitizeText((req.body as Record<string, unknown>)?.idempotencyKey, 128);
    const idempotencyKey = headerKey || bodyKey || generateRecordId('idemp');

    // Fast path: return existing certificate if this exact submission was already committed
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

    const settings = await store.getSettings();
    const input = validated.data;
    const now = new Date().toISOString();
    const driveReady = settings.driveSyncEnabled && isDriveConfigured(settings.driveFolderId);

    // Retry up to 8 times if a random number collides concurrently
    let candidateCertNo = input.certificateNumber;
    let candidateRegNo = input.scrappingRegNumber;

    for (let attempt = 0; attempt < 8; attempt++) {
      if (!candidateCertNo || !candidateRegNo || attempt > 0) {
        const fresh = await generateAvailableCandidateNumbers(input.issueDate);
        candidateCertNo = fresh.certificateNumber;
        candidateRegNo = fresh.scrappingRegNumber;
      }

      const certId = generateRecordId('cert');
      const qrToken = generateQrToken();
      const baseCert: Omit<CertificateRecord, 'canonicalHash'> = {
        id: certId,
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
        facilityName: settings.facilityName,
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

      const certificate: CertificateRecord = {
        ...baseCert,
        canonicalHash: computeCanonicalHash(baseCert),
      };

      try {
        const committed = await store.createCertificateAtomic({
          certificate,
          idempotencyKey,
          auditLog: {
            id: generateRecordId('aud'),
            timestamp: now,
            actor: req.session!.username,
            actorRole: req.session!.role,
            action: 'CERTIFICATE_CREATED',
            certificateId: certificate.id,
            certificateNumber: certificate.certificateNumber,
            ipAddress: getClientIp(req),
            metadata: {
              scrappingRegNumber: certificate.scrappingRegNumber,
              vehicleRegNumber: certificate.vehicleRegNumber,
            },
          },
        });

        // Fire-and-forget optional Google Drive sync (never blocks issuance response)
        if (driveReady) {
          void syncCertificateToDriveInBackground(store, committed, 1);
        }

        res.status(201).json({
          certificate: committed,
          idempotentReplay: false,
          persistenceMs: Date.now() - startMs,
        });
        return;
      } catch (err) {
        if ((err as NodeJS.ErrnoException)?.code === 'NUMBER_COLLISION') {
          candidateCertNo = undefined;
          candidateRegNo = undefined;
          continue;
        }
        throw err;
      }
    }

    res.status(503).json({
      error: 'Unable to reserve unique certificate numbers due to high concurrency. Please try again.',
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
    const [certs, reserved, backups] = await Promise.all([
      store.getAllCertificates(),
      store.getReservedCounts(),
      store.listBackups(),
    ]);

    const todayPrefix = new Date().toISOString().slice(0, 10);
    const monthPrefix = new Date().toISOString().slice(0, 7);

    const stats: DashboardStats = {
      totalCertificates: certs.length,
      activeCertificates: certs.filter((c) => c.status === 'ACTIVE').length,
      cancelledCertificates: certs.filter((c) => c.status === 'CANCELLED').length,
      softDeletedCertificates: certs.filter((c) => c.status === 'SOFT_DELETED').length,
      issuedToday: certs.filter((c) => c.createdAt.startsWith(todayPrefix)).length,
      issuedThisMonth: certs.filter((c) => c.createdAt.startsWith(monthPrefix)).length,
      reservedCertNumbers: reserved.certCount,
      reservedRegNumbers: reserved.regCount,
      totalBackups: backups.length,
      lastBackupAt: backups[0]?.createdAt ?? null,
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

    const validated = validateCertificatePayload({
      ...existing,
      ...(body.updates && typeof body.updates === 'object' ? body.updates : {}),
      certificateNumber: existing.certificateNumber,
      scrappingRegNumber: existing.scrappingRegNumber,
    });
    if (!validated.ok) {
      res.status(400).json({ error: validated.error });
      return;
    }

    const now = new Date().toISOString();
    const snapshot = {
      version: existing.version,
      editedAt: now,
      editedBy: req.session!.username,
      reason,
      previousCanonicalHash: existing.canonicalHash,
      previousData: {
        ownerName: existing.ownerName,
        ownerAddress: existing.ownerAddress,
        idProofType: existing.idProofType,
        idProofNumber: existing.idProofNumber,
        vehicleRegNumber: existing.vehicleRegNumber,
        make: existing.make,
        model: existing.model,
        manufactureYear: existing.manufactureYear,
        chassisNumber: existing.chassisNumber,
        engineNumber: existing.engineNumber,
        unhideChassisEngine: existing.unhideChassisEngine,
        rtoAuthority: existing.rtoAuthority,
        issueDate: existing.issueDate,
        handoverDate: existing.handoverDate,
        facilityName: existing.facilityName,
        facilityAddress: existing.facilityAddress,
        remarks: existing.remarks,
      },
    };

    const updates = validated.data;
    const nextCertBase: Omit<CertificateRecord, 'canonicalHash'> = {
      ...existing,
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
      versionHistory: [snapshot, ...(existing.versionHistory ?? [])],
    };

    const updated: CertificateRecord = {
      ...nextCertBase,
      canonicalHash: computeCanonicalHash(nextCertBase),
    };

    await store.saveCertificate(updated);
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
        previousVersion: existing.version,
        newVersion: updated.version,
      },
    });

    res.json({ certificate: updated });
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

  // Protected Delete (Soft Delete by default; Permanent Delete requires explicit phrase + safety backup)
  router.delete('/admin/certificates/:id', requireMainAdmin, async (req: AuthedRequest, res) => {
    const store = getStore();
    const id = sanitizeText(req.params.id, 100);
    const body = (req.body ?? {}) as Record<string, unknown>;
    const deletePassword = typeof body.deletePassword === 'string' ? body.deletePassword : '';
    const reason = sanitizeText(body.reason, 300);
    const permanent = body.permanent === true;
    const confirmPhrase = sanitizeText(body.confirmPhrase, 60);

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

    if (permanent) {
      if (confirmPhrase !== 'PERMANENT DELETE') {
        res.status(400).json({
          error: 'Permanent deletion requires typing exact confirmation phrase: PERMANENT DELETE',
        });
        return;
      }

      // Recovery safeguard: create a verified pre-delete safety snapshot before permanent removal
      const safetyBackup = await store.createBackup(req.session!.username, 'PRE_RESTORE_SAFETY');
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

    // Default: Soft Delete (reversible, hidden from Maker recent list and public verify)
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
    });

    res.json({ deleted: true, permanent: false, certificate: updated });
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
        sha256Checksum: snapshot.sha256Checksum,
      },
    });
    res.status(201).json({ backup: snapshot });
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
      },
    });

    res.json({ success: true, ...result });
  });

  // Scheduled Cron Backup Route (Protected via CRON_SECRET)
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
    const snapshot = await getStore().createBackup('cron-scheduler', 'SCHEDULED');
    res.json({ success: true, backup: snapshot });
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

    // Issue fresh token on new sessionVersion so current admin stays signed in while all prior sessions terminate
    const { token, session } = signSessionToken({
      username: 'Main Core Admin',
      role: 'main_admin',
      sessionVersion: nextVersion,
    });
    setSessionCookie(res, token, session.expiresAt - session.issuedAt);

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

    const { token, session } = signSessionToken({
      username: 'Main Core Admin',
      role: 'main_admin',
      sessionVersion: nextVersion,
    });
    setSessionCookie(res, token, session.expiresAt - session.issuedAt);

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
