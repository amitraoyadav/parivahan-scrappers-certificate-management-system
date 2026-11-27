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
  verifyPassword,
  verifySessionToken,
} from './crypto.js';
import { isDriveConfigured, syncCertificateToDriveInBackground } from './driveSync.js';
import { checkRateLimit, clearAuthFailures, recordAuthFailure } from './rateLimit.js';
import { getStore, type StoredCredentials } from './store.js';

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

const DEFAULT_MAKER_USERNAME = 'pscrappers';

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

function verifyEnvOrHash(plain: string, envValue: string | undefined, storedHash: string | undefined): boolean {
  const normalizedEnv = normalizeEnvCredentialValue(envValue);
  if (normalizedEnv.length > 0) {
    if (normalizedEnv.startsWith('scrypt$')) {
      return verifyPassword(plain, normalizedEnv);
    }
    return timingSafeStringEqual(plain, normalizedEnv);
  }
  if (storedHash) {
    return verifyPassword(plain, storedHash);
  }
  return false;
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
  if (rtoAuthority.length < 2) {
    return { ok: false, error: 'RTO / Registering Authority is required.' };
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
  const creds = await store.getCredentials();
  if (mode === 'delete') {
    const envDel = process.env.ADMIN_DELETE_PASSWORD?.trim() || process.env.ADMIN_PROTECTED_PASSWORD?.trim();
    return verifyEnvOrHash(password, envDel, creds?.deletePasswordHash ?? creds?.protectedPasswordHash);
  }
  const envProt = process.env.ADMIN_PROTECTED_PASSWORD?.trim() || process.env.ADMIN_DELETE_PASSWORD?.trim();
  return verifyEnvOrHash(password, envProt, creds?.protectedPasswordHash ?? creds?.deletePasswordHash);
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

    await store.saveCredentials(creds);
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

  // Certificate Maker Login
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
        error: `Too many failed login attempts. Please wait ${Math.ceil(limit.retryAfterSeconds / 60)} minute(s) before trying again.`,
        retryAfterSeconds: limit.retryAfterSeconds,
      });
      return;
    }

    const creds = await store.getCredentials();
    const envUsername = normalizeEnvCredentialValue(process.env.ADMIN_USERNAME);
    const hasEnvMakerPassword = Boolean(normalizeEnvCredentialValue(process.env.ADMIN_PASSWORD));
    const expectedUsername =
      envUsername ||
      creds?.makerUsername ||
      (hasEnvMakerPassword ? DEFAULT_MAKER_USERNAME : '');
    if (!expectedUsername) {
      res.status(503).json({
        error: 'System credentials are not initialized yet. Complete first-run setup first.',
      });
      return;
    }

    const usernameMatches = timingSafeStringEqual(
      username.toLowerCase(),
      expectedUsername.toLowerCase()
    );
    const passwordMatches = verifyEnvOrHash(
      password,
      process.env.ADMIN_PASSWORD,
      creds?.makerPasswordHash
    );

    if (!usernameMatches || !passwordMatches) {
      const failState = recordAuthFailure(rateKey);
      await store.addAuditLog({
        id: generateRecordId('aud'),
        timestamp: new Date().toISOString(),
        actor: username || 'unknown',
        actorRole: 'maker',
        action: 'LOGIN_FAILED',
        ipAddress: ip,
        reason: 'Invalid Certificate Maker credentials',
      });
      res.status(401).json({
        error: failState.locked
          ? 'Account login temporarily locked due to multiple failed attempts.'
          : `Invalid username or password. (${failState.remainingAttempts} attempt(s) remaining)`,
      });
      return;
    }

    clearAuthFailures(rateKey);
    const sessionVersion = creds?.sessionVersion ?? 1;
    const { token, session } = signSessionToken({
      username: expectedUsername,
      role: 'maker',
      sessionVersion,
    });

    setSessionCookie(res, token, session.expiresAt - session.issuedAt);
    await store.addAuditLog({
      id: generateRecordId('aud'),
      timestamp: new Date().toISOString(),
      actor: expectedUsername,
      actorRole: 'maker',
      action: 'LOGIN_SUCCESS',
      ipAddress: ip,
    });

    res.json({ session, token });
  });

  // Main Core Admin Separate Unlock
  router.post('/auth/admin-unlock', async (req, res) => {
    const store = getStore();
    const ip = getClientIp(req);
    const rateKey = `main_admin:${ip}`;
    const limit = checkRateLimit(rateKey);
    if (!limit.allowed) {
      res.status(429).json({
        error: `Main Core Admin unlock throttled. Try again in ${Math.ceil(limit.retryAfterSeconds / 60)} minute(s).`,
        retryAfterSeconds: limit.retryAfterSeconds,
      });
      return;
    }

    const body = (req.body ?? {}) as Record<string, unknown>;
    const password = typeof body.password === 'string' ? body.password : '';
    const creds = await store.getCredentials();

    if (!process.env.MAIN_ADMIN_PASSWORD?.trim() && !creds?.mainAdminPasswordHash) {
      res.status(503).json({
        error: 'Main Core Admin password is not configured yet. Complete first-run setup or set MAIN_ADMIN_PASSWORD.',
      });
      return;
    }

    const ok = verifyEnvOrHash(
      password,
      process.env.MAIN_ADMIN_PASSWORD,
      creds?.mainAdminPasswordHash
    );

    if (!ok) {
      const failState = recordAuthFailure(rateKey);
      await store.addAuditLog({
        id: generateRecordId('aud'),
        timestamp: new Date().toISOString(),
        actor: 'Main Core Admin',
        actorRole: 'main_admin',
        action: 'ADMIN_UNLOCK_FAILED',
        ipAddress: ip,
        reason: 'Invalid Main Core Admin unlock password',
      });
      res.status(401).json({
        error: failState.locked
          ? 'Main Core Admin unlock temporarily locked due to repeated failed attempts.'
          : `Invalid Main Core Admin password. (${failState.remainingAttempts} attempt(s) remaining)`,
      });
      return;
    }

    clearAuthFailures(rateKey);
    const sessionVersion = creds?.sessionVersion ?? 1;
    const { token, session } = signSessionToken({
      username: 'Main Core Admin',
      role: 'main_admin',
      sessionVersion,
    });

    setSessionCookie(res, token, session.expiresAt - session.issuedAt);
    await store.addAuditLog({
      id: generateRecordId('aud'),
      timestamp: new Date().toISOString(),
      actor: 'Main Core Admin',
      actorRole: 'main_admin',
      action: 'ADMIN_UNLOCK_SUCCESS',
      ipAddress: ip,
    });

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
        rtoAuthority: input.rtoAuthority,
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
      rtoAuthority: updates.rtoAuthority,
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
    const [settings, creds] = await Promise.all([
      store.getSettings(),
      store.getCredentials(),
    ]);
    const envUsername = normalizeEnvCredentialValue(process.env.ADMIN_USERNAME);
    const makerPasswordEnvManaged = Boolean(normalizeEnvCredentialValue(process.env.ADMIN_PASSWORD));
    res.json({
      settings,
      envManagedCredentials: hasEnvCredentialsConfigured(),
      makerPasswordEnvManaged,
      makerUsername:
        envUsername ||
        creds?.makerUsername ||
        (makerPasswordEnvManaged ? DEFAULT_MAKER_USERNAME : ''),
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

  // Password rotation + immediate global session invalidation
  router.post('/admin/rotate-passwords', requireMainAdmin, async (req: AuthedRequest, res) => {
    const store = getStore();
    if (hasEnvCredentialsConfigured()) {
      res.status(400).json({
        error: 'Credentials are controlled by Vercel Environment Variables. Rotate them in Vercel Project Settings and redeploy.',
      });
      return;
    }

    const creds = await store.getCredentials();
    if (!creds) {
      res.status(400).json({ error: 'Stored credentials not found.' });
      return;
    }

    const body = (req.body ?? {}) as Record<string, unknown>;
    const currentMainPassword = typeof body.currentMainPassword === 'string' ? body.currentMainPassword : '';
    if (!verifyEnvOrHash(currentMainPassword, process.env.MAIN_ADMIN_PASSWORD, creds.mainAdminPasswordHash)) {
      res.status(403).json({ error: 'Current Main Core Admin password is incorrect.' });
      return;
    }

    const nextMakerUsername = sanitizeText(body.makerUsername, 60) || creds.makerUsername;
    const newMakerPassword = typeof body.newMakerPassword === 'string' ? body.newMakerPassword : '';
    const newMainAdminPassword = typeof body.newMainAdminPassword === 'string' ? body.newMainAdminPassword : '';
    const newProtectedPassword = typeof body.newProtectedPassword === 'string' ? body.newProtectedPassword : '';

    if (newMakerPassword && normalizeEnvCredentialValue(process.env.ADMIN_PASSWORD)) {
      res.status(400).json({
        error: 'ADMIN_PASSWORD is set in Vercel Environment Variables and overrides Firestore. Update ADMIN_PASSWORD in Vercel Project Settings and redeploy.',
      });
      return;
    }

    if (
      (newMakerPassword && newMakerPassword.length < 8) ||
      (newMainAdminPassword && newMainAdminPassword.length < 8) ||
      (newProtectedPassword && newProtectedPassword.length < 8)
    ) {
      res.status(400).json({ error: 'Any new password must be at least 8 characters long.' });
      return;
    }

    const now = new Date().toISOString();
    const nextVersion = creds.sessionVersion + 1;
    const updatedCreds: StoredCredentials = {
      ...creds,
      makerUsername: nextMakerUsername,
      makerPasswordHash: newMakerPassword ? hashPassword(newMakerPassword) : creds.makerPasswordHash,
      mainAdminPasswordHash: newMainAdminPassword ? hashPassword(newMainAdminPassword) : creds.mainAdminPasswordHash,
      protectedPasswordHash: newProtectedPassword ? hashPassword(newProtectedPassword) : creds.protectedPasswordHash,
      deletePasswordHash: newProtectedPassword ? hashPassword(newProtectedPassword) : creds.deletePasswordHash,
      sessionVersion: nextVersion,
      updatedAt: now,
    };

    await store.saveCredentials(updatedCreds);

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
      reason: 'Rotated server-side scrypt credentials and incremented sessionVersion',
      metadata: { newSessionVersion: nextVersion },
    });

    res.json({
      success: true,
      session,
      token,
      message: 'Credentials rotated. All previous Maker and Admin sessions have been invalidated.',
    });
  });

  // Dedicated Maker-Only Password Rotation (preserves makerUsername & Main Core Admin password untouched)
  router.post('/admin/rotate-maker-password', requireMainAdmin, async (req: AuthedRequest, res) => {
    const store = getStore();
    if (normalizeEnvCredentialValue(process.env.ADMIN_PASSWORD)) {
      res.status(400).json({
        error: 'Maker password is controlled by the ADMIN_PASSWORD Vercel Environment Variable (which overrides Firestore). Update ADMIN_PASSWORD in Vercel Project Settings with a salted scrypt hash and redeploy.',
      });
      return;
    }

    const creds = await store.getCredentials();
    if (!creds) {
      res.status(404).json({ error: 'Stored primary_credentials document not found.' });
      return;
    }

    const body = (req.body ?? {}) as Record<string, unknown>;
    const currentMainPassword = typeof body.currentMainPassword === 'string' ? body.currentMainPassword : '';
    const newMakerPassword = typeof body.newMakerPassword === 'string' ? body.newMakerPassword : '';

    if (!verifyEnvOrHash(currentMainPassword, process.env.MAIN_ADMIN_PASSWORD, creds.mainAdminPasswordHash)) {
      res.status(403).json({ error: 'Current Main Core Admin password is incorrect.' });
      return;
    }

    if (newMakerPassword.length < 8) {
      res.status(400).json({ error: 'New Maker password must be at least 8 characters long.' });
      return;
    }

    const now = new Date().toISOString();
    const nextVersion = creds.sessionVersion + 1;
    const updatedCreds: StoredCredentials = {
      ...creds,
      // Explicitly update ONLY makerPasswordHash, sessionVersion, and updatedAt
      makerPasswordHash: hashPassword(newMakerPassword),
      sessionVersion: nextVersion,
      updatedAt: now,
    };

    await store.saveCredentials(updatedCreds);

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
      reason: 'Rotated Maker password hash only (username and Main Core Admin password unchanged)',
      metadata: { scope: 'maker_only', newSessionVersion: nextVersion },
    });

    res.json({
      success: true,
      session,
      token,
      makerUsername: updatedCreds.makerUsername,
      message: 'Maker password updated with a new salted scrypt hash. Previous sessions have been invalidated.',
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
