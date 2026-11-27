import crypto from 'node:crypto';
import type { CertificateRecord, SessionInfo, UserRole } from '../shared/types.js';
import { maskVehicleIdNumber } from '../shared/vehicleData.js';

const SCRYPT_KEYLEN = 64;
const SCRYPT_PARAMS = { N: 16384, r: 8, p: 1 };

// Ephemeral fallback only when ADMIN_SESSION_SECRET is not provided in process.env
const ephemeralFallbackSecret = crypto.randomBytes(32).toString('hex');

function getSessionSecret(): Buffer {
  const configured = process.env.ADMIN_SESSION_SECRET?.trim();
  const baseSecret = configured && configured.length >= 16 ? configured : ephemeralFallbackSecret;
  // Bind signing key to ADMIN_SESSION_SECRET and MAIN_ADMIN_PASSWORD (when env-managed).
  // Maker password rotations invalidate all prior sessions globally via Firestore sessionVersion.
  return crypto
    .createHash('sha256')
    .update(baseSecret)
    .update('|')
    .update(process.env.MAIN_ADMIN_PASSWORD?.trim() || '')
    .digest();
}

export type PasswordHashValidationResult =
  | { valid: true; salt: string; keyHex: string }
  | { valid: false; reason: string };

export function validateScryptHashFormat(storedHash: unknown): PasswordHashValidationResult {
  if (typeof storedHash !== 'string' || storedHash.length === 0) {
    return { valid: false, reason: 'hash_missing_or_empty' };
  }
  if (storedHash !== storedHash.trim()) {
    return { valid: false, reason: 'hash_has_leading_or_trailing_whitespace' };
  }
  const parts = storedHash.split('$');
  if (parts.length !== 3) {
    return { valid: false, reason: `invalid_segment_count_${parts.length}` };
  }
  const [algorithm, salt, keyHex] = parts;
  if (algorithm !== 'scrypt') {
    return { valid: false, reason: 'unsupported_algorithm_prefix' };
  }
  if (!salt || salt.length < 16 || /\s/.test(salt)) {
    return { valid: false, reason: 'invalid_salt_format' };
  }
  if (!keyHex || keyHex.length !== SCRYPT_KEYLEN * 2 || !/^[0-9a-fA-F]+$/.test(keyHex)) {
    return { valid: false, reason: 'invalid_derived_key_hex_format' };
  }
  return { valid: true, salt, keyHex };
}

export function hashPassword(plainPassword: string): string {
  const salt = crypto.randomBytes(16).toString('hex');
  const derived = crypto.scryptSync(plainPassword, salt, SCRYPT_KEYLEN, SCRYPT_PARAMS);
  return `scrypt$${salt}$${derived.toString('hex')}`;
}

export function verifyPassword(plainPassword: string, storedHash: string): boolean {
  if (!plainPassword || !storedHash) return false;
  const parsed = validateScryptHashFormat(storedHash);
  if (!parsed.valid) return false;

  try {
    const derived = crypto.scryptSync(plainPassword, parsed.salt, SCRYPT_KEYLEN, SCRYPT_PARAMS);
    const expected = Buffer.from(parsed.keyHex, 'hex');
    if (derived.length !== expected.length) return false;
    return crypto.timingSafeEqual(derived, expected);
  } catch {
    return false;
  }
}

export function timingSafeStringEqual(a: string, b: string): boolean {
  const bufA = Buffer.from(a, 'utf8');
  const bufB = Buffer.from(b, 'utf8');
  const maxLen = Math.max(bufA.length, bufB.length, 1);
  const paddedA = Buffer.alloc(maxLen);
  const paddedB = Buffer.alloc(maxLen);
  bufA.copy(paddedA);
  bufB.copy(paddedB);
  return crypto.timingSafeEqual(paddedA, paddedB) && bufA.length === bufB.length;
}

export function signSessionToken(payload: {
  username: string;
  role: UserRole;
  sessionVersion: number;
  ttlSeconds?: number;
}): { token: string; session: SessionInfo } {
  const nowSec = Math.floor(Date.now() / 1000);
  const defaultTtl = payload.role === 'main_admin' ? 2 * 60 * 60 : 4 * 60 * 60;
  const session: SessionInfo = {
    username: payload.username,
    role: payload.role,
    sessionVersion: payload.sessionVersion,
    issuedAt: nowSec * 1000,
    expiresAt: (nowSec + (payload.ttlSeconds ?? defaultTtl)) * 1000,
  };

  const bodyB64 = Buffer.from(JSON.stringify(session), 'utf8').toString('base64url');
  const sig = crypto
    .createHmac('sha256', getSessionSecret())
    .update(bodyB64)
    .digest('base64url');

  return { token: `${bodyB64}.${sig}`, session };
}

export function verifySessionToken(
  token: string,
  expectedSessionVersion: number
): SessionInfo | null {
  if (!token || typeof token !== 'string') return null;
  const dotIdx = token.indexOf('.');
  if (dotIdx <= 0 || dotIdx === token.length - 1) return null;

  const bodyB64 = token.slice(0, dotIdx);
  const sig = token.slice(dotIdx + 1);
  const expectedSig = crypto
    .createHmac('sha256', getSessionSecret())
    .update(bodyB64)
    .digest('base64url');

  if (!timingSafeStringEqual(sig, expectedSig)) return null;

  try {
    const parsed = JSON.parse(Buffer.from(bodyB64, 'base64url').toString('utf8')) as SessionInfo;
    if (!parsed || typeof parsed.expiresAt !== 'number') return null;
    if (Date.now() >= parsed.expiresAt) return null;
    if (parsed.sessionVersion !== expectedSessionVersion) return null;
    if (parsed.role !== 'maker' && parsed.role !== 'main_admin') return null;
    if (!parsed.username || typeof parsed.username !== 'string') return null;
    return parsed;
  } catch {
    return null;
  }
}

export function generateRandomCertificateNumber(issueDate?: string): {
  certificateNumber: string;
  issueYearShort: string;
} {
  let yearNum = new Date().getFullYear();
  if (issueDate && /^\d{4}-\d{2}-\d{2}/.test(issueDate)) {
    const parsedYear = Number(issueDate.slice(0, 4));
    if (parsedYear >= 2020 && parsedYear <= 2099) {
      yearNum = parsedYear;
    }
  }
  const yy = String(yearNum).slice(-2);
  const sevenDigits = crypto.randomInt(1000000, 10000000);
  return {
    certificateNumber: `PS/${yy}/R${sevenDigits}`,
    issueYearShort: yy,
  };
}

export function generateRandomScrappingRegNumber(): string {
  const sixDigits = crypto.randomInt(100000, 1000000);
  return `REG-C${sixDigits}`;
}

export function isValidCertificateNumberFormat(value: string): boolean {
  return /^PS\/\d{2}\/R\d{7}$/.test(value);
}

export function isValidScrappingRegFormat(value: string): boolean {
  return /^REG-C\d{6}$/.test(value);
}

export function generateQrToken(): string {
  return crypto.randomBytes(24).toString('hex');
}

export function generateRecordId(prefix: string): string {
  return `${prefix}_${Date.now().toString(36)}_${crypto.randomBytes(6).toString('hex')}`;
}

export function computeCanonicalHash(
  cert: Pick<
    CertificateRecord,
    | 'certificateNumber'
    | 'scrappingRegNumber'
    | 'status'
    | 'version'
    | 'issueDate'
    | 'handoverDate'
    | 'ownerName'
    | 'vehicleRegNumber'
    | 'make'
    | 'model'
    | 'manufactureYear'
    | 'chassisNumber'
    | 'engineNumber'
    | 'rtoAuthority'
    | 'facilityRvsfCode'
    | 'qrToken'
  >
): string {
  const canonicalPayload = {
    certificateNumber: cert.certificateNumber.trim().toUpperCase(),
    scrappingRegNumber: cert.scrappingRegNumber.trim().toUpperCase(),
    status: cert.status,
    version: cert.version,
    issueDate: cert.issueDate.trim(),
    handoverDate: cert.handoverDate.trim(),
    ownerName: cert.ownerName.trim().toUpperCase(),
    vehicleRegNumber: cert.vehicleRegNumber.trim().toUpperCase(),
    make: cert.make.trim().toUpperCase(),
    model: cert.model.trim().toUpperCase(),
    manufactureYear: Number(cert.manufactureYear),
    chassisNumber: cert.chassisNumber.trim().toUpperCase(),
    engineNumber: cert.engineNumber.trim().toUpperCase(),
    rtoAuthority: (cert.rtoAuthority ?? '').trim().toUpperCase(),
    facilityRvsfCode: cert.facilityRvsfCode.trim().toUpperCase(),
    qrToken: cert.qrToken,
  };

  return crypto
    .createHash('sha256')
    .update(JSON.stringify(canonicalPayload))
    .digest('hex');
}

export function computeSha256(data: string): string {
  return crypto.createHash('sha256').update(data, 'utf8').digest('hex');
}

export function maskSensitiveNumber(value: string): string {
  return maskVehicleIdNumber(value);
}
