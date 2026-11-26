import crypto from 'node:crypto';
import type { CertificateRecord } from '../shared/types.js';
import { generateRecordId } from './crypto.js';
import type { RegistryStore } from './store.js';

export function isDriveConfigured(folderIdOverride?: string): boolean {
  const folderId = folderIdOverride?.trim() || process.env.GOOGLE_DRIVE_FOLDER_ID?.trim();
  const clientEmail = process.env.GOOGLE_DRIVE_CLIENT_EMAIL?.trim();
  const privateKey = process.env.GOOGLE_DRIVE_PRIVATE_KEY?.trim();
  return Boolean(folderId && clientEmail && privateKey);
}

async function getDriveAccessToken(clientEmail: string, privateKey: string): Promise<string> {
  const now = Math.floor(Date.now() / 1000);
  const header = Buffer.from(JSON.stringify({ alg: 'RS256', typ: 'JWT' })).toString('base64url');
  const claim = Buffer.from(
    JSON.stringify({
      iss: clientEmail,
      scope: 'https://www.googleapis.com/auth/drive.file',
      aud: 'https://oauth2.googleapis.com/token',
      iat: now,
      exp: now + 3600,
    })
  ).toString('base64url');

  const unsigned = `${header}.${claim}`;
  const signer = crypto.createSign('RSA-SHA256');
  signer.update(unsigned);
  const sig = signer.sign(privateKey.replace(/\\n/g, '\n'), 'base64url');

  const res = await fetch('https://oauth2.googleapis.com/token', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      grant_type: 'urn:ietf:params:oauth:grant-type:jwt-bearer',
      assertion: `${unsigned}.${sig}`,
    }),
  });
  if (!res.ok) {
    throw new Error(`Drive OAuth2 failed (${res.status}): ${await res.text()}`);
  }
  const data = (await res.json()) as { access_token: string };
  return data.access_token;
}

export async function syncCertificateToDriveInBackground(
  store: RegistryStore,
  cert: CertificateRecord,
  attemptCount = 1
): Promise<void> {
  const settings = await store.getSettings();
  const folderId = settings.driveFolderId?.trim() || process.env.GOOGLE_DRIVE_FOLDER_ID?.trim();
  const clientEmail = process.env.GOOGLE_DRIVE_CLIENT_EMAIL?.trim();
  const privateKey = process.env.GOOGLE_DRIVE_PRIVATE_KEY?.trim();

  if (!settings.driveSyncEnabled || !folderId || !clientEmail || !privateKey) {
    return;
  }

  const attemptedAt = new Date().toISOString();
  try {
    const token = await getDriveAccessToken(clientEmail, privateKey);
    const metadata = {
      name: `${cert.certificateNumber.replace(/\//g, '_')}_v${cert.version}.json`,
      parents: [folderId],
      mimeType: 'application/json',
    };
    const boundary = `parivahan_${crypto.randomBytes(8).toString('hex')}`;
    const body = [
      `--${boundary}`,
      'Content-Type: application/json; charset=UTF-8',
      '',
      JSON.stringify(metadata),
      `--${boundary}`,
      'Content-Type: application/json; charset=UTF-8',
      '',
      JSON.stringify(cert, null, 2),
      `--${boundary}--`,
    ].join('\r\n');

    const uploadRes = await fetch(
      'https://www.googleapis.com/upload/drive/v3/files?uploadType=multipart&fields=id',
      {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${token}`,
          'Content-Type': `multipart/related; boundary=${boundary}`,
        },
        body,
      }
    );

    if (!uploadRes.ok) {
      throw new Error(`Drive upload failed (${uploadRes.status}): ${await uploadRes.text()}`);
    }

    const uploaded = (await uploadRes.json()) as { id: string };
    const updatedCert: CertificateRecord = {
      ...cert,
      driveSyncStatus: 'SYNCED',
      driveFileId: uploaded.id,
      driveSyncedAt: attemptedAt,
      driveLastError: undefined,
    };
    await store.saveCertificate(updatedCert);
    await store.addDriveSyncLog({
      id: generateRecordId('drv'),
      certificateId: cert.id,
      certificateNumber: cert.certificateNumber,
      attemptedAt,
      status: 'SYNCED',
      driveFileId: uploaded.id,
      attemptCount,
    });
    await store.addAuditLog({
      id: generateRecordId('aud'),
      timestamp: attemptedAt,
      actor: 'system',
      actorRole: 'system',
      action: 'DRIVE_SYNC_SUCCESS',
      certificateId: cert.id,
      certificateNumber: cert.certificateNumber,
      metadata: { driveFileId: uploaded.id, attemptCount },
    });
  } catch (err) {
    const errorMessage = err instanceof Error ? err.message : 'Drive synchronization error';
    const updatedCert: CertificateRecord = {
      ...cert,
      driveSyncStatus: 'FAILED',
      driveLastError: errorMessage,
    };
    await store.saveCertificate(updatedCert);
    await store.addDriveSyncLog({
      id: generateRecordId('drv'),
      certificateId: cert.id,
      certificateNumber: cert.certificateNumber,
      attemptedAt,
      status: 'FAILED',
      errorMessage,
      attemptCount,
    });
    await store.addAuditLog({
      id: generateRecordId('aud'),
      timestamp: attemptedAt,
      actor: 'system',
      actorRole: 'system',
      action: 'DRIVE_SYNC_FAILED',
      certificateId: cert.id,
      certificateNumber: cert.certificateNumber,
      reason: errorMessage,
      metadata: { attemptCount },
    });
  }
}
