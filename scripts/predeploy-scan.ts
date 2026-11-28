import fs from 'node:fs';
import path from 'node:path';

const FORBIDDEN_FILE_PATTERNS = [
  /certificates\.json$/i,
  /MASTER_CERTIFICATE_REGISTRY\.json$/i,
  /ALL_920_CERTIFICATES\.json$/i,
  /COMPLETE_LIVE_DATABASE_BACKUP\.json$/i,
  /authoritativePreservedCertificates\.json$/i,
  /service-?account.*\.json$/i,
  /firebase-adminsdk.*\.json$/i,
  /credentials.*\.json$/i,
  /\.pem$/i,
  /\.key$/i,
  /PS[-_]\d{2}[-_].*\.pdf$/i,
];

const FORBIDDEN_DIR_SEGMENTS = [
  'database_backups',
  'vault_backups',
  'historical_exports',
];

const SECRET_PATTERNS: Array<{ label: string; regex: RegExp }> = [
  { label: 'Private Key Block', regex: /-----BEGIN [A-Z ]*PRIVATE KEY-----/ },
  { label: 'Google API Key', regex: /AIza[0-9A-Za-z\-_]{35}/ },
  { label: 'GitHub PAT', regex: /ghp_[0-9A-Za-z]{36}/ },
];

const IGNORED_DIRS = new Set(['node_modules', 'dist', '.git', '.vercel']);
const TEXT_EXTENSIONS = new Set(['.ts', '.tsx', '.js', '.mjs', '.cjs', '.json', '.env', '.md', '.html', '.css']);

function walk(dir: string, rootDir: string, findings: string[]): void {
  const entries = fs.readdirSync(dir, { withFileTypes: true });
  for (const entry of entries) {
    if (IGNORED_DIRS.has(entry.name)) continue;

    const fullPath = path.join(dir, entry.name);
    const relPath = path.relative(rootDir, fullPath).replace(/\\/g, '/');

    if (entry.isDirectory()) {
      if (FORBIDDEN_DIR_SEGMENTS.includes(entry.name)) {
        findings.push(`[FORBIDDEN_DIR] Historical/backup directory detected: ${relPath}`);
        continue;
      }
      walk(fullPath, rootDir, findings);
      continue;
    }

    for (const pattern of FORBIDDEN_FILE_PATTERNS) {
      if (pattern.test(relPath)) {
        findings.push(`[FORBIDDEN_FILE] Historical data or credential file detected: ${relPath}`);
      }
    }

    if (entry.name.startsWith('.env') && entry.name !== '.env.example') {
      findings.push(`[FORBIDDEN_ENV] Local environment file should not be bundled or committed: ${relPath}`);
    }

    const ext = path.extname(entry.name).toLowerCase();
    if (TEXT_EXTENSIONS.has(ext) && relPath !== 'scripts/predeploy-scan.ts') {
      const stat = fs.statSync(fullPath);
      if (stat.size <= 2 * 1024 * 1024) {
        const content = fs.readFileSync(fullPath, 'utf8');
        for (const { label, regex } of SECRET_PATTERNS) {
          if (regex.test(content)) {
            findings.push(`[SECRET_DETECTED] ${label} found in ${relPath}`);
          }
        }
      }
    }
  }
}

const FORBIDDEN_CODE_PATTERNS: Array<{ label: string; regex: RegExp }> = [
  { label: 'Destructive Collection Wipe Function', regex: /\b(wipeAllCertificates|deleteAllCertificates|clearCertificatesCollection|resetProductionDatabase)\b/ },
  { label: 'Demo Certificate Auto-Seeding', regex: /\b(seedDemoCertificates|autoSeedCertificates|importHistoricalCertificates)\b/ },
];

function checkFirestoreRules(rootDir: string, findings: string[]): void {
  const rulesPath = path.join(rootDir, 'firestore.rules');
  if (!fs.existsSync(rulesPath)) {
    findings.push('[SECURITY_RULES] Missing firestore.rules file.');
    return;
  }
  const content = fs.readFileSync(rulesPath, 'utf8');
  if (!/allow\s+read\s*,\s*write\s*:\s*if\s+false\s*;/.test(content)) {
    findings.push('[SECURITY_RULES] firestore.rules must enforce zero-trust `allow read, write: if false;`.');
  }
}

const rootDir = process.cwd();
const findings: string[] = [];
walk(rootDir, rootDir, findings);
checkFirestoreRules(rootDir, findings);

// Scan runtime source directories (src/, api/) for destructive auto-wipe or demo seeding code
for (const runtimeDir of ['src', 'api']) {
  const fullRuntimeDir = path.join(rootDir, runtimeDir);
  if (!fs.existsSync(fullRuntimeDir)) continue;
  const stack = [fullRuntimeDir];
  while (stack.length > 0) {
    const current = stack.pop()!;
    for (const entry of fs.readdirSync(current, { withFileTypes: true })) {
      const fullPath = path.join(current, entry.name);
      if (entry.isDirectory()) {
        if (!IGNORED_DIRS.has(entry.name)) stack.push(fullPath);
        continue;
      }
      const ext = path.extname(entry.name).toLowerCase();
      if (!TEXT_EXTENSIONS.has(ext)) continue;
      const content = fs.readFileSync(fullPath, 'utf8');
      const relPath = path.relative(rootDir, fullPath).replace(/\\/g, '/');
      for (const { label, regex } of FORBIDDEN_CODE_PATTERNS) {
        if (regex.test(content)) {
          findings.push(`[FORBIDDEN_CODE] ${label} detected in ${relPath}`);
        }
      }
    }
  }
}

if (findings.length > 0) {
  console.error('\nPre-deployment security & data-protection scan FAILED:\n');
  for (const finding of findings) {
    console.error(`  - ${finding}`);
  }
  console.error('\nResolve all findings before deploying.\n');
  process.exit(1);
}

console.log(
  'Pre-deployment scan PASSED: 0 historical certificate files, 0 backup dumps, 0 hardcoded secrets, 0 destructive auto-wipe patterns, zero-trust firestore.rules verified.'
);
