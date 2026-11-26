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
  /PS_\d{2}_.*\.pdf$/i,
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

const rootDir = process.cwd();
const findings: string[] = [];
walk(rootDir, rootDir, findings);

if (findings.length > 0) {
  console.error('\nPre-deployment security & clean-registry scan FAILED:\n');
  for (const finding of findings) {
    console.error(`  - ${finding}`);
  }
  console.error('\nRemove forbidden historical data or credential files before deploying.\n');
  process.exit(1);
}

console.log('Pre-deployment scan PASSED: 0 historical certificate files, 0 backup dumps, 0 hardcoded secrets.');
