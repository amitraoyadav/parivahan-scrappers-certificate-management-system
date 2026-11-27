interface AttemptBucket {
  failures: number[];
  lockedUntil: number;
}

const WINDOW_MS = 15 * 60 * 1000; // 15-minute rolling failure window
const SOFT_LIMIT_FAILURES = 5; // 5 attempts before short cooldown
const HARD_LIMIT_FAILURES = 10; // 10 attempts before extended cooldown
const SOFT_COOLDOWN_MS = 60 * 1000; // 60 seconds (avoids stranding owner on typos)
const HARD_COOLDOWN_MS = 5 * 60 * 1000; // 5 minutes (mitigates brute-force attacks)

const buckets = new Map<string, AttemptBucket>();

function pruneBucket(bucket: AttemptBucket, now: number): void {
  bucket.failures = bucket.failures.filter((ts) => now - ts < WINDOW_MS);
  if (bucket.lockedUntil > 0 && now >= bucket.lockedUntil) {
    bucket.lockedUntil = 0;
  }
}

export function checkRateLimit(key: string): {
  allowed: boolean;
  retryAfterSeconds: number;
  remainingAttempts: number;
} {
  const now = Date.now();
  const bucket = buckets.get(key);
  if (!bucket) {
    return { allowed: true, retryAfterSeconds: 0, remainingAttempts: SOFT_LIMIT_FAILURES };
  }

  pruneBucket(bucket, now);
  if (bucket.lockedUntil > now) {
    return {
      allowed: false,
      retryAfterSeconds: Math.ceil((bucket.lockedUntil - now) / 1000),
      remainingAttempts: 0,
    };
  }

  return {
    allowed: true,
    retryAfterSeconds: 0,
    remainingAttempts: Math.max(0, SOFT_LIMIT_FAILURES - bucket.failures.length),
  };
}

export function recordAuthFailure(key: string): {
  locked: boolean;
  retryAfterSeconds: number;
  remainingAttempts: number;
} {
  const now = Date.now();
  let bucket = buckets.get(key);
  if (!bucket) {
    bucket = { failures: [], lockedUntil: 0 };
    buckets.set(key, bucket);
  }

  pruneBucket(bucket, now);
  bucket.failures.push(now);

  if (bucket.failures.length >= HARD_LIMIT_FAILURES) {
    bucket.lockedUntil = now + HARD_COOLDOWN_MS;
    return {
      locked: true,
      retryAfterSeconds: Math.ceil(HARD_COOLDOWN_MS / 1000),
      remainingAttempts: 0,
    };
  }

  if (bucket.failures.length >= SOFT_LIMIT_FAILURES) {
    bucket.lockedUntil = now + SOFT_COOLDOWN_MS;
    return {
      locked: true,
      retryAfterSeconds: Math.ceil(SOFT_COOLDOWN_MS / 1000),
      remainingAttempts: 0,
    };
  }

  return {
    locked: false,
    retryAfterSeconds: 0,
    remainingAttempts: Math.max(0, SOFT_LIMIT_FAILURES - bucket.failures.length),
  };
}

export function clearAuthFailures(key: string): void {
  buckets.delete(key);
}

export function clearAllAuthFailures(): void {
  buckets.clear();
}

