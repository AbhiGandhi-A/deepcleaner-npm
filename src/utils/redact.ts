export function maskSecret(secret: string): string {
  if (!secret) return '[REDACTED]';
  const trimmed = secret.trim();
  const len = trimmed.length;

  if (len <= 8) {
    return '***REDACTED***';
  }

  const prefixLen = Math.min(4, Math.floor(len / 4));
  const suffixLen = Math.min(4, Math.floor(len / 4));
  const prefix = trimmed.slice(0, prefixLen);
  const suffix = trimmed.slice(len - suffixLen);
  const stars = '*'.repeat(Math.max(4, len - prefixLen - suffixLen));

  return `${prefix}${stars}${suffix}`;
}

const COMMON_SECRET_PATTERNS: RegExp[] = [
  /\b(AKIA[0-9A-Z]{16})\b/g,
  /\b(gh[pousr]_[A-Za-z0-9_]{36,255})\b/g,
  /\b(github_pat_[A-Za-z0-9_]{22}_[A-Za-z0-9_]{59})\b/g,
  /\b(glpat-[0-9a-zA-Z\-_]{20,})\b/g,
  /\b(xox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24,32})\b/g,
  /\b(sk_live_[0-9a-zA-Z]{24,})\b/g,
  /\b(rk_live_[0-9a-zA-Z]{24,})\b/g,
  /\b(AIza[0-9A-Za-z\-_]{35})\b/g,
  /-----BEGIN [A-Z ]+ PRIVATE KEY-----[\s\S]*?-----END [A-Z ]+ PRIVATE KEY-----/g,
  /((?:postgres|postgresql|mysql|mongodb(?:\+srv)?|redis):\/\/[^:\s]+:)([^@\s]+)(@[^\s]+)/gi,
  /\b(ey[A-Za-z0-9_-]{10,}\.ey[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})\b/g
];

export function sanitizeEvidence(text: string): string {
  if (!text) return '';
  let sanitized = text;

  sanitized = sanitized.replace(
    /-----BEGIN [A-Z ]+ PRIVATE KEY-----[\s\S]*?-----END [A-Z ]+ PRIVATE KEY-----/g,
    '-----BEGIN PRIVATE KEY-----\n[REDACTED PRIVATE KEY DATA]\n-----END PRIVATE KEY-----'
  );

  sanitized = sanitized.replace(
    /((?:postgres|postgresql|mysql|mongodb(?:\+srv)?|redis):\/\/[^:\s]+:)([^@\s]+)(@[^\s]+)/gi,
    (_match, prefix, pass, suffix) => `${prefix}${maskSecret(pass)}${suffix}`
  );

  sanitized = sanitized.replace(
    /(['"]?(?:api[_-]?key|secret|password|passwd|auth[_-]?token|access[_-]?token)['"]?\s*[:=]\s*['"])([^'"\n\r]{6,})(['"])/gi,
    (_match, p1, val, p3) => `${p1}${maskSecret(val)}${p3}`
  );

  for (const pattern of COMMON_SECRET_PATTERNS) {
    sanitized = sanitized.replace(pattern, (match) => {
      if (match.includes('\n')) return '[REDACTED]';
      return maskSecret(match);
    });
  }

  return sanitized;
}

export function redactForAI(text: string): string {
  if (!text) return '';
  let cleaned = sanitizeEvidence(text);

  cleaned = cleaned.replace(/[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g, '[REDACTED_EMAIL]');
  cleaned = cleaned.replace(/\b(?!(?:127\.0\.0\.1|0\.0\.0\.0|255\.255\.255\.255))\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/g, '[REDACTED_IP]');

  return cleaned;
}
