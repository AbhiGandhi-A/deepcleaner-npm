import { describe, it, expect } from 'vitest';
import path from 'node:path';
import { SecretsScanner } from '../src/scanners/secrets/secrets-scanner.js';
import { ScanContext } from '../src/core/context.js';
import { maskSecret, sanitizeEvidence } from '../src/utils/redact.js';
import { calculateShannonEntropy } from '../src/utils/hashing.js';

describe('Secrets Scanner & Redaction', () => {
  it('masks sensitive tokens correctly without leaking', () => {
    const awsKey = 'AKIA1234567890ABCDEF';
    const masked = maskSecret(awsKey);
    expect(masked).not.toBe(awsKey);
    expect(masked.startsWith('AKIA')).toBe(true);
    expect(masked.endsWith('CDEF')).toBe(true);
    expect(masked.includes('***')).toBe(true);
  });

  it('sanitizes evidence lines containing secrets', () => {
    const rawLine = 'const apiKey = "ghp_1234567890abcdefghijklmnopqrstuvwxyz1234";';
    const sanitized = sanitizeEvidence(rawLine);
    expect(sanitized).not.toContain('ghp_1234567890abcdefghijklmnopqrstuvwxyz1234');
    expect(sanitized).toContain('ghp_');
  });

  it('calculates Shannon entropy accurately', () => {
    const lowEntropy = 'aaaaaaaaaaaaaaaa';
    const highEntropy = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY';
    expect(calculateShannonEntropy(lowEntropy)).toBe(0);
    expect(calculateShannonEntropy(highEntropy)).toBeGreaterThan(4.0);
  });

  it('detects secrets in fixture directory', async () => {
    const target = path.resolve(process.cwd(), 'fixtures/vulnerable/secret');
    const ctx = new ScanContext(target, { target });
    ctx.files = [
      {
        path: path.join(target, 'credentials.env'),
        relativePath: 'credentials.env',
        size: 500,
        extension: 'env',
        isBinary: false,
        isArchive: false,
        isExecutable: false,
        isDisguised: false
      }
    ];

    const scanner = new SecretsScanner();
    const result = await scanner.scan(ctx);

    expect(result.findings.length).toBeGreaterThan(0);
    const ids = result.findings.map((f) => f.id);
    expect(ids).toContain('DC-SECRET-001'); // AWS Key
    expect(ids).toContain('DC-SECRET-008'); // Slack Bot Token
  });
});

