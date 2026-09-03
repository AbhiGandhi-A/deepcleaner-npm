import { describe, it, expect } from 'vitest';
import { sanitizeFindingForAI } from '../src/ai/redaction.js';
import { GroqClient } from '../src/ai/groq.js';
import { runAiFindingAnalysis } from '../src/ai/analyzer.js';
import { ScanContext } from '../src/core/context.js';
import type { Finding } from '../src/models/finding.js';

describe('AI Analysis & Redaction Layer', () => {
  it('redacts secrets, emails, and IPs from evidence before AI dispatch', () => {
    const rawFinding: Finding = {
      id: 'DC-SECRET-001',
      scanner: 'secrets',
      category: 'Secrets',
      severity: 'HIGH',
      confidence: 90,
      title: 'AWS Key',
      description: 'Test',
      file: 'config.js',
      evidence: 'const aws = "AKIA1234567890ABCDEF"; const admin = "admin@example.com"; const ip = "192.168.1.50";'
    };

    const sanitized = sanitizeFindingForAI(rawFinding);
    expect(sanitized.sanitizedEvidence).not.toContain('AKIA1234567890ABCDEF');
    expect(sanitized.sanitizedEvidence).not.toContain('admin@example.com');
    expect(sanitized.sanitizedEvidence).toContain('[REDACTED_EMAIL]');
  });

  it('handles missing GROQ_API_KEY gracefully without throwing', async () => {
    const originalKey = process.env.GROQ_API_KEY;
    delete process.env.GROQ_API_KEY;

    const client = new GroqClient(undefined);
    expect(client.isConfigured()).toBe(false);

    const ctx = new ScanContext('/nonexistent_test_path_xyz', { target: '/nonexistent_test_path_xyz', ai: true });
    delete process.env.GROQ_API_KEY;
    const result = await runAiFindingAnalysis(ctx, [
      { id: 'DC-SEC-001', scanner: 'sast', category: 'Security', severity: 'CRITICAL', confidence: 90, title: 'T', description: 'D', file: 'f.js' }
    ]);
    expect(result.status).toBe('skipped');
    expect(result.message).toContain('GROQ_API_KEY is not configured');

    if (originalKey) {
      process.env.GROQ_API_KEY = originalKey;
    }
  });
});
