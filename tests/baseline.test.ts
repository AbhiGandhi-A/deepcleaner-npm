import { describe, it, expect } from 'vitest';
import path from 'node:path';
import fs from 'node:fs';
import { createBaseline, applyBaseline, generateFindingFingerprint } from '../src/utils/baseline.js';
import type { Finding } from '../src/models/finding.js';

describe('Baseline Mechanism', () => {
  const tempBaselineFile = path.resolve(process.cwd(), 'temp-test-baseline.json');

  const testFindings: Finding[] = [
    {
      id: 'DC-SEC-001',
      scanner: 'sast',
      category: 'Security',
      severity: 'CRITICAL',
      confidence: 90,
      title: 'Command injection',
      description: 'exec()',
      file: 'app.ts',
      line: 12
    },
    {
      id: 'DC-SECRET-001',
      scanner: 'secrets',
      category: 'Secrets',
      severity: 'HIGH',
      confidence: 95,
      title: 'AWS Key',
      description: 'Key found',
      file: 'config.env',
      line: 2
    }
  ];

  it('creates a deterministic baseline file from findings', () => {
    const baseline = createBaseline(testFindings, tempBaselineFile);
    expect(baseline.findingsCount).toBe(2);
    expect(baseline.entries.length).toBe(2);
    expect(fs.existsSync(tempBaselineFile)).toBe(true);
  });

  it('suppresses known baseline findings and flags new findings', () => {
    const newFinding: Finding = {
      id: 'DC-SEC-002',
      scanner: 'sast',
      category: 'Security',
      severity: 'CRITICAL',
      confidence: 95,
      title: 'eval() used',
      description: 'eval()',
      file: 'server.ts',
      line: 45
    };

    const mixedFindings = [...testFindings, newFinding];
    const result = applyBaseline(mixedFindings, tempBaselineFile);

    expect(result.suppressedCount).toBe(2);
    expect(result.activeFindings.length).toBe(1);
    expect(result.activeFindings[0].id).toBe('DC-SEC-002');

    // Clean up
    if (fs.existsSync(tempBaselineFile)) {
      fs.unlinkSync(tempBaselineFile);
    }
  });
});
