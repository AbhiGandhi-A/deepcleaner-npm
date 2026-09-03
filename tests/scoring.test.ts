import { describe, it, expect } from 'vitest';
import { calculateRiskScore, calculateSummary } from '../src/scoring/risk-score.js';
import type { Finding } from '../src/models/finding.js';

describe('Scoring Module', () => {
  it('calculates accurate risk score for clean projects', () => {
    const score = calculateRiskScore([]);
    expect(score.score).toBe(0);
    expect(score.grade).toBe('A');
  });

  it('calculates risk score and grade for critical findings', () => {
    const findings: Finding[] = [
      {
        id: 'DC-SEC-001',
        scanner: 'sast',
        category: 'Security',
        severity: 'CRITICAL',
        confidence: 95,
        title: 'Command Injection',
        description: 'Test',
        file: 'runner.ts'
      },
      {
        id: 'DC-SECRET-001',
        scanner: 'secrets',
        category: 'Secrets',
        severity: 'HIGH',
        confidence: 90,
        title: 'AWS Key',
        description: 'Test',
        file: '.env'
      }
    ];

    const summary = calculateSummary(findings);
    expect(summary.critical).toBe(1);
    expect(summary.high).toBe(1);
    expect(summary.total).toBe(2);

    const score = calculateRiskScore(findings);
    expect(score.score).toBeGreaterThan(40);
    expect(['C', 'D', 'F']).toContain(score.grade);
  });
});

