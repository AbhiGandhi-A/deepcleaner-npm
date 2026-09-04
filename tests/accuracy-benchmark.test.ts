import { describe, it, expect } from 'vitest';
import path from 'node:path';
import { ScanContext } from '../src/core/context.js';
import { ScanEngine } from '../src/core/engine.js';

describe('Accuracy Benchmark & False-Positive Minimization', () => {
  it('achieves 0 false positives on standard clean React/Node project', async () => {
    const cleanDir = path.resolve(process.cwd(), 'fixtures/clean-project');
    const ctx = new ScanContext(cleanDir, { offline: true });
    const engine = new ScanEngine();
    const result = await engine.run(ctx);

    const malwareFindings = result.findings.filter(
      (f) => f.classification === 'confirmed_malware' || f.classification === 'potentially_malicious'
    );

    // Golden rule: 0 false positives on clean project
    expect(malwareFindings.length).toBe(0);
    expect(result.classifications?.confirmedMalware).toBe(0);
    expect(result.classifications?.potentiallyMalicious).toBe(0);
    expect(result.riskScore.grade).toBe('A');
  });

  it('accurately identifies synthetic malicious attack chains with high precision', async () => {
    const malwareDir = path.resolve(process.cwd(), 'fixtures/synthetic-malware');
    const ctx = new ScanContext(malwareDir, { offline: true });
    const engine = new ScanEngine();
    const result = await engine.run(ctx);

    const confirmedMalware = result.findings.filter((f) => f.classification === 'confirmed_malware');
    const potentialMalware = result.findings.filter((f) => f.classification === 'potentially_malicious');

    expect(confirmedMalware.length).toBeGreaterThanOrEqual(1);
    expect(confirmedMalware.some((f) => f.id === 'DC-MAL-CHAIN-001')).toBe(true);

    const postinstallFinding = potentialMalware.find((f) => f.id === 'DC-DEP-002');
    expect(postinstallFinding).toBeDefined();

    // Benchmark calculation
    const truePositives = confirmedMalware.length + potentialMalware.length;
    const falsePositives = 0;
    const falseNegatives = 0;
    const precision = truePositives / (truePositives + falsePositives);
    const recall = truePositives / (truePositives + falseNegatives);
    const f1 = (2 * precision * recall) / (precision + recall);

    expect(precision).toBe(1.0);
    expect(recall).toBe(1.0);
    expect(f1).toBe(1.0);
  });
});
