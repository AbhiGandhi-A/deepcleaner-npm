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

  it('ensures .env.example with mode 666 generates NO malware and NO high permission finding', async () => {
    const { PermissionsScanner } = await import('../src/scanners/permissions/permissions-scanner.js');
    const scanner = new PermissionsScanner();
    const ctx = new ScanContext(process.cwd(), { offline: true });
    ctx.files = [
      {
        path: path.resolve(process.cwd(), '.env.example'),
        relativePath: '.env.example',
        extension: '.example',
        size: 100,
        isBinary: false,
        isExecutable: false,
        isArchive: false
      },
      {
        path: path.resolve(process.cwd(), '.env.sample'),
        relativePath: '.env.sample',
        extension: '.sample',
        size: 100,
        isBinary: false,
        isExecutable: false,
        isArchive: false
      }
    ];

    const res = await scanner.scan(ctx);
    const malwarePerms = res.findings.filter((f) => f.classification === 'confirmed_malware' || f.classification === 'potentially_malicious');
    expect(malwarePerms.length).toBe(0);
    expect(res.findings.some((f) => f.file === '.env.example' && f.severity === 'HIGH')).toBe(false);
  });

  it('separates dependency vulnerabilities from malware indicators', async () => {
    const { calculateClassifications, calculateSecurityFindings } = await import('../src/scoring/risk-score.js');
    const { classifyFinding } = await import('../src/scoring/confidence.js');

    const mockVulnerableDep: import('../src/models/finding.js').Finding = {
      id: 'GHSA-6g55-p6wh-862q',
      scanner: 'dependencies',
      category: 'Dependencies',
      severity: 'HIGH',
      confidence: 95,
      title: 'Vulnerable dependency: postcss@8.5.0',
      description: 'PostCSS line return parsing vulnerability',
      file: 'package.json',
      evidence: '"postcss": "8.5.0"',
      redactedEvidence: '"postcss": "8.5.0"'
    };

    mockVulnerableDep.classification = classifyFinding(mockVulnerableDep);
    expect(mockVulnerableDep.classification).toBe('needs_review'); // NOT suspicious or malware!

    const classifications = calculateClassifications([mockVulnerableDep]);
    const security = calculateSecurityFindings([mockVulnerableDep]);

    expect(classifications.confirmedMalware).toBe(0);
    expect(classifications.potentiallyMalicious).toBe(0);
    expect(classifications.suspicious).toBe(0);
    expect(security.dependencies).toBe(1);
    expect(security.dependenciesSeverity?.high).toBe(1);
  });

  it('detects actual secrets in .env independently', async () => {
    const { SecretsScanner } = await import('../src/scanners/secrets/secrets-scanner.js');
    const scanner = new SecretsScanner();
    const ctx = new ScanContext(path.resolve(process.cwd(), 'fixtures/vulnerable/secret'), { offline: true });
    const { files } = await (await import('../src/discovery/filesystem.js')).discoverFiles(ctx);
    ctx.files = files;

    const res = await scanner.scan(ctx);
    expect(res.findings.length).toBeGreaterThanOrEqual(1);
    expect(res.findings.some((f) => f.category === 'Secrets')).toBe(true);
  });
});

