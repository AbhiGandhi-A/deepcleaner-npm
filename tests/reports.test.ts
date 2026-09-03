import { describe, it, expect } from 'vitest';
import { renderJsonReport } from '../src/reports/json.js';
import { renderHtmlReport } from '../src/reports/html.js';
import { renderSarifReport } from '../src/reports/sarif.js';
import { renderTerminalReport } from '../src/reports/terminal.js';
import type { ScanResult } from '../src/models/scan-result.js';

describe('Report Generation Formats', () => {
  const mockResult: ScanResult = {
    tool: { name: 'deepcleaner-ag', version: '1.0.0' },
    target: { path: '.', absolutePath: '/workspace/test' },
    timestamp: '2026-09-03T12:00:00.000Z',
    durationMs: 120,
    project: {
      rootPath: '/workspace/test',
      name: 'test',
      projectTypes: ['nodejs'],
      manifestFiles: ['package.json'],
      lockFiles: [],
      totalFiles: 5,
      totalBytes: 10240,
      hasGit: true,
      languagesDetected: { typescript: 5 },
      ignoredPatterns: []
    },
    riskScore: {
      score: 45,
      grade: 'C',
      explanation: 'Moderate risk',
      impacts: { criticalCount: 0, highCount: 1, mediumCount: 2, lowCount: 0, deduplicatedFindings: 3 }
    },
    summary: { critical: 0, high: 1, medium: 2, low: 0, info: 0, total: 3 },
    scanners: {},
    findings: [
      {
        id: 'DC-SEC-001',
        scanner: 'sast',
        category: 'Security',
        severity: 'HIGH',
        confidence: 90,
        title: 'Command Injection',
        description: 'Shell execution',
        file: 'src/runner.ts',
        line: 14,
        evidence: 'child_process.exec(cmd)'
      }
    ],
    disclaimers: ['Disclaimer test'],
    skippedChecks: []
  };

  it('generates valid JSON report', () => {
    const jsonStr = renderJsonReport(mockResult);
    const parsed = JSON.parse(jsonStr);
    expect(parsed.tool.name).toBe('deepcleaner-ag');
    expect(parsed.riskScore.score).toBe(45);
    expect(parsed.findings.length).toBe(1);
  });

  it('generates offline HTML report with embedded styles', () => {
    const htmlStr = renderHtmlReport(mockResult);
    expect(htmlStr).toContain('<!DOCTYPE html>');
    expect(htmlStr).toContain('DeepCleaner Security Report');
    expect(htmlStr).toContain('Command Injection');
    expect(htmlStr).not.toContain('http://cdn'); // Verifies zero external CDN dependency
  });

  it('generates valid SARIF v2.1.0 report', () => {
    const sarifStr = renderSarifReport(mockResult);
    const parsed = JSON.parse(sarifStr);
    expect(parsed.version).toBe('2.1.0');
    expect(parsed.runs[0].tool.driver.name).toBe('deepcleaner-ag');
    expect(parsed.runs[0].results.length).toBe(1);
  });

  it('generates rich ANSI terminal report', () => {
    const term = renderTerminalReport(mockResult);
    expect(term).toContain('DEEPCLEANER AG');
    expect(term).toContain('SECURITY RESULT');
    expect(term).toContain('Command Injection');
  });
});

