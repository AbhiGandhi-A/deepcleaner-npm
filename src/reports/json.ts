import type { ScanResult } from '../models/scan-result.js';

export function renderJsonReport(result: ScanResult): string {
  const normalizedFindings = result.findings.map((f) => ({
    file: f.file,
    classification: f.classification || (f.category === 'Malware' ? 'malicious' : f.category === 'Suspicious' ? 'suspicious' : 'clean'),
    severity: f.severity.toLowerCase(),
    confidence: f.confidence,
    rule: f.id,
    title: f.title,
    description: f.description,
    evidence: f.evidenceChain && f.evidenceChain.length > 0 ? f.evidenceChain : f.evidence ? [f.evidence] : [],
    detectors: [f.scanner, ...(f.detectionMethod ? [f.detectionMethod] : [])],
    recommendation: f.remediation || f.suggestedFix || 'Review finding in context',
    cwe: f.cwe,
    cve: f.cve,
    taintPath: f.taintPath,
    aiAnalysis: f.aiAnalysis
  }));

  const output = {
    ...result,
    findings: normalizedFindings
  };

  return JSON.stringify(output, null, 2);
}
