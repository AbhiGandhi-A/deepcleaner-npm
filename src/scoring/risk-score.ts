import type { Finding } from '../models/finding.js';
import type { RiskScoreDetails, SeveritySummary } from '../models/scan-result.js';

export function calculateSummary(findings: Finding[]): SeveritySummary {
  let critical = 0;
  let high = 0;
  let medium = 0;
  let low = 0;
  let info = 0;

  for (const f of findings) {
    switch (f.severity) {
      case 'CRITICAL':
        critical++;
        break;
      case 'HIGH':
        high++;
        break;
      case 'MEDIUM':
        medium++;
        break;
      case 'LOW':
        low++;
        break;
      case 'INFO':
        info++;
        break;
    }
  }

  return {
    critical,
    high,
    medium,
    low,
    info,
    total: findings.length
  };
}

export function calculateRiskScore(findings: Finding[]): RiskScoreDetails {
  const seenKeys = new Set<string>();
  const deduplicated: Finding[] = [];

  for (const f of findings) {
    const key = `${f.id}:${f.file}:${f.line ?? 0}`;
    if (!seenKeys.has(key)) {
      seenKeys.add(key);
      deduplicated.push(f);
    }
  }

  let criticalCount = 0;
  let highCount = 0;
  let mediumCount = 0;
  let lowCount = 0;

  let rawScore = 0;

  for (const f of deduplicated) {
    const confFactor = Math.max(0.3, f.confidence / 100);

    switch (f.severity) {
      case 'CRITICAL':
        criticalCount++;
        rawScore += 35 * confFactor;
        break;
      case 'HIGH':
        highCount++;
        rawScore += 15 * confFactor;
        break;
      case 'MEDIUM':
        mediumCount++;
        rawScore += 5 * confFactor;
        break;
      case 'LOW':
        lowCount++;
        rawScore += 1.5 * confFactor;
        break;
    }
  }

  const score = Math.min(100, Math.round(rawScore));

  let grade: 'A' | 'B' | 'C' | 'D' | 'F' = 'A';
  if (score > 80) grade = 'F';
  else if (score > 60) grade = 'D';
  else if (score > 35) grade = 'C';
  else if (score > 15) grade = 'B';
  else grade = 'A';

  const explanations: string[] = [];
  if (criticalCount > 0) {
    explanations.push(`${criticalCount} critical finding(s) require immediate remediation`);
  }
  if (highCount > 0) {
    explanations.push(`${highCount} high severity issue(s) materially increase exploitability`);
  }
  if (mediumCount > 0) {
    explanations.push(`${mediumCount} medium severity issue(s) detected`);
  }
  if (score === 0) {
    explanations.push('No significant security vulnerabilities or malware indicators detected');
  }

  return {
    score,
    grade,
    explanation: explanations.join('; ') || 'Minimal risk posture',
    impacts: {
      criticalCount,
      highCount,
      mediumCount,
      lowCount,
      deduplicatedFindings: deduplicated.length
    }
  };
}
