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

export function calculateClassifications(findings: Finding[]): import('../models/scan-result.js').ClassificationSummary {
  let confirmedMalware = 0;
  let potentiallyMalicious = 0;
  let suspicious = 0;
  let needsReview = 0;
  let clean = 0;

  for (const f of findings) {
    const isMalwareCategory = f.category === 'Malware' || f.category === 'Malware Indicator' || f.category === 'Suspicious';
    const cls = f.classification || (isMalwareCategory ? 'suspicious' : 'needs_review');

    if (!isMalwareCategory) {
      if (cls === 'clean') clean++;
      else needsReview++;
      continue;
    }

    switch (cls) {
      case 'confirmed_malware':
        confirmedMalware++;
        break;
      case 'potentially_malicious':
        potentiallyMalicious++;
        break;
      case 'suspicious':
        suspicious++;
        break;
      case 'needs_review':
        needsReview++;
        break;
      case 'clean':
        clean++;
        break;
    }
  }

  return {
    confirmedMalware,
    potentiallyMalicious,
    suspicious,
    needsReview,
    clean
  };
}

export function calculateSecurityFindings(findings: Finding[]): import('../models/scan-result.js').SecurityFindingsSummary {
  let dependencies = 0;
  let configuration = 0;
  let permissions = 0;
  let secrets = 0;
  let sast = 0;

  const depSev = { critical: 0, high: 0, medium: 0, low: 0 };

  for (const f of findings) {
    switch (f.category) {
      case 'Dependencies':
        dependencies++;
        if (f.severity === 'CRITICAL') depSev.critical++;
        else if (f.severity === 'HIGH') depSev.high++;
        else if (f.severity === 'MEDIUM') depSev.medium++;
        else if (f.severity === 'LOW') depSev.low++;
        break;
      case 'Configuration':
        configuration++;
        break;
      case 'Permissions':
        permissions++;
        break;
      case 'Secrets':
      case 'Git History':
        secrets++;
        break;
      case 'Security':
        sast++;
        break;
    }
  }

  return {
    dependencies,
    configuration,
    permissions,
    secrets,
    sast,
    dependenciesSeverity: depSev
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

  let malwareCount = 0;
  let depCount = 0;
  let secretCount = 0;
  let sastCount = 0;
  let configCount = 0;
  let permCount = 0;

  for (const f of deduplicated) {
    const confFactor = Math.max(0.3, f.confidence / 100);

    if (f.category === 'Malware' || f.category === 'Malware Indicator' || f.category === 'Suspicious') {
      malwareCount++;
    } else if (f.category === 'Dependencies') {
      depCount++;
    } else if (f.category === 'Secrets' || f.category === 'Git History') {
      secretCount++;
    } else if (f.category === 'Security') {
      sastCount++;
    } else if (f.category === 'Configuration') {
      configCount++;
    } else if (f.category === 'Permissions') {
      permCount++;
    }

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
    contributors: {
      dependencies: `${depCount}`,
      malware: `${malwareCount}`,
      secrets: `${secretCount}`,
      sast: `${sastCount}`,
      configuration: `${configCount}`,
      permissions: `${permCount}`
    },
    impacts: {
      criticalCount,
      highCount,
      mediumCount,
      lowCount,
      deduplicatedFindings: deduplicated.length
    }
  };
}
