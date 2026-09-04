const PLACEHOLDER_TERMS = [
  'example',
  'test',
  'dummy',
  'placeholder',
  'changeme',
  'your-key-here',
  'your_api_key',
  'your_token',
  'xxxx',
  '12345678',
  'abcdef',
  'foobar',
  'sample',
  'demo'
];

export function isPlaceholderOrTestValue(evidence: string): boolean {
  const lower = evidence.toLowerCase();
  for (const term of PLACEHOLDER_TERMS) {
    if (lower.includes(term)) {
      return true;
    }
  }
  return false;
}

export function adjustConfidence(
  baseConfidence: number,
  options: {
    isTestFile?: boolean;
    isPlaceholder?: boolean;
    entropy?: number;
    hasTaint?: boolean;
  }
): number {
  let conf = baseConfidence;

  if (options.isPlaceholder) {
    conf = Math.min(conf, 20);
  }

  if (options.isTestFile) {
    conf = Math.round(conf * 0.7);
  }

  if (options.hasTaint) {
    conf = Math.min(100, conf + 15);
  }

  if (options.entropy !== undefined) {
    if (options.entropy > 4.5) {
      conf = Math.min(100, conf + 10);
    } else if (options.entropy < 3.0) {
      conf = Math.max(20, conf - 20);
    }
  }

  return Math.max(0, Math.min(100, conf));
}

export function classifyFinding(finding: {
  category: string;
  confidence: number;
  id?: string;
  evidenceChain?: string[];
  behaviorCategories?: string[];
  metadata?: Record<string, unknown>;
}): import('../models/finding.js').FindingClassification {
  const isMalware = finding.category === 'Malware' || finding.category === 'Malware Indicator';
  const hasChain = (finding.evidenceChain && finding.evidenceChain.length >= 2) ||
                   (finding.behaviorCategories && finding.behaviorCategories.length >= 2);
  const isSignatureOrHash = finding.id?.includes('MAL-001') || finding.metadata?.threatIntelMatch;

  if (isSignatureOrHash || (isMalware && hasChain && finding.confidence >= 95)) {
    return 'confirmed_malware';
  }

  if ((isMalware || finding.category === 'Suspicious') && (hasChain || finding.confidence >= 80)) {
    return 'potentially_malicious';
  }

  if (finding.confidence >= 60 || isMalware || finding.category === 'Suspicious') {
    return 'suspicious';
  }

  if (finding.confidence >= 20) {
    return 'needs_review';
  }

  return 'clean';
}
