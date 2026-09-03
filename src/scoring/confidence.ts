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
