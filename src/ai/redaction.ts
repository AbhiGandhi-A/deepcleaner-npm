import { redactForAI } from '../utils/redact.js';
import type { Finding } from '../models/finding.js';

export interface SanitizedFindingContext {
  id: string;
  scanner: string;
  category: string;
  severity: string;
  title: string;
  description: string;
  file: string;
  line?: number;
  sanitizedEvidence: string;
  remediation?: string;
  taintSteps?: Array<{ file: string; line: number; description: string }>;
}

export function sanitizeFindingForAI(finding: Finding): SanitizedFindingContext {
  const rawEvidence = finding.evidence || '';
  const sanitized = redactForAI(rawEvidence);

  return {
    id: finding.id,
    scanner: finding.scanner,
    category: finding.category,
    severity: finding.severity,
    title: finding.title,
    description: finding.description,
    file: finding.file,
    line: finding.line,
    sanitizedEvidence: sanitized,
    remediation: finding.remediation,
    taintSteps: finding.taintPath?.map((t) => ({
      file: t.file,
      line: t.line,
      description: redactForAI(t.description)
    }))
  };
}
