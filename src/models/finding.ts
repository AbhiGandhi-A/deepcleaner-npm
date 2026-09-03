export type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';

export type FindingCategory =
  | 'Security'
  | 'Secrets'
  | 'Dependencies'
  | 'Malware'
  | 'Malware Indicator'
  | 'Suspicious'
  | 'Potentially Dangerous'
  | 'Configuration'
  | 'Binary'
  | 'Archive'
  | 'Permissions'
  | 'Git History'
  | 'Informational';

export interface CodeLocation {
  file: string;
  line?: number;
  column?: number;
  endLine?: number;
  endColumn?: number;
}

export interface TaintStep {
  file: string;
  line: number;
  description: string;
  codeSnippet?: string;
}

export interface Finding {
  id: string;
  scanner: string;
  category: FindingCategory;
  severity: Severity;
  confidence: number;
  title: string;
  description: string;
  file: string;
  line?: number;
  column?: number;
  endLine?: number;
  endColumn?: number;
  evidence?: string;
  redactedEvidence?: string;
  source?: string;
  remediation?: string;
  suggestedFix?: string;
  references?: string[];
  cwe?: string[];
  cve?: string[];
  ghsa?: string[];
  osv?: string[];
  taintPath?: TaintStep[];
  aiAnalysis?: {
    verdict: 'confirmed' | 'likely' | 'suspicious' | 'false_positive' | 'unknown';
    confidence: number;
    severity: string;
    explanation: string;
    attackPath?: string[];
    recommendation: string;
    reasoningSummary: string;
  };
  metadata?: Record<string, unknown>;
}

export interface RuleDefinition {
  id: string;
  name: string;
  category: FindingCategory;
  defaultSeverity: Severity;
  defaultConfidence: number;
  description: string;
  remediation: string;
  cwe?: string[];
  references?: string[];
  languages?: string[];
}
