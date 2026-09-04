import type { Finding } from './finding.js';
import type { ScannerResult } from './scanner.js';
import type { ProjectMetadata } from './project.js';

export interface SeveritySummary {
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
  total: number;
}

export interface ClassificationSummary {
  confirmedMalware: number;
  potentiallyMalicious: number;
  suspicious: number;
  needsReview: number;
  clean: number;
}

export interface SecurityFindingsSummary {
  dependencies: number;
  configuration: number;
  permissions: number;
  secrets: number;
  sast: number;
  dependenciesSeverity?: { critical: number; high: number; medium: number; low: number };
}

export interface MetricsSummary {
  filesScanned: number;
  filesSkipped: number;
  hiddenFilesScanned: number;
  archivesInspected: number;
  binariesInspected: number;
  secretsDetected: number;
  dependenciesAnalyzed: number;
}

export interface RiskContributors {
  malware: string;
  dependencies: string;
  secrets: string;
  sast: string;
  configuration: string;
  permissions: string;
}

export interface RiskScoreDetails {
  score: number;
  grade: 'A' | 'B' | 'C' | 'D' | 'F';
  explanation: string;
  contributors?: RiskContributors;
  impacts: {
    criticalCount: number;
    highCount: number;
    mediumCount: number;
    lowCount: number;
    deduplicatedFindings: number;
  };
}

export interface ScanResult {
  tool: {
    name: string;
    version: string;
    homepage?: string;
  };
  target: {
    path: string;
    absolutePath: string;
  };
  timestamp: string;
  durationMs: number;
  project: ProjectMetadata;
  riskScore: RiskScoreDetails;
  summary: SeveritySummary;
  classifications?: ClassificationSummary;
  securityFindings?: SecurityFindingsSummary;
  metrics?: MetricsSummary;
  scanners: Record<string, ScannerResult>;
  findings: Finding[];
  disclaimers: string[];
  skippedChecks: {
    name: string;
    reason: string;
  }[];
}
