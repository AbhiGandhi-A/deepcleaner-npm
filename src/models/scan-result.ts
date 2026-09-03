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

export interface RiskScoreDetails {
  score: number;
  grade: 'A' | 'B' | 'C' | 'D' | 'F';
  explanation: string;
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
  scanners: Record<string, ScannerResult>;
  findings: Finding[];
  disclaimers: string[];
  skippedChecks: {
    name: string;
    reason: string;
  }[];
}
