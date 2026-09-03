import type { Severity } from '../models/finding.js';

export const SEVERITY_WEIGHTS: Record<Severity, number> = {
  CRITICAL: 25,
  HIGH: 10,
  MEDIUM: 3,
  LOW: 1,
  INFO: 0
};

export function compareSeverity(a: Severity, b: Severity): number {
  return SEVERITY_WEIGHTS[b] - SEVERITY_WEIGHTS[a];
}

export function isSeverityAtLeast(findingSeverity: Severity, threshold: 'critical' | 'high' | 'medium' | 'low'): boolean {
  const normThreshold = threshold.toUpperCase() as Severity;
  return SEVERITY_WEIGHTS[findingSeverity] >= SEVERITY_WEIGHTS[normThreshold];
}
