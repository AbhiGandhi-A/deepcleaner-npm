import type { Finding } from './finding.js';
import type { ScanContext } from '../core/context.js';

export type ScannerStatus = 'completed' | 'skipped' | 'unavailable' | 'error';

export interface ScannerResult {
  scannerId: string;
  name: string;
  status: ScannerStatus;
  durationMs: number;
  filesScanned: number;
  findings: Finding[];
  error?: string;
  skipReason?: string;
  metadata?: Record<string, unknown>;
}

export interface IScanner {
  readonly id: string;
  readonly name: string;
  readonly description: string;
  isAvailable(ctx: ScanContext): Promise<boolean> | boolean;
  shouldRun(ctx: ScanContext): boolean;
  scan(ctx: ScanContext): Promise<ScannerResult>;
}
