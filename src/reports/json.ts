import type { ScanResult } from '../models/scan-result.js';

export function renderJsonReport(result: ScanResult): string {
  return JSON.stringify(result, null, 2);
}
