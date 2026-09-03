import fs from 'node:fs';
import path from 'node:path';
import type { Finding } from '../models/finding.js';
import { calculateSha256 } from './hashing.js';

export interface BaselineEntry {
  id: string;
  file: string;
  fingerprint: string;
}

export interface BaselineFile {
  version: string;
  createdAt: string;
  findingsCount: number;
  entries: BaselineEntry[];
}

export function generateFindingFingerprint(finding: Finding): string {
  const normFile = finding.file.replace(/\\/g, '/');
  const content = `${finding.id}:${normFile}:${finding.line ?? 0}:${finding.title}`;
  return calculateSha256(content);
}

export function createBaseline(findings: Finding[], filePath: string): BaselineFile {
  const entries: BaselineEntry[] = findings.map((f) => ({
    id: f.id,
    file: f.file.replace(/\\/g, '/'),
    fingerprint: generateFindingFingerprint(f)
  }));

  const baselineData: BaselineFile = {
    version: '1.0.0',
    createdAt: new Date().toISOString(),
    findingsCount: entries.length,
    entries
  };

  const resolvedPath = path.resolve(process.cwd(), filePath);
  fs.writeFileSync(resolvedPath, JSON.stringify(baselineData, null, 2), 'utf-8');
  return baselineData;
}

export function applyBaseline(
  findings: Finding[],
  baselineFilePath: string
): { activeFindings: Finding[]; suppressedFindings: Finding[]; suppressedCount: number } {
  const resolvedPath = path.resolve(process.cwd(), baselineFilePath);
  if (!fs.existsSync(resolvedPath)) {
    throw new Error(`Baseline file does not exist: ${resolvedPath}`);
  }

  const content = fs.readFileSync(resolvedPath, 'utf-8');
  const baselineData = JSON.parse(content) as BaselineFile;

  const baselineFingerprints = new Set<string>();
  if (Array.isArray(baselineData.entries)) {
    for (const entry of baselineData.entries) {
      if (entry.fingerprint) {
        baselineFingerprints.add(entry.fingerprint);
      }
    }
  }

  const activeFindings: Finding[] = [];
  const suppressedFindings: Finding[] = [];

  for (const finding of findings) {
    const fp = generateFindingFingerprint(finding);
    if (baselineFingerprints.has(fp)) {
      suppressedFindings.push(finding);
    } else {
      activeFindings.push(finding);
    }
  }

  return {
    activeFindings,
    suppressedFindings,
    suppressedCount: suppressedFindings.length
  };
}
