import type { IScanner, ScannerResult } from '../../models/scanner.js';
import type { Finding } from '../../models/finding.js';
import type { ScanContext } from '../../core/context.js';
import { inspectZipArchiveSafe } from '../../discovery/archive-detector.js';

export class ArchiveScanner implements IScanner {
  public readonly id = 'archives';
  public readonly name = 'Archive Security Scanner';
  public readonly description = 'Inspects ZIP, TAR, and GZ archives for zip bombs, path traversal entries (Zip Slip), and nested payloads.';

  isAvailable(_ctx: ScanContext): boolean {
    return true;
  }

  shouldRun(ctx: ScanContext): boolean {
    return ctx.isScannerEnabled(this.id);
  }

  async scan(ctx: ScanContext): Promise<ScannerResult> {
    const startTime = Date.now();
    const findings: Finding[] = [];
    let filesScanned = 0;

    const archiveFiles = ctx.files.filter((f) => f.isArchive || f.extension === 'zip' || f.extension === 'gz');

    for (const file of archiveFiles) {
      filesScanned++;
      if (file.extension === 'zip' || file.isArchive) {
        const inspection = inspectZipArchiveSafe(file.path);
        if (inspection.isArchive) {
          if (inspection.isZipBomb) {
            findings.push({
              id: 'DC-MAL-005',
              scanner: this.id,
              category: 'Archive',
              severity: 'HIGH',
              confidence: 90,
              title: 'Potential Zip Bomb detected in archive',
              description: `Archive '${file.relativePath}' has an anomalous uncompressed size of ${(inspection.totalUncompressedBytes / 1024 / 1024).toFixed(1)} MB (${inspection.entryCount} entries).`,
              file: file.relativePath,
              evidence: inspection.suspiciousEntries.join('; '),
              redactedEvidence: inspection.suspiciousEntries.join('; '),
              remediation: 'Do not extract untrusted archive without decompression size limits.',
              cwe: ['CWE-409']
            });
          }

          if (inspection.hasPathTraversal) {
            findings.push({
              id: 'DC-SEC-005',
              scanner: this.id,
              category: 'Archive',
              severity: 'CRITICAL',
              confidence: 95,
              title: 'Zip Slip Path Traversal vulnerability in archive entries',
              description: `Archive '${file.relativePath}' contains filenames with directory traversal sequences (\`../\` or absolute paths) that escape extraction directory.`,
              file: file.relativePath,
              evidence: inspection.suspiciousEntries.join('; '),
              redactedEvidence: inspection.suspiciousEntries.join('; '),
              remediation: 'Sanitize target paths during archive decompression using `path.resolve` and strict prefix checks.',
              cwe: ['CWE-22'],
              references: ['https://snyk.io/research/zip-slip-vulnerability/']
            });
          }
        }
      }
    }

    return {
      scannerId: this.id,
      name: this.name,
      status: 'completed',
      durationMs: Date.now() - startTime,
      filesScanned,
      findings
    };
  }
}
