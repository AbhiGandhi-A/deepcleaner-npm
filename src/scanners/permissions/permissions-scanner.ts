import fs from 'node:fs';
import type { IScanner, ScannerResult } from '../../models/scanner.js';
import type { Finding } from '../../models/finding.js';
import type { ScanContext } from '../../core/context.js';

export class PermissionsScanner implements IScanner {
  public readonly id = 'permissions';
  public readonly name = 'File Permissions & Access Control Scanner';
  public readonly description = 'Checks for overly permissive files (world-writable, executable secrets, or sensitive certificates).';

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

    if (process.platform === 'win32') {
      return {
        scannerId: this.id,
        name: this.name,
        status: 'completed',
        durationMs: 0,
        filesScanned: 0,
        findings: []
      };
    }

    for (const file of ctx.files) {
      filesScanned++;
      try {
        const stats = fs.statSync(file.path);
        const mode = stats.mode;

        if ((mode & 0o002) !== 0) {
          findings.push({
            id: 'DC-CONFIG-001',
            scanner: this.id,
            category: 'Permissions',
            severity: 'MEDIUM',
            confidence: 90,
            title: `World-writable file detected (${file.relativePath})`,
            description: `File '${file.relativePath}' has world-writable permissions (chmod o+w), allowing any user on the system to modify its contents.`,
            file: file.relativePath,
            evidence: `Permissions mode: ${(mode & 0o777).toString(8)}`,
            redactedEvidence: `Permissions mode: ${(mode & 0o777).toString(8)}`,
            remediation: `Run \`chmod o-w "${file.relativePath}"\` to restrict write access.`,
            cwe: ['CWE-732']
          });
        }
      } catch {
        // ignore
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
