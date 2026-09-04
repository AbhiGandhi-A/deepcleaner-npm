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

    const isContainer =
      fs.existsSync('/.dockerenv') ||
      process.env.CODESPACES === 'true' ||
      process.env.REMOTE_CONTAINERS === 'true' ||
      process.env.GITHUB_ACTIONS === 'true';

    for (const file of ctx.files) {
      filesScanned++;
      try {
        const stats = fs.statSync(file.path);
        const mode = stats.mode;
        const octal = (mode & 0o777).toString(8);
        const isWorldWritable = (mode & 0o002) !== 0;
        const isWorldExecutable = (mode & 0o001) !== 0;

        if (!isWorldWritable) continue;

        // Determine if security-critical
        const isSensitiveFile =
          file.relativePath.startsWith('.env') ||
          file.relativePath.includes('id_rsa') ||
          file.relativePath.endsWith('.key') ||
          file.relativePath.endsWith('.pem') ||
          file.relativePath.endsWith('.npmrc');

        const isExecutableScript =
          isWorldExecutable ||
          ['.sh', '.bash', '.ps1', '.py', '.rb'].some((ext) => file.relativePath.endsWith(ext));

        if (isSensitiveFile) {
          findings.push({
            id: 'DC-PERM-001',
            scanner: this.id,
            category: 'Permissions',
            severity: 'HIGH',
            confidence: 90,
            classification: 'potentially_malicious',
            title: `World-writable sensitive credential/configuration file (${file.relativePath})`,
            description: `Sensitive file '${file.relativePath}' has world-writable mode (${octal}), permitting unauthorized tampering.`,
            file: file.relativePath,
            evidence: `Permissions mode: ${octal} (owner: ${stats.uid}, group: ${stats.gid})`,
            redactedEvidence: `Permissions mode: ${octal}`,
            detectionMethod: 'Filesystem Inode Access Control Audit',
            whyItIsSuspicious: 'Sensitive key/credential file is writeable by any local user.',
            remediation: `Run \`chmod 600 "${file.relativePath}"\` to restrict access to owner only.`,
            cwe: ['CWE-732']
          });
        } else if (isExecutableScript && !isContainer) {
          findings.push({
            id: 'DC-PERM-002',
            scanner: this.id,
            category: 'Permissions',
            severity: 'MEDIUM',
            confidence: 75,
            classification: 'needs_review',
            title: `World-writable executable script (${file.relativePath})`,
            description: `Executable script '${file.relativePath}' has world-writable mode (${octal}).`,
            file: file.relativePath,
            evidence: `Permissions mode: ${octal}`,
            redactedEvidence: `Permissions mode: ${octal}`,
            detectionMethod: 'Filesystem Inode Access Control Audit',
            whyItIsSuspicious: 'Executable script can be modified by non-privileged accounts.',
            remediation: `Run \`chmod 755 "${file.relativePath}"\` to remove other-write permissions.`,
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
