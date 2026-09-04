import fs from 'node:fs';
import type { IScanner, ScannerResult } from '../../models/scanner.js';
import type { Finding } from '../../models/finding.js';
import type { ScanContext } from '../../core/context.js';
import { extractPrintableStrings } from '../../utils/files.js';

export class BinaryScanner implements IScanner {
  public readonly id = 'binaries';
  public readonly name = 'Binary & Executable Inspector';
  public readonly description = 'Inspects PE, ELF, and Mach-O binaries for suspicious embedded strings and commands without execution.';

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

    const binaryFiles = ctx.files.filter((f) => f.isBinary || f.isExecutable);

    for (const file of binaryFiles) {
      filesScanned++;
      let buffer: Buffer;
      try {
        buffer = fs.readFileSync(file.path);
      } catch {
        continue;
      }

      if (['exe', 'dll', 'so', 'dylib', 'bin'].includes(file.extension)) {
        findings.push({
          id: 'DC-MAL-005',
          scanner: this.id,
          category: 'Binary',
          severity: 'LOW',
          confidence: 60,
          classification: 'needs_review',
          title: `Pre-compiled binary executable present in repository (${file.extension.toUpperCase()})`,
          description: `Executable binary file '${file.relativePath}' is committed in the workspace. Pre-compiled binaries can conceal backdoors.`,
          file: file.relativePath,
          evidence: `Binary file: ${file.relativePath} (${(file.size / 1024).toFixed(1)} KB)`,
          redactedEvidence: `Binary file: ${file.relativePath} (${(file.size / 1024).toFixed(1)} KB)`,
          detectionMethod: 'Static PE/ELF Header Analysis',
          whyItIsSuspicious: 'Pre-compiled binary file without verifiable source compilation artifact.',
          remediation: 'Build binaries from audited source code rather than committing pre-compiled binaries.',
          cwe: ['CWE-506']
        });
      }

      const strings = extractPrintableStrings(buffer, 5, 3000);
      const joinedStrings = strings.join('\n');

      if (
        /powershell.*-(?:enc|encodedcommand)|IEX\s*\(New-Object|cmd\.exe\s*\/c|nc\s+-e\s+\/bin\/sh|\/bin\/bash\s+-i|HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Run/i.test(
          joinedStrings
        )
      ) {
        findings.push({
          id: 'DC-MAL-001',
          scanner: this.id,
          category: 'Binary',
          severity: 'CRITICAL',
          confidence: 90,
          classification: 'potentially_malicious',
          title: 'Binary contains suspicious command execution / persistence strings',
          description: `Binary file '${file.relativePath}' contains embedded strings matching shell invocation, encoded PowerShell, or registry persistence.`,
          file: file.relativePath,
          evidence: `Binary string signatures matched in ${file.relativePath}`,
          redactedEvidence: `Binary string signatures matched in ${file.relativePath}`,
          detectionMethod: 'Binary Static String Heuristics',
          whyItIsSuspicious: 'Embedded reverse-shell or encoded PowerShell command signatures found inside binary payload.',
          remediation: 'Do not execute this binary. Perform deeper static disassembly / sandbox analysis.',
          cwe: ['CWE-506']
        });
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
