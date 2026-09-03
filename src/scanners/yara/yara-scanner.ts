import path from 'node:path';
import fs from 'node:fs';
import { fileURLToPath } from 'node:url';
import type { IScanner, ScannerResult } from '../../models/scanner.js';
import type { Finding } from '../../models/finding.js';
import type { ScanContext } from '../../core/context.js';
import { isExecutableAvailable, runCommandSafe } from '../../utils/process.js';
import { toRelative } from '../../utils/paths.js';

export class YaraScanner implements IScanner {
  public readonly id = 'yara';
  public readonly name = 'YARA Pattern Engine';
  public readonly description = 'Runs defensive YARA signature rules if the system YARA binary is available.';

  async isAvailable(_ctx: ScanContext): Promise<boolean> {
    return isExecutableAvailable('yara');
  }

  shouldRun(ctx: ScanContext): boolean {
    return ctx.isScannerEnabled(this.id);
  }

  async scan(ctx: ScanContext): Promise<ScannerResult> {
    const startTime = Date.now();
    const findings: Finding[] = [];

    const available = await this.isAvailable(ctx);
    if (!available) {
      return {
        scannerId: this.id,
        name: this.name,
        status: 'unavailable',
        durationMs: 0,
        filesScanned: 0,
        findings: [],
        skipReason: 'YARA engine: unavailable (yara executable not found in PATH)'
      };
    }

    ctx.logger.verbose('Running YARA pattern rules...');

    let rulesFile = path.resolve(process.cwd(), 'rules', 'yara', 'defensive-rules.yar');
    if (!fs.existsSync(rulesFile)) {
      try {
        const __dirname = path.dirname(fileURLToPath(import.meta.url));
        const candidate = path.resolve(__dirname, '../../../rules/yara/defensive-rules.yar');
        if (fs.existsSync(candidate)) {
          rulesFile = candidate;
        }
      } catch {
        // fallback
      }
    }

    if (!fs.existsSync(rulesFile)) {
      return {
        scannerId: this.id,
        name: this.name,
        status: 'skipped',
        durationMs: 0,
        filesScanned: 0,
        findings: [],
        skipReason: 'Defensive YARA rules file not found'
      };
    }

    try {
      const res = await runCommandSafe('yara', ['-r', rulesFile, ctx.absoluteTarget], {
        timeoutMs: ctx.limits.timeoutMs
      });

      if (res.exitCode === 0 && res.stdout) {
        const lines = res.stdout.split(/\r?\n/);
        for (const line of lines) {
          const match = line.match(/^([A-Za-z0-9_]+)\s+(.+)$/);
          if (match) {
            const ruleName = match[1];
            const matchedFile = match[2];
            const relFile = toRelative(matchedFile, ctx.absoluteTarget);

            findings.push({
              id: 'DC-MAL-001',
              scanner: this.id,
              category: 'Malware Indicator',
              severity: 'HIGH',
              confidence: 90,
              title: `YARA rule matched: ${ruleName}`,
              description: `Target file matched defensive YARA signature \`${ruleName}\`.`,
              file: relFile,
              evidence: `YARA Match: ${ruleName}`,
              redactedEvidence: `YARA Match: ${ruleName}`,
              remediation: 'Inspect file contents and origin.',
              cwe: ['CWE-506']
            });
          }
        }
      }
    } catch {
      // Graceful error handling
    }

    return {
      scannerId: this.id,
      name: this.name,
      status: 'completed',
      durationMs: Date.now() - startTime,
      filesScanned: ctx.files.length,
      findings
    };
  }
}
