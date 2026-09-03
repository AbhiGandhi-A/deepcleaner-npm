import path from 'node:path';
import fs from 'node:fs';
import type { IScanner, ScannerResult } from '../../models/scanner.js';
import type { Finding } from '../../models/finding.js';
import type { ScanContext } from '../../core/context.js';
import { runCommandSafe, isExecutableAvailable } from '../../utils/process.js';
import { SECRET_RULES } from '../../rules/secrets/index.js';
import { maskSecret, sanitizeEvidence } from '../../utils/redact.js';
import { isPlaceholderOrTestValue } from '../../scoring/confidence.js';

export class GitScanner implements IScanner {
  public readonly id = 'git';
  public readonly name = 'Git History Secret Scanner';
  public readonly description = 'Scans recent commit history for accidentally committed API keys, tokens, and credentials.';

  async isAvailable(ctx: ScanContext): Promise<boolean> {
    const gitDir = path.join(ctx.absoluteTarget, '.git');
    if (!fs.existsSync(gitDir)) return false;
    return isExecutableAvailable('git');
  }

  shouldRun(ctx: ScanContext): boolean {
    return (ctx.options.deep === true || ctx.options.full === true || ctx.options.secrets === true) && ctx.isScannerEnabled(this.id);
  }

  async scan(ctx: ScanContext): Promise<ScannerResult> {
    const startTime = Date.now();
    const findings: Finding[] = [];

    const available = await this.isAvailable(ctx);
    if (!available) {
      return {
        scannerId: this.id,
        name: this.name,
        status: 'skipped',
        durationMs: 0,
        filesScanned: 0,
        findings: [],
        skipReason: 'Not a git repository or git binary not available'
      };
    }

    ctx.logger.verbose('Scanning Git commit history for committed secrets...');

    try {
      const res = await runCommandSafe('git', ['log', '-p', '-n', '30', '--no-color'], {
        cwd: ctx.absoluteTarget,
        timeoutMs: 15000
      });

      if (res.exitCode === 0 && res.stdout) {
        const diffText = res.stdout;
        const lines = diffText.split(/\r?\n/);
        let currentCommit = 'HEAD';
        let currentFile = 'git-history';

        for (let i = 0; i < lines.length; i++) {
          const line = lines[i];
          if (line.startsWith('commit ')) {
            currentCommit = line.slice(7, 15);
          } else if (line.startsWith('+++ b/')) {
            currentFile = line.slice(6);
          } else if (line.startsWith('+') && !line.startsWith('+++')) {
            const addedLine = line.slice(1);

            for (const rule of SECRET_RULES) {
              rule.regex.lastIndex = 0;
              let match: RegExpExecArray | null;

              while ((match = rule.regex.exec(addedLine)) !== null) {
                const matchedVal = match[1] || match[0];
                if (!matchedVal || matchedVal.length < 6) continue;
                if (isPlaceholderOrTestValue(matchedVal)) continue;

                const maskedToken = maskSecret(matchedVal);
                const evidence = sanitizeEvidence(addedLine.trim());

                findings.push({
                  id: rule.id,
                  scanner: this.id,
                  category: 'Git History',
                  severity: rule.defaultSeverity,
                  confidence: 90,
                  title: `${rule.name} committed in Git history (commit ${currentCommit})`,
                  description: `${rule.description}. Exposed secret value in commit ${currentCommit} (${currentFile}): ${maskedToken}`,
                  file: currentFile,
                  line: i + 1,
                  evidence: `[Git Commit ${currentCommit}] ${evidence}`,
                  redactedEvidence: `[Git Commit ${currentCommit}] ${evidence}`,
                  remediation: 'Rotate the exposed secret immediately and consider purging commit history with git-filter-repo.',
                  cwe: rule.cwe,
                  references: rule.references
                });
              }
            }
          }
        }
      }
    } catch {
      // Continue gracefully
    }

    return {
      scannerId: this.id,
      name: this.name,
      status: 'completed',
      durationMs: Date.now() - startTime,
      filesScanned: findings.length,
      findings
    };
  }
}
