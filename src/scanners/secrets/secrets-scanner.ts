import fs from 'node:fs';
import type { IScanner, ScannerResult } from '../../models/scanner.js';
import type { Finding } from '../../models/finding.js';
import type { ScanContext } from '../../core/context.js';
import { SECRET_RULES } from '../../rules/secrets/index.js';
import { calculateShannonEntropy } from '../../utils/hashing.js';
import { maskSecret, sanitizeEvidence } from '../../utils/redact.js';
import { isPlaceholderOrTestValue, adjustConfidence } from '../../scoring/confidence.js';
import { mapConcurrent } from '../../core/scheduler.js';

export class SecretsScanner implements IScanner {
  public readonly id = 'secrets';
  public readonly name = 'Secret & Credential Scanner';
  public readonly description = 'Detects exposed API keys, private certificates, tokens, database credentials, and high-entropy secrets.';

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

    const targetFiles = ctx.files.filter((f) => !f.isBinary && f.size < ctx.limits.maxFileSize);

    await mapConcurrent(targetFiles, ctx.limits.concurrency, async (file) => {
      filesScanned++;
      let content: string;
      try {
        content = fs.readFileSync(file.path, 'utf-8');
      } catch {
        return;
      }

      const isTestFile =
        file.relativePath.includes('test') ||
        file.relativePath.includes('fixture') ||
        file.relativePath.includes('mock') ||
        file.relativePath.includes('spec');

      const lines = content.split(/\r?\n/);

      for (const rule of SECRET_RULES) {
        rule.regex.lastIndex = 0;
        let match: RegExpExecArray | null;

        while ((match = rule.regex.exec(content)) !== null) {
          const matchedSecret = match[1] || match[0];
          if (!matchedSecret || matchedSecret.length < 6) continue;

          const isPlaceholder = isPlaceholderOrTestValue(matchedSecret);

          let entropy: number | undefined;
          if (rule.minEntropy !== undefined) {
            entropy = calculateShannonEntropy(matchedSecret);
            if (entropy < rule.minEntropy) {
              continue;
            }
          }

          const matchOffset = match.index;
          const preMatch = content.slice(0, matchOffset);
          const lineNum = preMatch.split('\n').length;
          const lineContent = lines[lineNum - 1] || '';

          const confidence = adjustConfidence(rule.defaultConfidence, {
            isTestFile,
            isPlaceholder,
            entropy
          });

          const maskedToken = maskSecret(matchedSecret);
          const evidence = sanitizeEvidence(lineContent.trim());

          findings.push({
            id: rule.id,
            scanner: this.id,
            category: 'Secrets',
            severity: isPlaceholder ? 'LOW' : rule.defaultSeverity,
            confidence,
            title: `${rule.name} detected`,
            description: `${rule.description}. Exposed secret value: ${maskedToken}`,
            file: file.relativePath,
            line: lineNum,
            evidence,
            redactedEvidence: evidence,
            remediation: rule.remediation,
            cwe: rule.cwe,
            references: rule.references
          });
        }
      }
    });

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
