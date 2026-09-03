import fs from 'node:fs';
import path from 'node:path';
import type { IScanner, ScannerResult } from '../../models/scanner.js';
import type { Finding } from '../../models/finding.js';
import type { ScanContext } from '../../core/context.js';
import { calculateShannonEntropy } from '../../utils/hashing.js';
import { sanitizeEvidence } from '../../utils/redact.js';

export class SuspiciousScanner implements IScanner {
  public readonly id = 'suspicious';
  public readonly name = 'Suspicious Code & Obfuscation Scanner';
  public readonly description = 'Detects obfuscated scripts, multi-layer encoding, dynamic reconstruction, and lifecycle script anomalies.';

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

    for (const file of ctx.files) {
      if (file.isBinary) continue;
      const base = path.basename(file.relativePath);

      if (base.endsWith('.min.js') || base.endsWith('.bundle.js') || base.endsWith('.min.css')) {
        continue;
      }

      let content: string;
      try {
        content = fs.readFileSync(file.path, 'utf-8');
      } catch {
        continue;
      }
      filesScanned++;

      if (base === 'package.json') {
        try {
          const pkg = JSON.parse(content);
          const scripts = pkg.scripts || {};
          for (const hook of ['preinstall', 'postinstall', 'install', 'preuninstall']) {
            const scriptCmd = scripts[hook];
            if (typeof scriptCmd === 'string') {
              if (/(?:curl|wget|powershell|bash|sh|node\s+-e)\s+/i.test(scriptCmd) && !scriptCmd.includes('node-gyp') && !scriptCmd.includes('patch-package')) {
                const evidence = sanitizeEvidence(`"${hook}": "${scriptCmd}"`);
                findings.push({
                  id: 'DC-SUSP-004',
                  scanner: this.id,
                  category: 'Potentially Dangerous',
                  severity: 'HIGH',
                  confidence: 85,
                  title: `Suspicious package lifecycle script '${hook}'`,
                  description: `Package '${hook}' script runs commands that may download external code during install: \`${scriptCmd.slice(0, 80)}\``,
                  file: file.relativePath,
                  evidence,
                  redactedEvidence: evidence,
                  remediation: 'Ensure lifecycle scripts do not download or execute untrusted remote code.',
                  cwe: ['CWE-506']
                });
              }
            }
          }
        } catch {
          // ignore
        }
      }

      if (
        /eval\s*\(\s*(?:String\.fromCharCode|atob|Buffer\.from\s*\([^)]*['"]base64['"]\))/i.test(content) ||
        /\b(?:Function|eval)\s*\(\s*["']\\x[0-9a-fA-F]{2}/i.test(content) ||
        (content.includes('String.fromCharCode') && /\beval\s*\(/.test(content))
      ) {
        findings.push({
          id: 'DC-SUSP-001',
          scanner: this.id,
          category: 'Suspicious',
          severity: 'HIGH',
          confidence: 85,
          title: 'Obfuscated dynamic payload execution (eval of decoded bytes/array)',
          description: 'Code decodes byte arrays or base64 strings and immediately executes them via `eval` or `Function`.',
          file: file.relativePath,
          evidence: 'eval(String.fromCharCode(...) / Buffer.from(..., "base64"))',
          redactedEvidence: 'eval(String.fromCharCode(...) / Buffer.from(..., "base64"))',
          remediation: 'Inspect decoded payload to ensure absence of malware.',
          cwe: ['CWE-506'],
          references: ['https://attack.mitre.org/techniques/T1027/']
        });
      }

      if (file.language === 'javascript' || file.language === 'typescript' || file.language === 'python') {
        const largeStringMatches = content.match(/['"`]([A-Za-z0-9+/=]{400,})['"`]/g);
        if (largeStringMatches) {
          for (const rawStr of largeStringMatches) {
            const cleanStr = rawStr.slice(1, -1);
            const entropy = calculateShannonEntropy(cleanStr);
            if (entropy > 5.5 && !cleanStr.includes('data:image')) {
              findings.push({
                id: 'DC-SUSP-002',
                scanner: this.id,
                category: 'Suspicious',
                severity: 'MEDIUM',
                confidence: 70,
                title: 'High-entropy embedded data block in source code',
                description: `Embedded payload string with Shannon entropy ${entropy.toFixed(2)} (${cleanStr.length} chars).`,
                file: file.relativePath,
                evidence: `${cleanStr.slice(0, 30)}... [${cleanStr.length} chars, entropy ${entropy.toFixed(2)}]`,
                redactedEvidence: `${cleanStr.slice(0, 30)}... [${cleanStr.length} chars, entropy ${entropy.toFixed(2)}]`,
                remediation: 'Verify whether the embedded payload is a legitimate compressed asset.',
                cwe: ['CWE-506']
              });
              break;
            }
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
