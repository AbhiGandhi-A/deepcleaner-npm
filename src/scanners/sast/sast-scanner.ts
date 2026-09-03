import fs from 'node:fs';
import type { IScanner, ScannerResult } from '../../models/scanner.js';
import type { Finding } from '../../models/finding.js';
import type { ScanContext } from '../../core/context.js';
import { analyzeJavaScriptAst } from '../../languages/javascript/ast-analyzer.js';
import { analyzePythonCode } from '../../languages/python/python-analyzer.js';
import { analyzePhpCode } from '../../languages/php/php-analyzer.js';
import { analyzeGenericCode } from '../../languages/generic/generic-analyzer.js';
import { mapConcurrent } from '../../core/scheduler.js';

export class SastScanner implements IScanner {
  public readonly id = 'sast';
  public readonly name = 'Static Application Security Testing (SAST)';
  public readonly description = 'Analyzes source code AST and patterns for injection, XSS, insecure deserialization, SSRF, and dangerous APIs.';

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

    const codeFiles = ctx.files.filter((f) => !f.isBinary && f.language && f.size < ctx.limits.maxFileSize);

    await mapConcurrent(codeFiles, ctx.limits.concurrency, async (file) => {
      filesScanned++;
      let content: string;
      try {
        content = fs.readFileSync(file.path, 'utf-8');
      } catch {
        return;
      }

      if (file.language === 'javascript' || file.language === 'typescript') {
        const jsFindings = analyzeJavaScriptAst({
          filePath: file.path,
          relativePath: file.relativePath,
          code: content
        });
        findings.push(...jsFindings);
      }

      if (file.language === 'python') {
        const pyFindings = analyzePythonCode(file.path, file.relativePath, content);
        findings.push(...pyFindings);
      }

      if (file.language === 'php') {
        const phpFindings = analyzePhpCode(file.path, file.relativePath, content);
        findings.push(...phpFindings);
      }

      const genericFindings = analyzeGenericCode(file.path, file.relativePath, content, file.language);
      findings.push(...genericFindings);
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
