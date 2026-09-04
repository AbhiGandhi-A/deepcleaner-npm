import path from 'node:path';
import type { ScanContext } from './context.js';
import type { ScanResult } from '../models/scan-result.js';
import type { Finding } from '../models/finding.js';
import type { IScanner, ScannerResult } from '../models/scanner.js';
import { discoverFiles } from '../discovery/filesystem.js';
import { detectProjectTypes } from '../discovery/project-detector.js';
import { calculateRiskScore, calculateSummary } from '../scoring/risk-score.js';
import { SecretsScanner } from '../scanners/secrets/secrets-scanner.js';
import { DependencyScanner } from '../scanners/dependencies/dependency-scanner.js';
import { SastScanner } from '../scanners/sast/sast-scanner.js';
import { ConfigurationScanner } from '../scanners/configuration/configuration-scanner.js';
import { MalwareScanner } from '../scanners/malware/malware-scanner.js';
import { SuspiciousScanner } from '../scanners/suspicious/suspicious-scanner.js';
import { BinaryScanner } from '../scanners/binaries/binary-scanner.js';
import { ArchiveScanner } from '../scanners/archives/archive-scanner.js';
import { PermissionsScanner } from '../scanners/permissions/permissions-scanner.js';
import { GitScanner } from '../scanners/git/git-scanner.js';
import { YaraScanner } from '../scanners/yara/yara-scanner.js';
import { runAiFindingAnalysis } from '../ai/analyzer.js';
import { runDockerSandboxAnalysis } from '../sandbox/docker.js';

export const STANDARD_DISCLAIMERS = [
  'No automated security scanner can detect 100% of malware samples or software bugs.',
  'Static analysis findings may produce false positives; verify reachability in your application context.',
  'Dynamic sandbox analysis is strictly isolated and does not execute untrusted project build scripts.',
  'Vulnerability databases (such as OSV and NVD) are continuously updated and may be incomplete.',
  'AI-generated insights are advisory and must be verified by a security professional.'
];

export class ScanEngine {
  private scanners: IScanner[] = [
    new SecretsScanner(),
    new DependencyScanner(),
    new SastScanner(),
    new ConfigurationScanner(),
    new MalwareScanner(),
    new SuspiciousScanner(),
    new BinaryScanner(),
    new ArchiveScanner(),
    new PermissionsScanner(),
    new GitScanner(),
    new YaraScanner()
  ];

  async run(ctx: ScanContext, onProgress?: (step: number, total: number, message: string) => void): Promise<ScanResult> {
    const startTime = Date.now();
    ctx.startTime = startTime;

    if (onProgress) onProgress(1, 10, 'Discovering project files');
    const { files, ignoredPatterns, totalBytes } = await discoverFiles(ctx);
    ctx.files = files;

    const relPaths = files.map((f) => f.relativePath);
    const projDetection = detectProjectTypes(relPaths);

    const langCounts: Record<string, number> = {};
    for (const f of files) {
      if (f.language) {
        langCounts[f.language] = (langCounts[f.language] || 0) + 1;
      }
    }

    ctx.projectMetadata = {
      rootPath: ctx.absoluteTarget,
      name: path.basename(ctx.absoluteTarget) || 'project',
      projectTypes: projDetection.types,
      manifestFiles: projDetection.manifests,
      lockFiles: projDetection.lockfiles,
      totalFiles: files.length,
      totalBytes,
      hasGit: files.some((f) => f.relativePath.startsWith('.git')),
      languagesDetected: langCounts,
      ignoredPatterns
    };

    if (onProgress) onProgress(2, 10, `Discovered ${files.length} files (${(totalBytes / 1024 / 1024).toFixed(1)}MB)`);

    const scannerResults: Record<string, ScannerResult> = {};
    const allFindings: Finding[] = [];
    const skippedChecks: Array<{ name: string; reason: string }> = [];

    let stepIndex = 3;
    for (const scanner of this.scanners) {
      if (stepIndex <= 8 && onProgress) {
        onProgress(stepIndex, 10, `Running ${scanner.name}`);
      }
      stepIndex++;

      if (!scanner.shouldRun(ctx)) {
        scannerResults[scanner.id] = {
          scannerId: scanner.id,
          name: scanner.name,
          status: 'skipped',
          durationMs: 0,
          filesScanned: 0,
          findings: [],
          skipReason: 'Disabled by configuration or focus flags'
        };
        skippedChecks.push({ name: scanner.name, reason: 'Disabled by configuration or focus flags' });
        continue;
      }

      const isAvail = await scanner.isAvailable(ctx);
      if (!isAvail) {
        scannerResults[scanner.id] = {
          scannerId: scanner.id,
          name: scanner.name,
          status: 'unavailable',
          durationMs: 0,
          filesScanned: 0,
          findings: [],
          skipReason: `${scanner.name} prerequisites are not available on this host`
        };
        skippedChecks.push({ name: scanner.name, reason: 'Prerequisites not available' });
        continue;
      }

      try {
        const res = await scanner.scan(ctx);
        scannerResults[scanner.id] = res;
        allFindings.push(...res.findings);
        if (res.skipReason) {
          skippedChecks.push({ name: scanner.name, reason: res.skipReason });
        }
      } catch (err: any) {
        ctx.logger.error(`Scanner '${scanner.name}' encountered an error: ${err?.message || err}`);
        scannerResults[scanner.id] = {
          scannerId: scanner.id,
          name: scanner.name,
          status: 'error',
          durationMs: 0,
          filesScanned: 0,
          findings: [],
          error: err?.message || String(err)
        };
      }
    }

    if (ctx.options.sandbox || ctx.options.full) {
      const sandboxRes = await runDockerSandboxAnalysis(ctx);
      if (sandboxRes.status !== 'completed') {
        skippedChecks.push({ name: 'Docker Dynamic Sandbox', reason: sandboxRes.message });
      }
    }

    if (onProgress) onProgress(9, 10, 'AI Advisory Analysis');
    if (ctx.options.ai || ctx.options.full) {
      const aiResult = await runAiFindingAnalysis(ctx, allFindings);
      if (aiResult.status === 'skipped' || aiResult.status === 'unavailable') {
        skippedChecks.push({ name: 'AI Advisory Analysis', reason: aiResult.message });
      }
    } else {
      skippedChecks.push({ name: 'AI Advisory Analysis', reason: 'Not requested (use --ai or --full with GROQ_API_KEY)' });
    }

    if (onProgress) onProgress(10, 10, 'Compiling report');

    // Auto-classify findings based on confidence and behavioral evidence
    const { classifyFinding } = await import('../scoring/confidence.js');
    const { calculateClassifications, calculateSecurityFindings } = await import('../scoring/risk-score.js');

    for (const f of allFindings) {
      if (!f.classification) {
        f.classification = classifyFinding(f);
      }
    }

    const summary = calculateSummary(allFindings);
    const riskScore = calculateRiskScore(allFindings);
    const classifications = calculateClassifications(allFindings);
    const securityFindings = calculateSecurityFindings(allFindings);

    const hiddenFilesCount = files.filter((f) => path.basename(f.relativePath).startsWith('.')).length;
    const archivesInspected = files.filter((f) => f.isArchive).length;
    const binariesInspected = files.filter((f) => f.isBinary || f.isExecutable).length;
    const secretsDetected = allFindings.filter((f) => f.category === 'Secrets').length;
    const dependenciesAnalyzed = files.filter((f) => ['package.json', 'package-lock.json', 'yarn.lock', 'pnpm-lock.yaml', 'requirements.txt', 'composer.lock', 'go.mod'].includes(path.basename(f.relativePath))).length;

    const scanResult: ScanResult = {
      tool: {
        name: 'deepcleaner-ag',
        version: '1.0.5',
        homepage: 'https://github.com/AbhiGandhi-A/deepcleaner-npm#readme'
      },
      target: {
        path: ctx.targetPath,
        absolutePath: ctx.absoluteTarget
      },
      timestamp: new Date().toISOString(),
      durationMs: Date.now() - startTime,
      project: ctx.projectMetadata,
      riskScore,
      summary,
      classifications,
      securityFindings,
      metrics: {
        filesScanned: files.length,
        filesSkipped: 0,
        hiddenFilesScanned: hiddenFilesCount,
        archivesInspected,
        binariesInspected,
        secretsDetected,
        dependenciesAnalyzed
      },
      scanners: scannerResults,
      findings: allFindings,
      disclaimers: STANDARD_DISCLAIMERS,
      skippedChecks
    };

    return scanResult;
  }
}
