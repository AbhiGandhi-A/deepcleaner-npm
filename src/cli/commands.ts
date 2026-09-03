import path from 'node:path';
import fs from 'node:fs';
import pc from 'picocolors';
import type { CliOptions, UserConfig } from '../core/context.js';
import { ScanContext } from '../core/context.js';
import { ScanEngine } from '../core/engine.js';
import { ProgressReporter } from './output.js';
import { renderTerminalReport } from '../reports/terminal.js';
import { renderJsonReport } from '../reports/json.js';
import { renderHtmlReport } from '../reports/html.js';
import { renderSarifReport } from '../reports/sarif.js';
import { isSeverityAtLeast } from '../scoring/severity.js';
import { createBaseline, applyBaseline } from '../utils/baseline.js';
import { runDoctor, renderDoctorReport } from './doctor.js';
import { saveScanResultToMongo } from '../storage/mongodb.js';

export function loadUserConfig(targetDir: string): UserConfig {
  const configNames = ['.deepcleanerrc.json', '.deepcleanerrc', '.deepcleaner.json'];
  for (const name of configNames) {
    const p = path.join(targetDir, name);
    if (fs.existsSync(p)) {
      try {
        const content = fs.readFileSync(p, 'utf-8');
        return JSON.parse(content);
      } catch {
        // ignore
      }
    }
  }
  return {};
}

export async function executeDoctor(): Promise<number> {
  const checks = await runDoctor();
  console.log(renderDoctorReport(checks));
  const hasErrors = checks.some((c) => c.status === 'error');
  return hasErrors ? 1 : 0;
}

export async function executeScan(target: string, options: CliOptions): Promise<number> {
  const absoluteTarget = path.resolve(process.cwd(), target);

  if (!fs.existsSync(absoluteTarget)) {
    console.error(pc.red(`Error: Target path does not exist: ${absoluteTarget}`));
    return 2;
  }

  const userConfig = loadUserConfig(absoluteTarget);
  const ctx = new ScanContext(absoluteTarget, options, userConfig);

  if (options.verbose) {
    ctx.logger.setLevel('verbose');
  } else if (options.quiet) {
    ctx.logger.setLevel('quiet');
  }

  if (options.json) {
    ctx.logger.setJsonMode(true);
  }

  if (options.offline && !options.json && !options.quiet) {
    ctx.logger.info(pc.yellow('⚡ Offline mode enabled (external intelligence queries disabled)'));
  }

  const progress = new ProgressReporter(options.json, options.quiet);
  const engine = new ScanEngine();

  const scanResult = await engine.run(ctx, (step, total, msg) => {
    progress.report(step, total, msg);
  });
  progress.clear();

  // Handle Baseline Creation
  if (options.baselineCreate) {
    try {
      const baseline = createBaseline(scanResult.findings, options.baselineCreate);
      if (!options.json && !options.quiet) {
        console.log(pc.green(`✓ Baseline created: ${options.baselineCreate} (${baseline.findingsCount} findings recorded)`));
      }
    } catch (err: any) {
      console.error(pc.red(`Failed to write baseline file: ${err?.message || err}`));
      return 2;
    }
  }

  // Handle Baseline Suppression
  let suppressedCount = 0;
  if (options.baseline) {
    try {
      const baselineResult = applyBaseline(scanResult.findings, options.baseline);
      scanResult.findings = baselineResult.activeFindings;
      suppressedCount = baselineResult.suppressedCount;
      if (!options.json && !options.quiet && suppressedCount > 0) {
        console.log(pc.dim(`⚡ Baseline applied: ${suppressedCount} previously known findings suppressed.`));
      }
    } catch (err: any) {
      console.error(pc.red(`Failed to load baseline file: ${err?.message || err}`));
      return 2;
    }
  }

  // Handle MongoDB Storage Push
  if (options.mongodb || process.env.MONGODB_URI) {
    const customUri = typeof options.mongodb === 'string' ? options.mongodb : undefined;
    const mongoRes = await saveScanResultToMongo(scanResult, customUri);
    if (!options.json && !options.quiet) {
      if (mongoRes.success) {
        console.log(pc.green(`✓ Scan report pushed to MongoDB collection '${mongoRes.collection}' (id: ${mongoRes.insertedId})`));
      } else if (options.mongodb) {
        console.log(pc.yellow(`○ MongoDB push skipped/failed: ${mongoRes.error}`));
      }
    }
  }

  if (options.json) {
    const jsonOutput = renderJsonReport(scanResult);
    if (options.outputFile) {
      fs.writeFileSync(path.resolve(process.cwd(), options.outputFile), jsonOutput, 'utf-8');
    } else {
      console.log(jsonOutput);
    }
  } else if (options.sarif) {
    const sarifOutput = renderSarifReport(scanResult);
    if (options.outputFile) {
      fs.writeFileSync(path.resolve(process.cwd(), options.outputFile), sarifOutput, 'utf-8');
      console.log(pc.green(`SARIF report written to ${options.outputFile}`));
    } else {
      console.log(sarifOutput);
    }
  } else {
    const terminalReport = renderTerminalReport(scanResult, options.verbose);
    console.log(terminalReport);

    if (options.html) {
      const htmlOutput = renderHtmlReport(scanResult);
      const htmlPath = options.outputFile || 'deepcleaner-report.html';
      fs.writeFileSync(path.resolve(process.cwd(), htmlPath), htmlOutput, 'utf-8');
      console.log(pc.green(`✓ Standalone HTML report generated: ${htmlPath}`));
    }
  }

  if (options.fix && scanResult.findings.length > 0) {
    console.log(pc.bold('\n--- SAFE FIX SUGGESTIONS ---'));
    for (const f of scanResult.findings) {
      if (f.remediation) {
        console.log(`\n${pc.bold('File:')} ${f.file}${f.line ? `:${f.line}` : ''}`);
        console.log(`${pc.cyan('Finding:')} ${f.title}`);
        console.log(`${pc.green('Suggested Fix:')} ${f.remediation}`);
      }
    }
    console.log(pc.dim('\nRun fixes manually or review proposed transformations before applying.'));
  }

  if (options.ci) {
    const failThreshold = options.failOn || userConfig.failOn || 'high';
    const thresholdExceeded = scanResult.findings.some((f) => isSeverityAtLeast(f.severity, failThreshold));
    if (thresholdExceeded) {
      if (!options.json && !options.quiet) {
        console.error(pc.red(`\nCI Check Failed: Findings exceeded configured threshold (${failThreshold.toUpperCase()})`));
      }
      return 1;
    }
  }

  return 0;
}
