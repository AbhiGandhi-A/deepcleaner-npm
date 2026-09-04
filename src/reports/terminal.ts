import pc from 'picocolors';
import type { ScanResult } from '../models/scan-result.js';
import type { Finding, Severity } from '../models/finding.js';

export function renderSeverityBadge(sev: Severity): string {
  switch (sev) {
    case 'CRITICAL':
      return pc.bgRed(pc.white(pc.bold(' CRITICAL ')));
    case 'HIGH':
      return pc.red(pc.bold(' HIGH '));
    case 'MEDIUM':
      return pc.yellow(pc.bold(' MEDIUM '));
    case 'LOW':
      return pc.blue(' LOW ');
    case 'INFO':
      return pc.dim(' INFO ');
  }
}

export function renderTerminalReport(result: ScanResult, verbose = false): string {
  const lines: string[] = [];

  lines.push('');
  lines.push(pc.cyan('╔═══════════════════════════════════════════════════════════╗'));
  lines.push(pc.cyan('║') + pc.bold('                      DEEPCLEANER AG                       ') + pc.cyan('║'));
  lines.push(pc.cyan('║') + pc.dim('         Deep Local Security & Malware Scanner             ') + pc.cyan('║'));
  lines.push(pc.cyan('╚═══════════════════════════════════════════════════════════╝'));
  lines.push('');

  lines.push(pc.bold('Target: ') + pc.white(result.target.absolutePath));
  lines.push(
    pc.bold('Project: ') +
      pc.magenta(result.project.projectTypes.join(', ').toUpperCase()) +
      pc.dim(` (${result.project.totalFiles} files, ${(result.project.totalBytes / 1024 / 1024).toFixed(2)} MB, scanned in ${result.durationMs}ms)`)
  );
  lines.push('');

  lines.push(pc.bold('Scanner Coverage:'));
  for (const [id, sc] of Object.entries(result.scanners)) {
    if (sc.status === 'completed') {
      lines.push(`  ${pc.green('✓')} ${sc.name} ${pc.dim(`(${sc.findings.length} findings, ${sc.durationMs}ms)`)}`);
    } else if (sc.status === 'unavailable') {
      lines.push(`  ${pc.yellow('⊘')} ${sc.name} ${pc.dim(`[Unavailable: ${sc.skipReason || 'prerequisites missing'}]`)}`);
    } else if (sc.status === 'skipped') {
      lines.push(`  ${pc.dim('○')} ${sc.name} ${pc.dim(`[Skipped: ${sc.skipReason || 'not requested'}]`)}`);
    } else {
      lines.push(`  ${pc.red('✗')} ${sc.name} ${pc.dim(`[Error: ${sc.error}]`)}`);
    }
  }
  lines.push('');

  lines.push(pc.cyan('─────────────────────────────────────────────────────────────'));
  lines.push(pc.bold('SECURITY RESULT & CLASSIFICATION SUMMARY'));
  lines.push('');

  const m = result.metrics;
  const cls = result.classifications;
  const sec = result.securityFindings;

  if (m) {
    lines.push(
      `  Files scanned: ${pc.bold(m.filesScanned.toString())} | Hidden files: ${pc.bold(m.hiddenFilesScanned.toString())} | ` +
      `Archives: ${pc.bold(m.archivesInspected.toString())} | Binaries: ${pc.bold(m.binariesInspected.toString())}`
    );
    lines.push(
      `  Secrets detected: ${pc.bold(m.secretsDetected.toString())} | Dependencies analyzed: ${pc.bold(m.dependenciesAnalyzed.toString())}`
    );
    lines.push('');
  }

  if (cls) {
    lines.push(pc.bold('MALWARE ANALYSIS'));
    let malStyle = cls.confirmedMalware > 0 ? pc.bgRed(pc.white(pc.bold(` ${cls.confirmedMalware} `))) : pc.green('0');
    let potStyle = cls.potentiallyMalicious > 0 ? pc.red(pc.bold(cls.potentiallyMalicious.toString())) : pc.dim('0');
    let suspStyle = cls.suspicious > 0 ? pc.yellow(pc.bold(cls.suspicious.toString())) : pc.dim('0');
    let revStyle = cls.needsReview > 0 ? pc.blue(pc.bold(cls.needsReview.toString())) : pc.dim('0');

    lines.push(
      `  Confirmed Malware: ${malStyle}   ` +
      `  Potentially Malicious: ${potStyle}   ` +
      `  Suspicious Indicators: ${suspStyle}   ` +
      `  Needs Review: ${revStyle}`
    );
    lines.push('');
  }

  if (sec) {
    lines.push(pc.bold('SECURITY FINDINGS'));
    let depStr = `${sec.dependencies}`;
    if (sec.dependenciesSeverity) {
      const parts: string[] = [];
      if (sec.dependenciesSeverity.critical > 0) parts.push(`${sec.dependenciesSeverity.critical} CRITICAL`);
      if (sec.dependenciesSeverity.high > 0) parts.push(`${sec.dependenciesSeverity.high} HIGH`);
      if (sec.dependenciesSeverity.medium > 0) parts.push(`${sec.dependenciesSeverity.medium} MEDIUM`);
      if (sec.dependenciesSeverity.low > 0) parts.push(`${sec.dependenciesSeverity.low} LOW`);
      if (parts.length > 0) depStr += ` (${parts.join(', ')})`;
    }

    lines.push(`  Dependency Vulnerabilities: ${pc.bold(depStr)}`);
    lines.push(`  Permission Issues:          ${pc.bold(sec.permissions.toString())}`);
    lines.push(`  Secrets & Exposed Keys:     ${pc.bold(sec.secrets.toString())}`);
    lines.push(`  SAST Code Vulnerabilities:  ${pc.bold(sec.sast.toString())}`);
    lines.push(`  Security Configuration:     ${pc.bold(sec.configuration.toString())}`);
    lines.push('');
  }

  let scoreColor = pc.green;
  if (result.riskScore.score > 70) scoreColor = pc.red;
  else if (result.riskScore.score > 35) scoreColor = pc.yellow;

  lines.push(
    `Risk Score: ${scoreColor(pc.bold(`${result.riskScore.score}/100`))} ` +
      `[Grade: ${scoreColor(pc.bold(result.riskScore.grade))}] - ${pc.dim(result.riskScore.explanation)}`
  );

  if (result.riskScore.contributors) {
    const c = result.riskScore.contributors;
    lines.push(
      pc.dim(
        `  (Contributors: Dependencies: ${c.dependencies}, Malware: ${c.malware}, Secrets: ${c.secrets}, SAST: ${c.sast}, Config: ${c.configuration}, Perms: ${c.permissions})`
      )
    );
  }
  lines.push('');

  lines.push(
    `  ${pc.bgRed(pc.white(pc.bold(' CRITICAL ')))} ${result.summary.critical.toString().padStart(4)}   ` +
      `  ${pc.red(pc.bold(' HIGH '))} ${result.summary.high.toString().padStart(4)}   ` +
      `  ${pc.yellow(pc.bold(' MEDIUM '))} ${result.summary.medium.toString().padStart(4)}   ` +
      `  ${pc.blue(' LOW ')} ${result.summary.low.toString().padStart(4)}   ` +
      `  ${pc.dim(' INFO ')} ${result.summary.info.toString().padStart(4)}`
  );
  lines.push(pc.cyan('─────────────────────────────────────────────────────────────'));
  lines.push('');

  if (result.findings.length === 0) {
    lines.push(pc.green(pc.bold('✔ No security vulnerabilities or malware indicators discovered!')));
    lines.push('');
  } else {
    const sorted = [...result.findings].sort((a, b) => {
      const order: Record<Severity, number> = { CRITICAL: 5, HIGH: 4, MEDIUM: 3, LOW: 2, INFO: 1 };
      return order[b.severity] - order[a.severity];
    });

    lines.push(pc.bold(`Discovered Findings (${sorted.length}):`));
    lines.push('');

    for (const f of sorted) {
      lines.push(`${renderSeverityBadge(f.severity)} ${pc.bold(f.title)} ${pc.dim(`[${f.id}]`)}`);
      lines.push(`  ${pc.cyan('Location:')}   ${pc.white(f.file)}${f.line ? pc.yellow(`:${f.line}`) : ''}`);
      lines.push(`  ${pc.cyan('Scanner:')}    ${pc.dim(f.scanner)} | Category: ${pc.dim(f.category)} | Confidence: ${pc.green(`${f.confidence}%`)}`);

      if (f.redactedEvidence || f.evidence) {
        lines.push(`  ${pc.cyan('Evidence:')}   ${pc.dim(f.redactedEvidence || f.evidence)}`);
      }

      if (f.taintPath && f.taintPath.length > 0) {
        lines.push(`  ${pc.magenta('Taint Flow:')}`);
        for (const step of f.taintPath) {
          lines.push(`    ${pc.magenta('↳')} [Line ${step.line}] ${step.description}`);
        }
      }

      if (f.aiAnalysis) {
        lines.push(`  ${pc.cyan('AI Verdict:')} ${pc.bold(f.aiAnalysis.verdict.toUpperCase())} (Confidence: ${f.aiAnalysis.confidence}%)`);
        lines.push(`  ${pc.cyan('AI Review:')}  ${f.aiAnalysis.reasoningSummary || f.aiAnalysis.explanation}`);
      }

      if (f.remediation) {
        lines.push(`  ${pc.green('Remedy:')}     ${f.remediation}`);
      }
      lines.push('');
    }
  }

  lines.push(pc.dim('─────────────────────────────────────────────────────────────'));
  lines.push(pc.dim('Safety Disclaimers:'));
  for (const d of result.disclaimers) {
    lines.push(pc.dim(`• ${d}`));
  }
  lines.push('');

  return lines.join('\n');
}
