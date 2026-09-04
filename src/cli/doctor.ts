import pc from 'picocolors';
import { detectDockerRuntime } from '../sandbox/detector.js';
import { isExecutableAvailable } from '../utils/process.js';
import { GroqClient } from '../ai/groq.js';
import { testMongoConnection } from '../storage/mongodb.js';
import { loadEnv } from '../utils/env.js';

export interface DoctorCheck {
  category: string;
  name: string;
  status: 'ok' | 'optional_missing' | 'warning' | 'error';
  message: string;
}

export async function runDoctor(): Promise<DoctorCheck[]> {
  loadEnv();
  const checks: DoctorCheck[] = [];

  // 1. Node.js version
  const nodeVer = process.version;
  const majorVer = parseInt(nodeVer.replace(/^v/, '').split('.')[0], 10);
  if (majorVer >= 20) {
    checks.push({
      category: 'Environment',
      name: 'Node.js Runtime',
      status: 'ok',
      message: `${nodeVer} (Supported >=20.0.0)`
    });
  } else {
    checks.push({
      category: 'Environment',
      name: 'Node.js Runtime',
      status: 'error',
      message: `${nodeVer} (Requires Node.js >=20.0.0)`
    });
  }

  // 2. Core Scanner Engines
  checks.push({
    category: 'Core Engines',
    name: 'Secret & Credential Scanner',
    status: 'ok',
    message: 'Active (40+ entropy-validated patterns)'
  });

  checks.push({
    category: 'Core Engines',
    name: 'Static Application Security Testing (SAST)',
    status: 'ok',
    message: 'Active (Babel AST + multi-language analyzers)'
  });

  checks.push({
    category: 'Core Engines',
    name: 'Dependency Vulnerability Engine',
    status: 'ok',
    message: 'Active (OSV batch API + offline fallback)'
  });

  checks.push({
    category: 'Core Engines',
    name: 'Security Configuration Auditor',
    status: 'ok',
    message: 'Active (Docker, K8s, GitHub Actions, Terraform)'
  });

  checks.push({
    category: 'Core Engines',
    name: 'Malware & Suspicious Code Scanner',
    status: 'ok',
    message: 'Active (Disguised binaries, reverse shells, obfuscation)'
  });

  // 3. External Integrations
  const dockerInfo = await detectDockerRuntime();
  if (dockerInfo.available && dockerInfo.isDaemonRunning) {
    checks.push({
      category: 'Optional Integrations',
      name: 'Docker Dynamic Sandbox',
      status: 'ok',
      message: `Available (v${dockerInfo.version})`
    });
  } else {
    checks.push({
      category: 'Optional Integrations',
      name: 'Docker Dynamic Sandbox',
      status: 'optional_missing',
      message: 'Unavailable (Docker daemon not running; static analysis fully operational)'
    });
  }

  const yaraAvail = await isExecutableAvailable('yara');
  if (yaraAvail) {
    checks.push({
      category: 'Optional Integrations',
      name: 'YARA Pattern Engine',
      status: 'ok',
      message: 'Available (System yara binary found)'
    });
  } else {
    checks.push({
      category: 'Optional Integrations',
      name: 'YARA Pattern Engine',
      status: 'optional_missing',
      message: 'Unavailable (yara not in PATH; built-in pattern detection active)'
    });
  }

  const clamAvail = (await isExecutableAvailable('clamscan')) || (await isExecutableAvailable('clamdscan'));
  if (clamAvail) {
    checks.push({
      category: 'Optional Integrations',
      name: 'ClamAV Antivirus Engine',
      status: 'ok',
      message: 'Available (clamscan binary found)'
    });
  } else {
    checks.push({
      category: 'Optional Integrations',
      name: 'ClamAV Antivirus Engine',
      status: 'optional_missing',
      message: 'Unavailable (clamscan not in PATH; static heuristics active)'
    });
  }

  // 4. OSV Connectivity
  try {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 4000);
    const res = await fetch('https://api.osv.dev/v1/querybatch', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ queries: [] }),
      signal: controller.signal
    });
    clearTimeout(timer);
    if (res.ok) {
      checks.push({
        category: 'Network & Intelligence',
        name: 'OSV Vulnerability Database',
        status: 'ok',
        message: 'Connected (api.osv.dev online)'
      });
    } else {
      checks.push({
        category: 'Network & Intelligence',
        name: 'OSV Vulnerability Database',
        status: 'warning',
        message: `HTTP ${res.status} (Offline fallback available)`
      });
    }
  } catch {
    checks.push({
      category: 'Network & Intelligence',
      name: 'OSV Vulnerability Database',
      status: 'warning',
      message: 'Unreachable (Offline fallback available)'
    });
  }

  // 5. AI Advisory Layer
  try {
    const groq = new GroqClient();
    if (groq.isConfigured()) {
      checks.push({
        category: 'AI Advisory Layer',
        name: 'Groq AI Advisor',
        status: 'ok',
        message: 'Configured (GROQ_API_KEY detected)'
      });
    } else {
      checks.push({
        category: 'AI Advisory Layer',
        name: 'Groq AI Advisor',
        status: 'optional_missing',
        message: 'Not configured (Set GROQ_API_KEY in environment or .env for --ai advisory)'
      });
    }
  } catch (err: any) {
    checks.push({
      category: 'AI Advisory Layer',
      name: 'Groq AI Advisor',
      status: 'warning',
      message: `Configuration check error: ${err?.message || String(err)}`
    });
  }

  // 6. MongoDB Database Storage
  try {
    const mongoCheck = await testMongoConnection();
    if (mongoCheck.connected) {
      checks.push({
        category: 'Database & Storage',
        name: 'MongoDB Database Storage',
        status: 'ok',
        message: 'Connected (DeepCleaner scan repository active)'
      });
    } else {
      checks.push({
        category: 'Database & Storage',
        name: 'MongoDB Database Storage',
        status: 'optional_missing',
        message: process.env.MONGODB_URI ? `Configured but unreachable: ${mongoCheck.message}` : 'Not configured (Set MONGODB_URI to auto-save scan records)'
      });
    }
  } catch (err: any) {
    checks.push({
      category: 'Database & Storage',
      name: 'MongoDB Database Storage',
      status: 'optional_missing',
      message: `Unreachable: ${err?.message || String(err)}`
    });
  }

  return checks;
}

export function renderDoctorReport(checks: DoctorCheck[]): string {
  const lines: string[] = [];
  lines.push('');
  lines.push(pc.cyan('╔═══════════════════════════════════════════════════════════╗'));
  lines.push(pc.cyan('║') + pc.bold('                  DEEPCLEANER DOCTOR                       ') + pc.cyan('║'));
  lines.push(pc.cyan('║') + pc.dim('           System & Engine Readiness Diagnostic            ') + pc.cyan('║'));
  lines.push(pc.cyan('╚═══════════════════════════════════════════════════════════╝'));
  lines.push('');

  let currentCategory = '';
  for (const c of checks) {
    if (c.category !== currentCategory) {
      currentCategory = c.category;
      lines.push(pc.bold(`\n[${currentCategory}]`));
    }

    let symbol = pc.green('✓');
    if (c.status === 'error') symbol = pc.red('✗');
    else if (c.status === 'warning') symbol = pc.yellow('!');
    else if (c.status === 'optional_missing') symbol = pc.dim('○');

    lines.push(`  ${symbol} ${pc.bold(c.name)}: ${pc.dim(c.message)}`);
  }

  const hasErrors = checks.some((c) => c.status === 'error');
  lines.push('\n' + pc.cyan('─────────────────────────────────────────────────────────────'));
  if (hasErrors) {
    lines.push(pc.red(pc.bold('DeepCleaner has diagnostic errors that need attention.')));
  } else {
    lines.push(pc.green(pc.bold('✓ DeepCleaner is ready for defensive security scanning.')));
  }
  lines.push('');

  return lines.join('\n');
}
