import { Command } from 'commander';
import type { CliOptions } from '../core/context.js';

export function createCliProgram(): Command {
  const program = new Command();

  program
    .name('deepcleaner')
    .description('Deep local security and malware-indicator scanner for software projects')
    .version('1.0.2', '-v, --version', 'Output DeepCleaner version');

  // Doctor command
  program
    .command('doctor')
    .description('Run system readiness diagnostic and check engine availability')
    .action(async () => {
      // Handled in entrypoint
    });

  // Scan command
  program
    .command('scan [target]', { isDefault: true })
    .description('Scan target directory or project path (default command)')
    .option('--deep', 'Perform deep recursive scanning including Git commit history')
    .option('--security', 'Focus on SAST code security vulnerabilities')
    .option('--malware', 'Focus on malware indicators and suspicious code')
    .option('--secrets', 'Focus on exposed API keys, private certificates, and secrets')
    .option('--deps', 'Focus on dependency vulnerabilities (OSV)')
    .option('--no-deps', 'Disable dependency scanning')
    .option('--no-git', 'Disable Git history scanning')
    .option('--yara', 'Enable YARA signature scanning')
    .option('--clamav', 'Enable ClamAV antivirus scanning')
    .option('--config', 'Focus on Docker, Kubernetes, and CI/CD configuration security')
    .option('--ai', 'Enable advisory AI finding analysis with Groq (requires GROQ_API_KEY)')
    .option('--full', 'Enable all security scanners, AI analysis, and deep checks')
    .option('--sandbox', 'Run isolated dynamic inspection in disposable Docker container')
    .option('--json', 'Output scan results strictly as JSON to stdout')
    .option('--html [file]', 'Generate standalone offline HTML report (default: deepcleaner-report.html)')
    .option('--sarif [file]', 'Generate SARIF v2.1.0 output for GitHub Code Scanning / CI')
    .option('--mongodb [uri]', 'Push scan results directly to MongoDB database')
    .option('--ci', 'Run in CI mode with exit code control based on severity')
    .option('--fail-on <severity>', 'Fail CI if findings meet or exceed severity (critical|high|medium|low)')
    .option('--fix', 'Suggest safe deterministic remediations interactively')
    .option('--offline', 'Run scan in offline mode (skip OSV and remote threat queries)')
    .option('-o, --output <file>', 'Save report output to specified file path')
    .option('--baseline <file>', 'Path to baseline file to suppress previously known findings')
    .option('--baseline-create <file>', 'Generate a baseline file recording current findings')
    .option('--ignore <patterns...>', 'Additional glob patterns or file paths to ignore')
    .option('--verbose', 'Show verbose diagnostic logging')
    .option('--quiet', 'Suppress non-error terminal output');

  return program;
}

export function parseCliOptions(program: Command, argv: string[] = process.argv): { command: 'doctor' | 'scan'; target: string; options: CliOptions } {
  // Check if doctor command is explicitly invoked
  const isDoctor = argv.includes('doctor') && !argv.includes('--help') && !argv.includes('-h');
  if (isDoctor) {
    return { command: 'doctor', target: '.', options: { target: '.' } };
  }

  program.parse(argv);
  const rawOpts = program.opts();

  // Handle options when subcommands are used or default command
  const scanCmd = program.commands.find((c) => c.name() === 'scan');
  const scanOpts = scanCmd ? scanCmd.opts() : {};
  const mergedOpts = { ...rawOpts, ...scanOpts };

  const target = program.args.find((a) => a !== 'scan' && a !== 'doctor') || '.';

  const ignoreList: string[] = [];
  if (Array.isArray(mergedOpts.ignore)) {
    ignoreList.push(...mergedOpts.ignore);
  } else if (typeof mergedOpts.ignore === 'string') {
    ignoreList.push(mergedOpts.ignore);
  }

  const options: CliOptions = {
    target,
    deep: Boolean(mergedOpts.deep),
    security: Boolean(mergedOpts.security),
    malware: Boolean(mergedOpts.malware),
    secrets: Boolean(mergedOpts.secrets),
    deps: Boolean(mergedOpts.deps),
    config: Boolean(mergedOpts.config),
    ai: Boolean(mergedOpts.ai),
    full: Boolean(mergedOpts.full),
    sandbox: Boolean(mergedOpts.sandbox),
    json: Boolean(mergedOpts.json),
    html: Boolean(mergedOpts.html),
    sarif: Boolean(mergedOpts.sarif),
    ci: Boolean(mergedOpts.ci || mergedOpts.failOn),
    fix: Boolean(mergedOpts.fix),
    verbose: Boolean(mergedOpts.verbose),
    quiet: Boolean(mergedOpts.quiet),
    offline: Boolean(mergedOpts.offline),
    failOn: mergedOpts.failOn?.toLowerCase(),
    outputFile: mergedOpts.output,
    baseline: mergedOpts.baseline,
    baselineCreate: mergedOpts.baselineCreate,
    ignore: ignoreList.length > 0 ? ignoreList : undefined,
    mongodb: mergedOpts.mongodb,
    noDeps: Boolean(mergedOpts.deps === false || mergedOpts.noDeps),
    noGit: Boolean(mergedOpts.git === false || mergedOpts.noGit),
    yara: Boolean(mergedOpts.yara),
    clamav: Boolean(mergedOpts.clamav)
  };

  return { command: 'scan', target, options };
}
