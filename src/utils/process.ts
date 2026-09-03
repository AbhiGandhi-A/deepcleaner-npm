import { execFile } from 'node:child_process';
import { promisify } from 'node:util';

const execFileAsync = promisify(execFile);

export interface CommandResult {
  stdout: string;
  stderr: string;
  exitCode: number;
}

export async function runCommandSafe(
  binary: string,
  args: string[],
  options: {
    cwd?: string;
    timeoutMs?: number;
    maxBuffer?: number;
    env?: NodeJS.ProcessEnv;
  } = {}
): Promise<CommandResult> {
  const timeout = options.timeoutMs ?? 10000;
  const maxBuffer = options.maxBuffer ?? 10 * 1024 * 1024;

  try {
    const { stdout, stderr } = await execFileAsync(binary, args, {
      cwd: options.cwd,
      timeout,
      maxBuffer,
      env: { ...process.env, ...options.env }
    });
    return {
      stdout: stdout.toString(),
      stderr: stderr.toString(),
      exitCode: 0
    };
  } catch (err: any) {
    return {
      stdout: err.stdout ? err.stdout.toString() : '',
      stderr: err.stderr ? err.stderr.toString() : (err.message || ''),
      exitCode: typeof err.code === 'number' ? err.code : 1
    };
  }
}

export async function isExecutableAvailable(binaryName: string): Promise<boolean> {
  const isWindows = process.platform === 'win32';
  const checker = isWindows ? 'where' : 'which';
  try {
    const res = await runCommandSafe(checker, [binaryName], { timeoutMs: 3000 });
    return res.exitCode === 0 && res.stdout.trim().length > 0;
  } catch {
    return false;
  }
}
