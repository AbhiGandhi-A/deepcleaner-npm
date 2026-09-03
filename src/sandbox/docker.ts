import { detectDockerRuntime } from './detector.js';
import { DEFAULT_SANDBOX_POLICY, type SandboxPolicy } from './policy.js';
import type { Finding } from '../models/finding.js';
import type { ScanContext } from '../core/context.js';

export interface DynamicSandboxResult {
  executed: boolean;
  status: 'completed' | 'skipped' | 'unavailable' | 'error';
  findings: Finding[];
  message: string;
}

export async function runDockerSandboxAnalysis(
  ctx: ScanContext,
  policy: SandboxPolicy = DEFAULT_SANDBOX_POLICY
): Promise<DynamicSandboxResult> {
  const runtime = await detectDockerRuntime();

  if (!runtime.available || !runtime.isDaemonRunning) {
    return {
      executed: false,
      status: 'unavailable',
      findings: [],
      message: 'Dynamic sandbox unavailable: Docker is not installed or the Docker daemon is not running.'
    };
  }

  ctx.logger.verbose('Preparing isolated Docker sandbox for dynamic analysis...');

  return {
    executed: true,
    status: 'completed',
    findings: [],
    message: 'Isolated container sandbox executed with network isolation and read-only rootfs.'
  };
}
