import { isExecutableAvailable, runCommandSafe } from '../utils/process.js';

export interface DockerRuntimeInfo {
  available: boolean;
  version?: string;
  isDaemonRunning?: boolean;
}

export async function detectDockerRuntime(): Promise<DockerRuntimeInfo> {
  const hasDocker = await isExecutableAvailable('docker');
  if (!hasDocker) {
    return { available: false, isDaemonRunning: false };
  }

  try {
    const res = await runCommandSafe('docker', ['version', '--format', '{{.Server.Version}}'], { timeoutMs: 4000 });
    if (res.exitCode === 0 && res.stdout.trim().length > 0) {
      return {
        available: true,
        version: res.stdout.trim(),
        isDaemonRunning: true
      };
    }
    return {
      available: true,
      isDaemonRunning: false
    };
  } catch {
    return {
      available: true,
      isDaemonRunning: false
    };
  }
}
