export interface SandboxPolicy {
  cpuLimit: string;
  memoryLimit: string;
  timeoutSeconds: number;
  networkDisabled: boolean;
  readOnlyRootFs: boolean;
  dropCapabilities: string[];
  user: string;
}

export const DEFAULT_SANDBOX_POLICY: SandboxPolicy = {
  cpuLimit: '0.5',
  memoryLimit: '256m',
  timeoutSeconds: 30,
  networkDisabled: true,
  readOnlyRootFs: true,
  dropCapabilities: ['ALL'],
  user: '10001:10001'
};
