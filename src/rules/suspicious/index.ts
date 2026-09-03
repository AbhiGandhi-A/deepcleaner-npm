import type { RuleDefinition } from '../../models/finding.js';

export const SUSPICIOUS_RULES: RuleDefinition[] = [
  {
    id: 'DC-SUSP-001',
    name: 'Obfuscated Script / Eval of Decoded Array',
    category: 'Suspicious',
    defaultSeverity: 'HIGH',
    defaultConfidence: 80,
    description: 'Dynamic execution of reconstructed strings or encoded byte arrays (String.fromCharCode / atob / Buffer.from)',
    remediation: 'Inspect decoded payload to ensure it is not executing obfuscated malicious logic.',
    cwe: ['CWE-506'],
    references: ['https://attack.mitre.org/techniques/T1027/']
  },
  {
    id: 'DC-SUSP-002',
    name: 'Suspicious High-Entropy Code Block',
    category: 'Suspicious',
    defaultSeverity: 'MEDIUM',
    defaultConfidence: 70,
    description: 'Unusually large high-entropy base64/hex payload string embedded directly in source file',
    remediation: 'Verify whether the embedded string is an asset (e.g. image/font) or an encoded executable/script.',
    cwe: ['CWE-506'],
    references: ['https://attack.mitre.org/techniques/T1027/']
  },
  {
    id: 'DC-SUSP-003',
    name: 'Suspicious Network Socket in Non-Network Script',
    category: 'Suspicious',
    defaultSeverity: 'MEDIUM',
    defaultConfidence: 65,
    description: 'Raw network socket connection or DNS lookup in a standalone script or utility file',
    remediation: 'Confirm expected destination IP/domain and verify network operations are documented.',
    cwe: ['CWE-506'],
    references: ['https://attack.mitre.org/techniques/T1071/']
  },
  {
    id: 'DC-SUSP-004',
    name: 'Suspicious Child Process Spawning from Install Script',
    category: 'Potentially Dangerous',
    defaultSeverity: 'HIGH',
    defaultConfidence: 85,
    description: 'Execution of child process or network request inside a package lifecycle script (preinstall/postinstall)',
    remediation: 'Ensure package lifecycle scripts do not download or execute arbitrary remote binaries.',
    cwe: ['CWE-506'],
    references: ['https://docs.npmjs.com/cli/v10/using-npm/scripts']
  }
];
