import type { RuleDefinition } from '../models/finding.js';
import { SECRET_RULES } from './secrets/index.js';
import { SECURITY_RULES } from './security/index.js';
import { MALWARE_RULES } from './malware/index.js';
import { SUSPICIOUS_RULES } from './suspicious/index.js';
import { CONFIGURATION_RULES } from './configuration/index.js';

export * from './secrets/index.js';
export * from './security/index.js';
export * from './malware/index.js';
export * from './suspicious/index.js';
export * from './configuration/index.js';

export const ALL_RULES: RuleDefinition[] = [
  ...SECRET_RULES,
  ...SECURITY_RULES,
  ...MALWARE_RULES,
  ...SUSPICIOUS_RULES,
  ...CONFIGURATION_RULES
];

export const RULE_MAP = new Map<string, RuleDefinition>(
  ALL_RULES.map((r) => [r.id, r])
);

export function getRuleById(id: string): RuleDefinition | undefined {
  return RULE_MAP.get(id);
}
