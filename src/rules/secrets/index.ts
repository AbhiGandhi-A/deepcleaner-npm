import type { RuleDefinition } from '../../models/finding.js';

export interface SecretPatternRule extends RuleDefinition {
  regex: RegExp;
  minEntropy?: number;
  verifyFn?: (match: string) => boolean;
}

export const SECRET_RULES: SecretPatternRule[] = [
  {
    id: 'DC-SECRET-001',
    name: 'AWS Access Key ID',
    category: 'Secrets',
    defaultSeverity: 'HIGH',
    defaultConfidence: 95,
    description: 'Hardcoded AWS Access Key ID detected',
    remediation: 'Remove AWS key and use AWS IAM roles or environment variables injected via a secret manager.',
    cwe: ['CWE-798'],
    references: ['https://docs.aws.amazon.com/general/latest/gr/aws-sec-cred-types.html'],
    regex: /\b(AKIA[0-9A-Z]{16})\b/g
  },
  {
    id: 'DC-SECRET-002',
    name: 'AWS Secret Access Key',
    category: 'Secrets',
    defaultSeverity: 'CRITICAL',
    defaultConfidence: 90,
    description: 'Potential AWS Secret Access Key detected in key-value assignment',
    remediation: 'Revoke and rotate the exposed AWS Secret Access Key immediately.',
    cwe: ['CWE-798'],
    references: ['https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_access-keys.html'],
    regex: /(?:aws_secret_access_key|aws_sec_key|secret_access_key)\s*[:=]\s*['"]?([0-9a-zA-Z/+=]{40})['"]?/gi,
    minEntropy: 4.2
  },
  {
    id: 'DC-SECRET-003',
    name: 'GitHub Personal Access Token',
    category: 'Secrets',
    defaultSeverity: 'CRITICAL',
    defaultConfidence: 98,
    description: 'Hardcoded GitHub Personal Access Token (classic or fine-grained) detected',
    remediation: 'Revoke the token on GitHub Settings -> Developer Settings -> Personal Access Tokens.',
    cwe: ['CWE-798'],
    references: ['https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/about-authentication-to-github'],
    regex: /\b(ghp_[A-Za-z0-9_]{36,255}|github_pat_[A-Za-z0-9_]{22}_[A-Za-z0-9_]{59})\b/g
  },
  {
    id: 'DC-SECRET-004',
    name: 'GitHub OAuth or App Token',
    category: 'Secrets',
    defaultSeverity: 'HIGH',
    defaultConfidence: 95,
    description: 'Hardcoded GitHub OAuth Access Token or App Token detected',
    remediation: 'Revoke the GitHub OAuth token and load credentials from a secure runtime secret store.',
    cwe: ['CWE-798'],
    references: ['https://docs.github.com/en/apps'],
    regex: /\b(gh[ousr]_[A-Za-z0-9_]{36,255})\b/g
  },
  {
    id: 'DC-SECRET-005',
    name: 'GitLab Personal Access Token',
    category: 'Secrets',
    defaultSeverity: 'CRITICAL',
    defaultConfidence: 95,
    description: 'Hardcoded GitLab Personal Access Token detected',
    remediation: 'Revoke the token in GitLab User Settings -> Access Tokens.',
    cwe: ['CWE-798'],
    references: ['https://docs.gitlab.com/ee/user/profile/personal_access_tokens.html'],
    regex: /\b(glpat-[0-9a-zA-Z\-_]{20,})\b/g
  },
  {
    id: 'DC-SECRET-006',
    name: 'Google Cloud / Maps API Key',
    category: 'Secrets',
    defaultSeverity: 'HIGH',
    defaultConfidence: 90,
    description: 'Hardcoded Google Cloud or Maps API key detected',
    remediation: 'Restrict key by API, HTTP referrer or IP in Google Cloud Console, or use secret management.',
    cwe: ['CWE-798'],
    references: ['https://cloud.google.com/docs/authentication/api-keys'],
    regex: /\b(AIza[0-9A-Za-z\-_]{35})\b/g
  },
  {
    id: 'DC-SECRET-007',
    name: 'Stripe Secret Key',
    category: 'Secrets',
    defaultSeverity: 'CRITICAL',
    defaultConfidence: 98,
    description: 'Live Stripe Secret or Restricted API Key detected',
    remediation: 'Rotate the Stripe key in Stripe Dashboard -> Developers -> API keys immediately.',
    cwe: ['CWE-798'],
    references: ['https://stripe.com/docs/keys'],
    regex: /\b(sk_live_[0-9a-zA-Z]{24,}|rk_live_[0-9a-zA-Z]{24,})\b/g
  },
  {
    id: 'DC-SECRET-008',
    name: 'Slack Bot / User Token',
    category: 'Secrets',
    defaultSeverity: 'HIGH',
    defaultConfidence: 95,
    description: 'Hardcoded Slack bot or user token detected',
    remediation: 'Revoke the token at api.slack.com/apps.',
    cwe: ['CWE-798'],
    references: ['https://api.slack.com/authentication/token-types'],
    regex: /\b(xox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24,32})\b/g
  },
  {
    id: 'DC-SECRET-009',
    name: 'Slack Webhook URL',
    category: 'Secrets',
    defaultSeverity: 'MEDIUM',
    defaultConfidence: 95,
    description: 'Hardcoded incoming Slack Webhook URL detected',
    remediation: 'Revoke webhook URL in Slack App settings and store in environment variables.',
    cwe: ['CWE-798'],
    references: ['https://api.slack.com/messaging/webhooks'],
    regex: /https:\/\/hooks\.slack\.com\/services\/T[A-Z0-9_]{8,12}\/B[A-Z0-9_]{8,12}\/[A-Za-z0-9_]{24}/g
  },
  {
    id: 'DC-SECRET-010',
    name: 'Discord Bot Token / Webhook',
    category: 'Secrets',
    defaultSeverity: 'HIGH',
    defaultConfidence: 90,
    description: 'Discord Bot Token or Webhook URL detected',
    remediation: 'Regenerate token in Discord Developer Portal.',
    cwe: ['CWE-798'],
    references: ['https://discord.com/developers/docs/topics/oauth2'],
    regex: /(?:https:\/\/discord(?:app)?\.com\/api\/webhooks\/[0-9]{17,20}\/[A-Za-z0-9_-]{60,68}|(?:discord[_-]?token|bot[_-]?token)\s*[:=]\s*['"][MNO][a-zA-Z0-9_-]{23,25}\.[a-zA-Z0-9_-]{6}\.[a-zA-Z0-9_-]{27}['"])/gi
  },
  {
    id: 'DC-SECRET-011',
    name: 'Telegram Bot Token',
    category: 'Secrets',
    defaultSeverity: 'HIGH',
    defaultConfidence: 92,
    description: 'Telegram Bot API Token detected',
    remediation: 'Revoke token via BotFather on Telegram.',
    cwe: ['CWE-798'],
    references: ['https://core.telegram.org/bots/api#authorizing-your-bot'],
    regex: /\b([0-9]{8,10}:[a-zA-Z0-9_-]{35})\b/g
  },
  {
    id: 'DC-SECRET-012',
    name: 'Private RSA / EC / SSH Key',
    category: 'Secrets',
    defaultSeverity: 'CRITICAL',
    defaultConfidence: 99,
    description: 'Unencrypted Private Cryptographic Key (RSA/EC/DSA/OPENSSH) detected',
    remediation: 'Remove private key file from version control immediately and generate new keypairs.',
    cwe: ['CWE-798', 'CWE-321'],
    references: ['https://cwe.mitre.org/data/definitions/798.html'],
    regex: /-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----/g
  },
  {
    id: 'DC-SECRET-013',
    name: 'JSON Web Token (JWT)',
    category: 'Secrets',
    defaultSeverity: 'LOW',
    defaultConfidence: 85,
    description: 'Hardcoded JSON Web Token detected',
    remediation: 'Ensure test JWTs do not contain production signatures or long-lived secret claims.',
    cwe: ['CWE-798'],
    references: ['https://jwt.io/introduction'],
    regex: /\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/g
  },
  {
    id: 'DC-SECRET-014',
    name: 'Database Connection String With Password',
    category: 'Secrets',
    defaultSeverity: 'HIGH',
    defaultConfidence: 92,
    description: 'Database connection URI containing plaintext authentication credentials detected',
    remediation: 'Inject database credentials dynamically via environment variables.',
    cwe: ['CWE-798', 'CWE-259'],
    references: ['https://cwe.mitre.org/data/definitions/259.html'],
    regex: /(?:postgres|postgresql|mysql|mongodb(?:\+srv)?|redis|mssql):\/\/[a-zA-Z0-9_.-]+:([^@\s:]{4,})@[a-zA-Z0-9_.-]+/gi
  },
  {
    id: 'DC-SECRET-015',
    name: 'Generic API Key / Password in Assignment',
    category: 'Secrets',
    defaultSeverity: 'MEDIUM',
    defaultConfidence: 75,
    description: 'High-entropy secret or password assigned in configuration or code',
    remediation: 'Store credentials in secure environment variables or vault.',
    cwe: ['CWE-798'],
    references: ['https://cwe.mitre.org/data/definitions/798.html'],
    regex: /(?:api[_-]?key|client[_-]?secret|db[_-]?password|app[_-]?secret|auth[_-]?token)\s*[:=]\s*['"]([^'"\s]{16,64})['"]/gi,
    minEntropy: 3.8
  }
];
