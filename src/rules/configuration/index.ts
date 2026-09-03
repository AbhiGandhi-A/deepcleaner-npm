import type { RuleDefinition } from '../../models/finding.js';

export const CONFIGURATION_RULES: RuleDefinition[] = [
  {
    id: 'DC-CONFIG-001',
    name: 'Container Running as Root User',
    category: 'Configuration',
    defaultSeverity: 'MEDIUM',
    defaultConfidence: 90,
    description: 'Dockerfile does not specify a non-root USER, causing containers to execute with root privileges',
    remediation: 'Add `USER nonroot` or `USER 10001` before the ENTRYPOINT/CMD in Dockerfile.',
    cwe: ['CWE-250'],
    references: ['https://docs.docker.com/develop/develop-images/dockerfile_best-practices/#user']
  },
  {
    id: 'DC-CONFIG-002',
    name: 'Privileged Container Configuration',
    category: 'Configuration',
    defaultSeverity: 'HIGH',
    defaultConfidence: 95,
    description: 'Container configured with `privileged: true` or `securityContext.privileged: true`',
    remediation: 'Remove privileged mode. Grant only the specific Linux capabilities needed via `cap_add`.',
    cwe: ['CWE-250'],
    references: ['https://kubernetes.io/docs/concepts/security/pod-security-standards/']
  },
  {
    id: 'DC-CONFIG-003',
    name: 'Host Filesystem or Host Network Mount',
    category: 'Configuration',
    defaultSeverity: 'HIGH',
    defaultConfidence: 90,
    description: 'Container mounts sensitive host path (/ or /var/run/docker.sock) or enables hostNetwork/hostPID',
    remediation: 'Avoid mounting Docker socket or root filesystem into containers.',
    cwe: ['CWE-250'],
    references: ['https://kubernetes.io/docs/concepts/security/pod-security-standards/']
  },
  {
    id: 'DC-CONFIG-004',
    name: 'Dangerous GitHub Actions pull_request_target with Checkout',
    category: 'Configuration',
    defaultSeverity: 'CRITICAL',
    defaultConfidence: 95,
    description: 'Workflow triggered by `pull_request_target` checks out and executes untrusted code from PR head with write tokens',
    remediation: 'Use `pull_request` trigger instead or avoid checking out PR head in `pull_request_target`.',
    cwe: ['CWE-829'],
    references: ['https://securitylab.github.com/research/github-actions-preventing-pwn-requests/']
  },
  {
    id: 'DC-CONFIG-005',
    name: 'Unpinned Third-Party GitHub Action',
    category: 'Configuration',
    defaultSeverity: 'LOW',
    defaultConfidence: 85,
    description: 'GitHub Action referenced using mutable branch or tag instead of full commit SHA',
    remediation: 'Pin actions to immutable full commit SHAs (e.g. `actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683`).',
    cwe: ['CWE-829'],
    references: ['https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions']
  },
  {
    id: 'DC-CONFIG-006',
    name: 'Terraform Public Ingress or Open S3 Bucket',
    category: 'Configuration',
    defaultSeverity: 'HIGH',
    defaultConfidence: 90,
    description: 'Terraform security group opens port 22/3389 to 0.0.0.0/0 or S3 bucket ACL is set to public-read',
    remediation: 'Restrict CIDR blocks to internal bastion IPs and enable S3 Block Public Access.',
    cwe: ['CWE-732'],
    references: ['https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/security-group-rules.html']
  },
  {
    id: 'DC-CONFIG-007',
    name: 'Committed Environment (.env) File',
    category: 'Configuration',
    defaultSeverity: 'MEDIUM',
    defaultConfidence: 95,
    description: '.env file found committed in project workspace',
    remediation: 'Add `.env` to `.gitignore` and distribute `.env.example` with template values instead.',
    cwe: ['CWE-540'],
    references: ['https://cwe.mitre.org/data/definitions/540.html']
  }
];
