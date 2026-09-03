import fs from 'node:fs';
import path from 'node:path';
import type { IScanner, ScannerResult } from '../../models/scanner.js';
import type { Finding } from '../../models/finding.js';
import type { ScanContext } from '../../core/context.js';
import { sanitizeEvidence } from '../../utils/redact.js';

export class ConfigurationScanner implements IScanner {
  public readonly id = 'configuration';
  public readonly name = 'Security Configuration Scanner';
  public readonly description = 'Audits Dockerfiles, Kubernetes manifests, GitHub Actions, Terraform scripts, and .env files for misconfigurations.';

  isAvailable(_ctx: ScanContext): boolean {
    return true;
  }

  shouldRun(ctx: ScanContext): boolean {
    return ctx.isScannerEnabled(this.id);
  }

  async scan(ctx: ScanContext): Promise<ScannerResult> {
    const startTime = Date.now();
    const findings: Finding[] = [];
    let filesScanned = 0;

    for (const file of ctx.files) {
      if (file.isBinary) continue;
      const base = path.basename(file.relativePath).toLowerCase();

      if (base.startsWith('.env') && !base.includes('.example') && !base.includes('.sample') && !base.includes('.template')) {
        findings.push({
          id: 'DC-CONFIG-007',
          scanner: this.id,
          category: 'Configuration',
          severity: 'MEDIUM',
          confidence: 95,
          title: 'Committed environment (.env) file discovered',
          description: `Environment configuration file '${file.relativePath}' is committed in the repository.`,
          file: file.relativePath,
          evidence: `File present in repository: ${file.relativePath}`,
          redactedEvidence: `File present in repository: ${file.relativePath}`,
          remediation: 'Add `.env` to `.gitignore` and distribute `.env.example` without real secret values.',
          cwe: ['CWE-540'],
          references: ['https://cwe.mitre.org/data/definitions/540.html']
        });
      }

      let content: string;
      try {
        content = fs.readFileSync(file.path, 'utf-8');
      } catch {
        continue;
      }
      filesScanned++;

      const lines = content.split(/\r?\n/);

      if (file.language === 'dockerfile' || base.startsWith('dockerfile')) {
        let hasUserDirective = false;
        let lastFromIndex = 0;

        for (let i = 0; i < lines.length; i++) {
          const line = lines[i].trim();
          if (line.startsWith('#')) continue;

          if (/^FROM\s+/i.test(line)) {
            lastFromIndex = i;
            hasUserDirective = false;
          }
          if (/^USER\s+/i.test(line) && !line.includes('root') && !line.includes('0')) {
            hasUserDirective = true;
          }

          if (/^RUN\s+.*(?:curl|wget)\s+[^|]+\|\s*(?:ba)?sh/i.test(line)) {
            const evidence = sanitizeEvidence(line);
            findings.push({
              id: 'DC-MAL-002',
              scanner: this.id,
              category: 'Configuration',
              severity: 'CRITICAL',
              confidence: 95,
              title: 'Dockerfile executes untrusted remote script via curl | sh',
              description: 'RUN instruction pipes unverified remote script directly into shell.',
              file: file.relativePath,
              line: i + 1,
              evidence,
              redactedEvidence: evidence,
              remediation: 'Download script to disk, verify SHA-256 hash or signature, then execute.',
              cwe: ['CWE-494']
            });
          }
        }

        if (!hasUserDirective && lines.length > 3) {
          findings.push({
            id: 'DC-CONFIG-001',
            scanner: this.id,
            category: 'Configuration',
            severity: 'MEDIUM',
            confidence: 85,
            title: 'Dockerfile missing non-root USER specification',
            description: 'Container runs by default as the root superuser, increasing blast radius if container is breached.',
            file: file.relativePath,
            line: lastFromIndex + 1,
            evidence: lines[lastFromIndex] || 'FROM ...',
            redactedEvidence: lines[lastFromIndex] || 'FROM ...',
            remediation: 'Add `USER nonroot` or `USER 10001` before ENTRYPOINT/CMD.',
            cwe: ['CWE-250'],
            references: ['https://docs.docker.com/develop/develop-images/dockerfile_best-practices/#user']
          });
        }
      }

      if (file.extension === 'yaml' || file.extension === 'yml') {
        for (let i = 0; i < lines.length; i++) {
          const line = lines[i];
          const trimmed = line.trim();

          if (/privileged\s*:\s*true/i.test(trimmed)) {
            const evidence = sanitizeEvidence(trimmed);
            findings.push({
              id: 'DC-CONFIG-002',
              scanner: this.id,
              category: 'Configuration',
              severity: 'HIGH',
              confidence: 95,
              title: 'Privileged container configuration detected',
              description: 'Container configured with full kernel privileges (`privileged: true`), granting root host access.',
              file: file.relativePath,
              line: i + 1,
              evidence,
              redactedEvidence: evidence,
              remediation: 'Remove `privileged: true` and grant specific capabilities with `cap_add`.',
              cwe: ['CWE-250']
            });
          }

          if (/\/var\/run\/docker\.sock/i.test(trimmed) || /hostPath\s*:/i.test(trimmed)) {
            const evidence = sanitizeEvidence(trimmed);
            findings.push({
              id: 'DC-CONFIG-003',
              scanner: this.id,
              category: 'Configuration',
              severity: 'HIGH',
              confidence: 90,
              title: 'Sensitive host socket or hostPath mount detected',
              description: 'Mounting `/var/run/docker.sock` allows containers to break out and control the host Docker daemon.',
              file: file.relativePath,
              line: i + 1,
              evidence,
              redactedEvidence: evidence,
              remediation: 'Avoid mounting Docker socket or host root filesystem.',
              cwe: ['CWE-250']
            });
          }
        }
      }

      if (file.relativePath.includes('.github/workflows')) {
        let hasPullRequestTarget = false;

        for (let i = 0; i < lines.length; i++) {
          const line = lines[i];
          const trimmed = line.trim();

          if (/pull_request_target\s*:/i.test(trimmed) || trimmed === 'pull_request_target') {
            hasPullRequestTarget = true;
          }

          if (hasPullRequestTarget && /actions\/checkout/i.test(trimmed) && /ref:\s*\${{\s*github\.event\.pull_request\.head/i.test(content)) {
            const evidence = sanitizeEvidence(trimmed);
            findings.push({
              id: 'DC-CONFIG-004',
              scanner: this.id,
              category: 'Configuration',
              severity: 'CRITICAL',
              confidence: 95,
              title: 'GitHub Actions pull_request_target checking out PR head code',
              description: 'Checking out untrusted pull request code in a `pull_request_target` workflow gives fork PRs access to repository write secrets.',
              file: file.relativePath,
              line: i + 1,
              evidence,
              redactedEvidence: evidence,
              remediation: 'Use `on: pull_request` instead or do not check out PR head in `pull_request_target`.',
              cwe: ['CWE-829'],
              references: ['https://securitylab.github.com/research/github-actions-preventing-pwn-requests/']
            });
            break;
          }
        }
      }

      if (file.extension === 'tf' || file.extension === 'tfvars') {
        for (let i = 0; i < lines.length; i++) {
          const line = lines[i];
          const trimmed = line.trim();

          if (/cidr_blocks\s*=\s*\[\s*["']0\.0\.0\.0\/0["']\s*\]/i.test(trimmed) && (content.includes('22') || content.includes('3389'))) {
            const evidence = sanitizeEvidence(trimmed);
            findings.push({
              id: 'DC-CONFIG-006',
              scanner: this.id,
              category: 'Configuration',
              severity: 'HIGH',
              confidence: 90,
              title: 'Terraform open ingress security group rule (0.0.0.0/0)',
              description: 'Security group rule exposes administration ports (22 / 3389) publicly to the internet.',
              file: file.relativePath,
              line: i + 1,
              evidence,
              redactedEvidence: evidence,
              remediation: 'Restrict CIDR blocks to internal corporate VPN or bastion subnets.',
              cwe: ['CWE-732']
            });
            break;
          }
        }
      }
    }

    return {
      scannerId: this.id,
      name: this.name,
      status: 'completed',
      durationMs: Date.now() - startTime,
      filesScanned,
      findings
    };
  }
}
