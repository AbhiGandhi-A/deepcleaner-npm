import { describe, it, expect } from 'vitest';
import path from 'node:path';
import { ConfigurationScanner } from '../src/scanners/configuration/configuration-scanner.js';
import { ScanContext } from '../src/core/context.js';

describe('Configuration Scanner', () => {
  it('detects insecure Dockerfile and docker-compose settings', async () => {
    const target = path.resolve(process.cwd(), 'fixtures/vulnerable/insecure-config');
    const ctx = new ScanContext(target, { target });
    ctx.files = [
      {
        path: path.join(target, 'Dockerfile'),
        relativePath: 'Dockerfile',
        size: 200,
        extension: 'dockerfile',
        language: 'dockerfile',
        isBinary: false,
        isArchive: false,
        isExecutable: false,
        isDisguised: false
      },
      {
        path: path.join(target, 'docker-compose.yml'),
        relativePath: 'docker-compose.yml',
        size: 200,
        extension: 'yml',
        language: 'yaml',
        isBinary: false,
        isArchive: false,
        isExecutable: false,
        isDisguised: false
      }
    ];

    const scanner = new ConfigurationScanner();
    const result = await scanner.scan(ctx);

    const ids = result.findings.map((f) => f.id);
    expect(ids).toContain('DC-CONFIG-001'); // Root user
    expect(ids).toContain('DC-CONFIG-002'); // Privileged container
    expect(ids).toContain('DC-CONFIG-003'); // Docker socket mount
  });
});

