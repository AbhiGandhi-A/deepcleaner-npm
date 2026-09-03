import { describe, it, expect } from 'vitest';
import path from 'node:path';
import { createCliProgram, parseCliOptions } from '../src/cli/arguments.js';
import { executeScan } from '../src/cli/commands.js';

describe('CLI Commands & Exit Codes', () => {
  it('parses CLI arguments correctly', () => {
    const program = createCliProgram();
    const { target, options } = parseCliOptions(program, [
      'node',
      'deepcleaner',
      './my-proj',
      '--deep',
      '--json',
      '--ci',
      '--fail-on',
      'critical'
    ]);

    expect(target).toBe('./my-proj');
    expect(options.deep).toBe(true);
    expect(options.json).toBe(true);
    expect(options.ci).toBe(true);
    expect(options.failOn).toBe('critical');
  });

  it('runs scan on safe fixture and returns exit code 0', async () => {
    const safeTarget = path.resolve(process.cwd(), 'fixtures/safe');
    const exitCode = await executeScan(safeTarget, {
      target: safeTarget,
      quiet: true,
      ci: true,
      failOn: 'high'
    });

    expect(exitCode).toBe(0);
  });

  it('runs scan on vulnerable fixture and returns exit code 1 when CI threshold exceeded', async () => {
    const vulnTarget = path.resolve(process.cwd(), 'fixtures/vulnerable/command-injection');
    const exitCode = await executeScan(vulnTarget, {
      target: vulnTarget,
      quiet: true,
      ci: true,
      failOn: 'high'
    });

    expect(exitCode).toBe(1);
  });

  it('returns exit code 2 when target does not exist', async () => {
    const nonExistent = path.resolve(process.cwd(), 'non-existent-directory-xyz');
    const exitCode = await executeScan(nonExistent, {
      target: nonExistent,
      quiet: true
    });

    expect(exitCode).toBe(2);
  });
});

