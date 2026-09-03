import { describe, it, expect } from 'vitest';
import path from 'node:path';
import { ScanEngine } from '../src/core/engine.js';
import { ScanContext } from '../src/core/context.js';

describe('Hostile Inputs & Safety Boundaries', () => {
  it('gracefully handles non-existent or inaccessible targets without crashing', async () => {
    const target = path.resolve(process.cwd(), 'non-existent-folder-test-123');
    const ctx = new ScanContext(target, { target });
    const engine = new ScanEngine();
    const result = await engine.run(ctx);

    expect(result.summary.total).toBe(0);
    expect(result.project.totalFiles).toBe(0);
  });

  it('handles binary data and corrupted files safely', async () => {
    const target = path.resolve(process.cwd(), 'fixtures/safe');
    const ctx = new ScanContext(target, { target });
    const engine = new ScanEngine();
    const result = await engine.run(ctx);

    expect(result.tool.name).toBe('deepcleaner-ag');
    expect(result.riskScore.score).toBe(0);
  });
});
