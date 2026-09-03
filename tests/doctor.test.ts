import { describe, it, expect } from 'vitest';
import { runDoctor, renderDoctorReport } from '../src/cli/doctor.js';

describe('DeepCleaner Doctor', () => {
  it('runs diagnostic checks and returns structured check results', async () => {
    const checks = await runDoctor();
    expect(checks.length).toBeGreaterThan(4);

    const checkNames = checks.map((c) => c.name);
    expect(checkNames).toContain('Node.js Runtime');
    expect(checkNames).toContain('Secret & Credential Scanner');
    expect(checkNames).toContain('Static Application Security Testing (SAST)');
    expect(checkNames).toContain('Docker Dynamic Sandbox');
    expect(checkNames).toContain('YARA Pattern Engine');

    const nodeCheck = checks.find((c) => c.name === 'Node.js Runtime');
    expect(nodeCheck?.status).toBe('ok');
  });

  it('renders a formatted ANSI doctor diagnostic report', async () => {
    const checks = await runDoctor();
    const report = renderDoctorReport(checks);
    expect(report).toContain('DEEPCLEANER DOCTOR');
    expect(report).toContain('Node.js Runtime');
    expect(report).toContain('DeepCleaner is ready');
  });
});
