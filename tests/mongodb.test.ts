import { describe, it, expect } from 'vitest';
import { saveScanResultToMongo, testMongoConnection } from '../src/storage/mongodb.js';

describe('MongoDB Storage Module', () => {
  it('returns graceful error when MongoDB URI is invalid or unavailable', async () => {
    const res = await saveScanResultToMongo(
      {
        tool: { name: 'deepcleaner-ag', version: '1.0.0' },
        target: { path: '.', absolutePath: process.cwd() },
        timestamp: new Date().toISOString(),
        durationMs: 100,
        project: {
          rootPath: process.cwd(),
          name: 'test',
          projectTypes: ['nodejs'],
          manifestFiles: [],
          lockFiles: [],
          totalFiles: 1,
          totalBytes: 100,
          hasGit: false,
          languagesDetected: {},
          ignoredPatterns: []
        },
        riskScore: {
          score: 0,
          grade: 'A',
          explanation: 'Clean',
          impacts: { criticalCount: 0, highCount: 0, mediumCount: 0, lowCount: 0, deduplicatedFindings: 0 }
        },
        summary: { critical: 0, high: 0, medium: 0, low: 0, info: 0, total: 0 },
        scanners: {},
        findings: [],
        disclaimers: [],
        skippedChecks: []
      },
      'mongodb://invalid-host-test:27017'
    );

    expect(res.success).toBe(false);
    expect(res.error).toBeDefined();
  });

  it('handles missing URI gracefully in connection tester', async () => {
    const check = await testMongoConnection('');
    expect(check.connected).toBe(false);
  });
});

