import { describe, it, expect } from 'vitest';
import path from 'node:path';
import { IgnoreFilter } from '../src/discovery/ignore.js';
import { detectLanguage } from '../src/discovery/language-detector.js';
import { detectProjectTypes } from '../src/discovery/project-detector.js';
import { inspectZipArchiveSafe } from '../src/discovery/archive-detector.js';

describe('Discovery Module', () => {
  it('detects language from file extensions and names', () => {
    expect(detectLanguage('index.ts')).toBe('typescript');
    expect(detectLanguage('server.js')).toBe('javascript');
    expect(detectLanguage('main.py')).toBe('python');
    expect(detectLanguage('app.php')).toBe('php');
    expect(detectLanguage('Dockerfile')).toBe('dockerfile');
    expect(detectLanguage('Dockerfile.prod')).toBe('dockerfile');
    expect(detectLanguage('.env.local')).toBe('dotenv');
  });

  it('detects project types from manifests', () => {
    const files = ['package.json', 'package-lock.json', 'Dockerfile', 'requirements.txt'];
    const result = detectProjectTypes(files);
    expect(result.types).toContain('nodejs');
    expect(result.types).toContain('python');
    expect(result.types).toContain('docker');
    expect(result.manifests).toContain('package.json');
  });

  it('filters ignored files and default ignores', () => {
    const filter = new IgnoreFilter(['custom-ignore/**', '*.log']);
    expect(filter.isIgnored('node_modules/express/index.js')).toBe(true);
    expect(filter.isIgnored('.git/config')).toBe(true);
    expect(filter.isIgnored('dist/bundle.js')).toBe(true);
    expect(filter.isIgnored('custom-ignore/secret.txt')).toBe(true);
    expect(filter.isIgnored('app.log')).toBe(true);
    expect(filter.isIgnored('src/index.ts')).toBe(false);
  });
});

