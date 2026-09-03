import fs from 'node:fs';
import path from 'node:path';
import { normalizePath } from '../utils/paths.js';

export const DEFAULT_IGNORED_PATTERNS = [
  'node_modules/**',
  'node_modules',
  '.git/**',
  '.git',
  '.svn/**',
  '.svn',
  '.hg/**',
  '.hg',
  'dist/**',
  'dist',
  'build/**',
  'build',
  'coverage/**',
  'coverage',
  '.cache/**',
  '.cache',
  '.next/**',
  '.next',
  '.nuxt/**',
  '.nuxt',
  'vendor/**',
  'vendor',
  'target/**',
  'target',
  '*.pyc',
  '__pycache__/**',
  '.turbo/**',
  '.gradle/**',
  'out/**',
  'bin/**',
  'obj/**'
];

export class IgnoreFilter {
  private patterns: string[] = [];

  constructor(customPatterns: string[] = []) {
    this.patterns = [...DEFAULT_IGNORED_PATTERNS, ...customPatterns];
  }

  loadIgnoreFiles(rootDir: string): string[] {
    const loadedPatterns: string[] = [];
    const ignoreFileNames = ['.deepcleanerignore', '.deepscanignore', '.gitignore'];

    for (const name of ignoreFileNames) {
      const p = path.join(rootDir, name);
      if (fs.existsSync(p)) {
        try {
          const content = fs.readFileSync(p, 'utf-8');
          const lines = content
            .split(/\r?\n/)
            .map((l) => l.trim())
            .filter((l) => l.length > 0 && !l.startsWith('#'));
          this.patterns.push(...lines);
          loadedPatterns.push(...lines);
        } catch {
          // ignore read error
        }
      }
    }
    return loadedPatterns;
  }

  addPattern(pattern: string): void {
    if (pattern && !this.patterns.includes(pattern)) {
      this.patterns.push(pattern);
    }
  }

  isIgnored(relativePath: string, isDirectory = false): boolean {
    const norm = normalizePath(relativePath);
    const parts = norm.split('/').filter(Boolean);

    for (const part of parts) {
      if (
        part === 'node_modules' ||
        part === '.git' ||
        part === '.svn' ||
        part === '.hg' ||
        part === 'coverage' ||
        part === '.cache' ||
        part === '.next' ||
        part === '.nuxt' ||
        part === '__pycache__'
      ) {
        return true;
      }
    }

    for (const pattern of this.patterns) {
      if (this.matchPattern(norm, pattern, isDirectory)) {
        return true;
      }
    }
    return false;
  }

  private matchPattern(filePath: string, pattern: string, isDirectory: boolean): boolean {
    let cleanPat = pattern.trim();
    if (!cleanPat || cleanPat.startsWith('#')) return false;

    if (cleanPat.startsWith('/')) {
      cleanPat = cleanPat.slice(1);
    }

    if (filePath === cleanPat || (isDirectory && filePath === cleanPat.replace(/\/$/, ''))) {
      return true;
    }

    if (cleanPat.endsWith('/**')) {
      const prefix = cleanPat.slice(0, -3);
      if (filePath === prefix || filePath.startsWith(prefix + '/')) return true;
    }

    if (cleanPat.endsWith('/')) {
      const prefix = cleanPat.slice(0, -1);
      if (filePath === prefix || filePath.startsWith(prefix + '/')) return true;
    }

    if (cleanPat.startsWith('*.')) {
      const ext = cleanPat.slice(1);
      if (filePath.endsWith(ext)) return true;
    }

    if (!cleanPat.includes('/')) {
      const basename = path.basename(filePath);
      if (basename === cleanPat) return true;
      if (cleanPat.startsWith('*') && basename.endsWith(cleanPat.slice(1))) return true;
    }

    if (filePath.startsWith(cleanPat + '/')) {
      return true;
    }

    return false;
  }
}
