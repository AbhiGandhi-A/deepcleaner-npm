import path from 'node:path';

export function normalizePath(p: string): string {
  return p.replace(/\\/g, '/');
}

export function toRelative(targetPath: string, rootDir: string): string {
  const rel = path.relative(rootDir, targetPath);
  return normalizePath(rel);
}

export function isSubPath(parent: string, child: string): boolean {
  const rel = path.relative(parent, child);
  return !rel.startsWith('..') && !path.isAbsolute(rel);
}

export function getFileExtension(filename: string): string {
  const ext = path.extname(filename).toLowerCase();
  return ext.startsWith('.') ? ext.slice(1) : ext;
}
