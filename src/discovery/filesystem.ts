import fs from 'node:fs';
import path from 'node:path';
import type { DiscoveredFile } from '../models/project.js';
import type { ScanContext } from '../core/context.js';
import { IgnoreFilter } from './ignore.js';
import { detectLanguage } from './language-detector.js';
import { detectMagicBytes } from '../utils/files.js';
import { toRelative, getFileExtension } from '../utils/paths.js';

export async function discoverFiles(ctx: ScanContext): Promise<{
  files: DiscoveredFile[];
  ignoredPatterns: string[];
  totalBytes: number;
}> {
  const rootDir = ctx.absoluteTarget;
  const ignoreFilter = new IgnoreFilter(ctx.userConfig.ignore || ctx.options.ignore || []);
  const loadedPatterns = ignoreFilter.loadIgnoreFiles(rootDir);

  const discovered: DiscoveredFile[] = [];
  const visitedRealPaths = new Set<string>();
  let totalBytes = 0;

  let rootRealPath = rootDir;
  try {
    rootRealPath = fs.realpathSync(rootDir);
    visitedRealPaths.add(rootRealPath);
  } catch {
    // ignore
  }

  async function walk(currentDir: string, depth: number): Promise<void> {
    if (depth > ctx.limits.maxDirectoryDepth) return;
    if (discovered.length >= ctx.limits.maxFileCount) return;
    if (totalBytes >= ctx.limits.maxTotalBytes) return;

    let entries: fs.Dirent[] = [];
    try {
      entries = fs.readdirSync(currentDir, { withFileTypes: true });
    } catch {
      return;
    }

    for (const entry of entries) {
      const fullPath = path.join(currentDir, entry.name);
      const relPath = toRelative(fullPath, rootDir);

      if (entry.isSymbolicLink()) {
        try {
          const realPath = fs.realpathSync(fullPath);
          if (visitedRealPaths.has(realPath)) {
            continue;
          }
          if (!realPath.startsWith(rootRealPath)) {
            continue;
          }
          visitedRealPaths.add(realPath);
        } catch {
          continue;
        }
      }

      if (entry.isDirectory()) {
        if (ignoreFilter.isIgnored(relPath, true)) {
          continue;
        }
        await walk(fullPath, depth + 1);
      } else if (entry.isFile()) {
        if (ignoreFilter.isIgnored(relPath, false)) {
          continue;
        }

        let stats: fs.Stats;
        try {
          stats = fs.statSync(fullPath);
        } catch {
          continue;
        }

        if (stats.size > ctx.limits.maxFileSize) {
          ctx.logger.verbose(`Skipping large file (${(stats.size / 1024 / 1024).toFixed(1)}MB): ${relPath}`);
          continue;
        }

        totalBytes += stats.size;
        const ext = getFileExtension(entry.name);
        const language = detectLanguage(entry.name);

        const magic = await detectMagicBytes(fullPath);

        let isDisguised = false;
        if (magic.isExecutable && !['exe', 'dll', 'so', 'dylib', 'bin', 'out', 'com'].includes(ext)) {
          isDisguised = true;
        }

        discovered.push({
          path: fullPath,
          relativePath: relPath,
          size: stats.size,
          extension: ext,
          language,
          mime: magic.mime,
          isBinary: magic.isBinary,
          isArchive: magic.isArchive,
          isExecutable: magic.isExecutable,
          isDisguised
        });

        if (discovered.length >= ctx.limits.maxFileCount || totalBytes >= ctx.limits.maxTotalBytes) {
          ctx.logger.warn(`Safety limit reached: ${discovered.length} files, ${(totalBytes / 1024 / 1024).toFixed(1)}MB`);
          break;
        }
      }
    }
  }

  await walk(rootDir, 0);

  return {
    files: discovered,
    ignoredPatterns: loadedPatterns,
    totalBytes
  };
}
