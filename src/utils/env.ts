import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { fileURLToPath } from 'node:url';

function parseEnvFile(content: string): Record<string, string> {
  const result: Record<string, string> = {};
  // Strip UTF-8 BOM if present
  const cleanContent = content.charCodeAt(0) === 0xfeff ? content.slice(1) : content;

  for (const rawLine of cleanContent.split(/\r?\n/)) {
    let line = rawLine.trim();
    if (!line || line.startsWith('#') || line.startsWith('//')) continue;

    // Remove leading 'export ' if present
    if (line.startsWith('export ')) {
      line = line.slice(7).trim();
    }

    const eqIdx = line.indexOf('=');
    const colonIdx = line.indexOf(':');
    let sepIdx = eqIdx;
    if (sepIdx === -1 || (colonIdx > 0 && colonIdx < sepIdx)) {
      sepIdx = colonIdx;
    }

    if (sepIdx > 0) {
      let key = line.slice(0, sepIdx).trim();
      let val = line.slice(sepIdx + 1).trim();

      // Handle quoted values
      if ((val.startsWith('"') && val.endsWith('"')) || (val.startsWith("'") && val.endsWith("'")) || (val.startsWith('`') && val.endsWith('`'))) {
        val = val.slice(1, -1);
      } else {
        // Strip inline comments if unquoted
        const commentIdx = val.indexOf('#');
        if (commentIdx >= 0) {
          val = val.slice(0, commentIdx).trim();
        }
      }

      // Handle escaped newlines
      val = val.replace(/\\n/g, '\n').replace(/\\r/g, '\r');

      if (key && val) {
        result[key] = val;
      }
    }
  }

  return result;
}

function parseJsonEnv(content: string): Record<string, string> {
  const result: Record<string, string> = {};
  try {
    const parsed = JSON.parse(content);
    if (typeof parsed === 'object' && parsed !== null) {
      for (const [k, v] of Object.entries(parsed)) {
        if (typeof v === 'string') {
          result[k] = v;
        }
      }
    }
  } catch {
    // ignore
  }
  return result;
}

export function loadEnv(targetDir: string = process.cwd()): void {
  const currentFileDir = path.dirname(fileURLToPath(import.meta.url));
  const packageRootDir = path.resolve(currentFileDir, '../../');

  const fileNames = [
    '.env',
    '.env.local',
    '.env.production',
    '.env.development',
    'credentials.env',
    'deepcleaner.env',
    'credentials.json',
    'config.json'
  ];

  const searchDirs: string[] = [];

  // 1. Traverse targetDir up to root
  try {
    let cur = path.resolve(targetDir);
    while (cur) {
      if (!searchDirs.includes(cur)) searchDirs.push(cur);
      const parent = path.dirname(cur);
      if (parent === cur) break;
      cur = parent;
    }
  } catch {
    // ignore
  }

  // 2. Traverse process.cwd() up to root
  try {
    let cur = path.resolve(process.cwd());
    while (cur) {
      if (!searchDirs.includes(cur)) searchDirs.push(cur);
      const parent = path.dirname(cur);
      if (parent === cur) break;
      cur = parent;
    }
  } catch {
    // ignore
  }

  // 3. User home directory and common deepcleaner config dirs
  const home = os.homedir();
  if (home) {
    searchDirs.push(
      home,
      path.join(home, '.deepcleaner'),
      path.join(home, '.config', 'deepcleaner'),
      path.join(home, '.config')
    );
  }

  // 4. Package directory
  try {
    let cur = packageRootDir;
    while (cur) {
      if (!searchDirs.includes(cur)) searchDirs.push(cur);
      const parent = path.dirname(cur);
      if (parent === cur) break;
      cur = parent;
    }
  } catch {
    // ignore
  }

  for (const dir of searchDirs) {
    for (const name of fileNames) {
      const fullPath = path.join(dir, name);
      if (fs.existsSync(fullPath)) {
        try {
          const content = fs.readFileSync(fullPath, 'utf-8');
          const parsed = name.endsWith('.json') ? parseJsonEnv(content) : parseEnvFile(content);

          for (const [key, val] of Object.entries(parsed)) {
            if (!process.env[key] || process.env[key] === '') {
              process.env[key] = val;
            }

            // Normalize known aliases
            const upper = key.toUpperCase();
            if (['MONGODB_URI', 'MONGO_URI', 'MONGODB_URL', 'MONGO_URL', 'DATABASE_URL'].includes(upper)) {
              if (!process.env.MONGODB_URI) process.env.MONGODB_URI = val;
            }
            if (['GROQ_API_KEY', 'GROQ_KEY', 'GROQ_APIKEY', 'GROQ_TOKEN'].includes(upper)) {
              if (!process.env.GROQ_API_KEY) process.env.GROQ_API_KEY = val;
            }
          }
        } catch {
          // ignore
        }
      }
    }
  }

  // Also bind aliases from existing process.env
  if (!process.env.MONGODB_URI) {
    process.env.MONGODB_URI =
      process.env.MONGO_URI ||
      process.env.MONGODB_URL ||
      process.env.MONGO_URL ||
      process.env.DATABASE_URL;
  }
  if (!process.env.GROQ_API_KEY) {
    process.env.GROQ_API_KEY =
      process.env.GROQ_KEY ||
      process.env.GROQ_APIKEY ||
      process.env.GROQ_TOKEN;
  }
}
