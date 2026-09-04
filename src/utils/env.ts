import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { fileURLToPath } from 'node:url';

export function loadEnv(targetDir: string = process.cwd()): void {
  const currentFileDir = path.dirname(fileURLToPath(import.meta.url));
  const packageRootDir = path.resolve(currentFileDir, '../../');

  const candidates = [
    path.join(targetDir, '.env'),
    path.join(targetDir, '.env.local'),
    path.join(targetDir, 'credentials.env'),
    path.join(process.cwd(), '.env'),
    path.join(process.cwd(), '.env.local'),
    path.join(process.cwd(), 'credentials.env'),
    path.join(os.homedir(), '.deepcleaner', '.env'),
    path.join(os.homedir(), '.deepcleaner', 'credentials.env'),
    path.join(packageRootDir, '.env'),
    path.join(packageRootDir, 'credentials.env')
  ];

  // Also search parent directories upwards up to 5 levels
  let cur = targetDir;
  for (let i = 0; i < 5; i++) {
    candidates.push(path.join(cur, '.env'), path.join(cur, '.env.local'), path.join(cur, 'credentials.env'));
    const parent = path.dirname(cur);
    if (parent === cur) break;
    cur = parent;
  }

  for (const envPath of candidates) {
    if (fs.existsSync(envPath)) {
      try {
        const content = fs.readFileSync(envPath, 'utf-8');
        for (const line of content.split(/\r?\n/)) {
          const trimmed = line.trim();
          if (!trimmed || trimmed.startsWith('#')) continue;
          const eqIdx = trimmed.indexOf('=');
          if (eqIdx > 0) {
            const key = trimmed.slice(0, eqIdx).trim();
            const val = trimmed.slice(eqIdx + 1).trim().replace(/^['"]|['"]$/g, '');
            if (!process.env[key]) {
              process.env[key] = val;
            }
          }
        }
      } catch {
        // ignore
      }
    }
  }
}

