import { execFile } from 'node:child_process';
import crypto from 'node:crypto';

export function runGitStatus(): Promise<string> {
  return new Promise((resolve, reject) => {
    execFile('git', ['status'], (err, stdout) => {
      if (err) return reject(err);
      resolve(stdout);
    });
  });
}

export function generateToken(): string {
  return crypto.randomBytes(32).toString('hex');
}
