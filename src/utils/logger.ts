import pc from 'picocolors';

export type LogLevel = 'silent' | 'quiet' | 'normal' | 'verbose' | 'debug';

export class Logger {
  private level: LogLevel = 'normal';
  private isJsonMode = false;

  setLevel(level: LogLevel): void {
    this.level = level;
  }

  setJsonMode(json: boolean): void {
    this.isJsonMode = json;
  }

  debug(msg: string): void {
    if (this.isJsonMode) return;
    if (this.level === 'debug' || this.level === 'verbose') {
      console.error(pc.dim(`[DEBUG] ${msg}`));
    }
  }

  verbose(msg: string): void {
    if (this.isJsonMode) return;
    if (this.level === 'verbose' || this.level === 'debug') {
      console.error(pc.cyan(`[INFO] ${msg}`));
    }
  }

  info(msg: string): void {
    if (this.isJsonMode) return;
    if (this.level !== 'silent' && this.level !== 'quiet') {
      console.log(msg);
    }
  }

  warn(msg: string): void {
    if (this.isJsonMode) return;
    if (this.level !== 'silent') {
      console.error(pc.yellow(`[WARN] ${msg}`));
    }
  }

  error(msg: string, err?: unknown): void {
    if (this.isJsonMode) return;
    console.error(pc.red(`[ERROR] ${msg}`));
    if (err && (this.level === 'verbose' || this.level === 'debug')) {
      console.error(err);
    }
  }

  raw(msg: string): void {
    if (this.isJsonMode) return;
    console.log(msg);
  }
}

export const logger = new Logger();
