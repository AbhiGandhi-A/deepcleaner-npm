import pc from 'picocolors';

export class ProgressReporter {
  private isJson: boolean;
  private isQuiet: boolean;

  constructor(isJson = false, isQuiet = false) {
    this.isJson = isJson;
    this.isQuiet = isQuiet;
  }

  report(step: number, total: number, message: string): void {
    if (this.isJson || this.isQuiet) return;
    process.stderr.write(`\r${pc.cyan(`[${step}/${total}]`)} ${pc.white(message.padEnd(45))}`);
    if (step === total) {
      process.stderr.write('\n');
    }
  }

  clear(): void {
    if (this.isJson || this.isQuiet) return;
    process.stderr.write('\r' + ' '.repeat(60) + '\r');
  }
}
