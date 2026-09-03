import { createCliProgram, parseCliOptions } from './arguments.js';
import { executeScan, executeDoctor } from './commands.js';
import { loadEnv } from '../utils/env.js';

export async function runCli(argv: string[] = process.argv): Promise<void> {
  loadEnv();
  const program = createCliProgram();
  const { command, target, options } = parseCliOptions(program, argv);

  let exitCode = 0;
  if (command === 'doctor') {
    exitCode = await executeDoctor();
  } else {
    exitCode = await executeScan(target, options);
  }

  if (exitCode !== 0) {
    process.exit(exitCode);
  }
}

export const main = runCli;

export { executeScan, executeDoctor, createCliProgram, parseCliOptions };
