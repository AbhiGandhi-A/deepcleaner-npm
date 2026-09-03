import { exec } from 'node:child_process';

export function runUserCommand(userInput: string) {
  // Direct command injection vulnerability
  exec('ls ' + userInput, (err, stdout) => {
    console.log(stdout);
  });

  // Dynamic eval vulnerability
  eval(userInput);
}
