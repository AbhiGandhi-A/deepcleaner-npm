import { describe, it, expect } from 'vitest';
import { analyzeJavaScriptAst } from '../src/languages/javascript/ast-analyzer.js';
import { analyzePythonCode } from '../src/languages/python/python-analyzer.js';
import { analyzePhpCode } from '../src/languages/php/php-analyzer.js';

describe('SAST & Taint Analysis', () => {
  it('detects command injection and eval in JavaScript with taint tracking', () => {
    const code = `
      function handler(req) {
        const cmd = req.query.command;
        child_process.exec(cmd);
        eval(cmd);
      }
    `;
    const findings = analyzeJavaScriptAst({
      filePath: '/test/runner.js',
      relativePath: 'src/runner.js',
      code
    });

    expect(findings.length).toBeGreaterThanOrEqual(2);
    const cmdFinding = findings.find((f) => f.id === 'DC-SEC-001');
    expect(cmdFinding).toBeDefined();
    expect(cmdFinding?.taintPath).toBeDefined();

    const evalFinding = findings.find((f) => f.id === 'DC-SEC-002');
    expect(evalFinding).toBeDefined();
  });

  it('detects XSS DOM sinks in React / DOM', () => {
    const code = `
      function App() {
        return <div dangerouslySetInnerHTML={{ __html: userHtml }} />;
      }
    `;
    const findings = analyzeJavaScriptAst({
      filePath: '/test/App.tsx',
      relativePath: 'src/App.tsx',
      code
    });

    const xssFinding = findings.find((f) => f.id === 'DC-SEC-004');
    expect(xssFinding).toBeDefined();
  });

  it('detects Python command injection and unsafe pickle', () => {
    const pyCode = `
      import os, pickle
      def handle(data):
        os.system("ls " + data)
        return pickle.loads(data)
    `;
    const findings = analyzePythonCode('/test/app.py', 'app.py', pyCode);
    const osFinding = findings.find((f) => f.id === 'DC-SEC-001');
    const pickleFinding = findings.find((f) => f.id === 'DC-SEC-007');

    expect(osFinding).toBeDefined();
    expect(pickleFinding).toBeDefined();
  });

  it('detects PHP eval and command execution', () => {
    const phpCode = `
      <?php
      $cmd = $_GET['c'];
      system($cmd);
      eval($cmd);
    `;
    const findings = analyzePhpCode('/test/index.php', 'index.php', phpCode);
    expect(findings.some((f) => f.id === 'DC-SEC-001')).toBe(true);
    expect(findings.some((f) => f.id === 'DC-SEC-002')).toBe(true);
  });
});

