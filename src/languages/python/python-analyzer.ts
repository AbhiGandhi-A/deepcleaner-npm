import type { Finding } from '../../models/finding.js';
import { sanitizeEvidence } from '../../utils/redact.js';

export function analyzePythonCode(filePath: string, relativePath: string, code: string): Finding[] {
  const findings: Finding[] = [];
  const lines = code.split(/\r?\n/);

  for (let i = 0; i < lines.length; i++) {
    const lineNum = i + 1;
    const line = lines[i];
    const trimmed = line.trim();

    if (trimmed.startsWith('#')) continue;

    const evidence = sanitizeEvidence(trimmed);

    if (/\bos\.(?:system|popen)\s*\(/.test(trimmed)) {
      findings.push({
        id: 'DC-SEC-001',
        scanner: 'sast',
        category: 'Security',
        severity: 'CRITICAL',
        confidence: 90,
        title: 'Python os.system / os.popen shell command execution',
        description: 'Executing system commands via `os.system` invokes the system shell and is susceptible to command injection.',
        file: relativePath,
        line: lineNum,
        evidence,
        redactedEvidence: evidence,
        remediation: 'Use `subprocess.run(["cmd", "arg"], shell=False)` with arguments passed as a list.',
        cwe: ['CWE-78'],
        references: ['https://cwe.mitre.org/data/definitions/78.html']
      });
    }

    if (/\bsubprocess\.(?:run|call|check_call|check_output|Popen)\s*\([^)]*shell\s*=\s*True/i.test(trimmed)) {
      findings.push({
        id: 'DC-SEC-001',
        scanner: 'sast',
        category: 'Security',
        severity: 'CRITICAL',
        confidence: 95,
        title: 'Python subprocess execution with shell=True',
        description: 'Passing `shell=True` to `subprocess` executes commands via `/bin/sh` or `cmd.exe`, enabling command injection.',
        file: relativePath,
        line: lineNum,
        evidence,
        redactedEvidence: evidence,
        remediation: 'Set `shell=False` and supply command arguments as a sequence list.',
        cwe: ['CWE-78']
      });
    }

    if (/\b(?:eval|exec)\s*\(/.test(trimmed)) {
      findings.push({
        id: 'DC-SEC-002',
        scanner: 'sast',
        category: 'Security',
        severity: 'CRITICAL',
        confidence: 90,
        title: 'Python dynamic code execution via eval() / exec()',
        description: 'Direct call to `eval()` or `exec()` in Python can execute arbitrary bytecode instructions.',
        file: relativePath,
        line: lineNum,
        evidence,
        redactedEvidence: evidence,
        remediation: 'Use `ast.literal_eval()` for safe string literal evaluation or `json.loads()`.',
        cwe: ['CWE-95']
      });
    }

    if (/\bpickle\.(?:loads|load)\s*\(/.test(trimmed)) {
      findings.push({
        id: 'DC-SEC-007',
        scanner: 'sast',
        category: 'Security',
        severity: 'CRITICAL',
        confidence: 95,
        title: 'Unsafe Python pickle deserialization',
        description: '`pickle.load()` / `pickle.loads()` is inherently unsafe against untrusted data, leading to arbitrary code execution via `__reduce__`.',
        file: relativePath,
        line: lineNum,
        evidence,
        redactedEvidence: evidence,
        remediation: 'Use safe serialization alternatives such as JSON or protobuf.',
        cwe: ['CWE-502']
      });
    }

    if (/\byaml\.load\s*\([^)]*(?!Loader=yaml\.SafeLoader|Loader=SafeLoader|safe_load)/.test(trimmed) && !trimmed.includes('safe_load')) {
      findings.push({
        id: 'DC-SEC-007',
        scanner: 'sast',
        category: 'Security',
        severity: 'HIGH',
        confidence: 85,
        title: 'Unsafe PyYAML yaml.load() call',
        description: 'Calling `yaml.load()` without specifying `Loader=yaml.SafeLoader` can instantiate arbitrary Python objects.',
        file: relativePath,
        line: lineNum,
        evidence,
        redactedEvidence: evidence,
        remediation: 'Use `yaml.safe_load()` instead.',
        cwe: ['CWE-502']
      });
    }

    if (/\b(?:cursor|db|session)\.execute\s*\(\s*(?:f["']|["'].*?%|["'].*?\.format\()/i.test(trimmed)) {
      findings.push({
        id: 'DC-SEC-003',
        scanner: 'sast',
        category: 'Security',
        severity: 'CRITICAL',
        confidence: 90,
        title: 'Python SQL Query string interpolation in execute()',
        description: 'Dynamic string formatting in database execute method is vulnerable to SQL injection.',
        file: relativePath,
        line: lineNum,
        evidence,
        redactedEvidence: evidence,
        remediation: 'Use parameterized query placeholders e.g. `cursor.execute("SELECT * FROM u WHERE id = %s", (user_id,))`.',
        cwe: ['CWE-89']
      });
    }

    if (/\bpty\.spawn\s*\(\s*["']\/(?:bin|usr\/bin)\/(?:bash|sh|zsh)["']\s*\)/i.test(trimmed)) {
      findings.push({
        id: 'DC-MAL-003',
        scanner: 'malware',
        category: 'Malware',
        severity: 'CRITICAL',
        confidence: 95,
        title: 'Interactive PTY shell spawn detected',
        description: 'Spawning an interactive PTY shell (`pty.spawn("/bin/bash")`) is characteristic of reverse shell payloads.',
        file: relativePath,
        line: lineNum,
        evidence,
        redactedEvidence: evidence,
        remediation: 'Verify whether interactive terminal spawning is authorized.',
        cwe: ['CWE-506']
      });
    }
  }

  return findings;
}
