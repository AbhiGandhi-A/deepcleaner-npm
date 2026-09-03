import type { Finding } from '../../models/finding.js';
import { sanitizeEvidence } from '../../utils/redact.js';

export function analyzeGenericCode(filePath: string, relativePath: string, code: string, language?: string): Finding[] {
  const findings: Finding[] = [];
  const lines = code.split(/\r?\n/);

  for (let i = 0; i < lines.length; i++) {
    const lineNum = i + 1;
    const line = lines[i];
    const trimmed = line.trim();

    if (trimmed.startsWith('#') || trimmed.startsWith('//')) continue;
    const evidence = sanitizeEvidence(trimmed);

    if (/(?:curl|wget)\s+[^|]+\|\s*(?:ba)?sh\b/i.test(trimmed)) {
      findings.push({
        id: 'DC-MAL-002',
        scanner: 'malware',
        category: 'Malware Indicator',
        severity: 'CRITICAL',
        confidence: 95,
        title: 'Download and Execute pipe pattern (curl | sh)',
        description: 'Directly piping remote HTTP response into shell interpreter without verification.',
        file: relativePath,
        line: lineNum,
        evidence,
        redactedEvidence: evidence,
        remediation: 'Download scripts to a temporary file and verify integrity checksums before running.',
        cwe: ['CWE-494']
      });
    }

    if (/(?:powershell|pwsh)(?:\.exe)?\s+.*-(?:enc|encodedcommand)\s+[A-Za-z0-9+/=]{10,}/i.test(trimmed)) {
      findings.push({
        id: 'DC-MAL-001',
        scanner: 'malware',
        category: 'Malware Indicator',
        severity: 'CRITICAL',
        confidence: 95,
        title: 'PowerShell execution with base64 EncodedCommand',
        description: 'Execution of base64 encoded PowerShell commands is frequently used to evade detection.',
        file: relativePath,
        line: lineNum,
        evidence,
        redactedEvidence: evidence,
        remediation: 'Decode command payload and inspect instructions.',
        cwe: ['CWE-506']
      });
    }

    if (language === 'go' && /exec\.Command\s*\(\s*["'](?:sh|bash|cmd)["']\s*,\s*["']-[cC]["']/i.test(trimmed)) {
      findings.push({
        id: 'DC-SEC-001',
        scanner: 'sast',
        category: 'Security',
        severity: 'HIGH',
        confidence: 85,
        title: 'Go exec.Command invoking shell interpreter',
        description: 'Invoking shell with dynamic string parameters in Go can lead to command injection.',
        file: relativePath,
        line: lineNum,
        evidence,
        redactedEvidence: evidence,
        remediation: 'Invoke specific binary directly without running through shell interpreter.',
        cwe: ['CWE-78']
      });
    }

    if (language === 'java' && /Runtime\.getRuntime\(\)\.exec\s*\(/i.test(trimmed)) {
      findings.push({
        id: 'DC-SEC-001',
        scanner: 'sast',
        category: 'Security',
        severity: 'HIGH',
        confidence: 80,
        title: 'Java Runtime.getRuntime().exec() called',
        description: 'Executing external system processes in Java requires strict input validation.',
        file: relativePath,
        line: lineNum,
        evidence,
        redactedEvidence: evidence,
        remediation: 'Use `ProcessBuilder` with arguments passed as discrete elements.',
        cwe: ['CWE-78']
      });
    }

    if ((language === 'c' || language === 'cpp') && /\b(?:gets|strcpy|sprintf)\s*\(/.test(trimmed)) {
      findings.push({
        id: 'DC-SEC-001',
        scanner: 'sast',
        category: 'Security',
        severity: 'HIGH',
        confidence: 85,
        title: 'Unsafe C buffer function (gets / strcpy / sprintf)',
        description: 'Unbounded buffer copy functions are vulnerable to stack buffer overflows.',
        file: relativePath,
        line: lineNum,
        evidence,
        redactedEvidence: evidence,
        remediation: 'Use bounded safe alternatives such as `fgets()`, `strncpy()`, or `snprintf()`.',
        cwe: ['CWE-120']
      });
    }
  }

  return findings;
}
