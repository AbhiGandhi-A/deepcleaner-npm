import type { Finding } from '../../models/finding.js';
import { sanitizeEvidence } from '../../utils/redact.js';

export function analyzePhpCode(filePath: string, relativePath: string, code: string): Finding[] {
  const findings: Finding[] = [];
  const lines = code.split(/\r?\n/);

  for (let i = 0; i < lines.length; i++) {
    const lineNum = i + 1;
    const line = lines[i];
    const trimmed = line.trim();

    if (trimmed.startsWith('//') || trimmed.startsWith('#') || trimmed.startsWith('/*')) continue;

    const evidence = sanitizeEvidence(trimmed);

    if (/\b(?:system|exec|shell_exec|passthru|proc_open|popen)\s*\(|`[^`]+`/.test(trimmed)) {
      const hasInput = /\$_(?:GET|POST|REQUEST|COOKIE|SERVER)/i.test(trimmed);
      findings.push({
        id: 'DC-SEC-001',
        scanner: 'sast',
        category: 'Security',
        severity: 'CRITICAL',
        confidence: hasInput ? 98 : 85,
        title: hasInput ? 'Direct Command Injection via PHP shell function with user input' : 'PHP Command Execution function called',
        description: 'PHP execution function invoked (`system`, `exec`, `shell_exec`, or backticks).',
        file: relativePath,
        line: lineNum,
        evidence,
        redactedEvidence: evidence,
        remediation: 'Use `escapeshellarg()` and `escapeshellcmd()` or avoid shell execution.',
        cwe: ['CWE-78'],
        references: ['https://cwe.mitre.org/data/definitions/78.html']
      });
    }

    if (/\b(?:eval|assert)\s*\(/.test(trimmed)) {
      findings.push({
        id: 'DC-SEC-002',
        scanner: 'sast',
        category: 'Security',
        severity: 'CRITICAL',
        confidence: 95,
        title: 'PHP dynamic code execution via eval() / assert()',
        description: 'PHP `eval()` executes arbitrary code directly within the current script context.',
        file: relativePath,
        line: lineNum,
        evidence,
        redactedEvidence: evidence,
        remediation: 'Refactor code to avoid dynamic code evaluation.',
        cwe: ['CWE-95']
      });
    }

    if (/\bunserialize\s*\([^)]*\$_(?:GET|POST|REQUEST|COOKIE)/i.test(trimmed)) {
      findings.push({
        id: 'DC-SEC-007',
        scanner: 'sast',
        category: 'Security',
        severity: 'CRITICAL',
        confidence: 95,
        title: 'Unsafe PHP unserialize() with user-controlled input',
        description: 'Passing user input directly to `unserialize()` can trigger PHP Object Injection / POP chains.',
        file: relativePath,
        line: lineNum,
        evidence,
        redactedEvidence: evidence,
        remediation: 'Use `json_decode()` instead of `unserialize()`.',
        cwe: ['CWE-502']
      });
    }

    if (/\b(?:include|require|include_once|require_once)\s*\(?\s*.*\$_(?:GET|POST|REQUEST)/i.test(trimmed)) {
      findings.push({
        id: 'DC-SEC-005',
        scanner: 'sast',
        category: 'Security',
        severity: 'HIGH',
        confidence: 90,
        title: 'PHP Local / Remote File Inclusion (LFI/RFI)',
        description: 'Dynamic file inclusion using unvalidated superglobal parameters.',
        file: relativePath,
        line: lineNum,
        evidence,
        redactedEvidence: evidence,
        remediation: 'Use a strict allow-list of known safe file paths for inclusion.',
        cwe: ['CWE-98']
      });
    }
  }

  return findings;
}
