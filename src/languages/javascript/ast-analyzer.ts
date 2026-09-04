import { parse } from '@babel/parser';
import traverseModule from '@babel/traverse';
import type { Finding, TaintStep } from '../../models/finding.js';
import { sanitizeEvidence } from '../../utils/redact.js';

const traverse = (traverseModule as any).default || traverseModule;

export interface AstAnalysisOptions {
  filePath: string;
  relativePath: string;
  code: string;
}

export function analyzeJavaScriptAst(options: AstAnalysisOptions): Finding[] {
  const { filePath, relativePath, code } = options;
  const findings: Finding[] = [];

  let ast: any;
  try {
    ast = parse(code, {
      sourceType: 'unambiguous',
      plugins: [
        'jsx',
        'typescript',
        'decorators-legacy',
        'dynamicImport',
        'classProperties',
        'exportDefaultFrom',
        'objectRestSpread',
        'asyncGenerators',
        'optionalChaining',
        'nullishCoalescingOperator'
      ],
      errorRecovery: true
    });
  } catch {
    return findings;
  }

  const taintedVars = new Map<string, { source: string; line: number }>();
  const lines = code.split(/\r?\n/);
  const getLineSnippet = (lineNum?: number) => {
    if (!lineNum || lineNum < 1 || lineNum > lines.length) return '';
    return sanitizeEvidence(lines[lineNum - 1].trim());
  };

  try {
    traverse(ast, {
      VariableDeclarator(path: any) {
        const idNode = path.node.id;
        const initNode = path.node.init;
        if (idNode && idNode.type === 'Identifier' && initNode) {
          const varName = idNode.name;
          const initStr = code.slice(initNode.start ?? 0, initNode.end ?? 0);

          if (/req\.(?:query|body|params|headers|cookies)|location\.(?:search|hash)|window\.location/i.test(initStr)) {
            taintedVars.set(varName, {
              source: initStr.slice(0, 50),
              line: path.node.loc?.start.line ?? 1
            });
          } else if (initNode.type === 'Identifier' && taintedVars.has(initNode.name)) {
            const parentTaint = taintedVars.get(initNode.name)!;
            taintedVars.set(varName, {
              source: `Derived from ${initNode.name} (${parentTaint.source})`,
              line: path.node.loc?.start.line ?? 1
            });
          }
        }
      },

      CallExpression(path: any) {
        const callee = path.node.callee;
        const args = path.node.arguments || [];
        const loc = path.node.loc?.start;
        const line = loc?.line ?? 1;
        const column = loc?.column ?? 1;

        if (callee.type === 'Identifier' && callee.name === 'eval') {
          const evidence = getLineSnippet(line);
          findings.push({
            id: 'DC-SEC-002',
            scanner: 'sast',
            category: 'Security',
            severity: 'CRITICAL',
            confidence: 95,
            title: 'Dynamic code execution via eval()',
            description: 'Direct call to eval() executes strings as code, presenting a direct Remote Code Execution (RCE) vector.',
            file: relativePath,
            line,
            column,
            evidence,
            redactedEvidence: evidence,
            remediation: 'Replace eval() with safe JSON parsing or deterministic logic dispatch.',
            cwe: ['CWE-95'],
            references: ['https://cwe.mitre.org/data/definitions/95.html']
          });
        }

        let isExecCall = false;
        let isSpawnCall = false;

        if (callee.type === 'Identifier' && (callee.name === 'exec' || callee.name === 'execSync')) {
          isExecCall = true;
        } else if (callee.type === 'MemberExpression') {
          const prop = callee.property?.name;
          const obj = callee.object?.name;
          if ((prop === 'exec' || prop === 'execSync') && (obj === 'child_process' || obj === 'cp' || !obj)) {
            isExecCall = true;
          }
          if (prop === 'spawn' || prop === 'spawnSync') {
            isSpawnCall = true;
          }
        }

        if (isExecCall && args.length > 0) {
          const firstArg = args[0];
          const firstArgStr = code.slice(firstArg.start ?? 0, firstArg.end ?? 0);
          const evidence = getLineSnippet(line);

          const isDynamic =
            firstArg.type === 'BinaryExpression' ||
            (firstArg.type === 'TemplateLiteral' && firstArg.expressions.length > 0) ||
            firstArg.type === 'Identifier';

          let hasTaint = false;
          let taintSteps: TaintStep[] | undefined;

          if (firstArg.type === 'Identifier' && taintedVars.has(firstArg.name)) {
            hasTaint = true;
            const t = taintedVars.get(firstArg.name)!;
            taintSteps = [
              { file: relativePath, line: t.line, description: `Input source: ${t.source}` },
              { file: relativePath, line, description: `Command injection sink: exec(${firstArg.name})` }
            ];
          }

          findings.push({
            id: 'DC-SEC-001',
            scanner: 'sast',
            category: 'Security',
            severity: 'CRITICAL',
            confidence: hasTaint ? 98 : isDynamic ? 90 : 70,
            title: hasTaint ? 'Command Injection: User input reaches child_process.exec()' : 'Potential Command Injection via child_process.exec()',
            description: `Command execution function called with ${isDynamic ? 'dynamic' : 'static'} argument '${firstArgStr.slice(0, 40)}'.`,
            file: relativePath,
            line,
            column,
            evidence,
            redactedEvidence: evidence,
            taintPath: taintSteps,
            remediation: 'Use `child_process.execFile` or `spawn` with an array of arguments, avoiding shell interpolation.',
            cwe: ['CWE-78'],
            references: ['https://cwe.mitre.org/data/definitions/78.html']
          });
        }

        if (isSpawnCall && args.length >= 3) {
          const optsArg = args[2];
          const optsStr = code.slice(optsArg.start ?? 0, optsArg.end ?? 0);
          if (/shell\s*:\s*true/.test(optsStr)) {
            const evidence = getLineSnippet(line);
            findings.push({
              id: 'DC-SEC-001',
              scanner: 'sast',
              category: 'Security',
              severity: 'HIGH',
              confidence: 85,
              title: 'child_process.spawn called with { shell: true }',
              description: 'Spawning processes with `{ shell: true }` passes commands through the system shell, enabling command injection if arguments contain shell metacharacters.',
              file: relativePath,
              line,
              column,
              evidence,
              redactedEvidence: evidence,
              remediation: 'Remove `{ shell: true }` from spawn options.',
              cwe: ['CWE-78']
            });
          }
        }

        if (
          (callee.type === 'MemberExpression' && (callee.property?.name === 'query' || callee.property?.name === 'raw')) ||
          (callee.type === 'Identifier' && (callee.name === 'query' || callee.name === 'dbQuery'))
        ) {
          if (args.length > 0) {
            const queryArg = args[0];
            const isConcatenated = queryArg.type === 'BinaryExpression' && queryArg.operator === '+';
            const isTemplateWithExpr = queryArg.type === 'TemplateLiteral' && queryArg.expressions.length > 0;

            if (isConcatenated || isTemplateWithExpr) {
              const evidence = getLineSnippet(line);
              findings.push({
                id: 'DC-SEC-003',
                scanner: 'sast',
                category: 'Security',
                severity: 'CRITICAL',
                confidence: 90,
                title: 'SQL Injection via dynamic string formatting in query()',
                description: 'Database query constructed via string concatenation or template literal interpolation without parameterized placeholders.',
                file: relativePath,
                line,
                column,
                evidence,
                redactedEvidence: evidence,
                remediation: 'Use parameterized queries e.g. `db.query("SELECT * FROM users WHERE id = ?", [id])`.',
                cwe: ['CWE-89'],
                references: ['https://cwe.mitre.org/data/definitions/89.html']
              });
            }
          }
        }

        if (
          callee.type === 'MemberExpression' &&
          callee.object?.name === 'crypto' &&
          callee.property?.name === 'createCipher'
        ) {
          const evidence = getLineSnippet(line);
          findings.push({
            id: 'DC-SEC-008',
            scanner: 'sast',
            category: 'Security',
            severity: 'MEDIUM',
            confidence: 95,
            title: 'Deprecated insecure crypto.createCipher() used',
            description: '`crypto.createCipher()` derives IV and keys insecurely. It was deprecated in Node.js v10.',
            file: relativePath,
            line,
            column,
            evidence,
            redactedEvidence: evidence,
            remediation: 'Use `crypto.createCipheriv()` with a cryptographically random initialization vector (IV).',
            cwe: ['CWE-327']
          });
        }
      },

      NewExpression(path: any) {
        const callee = path.node.callee;
        const loc = path.node.loc?.start;
        const line = loc?.line ?? 1;
        const column = loc?.column ?? 1;

        if (callee.type === 'Identifier' && callee.name === 'Function') {
          const evidence = getLineSnippet(line);
          findings.push({
            id: 'DC-SEC-002',
            scanner: 'sast',
            category: 'Security',
            severity: 'CRITICAL',
            confidence: 95,
            title: 'Dynamic code execution via new Function()',
            description: '`new Function(...)` creates executable functions from strings at runtime, equivalent to eval().',
            file: relativePath,
            line,
            column,
            evidence,
            redactedEvidence: evidence,
            remediation: 'Avoid dynamic function generation from strings.',
            cwe: ['CWE-95']
          });
        }
      },

      AssignmentExpression(path: any) {
        const left = path.node.left;
        const loc = path.node.loc?.start;
        const line = loc?.line ?? 1;
        const column = loc?.column ?? 1;

        if (left.type === 'MemberExpression' && left.property?.name === 'innerHTML') {
          const evidence = getLineSnippet(line);
          findings.push({
            id: 'DC-SEC-004',
            scanner: 'sast',
            category: 'Security',
            severity: 'HIGH',
            confidence: 85,
            title: 'Cross-Site Scripting (XSS) via innerHTML assignment',
            description: 'Direct assignment to `element.innerHTML` bypasses HTML encoding and can execute malicious scripts if input contains user data.',
            file: relativePath,
            line,
            column,
            evidence,
            redactedEvidence: evidence,
            remediation: 'Use `element.textContent` or sanitize HTML with DOMPurify.',
            cwe: ['CWE-79'],
            references: ['https://cwe.mitre.org/data/definitions/79.html']
          });
        }
      },

      JSXAttribute(path: any) {
        if (path.node.name?.name === 'dangerouslySetInnerHTML') {
          const loc = path.node.loc?.start;
          const line = loc?.line ?? 1;
          const column = loc?.column ?? 1;
          const evidence = getLineSnippet(line);

          findings.push({
            id: 'DC-SEC-004',
            scanner: 'sast',
            category: 'Security',
            severity: 'HIGH',
            confidence: 90,
            title: 'React dangerouslySetInnerHTML usage detected',
            description: '`dangerouslySetInnerHTML` renders unsanitized HTML directly into the React virtual DOM.',
            file: relativePath,
            line,
            column,
            evidence,
            redactedEvidence: evidence,
            remediation: 'Ensure content passed to `__html` is sanitized with DOMPurify.',
            cwe: ['CWE-79']
          });
        }
      }
    });

    // Multi-step Behavioral Attack Chain Detection
    const behaviorSteps: { type: string; line: number; desc: string }[] = [];

    // 1. Scan for Credential / Secret File Access
    const credPatterns = /(?:id_rsa|\.ssh|\.aws|\.env|\.npmrc|\/etc\/shadow|\/etc\/passwd|process\.env)/i;
    if (credPatterns.test(code) && /(?:readFileSync|readFile|createReadStream|JSON\.stringify\(process\.env\))/i.test(code)) {
      behaviorSteps.push({
        type: 'credential_access',
        line: 1,
        desc: 'Accesses credential files or dumps process.env'
      });
    }

    // 2. Scan for Data Encoding / Obfuscation Transform
    if (/(?:toString\(['"]base64['"]\)|Buffer\.from\([^)]+['"]base64['"]\)|btoa\(|String\.fromCharCode)/i.test(code)) {
      behaviorSteps.push({
        type: 'encoding',
        line: 1,
        desc: 'Encodes data using Base64 or byte reconstruction'
      });
    }

    // 3. Scan for External Network Exfiltration
    if (/(?:fetch\s*\(|axios\.(?:post|put)|https?\.request|net\.connect|new\s+WebSocket|https?:\/\/[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)/i.test(code)) {
      behaviorSteps.push({
        type: 'network_exfiltration',
        line: 1,
        desc: 'Transmits data to external network address or remote server'
      });
    }

    // 4. Scan for Payload Execution
    if (/(?:child_process\.exec|execSync|spawnSync|eval\s*\(|new\s+Function)/i.test(code)) {
      behaviorSteps.push({
        type: 'execution',
        line: 1,
        desc: 'Dynamically executes shell commands or strings as code'
      });
    }

    // Correlate: Credential Access + Network Exfiltration = Malicious Data Stealer Attack Chain
    const hasCreds = behaviorSteps.some((s) => s.type === 'credential_access');
    const hasNet = behaviorSteps.some((s) => s.type === 'network_exfiltration');
    const hasExec = behaviorSteps.some((s) => s.type === 'execution');

    if (hasCreds && hasNet) {
      const chain = behaviorSteps.map((s, idx) => `${idx + 1}. ${s.desc}`);
      findings.push({
        id: 'DC-MAL-CHAIN-001',
        scanner: 'sast',
        category: 'Malware',
        severity: 'CRITICAL',
        confidence: hasExec ? 99 : 96,
        classification: 'confirmed_malware',
        title: 'Malicious Credential Theft and Network Exfiltration Attack Chain',
        description: 'Multi-step behavioral attack chain detected: local credentials or environment secrets are accessed, transformed, and transmitted to a remote network destination.',
        file: relativePath,
        line: 1,
        column: 1,
        evidence: chain.join(' -> '),
        redactedEvidence: chain.join(' -> '),
        evidenceChain: chain,
        whyItIsSuspicious: 'Correlated multi-stage attack flow: Credential harvesting combined with remote data transmission.',
        detectionMethod: 'AST Behavioral Attack-Chain Correlation',
        behaviorCategories: behaviorSteps.map((s) => s.type),
        remediation: 'Quarantine file immediately and inspect all outbound network transmissions.',
        cwe: ['CWE-200', 'CWE-506']
      });
    }
  } catch {
    // Graceful error recovery
  }

  return findings;
}
