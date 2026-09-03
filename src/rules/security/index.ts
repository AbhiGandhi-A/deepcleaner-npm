import type { RuleDefinition } from '../../models/finding.js';

export const SECURITY_RULES: RuleDefinition[] = [
  {
    id: 'DC-SEC-001',
    name: 'Command Injection via Shell Execution',
    category: 'Security',
    defaultSeverity: 'CRITICAL',
    defaultConfidence: 90,
    description: 'Execution of OS commands using shell interpreter with dynamic or unvalidated input',
    remediation: 'Use `child_process.execFile` or `spawn` without `{ shell: true }` and pass arguments as an array.',
    cwe: ['CWE-78'],
    references: ['https://cwe.mitre.org/data/definitions/78.html'],
    languages: ['javascript', 'typescript', 'python', 'php', 'ruby', 'go']
  },
  {
    id: 'DC-SEC-002',
    name: 'Unsafe Dynamic Code Execution (eval / Function)',
    category: 'Security',
    defaultSeverity: 'CRITICAL',
    defaultConfidence: 95,
    description: 'Dynamic code execution using eval(), new Function(), or vm.runInContext()',
    remediation: 'Avoid dynamic code execution. Use safe JSON parsing or explicit logic mapping.',
    cwe: ['CWE-95'],
    references: ['https://cwe.mitre.org/data/definitions/95.html'],
    languages: ['javascript', 'typescript', 'python', 'php']
  },
  {
    id: 'DC-SEC-003',
    name: 'SQL Injection via String Concatenation',
    category: 'Security',
    defaultSeverity: 'CRITICAL',
    defaultConfidence: 85,
    description: 'Constructing SQL queries through dynamic string concatenation or template literals',
    remediation: 'Use parameterized queries or prepared statements provided by your database driver/ORM.',
    cwe: ['CWE-89'],
    references: ['https://cwe.mitre.org/data/definitions/89.html'],
    languages: ['javascript', 'typescript', 'python', 'php', 'java', 'go']
  },
  {
    id: 'DC-SEC-004',
    name: 'Cross-Site Scripting (XSS) via DOM Sink',
    category: 'Security',
    defaultSeverity: 'HIGH',
    defaultConfidence: 85,
    description: 'Direct assignment to raw HTML sinks (innerHTML, dangerouslySetInnerHTML, document.write)',
    remediation: 'Use textContent, DOMPurify, or safe framework data binding mechanisms.',
    cwe: ['CWE-79'],
    references: ['https://cwe.mitre.org/data/definitions/79.html'],
    languages: ['javascript', 'typescript']
  },
  {
    id: 'DC-SEC-005',
    name: 'Path Traversal in File Operations',
    category: 'Security',
    defaultSeverity: 'HIGH',
    defaultConfidence: 80,
    description: 'Filesystem operation using unvalidated path joining or user-supplied file names',
    remediation: 'Sanitize path using `path.basename` or verify with `path.resolve` against an allowed directory root.',
    cwe: ['CWE-22'],
    references: ['https://cwe.mitre.org/data/definitions/22.html'],
    languages: ['javascript', 'typescript', 'python', 'php', 'go']
  },
  {
    id: 'DC-SEC-006',
    name: 'Server-Side Request Forgery (SSRF)',
    category: 'Security',
    defaultSeverity: 'HIGH',
    defaultConfidence: 75,
    description: 'HTTP request initiated to user-supplied or dynamic URL without allow-list validation',
    remediation: 'Validate target URLs against an explicit domain allow-list and disallow private IP ranges (127.0.0.1, 10.x, 169.254.x).',
    cwe: ['CWE-918'],
    references: ['https://cwe.mitre.org/data/definitions/918.html'],
    languages: ['javascript', 'typescript', 'python', 'php']
  },
  {
    id: 'DC-SEC-007',
    name: 'Unsafe Object Deserialization / Pickle',
    category: 'Security',
    defaultSeverity: 'CRITICAL',
    defaultConfidence: 90,
    description: 'Deserialization of untrusted data using unsafe engines (pickle, serialize-javascript, unserialize)',
    remediation: 'Use safe serialization formats such as JSON or YAML safe_load.',
    cwe: ['CWE-502'],
    references: ['https://cwe.mitre.org/data/definitions/502.html'],
    languages: ['python', 'php', 'javascript', 'typescript']
  },
  {
    id: 'DC-SEC-008',
    name: 'Insecure Cryptographic Algorithm / Randomness',
    category: 'Security',
    defaultSeverity: 'MEDIUM',
    defaultConfidence: 85,
    description: 'Use of broken cipher (DES/RC4), weak hashing (MD5/SHA1 for auth), or Math.random() for security tokens',
    remediation: 'Use `crypto.randomBytes()` / `secrets` module and modern algorithms (AES-256-GCM, SHA-256, Argon2/bcrypt).',
    cwe: ['CWE-327', 'CWE-338'],
    references: ['https://cwe.mitre.org/data/definitions/327.html'],
    languages: ['javascript', 'typescript', 'python', 'php', 'java']
  },
  {
    id: 'DC-SEC-009',
    name: 'Prototype Pollution Vulnerability',
    category: 'Security',
    defaultSeverity: 'HIGH',
    defaultConfidence: 80,
    description: 'Recursive object merge or path assignment allowing modification of Object.prototype',
    remediation: 'Validate object keys to disallow `__proto__`, `constructor`, and `prototype`, or use `Object.create(null)`.',
    cwe: ['CWE-1321'],
    references: ['https://cwe.mitre.org/data/definitions/1321.html'],
    languages: ['javascript', 'typescript']
  },
  {
    id: 'DC-SEC-010',
    name: 'Open Redirect Vulnerability',
    category: 'Security',
    defaultSeverity: 'MEDIUM',
    defaultConfidence: 75,
    description: 'HTTP redirect location constructed directly from query parameters without validation',
    remediation: 'Enforce relative path redirects or validate destination against an allowed domains list.',
    cwe: ['CWE-601'],
    references: ['https://cwe.mitre.org/data/definitions/601.html'],
    languages: ['javascript', 'typescript', 'python', 'php']
  },
  {
    id: 'DC-SEC-011',
    name: 'Insecure CORS Wildcard with Credentials',
    category: 'Security',
    defaultSeverity: 'MEDIUM',
    defaultConfidence: 85,
    description: 'CORS header `Access-Control-Allow-Origin: *` configured on sensitive API endpoints',
    remediation: 'Specify explicit trusted origins instead of wildcard `*`.',
    cwe: ['CWE-942'],
    references: ['https://cwe.mitre.org/data/definitions/942.html'],
    languages: ['javascript', 'typescript', 'python']
  },
  {
    id: 'DC-SEC-012',
    name: 'Insecure JWT Verification / Missing Algorithm',
    category: 'Security',
    defaultSeverity: 'HIGH',
    defaultConfidence: 85,
    description: 'JWT verification missing explicit `algorithms` parameter, enabling `none` algorithm bypass',
    remediation: 'Explicitly specify `algorithms: ["RS256"]` or `["HS256"]` in `jwt.verify()`.',
    cwe: ['CWE-345'],
    references: ['https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/'],
    languages: ['javascript', 'typescript', 'python']
  }
];
