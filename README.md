# deepcleaner-ag

> **Deep Local Security & Malware Indicator Scanner for Software Projects**

[![npm version](https://img.shields.io/npm/v/deepcleaner-ag.svg)](https://www.npmjs.com/package/deepcleaner-ag)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![Node.js Version](https://img.shields.io/badge/node-%3E%3D20.0.0-brightgreen.svg)](https://nodejs.org/)

DeepCleaner is an open-source, local-first developer security scanner that performs comprehensive static analysis, secret detection, dependency vulnerability intelligence, configuration auditing, malware indicator scanning, and optional AI-assisted finding verification.

---

## ⚡ Quick Start

Run instantly without installing:

```bash
npx deepcleaner-ag .
```

Or install globally:

```bash
npm install -g deepcleaner-ag
deepcleaner .
```

---

## 🛡️ Core Capabilities

* **Secret & Credential Scanner**: 40+ patterns for cloud credentials (AWS, Google, Azure), tokens (GitHub, GitLab, Slack, Discord, Stripe), private certificates, JWTs, and database URIs with Shannon entropy validation and strict evidence masking.
* **AST-Based SAST**: AST traversal for JavaScript and TypeScript with taint-tracking from untrusted sources (`req.query`, `req.body`, `req.params`) to sensitive sinks (`exec`, `eval`, `innerHTML`, `db.query`). Rules for Python, PHP, Go, Java, and C/C++.
* **Dependency Intelligence**: Multi-ecosystem manifest parsing (npm, PyPI, Packagist, Go) with batched OSV queries and offline fallback.
* **Security Configuration Audits**: Inspects Dockerfile (`USER` non-root, `curl | sh`), Docker Compose / Kubernetes (`privileged`, host socket mounts), GitHub Actions (`pull_request_target`), and Terraform security groups.
* **Malware & Suspicious Code Scanner**: Detects disguised executables, reverse shell socket payloads, encoded PowerShell cradles, and obfuscated dynamic evaluations.
* **Multi-Format Reporting**: ANSI terminal UI with 0–100 risk scoring, pure JSON (`--json`), standalone offline interactive HTML (`--html`), and OASIS SARIF v2.1.0 (`--sarif`).
* **CI/CD Integration**: Exit code gating (`--ci --fail-on <severity>`) returning standard exit codes (0 = clean, 1 = threshold exceeded, 2 = usage error).
* **Advisory AI Layer**: Opt-in Groq Llama-3 advisory analysis (`--ai`) with pre-transmission credential redaction.

---

## 📖 CLI Usage

```bash
# Basic scan of the current directory
deepcleaner .

# Deep scan including Git commit history
deepcleaner --deep .

# Run in CI mode (fail if HIGH or CRITICAL issues found)
deepcleaner --ci --fail-on high .

# Generate an offline HTML dashboard
deepcleaner --html -o security-report.html .

# Output SARIF format for GitHub Code Scanning
deepcleaner --sarif -o results.sarif .

# Full scan with AI verification (requires GROQ_API_KEY)
deepcleaner --full .

# Interactive fix suggestions
deepcleaner --fix .
```

---

## 🔒 Disclaimers & Safety

* **No scanner can detect 100% of malware samples or software bugs.**
* Static analysis findings may include false positives; verify reachability within your application architecture.
* Vulnerability databases (OSV, NVD) are continuously updated and may be incomplete.
* AI-generated insights are advisory and should be reviewed by an engineer.

---

## 📄 License

MIT License © Google DeepMind Advanced Agentic Coding

