# deepcleaner-ag

> **High-Accuracy, Multi-Layer Defensive Security & Malware Indicator Scanner for Software Projects**

[![npm version](https://img.shields.io/npm/v/deepcleaner-ag.svg)](https://www.npmjs.com/package/deepcleaner-ag)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![Node.js Version](https://img.shields.io/badge/node-%3E%3D20.0.0-brightgreen.svg)](https://nodejs.org/)

DeepCleaner is an evidence-driven, local-first developer security scanner designed for high accuracy and minimal false positives. It performs comprehensive recursive scanning across normal and hidden project files, AST taint-tracking, multi-step behavioral attack chain correlation, OSV dependency lookups, configuration auditing, and optional AI-assisted verification.

---

## 🎯 Accuracy Philosophy & The Golden Rule

> **Accuracy > Number of Findings.**
> DeepCleaner prioritizes precision over raw alert counts. A file is **never** labeled as malware solely because it contains minified code, encoded strings, shell commands, dynamic imports, or unusual JavaScript.

### Multi-Tier Classification
Findings are categorized using evidence-based confidence:
* **Confirmed Malware**: Requires verified cryptographic signatures, known threat intel hashes, or full behavioral attack chains.
* **Potentially Malicious**: High-confidence suspicious correlation requiring immediate review.
* **Suspicious**: Anomalies (e.g. disguised executables, reverse shell patterns, obfuscated loaders).
* **Needs Review**: Informational or unverified security practices.

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

* **Behavioral Attack-Chain Tracker**: Correlates multi-step attack flows across AST nodes (e.g., `Credential Access (id_rsa/.env)` + `Base64/XOR Encoding` + `Network Transmission (fetch/socket)` + `Dynamic Execution`).
* **Secret & Credential Scanner**: 40+ patterns for cloud credentials (AWS, Google, Azure), tokens (GitHub, GitLab, Slack, Discord, Stripe), private certificates, JWTs, and database URIs with Shannon entropy validation and strict evidence masking.
* **AST-Based SAST**: Babel AST traversal with taint-tracking from untrusted sources (`req.query`, `req.body`, `req.params`) to sensitive sinks (`exec`, `eval`, `innerHTML`, `db.query`). Multi-language support for Python, PHP, Go, Java, and C/C++.
* **Dependency Intelligence**: Multi-ecosystem manifest parsing (`package.json`, `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`, `requirements.txt`, `composer.lock`, `go.mod`) with batched OSV queries, lifecycle script auditing (`preinstall`/`postinstall`), and offline fallback.
* **Polyglot & Binary Inspection**: Magic-byte signature verification detecting disguised executables (e.g. PE/ELF payloads hidden with `.png` or `.pdf` extensions).
* **Container-Aware Inode Permissions**: Suppresses false positives in containerized environments (Docker, GitHub Actions, Codespaces) while alerting on truly dangerous writable credentials and scripts.
* **External Engine Integration**: Transparently detects local `yara` and `clamscan`/`clamdscan` installations with graceful fallbacks.
* **Multi-Format Reporting**: ANSI terminal UI with 0–100 risk scoring, pure JSON (`--json`), standalone offline interactive HTML (`--html`), and OASIS SARIF v2.1.0 (`--sarif`).
* **Database Telemetry & Persistence**: Optional direct scan report synchronization into MongoDB Atlas (`--mongodb`).
* **Advisory AI Layer**: Opt-in Groq Llama-3 advisory analysis (`--ai`) with pre-transmission credential redaction.

---

## 📖 CLI Usage

```bash
# Basic scan of the current directory
deepcleaner .

# Deep scan including Git commit history
deepcleaner --deep .

# Run with focus on malware indicators
deepcleaner --malware .

# Disable dependency queries or git scans
deepcleaner --no-deps --no-git .

# Run in CI mode (fail if HIGH or CRITICAL issues found)
deepcleaner --ci --fail-on high .

# Generate an offline HTML dashboard
deepcleaner --html -o security-report.html .

# Output pure JSON for automated tooling
deepcleaner --json .

# Push scan results directly to MongoDB
deepcleaner --mongodb .

# Run system diagnostic health check
deepcleaner doctor
```

---

## 🔒 Disclaimers & Safety

* **No automated scanner can detect 100% of malware samples or software bugs.**
* Static analysis findings may include false positives; verify reachability within your application architecture.
* Vulnerability databases (OSV, NVD) are continuously updated and may be incomplete.
* AI-generated insights are advisory and should be verified by a security professional.

---

## 📄 License

MIT License © Abhishek Gandhi
