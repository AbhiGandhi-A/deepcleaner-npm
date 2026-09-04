# Changelog

All notable changes to **DeepCleaner** (`deepcleaner-ag`) will be documented in this file.

## [1.0.5] - 2026-09-04

### Fixed
- **Database Connection Safety**: Prevented `MongoParseError` when scanning projects containing generic or non-MongoDB `DATABASE_URL` (such as PostgreSQL/MySQL).
- **Storage Diagnostics**: Enhanced `doctor` and MongoDB persistence layer with strict URI scheme validation.

## [1.0.4] - 2026-09-04

### Improved
- **CLI Help Output**: Configured global command help so `deepcleaner --help` immediately displays all available CLI flags, subcommands (`scan`, `doctor`), and scan options.

## [1.0.3] - 2026-09-04

### Fixed
- **Permissions False Positives**: Template files (`.env.example`, `.env.sample`, `.env.template`, `example.env`) are excluded from sensitive credential classification.
- **Classification Separation**: Completely separated Malware Analysis (`Confirmed Malware`, `Potentially Malicious`, `Suspicious Indicators`, `Needs Review`) from Security Findings (`Dependency Vulnerabilities`, `Permission Issues`, `Secrets`, `SAST`, `Security Configuration`). Dependency vulnerabilities no longer increment suspicious malware counts.
- **Risk Score Breakdown**: Added transparent risk contributors to risk score explanation.
- **Environment & Telemetry Auto-Detection**: Enhanced `loadEnv` to search multiple candidate locations with built-in cloud persistence fallbacks for MongoDB Atlas and Groq AI Advisor.
- **Regression Tests**: Added test suites verifying template handling, isolated dependency categorization, and secret detection.

## [1.0.2] - 2026-09-04

### Added
- **Multi-Step Behavioral Attack-Chain Tracker**: Correlates credential access, data encoding, remote network exfiltration, and dynamic execution across AST nodes.
- **Evidence-Based Confidence & Classification Engine**: Classifies findings into `clean`, `needs_review`, `suspicious`, `potentially_malicious`, and `confirmed_malware`.
- **ClamAV Antivirus Integration**: Added detection for `clamscan` and `clamdscan` in doctor diagnostic and engine status reporting.
- **Extended Manifest Parsing**: Added support for `yarn.lock` and `pnpm-lock.yaml`, and malicious lifecycle script checks (`preinstall`/`postinstall`).
- **Container-Aware Inode Permissions**: Added container environment detection (`/.dockerenv`, `CODESPACES`, `GITHUB_ACTIONS`) to eliminate false-positive permissions noise.
- **Accuracy Benchmark Suite**: Automated benchmark test suite confirming 100% precision on clean projects and verified synthetic attack chains.
- **CLI Options**: Added `--no-deps`, `--no-git`, `--yara`, `--clamav` options.

### Changed
- Refined binary scanner to assign non-malicious binaries as `needs_review` rather than high-risk alerts.
- Updated terminal and JSON report format with full scan metrics table and classification breakdowns.

## [1.0.0] - 2026-09-03

### Added
- Initial public release with 11 core scanners, OSV dependency intelligence, Babel SAST, Groq AI advisory, and MongoDB telemetry persistence.

