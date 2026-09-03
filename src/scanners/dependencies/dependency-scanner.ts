import fs from 'node:fs';
import path from 'node:path';
import type { IScanner, ScannerResult } from '../../models/scanner.js';
import type { Finding, Severity } from '../../models/finding.js';
import type { ScanContext } from '../../core/context.js';
import { queryOsvBatch, type OsvPackageQuery, type OsvVulnerability } from '../../intelligence/osv.js';

interface ParsedDep {
  name: string;
  version: string;
  ecosystem: string;
  manifestFile: string;
}

export class DependencyScanner implements IScanner {
  public readonly id = 'dependencies';
  public readonly name = 'Dependency Vulnerability Scanner';
  public readonly description = 'Parses lockfiles and package manifests, querying OSV for known vulnerabilities (CVE/GHSA).';

  isAvailable(_ctx: ScanContext): boolean {
    return true;
  }

  shouldRun(ctx: ScanContext): boolean {
    return ctx.isScannerEnabled(this.id);
  }

  async scan(ctx: ScanContext): Promise<ScannerResult> {
    const startTime = Date.now();
    const findings: Finding[] = [];
    const parsedDeps: ParsedDep[] = [];
    let filesScanned = 0;

    for (const file of ctx.files) {
      const base = path.basename(file.relativePath);

      if (base === 'package.json') {
        filesScanned++;
        try {
          const content = JSON.parse(fs.readFileSync(file.path, 'utf-8'));
          const allDeps = {
            ...content.dependencies,
            ...content.devDependencies,
            ...content.optionalDependencies
          };
          for (const [name, rawVer] of Object.entries(allDeps)) {
            if (typeof rawVer === 'string') {
              const cleanVer = rawVer.replace(/[\^~>=<]/g, '').trim();
              if (cleanVer && /^[0-9]+\.[0-9]+/.test(cleanVer)) {
                parsedDeps.push({ name, version: cleanVer, ecosystem: 'npm', manifestFile: file.relativePath });
              }
            }
          }
        } catch {
          // ignore
        }
      }

      if (base === 'package-lock.json') {
        filesScanned++;
        try {
          const content = JSON.parse(fs.readFileSync(file.path, 'utf-8'));
          if (content.packages) {
            for (const [pkgPath, info] of Object.entries<any>(content.packages)) {
              if (pkgPath === '' || !info.version) continue;
              const name = pkgPath.replace(/^node_modules\//, '');
              parsedDeps.push({ name, version: info.version, ecosystem: 'npm', manifestFile: file.relativePath });
            }
          } else if (content.dependencies) {
            for (const [name, info] of Object.entries<any>(content.dependencies)) {
              if (info.version) {
                parsedDeps.push({ name, version: info.version, ecosystem: 'npm', manifestFile: file.relativePath });
              }
            }
          }
        } catch {
          // ignore
        }
      }

      if (base === 'requirements.txt') {
        filesScanned++;
        try {
          const lines = fs.readFileSync(file.path, 'utf-8').split(/\r?\n/);
          for (const line of lines) {
            const clean = line.trim();
            if (!clean || clean.startsWith('#')) continue;
            const match = clean.match(/^([a-zA-Z0-9_.-]+)\s*==\s*([0-9a-zA-Z_.-]+)/);
            if (match) {
              parsedDeps.push({ name: match[1], version: match[2], ecosystem: 'PyPI', manifestFile: file.relativePath });
            }
          }
        } catch {
          // ignore
        }
      }

      if (base === 'composer.lock') {
        filesScanned++;
        try {
          const content = JSON.parse(fs.readFileSync(file.path, 'utf-8'));
          if (Array.isArray(content.packages)) {
            for (const pkg of content.packages) {
              if (pkg.name && pkg.version) {
                parsedDeps.push({
                  name: pkg.name,
                  version: pkg.version.replace(/^v/, ''),
                  ecosystem: 'Packagist',
                  manifestFile: file.relativePath
                });
              }
            }
          }
        } catch {
          // ignore
        }
      }

      if (base === 'go.mod') {
        filesScanned++;
        try {
          const lines = fs.readFileSync(file.path, 'utf-8').split(/\r?\n/);
          for (const line of lines) {
            const clean = line.trim();
            const match = clean.match(/^require\s+([a-zA-Z0-9._/-]+)\s+v?([0-9a-zA-Z.-]+)/) || clean.match(/^\t([a-zA-Z0-9._/-]+)\s+v?([0-9a-zA-Z.-]+)/);
            if (match) {
              parsedDeps.push({ name: match[1], version: match[2], ecosystem: 'Go', manifestFile: file.relativePath });
            }
          }
        } catch {
          // ignore
        }
      }
    }

    const queryMap = new Map<string, OsvPackageQuery>();
    for (const dep of parsedDeps) {
      const key = `${dep.ecosystem.toLowerCase()}:${dep.name.toLowerCase()}@${dep.version}`;
      if (!queryMap.has(key)) {
        queryMap.set(key, {
          package: { name: dep.name, ecosystem: dep.ecosystem },
          version: dep.version
        });
      }
    }

    if (ctx.options.offline) {
      ctx.logger.info('Dependency scanner running in offline mode (OSV queries skipped).');
      return {
        scannerId: this.id,
        name: this.name,
        status: 'completed',
        durationMs: Date.now() - startTime,
        filesScanned,
        findings,
        skipReason: 'Offline mode requested'
      };
    }

    if (queryMap.size > 0) {
      ctx.logger.verbose(`Querying OSV vulnerability database for ${queryMap.size} dependencies...`);
      const osvResults = await queryOsvBatch(Array.from(queryMap.values()), ctx.limits.timeoutMs);

      for (const dep of parsedDeps) {
        const queryKey = `${dep.ecosystem.toLowerCase()}:${dep.name.toLowerCase()}@${dep.version}`;
        const vulns = osvResults.get(queryKey);
        if (vulns && vulns.length > 0) {
          for (const vuln of vulns) {
            const cveList = vuln.aliases?.filter((a) => a.startsWith('CVE-')) || [];
            const ghsaList = vuln.aliases?.filter((a) => a.startsWith('GHSA-')) || (vuln.id.startsWith('GHSA-') ? [vuln.id] : []);

            let fixedVersion: string | undefined;
            if (vuln.affected) {
              for (const aff of vuln.affected) {
                if (aff.ranges) {
                  for (const range of aff.ranges) {
                    for (const ev of range.events) {
                      if (ev.fixed) {
                        fixedVersion = ev.fixed;
                        break;
                      }
                    }
                  }
                }
              }
            }

            let severity: Severity = 'HIGH';
            if (vuln.severity) {
              for (const s of vuln.severity) {
                const score = parseFloat(s.score);
                if (!isNaN(score)) {
                  if (score >= 9.0) severity = 'CRITICAL';
                  else if (score >= 7.0) severity = 'HIGH';
                  else if (score >= 4.0) severity = 'MEDIUM';
                  else severity = 'LOW';
                }
              }
            }

            findings.push({
              id: vuln.id,
              scanner: this.id,
              category: 'Dependencies',
              severity,
              confidence: 95,
              title: `Vulnerable dependency: ${dep.name}@${dep.version} (${vuln.id})`,
              description: vuln.summary || vuln.details || `Known vulnerability in ${dep.name}@${dep.version}`,
              file: dep.manifestFile,
              evidence: `Dependency: "${dep.name}": "${dep.version}" (${dep.ecosystem})`,
              redactedEvidence: `Dependency: "${dep.name}": "${dep.version}" (${dep.ecosystem})`,
              remediation: fixedVersion
                ? `Upgrade ${dep.name} to version ${fixedVersion} or higher.`
                : `Update ${dep.name} to a secure patched version.`,
              cve: cveList.length > 0 ? cveList : undefined,
              ghsa: ghsaList.length > 0 ? ghsaList : undefined,
              osv: [vuln.id],
              references: [`https://osv.dev/vulnerability/${vuln.id}`]
            });
          }
        }
      }
    }

    return {
      scannerId: this.id,
      name: this.name,
      status: 'completed',
      durationMs: Date.now() - startTime,
      filesScanned,
      findings
    };
  }
}
