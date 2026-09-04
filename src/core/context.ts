import fs from 'node:fs';
import path from 'node:path';
import type { DiscoveredFile, ProjectMetadata } from '../models/project.js';
import type { Finding } from '../models/finding.js';
import type { Logger } from '../utils/logger.js';
import { logger } from '../utils/logger.js';

export interface ScanLimits {
  maxFileSize: number;
  maxTotalBytes: number;
  maxFileCount: number;
  maxDirectoryDepth: number;
  maxArchiveDepth: number;
  maxExtractedBytes: number;
  concurrency: number;
  timeoutMs: number;
}

export interface CliOptions {
  target: string;
  deep?: boolean;
  security?: boolean;
  malware?: boolean;
  secrets?: boolean;
  deps?: boolean;
  config?: boolean;
  ai?: boolean;
  full?: boolean;
  sandbox?: boolean;
  json?: boolean;
  html?: boolean;
  sarif?: boolean;
  ci?: boolean;
  fix?: boolean;
  verbose?: boolean;
  quiet?: boolean;
  offline?: boolean;
  failOn?: 'critical' | 'high' | 'medium' | 'low';
  outputFile?: string;
  ignore?: string[];
  maxFileSize?: number;
  baseline?: string;
  baselineCreate?: string;
  mongodb?: string | boolean;
  noDeps?: boolean;
  noGit?: boolean;
  yara?: boolean;
  clamav?: boolean;
}

export interface UserConfig {
  ignore?: string[];
  failOn?: 'critical' | 'high' | 'medium' | 'low';
  scanners?: {
    secrets?: boolean;
    dependencies?: boolean;
    sast?: boolean;
    malware?: boolean;
    configuration?: boolean;
    yara?: boolean;
    binary?: boolean;
    archive?: boolean;
    git?: boolean;
  };
  ai?: {
    enabled?: boolean;
    model?: string;
    apiKey?: string;
  };
  limits?: Partial<ScanLimits>;
}

export class ScanContext {
  public readonly targetPath: string;
  public readonly absoluteTarget: string;
  public readonly options: CliOptions;
  public readonly userConfig: UserConfig;
  public readonly limits: ScanLimits;
  public readonly logger: Logger;

  public files: DiscoveredFile[] = [];
  public projectMetadata: ProjectMetadata = {
    rootPath: '',
    name: '',
    projectTypes: [],
    manifestFiles: [],
    lockFiles: [],
    totalFiles: 0,
    totalBytes: 0,
    hasGit: false,
    languagesDetected: {},
    ignoredPatterns: []
  };

  public findings: Finding[] = [];
  public startTime = 0;
  public isCancelled = false;

  constructor(targetPath: string, options: CliOptions, userConfig: UserConfig = {}) {
    this.targetPath = targetPath;
    this.absoluteTarget = targetPath;
    this.options = options;
    this.userConfig = userConfig;
    this.logger = logger;

    this.limits = {
      maxFileSize: options.maxFileSize ?? userConfig.limits?.maxFileSize ?? 10 * 1024 * 1024,
      maxTotalBytes: userConfig.limits?.maxTotalBytes ?? 500 * 1024 * 1024,
      maxFileCount: userConfig.limits?.maxFileCount ?? 50000,
      maxDirectoryDepth: userConfig.limits?.maxDirectoryDepth ?? 30,
      maxArchiveDepth: userConfig.limits?.maxArchiveDepth ?? 3,
      maxExtractedBytes: userConfig.limits?.maxExtractedBytes ?? 50 * 1024 * 1024,
      concurrency: userConfig.limits?.concurrency ?? 8,
      timeoutMs: userConfig.limits?.timeoutMs ?? 60000
    };

    this.loadLocalEnv();
  }

  private loadLocalEnv(): void {
    if (process.env.GROQ_API_KEY) return;
    const candidateDirs = [this.absoluteTarget, process.cwd()];
    for (const dir of candidateDirs) {
      const envPath = path.join(dir, '.env');
      if (fs.existsSync(envPath)) {
        try {
          const content = fs.readFileSync(envPath, 'utf-8');
          const match = content.match(/^GROQ_API_KEY\s*=\s*['"]?([^\s'"]+)['"]?/m);
          if (match && match[1]) {
            process.env.GROQ_API_KEY = match[1];
            break;
          }
        } catch {
          // ignore
        }
      }
    }
  }

  isScannerEnabled(scannerId: string): boolean {
    const opts = this.options;
    if (scannerId === 'dependencies' && opts.noDeps) return false;
    if (scannerId === 'git' && opts.noGit) return false;

    const hasFocus = opts.security || opts.malware || opts.secrets || opts.deps || opts.config;
    if (opts.full) return true;

    if (hasFocus) {
      if (scannerId === 'secrets' && opts.secrets) return true;
      if (scannerId === 'sast' && opts.security) return true;
      if (scannerId === 'malware' && opts.malware) return true;
      if (scannerId === 'suspicious' && opts.malware) return true;
      if (scannerId === 'dependencies' && opts.deps) return true;
      if (scannerId === 'configuration' && opts.config) return true;
      if (scannerId === 'yara' && (opts.malware || opts.security)) return true;
      if (scannerId === 'binaries' && (opts.malware || opts.security)) return true;
      if (scannerId === 'archives' && (opts.malware || opts.security)) return true;
      if (scannerId === 'git' && opts.secrets) return true;
      return false;
    }

    const conf = this.userConfig.scanners;
    if (conf) {
      if (scannerId === 'secrets' && conf.secrets === false) return false;
      if (scannerId === 'dependencies' && conf.dependencies === false) return false;
      if (scannerId === 'sast' && conf.sast === false) return false;
      if (scannerId === 'malware' && conf.malware === false) return false;
      if (scannerId === 'configuration' && conf.configuration === false) return false;
      if (scannerId === 'yara' && conf.yara === false) return false;
      if (scannerId === 'binaries' && conf.binary === false) return false;
      if (scannerId === 'archives' && conf.archive === false) return false;
      if (scannerId === 'git' && conf.git === false) return false;
    }

    return true;
  }
}
