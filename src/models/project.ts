export type ProjectType =
  | 'nodejs'
  | 'python'
  | 'go'
  | 'java'
  | 'php'
  | 'ruby'
  | 'rust'
  | 'csharp'
  | 'cpp'
  | 'docker'
  | 'kubernetes'
  | 'terraform'
  | 'generic';

export interface ProjectMetadata {
  rootPath: string;
  name: string;
  projectTypes: ProjectType[];
  manifestFiles: string[];
  lockFiles: string[];
  totalFiles: number;
  totalBytes: number;
  hasGit: boolean;
  languagesDetected: Record<string, number>;
  ignoredPatterns: string[];
}

export interface DiscoveredFile {
  path: string;
  relativePath: string;
  size: number;
  extension: string;
  language?: string;
  mime?: string;
  isBinary: boolean;
  isArchive: boolean;
  isExecutable: boolean;
  isDisguised: boolean;
  sha256?: string;
}
