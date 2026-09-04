import path from 'node:path';

export const EXTENSION_LANGUAGE_MAP: Record<string, string> = {
  js: 'javascript',
  mjs: 'javascript',
  cjs: 'javascript',
  jsx: 'javascript',
  ts: 'typescript',
  mts: 'typescript',
  cts: 'typescript',
  tsx: 'typescript',
  py: 'python',
  pyw: 'python',
  php: 'php',
  phtml: 'php',
  go: 'go',
  java: 'java',
  kt: 'kotlin',
  rs: 'rust',
  rb: 'ruby',
  c: 'c',
  h: 'c',
  cpp: 'cpp',
  cc: 'cpp',
  cxx: 'cpp',
  hpp: 'cpp',
  cs: 'csharp',
  sh: 'shell',
  bash: 'shell',
  zsh: 'shell',
  ps1: 'powershell',
  psm1: 'powershell',
  bat: 'batch',
  cmd: 'batch',
  html: 'html',
  htm: 'html',
  css: 'css',
  scss: 'css',
  sass: 'css',
  json: 'json',
  yaml: 'yaml',
  yml: 'yaml',
  xml: 'xml',
  sql: 'sql',
  tf: 'terraform',
  tfvars: 'terraform',
  dockerfile: 'dockerfile',
  toml: 'toml',
  ini: 'ini',
  env: 'dotenv',
  properties: 'properties'
};

export const FILENAME_LANGUAGE_MAP: Record<string, string> = {
  Dockerfile: 'dockerfile',
  'docker-compose.yml': 'yaml',
  'docker-compose.yaml': 'yaml',
  Makefile: 'makefile',
  Jenkinsfile: 'groovy',
  Vagrantfile: 'ruby',
  Gemfile: 'ruby',
  Rakefile: 'ruby'
};

export function detectLanguage(filename: string): string | undefined {
  const base = path.basename(filename);

  if (FILENAME_LANGUAGE_MAP[base]) {
    return FILENAME_LANGUAGE_MAP[base];
  }

  if (base.toLowerCase().startsWith('dockerfile')) {
    return 'dockerfile';
  }

  if (base.startsWith('.env')) {
    return 'dotenv';
  }

  const ext = path.extname(filename).toLowerCase().replace(/^\./, '');
  return EXTENSION_LANGUAGE_MAP[ext];
}
