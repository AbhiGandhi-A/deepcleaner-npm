import path from 'node:path';
import type { ProjectType } from '../models/project.js';

export interface ProjectTypeDetection {
  types: ProjectType[];
  manifests: string[];
  lockfiles: string[];
}

export function detectProjectTypes(relativeFilePaths: string[]): ProjectTypeDetection {
  const types = new Set<ProjectType>();
  const manifests: string[] = [];
  const lockfiles: string[] = [];

  for (const relPath of relativeFilePaths) {
    const base = path.basename(relPath);

    if (base === 'package.json') {
      types.add('nodejs');
      manifests.push(relPath);
    }
    if (base === 'package-lock.json' || base === 'yarn.lock' || base === 'pnpm-lock.yaml' || base === 'npm-shrinkwrap.json') {
      types.add('nodejs');
      lockfiles.push(relPath);
    }

    if (base === 'requirements.txt' || base === 'setup.py' || base === 'pyproject.toml' || base === 'Pipfile') {
      types.add('python');
      manifests.push(relPath);
    }
    if (base === 'poetry.lock' || base === 'Pipfile.lock') {
      types.add('python');
      lockfiles.push(relPath);
    }

    if (base === 'composer.json') {
      types.add('php');
      manifests.push(relPath);
    }
    if (base === 'composer.lock') {
      types.add('php');
      lockfiles.push(relPath);
    }

    if (base === 'go.mod') {
      types.add('go');
      manifests.push(relPath);
    }
    if (base === 'go.sum') {
      types.add('go');
      lockfiles.push(relPath);
    }

    if (base === 'pom.xml' || base === 'build.gradle' || base === 'build.gradle.kts') {
      types.add('java');
      manifests.push(relPath);
    }

    if (base === 'Gemfile') {
      types.add('ruby');
      manifests.push(relPath);
    }
    if (base === 'Gemfile.lock') {
      types.add('ruby');
      lockfiles.push(relPath);
    }

    if (base === 'Cargo.toml') {
      types.add('rust');
      manifests.push(relPath);
    }
    if (base === 'Cargo.lock') {
      types.add('rust');
      lockfiles.push(relPath);
    }

    if (base.endsWith('.csproj') || base.endsWith('.sln')) {
      types.add('csharp');
      manifests.push(relPath);
    }

    if (base.toLowerCase().startsWith('dockerfile') || base === 'docker-compose.yml' || base === 'docker-compose.yaml') {
      types.add('docker');
    }

    if (base.endsWith('.tf') || base.endsWith('.tfvars')) {
      types.add('terraform');
    }
  }

  if (types.size === 0) {
    types.add('generic');
  }

  return {
    types: Array.from(types),
    manifests,
    lockfiles
  };
}
