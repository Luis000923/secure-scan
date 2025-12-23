/**
 * Python Dependency Parser
 * Parses requirements.txt, Pipfile, Pipfile.lock, and pyproject.toml
 */

import { BaseDependencyParser } from '../base';
import { 
  DependencyManifest, 
  ManifestFileType, 
  PackageEcosystem,
  Dependency
} from '../../types';

/**
 * Pipfile structure
 */
interface Pipfile {
  packages?: Record<string, string | PipfileDependency>;
  'dev-packages'?: Record<string, string | PipfileDependency>;
}

interface PipfileDependency {
  version?: string;
  extras?: string[];
  git?: string;
  ref?: string;
}

/**
 * Pipfile.lock structure
 */
interface PipfileLock {
  default?: Record<string, PipfileLockDependency>;
  develop?: Record<string, PipfileLockDependency>;
}

interface PipfileLockDependency {
  version?: string;
  hashes?: string[];
  markers?: string;
  index?: string;
}

/**
 * pyproject.toml structure (simplified)
 */
interface PyProjectToml {
  project?: {
    dependencies?: string[];
    'optional-dependencies'?: Record<string, string[]>;
  };
  'build-system'?: {
    requires?: string[];
  };
  tool?: {
    poetry?: {
      dependencies?: Record<string, string | PoetryDependency>;
      'dev-dependencies'?: Record<string, string | PoetryDependency>;
    };
  };
}

interface PoetryDependency {
  version?: string;
  optional?: boolean;
  extras?: string[];
  git?: string;
  branch?: string;
}

/**
 * Python Dependency Parser
 */
export class PythonDependencyParser extends BaseDependencyParser {
  name = 'Python Dependency Parser';
  supportedFiles: ManifestFileType[] = ['requirements.txt', 'Pipfile', 'Pipfile.lock', 'pyproject.toml'];
  ecosystem: PackageEcosystem = 'pip';

  /**
   * Parse manifest file
   */
  async parse(filePath: string, content: string): Promise<DependencyManifest> {
    this.logParsing(filePath);

    const fileName = filePath.split(/[/\\]/).pop() || '';
    const dependencies: Dependency[] = [];
    const parseErrors: string[] = [];

    try {
      if (fileName === 'requirements.txt' || fileName.endsWith('requirements.txt')) {
        dependencies.push(...this.parseRequirementsTxt(content, filePath, parseErrors));
      } else if (fileName === 'Pipfile') {
        dependencies.push(...this.parsePipfile(content, filePath, parseErrors));
      } else if (fileName === 'Pipfile.lock') {
        dependencies.push(...this.parsePipfileLock(content, filePath, parseErrors));
      } else if (fileName === 'pyproject.toml') {
        dependencies.push(...this.parsePyProjectToml(content, filePath, parseErrors));
      }
    } catch (error) {
      const errorMsg = error instanceof Error ? error.message : String(error);
      parseErrors.push(`Failed to parse ${fileName}: ${errorMsg}`);
      this.logError(filePath, errorMsg);
    }

    return {
      filePath,
      fileType: this.getFileType(fileName),
      ecosystem: this.ecosystem,
      dependencies,
      parseErrors: parseErrors.length > 0 ? parseErrors : undefined,
      isLockFile: fileName === 'Pipfile.lock'
    };
  }

  /**
   * Get manifest file type
   */
  private getFileType(fileName: string): ManifestFileType {
    if (fileName === 'Pipfile') return 'Pipfile';
    if (fileName === 'Pipfile.lock') return 'Pipfile.lock';
    if (fileName === 'pyproject.toml') return 'pyproject.toml';
    return 'requirements.txt';
  }

  /**
   * Parse requirements.txt
   */
  private parseRequirementsTxt(content: string, filePath: string, errors: string[]): Dependency[] {
    const dependencies: Dependency[] = [];
    const lines = content.split('\n');
    let lineNumber = 0;

    for (const line of lines) {
      lineNumber++;
      const trimmed = line.trim();

      // Skip comments, empty lines, and options
      if (!trimmed || trimmed.startsWith('#') || trimmed.startsWith('-')) {
        continue;
      }

      // Skip URLs and file paths
      if (trimmed.includes('://') || trimmed.startsWith('.') || trimmed.startsWith('/')) {
        continue;
      }

      // Parse requirement line
      const parsed = this.parseRequirementLine(trimmed);
      if (parsed) {
        dependencies.push(this.createDependency(parsed.name, parsed.version, filePath, {
          dependencyType: 'direct',
          lineNumber
        }));
      }
    }

    return dependencies;
  }

  /**
   * Parse a single requirement line
   */
  private parseRequirementLine(line: string): { name: string; version: string } | null {
    // Handle environment markers (e.g., package ; python_version >= "3.7")
    const markerIndex = line.indexOf(';');
    if (markerIndex > 0) {
      line = line.substring(0, markerIndex).trim();
    }

    // Handle extras (e.g., package[extra1,extra2])
    const extrasIndex = line.indexOf('[');
    if (extrasIndex > 0) {
      const endExtras = line.indexOf(']', extrasIndex);
      if (endExtras > extrasIndex) {
        line = line.substring(0, extrasIndex) + line.substring(endExtras + 1);
      }
    }

    // Parse version specifiers
    // Patterns: ==, >=, <=, >, <, ~=, !=, ===
    const versionOperators = ['===', '~=', '==', '>=', '<=', '!=', '>', '<'];
    
    for (const op of versionOperators) {
      const opIndex = line.indexOf(op);
      if (opIndex > 0) {
        const name = line.substring(0, opIndex).trim();
        const version = line.substring(opIndex).trim();
        return { name: this.normalizePythonPackageName(name), version };
      }
    }

    // No version specified
    const name = line.trim();
    if (name && /^[a-zA-Z0-9][\w.-]*$/.test(name)) {
      return { name: this.normalizePythonPackageName(name), version: '*' };
    }

    return null;
  }

  /**
   * Normalize Python package name (PEP 503)
   */
  private normalizePythonPackageName(name: string): string {
    return name.toLowerCase().replace(/[-_.]+/g, '-');
  }

  /**
   * Parse Pipfile (TOML format)
   */
  private parsePipfile(content: string, filePath: string, errors: string[]): Dependency[] {
    const dependencies: Dependency[] = [];
    
    // Simple TOML parser for Pipfile
    const sections = this.parseSimpleToml(content);
    
    // Parse packages
    if (sections.packages) {
      for (const [name, value] of Object.entries(sections.packages)) {
        const version = this.extractPipfileVersion(value);
        dependencies.push(this.createDependency(name, version, filePath, {
          dependencyType: 'direct'
        }));
      }
    }

    // Parse dev-packages
    if (sections['dev-packages']) {
      for (const [name, value] of Object.entries(sections['dev-packages'])) {
        const version = this.extractPipfileVersion(value);
        dependencies.push(this.createDependency(name, version, filePath, {
          dependencyType: 'dev'
        }));
      }
    }

    return dependencies;
  }

  /**
   * Extract version from Pipfile dependency value
   */
  private extractPipfileVersion(value: any): string {
    if (typeof value === 'string') {
      return value === '*' ? '*' : value;
    }
    if (typeof value === 'object' && value !== null) {
      return value.version || '*';
    }
    return '*';
  }

  /**
   * Simple TOML parser (handles basic Pipfile structure)
   */
  private parseSimpleToml(content: string): Record<string, Record<string, any>> {
    const sections: Record<string, Record<string, any>> = {};
    let currentSection = '';
    
    const lines = content.split('\n');
    
    for (const line of lines) {
      const trimmed = line.trim();
      
      // Skip comments and empty lines
      if (!trimmed || trimmed.startsWith('#')) continue;
      
      // Section header
      const sectionMatch = trimmed.match(/^\[([^\]]+)\]$/);
      if (sectionMatch) {
        currentSection = sectionMatch[1];
        sections[currentSection] = {};
        continue;
      }
      
      // Key-value pair
      if (currentSection) {
        const kvMatch = trimmed.match(/^([^=]+)\s*=\s*(.+)$/);
        if (kvMatch) {
          const key = kvMatch[1].trim().replace(/^["']|["']$/g, '');
          let value = kvMatch[2].trim();
          
          // Parse value
          if (value.startsWith('{')) {
            // Inline table - extract version
            const versionMatch = value.match(/version\s*=\s*["']([^"']+)["']/);
            value = versionMatch ? versionMatch[1] : '*';
          } else {
            // Remove quotes
            value = value.replace(/^["']|["']$/g, '');
          }
          
          sections[currentSection][key] = value;
        }
      }
    }
    
    return sections;
  }

  /**
   * Parse Pipfile.lock
   */
  private parsePipfileLock(content: string, filePath: string, errors: string[]): Dependency[] {
    const dependencies: Dependency[] = [];
    
    let lockFile: PipfileLock;
    try {
      lockFile = JSON.parse(content);
    } catch (e) {
      errors.push('Invalid JSON in Pipfile.lock');
      return dependencies;
    }

    // Parse default (production) dependencies
    if (lockFile.default) {
      for (const [name, dep] of Object.entries(lockFile.default)) {
        const version = dep.version?.replace(/^==/, '') || '*';
        dependencies.push(this.createDependency(name, version, filePath, {
          dependencyType: 'direct',
          resolvedVersion: version
        }));
      }
    }

    // Parse develop dependencies
    if (lockFile.develop) {
      for (const [name, dep] of Object.entries(lockFile.develop)) {
        const version = dep.version?.replace(/^==/, '') || '*';
        dependencies.push(this.createDependency(name, version, filePath, {
          dependencyType: 'dev',
          resolvedVersion: version
        }));
      }
    }

    return dependencies;
  }

  /**
   * Parse pyproject.toml
   */
  private parsePyProjectToml(content: string, filePath: string, errors: string[]): Dependency[] {
    const dependencies: Dependency[] = [];
    const sections = this.parseSimpleToml(content);
    
    // This is a simplified parser - for production, use a proper TOML library
    // Parse dependencies from various formats
    
    // Try to parse [project.dependencies] format (PEP 621)
    const lines = content.split('\n');
    let inDependencies = false;
    let inDevDependencies = false;
    
    for (const line of lines) {
      const trimmed = line.trim();
      
      // Track sections
      if (trimmed === '[project]' || trimmed === '[tool.poetry.dependencies]') {
        inDependencies = true;
        inDevDependencies = false;
        continue;
      }
      if (trimmed === '[tool.poetry.dev-dependencies]' || trimmed === '[project.optional-dependencies]') {
        inDependencies = true;
        inDevDependencies = true;
        continue;
      }
      if (trimmed.startsWith('[') && trimmed.endsWith(']')) {
        inDependencies = false;
        inDevDependencies = false;
        continue;
      }
      
      // Parse dependencies line
      if (inDependencies && !trimmed.startsWith('#')) {
        // Handle 'dependencies = [...]' format
        if (trimmed.startsWith('dependencies') && trimmed.includes('[')) {
          const arrayContent = this.extractTomlArray(content, 'dependencies');
          for (const dep of arrayContent) {
            const parsed = this.parseRequirementLine(dep);
            if (parsed) {
              dependencies.push(this.createDependency(parsed.name, parsed.version, filePath, {
                dependencyType: inDevDependencies ? 'dev' : 'direct'
              }));
            }
          }
        }
        // Handle 'package = "version"' format (Poetry)
        else if (trimmed.includes('=')) {
          const match = trimmed.match(/^([^=]+)\s*=\s*["']?([^"'\n]+)["']?/);
          if (match) {
            const name = match[1].trim();
            let version = match[2].trim();
            
            // Skip python version specification
            if (name === 'python') continue;
            
            // Handle caret/tilde version
            if (version.startsWith('^') || version.startsWith('~')) {
              version = version.substring(1);
            }
            
            dependencies.push(this.createDependency(name, version, filePath, {
              dependencyType: inDevDependencies ? 'dev' : 'direct'
            }));
          }
        }
      }
    }

    return dependencies;
  }

  /**
   * Extract TOML array content
   */
  private extractTomlArray(content: string, key: string): string[] {
    const result: string[] = [];
    const regex = new RegExp(`${key}\\s*=\\s*\\[([^\\]]+)\\]`, 's');
    const match = content.match(regex);
    
    if (match) {
      const arrayContent = match[1];
      const items = arrayContent.match(/"[^"]+"|'[^']+'/g);
      if (items) {
        for (const item of items) {
          result.push(item.replace(/^["']|["']$/g, ''));
        }
      }
    }
    
    return result;
  }
}

export default PythonDependencyParser;
