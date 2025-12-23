/**
 * PHP Dependency Parser
 * Parses composer.json and composer.lock
 */

import { BaseDependencyParser } from '../base';
import { 
  DependencyManifest, 
  ManifestFileType, 
  PackageEcosystem,
  Dependency
} from '../../types';

/**
 * composer.json structure
 */
interface ComposerJson {
  name?: string;
  version?: string;
  require?: Record<string, string>;
  'require-dev'?: Record<string, string>;
  scripts?: Record<string, string | string[]>;
}

/**
 * composer.lock structure
 */
interface ComposerLock {
  packages?: ComposerPackage[];
  'packages-dev'?: ComposerPackage[];
}

interface ComposerPackage {
  name: string;
  version: string;
  require?: Record<string, string>;
  'require-dev'?: Record<string, string>;
  type?: string;
  license?: string | string[];
  abandoned?: boolean | string;
}

/**
 * PHP Dependency Parser
 */
export class PHPDependencyParser extends BaseDependencyParser {
  name = 'PHP Dependency Parser';
  supportedFiles: ManifestFileType[] = ['composer.json', 'composer.lock'];
  ecosystem: PackageEcosystem = 'composer';

  /**
   * Parse manifest file
   */
  async parse(filePath: string, content: string): Promise<DependencyManifest> {
    this.logParsing(filePath);

    const fileName = filePath.split(/[/\\]/).pop() || '';
    const dependencies: Dependency[] = [];
    const parseErrors: string[] = [];

    try {
      if (fileName === 'composer.json') {
        dependencies.push(...this.parseComposerJson(content, filePath, parseErrors));
      } else if (fileName === 'composer.lock') {
        dependencies.push(...this.parseComposerLock(content, filePath, parseErrors));
      }
    } catch (error) {
      const errorMsg = error instanceof Error ? error.message : String(error);
      parseErrors.push(`Failed to parse ${fileName}: ${errorMsg}`);
      this.logError(filePath, errorMsg);
    }

    return {
      filePath,
      fileType: fileName as ManifestFileType,
      ecosystem: this.ecosystem,
      dependencies,
      parseErrors: parseErrors.length > 0 ? parseErrors : undefined,
      isLockFile: fileName === 'composer.lock'
    };
  }

  /**
   * Parse composer.json
   */
  private parseComposerJson(content: string, filePath: string, errors: string[]): Dependency[] {
    const dependencies: Dependency[] = [];
    
    let composer: ComposerJson;
    try {
      composer = JSON.parse(content);
    } catch (e) {
      errors.push('Invalid JSON in composer.json');
      return dependencies;
    }

    // Parse require
    if (composer.require) {
      for (const [name, version] of Object.entries(composer.require)) {
        // Skip PHP and extensions
        if (name === 'php' || name.startsWith('ext-')) continue;
        
        dependencies.push(this.createDependency(name, version, filePath, {
          dependencyType: 'direct'
        }));
      }
    }

    // Parse require-dev
    if (composer['require-dev']) {
      for (const [name, version] of Object.entries(composer['require-dev'])) {
        // Skip PHP and extensions
        if (name === 'php' || name.startsWith('ext-')) continue;
        
        dependencies.push(this.createDependency(name, version, filePath, {
          dependencyType: 'dev'
        }));
      }
    }

    return dependencies;
  }

  /**
   * Parse composer.lock
   */
  private parseComposerLock(content: string, filePath: string, errors: string[]): Dependency[] {
    const dependencies: Dependency[] = [];
    
    let lockFile: ComposerLock;
    try {
      lockFile = JSON.parse(content);
    } catch (e) {
      errors.push('Invalid JSON in composer.lock');
      return dependencies;
    }

    // Parse packages
    if (lockFile.packages) {
      for (const pkg of lockFile.packages) {
        dependencies.push(this.createDependency(pkg.name, pkg.version, filePath, {
          dependencyType: 'direct',
          resolvedVersion: pkg.version,
          license: Array.isArray(pkg.license) ? pkg.license[0] : pkg.license,
          deprecated: typeof pkg.abandoned === 'boolean' ? pkg.abandoned : !!pkg.abandoned,
          deprecationMessage: typeof pkg.abandoned === 'string' ? pkg.abandoned : undefined
        }));
      }
    }

    // Parse packages-dev
    if (lockFile['packages-dev']) {
      for (const pkg of lockFile['packages-dev']) {
        dependencies.push(this.createDependency(pkg.name, pkg.version, filePath, {
          dependencyType: 'dev',
          resolvedVersion: pkg.version,
          license: Array.isArray(pkg.license) ? pkg.license[0] : pkg.license,
          deprecated: typeof pkg.abandoned === 'boolean' ? pkg.abandoned : !!pkg.abandoned,
          deprecationMessage: typeof pkg.abandoned === 'string' ? pkg.abandoned : undefined
        }));
      }
    }

    return dependencies;
  }

  /**
   * Check for dangerous scripts in composer.json
   */
  detectDangerousScripts(content: string): { script: string; command: string }[] {
    const dangerous: { script: string; command: string }[] = [];
    
    try {
      const composer: ComposerJson = JSON.parse(content);
      if (!composer.scripts) return dangerous;

      const dangerousPatterns = [
        /curl\s+.*\|\s*(bash|sh|php)/i,
        /wget\s+.*\|\s*(bash|sh|php)/i,
        /eval\s*\(/i,
        /base64_decode/i,
        /system\s*\(/i,
        /exec\s*\(/i,
        /shell_exec/i,
        /passthru/i,
        /proc_open/i,
      ];

      for (const [script, command] of Object.entries(composer.scripts)) {
        const commands = Array.isArray(command) ? command : [command];
        for (const cmd of commands) {
          for (const pattern of dangerousPatterns) {
            if (pattern.test(cmd)) {
              dangerous.push({ script, command: cmd });
              break;
            }
          }
        }
      }
    } catch {
      // Ignore parse errors
    }

    return dangerous;
  }
}

export default PHPDependencyParser;
