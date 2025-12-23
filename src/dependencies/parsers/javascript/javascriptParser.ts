/**
 * JavaScript/Node.js Dependency Parser
 * Parses package.json, package-lock.json, and yarn.lock
 */

import { BaseDependencyParser } from '../base';
import { 
  DependencyManifest, 
  ManifestFileType, 
  PackageEcosystem,
  Dependency,
  DependencyType
} from '../../types';

/**
 * NPM package.json structure
 */
interface PackageJson {
  name?: string;
  version?: string;
  dependencies?: Record<string, string>;
  devDependencies?: Record<string, string>;
  peerDependencies?: Record<string, string>;
  optionalDependencies?: Record<string, string>;
  scripts?: Record<string, string>;
}

/**
 * NPM package-lock.json structure
 */
interface PackageLock {
  name?: string;
  version?: string;
  lockfileVersion?: number;
  dependencies?: Record<string, PackageLockDependency>;
  packages?: Record<string, PackageLockPackage>;
}

interface PackageLockDependency {
  version: string;
  resolved?: string;
  integrity?: string;
  dev?: boolean;
  optional?: boolean;
  requires?: Record<string, string>;
  dependencies?: Record<string, PackageLockDependency>;
}

interface PackageLockPackage {
  version?: string;
  resolved?: string;
  integrity?: string;
  dev?: boolean;
  optional?: boolean;
  dependencies?: Record<string, string>;
  devDependencies?: Record<string, string>;
}

/**
 * JavaScript/Node.js Dependency Parser
 */
export class JavaScriptDependencyParser extends BaseDependencyParser {
  name = 'JavaScript Dependency Parser';
  supportedFiles: ManifestFileType[] = ['package.json', 'package-lock.json', 'yarn.lock'];
  ecosystem: PackageEcosystem = 'npm';

  /**
   * Parse manifest file
   */
  async parse(filePath: string, content: string): Promise<DependencyManifest> {
    this.logParsing(filePath);

    const fileName = filePath.split(/[/\\]/).pop() || '';
    const dependencies: Dependency[] = [];
    const parseErrors: string[] = [];

    try {
      if (fileName === 'package.json') {
        dependencies.push(...this.parsePackageJson(content, filePath, parseErrors));
      } else if (fileName === 'package-lock.json') {
        dependencies.push(...this.parsePackageLock(content, filePath, parseErrors));
      } else if (fileName === 'yarn.lock') {
        dependencies.push(...this.parseYarnLock(content, filePath, parseErrors));
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
      isLockFile: this.isLockFile(fileName)
    };
  }

  /**
   * Get manifest file type
   */
  private getFileType(fileName: string): ManifestFileType {
    if (fileName === 'package-lock.json') return 'package-lock.json';
    if (fileName === 'yarn.lock') return 'yarn.lock';
    return 'package.json';
  }

  /**
   * Parse package.json
   */
  private parsePackageJson(content: string, filePath: string, errors: string[]): Dependency[] {
    const dependencies: Dependency[] = [];
    
    let pkg: PackageJson;
    try {
      pkg = JSON.parse(content);
    } catch (e) {
      errors.push('Invalid JSON in package.json');
      return dependencies;
    }

    // Parse regular dependencies
    if (pkg.dependencies) {
      for (const [name, version] of Object.entries(pkg.dependencies)) {
        dependencies.push(this.createDependency(name, version, filePath, {
          dependencyType: 'direct'
        }));
      }
    }

    // Parse dev dependencies
    if (pkg.devDependencies) {
      for (const [name, version] of Object.entries(pkg.devDependencies)) {
        dependencies.push(this.createDependency(name, version, filePath, {
          dependencyType: 'dev'
        }));
      }
    }

    // Parse peer dependencies
    if (pkg.peerDependencies) {
      for (const [name, version] of Object.entries(pkg.peerDependencies)) {
        dependencies.push(this.createDependency(name, version, filePath, {
          dependencyType: 'peer'
        }));
      }
    }

    // Parse optional dependencies
    if (pkg.optionalDependencies) {
      for (const [name, version] of Object.entries(pkg.optionalDependencies)) {
        dependencies.push(this.createDependency(name, version, filePath, {
          dependencyType: 'optional'
        }));
      }
    }

    return dependencies;
  }

  /**
   * Parse package-lock.json
   */
  private parsePackageLock(content: string, filePath: string, errors: string[]): Dependency[] {
    const dependencies: Dependency[] = [];
    
    let lockFile: PackageLock;
    try {
      lockFile = JSON.parse(content);
    } catch (e) {
      errors.push('Invalid JSON in package-lock.json');
      return dependencies;
    }

    // Handle lockfileVersion 2/3 (packages field)
    if (lockFile.packages) {
      for (const [pkgPath, pkg] of Object.entries(lockFile.packages)) {
        // Skip root package (empty path)
        if (!pkgPath || pkgPath === '') continue;
        
        // Extract package name from path (e.g., "node_modules/lodash" -> "lodash")
        const name = this.extractPackageName(pkgPath);
        if (!name || !pkg.version) continue;

        const depType: DependencyType = pkg.dev ? 'dev' : (pkg.optional ? 'optional' : 'transitive');
        const depth = this.calculateDepth(pkgPath);

        dependencies.push(this.createDependency(name, pkg.version, filePath, {
          dependencyType: depth === 1 ? 'direct' : depType,
          resolvedVersion: pkg.version,
          depth
        }));
      }
    }
    // Handle lockfileVersion 1 (dependencies field)
    else if (lockFile.dependencies) {
      this.parsePackageLockDependencies(
        lockFile.dependencies, 
        filePath, 
        dependencies, 
        0,
        false
      );
    }

    return dependencies;
  }

  /**
   * Extract package name from node_modules path
   */
  private extractPackageName(pkgPath: string): string | null {
    // Remove "node_modules/" prefix and handle scoped packages
    const parts = pkgPath.split('node_modules/');
    const lastPart = parts[parts.length - 1];
    
    if (!lastPart) return null;
    
    // Handle scoped packages (@scope/package)
    if (lastPart.startsWith('@')) {
      const scopedParts = lastPart.split('/');
      if (scopedParts.length >= 2) {
        return `${scopedParts[0]}/${scopedParts[1]}`;
      }
    }
    
    // Regular package
    return lastPart.split('/')[0];
  }

  /**
   * Calculate dependency depth from path
   */
  private calculateDepth(pkgPath: string): number {
    return (pkgPath.match(/node_modules/g) || []).length;
  }

  /**
   * Recursively parse package-lock dependencies (v1 format)
   */
  private parsePackageLockDependencies(
    deps: Record<string, PackageLockDependency>,
    filePath: string,
    result: Dependency[],
    depth: number,
    isDev: boolean
  ): void {
    for (const [name, dep] of Object.entries(deps)) {
      const depType: DependencyType = dep.dev || isDev 
        ? 'dev' 
        : (dep.optional ? 'optional' : (depth === 0 ? 'direct' : 'transitive'));

      result.push(this.createDependency(name, dep.version, filePath, {
        dependencyType: depType,
        resolvedVersion: dep.version,
        depth
      }));

      // Parse nested dependencies
      if (dep.dependencies) {
        this.parsePackageLockDependencies(
          dep.dependencies,
          filePath,
          result,
          depth + 1,
          dep.dev || isDev
        );
      }
    }
  }

  /**
   * Parse yarn.lock (v1 format)
   */
  private parseYarnLock(content: string, filePath: string, errors: string[]): Dependency[] {
    const dependencies: Dependency[] = [];
    
    // Simple yarn.lock parser
    const lines = content.split('\n');
    let currentPackage: string | null = null;
    let currentVersion: string | null = null;

    for (const line of lines) {
      // Skip comments and empty lines
      if (line.startsWith('#') || line.trim() === '') continue;

      // New package entry (lines that don't start with whitespace)
      if (!line.startsWith(' ') && !line.startsWith('\t')) {
        // Parse package name(s) from entry like '"lodash@^4.17.21":'
        const match = line.match(/^"?(@?[^@"]+)@[^"]+/);
        if (match) {
          currentPackage = match[1];
        }
      }
      // Version line
      else if (line.trim().startsWith('version')) {
        const versionMatch = line.match(/version\s+"?([^"]+)"?/);
        if (versionMatch && currentPackage) {
          currentVersion = versionMatch[1];
          
          // Check if this dependency already exists
          const existing = dependencies.find(d => 
            d.name === currentPackage && d.resolvedVersion === currentVersion
          );
          
          if (!existing) {
            dependencies.push(this.createDependency(currentPackage, currentVersion, filePath, {
              dependencyType: 'transitive',
              resolvedVersion: currentVersion,
              depth: 1
            }));
          }
          
          currentPackage = null;
          currentVersion = null;
        }
      }
    }

    return dependencies;
  }

  /**
   * Check for dangerous scripts in package.json
   */
  detectDangerousScripts(content: string): { script: string; command: string }[] {
    const dangerous: { script: string; command: string }[] = [];
    
    try {
      const pkg: PackageJson = JSON.parse(content);
      if (!pkg.scripts) return dangerous;

      const dangerousPatterns = [
        /curl\s+.*\|\s*(bash|sh)/i,           // curl pipe to shell
        /wget\s+.*\|\s*(bash|sh)/i,           // wget pipe to shell
        /eval\s*\(/i,                          // eval usage
        /base64\s+(-d|--decode)/i,            // base64 decode
        /\$\(.*\)/,                            // command substitution
        /nc\s+-e/i,                            // netcat reverse shell
        /powershell\s+-enc/i,                  // encoded powershell
        /node\s+-e\s+['"].*require.*http/i,   // inline node with http
      ];

      for (const [script, command] of Object.entries(pkg.scripts)) {
        for (const pattern of dangerousPatterns) {
          if (pattern.test(command)) {
            dangerous.push({ script, command });
            break;
          }
        }
      }
    } catch {
      // Ignore parse errors
    }

    return dangerous;
  }
}

export default JavaScriptDependencyParser;
