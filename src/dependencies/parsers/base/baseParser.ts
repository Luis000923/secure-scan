/**
 * Base Dependency Parser
 * Abstract base class for ecosystem-specific parsers
 */

import { 
  DependencyParser, 
  DependencyManifest, 
  ManifestFileType, 
  PackageEcosystem,
  Dependency 
} from '../../types';
import { logger } from '../../../utils/logger';

/**
 * Base Parser Class
 * Provides common functionality for all dependency parsers
 */
export abstract class BaseDependencyParser implements DependencyParser {
  abstract name: string;
  abstract supportedFiles: ManifestFileType[];
  abstract ecosystem: PackageEcosystem;

  /**
   * Check if parser supports a file
   */
  supports(fileName: string): boolean {
    const baseName = fileName.split(/[/\\]/).pop() || '';
    
    // Special handling for .csproj files
    if (baseName.endsWith('.csproj')) {
      return this.supportedFiles.includes('csproj');
    }
    
    return this.supportedFiles.some(ft => baseName === ft || baseName.endsWith(ft));
  }

  /**
   * Parse manifest file - must be implemented by subclasses
   */
  abstract parse(filePath: string, content: string): Promise<DependencyManifest>;

  /**
   * Helper to create a dependency object
   */
  protected createDependency(
    name: string,
    version: string,
    sourceFile: string,
    options: Partial<Dependency> = {}
  ): Dependency {
    return {
      name,
      version,
      ecosystem: this.ecosystem,
      dependencyType: 'direct',
      depth: 0,
      sourceFile,
      ...options
    };
  }

  /**
   * Helper to normalize version string
   */
  protected normalizeVersion(version: string): string {
    if (!version) return '*';
    
    // Remove common prefixes
    version = version.replace(/^[v=~^]/, '');
    
    // Handle special cases
    if (version === 'latest' || version === '*') {
      return '*';
    }
    
    return version.trim();
  }

  /**
   * Helper to determine if file is a lock file
   */
  protected isLockFile(fileName: string): boolean {
    const lockPatterns = [
      'package-lock.json',
      'yarn.lock',
      'Pipfile.lock',
      'composer.lock'
    ];
    return lockPatterns.some(p => fileName.endsWith(p));
  }

  /**
   * Log parsing info
   */
  protected logParsing(filePath: string): void {
    logger.debug(`[${this.name}] Parsing: ${filePath}`);
  }

  /**
   * Log parsing error
   */
  protected logError(filePath: string, error: string): void {
    logger.debug(`[${this.name}] Error parsing ${filePath}: ${error}`);
  }
}

export default BaseDependencyParser;
