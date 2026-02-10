/**
 * Enhanced CVE Database with Real-time Integration
 * Combines static database with OSV API for comprehensive vulnerability detection
 */

import { CVEInfo, PackageEcosystem, Severity } from '../types';
import { CVE_DATABASE, CVEDatabaseEntry } from './cveDatabase';
import { osvClient, OSVClient } from './osvClient';
import { logger } from '../../utils/logger';

/**
 * Configuration for vulnerability lookup
 */
export interface VulnLookupConfig {
  /** Use online OSV API for real-time data */
  useOnlineAPI: boolean;
  /** Fallback to static database if API fails */
  fallbackToStatic: boolean;
  /** Timeout for API requests in ms */
  apiTimeout: number;
  /** Cache TTL in ms */
  cacheTTL: number;
}

const DEFAULT_CONFIG: VulnLookupConfig = {
  useOnlineAPI: true,
  fallbackToStatic: true,
  apiTimeout: 10000,
  cacheTTL: 3600000
};

/**
 * Vulnerability lookup result
 */
export interface VulnLookupResult {
  vulnerabilities: CVEInfo[];
  source: 'osv' | 'static' | 'combined';
  fromCache: boolean;
}

/**
 * Enhanced CVE Database Manager
 * Provides unified access to vulnerability data from multiple sources
 */
export class EnhancedCVEDatabase {
  private config: VulnLookupConfig;
  private osvClient: OSVClient;
  private staticDB: CVEDatabaseEntry[];

  constructor(config: Partial<VulnLookupConfig> = {}) {
    this.config = { ...DEFAULT_CONFIG, ...config };
    this.osvClient = osvClient;
    this.staticDB = CVE_DATABASE;
  }

  /**
   * Look up vulnerabilities for a package
   */
  async lookupPackage(
    packageName: string,
    version: string,
    ecosystem: PackageEcosystem
  ): Promise<VulnLookupResult> {
    const vulnerabilities: CVEInfo[] = [];
    let source: 'osv' | 'static' | 'combined' = 'static';
    let fromCache = false;

    // Try OSV API first if enabled
    if (this.config.useOnlineAPI) {
      try {
        const osvResults = await this.osvClient.queryPackage(packageName, version, ecosystem);
        
        if (osvResults.length > 0) {
          vulnerabilities.push(...osvResults);
          source = 'osv';
          logger.debug(`Found ${osvResults.length} vulnerabilities from OSV for ${packageName}@${version}`);
        }
      } catch (error) {
        logger.warn(`OSV lookup failed for ${packageName}: ${error}`);
        
        if (!this.config.fallbackToStatic) {
          return { vulnerabilities: [], source: 'osv', fromCache: false };
        }
      }
    }

    // Check static database
    const staticResults = this.lookupStatic(packageName, version, ecosystem);
    
    if (staticResults.length > 0) {
      // Merge with OSV results, avoiding duplicates
      for (const staticVuln of staticResults) {
        const isDuplicate = vulnerabilities.some(v => 
          v.id === staticVuln.id || 
          (v.id.startsWith('CVE-') && staticVuln.id.startsWith('CVE-') && v.id === staticVuln.id)
        );
        
        if (!isDuplicate) {
          vulnerabilities.push(staticVuln);
        }
      }
      
      if (source === 'osv' && staticResults.length > 0) {
        source = 'combined';
      } else if (source === 'static') {
        source = 'static';
      }
    }

    return { vulnerabilities, source, fromCache };
  }

  /**
   * Look up vulnerabilities in static database
   */
  private lookupStatic(
    packageName: string,
    version: string,
    ecosystem: PackageEcosystem
  ): CVEInfo[] {
    const results: CVEInfo[] = [];
    
    for (const entry of this.staticDB) {
      if (entry.ecosystem === ecosystem && entry.packageName.toLowerCase() === packageName.toLowerCase()) {
        if (this.isVersionVulnerable(version, entry.vulnerableVersions)) {
          results.push(entry.cve);
        }
      }
    }
    
    return results;
  }

  /**
   * Check if a version is in the vulnerable range
   */
  private isVersionVulnerable(version: string, vulnerableVersions: string[]): boolean {
    // Handle semver-style constraints
    for (const constraint of vulnerableVersions) {
      if (this.matchesConstraint(version, constraint)) {
        return true;
      }
    }
    return false;
  }

  /**
   * Match version against a constraint
   * Supports: exact match, <, >, <=, >=, ranges
   */
  private matchesConstraint(version: string, constraint: string): boolean {
    // Exact version match
    if (constraint === version) {
      return true;
    }

    // Handle operators
    if (constraint.startsWith('<')) {
      const targetVersion = constraint.slice(1);
      return this.compareVersions(version, targetVersion) < 0;
    }
    
    if (constraint.startsWith('>')) {
      const targetVersion = constraint.slice(1);
      return this.compareVersions(version, targetVersion) > 0;
    }
    
    if (constraint.startsWith('<=')) {
      const targetVersion = constraint.slice(2);
      return this.compareVersions(version, targetVersion) <= 0;
    }
    
    if (constraint.startsWith('>=')) {
      const targetVersion = constraint.slice(2);
      return this.compareVersions(version, targetVersion) >= 0;
    }

    // Handle ranges like ">=1.0,<2.0"
    if (constraint.includes(',')) {
      const parts = constraint.split(',');
      return parts.every(part => this.matchesConstraint(version, part.trim()));
    }

    return false;
  }

  /**
   * Compare two version strings
   * Returns: -1 if a < b, 0 if a === b, 1 if a > b
   */
  private compareVersions(a: string, b: string): number {
    const partsA = a.replace(/[^0-9.]/g, '').split('.').map(Number);
    const partsB = b.replace(/[^0-9.]/g, '').split('.').map(Number);
    
    const maxLength = Math.max(partsA.length, partsB.length);
    
    for (let i = 0; i < maxLength; i++) {
      const numA = partsA[i] || 0;
      const numB = partsB[i] || 0;
      
      if (numA < numB) return -1;
      if (numA > numB) return 1;
    }
    
    return 0;
  }

  /**
   * Batch lookup for multiple packages
   */
  async lookupBatch(
    packages: Array<{
      name: string;
      version: string;
      ecosystem: PackageEcosystem;
    }>
  ): Promise<Map<string, VulnLookupResult>> {
    const results = new Map<string, VulnLookupResult>();

    // Use OSV batch API if enabled
    if (this.config.useOnlineAPI) {
      try {
        const osvResults = await this.osvClient.queryBatch(packages);
        
        for (const pkg of packages) {
          const key = `${pkg.ecosystem}:${pkg.name}:${pkg.version}`;
          const osvVulns = osvResults.get(key) || [];
          const staticVulns = this.lookupStatic(pkg.name, pkg.version, pkg.ecosystem);
          
          // Merge results
          const mergedVulns = [...osvVulns];
          for (const staticVuln of staticVulns) {
            if (!mergedVulns.some(v => v.id === staticVuln.id)) {
              mergedVulns.push(staticVuln);
            }
          }
          
          results.set(key, {
            vulnerabilities: mergedVulns,
            source: osvVulns.length > 0 && staticVulns.length > 0 ? 'combined' :
                    osvVulns.length > 0 ? 'osv' : 'static',
            fromCache: false
          });
        }
        
        return results;
      } catch (error) {
        logger.warn(`OSV batch lookup failed: ${error}`);
      }
    }

    // Fallback to static-only lookup
    for (const pkg of packages) {
      const key = `${pkg.ecosystem}:${pkg.name}:${pkg.version}`;
      const staticVulns = this.lookupStatic(pkg.name, pkg.version, pkg.ecosystem);
      
      results.set(key, {
        vulnerabilities: staticVulns,
        source: 'static',
        fromCache: false
      });
    }

    return results;
  }

  /**
   * Get statistics about the database
   */
  getStats(): {
    staticEntries: number;
    ecosystems: Set<PackageEcosystem>;
    cacheStats: { size: number; entries: string[] };
  } {
    const ecosystems = new Set<PackageEcosystem>();
    
    for (const entry of this.staticDB) {
      ecosystems.add(entry.ecosystem);
    }

    return {
      staticEntries: this.staticDB.length,
      ecosystems,
      cacheStats: this.osvClient.getCacheStats()
    };
  }

  /**
   * Clear all caches
   */
  clearCache(): void {
    this.osvClient.clearCache();
  }

  /**
   * Update configuration
   */
  updateConfig(config: Partial<VulnLookupConfig>): void {
    this.config = { ...this.config, ...config };
  }
}

// Export singleton instance
export const enhancedCVEDatabase = new EnhancedCVEDatabase();

export default EnhancedCVEDatabase;
