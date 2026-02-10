/**
 * OSV (Open Source Vulnerabilities) API Client
 * Real-time vulnerability database integration
 * https://osv.dev/
 */

import https from 'https';
import { CVEInfo, PackageEcosystem, Severity } from '../types';
import { logger } from '../../utils/logger';

/**
 * OSV API response types
 */
interface OSVVulnerability {
  id: string;
  summary?: string;
  details?: string;
  aliases?: string[];
  modified: string;
  published: string;
  database_specific?: Record<string, any>;
  references?: Array<{
    type: string;
    url: string;
  }>;
  affected: Array<{
    package: {
      ecosystem: string;
      name: string;
    };
    ranges?: Array<{
      type: string;
      events: Array<{
        introduced?: string;
        fixed?: string;
        last_affected?: string;
      }>;
    }>;
    versions?: string[];
    database_specific?: Record<string, any>;
  }>;
  severity?: Array<{
    type: string;
    score: string;
  }>;
}

interface OSVQueryResponse {
  vulns?: OSVVulnerability[];
}

interface OSVBatchQueryResponse {
  results: Array<{
    vulns?: OSVVulnerability[];
  }>;
}

/**
 * Convert OSV ecosystem names to our ecosystem types
 */
function mapOSVEcosystem(osvEcosystem: string): PackageEcosystem | null {
  const mapping: Record<string, PackageEcosystem> = {
    'npm': 'npm',
    'PyPI': 'pip',
    'Packagist': 'composer',
    'Maven': 'maven',
    'NuGet': 'nuget',
    'crates.io': 'npm', // Rust, fallback
    'Go': 'npm', // Go, fallback
  };
  return mapping[osvEcosystem] || null;
}

/**
 * Convert our ecosystem to OSV ecosystem names
 */
function mapToOSVEcosystem(ecosystem: PackageEcosystem): string {
  const mapping: Record<PackageEcosystem, string> = {
    'npm': 'npm',
    'pip': 'PyPI',
    'composer': 'Packagist',
    'maven': 'Maven',
    'gradle': 'Maven',
    'nuget': 'NuGet',
    'vcpkg': 'OSS-Fuzz',
    'conan': 'OSS-Fuzz',
    'cmake': 'OSS-Fuzz'
  };
  return mapping[ecosystem] || ecosystem;
}

/**
 * Convert CVSS score to severity
 */
function cvssToSeverity(score: number): Severity {
  if (score >= 9.0) return Severity.CRITICAL;
  if (score >= 7.0) return Severity.HIGH;
  if (score >= 4.0) return Severity.MEDIUM;
  if (score >= 0.1) return Severity.LOW;
  return Severity.INFO;
}

/**
 * Parse CVSS score from OSV vulnerability
 */
function parseCVSSScore(vuln: OSVVulnerability): number {
  if (vuln.severity && vuln.severity.length > 0) {
    for (const sev of vuln.severity) {
      if (sev.type === 'CVSS_V3') {
        // Parse CVSS v3 vector to get score
        const match = sev.score.match(/CVSS:3\.\d\/AV:\w\/AC:\w\/PR:\w\/UI:\w\/S:\w\/C:\w\/I:\w\/A:\w/);
        if (match) {
          // Use a simplified scoring based on the vector
          return parseFloat(vuln.database_specific?.cvss?.score || '5.0');
        }
      }
    }
  }
  
  // Check database_specific for CVSS
  if (vuln.database_specific?.cvss?.score) {
    return parseFloat(vuln.database_specific.cvss.score);
  }
  
  // Default medium severity
  return 5.0;
}

/**
 * Extract fixed version from OSV vulnerability
 */
function getFixedVersion(vuln: OSVVulnerability): string | undefined {
  for (const affected of vuln.affected) {
    if (affected.ranges) {
      for (const range of affected.ranges) {
        for (const event of range.events) {
          if (event.fixed) {
            return event.fixed;
          }
        }
      }
    }
  }
  return undefined;
}

/**
 * Convert OSV vulnerability to our CVEInfo format
 */
function osvToCVEInfo(vuln: OSVVulnerability): CVEInfo {
  const cvssScore = parseCVSSScore(vuln);
  
  // Get CVE ID from aliases or use OSV ID
  const cveId = vuln.aliases?.find(a => a.startsWith('CVE-')) || vuln.id;
  
  return {
    id: cveId,
    description: vuln.summary || vuln.details || 'No description available',
    cvssScore,
    severity: cvssToSeverity(cvssScore),
    publishedDate: vuln.published,
    references: vuln.references?.map(r => r.url) || [],
    fixedVersion: getFixedVersion(vuln),
    cwes: vuln.database_specific?.cwe_ids || [],
    exploitAvailable: false // OSV doesn't track this directly
  };
}

/**
 * OSV API Client
 */
export class OSVClient {
  private baseUrl = 'api.osv.dev';
  private timeout = 10000; // 10 seconds
  private cache: Map<string, { data: CVEInfo[]; timestamp: number }> = new Map();
  private cacheTTL = 3600000; // 1 hour

  /**
   * Make HTTPS request to OSV API
   */
  private async request<T>(path: string, body: object): Promise<T> {
    return new Promise((resolve, reject) => {
      const data = JSON.stringify(body);
      
      const options = {
        hostname: this.baseUrl,
        port: 443,
        path,
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Content-Length': Buffer.byteLength(data),
          'User-Agent': 'secure-scan/1.2.5'
        },
        timeout: this.timeout
      };

      const req = https.request(options, (res) => {
        let responseData = '';
        
        res.on('data', (chunk) => {
          responseData += chunk;
        });
        
        res.on('end', () => {
          try {
            const parsed = JSON.parse(responseData);
            resolve(parsed as T);
          } catch (error) {
            reject(new Error(`Failed to parse OSV response: ${error}`));
          }
        });
      });

      req.on('error', (error) => {
        reject(new Error(`OSV API request failed: ${error.message}`));
      });

      req.on('timeout', () => {
        req.destroy();
        reject(new Error('OSV API request timed out'));
      });

      req.write(data);
      req.end();
    });
  }

  /**
   * Query vulnerabilities for a single package
   */
  async queryPackage(
    packageName: string,
    version: string,
    ecosystem: PackageEcosystem
  ): Promise<CVEInfo[]> {
    const cacheKey = `${ecosystem}:${packageName}:${version}`;
    
    // Check cache
    const cached = this.cache.get(cacheKey);
    if (cached && Date.now() - cached.timestamp < this.cacheTTL) {
      logger.debug(`OSV cache hit for ${cacheKey}`);
      return cached.data;
    }

    try {
      const response = await this.request<OSVQueryResponse>('/v1/query', {
        package: {
          name: packageName,
          ecosystem: mapToOSVEcosystem(ecosystem)
        },
        version
      });

      const cves = (response.vulns || []).map(osvToCVEInfo);
      
      // Cache result
      this.cache.set(cacheKey, { data: cves, timestamp: Date.now() });
      
      logger.debug(`OSV found ${cves.length} vulnerabilities for ${packageName}@${version}`);
      return cves;
    } catch (error) {
      logger.warn(`OSV query failed for ${packageName}: ${error}`);
      return [];
    }
  }

  /**
   * Query vulnerabilities for multiple packages in batch
   */
  async queryBatch(
    packages: Array<{
      name: string;
      version: string;
      ecosystem: PackageEcosystem;
    }>
  ): Promise<Map<string, CVEInfo[]>> {
    const results = new Map<string, CVEInfo[]>();
    
    // Build batch query
    const queries = packages.map(pkg => ({
      package: {
        name: pkg.name,
        ecosystem: mapToOSVEcosystem(pkg.ecosystem)
      },
      version: pkg.version
    }));

    try {
      const response = await this.request<OSVBatchQueryResponse>('/v1/querybatch', {
        queries
      });

      // Process results
      for (let i = 0; i < packages.length; i++) {
        const pkg = packages[i];
        const vulns = response.results[i]?.vulns || [];
        const cves = vulns.map(osvToCVEInfo);
        
        const key = `${pkg.ecosystem}:${pkg.name}:${pkg.version}`;
        results.set(key, cves);
        
        // Update cache
        this.cache.set(key, { data: cves, timestamp: Date.now() });
      }

      const totalVulns = Array.from(results.values()).reduce((sum, cves) => sum + cves.length, 0);
      logger.info(`OSV batch query found ${totalVulns} vulnerabilities across ${packages.length} packages`);
      
      return results;
    } catch (error) {
      logger.warn(`OSV batch query failed: ${error}`);
      
      // Return empty results for all packages
      for (const pkg of packages) {
        results.set(`${pkg.ecosystem}:${pkg.name}:${pkg.version}`, []);
      }
      
      return results;
    }
  }

  /**
   * Get vulnerability by ID
   */
  async getVulnerability(vulnId: string): Promise<CVEInfo | null> {
    try {
      const response = await this.request<OSVVulnerability>(`/v1/vulns/${vulnId}`, {});
      return osvToCVEInfo(response);
    } catch (error) {
      logger.warn(`Failed to get vulnerability ${vulnId}: ${error}`);
      return null;
    }
  }

  /**
   * Clear the cache
   */
  clearCache(): void {
    this.cache.clear();
  }

  /**
   * Get cache statistics
   */
  getCacheStats(): { size: number; entries: string[] } {
    return {
      size: this.cache.size,
      entries: Array.from(this.cache.keys())
    };
  }
}

// Export singleton instance
export const osvClient = new OSVClient();

export default OSVClient;
