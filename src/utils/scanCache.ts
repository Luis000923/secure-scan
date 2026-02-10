/**
 * Scan Cache Manager
 * Implements incremental scanning by caching file hashes and previous findings
 */

import * as fs from 'fs';
import * as path from 'path';
import * as crypto from 'crypto';
import { Finding, SupportedLanguage } from '../types';
import { logger } from './logger';

/**
 * Cached file entry
 */
export interface CachedFileEntry {
  /** File path relative to project root */
  relativePath: string;
  /** SHA-256 hash of file content */
  hash: string;
  /** File size in bytes */
  size: number;
  /** Last modified timestamp */
  lastModified: number;
  /** Language detected */
  language: SupportedLanguage | null;
  /** Cached findings for this file */
  findings: Finding[];
  /** Timestamp when this entry was cached */
  cachedAt: number;
  /** Analyzer versions used */
  analyzerVersions: Record<string, string>;
}

/**
 * Cache metadata
 */
export interface CacheMetadata {
  /** Cache version for compatibility */
  version: string;
  /** Project path */
  projectPath: string;
  /** Timestamp when cache was created */
  createdAt: number;
  /** Timestamp when cache was last updated */
  updatedAt: number;
  /** Total files cached */
  totalFiles: number;
  /** Rules version hash */
  rulesHash: string;
  /** Configuration hash */
  configHash: string;
}

/**
 * Full cache structure
 */
export interface ScanCache {
  metadata: CacheMetadata;
  files: Map<string, CachedFileEntry>;
}

/**
 * Cache hit result
 */
export interface CacheHitResult {
  hit: boolean;
  entry?: CachedFileEntry;
  reason?: 'hash_match' | 'not_found' | 'hash_mismatch' | 'expired' | 'rules_changed' | 'config_changed';
}

/**
 * Scan Cache Manager Class
 */
export class ScanCacheManager {
  private static readonly CACHE_VERSION = '1.0.0';
  private static readonly CACHE_FILENAME = '.secure-scan-cache.json';
  private static readonly DEFAULT_CACHE_TTL = 7 * 24 * 60 * 60 * 1000; // 7 days

  private projectPath: string;
  private cachePath: string;
  private cache: ScanCache | null = null;
  private cacheTTL: number;
  private rulesHash: string;
  private configHash: string;
  private dirty = false;

  constructor(options: {
    projectPath: string;
    rulesHash?: string;
    configHash?: string;
    cacheTTL?: number;
  }) {
    this.projectPath = path.resolve(options.projectPath);
    this.cachePath = path.join(this.projectPath, ScanCacheManager.CACHE_FILENAME);
    this.rulesHash = options.rulesHash || 'default';
    this.configHash = options.configHash || 'default';
    this.cacheTTL = options.cacheTTL || ScanCacheManager.DEFAULT_CACHE_TTL;
  }

  /**
   * Load cache from disk
   */
  async load(): Promise<boolean> {
    try {
      if (!fs.existsSync(this.cachePath)) {
        logger.debug('No cache file found, starting fresh');
        this.initializeEmptyCache();
        return false;
      }

      const content = await fs.promises.readFile(this.cachePath, 'utf-8');
      const data = JSON.parse(content);

      // Validate cache version
      if (data.metadata?.version !== ScanCacheManager.CACHE_VERSION) {
        logger.info('Cache version mismatch, invalidating cache');
        this.initializeEmptyCache();
        return false;
      }

      // Check if rules or config changed
      if (data.metadata?.rulesHash !== this.rulesHash) {
        logger.info('Rules changed, invalidating cache');
        this.initializeEmptyCache();
        return false;
      }

      if (data.metadata?.configHash !== this.configHash) {
        logger.info('Configuration changed, invalidating cache');
        this.initializeEmptyCache();
        return false;
      }

      // Reconstruct the cache
      this.cache = {
        metadata: data.metadata,
        files: new Map(Object.entries(data.files || {}))
      };

      logger.info(`Loaded cache with ${this.cache.files.size} file entries`);
      return true;
    } catch (error) {
      logger.warn(`Failed to load cache: ${error}`);
      this.initializeEmptyCache();
      return false;
    }
  }

  /**
   * Save cache to disk
   */
  async save(): Promise<void> {
    if (!this.cache || !this.dirty) {
      return;
    }

    try {
      this.cache.metadata.updatedAt = Date.now();
      this.cache.metadata.totalFiles = this.cache.files.size;

      const data = {
        metadata: this.cache.metadata,
        files: Object.fromEntries(this.cache.files)
      };

      await fs.promises.writeFile(
        this.cachePath,
        JSON.stringify(data, null, 2),
        'utf-8'
      );

      this.dirty = false;
      logger.debug(`Saved cache with ${this.cache.files.size} entries`);
    } catch (error) {
      logger.warn(`Failed to save cache: ${error}`);
    }
  }

  /**
   * Initialize empty cache
   */
  private initializeEmptyCache(): void {
    this.cache = {
      metadata: {
        version: ScanCacheManager.CACHE_VERSION,
        projectPath: this.projectPath,
        createdAt: Date.now(),
        updatedAt: Date.now(),
        totalFiles: 0,
        rulesHash: this.rulesHash,
        configHash: this.configHash
      },
      files: new Map()
    };
    this.dirty = true;
  }

  /**
   * Calculate hash for a file
   */
  calculateFileHash(content: string): string {
    return crypto.createHash('sha256').update(content).digest('hex');
  }

  /**
   * Check if a file has a valid cache hit
   */
  async checkFile(
    relativePath: string,
    content: string,
    currentHash?: string
  ): Promise<CacheHitResult> {
    if (!this.cache) {
      await this.load();
    }

    const entry = this.cache!.files.get(relativePath);

    if (!entry) {
      return { hit: false, reason: 'not_found' };
    }

    // Calculate hash if not provided
    const hash = currentHash || this.calculateFileHash(content);

    // Check hash match
    if (entry.hash !== hash) {
      return { hit: false, entry, reason: 'hash_mismatch' };
    }

    // Check TTL
    const age = Date.now() - entry.cachedAt;
    if (age > this.cacheTTL) {
      return { hit: false, entry, reason: 'expired' };
    }

    return { hit: true, entry, reason: 'hash_match' };
  }

  /**
   * Update cache entry for a file
   */
  async updateFile(
    relativePath: string,
    content: string,
    findings: Finding[],
    language: SupportedLanguage | null,
    analyzerVersions: Record<string, string>
  ): Promise<void> {
    if (!this.cache) {
      await this.load();
    }

    const hash = this.calculateFileHash(content);
    
    const entry: CachedFileEntry = {
      relativePath,
      hash,
      size: Buffer.byteLength(content, 'utf-8'),
      lastModified: Date.now(),
      language,
      findings,
      cachedAt: Date.now(),
      analyzerVersions
    };

    this.cache!.files.set(relativePath, entry);
    this.dirty = true;
  }

  /**
   * Remove file from cache
   */
  removeFile(relativePath: string): void {
    if (this.cache) {
      this.cache.files.delete(relativePath);
      this.dirty = true;
    }
  }

  /**
   * Get cached findings for a file
   */
  getCachedFindings(relativePath: string): Finding[] | null {
    const entry = this.cache?.files.get(relativePath);
    return entry?.findings || null;
  }

  /**
   * Clear the entire cache
   */
  async clear(): Promise<void> {
    this.initializeEmptyCache();
    
    try {
      if (fs.existsSync(this.cachePath)) {
        await fs.promises.unlink(this.cachePath);
      }
    } catch (error) {
      logger.warn(`Failed to delete cache file: ${error}`);
    }
  }

  /**
   * Get cache statistics
   */
  getStats(): {
    totalFiles: number;
    cacheAge: number;
    cacheSize: number;
    hitRate?: number;
  } {
    if (!this.cache) {
      return { totalFiles: 0, cacheAge: 0, cacheSize: 0 };
    }

    return {
      totalFiles: this.cache.files.size,
      cacheAge: Date.now() - this.cache.metadata.createdAt,
      cacheSize: this.estimateCacheSize()
    };
  }

  /**
   * Estimate cache size in bytes
   */
  private estimateCacheSize(): number {
    if (!this.cache) return 0;
    
    let size = 0;
    for (const entry of this.cache.files.values()) {
      // Rough estimation
      size += entry.relativePath.length * 2;
      size += entry.hash.length * 2;
      size += JSON.stringify(entry.findings).length;
    }
    return size;
  }

  /**
   * Prune expired entries
   */
  async prune(): Promise<number> {
    if (!this.cache) {
      return 0;
    }

    let pruned = 0;
    const now = Date.now();

    for (const [key, entry] of this.cache.files) {
      const age = now - entry.cachedAt;
      if (age > this.cacheTTL) {
        this.cache.files.delete(key);
        pruned++;
      }
    }

    if (pruned > 0) {
      this.dirty = true;
      logger.info(`Pruned ${pruned} expired cache entries`);
    }

    return pruned;
  }

  /**
   * Get files that need to be re-analyzed
   */
  getStaleFiles(allFiles: string[]): string[] {
    if (!this.cache) {
      return allFiles;
    }

    return allFiles.filter(file => {
      const entry = this.cache!.files.get(file);
      if (!entry) return true;
      
      const age = Date.now() - entry.cachedAt;
      return age > this.cacheTTL;
    });
  }

  /**
   * Check if cache is valid
   */
  isValid(): boolean {
    return this.cache !== null && 
           this.cache.metadata.version === ScanCacheManager.CACHE_VERSION;
  }
}

/**
 * Create a cache manager instance
 */
export function createCacheManager(projectPath: string, options?: {
  rulesHash?: string;
  configHash?: string;
  cacheTTL?: number;
}): ScanCacheManager {
  return new ScanCacheManager({
    projectPath,
    ...options
  });
}

export default ScanCacheManager;
