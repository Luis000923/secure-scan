/**
 * Dependency Analyzer
 * Main orchestrator for Software Composition Analysis (SCA)
 * Analyzes project dependencies without executing any code
 */

import * as fs from 'fs';
import * as path from 'path';
import { 
  DependencyAnalysisResult, 
  DependencyManifest, 
  Dependency,
  DependencyVulnerability,
  DependencyAnalysisStats,
  PackageEcosystem,
  DependencyRiskCategory
} from './types';
import { Severity, ScanConfig, AIConfig } from '../types';
import { getAllDependencyParsers, getParserForFile, getSupportedManifestFiles } from './parsers';
import { VulnerabilityDetector } from './detectors';
import { logger } from '../utils/logger';
import { generateId } from '../utils';

/**
 * Manifest file patterns to search for
 */
const MANIFEST_PATTERNS = [
  // JavaScript/Node.js
  'package.json',
  'package-lock.json',
  'yarn.lock',
  // Python
  'requirements.txt',
  'Pipfile',
  'Pipfile.lock',
  'pyproject.toml',
  // PHP
  'composer.json',
  'composer.lock',
  // Java
  'pom.xml',
  'build.gradle',
  // C/C++
  'vcpkg.json',
  'conanfile.txt',
  'CMakeLists.txt',
  // C#
  '*.csproj',
  'packages.config'
];

/**
 * Dependency Analyzer Configuration
 */
export interface DependencyAnalyzerConfig {
  /** Project path to analyze */
  projectPath: string;
  /** Enable AI-assisted analysis */
  useAI?: boolean;
  /** AI configuration */
  aiConfig?: AIConfig;
  /** Maximum depth to search for manifests */
  maxDepth?: number;
  /** Directories to exclude */
  exclude?: string[];
  /** Include dev dependencies in analysis */
  includeDevDependencies?: boolean;
  /** Verbose logging */
  verbose?: boolean;
}

/**
 * Dependency Analyzer Class
 * Main entry point for Software Composition Analysis
 */
export class DependencyAnalyzer {
  private config: DependencyAnalyzerConfig;
  private vulnerabilityDetector: VulnerabilityDetector;
  private aiAnalyzer?: any; // Will be integrated with AIAnalyzer

  constructor(config: DependencyAnalyzerConfig) {
    this.config = {
      ...config,
      maxDepth: config.maxDepth ?? 5,
      exclude: config.exclude ?? ['node_modules', 'vendor', 'venv', '.git', 'dist', 'build'],
      includeDevDependencies: config.includeDevDependencies ?? true,
      verbose: config.verbose ?? false
    };
    this.vulnerabilityDetector = new VulnerabilityDetector();
  }

  /**
   * Run dependency analysis
   */
  async analyze(): Promise<DependencyAnalysisResult> {
    const startTime = Date.now();
    logger.info('📦 Starting dependency analysis (SCA)...');

    // Find all manifest files
    logger.info('🔍 Searching for dependency manifests...');
    const manifestFiles = await this.findManifestFiles();
    
    if (manifestFiles.length === 0) {
      logger.warn('⚠️ No dependency manifest files found');
      return this.createEmptyResult(startTime);
    }

    logger.info(`📄 Found ${manifestFiles.length} manifest file(s)`);

    // Parse all manifests
    const manifests: DependencyManifest[] = [];
    const allDependencies: Dependency[] = [];

    for (const filePath of manifestFiles) {
      const manifest = await this.parseManifest(filePath);
      if (manifest) {
        manifests.push(manifest);
        allDependencies.push(...manifest.dependencies);
      }
    }

    // Deduplicate dependencies
    const uniqueDependencies = this.deduplicateDependencies(allDependencies);
    logger.info(`📊 Found ${uniqueDependencies.length} unique dependencies`);

    // Analyze for vulnerabilities
    logger.info('🔒 Analyzing dependencies for vulnerabilities...');
    const vulnerabilities = await this.analyzeVulnerabilities(uniqueDependencies);
    
    if (vulnerabilities.length > 0) {
      logger.warn(`⚠️ Found ${vulnerabilities.length} vulnerability issue(s)`);
    } else {
      logger.info('✅ No vulnerabilities detected');
    }

    // Calculate statistics
    const endTime = Date.now();
    const stats = this.calculateStats(manifests, uniqueDependencies, vulnerabilities, endTime - startTime);

    // Get ecosystems
    const ecosystems = [...new Set(manifests.map(m => m.ecosystem))];

    return {
      manifests,
      dependencies: uniqueDependencies,
      vulnerabilities,
      stats,
      ecosystems,
      timestamp: new Date()
    };
  }

  /**
   * Find all manifest files in the project
   */
  private async findManifestFiles(): Promise<string[]> {
    const manifestFiles: string[] = [];
    const parsers = getAllDependencyParsers();
    
    await this.walkDirectory(this.config.projectPath, 0, (filePath) => {
      const fileName = path.basename(filePath);
      
      // Check if any parser supports this file
      for (const parser of parsers) {
        if (parser.supports(fileName)) {
          manifestFiles.push(filePath);
          if (this.config.verbose) {
            logger.debug(`Found manifest: ${filePath}`);
          }
          break;
        }
      }
    });

    return manifestFiles;
  }

  /**
   * Recursively walk directory
   */
  private async walkDirectory(
    dir: string, 
    depth: number, 
    callback: (filePath: string) => void
  ): Promise<void> {
    if (depth > (this.config.maxDepth ?? 5)) return;

    try {
      const entries = fs.readdirSync(dir, { withFileTypes: true });

      for (const entry of entries) {
        const fullPath = path.join(dir, entry.name);

        if (entry.isDirectory()) {
          // Check if excluded
          if (this.config.exclude?.includes(entry.name)) continue;
          
          await this.walkDirectory(fullPath, depth + 1, callback);
        } else if (entry.isFile()) {
          callback(fullPath);
        }
      }
    } catch (error) {
      // Ignore permission errors
      if (this.config.verbose) {
        logger.debug(`Cannot read directory: ${dir}`);
      }
    }
  }

  /**
   * Parse a manifest file
   */
  private async parseManifest(filePath: string): Promise<DependencyManifest | null> {
    const fileName = path.basename(filePath);
    const parser = getParserForFile(fileName);

    if (!parser) {
      logger.debug(`No parser found for: ${fileName}`);
      return null;
    }

    try {
      const content = fs.readFileSync(filePath, 'utf-8');
      const manifest = await parser.parse(filePath, content);

      if (manifest.parseErrors && manifest.parseErrors.length > 0) {
        logger.warn(`⚠️ Parse errors in ${filePath}: ${manifest.parseErrors.join(', ')}`);
      }

      return manifest;
    } catch (error) {
      logger.debug(`Failed to parse ${filePath}: ${error}`);
      return null;
    }
  }

  /**
   * Deduplicate dependencies across manifests
   */
  private deduplicateDependencies(dependencies: Dependency[]): Dependency[] {
    const seen = new Map<string, Dependency>();

    for (const dep of dependencies) {
      const key = `${dep.ecosystem}:${dep.name}`;
      
      if (!seen.has(key)) {
        seen.set(key, dep);
      } else {
        // Keep the one with more information (resolved version, etc.)
        const existing = seen.get(key)!;
        if (dep.resolvedVersion && !existing.resolvedVersion) {
          seen.set(key, dep);
        }
      }
    }

    return Array.from(seen.values());
  }

  /**
   * Analyze dependencies for vulnerabilities
   */
  private async analyzeVulnerabilities(dependencies: Dependency[]): Promise<DependencyVulnerability[]> {
    const vulnerabilities: DependencyVulnerability[] = [];

    for (const dep of dependencies) {
      // Skip dev dependencies if configured
      if (!this.config.includeDevDependencies && dep.dependencyType === 'dev') {
        continue;
      }

      const depVulns = await this.vulnerabilityDetector.analyzeDependency(dep);
      vulnerabilities.push(...depVulns);

      // Log critical vulnerabilities
      for (const vuln of depVulns) {
        if (vuln.severity === Severity.CRITICAL || vuln.severity === Severity.HIGH) {
          logger.warn(`🚨 ${vuln.severity.toUpperCase()}: ${vuln.title}`);
        }
      }
    }

    // Sort by severity
    return this.sortVulnerabilities(vulnerabilities);
  }

  /**
   * Sort vulnerabilities by severity
   */
  private sortVulnerabilities(vulnerabilities: DependencyVulnerability[]): DependencyVulnerability[] {
    const severityOrder: Record<Severity, number> = {
      [Severity.CRITICAL]: 0,
      [Severity.HIGH]: 1,
      [Severity.MEDIUM]: 2,
      [Severity.LOW]: 3,
      [Severity.INFO]: 4
    };

    return vulnerabilities.sort((a, b) => 
      severityOrder[a.severity] - severityOrder[b.severity]
    );
  }

  /**
   * Calculate analysis statistics
   */
  private calculateStats(
    manifests: DependencyManifest[],
    dependencies: Dependency[],
    vulnerabilities: DependencyVulnerability[],
    duration: number
  ): DependencyAnalysisStats {
    const directDeps = dependencies.filter(d => d.dependencyType === 'direct');
    const transitiveDeps = dependencies.filter(d => d.dependencyType === 'transitive');
    
    const vulnerableDeps = new Set(vulnerabilities.map(v => `${v.dependency.ecosystem}:${v.dependency.name}`));

    const vulnBySeverity: Record<Severity, number> = {
      [Severity.CRITICAL]: 0,
      [Severity.HIGH]: 0,
      [Severity.MEDIUM]: 0,
      [Severity.LOW]: 0,
      [Severity.INFO]: 0
    };

    const vulnByCategory: Record<DependencyRiskCategory, number> = {
      [DependencyRiskCategory.VULNERABILITY]: 0,
      [DependencyRiskCategory.SUPPLY_CHAIN]: 0,
      [DependencyRiskCategory.MALICIOUS]: 0,
      [DependencyRiskCategory.OUTDATED]: 0,
      [DependencyRiskCategory.LICENSE]: 0,
      [DependencyRiskCategory.MAINTENANCE]: 0
    };

    for (const vuln of vulnerabilities) {
      vulnBySeverity[vuln.severity]++;
      vulnByCategory[vuln.category]++;
    }

    const ecosystems = [...new Set(manifests.map(m => m.ecosystem))];

    return {
      totalManifests: manifests.length,
      totalDependencies: dependencies.length,
      directDependencies: directDeps.length,
      transitiveDependencies: transitiveDeps.length,
      vulnerableDependencies: vulnerableDeps.size,
      vulnerabilitiesBySeverity: vulnBySeverity,
      vulnerabilitiesByCategory: vulnByCategory,
      ecosystemsAnalyzed: ecosystems,
      duration
    };
  }

  /**
   * Create empty result when no manifests found
   */
  private createEmptyResult(startTime: number): DependencyAnalysisResult {
    return {
      manifests: [],
      dependencies: [],
      vulnerabilities: [],
      stats: {
        totalManifests: 0,
        totalDependencies: 0,
        directDependencies: 0,
        transitiveDependencies: 0,
        vulnerableDependencies: 0,
        vulnerabilitiesBySeverity: {
          [Severity.CRITICAL]: 0,
          [Severity.HIGH]: 0,
          [Severity.MEDIUM]: 0,
          [Severity.LOW]: 0,
          [Severity.INFO]: 0
        },
        vulnerabilitiesByCategory: {
          [DependencyRiskCategory.VULNERABILITY]: 0,
          [DependencyRiskCategory.SUPPLY_CHAIN]: 0,
          [DependencyRiskCategory.MALICIOUS]: 0,
          [DependencyRiskCategory.OUTDATED]: 0,
          [DependencyRiskCategory.LICENSE]: 0,
          [DependencyRiskCategory.MAINTENANCE]: 0
        },
        ecosystemsAnalyzed: [],
        duration: Date.now() - startTime
      },
      ecosystems: [],
      timestamp: new Date()
    };
  }
}

export default DependencyAnalyzer;
