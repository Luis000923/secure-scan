/**
 * Installed Dependencies Scanner
 * Scans installed packages (node_modules, vendor, venv) for malware
 */

import * as fs from 'fs';
import * as path from 'path';
import * as crypto from 'crypto';
import {
  InstalledPackage,
  InstalledMalwareFinding,
  InstalledDependenciesScanResult,
  InstalledScanConfig,
  InstalledScanStats,
  ScannedFolder,
  IntegrityIssue,
  SuspiciousScriptFinding,
  PostInstallScript,
  InstalledPackageMetadata,
  IntegrityStatus
} from './types';
import { MALWARE_PATTERNS, SUSPICIOUS_SCRIPT_PATTERNS, getPatternsForFile } from './malwarePatterns';
import { MalwareIndicator, PackageEcosystem } from '../types';
import { Severity } from '../../types';
import { logger } from '../../utils/logger';
import { generateId } from '../../utils';

/**
 * Default configuration for installed dependencies scanner
 */
const DEFAULT_CONFIG: Partial<InstalledScanConfig> = {
  maxFileSizeBytes: 5 * 1024 * 1024, // 5MB
  fileExtensions: ['.js', '.ts', '.mjs', '.cjs', '.py', '.php', '.rb', '.sh', '.ps1', '.cmd', '.bat'],
  verifyIntegrity: true,
  scanPostInstallScripts: true,
  maxDepth: 10,
  verbose: false,
  parallelScans: 4
};

/**
 * Folder configurations for different ecosystems
 */
const DEPENDENCY_FOLDERS = {
  npm: ['node_modules'],
  pip: ['venv', '.venv', 'env', '.env', 'site-packages', 'lib/python*/site-packages'],
  composer: ['vendor'],
  maven: ['.m2/repository'],
  gradle: ['.gradle/caches/modules-2/files-2.1'],
  nuget: ['packages', '.nuget/packages']
};

/**
 * Installed Dependencies Scanner Class
 */
export class InstalledDependenciesScanner {
  private config: InstalledScanConfig;
  private scannedFiles: Set<string> = new Set();
  private stats: InstalledScanStats;

  constructor(config: InstalledScanConfig) {
    this.config = { ...DEFAULT_CONFIG, ...config };
    this.stats = this.initializeStats();
  }

  /**
   * Run the installed dependencies scan
   */
  async scan(): Promise<InstalledDependenciesScanResult> {
    const startTime = Date.now();
    logger.info('🔍 Starting installed dependencies scan...');

    const scannedFolders: ScannedFolder[] = [];
    const installedPackages: InstalledPackage[] = [];
    const malwareFindings: InstalledMalwareFinding[] = [];
    const integrityIssues: IntegrityIssue[] = [];
    const suspiciousScripts: SuspiciousScriptFinding[] = [];

    // Find and scan dependency folders
    const foldersToScan = this.config.foldersToScan || this.findDependencyFolders();
    
    for (const folderPath of foldersToScan) {
      if (!fs.existsSync(folderPath)) continue;

      logger.info(`📂 Scanning: ${folderPath}`);
      
      const folderInfo = await this.scanDependencyFolder(folderPath);
      scannedFolders.push(folderInfo.scannedFolder);
      installedPackages.push(...folderInfo.packages);
      malwareFindings.push(...folderInfo.malwareFindings);
      suspiciousScripts.push(...folderInfo.suspiciousScripts);
    }

    // Verify integrity if enabled
    if (this.config.verifyIntegrity) {
      const integrity = await this.verifyPackageIntegrity(installedPackages);
      integrityIssues.push(...integrity);
    }

    // Update statistics
    const endTime = Date.now();
    this.stats.duration = endTime - startTime;
    this.stats.totalFoldersScanned = scannedFolders.length;
    this.stats.totalPackagesFound = installedPackages.length;
    this.stats.malwareFindingsCount = malwareFindings.length;
    this.stats.integrityIssuesCount = integrityIssues.length;
    this.stats.suspiciousScriptsCount = suspiciousScripts.length;

    // Count findings by severity
    for (const finding of malwareFindings) {
      this.stats.findingsBySeverity[finding.severity] = 
        (this.stats.findingsBySeverity[finding.severity] || 0) + 1;
    }

    logger.info(`✅ Scan complete: ${malwareFindings.length} malware findings, ${integrityIssues.length} integrity issues`);

    return {
      scannedFolders,
      installedPackages,
      malwareFindings,
      integrityIssues,
      suspiciousScripts,
      stats: this.stats,
      timestamp: new Date()
    };
  }

  /**
   * Find dependency folders in the project
   */
  private findDependencyFolders(): string[] {
    const folders: string[] = [];
    const projectPath = this.config.projectPath;

    // Check for node_modules
    const nodeModules = path.join(projectPath, 'node_modules');
    if (fs.existsSync(nodeModules)) {
      folders.push(nodeModules);
    }

    // Check for vendor (PHP)
    const vendor = path.join(projectPath, 'vendor');
    if (fs.existsSync(vendor)) {
      folders.push(vendor);
    }

    // Check for Python virtual environments
    for (const venvName of ['venv', '.venv', 'env', '.env']) {
      const venv = path.join(projectPath, venvName);
      if (fs.existsSync(venv)) {
        // Look for site-packages
        const sitePackages = this.findSitePackages(venv);
        if (sitePackages) {
          folders.push(sitePackages);
        }
      }
    }

    return folders;
  }

  /**
   * Find site-packages in a Python virtual environment
   */
  private findSitePackages(venvPath: string): string | null {
    // Windows: venv/Lib/site-packages
    const windowsPath = path.join(venvPath, 'Lib', 'site-packages');
    if (fs.existsSync(windowsPath)) {
      return windowsPath;
    }

    // Unix: venv/lib/pythonX.X/site-packages
    const libPath = path.join(venvPath, 'lib');
    if (fs.existsSync(libPath)) {
      try {
        const entries = fs.readdirSync(libPath);
        for (const entry of entries) {
          if (entry.startsWith('python')) {
            const sitePackages = path.join(libPath, entry, 'site-packages');
            if (fs.existsSync(sitePackages)) {
              return sitePackages;
            }
          }
        }
      } catch {
        // Ignore errors
      }
    }

    return null;
  }

  /**
   * Scan a dependency folder
   */
  private async scanDependencyFolder(folderPath: string): Promise<{
    scannedFolder: ScannedFolder;
    packages: InstalledPackage[];
    malwareFindings: InstalledMalwareFinding[];
    suspiciousScripts: SuspiciousScriptFinding[];
  }> {
    const packages: InstalledPackage[] = [];
    const malwareFindings: InstalledMalwareFinding[] = [];
    const suspiciousScripts: SuspiciousScriptFinding[] = [];
    
    const folderType = this.getFolderType(folderPath);
    const ecosystem = this.getEcosystemFromFolder(folderPath);
    
    let totalSize = 0;
    let filesScanned = 0;

    // Get all packages in the folder
    const packageDirs = await this.getPackageDirectories(folderPath, ecosystem);

    for (const packageDir of packageDirs) {
      const pkg = await this.parseInstalledPackage(packageDir, ecosystem);
      if (pkg) {
        packages.push(pkg);
        totalSize += pkg.sizeBytes;

        // Scan package files for malware
        const findings = await this.scanPackageForMalware(pkg, packageDir);
        malwareFindings.push(...findings.malwareFindings);
        filesScanned += findings.filesScanned;

        // Check post-install scripts
        if (this.config.scanPostInstallScripts && pkg.hasPostInstallScripts) {
          const scriptFindings = this.analyzePostInstallScripts(pkg);
          suspiciousScripts.push(...scriptFindings);
        }

        // Update ecosystem stats
        this.stats.packagesByEcosystem[ecosystem] = 
          (this.stats.packagesByEcosystem[ecosystem] || 0) + 1;
      }
    }

    this.stats.totalFilesScanned += filesScanned;
    this.stats.totalBytesScanned += totalSize;

    return {
      scannedFolder: {
        path: folderPath,
        type: folderType,
        ecosystem,
        packageCount: packages.length,
        totalSizeBytes: totalSize,
        filesScanned
      },
      packages,
      malwareFindings,
      suspiciousScripts
    };
  }

  /**
   * Get folder type from path
   */
  private getFolderType(folderPath: string): ScannedFolder['type'] {
    const folderName = path.basename(folderPath);
    
    if (folderName === 'node_modules') return 'node_modules';
    if (folderName === 'vendor') return 'vendor';
    if (folderName === 'site-packages') return 'site-packages';
    if (['venv', '.venv', 'env', '.env'].includes(folderName)) return 'venv';
    if (folderName === 'packages') return 'packages';
    
    return 'other';
  }

  /**
   * Get ecosystem from folder path
   */
  private getEcosystemFromFolder(folderPath: string): PackageEcosystem {
    if (folderPath.includes('node_modules')) return 'npm';
    if (folderPath.includes('vendor')) return 'composer';
    if (folderPath.includes('site-packages') || folderPath.includes('venv')) return 'pip';
    if (folderPath.includes('.nuget') || folderPath.includes('packages')) return 'nuget';
    
    return 'npm'; // Default
  }

  /**
   * Get package directories in a dependency folder
   */
  private async getPackageDirectories(folderPath: string, ecosystem: PackageEcosystem): Promise<string[]> {
    const packageDirs: string[] = [];

    try {
      const entries = fs.readdirSync(folderPath, { withFileTypes: true });

      for (const entry of entries) {
        if (!entry.isDirectory()) continue;
        
        const fullPath = path.join(folderPath, entry.name);

        // Handle scoped packages for npm (@scope/package)
        if (ecosystem === 'npm' && entry.name.startsWith('@')) {
          const scopedEntries = fs.readdirSync(fullPath, { withFileTypes: true });
          for (const scopedEntry of scopedEntries) {
            if (scopedEntry.isDirectory()) {
              packageDirs.push(path.join(fullPath, scopedEntry.name));
            }
          }
        } else if (!entry.name.startsWith('.')) {
          packageDirs.push(fullPath);
        }
      }
    } catch (error) {
      logger.debug(`Error reading directory ${folderPath}: ${error}`);
    }

    return packageDirs;
  }

  /**
   * Parse an installed package directory
   */
  private async parseInstalledPackage(packageDir: string, ecosystem: PackageEcosystem): Promise<InstalledPackage | null> {
    try {
      let name = path.basename(packageDir);
      let version = 'unknown';
      let metadata: InstalledPackageMetadata = {};
      let hasPostInstallScripts = false;
      let postInstallScripts: PostInstallScript[] = [];

      // Handle scoped packages
      const parentDir = path.basename(path.dirname(packageDir));
      if (parentDir.startsWith('@')) {
        name = `${parentDir}/${name}`;
      }

      // Parse package.json for npm
      if (ecosystem === 'npm') {
        const packageJsonPath = path.join(packageDir, 'package.json');
        if (fs.existsSync(packageJsonPath)) {
          const packageJson = JSON.parse(fs.readFileSync(packageJsonPath, 'utf-8'));
          name = packageJson.name || name;
          version = packageJson.version || version;
          metadata = {
            author: typeof packageJson.author === 'string' ? packageJson.author : packageJson.author?.name,
            license: packageJson.license,
            homepage: packageJson.homepage,
            repository: typeof packageJson.repository === 'string' ? packageJson.repository : packageJson.repository?.url,
            description: packageJson.description,
            main: packageJson.main,
            binaries: packageJson.bin ? Object.keys(packageJson.bin) : undefined
          };

          // Check for post-install scripts
          const scripts = packageJson.scripts || {};
          for (const scriptType of ['preinstall', 'install', 'postinstall', 'preuninstall', 'postuninstall'] as const) {
            if (scripts[scriptType]) {
              hasPostInstallScripts = true;
              const scriptInfo = this.analyzeScript(scriptType, scripts[scriptType], packageDir);
              postInstallScripts.push(scriptInfo);
            }
          }
        }
      }

      // Parse for pip/Python
      if (ecosystem === 'pip') {
        // Try to find PKG-INFO or METADATA
        const metadataPath = path.join(packageDir, 'PKG-INFO');
        const distInfoDir = this.findDistInfoDir(packageDir);
        
        if (distInfoDir) {
          const metaPath = path.join(distInfoDir, 'METADATA');
          if (fs.existsSync(metaPath)) {
            const content = fs.readFileSync(metaPath, 'utf-8');
            const parsed = this.parsePythonMetadata(content);
            name = parsed.name || name;
            version = parsed.version || version;
            metadata = {
              author: parsed.author,
              license: parsed.license,
              homepage: parsed.homepage,
              description: parsed.summary
            };
          }
        }
      }

      // Calculate size and file count
      const sizeInfo = this.calculateDirectorySize(packageDir);

      return {
        name,
        version,
        ecosystem,
        installPath: packageDir,
        sizeBytes: sizeInfo.size,
        fileCount: sizeInfo.fileCount,
        hasPostInstallScripts,
        postInstallScripts: postInstallScripts.length > 0 ? postInstallScripts : undefined,
        metadata
      };
    } catch (error) {
      logger.debug(`Error parsing package at ${packageDir}: ${error}`);
      return null;
    }
  }

  /**
   * Find .dist-info directory for Python packages
   */
  private findDistInfoDir(packageDir: string): string | null {
    const parentDir = path.dirname(packageDir);
    const packageName = path.basename(packageDir);
    
    try {
      const entries = fs.readdirSync(parentDir);
      for (const entry of entries) {
        if (entry.startsWith(packageName.replace(/-/g, '_')) && entry.endsWith('.dist-info')) {
          return path.join(parentDir, entry);
        }
      }
    } catch {
      // Ignore
    }
    
    return null;
  }

  /**
   * Parse Python package metadata
   */
  private parsePythonMetadata(content: string): Record<string, string> {
    const result: Record<string, string> = {};
    const lines = content.split('\n');
    
    for (const line of lines) {
      const match = line.match(/^([A-Za-z-]+):\s*(.+)$/);
      if (match) {
        const key = match[1].toLowerCase().replace(/-/g, '_');
        result[key] = match[2].trim();
      }
    }
    
    return {
      name: result.name,
      version: result.version,
      author: result.author,
      license: result.license,
      homepage: result.home_page,
      summary: result.summary
    };
  }

  /**
   * Analyze a post-install script
   */
  private analyzeScript(type: PostInstallScript['type'], command: string, packageDir: string): PostInstallScript {
    const riskIndicators: string[] = [];
    let riskLevel: Severity = Severity.INFO;
    let scriptContent: string | undefined;
    let scriptPath: string | undefined;

    // Check for file reference
    const fileMatch = command.match(/node\s+([^\s]+)/);
    if (fileMatch) {
      const possiblePath = path.join(packageDir, fileMatch[1]);
      if (fs.existsSync(possiblePath)) {
        scriptPath = possiblePath;
        try {
          scriptContent = fs.readFileSync(possiblePath, 'utf-8');
        } catch {
          // Ignore read errors
        }
      }
    }

    // Analyze command and content for suspicious patterns
    const contentToAnalyze = scriptContent || command;
    
    for (const pattern of SUSPICIOUS_SCRIPT_PATTERNS) {
      if (pattern.test(contentToAnalyze)) {
        riskIndicators.push(pattern.source);
        if (riskLevel === Severity.INFO) riskLevel = Severity.LOW;
      }
    }

    // Check for high-risk patterns
    if (/curl.*\|.*sh|wget.*\|.*bash|rm\s+-rf/.test(contentToAnalyze)) {
      riskLevel = Severity.CRITICAL;
    } else if (/eval|exec|subprocess|child_process/.test(contentToAnalyze)) {
      riskLevel = Severity.HIGH;
    } else if (/http|fetch|request/.test(contentToAnalyze)) {
      riskLevel = Severity.MEDIUM;
    }

    return {
      type,
      command,
      scriptPath,
      content: scriptContent,
      riskLevel,
      riskIndicators
    };
  }

  /**
   * Analyze post-install scripts for a package
   */
  private analyzePostInstallScripts(pkg: InstalledPackage): SuspiciousScriptFinding[] {
    const findings: SuspiciousScriptFinding[] = [];

    if (!pkg.postInstallScripts) return findings;

    for (const script of pkg.postInstallScripts) {
      if (script.riskLevel !== 'info' && script.riskIndicators.length > 0) {
        findings.push({
          packageName: pkg.name,
          script,
          severity: script.riskLevel,
          description: `Suspicious ${script.type} script detected in package ${pkg.name}`,
          riskIndicators: script.riskIndicators
        });
      }
    }

    return findings;
  }

  /**
   * Calculate directory size
   */
  private calculateDirectorySize(dirPath: string): { size: number; fileCount: number } {
    let size = 0;
    let fileCount = 0;

    const calculate = (dir: string, depth: number = 0) => {
      if (depth > 5) return; // Limit recursion depth
      
      try {
        const entries = fs.readdirSync(dir, { withFileTypes: true });
        for (const entry of entries) {
          const fullPath = path.join(dir, entry.name);
          if (entry.isDirectory()) {
            calculate(fullPath, depth + 1);
          } else if (entry.isFile()) {
            const stats = fs.statSync(fullPath);
            size += stats.size;
            fileCount++;
          }
        }
      } catch {
        // Ignore permission errors
      }
    };

    calculate(dirPath);
    return { size, fileCount };
  }

  /**
   * Scan a package for malware
   */
  private async scanPackageForMalware(pkg: InstalledPackage, packageDir: string): Promise<{
    malwareFindings: InstalledMalwareFinding[];
    filesScanned: number;
  }> {
    const malwareFindings: InstalledMalwareFinding[] = [];
    let filesScanned = 0;

    const scanFile = (filePath: string) => {
      if (this.scannedFiles.has(filePath)) return;
      this.scannedFiles.add(filePath);

      const ext = path.extname(filePath).toLowerCase();
      if (!this.config.fileExtensions?.includes(ext)) return;

      try {
        const stats = fs.statSync(filePath);
        if (stats.size > (this.config.maxFileSizeBytes ?? 5 * 1024 * 1024)) return;

        const content = fs.readFileSync(filePath, 'utf-8');
        filesScanned++;

        // Get patterns applicable to this file type
        const patterns = getPatternsForFile(filePath);

        for (const pattern of patterns) {
          for (const regex of pattern.patterns) {
            // Reset regex state
            regex.lastIndex = 0;
            const match = regex.exec(content);
            
            if (match) {
              // Find line number
              const beforeMatch = content.substring(0, match.index);
              const lineNumber = beforeMatch.split('\n').length;

              // Extract code snippet
              const lines = content.split('\n');
              const startLine = Math.max(0, lineNumber - 2);
              const endLine = Math.min(lines.length, lineNumber + 2);
              const codeSnippet = lines.slice(startLine, endLine).join('\n');

              malwareFindings.push({
                id: generateId(),
                package: pkg,
                filePath,
                lineNumber,
                indicators: [pattern.indicator],
                severity: pattern.severity,
                title: pattern.name,
                description: pattern.description,
                matchedPattern: pattern.id,
                codeSnippet,
                standards: pattern.standards,
                recommendation: this.getRecommendation(pattern.indicator),
                confidence: pattern.confidence,
                timestamp: new Date()
              });

              // Only report first match per pattern per file
              break;
            }
          }
        }
      } catch (error) {
        // Ignore file read errors (binary files, etc.)
      }
    };

    const scanDirectory = (dir: string, depth: number = 0) => {
      if (depth > (this.config.maxDepth ?? 10)) return;

      try {
        const entries = fs.readdirSync(dir, { withFileTypes: true });
        for (const entry of entries) {
          const fullPath = path.join(dir, entry.name);
          if (entry.isDirectory()) {
            // Skip nested node_modules
            if (entry.name === 'node_modules' && depth > 0) continue;
            scanDirectory(fullPath, depth + 1);
          } else if (entry.isFile()) {
            scanFile(fullPath);
          }
        }
      } catch {
        // Ignore permission errors
      }
    };

    scanDirectory(packageDir);
    return { malwareFindings, filesScanned };
  }

  /**
   * Get recommendation for malware indicator
   */
  private getRecommendation(indicator: MalwareIndicator): string {
    const recommendations: Record<MalwareIndicator, string> = {
      [MalwareIndicator.BACKDOOR]: 'Remove this package immediately. It contains backdoor code that allows remote access.',
      [MalwareIndicator.CRYPTOMINER]: 'Remove this package. It contains cryptocurrency mining code that steals computational resources.',
      [MalwareIndicator.STEALER]: 'Remove this package immediately. It attempts to steal credentials or sensitive data.',
      [MalwareIndicator.LOADER]: 'Remove this package. It downloads and executes code from external sources.',
      [MalwareIndicator.OBFUSCATED]: 'Review this package carefully. Heavily obfuscated code may hide malicious functionality.',
      [MalwareIndicator.DATA_EXFILTRATION]: 'Remove this package. It attempts to send sensitive data to external servers.',
      [MalwareIndicator.KNOWN_MALWARE]: 'Remove this package immediately. It has been identified as known malware.'
    };

    return recommendations[indicator] || 'Review this package and consider removing it.';
  }

  /**
   * Verify package integrity
   */
  private async verifyPackageIntegrity(packages: InstalledPackage[]): Promise<IntegrityIssue[]> {
    const issues: IntegrityIssue[] = [];

    // Try to load lock file
    const lockFileData = await this.loadLockFile();
    if (!lockFileData) {
      logger.debug('No lock file found for integrity verification');
      return issues;
    }

    for (const pkg of packages) {
      const expectedVersion = lockFileData.packages[pkg.name];
      
      if (!expectedVersion) {
        // Package not in lock file
        issues.push({
          packageName: pkg.name,
          issueType: 'unexpected_package',
          severity: Severity.MEDIUM,
          description: `Package ${pkg.name} is installed but not in lock file`,
          actual: pkg.version
        });
      } else if (expectedVersion !== pkg.version) {
        // Version mismatch
        issues.push({
          packageName: pkg.name,
          issueType: 'version_mismatch',
          severity: Severity.HIGH,
          description: `Package ${pkg.name} version mismatch - possible tampering`,
          expected: expectedVersion,
          actual: pkg.version
        });
      }

      // Update package integrity status
      pkg.integrityStatus = {
        status: expectedVersion === pkg.version ? 'verified' : 
                expectedVersion ? 'mismatch' : 'unknown',
        expectedVersion,
        installedVersion: pkg.version
      };
    }

    // Check for missing packages
    for (const [pkgName, version] of Object.entries(lockFileData.packages)) {
      const installed = packages.find(p => p.name === pkgName);
      if (!installed) {
        issues.push({
          packageName: pkgName,
          issueType: 'missing_package',
          severity: Severity.LOW,
          description: `Package ${pkgName} is in lock file but not installed`,
          expected: version as string
        });
      }
    }

    return issues;
  }

  /**
   * Load lock file data
   */
  private async loadLockFile(): Promise<{ packages: Record<string, string> } | null> {
    const projectPath = this.config.projectPath;
    const packages: Record<string, string> = {};

    // Try package-lock.json
    const packageLockPath = path.join(projectPath, 'package-lock.json');
    if (fs.existsSync(packageLockPath)) {
      try {
        const lockFile = JSON.parse(fs.readFileSync(packageLockPath, 'utf-8'));
        
        // Handle npm v3 format
        if (lockFile.packages) {
          for (const [key, value] of Object.entries(lockFile.packages)) {
            if (key && key !== '') {
              const name = key.replace(/^node_modules\//, '');
              packages[name] = (value as any).version;
            }
          }
        }
        
        // Handle npm v1/v2 format
        if (lockFile.dependencies) {
          for (const [name, value] of Object.entries(lockFile.dependencies)) {
            packages[name] = (value as any).version;
          }
        }
        
        return { packages };
      } catch {
        logger.debug('Error parsing package-lock.json');
      }
    }

    // Try yarn.lock (simplified parsing)
    const yarnLockPath = path.join(projectPath, 'yarn.lock');
    if (fs.existsSync(yarnLockPath)) {
      try {
        const content = fs.readFileSync(yarnLockPath, 'utf-8');
        const lines = content.split('\n');
        let currentPackage = '';
        
        for (const line of lines) {
          const pkgMatch = line.match(/^"?(@?[^@\s]+)@/);
          if (pkgMatch) {
            currentPackage = pkgMatch[1];
          }
          const versionMatch = line.match(/^\s+version:?\s+"?([^"\s]+)"?/);
          if (versionMatch && currentPackage) {
            packages[currentPackage] = versionMatch[1];
          }
        }
        
        return { packages };
      } catch {
        logger.debug('Error parsing yarn.lock');
      }
    }

    return null;
  }

  /**
   * Initialize statistics
   */
  private initializeStats(): InstalledScanStats {
    return {
      totalFoldersScanned: 0,
      totalPackagesFound: 0,
      totalFilesScanned: 0,
      totalBytesScanned: 0,
      malwareFindingsCount: 0,
      integrityIssuesCount: 0,
      suspiciousScriptsCount: 0,
      packagesByEcosystem: {} as Record<PackageEcosystem, number>,
      findingsBySeverity: {} as Record<Severity, number>,
      duration: 0
    };
  }
}

/**
 * Quick scan function
 */
export async function scanInstalledDependencies(projectPath: string): Promise<InstalledDependenciesScanResult> {
  const scanner = new InstalledDependenciesScanner({ projectPath });
  return scanner.scan();
}
