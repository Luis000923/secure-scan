/**
 * Types for Installed Dependencies Analysis
 * Scans actual installed packages (node_modules, vendor, venv, etc.)
 */

import { PackageEcosystem, MalwareIndicator, Dependency } from '../types';
import { Severity } from '../../types';

/**
 * Simplified security standard reference for malware patterns
 */
export interface MalwareSecurityStandard {
  /** Standard name */
  standard: 'CWE' | 'MITRE' | 'OWASP' | 'SANS';
  /** Standard ID */
  id: string;
  /** Standard description */
  description: string;
}

/**
 * Installed package information
 */
export interface InstalledPackage {
  /** Package name */
  name: string;
  /** Installed version */
  version: string;
  /** Package ecosystem */
  ecosystem: PackageEcosystem;
  /** Installation path */
  installPath: string;
  /** Total size in bytes */
  sizeBytes: number;
  /** Number of files */
  fileCount: number;
  /** Has post-install scripts */
  hasPostInstallScripts: boolean;
  /** Post-install script content (if any) */
  postInstallScripts?: PostInstallScript[];
  /** Package metadata */
  metadata?: InstalledPackageMetadata;
  /** Integrity check result */
  integrityStatus?: IntegrityStatus;
}

/**
 * Package metadata from installed package
 */
export interface InstalledPackageMetadata {
  /** Author */
  author?: string;
  /** License */
  license?: string;
  /** Homepage */
  homepage?: string;
  /** Repository URL */
  repository?: string;
  /** Description */
  description?: string;
  /** Install date (if available) */
  installDate?: Date;
  /** Main entry point */
  main?: string;
  /** Binary commands */
  binaries?: string[];
}

/**
 * Post-install script information
 */
export interface PostInstallScript {
  /** Script type */
  type: 'preinstall' | 'install' | 'postinstall' | 'preuninstall' | 'postuninstall';
  /** Script command */
  command: string;
  /** Script file path (if file) */
  scriptPath?: string;
  /** Script content (if readable) */
  content?: string;
  /** Risk level */
  riskLevel: Severity;
  /** Risk indicators found */
  riskIndicators: string[];
}

/**
 * Integrity verification status
 */
export interface IntegrityStatus {
  /** Overall status */
  status: 'verified' | 'mismatch' | 'unknown' | 'missing_lockfile';
  /** Expected version from lock file */
  expectedVersion?: string;
  /** Installed version */
  installedVersion: string;
  /** Expected integrity hash */
  expectedHash?: string;
  /** Actual integrity hash */
  actualHash?: string;
  /** Mismatch details */
  mismatchDetails?: string;
}

/**
 * Malware scan result for installed package
 */
export interface InstalledMalwareFinding {
  /** Unique finding ID */
  id: string;
  /** Affected package */
  package: InstalledPackage;
  /** File where malware was detected */
  filePath: string;
  /** Line number (if applicable) */
  lineNumber?: number;
  /** Column number (if applicable) */
  columnNumber?: number;
  /** Malware indicators detected */
  indicators: MalwareIndicator[];
  /** Severity level */
  severity: Severity;
  /** Finding title */
  title: string;
  /** Detailed description */
  description: string;
  /** Matched pattern/signature */
  matchedPattern: string;
  /** Code snippet with malware */
  codeSnippet?: string;
  /** Security standards */
  standards: MalwareSecurityStandard[];
  /** Recommendation */
  recommendation: string;
  /** Confidence level (0-100) */
  confidence: number;
  /** Detection timestamp */
  timestamp: Date;
}

/**
 * Malware detection pattern
 */
export interface MalwarePattern {
  /** Pattern ID */
  id: string;
  /** Pattern name */
  name: string;
  /** Pattern description */
  description: string;
  /** Malware indicator type */
  indicator: MalwareIndicator;
  /** Severity */
  severity: Severity;
  /** Regex patterns */
  patterns: RegExp[];
  /** File extensions to scan */
  fileExtensions: string[];
  /** Keywords that trigger deeper analysis */
  keywords?: string[];
  /** Confidence level (0-100) */
  confidence: number;
  /** Related security standards */
  standards: MalwareSecurityStandard[];
}

/**
 * Installed dependencies scan result
 */
export interface InstalledDependenciesScanResult {
  /** Scanned package folders */
  scannedFolders: ScannedFolder[];
  /** All installed packages found */
  installedPackages: InstalledPackage[];
  /** Malware findings */
  malwareFindings: InstalledMalwareFinding[];
  /** Integrity issues */
  integrityIssues: IntegrityIssue[];
  /** Suspicious post-install scripts */
  suspiciousScripts: SuspiciousScriptFinding[];
  /** Statistics */
  stats: InstalledScanStats;
  /** Timestamp */
  timestamp: Date;
}

/**
 * Scanned folder information
 */
export interface ScannedFolder {
  /** Folder path */
  path: string;
  /** Folder type */
  type: 'node_modules' | 'vendor' | 'venv' | 'site-packages' | 'packages' | 'other';
  /** Ecosystem */
  ecosystem: PackageEcosystem;
  /** Number of packages */
  packageCount: number;
  /** Total size */
  totalSizeBytes: number;
  /** Files scanned */
  filesScanned: number;
}

/**
 * Integrity issue
 */
export interface IntegrityIssue {
  /** Package name */
  packageName: string;
  /** Issue type */
  issueType: 'version_mismatch' | 'hash_mismatch' | 'unexpected_package' | 'missing_package' | 'tampered';
  /** Severity */
  severity: Severity;
  /** Description */
  description: string;
  /** Expected value */
  expected?: string;
  /** Actual value */
  actual?: string;
}

/**
 * Suspicious script finding
 */
export interface SuspiciousScriptFinding {
  /** Package name */
  packageName: string;
  /** Script info */
  script: PostInstallScript;
  /** Severity */
  severity: Severity;
  /** Description */
  description: string;
  /** Risk indicators */
  riskIndicators: string[];
}

/**
 * Statistics for installed dependencies scan
 */
export interface InstalledScanStats {
  /** Total folders scanned */
  totalFoldersScanned: number;
  /** Total packages found */
  totalPackagesFound: number;
  /** Total files scanned */
  totalFilesScanned: number;
  /** Total bytes scanned */
  totalBytesScanned: number;
  /** Malware findings count */
  malwareFindingsCount: number;
  /** Integrity issues count */
  integrityIssuesCount: number;
  /** Suspicious scripts count */
  suspiciousScriptsCount: number;
  /** Packages by ecosystem */
  packagesByEcosystem: Record<PackageEcosystem, number>;
  /** Findings by severity */
  findingsBySeverity: Record<Severity, number>;
  /** Scan duration in ms */
  duration: number;
}

/**
 * Installed dependencies scanner configuration
 */
export interface InstalledScanConfig {
  /** Project root path */
  projectPath: string;
  /** Folders to scan */
  foldersToScan?: string[];
  /** Maximum file size to scan (bytes) */
  maxFileSizeBytes?: number;
  /** File extensions to scan */
  fileExtensions?: string[];
  /** Enable integrity verification */
  verifyIntegrity?: boolean;
  /** Scan post-install scripts */
  scanPostInstallScripts?: boolean;
  /** Maximum depth in node_modules */
  maxDepth?: number;
  /** Verbose logging */
  verbose?: boolean;
  /** Parallel scan threads */
  parallelScans?: number;
}
