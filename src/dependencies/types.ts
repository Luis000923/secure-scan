/**
 * Tipos para Análisis de Dependencias
 * Definiciones de tipos para SCA (Análisis de Composición de Software)
 */

import { Severity, SecurityStandard } from '../types';

// Re-export for convenience
export { Severity, SecurityStandard };

/**
 * Supported package ecosystems
 */
export type PackageEcosystem =
  | 'npm'       // JavaScript/Node.js
  | 'pip'       // Python
  | 'composer'  // PHP
  | 'maven'     // Java
  | 'gradle'    // Java
  | 'nuget'     // C#
  | 'vcpkg'     // C/C++
  | 'conan'     // C/C++
  | 'cmake';    // C/C++ (CMakeLists.txt)

/**
 * Type of dependency relationship
 */
export type DependencyType = 'direct' | 'transitive' | 'dev' | 'optional' | 'peer';

/**
 * Dependency risk category
 */
export enum DependencyRiskCategory {
  VULNERABILITY = 'vulnerability',
  SUPPLY_CHAIN = 'supply_chain',
  MALICIOUS = 'malicious',
  OUTDATED = 'outdated',
  LICENSE = 'license',
  MAINTENANCE = 'maintenance'
}

/**
 * Supply chain risk indicators
 */
export enum SupplyChainRisk {
  TYPOSQUATTING = 'typosquatting',
  ABANDONED = 'abandoned',
  SUSPICIOUS_RELEASE = 'suspicious_release',
  POST_INSTALL_SCRIPT = 'post_install_script',
  HIGH_MAINTAINER_TURNOVER = 'high_maintainer_turnover',
  NEW_PACKAGE = 'new_package',
  LOW_DOWNLOAD_COUNT = 'low_download_count'
}

/**
 * Malware indicator types
 */
export enum MalwareIndicator {
  BACKDOOR = 'backdoor',
  CRYPTOMINER = 'cryptominer',
  STEALER = 'stealer',
  LOADER = 'loader',
  OBFUSCATED = 'obfuscated',
  DATA_EXFILTRATION = 'data_exfiltration',
  KNOWN_MALWARE = 'known_malware'
}

/**
 * CVE (Common Vulnerabilities and Exposures) information
 */
export interface CVEInfo {
  /** CVE identifier (e.g., CVE-2021-44228) */
  id: string;
  /** CVE description */
  description: string;
  /** CVSS score (0-10) */
  cvssScore: number;
  /** CVSS vector string */
  cvssVector?: string;
  /** Severity based on CVSS */
  severity: Severity;
  /** Date published */
  publishedDate?: string;
  /** Date last modified */
  lastModifiedDate?: string;
  /** Reference URLs */
  references: string[];
  /** Affected versions */
  affectedVersions?: string;
  /** Fixed version (if available) */
  fixedVersion?: string;
  /** CWE identifiers */
  cwes?: string[];
  /** Exploit availability */
  exploitAvailable?: boolean;
}

/**
 * Dependency information
 */
export interface Dependency {
  /** Package name */
  name: string;
  /** Declared version or version range */
  version: string;
  /** Resolved version (if available from lock file) */
  resolvedVersion?: string;
  /** Package ecosystem */
  ecosystem: PackageEcosystem;
  /** Type of dependency */
  dependencyType: DependencyType;
  /** Parent dependency (for transitive) */
  parent?: string;
  /** Depth in dependency tree */
  depth: number;
  /** Source file where dependency was found */
  sourceFile: string;
  /** Line number in source file */
  lineNumber?: number;
  /** Package homepage URL */
  homepage?: string;
  /** Package repository URL */
  repository?: string;
  /** Package license */
  license?: string;
  /** Latest available version */
  latestVersion?: string;
  /** Is deprecated */
  deprecated?: boolean;
  /** Deprecation message */
  deprecationMessage?: string;
}

/**
 * Dependency vulnerability finding
 */
export interface DependencyVulnerability {
  /** Unique finding ID */
  id: string;
  /** Affected dependency */
  dependency: Dependency;
  /** Vulnerability severity */
  severity: Severity;
  /** Risk category */
  category: DependencyRiskCategory;
  /** Title of the finding */
  title: string;
  /** Detailed description */
  description: string;
  /** CVE information (if applicable) */
  cve?: CVEInfo;
  /** Supply chain risks (if applicable) */
  supplyChainRisks?: SupplyChainRisk[];
  /** Malware indicators (if applicable) */
  malwareIndicators?: MalwareIndicator[];
  /** Related security standards */
  standards: SecurityStandard[];
  /** Recommendation (upgrade, replace, remove) */
  recommendation: DependencyRecommendation;
  /** Recommended action details */
  recommendationDetails: string;
  /** Confidence level (0-100) */
  confidence: number;
  /** Detection timestamp */
  timestamp: Date;
  /** AI explanation (if available) */
  aiExplanation?: string;
}

/**
 * Recommendation type for dependency issues
 */
export enum DependencyRecommendation {
  UPGRADE = 'upgrade',
  REPLACE = 'replace',
  REMOVE = 'remove',
  REVIEW = 'review',
  MONITOR = 'monitor'
}

/**
 * Dependency manifest file information
 */
export interface DependencyManifest {
  /** File path */
  filePath: string;
  /** File type */
  fileType: ManifestFileType;
  /** Package ecosystem */
  ecosystem: PackageEcosystem;
  /** Parsed dependencies */
  dependencies: Dependency[];
  /** Parse errors (if any) */
  parseErrors?: string[];
  /** Is lock file */
  isLockFile: boolean;
}

/**
 * Types of manifest files
 */
export type ManifestFileType =
  // JavaScript/Node.js
  | 'package.json'
  | 'package-lock.json'
  | 'yarn.lock'
  // Python
  | 'requirements.txt'
  | 'Pipfile'
  | 'Pipfile.lock'
  | 'pyproject.toml'
  // PHP
  | 'composer.json'
  | 'composer.lock'
  // Java
  | 'pom.xml'
  | 'build.gradle'
  // C/C++
  | 'vcpkg.json'
  | 'conanfile.txt'
  | 'CMakeLists.txt'
  // C#
  | 'csproj'
  | 'packages.config';

/**
 * Dependency analysis result
 */
export interface DependencyAnalysisResult {
  /** All detected manifests */
  manifests: DependencyManifest[];
  /** All dependencies (direct + transitive) */
  dependencies: Dependency[];
  /** All vulnerabilities found */
  vulnerabilities: DependencyVulnerability[];
  /** Analysis statistics */
  stats: DependencyAnalysisStats;
  /** Ecosystems detected */
  ecosystems: PackageEcosystem[];
  /** Analysis timestamp */
  timestamp: Date;
}

/**
 * Dependency analysis statistics
 */
export interface DependencyAnalysisStats {
  /** Total manifests analyzed */
  totalManifests: number;
  /** Total dependencies found */
  totalDependencies: number;
  /** Direct dependencies */
  directDependencies: number;
  /** Transitive dependencies */
  transitiveDependencies: number;
  /** Dependencies with vulnerabilities */
  vulnerableDependencies: number;
  /** Vulnerabilities by severity */
  vulnerabilitiesBySeverity: Record<Severity, number>;
  /** Vulnerabilities by category */
  vulnerabilitiesByCategory: Record<DependencyRiskCategory, number>;
  /** Ecosystems analyzed */
  ecosystemsAnalyzed: string[];
  /** Analysis duration in milliseconds */
  duration: number;
}

/**
 * Known malicious package database entry
 */
export interface MaliciousPackageEntry {
  /** Package name */
  name: string;
  /** Package ecosystem */
  ecosystem: PackageEcosystem;
  /** Malware type indicators */
  indicators: MalwareIndicator[];
  /** Description of malicious behavior */
  description: string;
  /** Date reported */
  reportedDate: string;
  /** Reference URLs */
  references: string[];
  /** Affected versions */
  affectedVersions?: string;
}

/**
 * Typosquatting candidate
 */
export interface TyposquattingCandidate {
  /** Suspicious package name */
  suspiciousName: string;
  /** Likely legitimate package */
  legitimatePackage: string;
  /** Similarity score (0-100) */
  similarityScore: number;
  /** Type of typosquat */
  typosquatType: 'character_swap' | 'missing_char' | 'extra_char' | 'homograph' | 'bit_flip';
}

/**
 * Dependency parser interface
 */
export interface DependencyParser {
  /** Parser name */
  name: string;
  /** Supported file types */
  supportedFiles: ManifestFileType[];
  /** Ecosystem */
  ecosystem: PackageEcosystem;
  /** Parse manifest file */
  parse(filePath: string, content: string): Promise<DependencyManifest>;
  /** Check if file is supported */
  supports(fileName: string): boolean;
}

/**
 * Vulnerability database interface
 */
export interface VulnerabilityDatabase {
  /** Database name */
  name: string;
  /** Check dependency for vulnerabilities */
  checkVulnerabilities(dependency: Dependency): Promise<CVEInfo[]>;
  /** Get CVE details */
  getCVEDetails(cveId: string): Promise<CVEInfo | null>;
  /** Refresh database */
  refresh(): Promise<void>;
}
