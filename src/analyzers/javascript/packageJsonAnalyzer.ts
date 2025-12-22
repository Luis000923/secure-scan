/**
 * Package.json Security Analyzer
 * Deep analysis of npm package manifests for supply chain threats
 * 
 * Detects typosquatting, malicious scripts, suspicious dependencies
 */

import { Severity, ThreatType, FindingCategory } from '../../types';

/**
 * Calculate Levenshtein distance between two strings
 * (Simple implementation to avoid external dependency)
 */
function levenshteinDistance(a: string, b: string): number {
  const matrix: number[][] = [];
  
  for (let i = 0; i <= b.length; i++) {
    matrix[i] = [i];
  }
  for (let j = 0; j <= a.length; j++) {
    matrix[0][j] = j;
  }
  
  for (let i = 1; i <= b.length; i++) {
    for (let j = 1; j <= a.length; j++) {
      if (b.charAt(i - 1) === a.charAt(j - 1)) {
        matrix[i][j] = matrix[i - 1][j - 1];
      } else {
        matrix[i][j] = Math.min(
          matrix[i - 1][j - 1] + 1, // substitution
          matrix[i][j - 1] + 1,     // insertion
          matrix[i - 1][j] + 1      // deletion
        );
      }
    }
  }
  
  return matrix[b.length][a.length];
}

/**
 * Package.json analysis finding
 */
export interface PackageJsonFinding {
  /** Finding type */
  type: PackageJsonFindingType;
  /** Finding name */
  name: string;
  /** Description */
  description: string;
  /** Severity */
  severity: Severity;
  /** Threat type */
  threatType: ThreatType;
  /** Category */
  category: FindingCategory;
  /** Affected field */
  field: string;
  /** Value that triggered the finding */
  value: string;
  /** Confidence 0-100 */
  confidence: number;
  /** Remediation advice */
  remediation: string;
  /** Additional context */
  context?: Record<string, string>;
}

/**
 * Types of package.json findings
 */
export enum PackageJsonFindingType {
  MALICIOUS_SCRIPT = 'malicious_script',
  TYPOSQUATTING = 'typosquatting',
  SUSPICIOUS_DEPENDENCY = 'suspicious_dependency',
  PRIVATE_REGISTRY = 'private_registry',
  GIT_DEPENDENCY = 'git_dependency',
  LOCAL_PATH_DEPENDENCY = 'local_path_dependency',
  OVERLY_PERMISSIVE_VERSION = 'overly_permissive_version',
  DANGEROUS_POSTINSTALL = 'dangerous_postinstall',
  OUTDATED_DEPENDENCY = 'outdated_dependency',
  DEPRECATED_PACKAGE = 'deprecated_package',
  INSTALL_SCRIPT_ABUSE = 'install_script_abuse',
  SUSPICIOUS_MAINTAINER = 'suspicious_maintainer'
}

/**
 * Popular packages for typosquatting detection
 */
const POPULAR_PACKAGES = [
  // Core npm packages
  'lodash', 'underscore', 'express', 'react', 'vue', 'angular',
  'moment', 'axios', 'request', 'bluebird', 'async', 'chalk',
  'commander', 'debug', 'dotenv', 'fs-extra', 'glob', 'inquirer',
  'jest', 'mocha', 'chai', 'webpack', 'babel-core', 'typescript',
  'eslint', 'prettier', 'nodemon', 'pm2', 'mongoose', 'sequelize',
  'mysql', 'pg', 'redis', 'socket.io', 'graphql', 'apollo-server',
  'next', 'nuxt', 'gatsby', 'electron', 'puppeteer', 'cheerio',
  'uuid', 'jsonwebtoken', 'bcrypt', 'passport', 'cors', 'helmet',
  'morgan', 'winston', 'pino', 'bunyan', 'body-parser', 'cookie-parser',
  'multer', 'formidable', 'sharp', 'jimp', 'node-fetch', 'got',
  'superagent', 'cross-env', 'rimraf', 'mkdirp', 'semver', 'yargs',
  'minimist', 'ora', 'listr', 'execa', 'shelljs', 'cross-spawn',
  // React ecosystem
  'react-dom', 'react-router', 'react-redux', 'redux', 'redux-thunk',
  'redux-saga', 'mobx', 'mobx-react', 'styled-components', 'emotion',
  'material-ui', '@mui/material', 'antd', 'bootstrap', 'tailwindcss',
  // Vue ecosystem
  'vue-router', 'vuex', 'vuetify', 'element-ui', 'vant',
  // Angular ecosystem
  '@angular/core', '@angular/common', '@angular/router', 'rxjs',
  // Build tools
  'rollup', 'parcel', 'esbuild', 'vite', 'snowpack',
  'babel-loader', 'ts-loader', 'css-loader', 'style-loader',
  // Testing
  'cypress', 'playwright', '@testing-library/react', 'enzyme',
  // Security sensitive
  'crypto-js', 'node-forge', 'bcryptjs', 'argon2'
];

/**
 * Suspicious script patterns
 */
const SUSPICIOUS_SCRIPT_PATTERNS: Array<{
  pattern: RegExp;
  name: string;
  description: string;
  severity: Severity;
  confidence: number;
}> = [
  {
    pattern: /curl\s+[^\s]+\s*\|\s*(?:sh|bash|zsh)/i,
    name: 'Remote Script Execution',
    description: 'Downloads and executes a remote script',
    severity: Severity.CRITICAL,
    confidence: 95
  },
  {
    pattern: /wget\s+[^\s]+\s*(?:&&|;)\s*(?:sh|bash|chmod)/i,
    name: 'wget Remote Execution',
    description: 'Downloads and executes a remote script via wget',
    severity: Severity.CRITICAL,
    confidence: 95
  },
  {
    pattern: /node\s+-e\s+["'][^"']*(?:http|https|fetch|require\(['"]child_process)/i,
    name: 'Inline Node Execution',
    description: 'Executes inline Node.js code with network or process access',
    severity: Severity.HIGH,
    confidence: 85
  },
  {
    pattern: /powershell\s+(?:-(?:e|enc|encodedcommand))/i,
    name: 'PowerShell Encoded Command',
    description: 'Executes encoded PowerShell command',
    severity: Severity.CRITICAL,
    confidence: 90
  },
  {
    pattern: /echo\s+[A-Za-z0-9+/=]{50,}\s*\|\s*base64\s+-d/i,
    name: 'Base64 Decode Execution',
    description: 'Decodes and potentially executes Base64 content',
    severity: Severity.HIGH,
    confidence: 85
  },
  {
    pattern: /\$\(curl|`curl|\$\(wget|`wget/i,
    name: 'Command Substitution Download',
    description: 'Uses command substitution to download content',
    severity: Severity.HIGH,
    confidence: 85
  },
  {
    pattern: /eval\s*["'`]?\$\(/i,
    name: 'Eval Command Substitution',
    description: 'Evaluates the output of a command',
    severity: Severity.CRITICAL,
    confidence: 90
  },
  {
    pattern: />\s*\/dev\/tcp\//i,
    name: 'Bash Network Redirect',
    description: 'Uses bash /dev/tcp for network communication',
    severity: Severity.CRITICAL,
    confidence: 95
  },
  {
    pattern: /nc\s+-[^|]*\s+(?:\||&)/i,
    name: 'Netcat Usage',
    description: 'Uses netcat for network communication',
    severity: Severity.HIGH,
    confidence: 80
  },
  {
    pattern: /rm\s+-rf\s+(?:\/|~|\$HOME)/i,
    name: 'Dangerous File Deletion',
    description: 'Recursively deletes important directories',
    severity: Severity.CRITICAL,
    confidence: 90
  },
  {
    pattern: /chmod\s+(?:\+s|u\+s|4755|2755)/i,
    name: 'SetUID/SetGID Modification',
    description: 'Changes file permissions to setuid/setgid',
    severity: Severity.HIGH,
    confidence: 85
  },
  {
    pattern: /(?:\.ssh|id_rsa|authorized_keys)/i,
    name: 'SSH Key Access',
    description: 'Script accesses SSH keys or configuration',
    severity: Severity.HIGH,
    confidence: 75
  },
  {
    pattern: /(?:\/etc\/passwd|\/etc\/shadow)/i,
    name: 'System Password File Access',
    description: 'Script accesses system password files',
    severity: Severity.CRITICAL,
    confidence: 90
  }
];

/**
 * Known malicious or suspicious package names
 */
const KNOWN_MALICIOUS_PACKAGES = new Set([
  // Historical malicious packages
  'event-stream', 'flatmap-stream', 'ua-parser-js', 'coa', 'rc',
  'colors', 'faker', // These were sabotaged by maintainers
  // Common typosquatting targets that have been used maliciously
  'loadsh', 'lodahs', 'lodashs', 'crossenv', 'cross-env.js',
  'babelcli', 'http-proxy.js', 'mongose', 'mongoos',
  'mssql.js', 'mssql-node', 'mysqljs', 'node-fabric',
  'node-opencv', 'node-opensl', 'node-openssl', 'node-sqlite',
  'node-tkinter', 'nodefabric', 'nodeffmpeg', 'nodemailer-js',
  'noderequest', 'nodesass', 'nodesqlite', 'opencv.js',
  'openssl.js', 'proxy.js', 'shadowsock', 'smb', 'sqlite.js',
  'sqliter', 'sqlserver', 'tkinter'
]);

/**
 * Suspicious package name patterns
 */
const SUSPICIOUS_PACKAGE_PATTERNS = [
  { pattern: /^@[^/]+\/[^/]+--[^/]+$/, reason: 'Double hyphen in scoped package' },
  { pattern: /^[a-z]+-[0-9]+$/, reason: 'Package name with trailing numbers' },
  { pattern: /^node-(?!gyp|fetch|forge|uuid|notifier|schedule|html)/, reason: 'Suspicious node- prefix' },
  { pattern: /^js-(?!yaml|cookie|beautify)/, reason: 'Suspicious js- prefix' },
  { pattern: /\.(js|ts|json|node)$/, reason: 'Package name with file extension' },
  { pattern: /^npm-|^yarn-/i, reason: 'Package prefixed with package manager name' }
];

/**
 * Package.json Analyzer Class
 */
export class PackageJsonAnalyzer {
  private findings: PackageJsonFinding[] = [];

  /**
   * Analyze a package.json file
   */
  analyze(content: string, filePath: string): PackageJsonFinding[] {
    this.findings = [];

    let pkg: Record<string, unknown>;
    try {
      pkg = JSON.parse(content);
    } catch {
      // Invalid JSON
      return [];
    }

    // Analyze scripts
    if (pkg.scripts && typeof pkg.scripts === 'object') {
      this.analyzeScripts(pkg.scripts as Record<string, string>);
    }

    // Analyze dependencies
    const depFields = ['dependencies', 'devDependencies', 'peerDependencies', 'optionalDependencies'];
    for (const field of depFields) {
      if (pkg[field] && typeof pkg[field] === 'object') {
        this.analyzeDependencies(pkg[field] as Record<string, string>, field);
      }
    }

    // Check for bundledDependencies with version specifiers (unusual)
    if (pkg.bundledDependencies || pkg.bundleDependencies) {
      this.checkBundledDependencies(
        (pkg.bundledDependencies || pkg.bundleDependencies) as string[]
      );
    }

    // Check for suspicious package metadata
    this.analyzeMetadata(pkg);

    return this.findings;
  }

  /**
   * Analyze npm scripts for malicious patterns
   */
  private analyzeScripts(scripts: Record<string, string>): void {
    // High-risk lifecycle scripts
    const lifecycleScripts = ['preinstall', 'install', 'postinstall', 'preuninstall', 'postuninstall'];
    
    for (const [scriptName, scriptContent] of Object.entries(scripts)) {
      // Check lifecycle scripts more strictly
      const isLifecycle = lifecycleScripts.includes(scriptName);
      
      // Check against suspicious patterns
      for (const { pattern, name, description, severity, confidence } of SUSPICIOUS_SCRIPT_PATTERNS) {
        if (pattern.test(scriptContent)) {
          this.findings.push({
            type: PackageJsonFindingType.MALICIOUS_SCRIPT,
            name: `${name} in ${scriptName}`,
            description: `${description} found in npm script "${scriptName}"`,
            severity: isLifecycle ? Severity.CRITICAL : severity,
            threatType: ThreatType.MALICIOUS_LOADER,
            category: FindingCategory.MALWARE,
            field: `scripts.${scriptName}`,
            value: scriptContent,
            confidence: isLifecycle ? Math.min(confidence + 10, 100) : confidence,
            remediation: isLifecycle 
              ? 'Remove or thoroughly review this lifecycle script. Use npm config set ignore-scripts true for untrusted packages.'
              : 'Review and remove suspicious commands from the script.',
            context: { scriptName }
          });
        }
      }

      // Check for scripts that look obfuscated
      if (this.looksObfuscated(scriptContent)) {
        this.findings.push({
          type: PackageJsonFindingType.MALICIOUS_SCRIPT,
          name: 'Obfuscated Script',
          description: `Script "${scriptName}" appears to contain obfuscated code`,
          severity: isLifecycle ? Severity.CRITICAL : Severity.HIGH,
          threatType: ThreatType.OBFUSCATED_CODE,
          category: FindingCategory.MALWARE,
          field: `scripts.${scriptName}`,
          value: scriptContent.substring(0, 200),
          confidence: 75,
          remediation: 'Deobfuscate and analyze the script content.',
          context: { scriptName }
        });
      }
    }
  }

  /**
   * Analyze dependencies for security issues
   */
  private analyzeDependencies(deps: Record<string, string>, field: string): void {
    for (const [name, version] of Object.entries(deps)) {
      // Check for known malicious packages
      if (KNOWN_MALICIOUS_PACKAGES.has(name)) {
        this.findings.push({
          type: PackageJsonFindingType.SUSPICIOUS_DEPENDENCY,
          name: 'Known Malicious Package',
          description: `Package "${name}" has been flagged as malicious or compromised`,
          severity: Severity.CRITICAL,
          threatType: ThreatType.MALICIOUS_LOADER,
          category: FindingCategory.MALWARE,
          field: `${field}.${name}`,
          value: `${name}@${version}`,
          confidence: 95,
          remediation: 'Remove this package immediately and find a legitimate alternative.'
        });
      }

      // Check for typosquatting
      const typosquatResult = this.checkTyposquatting(name);
      if (typosquatResult) {
        this.findings.push({
          type: PackageJsonFindingType.TYPOSQUATTING,
          name: 'Potential Typosquatting',
          description: `Package "${name}" may be a typosquat of "${typosquatResult.target}"`,
          severity: Severity.HIGH,
          threatType: ThreatType.MALICIOUS_LOADER,
          category: FindingCategory.MALWARE,
          field: `${field}.${name}`,
          value: `${name}@${version}`,
          confidence: typosquatResult.confidence,
          remediation: `Verify you intended to install "${name}" and not "${typosquatResult.target}".`,
          context: { similarTo: typosquatResult.target }
        });
      }

      // Check for suspicious package name patterns
      for (const { pattern, reason } of SUSPICIOUS_PACKAGE_PATTERNS) {
        if (pattern.test(name)) {
          this.findings.push({
            type: PackageJsonFindingType.SUSPICIOUS_DEPENDENCY,
            name: 'Suspicious Package Name',
            description: `Package "${name}" has a suspicious name pattern: ${reason}`,
            severity: Severity.MEDIUM,
            threatType: ThreatType.MALICIOUS_LOADER,
            category: FindingCategory.MALWARE,
            field: `${field}.${name}`,
            value: `${name}@${version}`,
            confidence: 60,
            remediation: 'Verify this is the intended package before installing.'
          });
        }
      }

      // Check for git dependencies (can be risky)
      if (version.startsWith('git') || version.startsWith('github:') || version.includes('://')) {
        this.findings.push({
          type: PackageJsonFindingType.GIT_DEPENDENCY,
          name: 'Git URL Dependency',
          description: `Package "${name}" is installed from a git URL instead of npm registry`,
          severity: Severity.MEDIUM,
          threatType: ThreatType.SECURITY_MISCONFIGURATION,
          category: FindingCategory.VULNERABILITY,
          field: `${field}.${name}`,
          value: `${name}@${version}`,
          confidence: 70,
          remediation: 'Use npm registry versions when possible. Audit the git repository.'
        });
      }

      // Check for local file dependencies
      if (version.startsWith('file:') || version.startsWith('./') || version.startsWith('../')) {
        this.findings.push({
          type: PackageJsonFindingType.LOCAL_PATH_DEPENDENCY,
          name: 'Local Path Dependency',
          description: `Package "${name}" uses a local file path`,
          severity: Severity.LOW,
          threatType: ThreatType.SECURITY_MISCONFIGURATION,
          category: FindingCategory.CODE_SMELL,
          field: `${field}.${name}`,
          value: `${name}@${version}`,
          confidence: 80,
          remediation: 'Consider publishing the package or using a workspace configuration.'
        });
      }

      // Check for overly permissive version ranges
      if (version === '*' || version === 'latest' || /^>=?\s*0\./.test(version)) {
        this.findings.push({
          type: PackageJsonFindingType.OVERLY_PERMISSIVE_VERSION,
          name: 'Overly Permissive Version',
          description: `Package "${name}" uses "${version}" which could install any version`,
          severity: Severity.MEDIUM,
          threatType: ThreatType.VULNERABLE_DEPENDENCY,
          category: FindingCategory.BEST_PRACTICE,
          field: `${field}.${name}`,
          value: `${name}@${version}`,
          confidence: 85,
          remediation: 'Use a specific version or a caret/tilde range.'
        });
      }
    }
  }

  /**
   * Check for typosquatting against popular packages
   */
  private checkTyposquatting(packageName: string): { target: string; confidence: number } | null {
    const lowerName = packageName.toLowerCase();
    
    // Skip if it's a popular package itself
    if (POPULAR_PACKAGES.includes(lowerName)) {
      return null;
    }

    // Skip scoped packages for now (they're harder to typosquat)
    if (packageName.startsWith('@')) {
      return null;
    }

    for (const popular of POPULAR_PACKAGES) {
      const distance = levenshteinDistance(lowerName, popular.toLowerCase());
      const maxLength = Math.max(lowerName.length, popular.length);
      const similarity = 1 - (distance / maxLength);

      // If very similar but not exact
      if (distance > 0 && distance <= 2 && similarity > 0.8) {
        const confidence = Math.round(similarity * 100);
        return { target: popular, confidence };
      }

      // Check for common typosquatting patterns
      const patterns = [
        `${popular}-js`,
        `${popular}js`,
        `${popular}.js`,
        `js-${popular}`,
        `node-${popular}`,
        `${popular}-node`,
        `${popular}2`,
        `${popular}-v2`,
        popular.replace(/-/g, ''),
        popular.replace(/-/g, '_')
      ];

      for (const pattern of patterns) {
        if (lowerName === pattern.toLowerCase() && lowerName !== popular.toLowerCase()) {
          return { target: popular, confidence: 75 };
        }
      }
    }

    return null;
  }

  /**
   * Check bundled dependencies
   */
  private checkBundledDependencies(bundled: string[]): void {
    if (!Array.isArray(bundled)) return;

    for (const name of bundled) {
      if (typeof name !== 'string') continue;

      // Check for known malicious packages
      if (KNOWN_MALICIOUS_PACKAGES.has(name)) {
        this.findings.push({
          type: PackageJsonFindingType.SUSPICIOUS_DEPENDENCY,
          name: 'Malicious Bundled Dependency',
          description: `Bundled package "${name}" is known to be malicious`,
          severity: Severity.CRITICAL,
          threatType: ThreatType.MALICIOUS_LOADER,
          category: FindingCategory.MALWARE,
          field: 'bundledDependencies',
          value: name,
          confidence: 95,
          remediation: 'Remove this bundled dependency immediately.'
        });
      }
    }
  }

  /**
   * Analyze package metadata for suspicious patterns
   */
  private analyzeMetadata(pkg: Record<string, unknown>): void {
    // Check for suspicious repository URLs
    if (pkg.repository) {
      const repoUrl = typeof pkg.repository === 'string' 
        ? pkg.repository 
        : (pkg.repository as Record<string, string>).url;

      if (repoUrl) {
        // Check for IP-based repository URLs
        if (/https?:\/\/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/.test(repoUrl)) {
          this.findings.push({
            type: PackageJsonFindingType.SUSPICIOUS_DEPENDENCY,
            name: 'IP-Based Repository URL',
            description: 'Repository uses a raw IP address instead of a domain',
            severity: Severity.HIGH,
            threatType: ThreatType.SUSPICIOUS_NETWORK,
            category: FindingCategory.MALWARE,
            field: 'repository',
            value: repoUrl,
            confidence: 75,
            remediation: 'Verify the repository is legitimate.'
          });
        }

        // Check for non-standard git hosts
        const trustedHosts = ['github.com', 'gitlab.com', 'bitbucket.org', 'dev.azure.com'];
        const isStandardHost = trustedHosts.some(host => repoUrl.includes(host));
        if (!isStandardHost && repoUrl.includes('://')) {
          this.findings.push({
            type: PackageJsonFindingType.SUSPICIOUS_DEPENDENCY,
            name: 'Non-Standard Repository Host',
            description: 'Repository is hosted on a non-standard git host',
            severity: Severity.LOW,
            threatType: ThreatType.SECURITY_MISCONFIGURATION,
            category: FindingCategory.CODE_SMELL,
            field: 'repository',
            value: repoUrl,
            confidence: 50,
            remediation: 'Verify the repository host is trustworthy.'
          });
        }
      }
    }

    // Check for very new package (less relevant for static analysis, but worth noting)
    // This would normally require npm API access

    // Check for private registry configuration
    if (pkg.publishConfig && typeof pkg.publishConfig === 'object') {
      const publishConfig = pkg.publishConfig as Record<string, string>;
      if (publishConfig.registry && !publishConfig.registry.includes('registry.npmjs.org')) {
        this.findings.push({
          type: PackageJsonFindingType.PRIVATE_REGISTRY,
          name: 'Private Registry Configuration',
          description: 'Package is configured to publish to a private registry',
          severity: Severity.INFO,
          threatType: ThreatType.SECURITY_MISCONFIGURATION,
          category: FindingCategory.CODE_SMELL,
          field: 'publishConfig.registry',
          value: publishConfig.registry,
          confidence: 60,
          remediation: 'Verify the registry configuration is intentional.'
        });
      }
    }
  }

  /**
   * Check if content looks obfuscated
   */
  private looksObfuscated(content: string): boolean {
    // Check for base64-like patterns
    if (/[A-Za-z0-9+/=]{100,}/.test(content)) return true;
    
    // Check for heavy use of hex escapes
    if (/(?:\\x[0-9a-f]{2}){20,}/i.test(content)) return true;
    
    // Check for unicode escapes
    if (/(?:\\u[0-9a-f]{4}){15,}/i.test(content)) return true;
    
    // Check for very long single-line strings
    if (content.length > 500 && !content.includes(' ') && !content.includes('\n')) return true;

    return false;
  }
}

export default PackageJsonAnalyzer;
