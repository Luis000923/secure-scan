/**
 * JavaScript/TypeScript Security Analyzer v2.0
 * Advanced SAST analyzer with AST-based detection, taint analysis, and malware detection
 * 
 * Features:
 * - AST-based vulnerability detection (Babel Parser)
 * - Taint analysis (source-to-sink tracking)
 * - Malware detection (cryptominers, stealers, backdoors, etc.)
 * - Package.json security analysis
 * - OWASP/CWE compliance
 * 
 * @version 2.0.0
 * @author Secure-Scan Team
 */

import { BaseAnalyzer } from '../base';
import { 
  ScannedFile, 
  Finding, 
  Rule, 
  SupportedLanguage, 
  Severity, 
  ThreatType, 
  FindingCategory,
  SecurityStandard 
} from '../../types';
import { generateId, extractCodeContext, looksObfuscated, calculateEntropy } from '../../utils';
import { getStandardsForThreat } from '../../rules/standards';
import { logger } from '../../utils/logger';

// Import specialized modules
import { TaintAnalyzer, TaintFlow, TAINT_SOURCES, TAINT_SINKS } from './taintAnalyzer';
import { ASTUtils, DangerousCall, DangerousPatternType } from './astUtils';
import { MalwareDetector, MalwareMatch, MalwareType } from './malwareDetector';
import { PackageJsonAnalyzer, PackageJsonFinding } from './packageJsonAnalyzer';

/**
 * Analysis options for the JavaScript Analyzer
 */
export interface JSAnalyzerOptions {
  /** Enable AST-based analysis */
  enableAST?: boolean;
  /** Enable taint analysis */
  enableTaintAnalysis?: boolean;
  /** Enable malware detection */
  enableMalwareDetection?: boolean;
  /** Enable package.json analysis */
  enablePackageAnalysis?: boolean;
  /** Maximum file size to analyze (bytes) */
  maxFileSize?: number;
  /** Timeout per file (ms) */
  fileTimeout?: number;
  /** Minimum confidence to report (0-100) */
  minConfidence?: number;
}

/**
 * Default analyzer options
 */
const DEFAULT_OPTIONS: JSAnalyzerOptions = {
  enableAST: true,
  enableTaintAnalysis: true,
  enableMalwareDetection: true,
  enablePackageAnalysis: true,
  maxFileSize: 5 * 1024 * 1024, // 5MB
  fileTimeout: 30000, // 30 seconds
  minConfidence: 50
};

/**
 * Vulnerability patterns for regex-based fallback detection
 */
interface VulnerabilityPattern {
  id: string;
  name: string;
  pattern: RegExp;
  severity: Severity;
  threatType: ThreatType;
  category: FindingCategory;
  description: string;
  remediation: string;
  confidence: number;
  tags: string[];
}

/**
 * Vulnerability patterns database (regex fallback)
 */
const VULNERABILITY_PATTERNS: VulnerabilityPattern[] = [
  // === CODE EXECUTION ===
  {
    id: 'JS-EXEC-001',
    name: 'eval() Usage',
    pattern: /\beval\s*\(\s*(?!['"`])/g,
    severity: Severity.CRITICAL,
    threatType: ThreatType.COMMAND_INJECTION,
    category: FindingCategory.VULNERABILITY,
    description: 'Use of eval() with dynamic content can lead to code injection.',
    remediation: 'Avoid eval(). Use JSON.parse() for JSON data or safer alternatives.',
    confidence: 85,
    tags: ['injection', 'rce', 'owasp-a03']
  },
  {
    id: 'JS-EXEC-002',
    name: 'Function Constructor',
    pattern: /\bnew\s+Function\s*\(/g,
    severity: Severity.CRITICAL,
    threatType: ThreatType.COMMAND_INJECTION,
    category: FindingCategory.VULNERABILITY,
    description: 'new Function() is equivalent to eval() and can execute arbitrary code.',
    remediation: 'Use predefined functions instead of dynamically creating them.',
    confidence: 85,
    tags: ['injection', 'rce', 'owasp-a03']
  },
  {
    id: 'JS-EXEC-003',
    name: 'setTimeout/setInterval with String',
    pattern: /\bset(?:Timeout|Interval)\s*\(\s*['"`][^'"`]+['"`]/g,
    severity: Severity.HIGH,
    threatType: ThreatType.COMMAND_INJECTION,
    category: FindingCategory.VULNERABILITY,
    description: 'setTimeout/setInterval with string argument acts like eval().',
    remediation: 'Pass a function reference instead of a string.',
    confidence: 80,
    tags: ['injection', 'owasp-a03']
  },

  // === COMMAND INJECTION ===
  {
    id: 'JS-CMD-001',
    name: 'child_process exec()',
    pattern: /(?:child_process\.)?exec\s*\(\s*(?!['"`])/g,
    severity: Severity.CRITICAL,
    threatType: ThreatType.COMMAND_INJECTION,
    category: FindingCategory.VULNERABILITY,
    description: 'exec() with dynamic command string is vulnerable to command injection.',
    remediation: 'Use execFile() with argument array instead of exec().',
    confidence: 80,
    tags: ['injection', 'rce', 'owasp-a03']
  },
  {
    id: 'JS-CMD-002',
    name: 'spawn with shell: true',
    pattern: /spawn\s*\([^)]*shell\s*:\s*true/g,
    severity: Severity.HIGH,
    threatType: ThreatType.COMMAND_INJECTION,
    category: FindingCategory.VULNERABILITY,
    description: 'spawn() with shell option is vulnerable to command injection.',
    remediation: 'Remove shell: true and pass arguments as an array.',
    confidence: 85,
    tags: ['injection', 'rce', 'owasp-a03']
  },

  // === XSS VULNERABILITIES ===
  {
    id: 'JS-XSS-001',
    name: 'innerHTML Assignment',
    pattern: /\.innerHTML\s*=\s*(?!['"`]<)/g,
    severity: Severity.HIGH,
    threatType: ThreatType.XSS,
    category: FindingCategory.VULNERABILITY,
    description: 'Direct innerHTML assignment with dynamic content enables XSS.',
    remediation: 'Use textContent for text, or sanitize with DOMPurify.',
    confidence: 75,
    tags: ['xss', 'dom', 'owasp-a03']
  },
  {
    id: 'JS-XSS-002',
    name: 'document.write()',
    pattern: /document\.write(?:ln)?\s*\(/g,
    severity: Severity.HIGH,
    threatType: ThreatType.XSS,
    category: FindingCategory.VULNERABILITY,
    description: 'document.write() with dynamic content is vulnerable to XSS.',
    remediation: 'Use DOM manipulation methods like createElement() and textContent.',
    confidence: 80,
    tags: ['xss', 'dom', 'owasp-a03']
  },
  {
    id: 'JS-XSS-003',
    name: 'insertAdjacentHTML()',
    pattern: /\.insertAdjacentHTML\s*\(/g,
    severity: Severity.HIGH,
    threatType: ThreatType.XSS,
    category: FindingCategory.VULNERABILITY,
    description: 'insertAdjacentHTML() with unsanitized content enables XSS.',
    remediation: 'Sanitize HTML content with DOMPurify before insertion.',
    confidence: 75,
    tags: ['xss', 'dom', 'owasp-a03']
  },
  {
    id: 'JS-XSS-004',
    name: 'jQuery .html()',
    pattern: /\$\([^)]+\)\.html\s*\(\s*(?!['"`]<)/g,
    severity: Severity.HIGH,
    threatType: ThreatType.XSS,
    category: FindingCategory.VULNERABILITY,
    description: 'jQuery .html() with dynamic content is vulnerable to XSS.',
    remediation: 'Use .text() for text content or sanitize before .html().',
    confidence: 70,
    tags: ['xss', 'jquery', 'owasp-a03']
  },

  // === PROTOTYPE POLLUTION ===
  {
    id: 'JS-PP-001',
    name: '__proto__ Access',
    pattern: /\[['"`]?__proto__['"`]?\]|\.__proto__\b/g,
    severity: Severity.HIGH,
    threatType: ThreatType.DANGEROUS_FUNCTION,
    category: FindingCategory.VULNERABILITY,
    description: 'Direct __proto__ access can lead to prototype pollution.',
    remediation: 'Use Object.create(null) for safe objects or validate keys.',
    confidence: 85,
    tags: ['prototype-pollution', 'owasp-a03']
  },
  {
    id: 'JS-PP-002',
    name: 'Object.prototype Modification',
    pattern: /Object\.prototype\s*\.\s*\w+\s*=/g,
    severity: Severity.HIGH,
    threatType: ThreatType.DANGEROUS_FUNCTION,
    category: FindingCategory.VULNERABILITY,
    description: 'Modifying Object.prototype affects all objects.',
    remediation: 'Avoid modifying built-in prototypes.',
    confidence: 90,
    tags: ['prototype-pollution', 'owasp-a03']
  },
  {
    id: 'JS-PP-003',
    name: 'constructor.prototype Access',
    pattern: /constructor\s*\.\s*prototype/g,
    severity: Severity.MEDIUM,
    threatType: ThreatType.DANGEROUS_FUNCTION,
    category: FindingCategory.VULNERABILITY,
    description: 'Accessing constructor.prototype may indicate prototype pollution.',
    remediation: 'Validate and sanitize any dynamic property access.',
    confidence: 70,
    tags: ['prototype-pollution', 'owasp-a03']
  },

  // === INSECURE RANDOMNESS ===
  {
    id: 'JS-RAND-001',
    name: 'Math.random() for Security',
    pattern: /(?:token|secret|key|password|salt|nonce|iv)\s*[=:]\s*[^;{]*Math\.random/gi,
    severity: Severity.HIGH,
    threatType: ThreatType.WEAK_RANDOM,
    category: FindingCategory.VULNERABILITY,
    description: 'Math.random() is not cryptographically secure.',
    remediation: 'Use crypto.randomBytes() or crypto.getRandomValues().',
    confidence: 80,
    tags: ['crypto', 'random', 'owasp-a02']
  },

  // === HARDCODED CREDENTIALS ===
  {
    id: 'JS-CRED-001',
    name: 'Hardcoded Password',
    pattern: /(?:password|passwd|pwd)\s*[=:]\s*['"`][^'"`]{6,}['"`]/gi,
    severity: Severity.HIGH,
    threatType: ThreatType.HARDCODED_CREDENTIALS,
    category: FindingCategory.VULNERABILITY,
    description: 'Hardcoded password detected in source code.',
    remediation: 'Use environment variables or a secrets manager.',
    confidence: 75,
    tags: ['credentials', 'secrets', 'owasp-a07']
  },
  {
    id: 'JS-CRED-002',
    name: 'Hardcoded API Key',
    pattern: /(?:api[_-]?key|apikey)\s*[=:]\s*['"`][a-zA-Z0-9_-]{20,}['"`]/gi,
    severity: Severity.HIGH,
    threatType: ThreatType.HARDCODED_CREDENTIALS,
    category: FindingCategory.VULNERABILITY,
    description: 'Hardcoded API key detected in source code.',
    remediation: 'Use environment variables or a secrets manager.',
    confidence: 80,
    tags: ['credentials', 'secrets', 'owasp-a07']
  },
  {
    id: 'JS-CRED-003',
    name: 'Hardcoded Secret/Token',
    pattern: /(?:secret|token|auth)\s*[=:]\s*['"`][a-zA-Z0-9_-]{20,}['"`]/gi,
    severity: Severity.HIGH,
    threatType: ThreatType.HARDCODED_CREDENTIALS,
    category: FindingCategory.VULNERABILITY,
    description: 'Hardcoded secret or token detected in source code.',
    remediation: 'Use environment variables or a secrets manager.',
    confidence: 75,
    tags: ['credentials', 'secrets', 'owasp-a07']
  },

  // === INSECURE CRYPTO ===
  {
    id: 'JS-CRYPTO-001',
    name: 'MD5 Usage',
    pattern: /(?:createHash|crypto)\s*\(\s*['"`]md5['"`]\s*\)/gi,
    severity: Severity.MEDIUM,
    threatType: ThreatType.INSECURE_CRYPTO,
    category: FindingCategory.VULNERABILITY,
    description: 'MD5 is cryptographically broken and should not be used.',
    remediation: 'Use SHA-256 or stronger for hashing.',
    confidence: 90,
    tags: ['crypto', 'hash', 'owasp-a02']
  },
  {
    id: 'JS-CRYPTO-002',
    name: 'SHA1 Usage',
    pattern: /(?:createHash|crypto)\s*\(\s*['"`]sha1['"`]\s*\)/gi,
    severity: Severity.MEDIUM,
    threatType: ThreatType.INSECURE_CRYPTO,
    category: FindingCategory.VULNERABILITY,
    description: 'SHA-1 is deprecated for cryptographic use.',
    remediation: 'Use SHA-256 or stronger for hashing.',
    confidence: 85,
    tags: ['crypto', 'hash', 'owasp-a02']
  },
  {
    id: 'JS-CRYPTO-003',
    name: 'DES/3DES Usage',
    pattern: /(?:createCipher|createDecipher)\s*\(\s*['"`](?:des|3des|des-ede3)['"`]/gi,
    severity: Severity.HIGH,
    threatType: ThreatType.INSECURE_CRYPTO,
    category: FindingCategory.VULNERABILITY,
    description: 'DES and 3DES are deprecated encryption algorithms.',
    remediation: 'Use AES-256-GCM for encryption.',
    confidence: 90,
    tags: ['crypto', 'encryption', 'owasp-a02']
  },

  // === PATH TRAVERSAL ===
  {
    id: 'JS-PATH-001',
    name: 'Path Traversal in File Read',
    pattern: /(?:readFile|readFileSync|createReadStream)\s*\([^)]*(?:req\.(?:body|query|params)|process\.argv)/gi,
    severity: Severity.HIGH,
    threatType: ThreatType.PATH_TRAVERSAL,
    category: FindingCategory.VULNERABILITY,
    description: 'File read with user-controlled path enables path traversal.',
    remediation: 'Validate paths with path.resolve() and check against base directory.',
    confidence: 80,
    tags: ['path-traversal', 'file', 'owasp-a01']
  },

  // === SQL INJECTION ===
  {
    id: 'JS-SQL-001',
    name: 'SQL Query Concatenation',
    pattern: /\.query\s*\(\s*['"`](?:SELECT|INSERT|UPDATE|DELETE)[^'"]*\+/gi,
    severity: Severity.CRITICAL,
    threatType: ThreatType.SQL_INJECTION,
    category: FindingCategory.VULNERABILITY,
    description: 'SQL query with string concatenation is vulnerable to injection.',
    remediation: 'Use parameterized queries or prepared statements.',
    confidence: 85,
    tags: ['sqli', 'injection', 'owasp-a03']
  },
  {
    id: 'JS-SQL-002',
    name: 'SQL Template Literal',
    pattern: /\.query\s*\(\s*`(?:SELECT|INSERT|UPDATE|DELETE)[^`]*\$\{/gi,
    severity: Severity.CRITICAL,
    threatType: ThreatType.SQL_INJECTION,
    category: FindingCategory.VULNERABILITY,
    description: 'SQL query with template literal interpolation is vulnerable.',
    remediation: 'Use parameterized queries or prepared statements.',
    confidence: 85,
    tags: ['sqli', 'injection', 'owasp-a03']
  },

  // === SSRF ===
  {
    id: 'JS-SSRF-001',
    name: 'SSRF in fetch()',
    pattern: /fetch\s*\(\s*(?:req\.(?:body|query|params)|`[^`]*\$\{)/gi,
    severity: Severity.HIGH,
    threatType: ThreatType.SECURITY_MISCONFIGURATION,
    category: FindingCategory.VULNERABILITY,
    description: 'fetch() with user-controlled URL enables SSRF attacks.',
    remediation: 'Validate and whitelist URLs before making requests.',
    confidence: 75,
    tags: ['ssrf', 'owasp-a10']
  },

  // === INSECURE CONFIGURATION ===
  {
    id: 'JS-CONFIG-001',
    name: 'CORS Wildcard',
    pattern: /(?:cors|Access-Control-Allow-Origin)\s*[=:]\s*['"*]/gi,
    severity: Severity.MEDIUM,
    threatType: ThreatType.SECURITY_MISCONFIGURATION,
    category: FindingCategory.VULNERABILITY,
    description: 'CORS with wildcard origin allows any domain to access the API.',
    remediation: 'Specify allowed origins explicitly.',
    confidence: 80,
    tags: ['cors', 'config', 'owasp-a05']
  },
  {
    id: 'JS-CONFIG-002',
    name: 'Disabled CSRF Protection',
    pattern: /csrf\s*:\s*false|csrfProtection\s*=\s*false/gi,
    severity: Severity.HIGH,
    threatType: ThreatType.CSRF,
    category: FindingCategory.VULNERABILITY,
    description: 'CSRF protection is explicitly disabled.',
    remediation: 'Enable CSRF protection for state-changing operations.',
    confidence: 90,
    tags: ['csrf', 'config', 'owasp-a05']
  },
  {
    id: 'JS-CONFIG-003',
    name: 'Insecure Cookie Settings',
    pattern: /(?:secure|httpOnly)\s*:\s*false/gi,
    severity: Severity.MEDIUM,
    threatType: ThreatType.SECURITY_MISCONFIGURATION,
    category: FindingCategory.VULNERABILITY,
    description: 'Cookie security flags are explicitly disabled.',
    remediation: 'Set secure: true and httpOnly: true for session cookies.',
    confidence: 85,
    tags: ['cookie', 'config', 'owasp-a05']
  },

  // === POSTMESSAGE VULNERABILITIES ===
  {
    id: 'JS-PM-001',
    name: 'postMessage Wildcard Origin',
    pattern: /postMessage\s*\([^)]+,\s*['"]\*['"]\s*\)/g,
    severity: Severity.MEDIUM,
    threatType: ThreatType.SECURITY_MISCONFIGURATION,
    category: FindingCategory.VULNERABILITY,
    description: 'postMessage with "*" origin can leak data to any origin.',
    remediation: 'Specify the target origin explicitly.',
    confidence: 90,
    tags: ['postmessage', 'origin', 'owasp-a05']
  },
  {
    id: 'JS-PM-002',
    name: 'Missing Origin Check',
    pattern: /addEventListener\s*\(\s*['"`]message['"`][^}]*(?:eval|innerHTML|document\.write)/g,
    severity: Severity.HIGH,
    threatType: ThreatType.XSS,
    category: FindingCategory.VULNERABILITY,
    description: 'Message event handler without origin check enables XSS.',
    remediation: 'Always validate event.origin before processing messages.',
    confidence: 75,
    tags: ['postmessage', 'xss', 'owasp-a03']
  },

  // === DANGEROUS PATTERNS ===
  {
    id: 'JS-DANGER-001',
    name: 'debugger Statement',
    pattern: /\bdebugger\s*;/g,
    severity: Severity.LOW,
    threatType: ThreatType.SECURITY_MISCONFIGURATION,
    category: FindingCategory.CODE_SMELL,
    description: 'debugger statement should be removed in production.',
    remediation: 'Remove debugger statements before deployment.',
    confidence: 100,
    tags: ['debug', 'cleanup']
  },
  {
    id: 'JS-DANGER-002',
    name: 'console.log in Production',
    pattern: /console\.(?:log|debug|trace)\s*\([^)]*(?:password|secret|token|key)/gi,
    severity: Severity.MEDIUM,
    threatType: ThreatType.INFORMATION_DISCLOSURE,
    category: FindingCategory.VULNERABILITY,
    description: 'Logging sensitive data may expose credentials.',
    remediation: 'Remove or redact sensitive data from logs.',
    confidence: 70,
    tags: ['logging', 'secrets', 'owasp-a09']
  }
];

/**
 * JavaScript/TypeScript Analyzer Class v2.0
 */
export class JavaScriptAnalyzer extends BaseAnalyzer {
  name = 'JavaScript Analyzer';
  languages: SupportedLanguage[] = ['javascript', 'typescript'];
  version = '2.0.0';

  // Specialized analyzers
  private taintAnalyzer: TaintAnalyzer;
  private astUtils: ASTUtils;
  private malwareDetector: MalwareDetector;
  private packageJsonAnalyzer: PackageJsonAnalyzer;
  
  // Configuration
  private options: JSAnalyzerOptions;

  constructor(options: JSAnalyzerOptions = {}) {
    super();
    this.options = { ...DEFAULT_OPTIONS, ...options };
    
    // Initialize specialized analyzers
    this.taintAnalyzer = new TaintAnalyzer();
    this.astUtils = new ASTUtils();
    this.malwareDetector = new MalwareDetector();
    this.packageJsonAnalyzer = new PackageJsonAnalyzer();
  }

  /**
   * Initialize the analyzer
   */
  async initialize(): Promise<void> {
    await super.initialize();
    logger.debug('JavaScript Analyzer v2.0 initialized with AST, Taint, and Malware detection');
  }

  /**
   * Main analysis entry point
   */
  async analyze(file: ScannedFile, rules: Rule[]): Promise<Finding[]> {
    const findings: Finding[] = [];
    const startTime = Date.now();

    try {
      // Skip files that are too large
      if (file.size > this.options.maxFileSize!) {
        logger.warn(`Skipping ${file.relativePath}: file too large (${file.size} bytes)`);
        return findings;
      }

      // Filter rules for JS/TS
      const jsRules = rules.filter(r =>
        r.languages.includes('javascript') || r.languages.includes('typescript')
      );

      // Run rule engine (inherited from BaseAnalyzer)
      const ruleFindings = await this.ruleEngine.analyzeFile(file, jsRules);
      findings.push(...ruleFindings);

      // Special handling for package.json
      if (file.relativePath.endsWith('package.json')) {
        const pkgFindings = await this.analyzePackageJson(file);
        findings.push(...pkgFindings);
        return this.filterByConfidence(findings);
      }

      // Run parallel analysis for code files
      const analysisPromises: Promise<Finding[]>[] = [];

      // 1. Pattern-based vulnerability detection (fast, always run)
      analysisPromises.push(this.runPatternAnalysis(file));

      // 2. AST-based analysis (accurate, optional)
      if (this.options.enableAST) {
        analysisPromises.push(this.runASTAnalysis(file));
      }

      // 3. Taint analysis (complex, optional)
      if (this.options.enableTaintAnalysis) {
        analysisPromises.push(this.runTaintAnalysis(file));
      }

      // 4. Malware detection (comprehensive, optional)
      if (this.options.enableMalwareDetection) {
        analysisPromises.push(this.runMalwareAnalysis(file));
      }

      // 5. Obfuscation detection
      analysisPromises.push(this.checkObfuscation(file));

      // Wait for all analyses with timeout
      const results = await Promise.race([
        Promise.all(analysisPromises),
        this.timeout(this.options.fileTimeout!)
      ]) as Finding[][];

      // Flatten results
      for (const result of results) {
        findings.push(...result);
      }

      // Deduplicate findings
      const deduped = this.deduplicateFindings(findings);

      // Filter by confidence
      const filtered = this.filterByConfidence(deduped);

      const elapsed = Date.now() - startTime;
      logger.debug(`Analyzed ${file.relativePath} in ${elapsed}ms, found ${filtered.length} issues`);

      return filtered;

    } catch (error) {
      logger.error(`Error analyzing ${file.relativePath}:`, error);
      return findings;
    }
  }

  /**
   * Run pattern-based vulnerability detection
   */
  private async runPatternAnalysis(file: ScannedFile): Promise<Finding[]> {
    const findings: Finding[] = [];

    for (const vuln of VULNERABILITY_PATTERNS) {
      // Reset regex state
      vuln.pattern.lastIndex = 0;
      
      let match;
      while ((match = vuln.pattern.exec(file.content)) !== null) {
        // Find line number
        const beforeMatch = file.content.substring(0, match.index);
        const lineNum = beforeMatch.split('\n').length;
        
        const context = extractCodeContext(file.content, lineNum, 2);

        findings.push({
          id: generateId(),
          title: vuln.name,
          description: vuln.description,
          severity: vuln.severity,
          threatType: vuln.threatType,
          category: vuln.category,
          location: {
            file: file.relativePath,
            startLine: lineNum,
            endLine: lineNum
          },
          snippet: {
            code: context.code,
            contextBefore: context.contextBefore,
            contextAfter: context.contextAfter
          },
          standards: getStandardsForThreat(vuln.threatType),
          remediation: vuln.remediation,
          confidence: vuln.confidence,
          analyzer: this.name,
          timestamp: new Date(),
          tags: vuln.tags
        });
      }
    }

    return findings;
  }

  /**
   * Run AST-based analysis
   */
  private async runASTAnalysis(file: ScannedFile): Promise<Finding[]> {
    const findings: Finding[] = [];

    try {
      // Parse the file
      const ast = this.astUtils.safeParse(file.content, file.relativePath);
      if (!ast) {
        logger.debug(`Could not parse ${file.relativePath} for AST analysis`);
        return findings;
      }

      // Find dangerous calls
      const dangerousCalls = this.astUtils.findDangerousCalls(file.relativePath);
      for (const call of dangerousCalls) {
        findings.push(this.dangerousCallToFinding(call, file));
      }

      // Find hardcoded secrets
      const secrets = this.astUtils.findHardcodedSecrets();
      for (const secret of secrets) {
        findings.push(this.dangerousCallToFinding(secret, file));
      }

      // Find dangerous regex patterns
      const regexIssues = this.astUtils.findDangerousRegex();
      for (const regex of regexIssues) {
        findings.push(this.dangerousCallToFinding(regex, file));
      }

    } catch (error) {
      logger.debug(`AST analysis failed for ${file.relativePath}:`, error);
    }

    return findings;
  }

  /**
   * Run taint analysis
   */
  private async runTaintAnalysis(file: ScannedFile): Promise<Finding[]> {
    const findings: Finding[] = [];

    try {
      const flows = this.taintAnalyzer.analyze(file.content, file.relativePath);
      
      for (const flow of flows) {
        findings.push(this.taintFlowToFinding(flow, file));
      }
    } catch (error) {
      logger.debug(`Taint analysis failed for ${file.relativePath}:`, error);
    }

    return findings;
  }

  /**
   * Run malware detection
   */
  private async runMalwareAnalysis(file: ScannedFile): Promise<Finding[]> {
    const findings: Finding[] = [];

    try {
      const matches = this.malwareDetector.scan(file.content, file.relativePath);
      
      for (const match of matches) {
        findings.push(this.malwareMatchToFinding(match, file));
      }
    } catch (error) {
      logger.debug(`Malware analysis failed for ${file.relativePath}:`, error);
    }

    return findings;
  }

  /**
   * Analyze package.json for security issues
   */
  private async analyzePackageJson(file: ScannedFile): Promise<Finding[]> {
    const findings: Finding[] = [];

    if (!this.options.enablePackageAnalysis) {
      return findings;
    }

    try {
      const pkgFindings = this.packageJsonAnalyzer.analyze(file.content, file.relativePath);
      
      for (const finding of pkgFindings) {
        findings.push(this.packageFindingToFinding(finding, file));
      }
    } catch (error) {
      logger.debug(`Package.json analysis failed for ${file.relativePath}:`, error);
    }

    return findings;
  }

  /**
   * Check for obfuscated code
   */
  private async checkObfuscation(file: ScannedFile): Promise<Finding[]> {
    const findings: Finding[] = [];

    if (looksObfuscated(file.content)) {
      const entropy = calculateEntropy(file.content);
      
      findings.push({
        id: generateId(),
        title: 'Heavily Obfuscated Code',
        description: `This file contains heavily obfuscated code (entropy: ${entropy.toFixed(2)}). This is unusual for legitimate code and may hide malicious functionality.`,
        severity: Severity.HIGH,
        threatType: ThreatType.OBFUSCATED_CODE,
        category: FindingCategory.MALWARE,
        location: {
          file: file.relativePath,
          startLine: 1,
          endLine: Math.min(10, file.lineCount)
        },
        snippet: {
          code: file.content.substring(0, 200) + '...'
        },
        standards: getStandardsForThreat(ThreatType.OBFUSCATED_CODE),
        remediation: 'Deobfuscate and review the code. If this is a third-party library, verify its source and integrity.',
        confidence: 75,
        analyzer: this.name,
        timestamp: new Date(),
        tags: ['obfuscation', 'suspicious']
      });
    }

    return findings;
  }

  /**
   * Convert DangerousCall to Finding
   */
  private dangerousCallToFinding(call: DangerousCall, file: ScannedFile): Finding {
    const threatTypeMap: Record<DangerousPatternType, ThreatType> = {
      [DangerousPatternType.CODE_EXECUTION]: ThreatType.COMMAND_INJECTION,
      [DangerousPatternType.COMMAND_INJECTION]: ThreatType.COMMAND_INJECTION,
      [DangerousPatternType.PROTOTYPE_POLLUTION]: ThreatType.DANGEROUS_FUNCTION,
      [DangerousPatternType.XSS_SINK]: ThreatType.XSS,
      [DangerousPatternType.DYNAMIC_REQUIRE]: ThreatType.DANGEROUS_FUNCTION,
      [DangerousPatternType.INSECURE_RANDOM]: ThreatType.WEAK_RANDOM,
      [DangerousPatternType.HARDCODED_SECRET]: ThreatType.HARDCODED_CREDENTIALS,
      [DangerousPatternType.DANGEROUS_REGEX]: ThreatType.DANGEROUS_FUNCTION,
      [DangerousPatternType.UNSAFE_ASSIGNMENT]: ThreatType.DANGEROUS_FUNCTION,
      [DangerousPatternType.NETWORK_REQUEST]: ThreatType.SUSPICIOUS_NETWORK,
      [DangerousPatternType.FILE_OPERATION]: ThreatType.PATH_TRAVERSAL,
      [DangerousPatternType.CRYPTO_WEAKNESS]: ThreatType.INSECURE_CRYPTO
    };

    const severityMap: Record<DangerousPatternType, Severity> = {
      [DangerousPatternType.CODE_EXECUTION]: Severity.CRITICAL,
      [DangerousPatternType.COMMAND_INJECTION]: Severity.CRITICAL,
      [DangerousPatternType.PROTOTYPE_POLLUTION]: Severity.HIGH,
      [DangerousPatternType.XSS_SINK]: Severity.HIGH,
      [DangerousPatternType.DYNAMIC_REQUIRE]: Severity.MEDIUM,
      [DangerousPatternType.INSECURE_RANDOM]: Severity.MEDIUM,
      [DangerousPatternType.HARDCODED_SECRET]: Severity.HIGH,
      [DangerousPatternType.DANGEROUS_REGEX]: Severity.MEDIUM,
      [DangerousPatternType.UNSAFE_ASSIGNMENT]: Severity.MEDIUM,
      [DangerousPatternType.NETWORK_REQUEST]: Severity.MEDIUM,
      [DangerousPatternType.FILE_OPERATION]: Severity.MEDIUM,
      [DangerousPatternType.CRYPTO_WEAKNESS]: Severity.MEDIUM
    };

    const context = extractCodeContext(file.content, call.location.startLine, 2);

    return {
      id: generateId(),
      title: `AST: ${call.name}`,
      description: call.context || `Dangerous ${call.patternType.replace(/_/g, ' ')} detected via AST analysis`,
      severity: severityMap[call.patternType] || Severity.MEDIUM,
      threatType: threatTypeMap[call.patternType] || ThreatType.DANGEROUS_FUNCTION,
      category: FindingCategory.VULNERABILITY,
      location: {
        file: file.relativePath,
        startLine: call.location.startLine,
        endLine: call.location.endLine,
        startColumn: call.location.startColumn,
        endColumn: call.location.endColumn
      },
      snippet: {
        code: call.code,
        contextBefore: context.contextBefore,
        contextAfter: context.contextAfter
      },
      standards: getStandardsForThreat(threatTypeMap[call.patternType] || ThreatType.DANGEROUS_FUNCTION),
      remediation: 'Review and fix the identified security issue.',
      confidence: 85,
      analyzer: `${this.name} (AST)`,
      timestamp: new Date(),
      tags: ['ast', call.patternType]
    };
  }

  /**
   * Convert TaintFlow to Finding
   */
  private taintFlowToFinding(flow: TaintFlow, file: ScannedFile): Finding {
    const sourceDesc = TaintAnalyzer.getSourceDescription(flow.source.type);
    const sinkInfo = TaintAnalyzer.getSinkInfo(flow.sink.type);
    
    const context = extractCodeContext(file.content, flow.sink.line, 2);

    // Build detailed description with flow path
    let description = `Tainted data from ${sourceDesc} flows to ${flow.sink.type} sink.`;
    if (flow.propagation.length > 0) {
      description += ` The data passes through ${flow.propagation.length} intermediate assignments.`;
    }

    return {
      id: generateId(),
      title: `Taint Flow: ${flow.source.type} → ${flow.sink.type}`,
      description,
      severity: flow.sink.severity,
      threatType: flow.sink.threatType,
      category: FindingCategory.VULNERABILITY,
      location: {
        file: file.relativePath,
        startLine: flow.sink.line,
        endLine: flow.sink.line
      },
      snippet: {
        code: flow.sink.code,
        contextBefore: context.contextBefore,
        contextAfter: context.contextAfter
      },
      standards: getStandardsForThreat(flow.sink.threatType),
      remediation: sinkInfo?.remediation || 'Validate and sanitize all user input before use.',
      confidence: flow.confidence,
      analyzer: `${this.name} (Taint)`,
      timestamp: new Date(),
      tags: ['taint-analysis', flow.source.type, flow.sink.type]
    };
  }

  /**
   * Convert MalwareMatch to Finding
   */
  private malwareMatchToFinding(match: MalwareMatch, file: ScannedFile): Finding {
    const context = extractCodeContext(file.content, match.line, 2);

    return {
      id: generateId(),
      title: `Malware: ${match.name}`,
      description: match.description,
      severity: match.severity,
      threatType: MalwareDetector.getThreatType(match.type),
      category: FindingCategory.MALWARE,
      location: {
        file: file.relativePath,
        startLine: match.line,
        endLine: match.line
      },
      snippet: {
        code: match.code,
        contextBefore: context.contextBefore,
        contextAfter: context.contextAfter
      },
      standards: getStandardsForThreat(MalwareDetector.getThreatType(match.type)),
      remediation: match.remediation,
      confidence: match.confidence,
      analyzer: `${this.name} (Malware)`,
      timestamp: new Date(),
      tags: ['malware', match.type, ...(match.mitreAttack || [])]
    };
  }

  /**
   * Convert PackageJsonFinding to Finding
   */
  private packageFindingToFinding(pkgFinding: PackageJsonFinding, file: ScannedFile): Finding {
    return {
      id: generateId(),
      title: pkgFinding.name,
      description: pkgFinding.description,
      severity: pkgFinding.severity,
      threatType: pkgFinding.threatType,
      category: pkgFinding.category,
      location: {
        file: file.relativePath,
        startLine: 1,
        endLine: 1
      },
      snippet: {
        code: `"${pkgFinding.field}": "${pkgFinding.value.substring(0, 100)}"`
      },
      standards: getStandardsForThreat(pkgFinding.threatType),
      remediation: pkgFinding.remediation,
      confidence: pkgFinding.confidence,
      analyzer: `${this.name} (Package)`,
      timestamp: new Date(),
      tags: ['package-json', pkgFinding.type]
    };
  }

  /**
   * Deduplicate findings based on location and type
   */
  private deduplicateFindings(findings: Finding[]): Finding[] {
    const seen = new Map<string, Finding>();
    
    for (const finding of findings) {
      const key = `${finding.location.file}:${finding.location.startLine}:${finding.threatType}`;
      
      if (!seen.has(key)) {
        seen.set(key, finding);
      } else {
        // Keep the one with higher confidence
        const existing = seen.get(key)!;
        if (finding.confidence > existing.confidence) {
          seen.set(key, finding);
        }
      }
    }
    
    return Array.from(seen.values());
  }

  /**
   * Filter findings by minimum confidence
   */
  private filterByConfidence(findings: Finding[]): Finding[] {
    return findings.filter(f => f.confidence >= this.options.minConfidence!);
  }

  /**
   * Create a timeout promise
   */
  private timeout(ms: number): Promise<Finding[][]> {
    return new Promise((_, reject) => {
      setTimeout(() => reject(new Error('Analysis timeout')), ms);
    });
  }
}

export default JavaScriptAnalyzer;
