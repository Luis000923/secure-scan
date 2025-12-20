/**
 * Tipos principales para Secure-Scan SAST
 * Definiciones de tipos para análisis de seguridad
 */

/**
 * Lenguajes de programación soportados para análisis
 */
export type SupportedLanguage = 
  | 'javascript'
  | 'typescript'
  | 'python'
  | 'php'
  | 'java'
  | 'c'
  | 'cpp'
  | 'csharp'
  | 'dockerfile'
  | 'yaml'
  | 'terraform';

/**
 * Severity levels for findings
 */
export enum Severity {
  INFO = 'info',
  LOW = 'low',
  MEDIUM = 'medium',
  HIGH = 'high',
  CRITICAL = 'critical'
}

/**
 * Security standard references
 */
export interface SecurityStandard {
  /** Standard name (OWASP, CWE, MITRE, SANS) */
  name: 'OWASP' | 'CWE' | 'MITRE' | 'SANS';
  /** Standard ID (e.g., CWE-79, A01:2021) */
  id: string;
  /** Standard title */
  title: string;
  /** Standard description */
  description: string;
  /** URL to standard documentation */
  url?: string;
}

/**
 * Type of threat detected
 */
export enum ThreatType {
  // Vulnerabilities
  SQL_INJECTION = 'sql_injection',
  COMMAND_INJECTION = 'command_injection',
  XSS = 'xss',
  CSRF = 'csrf',
  INSECURE_DESERIALIZATION = 'insecure_deserialization',
  HARDCODED_CREDENTIALS = 'hardcoded_credentials',
  PATH_TRAVERSAL = 'path_traversal',
  LDAP_INJECTION = 'ldap_injection',
  INSECURE_CRYPTO = 'insecure_crypto',
  WEAK_RANDOM = 'weak_random',
  DANGEROUS_FUNCTION = 'dangerous_function',
  VULNERABLE_DEPENDENCY = 'vulnerable_dependency',
  INFORMATION_DISCLOSURE = 'information_disclosure',
  BROKEN_ACCESS_CONTROL = 'broken_access_control',
  SECURITY_MISCONFIGURATION = 'security_misconfiguration',
  
  // Malware
  BACKDOOR = 'backdoor',
  KEYLOGGER = 'keylogger',
  CRYPTOMINER = 'cryptominer',
  OBFUSCATED_CODE = 'obfuscated_code',
  EMBEDDED_PAYLOAD = 'embedded_payload',
  REVERSE_SHELL = 'reverse_shell',
  DATA_EXFILTRATION = 'data_exfiltration',
  SUSPICIOUS_NETWORK = 'suspicious_network',
  MALICIOUS_LOADER = 'malicious_loader'
}

/**
 * Category of finding
 */
export enum FindingCategory {
  VULNERABILITY = 'vulnerability',
  MALWARE = 'malware',
  CODE_SMELL = 'code_smell',
  BEST_PRACTICE = 'best_practice'
}

/**
 * Source location in code
 */
export interface SourceLocation {
  /** File path relative to project root */
  file: string;
  /** Start line number (1-indexed) */
  startLine: number;
  /** End line number (1-indexed) */
  endLine: number;
  /** Start column (optional) */
  startColumn?: number;
  /** End column (optional) */
  endColumn?: number;
}

/**
 * Code snippet with context
 */
export interface CodeSnippet {
  /** The vulnerable/malicious code */
  code: string;
  /** Lines before for context */
  contextBefore?: string;
  /** Lines after for context */
  contextAfter?: string;
  /** Highlighted portion */
  highlight?: {
    start: number;
    end: number;
  };
}

/**
 * Security finding from analysis
 */
export interface Finding {
  /** Unique finding ID */
  id: string;
  /** Finding title */
  title: string;
  /** Detailed description */
  description: string;
  /** Severity level */
  severity: Severity;
  /** Type of threat */
  threatType: ThreatType;
  /** Category of finding */
  category: FindingCategory;
  /** Source location */
  location: SourceLocation;
  /** Code snippet */
  snippet: CodeSnippet;
  /** Related security standards */
  standards: SecurityStandard[];
  /** Remediation advice */
  remediation: string;
  /** Confidence level (0-100) */
  confidence: number;
  /** Detected by which analyzer */
  analyzer: string;
  /** Detection timestamp */
  timestamp: Date;
  /** Tags for categorization */
  tags: string[];
  /** AI-generated explanation (if available) */
  aiExplanation?: string;
  /** Suggested fix (if available) */
  suggestedFix?: string;
}

/**
 * File information for scanning
 */
export interface ScannedFile {
  /** Absolute file path */
  absolutePath: string;
  /** Relative path from project root */
  relativePath: string;
  /** File extension */
  extension: string;
  /** Detected language */
  language: SupportedLanguage | null;
  /** File size in bytes */
  size: number;
  /** File content */
  content: string;
  /** Line count */
  lineCount: number;
  /** SHA256 hash of content */
  hash: string;
}

/**
 * Scan statistics
 */
export interface ScanStats {
  /** Total files scanned */
  totalFiles: number;
  /** Total lines of code */
  totalLines: number;
  /** Files by language */
  filesByLanguage: Record<string, number>;
  /** Findings by severity */
  findingsBySeverity: Record<Severity, number>;
  /** Findings by category */
  findingsByCategory: Record<FindingCategory, number>;
  /** Scan duration in milliseconds */
  duration: number;
  /** Scan start time */
  startTime: Date;
  /** Scan end time */
  endTime: Date;
}

/**
 * Complete scan result
 */
export interface ScanResult {
  /** Project path */
  projectPath: string;
  /** Project name */
  projectName: string;
  /** Scan ID */
  scanId: string;
  /** All findings */
  findings: Finding[];
  /** Scan statistics */
  stats: ScanStats;
  /** Risk score (0-100) */
  riskScore: number;
  /** Risk level */
  riskLevel: 'safe' | 'low' | 'medium' | 'high' | 'critical';
  /** Scanned files */
  scannedFiles: ScannedFile[];
  /** Configuration used */
  config: ScanConfig;
}

/**
 * Scan configuration
 */
export interface ScanConfig {
  /** Project path to scan */
  projectPath: string;
  /** Output file path */
  outputPath?: string;
  /** Languages to analyze */
  languages?: SupportedLanguage[];
  /** Patterns to exclude */
  exclude?: string[];
  /** Minimum severity to report */
  minSeverity?: Severity;
  /** Enable AI analysis */
  useAI?: boolean;
  /** AI provider configuration */
  aiConfig?: AIConfig;
  /** Verbose output */
  verbose?: boolean;
  /** Custom rules */
  customRules?: string[];
  /** Disabled rules */
  disabledRules?: string[];
  /** Maximum file size to scan (bytes) */
  maxFileSize?: number;
  /** Timeout per file (ms) */
  fileTimeout?: number;
  /** Report language (es = Spanish, en = English) */
  language?: 'es' | 'en';
}

/**
 * AI configuration
 */
export interface AIConfig {
  /** AI provider (auto-detected if not specified) */
  provider: 'openai' | 'anthropic' | 'google' | 'gemini' | 'local' | 'auto';
  /** API key */
  apiKey?: string;
  /** Model to use */
  model?: string;
  /** API endpoint (for local models) */
  endpoint?: string;
  /** Max tokens per request */
  maxTokens?: number;
  /** Temperature for generation */
  temperature?: number;
}

/**
 * Rule definition for detection
 */
export interface Rule {
  /** Unique rule ID */
  id: string;
  /** Rule name */
  name: string;
  /** Rule description */
  description: string;
  /** Languages this rule applies to */
  languages: SupportedLanguage[];
  /** Threat type this rule detects */
  threatType: ThreatType;
  /** Category */
  category: FindingCategory;
  /** Default severity */
  severity: Severity;
  /** Related standards */
  standards: SecurityStandard[];
  /** Detection patterns */
  patterns: RulePattern[];
  /** Remediation template */
  remediation: string;
  /** Is rule enabled by default */
  enabled: boolean;
  /** Tags */
  tags: string[];
}

/**
 * Pattern for rule matching
 */
export interface RulePattern {
  /** Pattern type */
  type: 'regex' | 'ast' | 'semantic';
  /** Pattern value */
  pattern: string;
  /** Pattern flags */
  flags?: string;
  /** Additional conditions */
  conditions?: PatternCondition[];
}

/**
 * Condition for pattern matching
 */
export interface PatternCondition {
  /** Condition type */
  type: 'context' | 'scope' | 'dataflow';
  /** Condition value */
  value: string;
  /** Is negated */
  negated?: boolean;
}

/**
 * Analyzer plugin interface
 */
export interface Analyzer {
  /** Analyzer name */
  name: string;
  /** Supported languages */
  languages: SupportedLanguage[];
  /** Analyzer version */
  version: string;
  /** Initialize analyzer */
  initialize(): Promise<void>;
  /** Analyze a file */
  analyze(file: ScannedFile, rules: Rule[]): Promise<Finding[]>;
  /** Cleanup resources */
  cleanup(): Promise<void>;
}

/**
 * Report generator interface
 */
export interface ReportGenerator {
  /** Generator name */
  name: string;
  /** Output format */
  format: 'html' | 'json' | 'pdf' | 'sarif';
  /** Generate report */
  generate(result: ScanResult): Promise<string>;
}
