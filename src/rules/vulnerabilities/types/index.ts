/**
 * @fileoverview Vulnerability Detection Module - Type Definitions
 * @module rules/vulnerabilities/types
 * 
 * Comprehensive type definitions for the vulnerability detection engine.
 * Supports multi-language analysis, AST-aware detection, taint analysis,
 * and enterprise-level reporting with OWASP/CWE/SANS/MITRE mappings.
 */

// ============================================================================
// ENUMERATIONS
// ============================================================================

/**
 * Supported programming languages for vulnerability detection
 */
export enum SupportedLanguage {
  JAVASCRIPT = 'javascript',
  TYPESCRIPT = 'typescript',
  PYTHON = 'python',
  PHP = 'php',
  C = 'c',
  CPP = 'cpp',
  CSHARP = 'csharp',
  JAVA = 'java',
  RUBY = 'ruby',
  GO = 'go',
  RUST = 'rust',
  SHELL = 'shell',
  POWERSHELL = 'powershell',
  DOCKERFILE = 'dockerfile',
  YAML = 'yaml',
  TERRAFORM = 'terraform'
}

/**
 * Vulnerability categories based on OWASP classification
 */
export enum VulnerabilityCategory {
  INJECTION = 'injection',
  XSS = 'xss',
  AUTHENTICATION = 'authentication',
  SESSION_MANAGEMENT = 'session_management',
  ACCESS_CONTROL = 'access_control',
  BROKEN_ACCESS_CONTROL = 'broken_access_control',
  CRYPTOGRAPHY = 'cryptography',
  CRYPTOGRAPHIC_FAILURE = 'cryptographic_failure',
  DESERIALIZATION = 'deserialization',
  FILE_HANDLING = 'file_handling',
  CONFIGURATION = 'configuration',
  SECURITY_MISCONFIGURATION = 'security_misconfiguration',
  INFORMATION_DISCLOSURE = 'information_disclosure',
  SENSITIVE_DATA_EXPOSURE = 'sensitive_data_exposure',
  INPUT_VALIDATION = 'input_validation',
  INFRASTRUCTURE = 'infrastructure',
  KNOWN_VULNERABLE_COMPONENT = 'known_vulnerable_component'
}

/**
 * Specific vulnerability types
 */
export enum VulnerabilityType {
  // Injection
  SQL_INJECTION = 'sql_injection',
  NOSQL_INJECTION = 'nosql_injection',
  COMMAND_INJECTION = 'command_injection',
  CODE_INJECTION = 'code_injection',
  LDAP_INJECTION = 'ldap_injection',
  XPATH_INJECTION = 'xpath_injection',
  TEMPLATE_INJECTION = 'template_injection',
  HEADER_INJECTION = 'header_injection',
  
  // XSS
  XSS_REFLECTED = 'xss_reflected',
  XSS_STORED = 'xss_stored',
  XSS_DOM = 'xss_dom',
  
  // Request Forgery
  CSRF = 'csrf',
  SSRF = 'ssrf',
  
  // Deserialization
  INSECURE_DESERIALIZATION = 'insecure_deserialization',
  PROTOTYPE_POLLUTION = 'prototype_pollution',
  
  // File Handling
  PATH_TRAVERSAL = 'path_traversal',
  UNSAFE_FILE_UPLOAD = 'unsafe_file_upload',
  FILE_UPLOAD = 'file_upload',
  ARBITRARY_FILE_READ = 'arbitrary_file_read',
  ARBITRARY_FILE_WRITE = 'arbitrary_file_write',
  
  // Authentication & Session
  INSECURE_AUTHENTICATION = 'insecure_authentication',
  BROKEN_AUTHENTICATION = 'broken_authentication',
  BROKEN_SESSION = 'broken_session',
  HARDCODED_CREDENTIALS = 'hardcoded_credentials',
  HARDCODED_SECRETS = 'hardcoded_secrets',
  WEAK_PASSWORD_POLICY = 'weak_password_policy',
  
  // Cryptography
  WEAK_CRYPTO = 'weak_crypto',
  WEAK_RANDOM = 'weak_random',
  INSECURE_TLS = 'insecure_tls',
  MISSING_ENCRYPTION = 'missing_encryption',
  
  // Access Control
  BROKEN_ACCESS_CONTROL = 'broken_access_control',
  IDOR = 'idor',
  PRIVILEGE_ESCALATION = 'privilege_escalation',
  
  // Information Disclosure
  INFORMATION_EXPOSURE = 'information_exposure',
  ERROR_DISCLOSURE = 'error_disclosure',
  DEBUG_ENABLED = 'debug_enabled',
  
  // Configuration
  SECURITY_MISCONFIGURATION = 'security_misconfiguration',
  CORS_MISCONFIGURATION = 'cors_misconfiguration',
  INSECURE_HEADERS = 'insecure_headers',
  DANGEROUS_FUNCTION = 'dangerous_function',
  
  // Infrastructure
  DOCKERFILE_ISSUE = 'dockerfile_issue',
  CICD_VULNERABILITY = 'cicd_vulnerability',
  IaC_ISSUE = 'iac_issue'
}

/**
 * Severity levels for vulnerability findings
 */
export enum VulnerabilitySeverity {
  CRITICAL = 'critical',    // Immediate exploitation risk
  HIGH = 'high',            // Serious vulnerability
  MEDIUM = 'medium',        // Moderate risk
  LOW = 'low',              // Minor concern
  INFO = 'info'             // Informational only
}

/**
 * Confidence level of the detection
 */
export enum ConfidenceLevel {
  CONFIRMED = 'confirmed',  // 95%+ certainty, verified taint flow
  HIGH = 'high',            // 80-95% certainty
  MEDIUM = 'medium',        // 60-80% certainty
  LOW = 'low',              // 40-60% certainty
  TENTATIVE = 'tentative'   // <40% certainty
}

/**
 * Pattern matching strategies
 */
export enum PatternType {
  REGEX = 'regex',
  LITERAL = 'literal',
  AST = 'ast',
  SEMANTIC = 'semantic',
  TAINT = 'taint',
  CFG = 'cfg'
}

/**
 * Taint flow stages
 */
export enum TaintStage {
  SOURCE = 'source',
  PROPAGATION = 'propagation',
  SANITIZER = 'sanitizer',
  SINK = 'sink'
}

// ============================================================================
// SECURITY STANDARDS REFERENCES
// ============================================================================

/**
 * OWASP Top 10 reference
 */
export interface OwaspReference {
  /** OWASP ID (e.g., A03:2021) */
  id: string;
  /** Category name */
  name: string;
  /** URL to OWASP documentation */
  url?: string;
}

/**
 * CWE reference
 */
export interface CweReference {
  /** CWE ID (e.g., CWE-79) */
  id: string;
  /** CWE title */
  title: string;
  /** URL to CWE documentation */
  url?: string;
}

/**
 * SANS Top 25 reference
 */
export interface SansReference {
  /** SANS ranking (1-25) */
  rank: number;
  /** Associated CWE ID */
  cweId: string;
  /** Category name */
  category: string;
}

/**
 * MITRE ATT&CK reference
 */
export interface MitreReference {
  /** Tactic ID (e.g., TA0001) */
  tacticId: string;
  /** Tactic name */
  tacticName: string;
  /** Technique ID (e.g., T1059) */
  techniqueId: string;
  /** Technique name */
  techniqueName: string;
  /** Sub-technique ID if applicable */
  subTechniqueId?: string;
  /** URL to MITRE documentation */
  url?: string;
}

/**
 * CVE reference
 */
export interface CveReference {
  /** CVE ID (e.g., CVE-2021-44228) */
  cveId: string;
  /** Brief description */
  description: string;
  /** CVSS score if available */
  cvssScore?: number;
  /** URL to CVE details */
  url?: string;
}

/**
 * Combined security standards for a vulnerability
 */
export interface SecurityStandards {
  owasp?: OwaspReference[];
  cwe?: CweReference[];
  sans?: SansReference[];
  mitre?: MitreReference[];
  cve?: CveReference[];
}

// ============================================================================
// PATTERN INTERFACES
// ============================================================================

/**
 * Base pattern definition
 */
export interface VulnerabilityPatternBase {
  /** Pattern type */
  type: PatternType;
  /** Pattern identifier for reference */
  patternId?: string;
  /** Languages this pattern applies to (empty = all) */
  languages?: SupportedLanguage[];
  /** Weight for scoring (0.0 - 1.0) */
  weight?: number;
  /** Description of what this pattern detects */
  description?: string;
}

/**
 * Regex-based pattern
 */
export interface RegexPattern extends VulnerabilityPatternBase {
  type: PatternType.REGEX;
  /** The regex pattern string */
  pattern: string;
  /** Regex flags (g, i, m, s, u) */
  flags?: string;
  /** Maximum execution time in ms (ReDoS protection) */
  timeout?: number;
  /** Maximum matches before stopping */
  maxMatches?: number;
}

/**
 * Literal string pattern
 */
export interface LiteralPattern extends VulnerabilityPatternBase {
  type: PatternType.LITERAL;
  /** The literal string to match */
  value: string;
  /** Case sensitive matching */
  caseSensitive?: boolean;
}

/**
 * AST-based pattern for structural matching
 */
export interface AstPattern extends VulnerabilityPatternBase {
  type: PatternType.AST;
  /** AST node type to match */
  nodeType: string;
  /** Properties to match on the node */
  properties?: Record<string, unknown>;
  /** Child patterns to match */
  children?: AstPattern[];
  /** Parent context requirements */
  parentContext?: string[];
}

/**
 * Taint analysis pattern
 */
export interface TaintPattern extends VulnerabilityPatternBase {
  type: PatternType.TAINT;
  /** Taint sources */
  sources: TaintSource[];
  /** Taint sinks */
  sinks: TaintSink[];
  /** Optional sanitizers that break the taint */
  sanitizers?: TaintSanitizer[];
  /** Required flow path */
  requiredPath?: string[];
}

/**
 * Semantic pattern for meaning-based matching
 */
export interface SemanticPattern extends VulnerabilityPatternBase {
  type: PatternType.SEMANTIC;
  /** Semantic concept to detect */
  concept: string;
  /** Required data flows */
  dataFlows?: string[];
}

/**
 * Control flow graph pattern
 */
export interface CfgPattern extends VulnerabilityPatternBase {
  type: PatternType.CFG;
  /** Entry point condition */
  entryCondition: string;
  /** Required path conditions */
  pathConditions?: string[];
  /** Exit point condition */
  exitCondition: string;
}

/**
 * Union type for all pattern types
 */
export type VulnerabilityPattern =
  | RegexPattern
  | LiteralPattern
  | AstPattern
  | TaintPattern
  | SemanticPattern
  | CfgPattern;

// ============================================================================
// TAINT ANALYSIS DEFINITIONS
// ============================================================================

/**
 * Taint source definition
 */
export interface TaintSource {
  /** Source identifier */
  id: string;
  /** Source name (e.g., req.body, $_GET) */
  name: string;
  /** Pattern to match the source */
  pattern: string | RegExp;
  /** Languages this source applies to */
  languages?: SupportedLanguage[];
  /** Trust level (0-100, lower = less trusted) */
  trustLevel?: number;
  /** Source category */
  category?: 'user_input' | 'environment' | 'database' | 'network' | 'file';
}

/**
 * Taint sink definition
 */
export interface TaintSink {
  /** Sink identifier */
  id: string;
  /** Sink name (e.g., exec, innerHTML) */
  name: string;
  /** Pattern to match the sink */
  pattern: string | RegExp;
  /** Languages this sink applies to */
  languages?: SupportedLanguage[];
  /** Vulnerability type this sink can cause */
  vulnerabilityType: VulnerabilityType;
  /** Arguments that are dangerous (0-indexed) */
  dangerousArgs?: number[];
}

/**
 * Taint sanitizer definition
 */
export interface TaintSanitizer {
  /** Sanitizer identifier */
  id: string;
  /** Sanitizer name */
  name: string;
  /** Pattern to match the sanitizer */
  pattern: string | RegExp;
  /** Languages this sanitizer applies to */
  languages?: SupportedLanguage[];
  /** Vulnerability types this sanitizer protects against */
  protectsAgainst: VulnerabilityType[];
  /** Effectiveness (0-100) */
  effectiveness?: number;
}

/**
 * Detected taint flow
 */
export interface TaintFlow {
  /** Source of the taint */
  source: TaintSource;
  /** Sink where taint reaches */
  sink: TaintSink;
  /** Propagation path */
  path: TaintPathNode[];
  /** Applied sanitizers */
  sanitizers: TaintSanitizer[];
  /** Is the flow exploitable */
  isExploitable: boolean;
  /** Confidence of the flow detection */
  confidence: ConfidenceLevel;
}

/**
 * Node in taint propagation path
 */
export interface TaintPathNode {
  /** Variable or expression name */
  name: string;
  /** Location in source */
  location: SourceLocation;
  /** Operation performed */
  operation?: string;
}

// ============================================================================
// RULE DEFINITION
// ============================================================================

/**
 * Example code for documentation
 */
export interface CodeExample {
  /** The example code */
  code: string;
  /** Language of the example */
  language: SupportedLanguage;
  /** Whether this is a vulnerable example */
  isVulnerable: boolean;
  /** Description of the example */
  description: string;
  /** If safe, explanation of why */
  safetyExplanation?: string;
}

/**
 * Impact assessment following CVSS-like scoring
 */
export interface ImpactAssessment {
  /** Confidentiality impact (none, low, medium, high) */
  confidentiality: 'none' | 'low' | 'medium' | 'high';
  /** Integrity impact (none, low, medium, high) */
  integrity: 'none' | 'low' | 'medium' | 'high';
  /** Availability impact (none, low, medium, high) */
  availability: 'none' | 'low' | 'medium' | 'high';
  /** Scope (unchanged, changed) */
  scope?: 'unchanged' | 'changed';
  /** Technical impact description */
  technicalImpact: string;
  /** Business impact description */
  businessImpact: string;
  /** Affected assets */
  affectedAssets?: string[];
  /** Data at risk */
  dataAtRisk?: string[];
}

/**
 * Exploitability assessment
 */
export interface ExploitabilityAssessment {
  /** Attack vector (network, adjacent, local, physical) */
  attackVector: 'network' | 'adjacent' | 'local' | 'physical';
  /** Attack complexity (low, medium, high) */
  attackComplexity: 'low' | 'medium' | 'high';
  /** Privileges required (none, low, high) */
  privilegesRequired: 'none' | 'low' | 'high';
  /** User interaction (none, required) */
  userInteraction: 'none' | 'required';
  /** Known exploits in the wild */
  knownExploits?: boolean;
  /** Exploit difficulty description */
  exploitDifficulty?: string;
}

/**
 * Remediation guidance
 */
export interface RemediationGuidance {
  /** Short remediation summary */
  summary: string;
  /** Detailed steps */
  steps: string[];
  /** Secure code example */
  secureCodeExample?: string;
  /** References for more information */
  references?: string[];
  /** Estimated effort (low, medium, high) */
  effort?: 'low' | 'medium' | 'high';
  /** Priority for fixing */
  priority?: 'immediate' | 'high' | 'medium' | 'low';
}

/**
 * Rule correlation configuration
 */
export interface RuleCorrelation {
  /** Rules that increase severity when both match */
  amplifyWith?: string[];
  /** Rules that must also match for this rule to trigger */
  requiresAlso?: string[];
  /** Rules that suppress this rule when matched */
  suppressedBy?: string[];
  /** Severity boost when correlated rules match */
  severityBoost?: number;
}

/**
 * Context conditions for severity adjustment
 */
export interface ContextConditions {
  /** Boost severity if in production code */
  productionBoost?: number;
  /** Reduce severity if in test code */
  testCodePenalty?: number;
  /** Boost if handles sensitive data */
  sensitiveDataBoost?: number;
  /** File path patterns to adjust severity */
  filePatterns?: Array<{
    pattern: string;
    severityAdjustment: number;
  }>;
}

/**
 * Comprehensive vulnerability detection rule
 */
export interface VulnerabilityRule {
  // === Identification ===
  /** Unique rule identifier (e.g., VUL-SQLI-001) */
  id: string;
  /** Human-readable rule name */
  name: string;
  /** Detailed technical description */
  description: string;
  /** Version of the rule */
  version?: string;

  // === Classification ===
  /** Specific vulnerability type */
  vulnerabilityType: VulnerabilityType;
  /** Vulnerability category */
  category: VulnerabilityCategory;
  /** Languages this rule applies to */
  languages: SupportedLanguage[];

  // === Severity & Confidence ===
  /** Base severity level */
  severity: VulnerabilitySeverity;
  /** Detection confidence */
  confidence: ConfidenceLevel;

  // === Detection Patterns ===
  /** Primary detection patterns */
  patterns: VulnerabilityPattern[];
  /** Secondary patterns that increase severity */
  amplifyingPatterns?: VulnerabilityPattern[];
  /** Patterns that indicate false positive */
  falsePositivePatterns?: VulnerabilityPattern[];

  // === Taint Analysis ===
  /** Taint sources for this vulnerability */
  taintSources?: TaintSource[];
  /** Taint sinks for this vulnerability */
  taintSinks?: TaintSink[];
  /** Sanitizers that prevent this vulnerability */
  taintSanitizers?: TaintSanitizer[];
  /** Simplified taint analysis config (sources, sinks, sanitizers as strings) */
  taintAnalysis?: {
    sources: string[];
    sinks: string[];
    sanitizers?: string[];
  };

  // === Correlation ===
  /** Rule correlation configuration */
  correlation?: RuleCorrelation;

  // === Context-based Severity ===
  /** Context conditions for severity adjustment */
  contextConditions?: ContextConditions;

  // === Scoring ===
  /** Base score contribution (0-100) */
  baseScore?: number;
  /** Scoring factors */
  scoringFactors?: ScoringFactors;

  // === Impact & Exploitability ===
  /** Impact assessment */
  impact: ImpactAssessment;
  /** Exploitability assessment */
  exploitability?: ExploitabilityAssessment;

  // === Documentation ===
  /** Example vulnerable code */
  vulnerableExamples?: CodeExample[];
  /** Example secure code */
  secureExamples?: CodeExample[];
  /** Known false positive examples */
  falsePositiveExamples?: CodeExample[];
  /** Remediation guidance */
  remediation: RemediationGuidance;

  // === Security Standards ===
  /** Security standard references */
  standards: SecurityStandards;

  // === Metadata ===
  /** Tags for categorization */
  tags: string[];
  /** Whether the rule is enabled */
  enabled: boolean;
  /** Author of the rule */
  author?: string;
  /** Creation date */
  createdAt?: string;
  /** Last update date */
  updatedAt?: string;
}

// ============================================================================
// SCORING SYSTEM
// ============================================================================

/**
 * Scoring factors for dynamic severity calculation
 */
export interface ScoringFactors {
  /** Taint flow weight */
  taintFlowWeight?: number;
  /** Pattern count weight */
  patternCountWeight?: number;
  /** Exploitability weight */
  exploitabilityWeight?: number;
  /** Impact weight */
  impactWeight?: number;
  /** Context weight */
  contextWeight?: number;
}

/**
 * Vulnerability score breakdown
 */
export interface VulnerabilityScoreBreakdown {
  /** Base score from rule */
  baseScore: number;
  /** Score from pattern matches */
  patternScore: number;
  /** Score from taint analysis */
  taintScore: number;
  /** Score from exploitability */
  exploitabilityScore: number;
  /** Score from impact assessment */
  impactScore: number;
  /** Score from context analysis */
  contextScore: number;
  /** Penalty for false positive indicators */
  falsePositivePenalty: number;
  /** Boost from correlated rules */
  correlationBoost: number;
  /** Final calculated score */
  totalScore: number;
}

/**
 * Complete vulnerability score result
 */
export interface VulnerabilityScore {
  /** Numeric score (0-100) */
  score: number;
  /** Score breakdown */
  breakdown: VulnerabilityScoreBreakdown;
  /** Calculated severity from score */
  calculatedSeverity: VulnerabilitySeverity;
  /** Risk level description */
  riskLevel: 'critical' | 'high' | 'medium' | 'low' | 'minimal';
  /** Explanation of the score */
  explanation: string;
}

// ============================================================================
// FINDINGS
// ============================================================================

/**
 * Location of a finding in source code
 */
export interface SourceLocation {
  /** File path */
  filePath: string;
  /** Starting line number (1-based) */
  startLine: number;
  /** Ending line number (1-based) */
  endLine: number;
  /** Starting column (0-based) */
  startColumn?: number;
  /** Ending column (0-based) */
  endColumn?: number;
}

/**
 * Pattern match details
 */
export interface PatternMatch {
  /** Pattern that matched */
  pattern: VulnerabilityPattern;
  /** Matched text */
  matchedText: string;
  /** Location of the match */
  location: SourceLocation;
  /** Capture groups if regex */
  captures?: string[];
}

/**
 * Data flow trace for audit reporting
 */
export interface DataFlowTrace {
  /** Starting source */
  source: {
    name: string;
    location: SourceLocation;
    codeSnippet: string;
  };
  /** Intermediate steps */
  propagation: Array<{
    variable: string;
    location: SourceLocation;
    operation: string;
    codeSnippet: string;
  }>;
  /** Ending sink */
  sink: {
    name: string;
    location: SourceLocation;
    codeSnippet: string;
  };
  /** Was the data sanitized? */
  sanitized: boolean;
  /** Sanitization details if applicable */
  sanitizationDetails?: {
    sanitizer: string;
    location: SourceLocation;
    effectiveness: number;
  };
}

/**
 * Complete vulnerability finding
 */
export interface VulnerabilityFinding {
  // === Identification ===
  /** Unique finding ID */
  id: string;
  /** Rule that triggered this finding */
  ruleId: string;
  /** Rule name */
  ruleName: string;

  // === Location ===
  /** Source code location */
  location: SourceLocation;
  /** Code snippet */
  codeSnippet: string;
  /** Highlighted portion */
  highlightedCode?: string;

  // === Classification ===
  /** Vulnerability type */
  vulnerabilityType: VulnerabilityType;
  /** Vulnerability category */
  category: VulnerabilityCategory;
  /** Final severity */
  severity: VulnerabilitySeverity;
  /** Confidence level */
  confidence: ConfidenceLevel;

  // === Scoring ===
  /** Vulnerability score */
  score: VulnerabilityScore;

  // === Detection Details ===
  /** Patterns that matched */
  patternMatches: PatternMatch[];
  /** Taint flow if detected */
  taintFlow?: TaintFlow;
  /** Data flow trace for audit */
  dataFlowTrace?: DataFlowTrace;
  /** Correlated findings */
  correlatedFindings?: string[];

  // === Reporting ===
  /** Human-readable message */
  message: string;
  /** Detailed analysis for auditors */
  auditAnalysis: string;
  /** Developer-friendly explanation */
  developerExplanation: string;
  /** Remediation guidance */
  remediation: RemediationGuidance;

  // === Security Standards ===
  /** Security standard references */
  standards: SecurityStandards;

  // === Metadata ===
  /** Detection timestamp */
  detectedAt: string;
  /** Language of the code */
  language: SupportedLanguage;
  /** Is in test code */
  isTestCode?: boolean;
  /** Is in vendor/node_modules */
  isVendorCode?: boolean;
  /** Additional context */
  context?: Record<string, unknown>;
}

// ============================================================================
// ANALYSIS CONTEXT
// ============================================================================

/**
 * Analysis context for rule evaluation
 */
export interface AnalysisContext {
  /** File being analyzed */
  filePath: string;
  /** File content */
  content: string;
  /** Detected language */
  language: SupportedLanguage;
  /** AST if available */
  ast?: unknown;
  /** Control flow graph if available */
  cfg?: unknown;
  /** Call graph if available */
  callGraph?: unknown;
  /** Detected taint flows */
  taintFlows?: TaintFlow[];
  /** Dependencies if available */
  dependencies?: string[];
  /** Is this in node_modules or vendor */
  isVendorCode?: boolean;
  /** Is this a test file */
  isTestFile?: boolean;
  /** Is this production code */
  isProductionCode?: boolean;
  /** File handles sensitive data */
  handlesSensitiveData?: boolean;
  /** Previous findings in this file */
  previousFindings?: VulnerabilityFinding[];
  /** Findings from related files */
  relatedFindings?: VulnerabilityFinding[];
  /** Project configuration */
  projectConfig?: ProjectConfig;
}

/**
 * Project configuration for context-aware analysis
 */
export interface ProjectConfig {
  /** Framework being used */
  framework?: string;
  /** Production vs development */
  environment?: 'production' | 'development' | 'staging';
  /** Configured security headers */
  securityHeaders?: string[];
  /** Enabled security features */
  securityFeatures?: string[];
}

/**
 * Analysis options
 */
export interface AnalysisOptions {
  /** Enable taint analysis */
  enableTaintAnalysis?: boolean;
  /** Enable AST analysis */
  enableAstAnalysis?: boolean;
  /** Enable CFG analysis */
  enableCfgAnalysis?: boolean;
  /** Minimum confidence to report */
  minConfidence?: ConfidenceLevel;
  /** Maximum findings per file */
  maxFindingsPerFile?: number;
  /** Timeout per rule in ms */
  ruleTimeoutMs?: number;
  /** Include info severity */
  includeInfo?: boolean;
  /** Exclude test files */
  excludeTestFiles?: boolean;
  /** Exclude vendor code */
  excludeVendorCode?: boolean;
}

// ============================================================================
// ENGINE INTERFACES
// ============================================================================

/**
 * Pattern matcher interface
 */
export interface IPatternMatcher {
  match(
    content: string,
    patterns: VulnerabilityPattern[],
    language: SupportedLanguage
  ): PatternMatch[];

  matchWithTimeout(
    content: string,
    patterns: VulnerabilityPattern[],
    language: SupportedLanguage,
    timeout: number
  ): Promise<PatternMatch[]>;
}

/**
 * Taint analyzer interface
 */
export interface ITaintAnalyzer {
  analyze(
    context: AnalysisContext,
    sources: TaintSource[],
    sinks: TaintSink[],
    sanitizers?: TaintSanitizer[]
  ): TaintFlow[];
}

/**
 * Score calculator interface
 */
export interface IScoreCalculator {
  calculateScore(
    rule: VulnerabilityRule,
    matches: PatternMatch[],
    context: AnalysisContext,
    taintFlow?: TaintFlow
  ): VulnerabilityScore;
}

/**
 * Vulnerability rule engine interface
 */
export interface IVulnerabilityRuleEngine {
  /** Analyze code against all enabled rules */
  analyze(
    context: AnalysisContext,
    options?: AnalysisOptions
  ): Promise<VulnerabilityFinding[]>;

  /** Get all registered rules */
  getRules(): VulnerabilityRule[];

  /** Get rule by ID */
  getRule(id: string): VulnerabilityRule | undefined;

  /** Enable/disable a rule */
  setRuleEnabled(id: string, enabled: boolean): void;

  /** Add a custom rule */
  addRule(rule: VulnerabilityRule): void;
}
