/**
 * @fileoverview Vulnerability Detection Module - Main Entry Point
 * @module rules/vulnerabilities
 * 
 * Enterprise-grade SAST vulnerability detection module.
 * Provides comprehensive security analysis covering OWASP Top 10,
 * CWE, SANS Top 25, and MITRE ATT&CK mapped vulnerabilities.
 * 
 * @example
 * ```typescript
 * import { 
 *   VulnerabilityRuleEngine, 
 *   createDefaultEngine,
 *   quickScan,
 *   allVulnerabilityRules 
 * } from '@/rules/vulnerabilities';
 * 
 * // Quick scan for vulnerabilities
 * const findings = await quickScan(code, 'javascript');
 * 
 * // Or use the full engine
 * const engine = createDefaultEngine();
 * const results = await engine.analyze(code, context);
 * ```
 */

// ============================================================================
// TYPE EXPORTS
// ============================================================================

export {
  // Enums
  VulnerabilityType,
  VulnerabilityCategory,
  VulnerabilitySeverity,
  ConfidenceLevel,
  SupportedLanguage,
  PatternType,
  
  // Interfaces
  type VulnerabilityRule,
  type VulnerabilityFinding,
  type VulnerabilityPattern,
  type VulnerabilityScore,
  type TaintSource,
  type TaintSink,
  type TaintSanitizer,
  type TaintFlow,
  type DataFlowTrace,
  type ImpactAssessment,
  type ExploitabilityAssessment,
  type RemediationGuidance,
  type SecurityStandards,
  type AnalysisContext,
  type PatternMatch
} from './types';

// ============================================================================
// CONSTANTS EXPORTS
// ============================================================================

export {
  // Score thresholds
  SCORE_THRESHOLDS,
  LIMITS,
  
  // Taint sources by language
  JS_TAINT_SOURCES,
  PYTHON_TAINT_SOURCES,
  PHP_TAINT_SOURCES,
  JAVA_TAINT_SOURCES,
  CSHARP_TAINT_SOURCES,
  
  // Taint sinks by category
  SQL_INJECTION_SINKS,
  COMMAND_INJECTION_SINKS,
  XSS_SINKS,
  PATH_TRAVERSAL_SINKS,
  SSRF_SINKS,
  
  // Sanitizers
  SQL_SANITIZERS,
  XSS_SANITIZERS,
  COMMAND_SANITIZERS,
  PATH_SANITIZERS,
  
  // Security standards
  OWASP_TOP_10_2021,
  CWE_REFERENCES
} from './constants';

// ============================================================================
// UTILITY EXPORTS
// ============================================================================

export {
  // Regex utilities
  safeRegexMatch,
  extractSnippet,
  normalizeCode,
  
  // Taint analysis helpers
  findTaintSources,
  findTaintSinks,
  findSanitizers,
  
  // Context detection
  isTestFile,
  isVendorCode,
  detectLanguage,
  
  // Confidence calculation
  calculateConfidence
} from './utils';

// ============================================================================
// SCORING EXPORTS
// ============================================================================

export {
  VulnerabilityScoreCalculator
} from './scoring';

// ============================================================================
// ENGINE EXPORTS
// ============================================================================

export {
  VulnerabilityRuleEngine,
  PatternMatcher,
  SimpleTaintAnalyzer,
  createDefaultEngine,
  quickScan
} from './engine';

// ============================================================================
// RULE IMPORTS
// ============================================================================

import { SupportedLanguage } from './types';
import { sqlInjectionRules } from './rules/sqlInjection';
import { xssRules } from './rules/xss';
import { commandInjectionRules } from './rules/commandInjection';
import { pathTraversalRules } from './rules/pathTraversal';
import { ssrfRules } from './rules/ssrf';
import { deserializationRules } from './rules/deserialization';
import { hardcodedSecretsRules } from './rules/hardcodedSecrets';
import { authenticationRules } from './rules/authentication';
import { securityMisconfigurationRules } from './rules/securityMisconfiguration';
import { csrfRules } from './rules/csrf';
import { prototypePollutionRules } from './rules/prototypePollution';
import { fileUploadRules } from './rules/fileUpload';

// ============================================================================
// INDIVIDUAL RULE EXPORTS
// ============================================================================

export { sqlInjectionRules } from './rules/sqlInjection';
export { xssRules } from './rules/xss';
export { commandInjectionRules } from './rules/commandInjection';
export { pathTraversalRules } from './rules/pathTraversal';
export { ssrfRules } from './rules/ssrf';
export { deserializationRules } from './rules/deserialization';
export { hardcodedSecretsRules } from './rules/hardcodedSecrets';
export { authenticationRules } from './rules/authentication';
export { securityMisconfigurationRules } from './rules/securityMisconfiguration';
export { csrfRules } from './rules/csrf';
export { prototypePollutionRules } from './rules/prototypePollution';
export { fileUploadRules } from './rules/fileUpload';

// ============================================================================
// AGGREGATED RULE COLLECTIONS
// ============================================================================

/**
 * All vulnerability detection rules combined.
 * Use this for comprehensive scanning.
 */
export const allVulnerabilityRules = [
  ...sqlInjectionRules,
  ...xssRules,
  ...commandInjectionRules,
  ...pathTraversalRules,
  ...ssrfRules,
  ...deserializationRules,
  ...hardcodedSecretsRules,
  ...authenticationRules,
  ...securityMisconfigurationRules,
  ...csrfRules,
  ...prototypePollutionRules,
  ...fileUploadRules
];

/**
 * Critical severity rules only.
 * Use for quick scans focusing on the most severe issues.
 */
export const criticalRules = allVulnerabilityRules.filter(
  rule => rule.severity === 'critical'
);

/**
 * High severity and above rules.
 * Balanced between speed and coverage.
 */
export const highSeverityRules = allVulnerabilityRules.filter(
  rule => rule.severity === 'critical' || rule.severity === 'high'
);

/**
 * OWASP Top 10 focused rules.
 * Rules specifically mapped to OWASP Top 10 2021.
 */
export const owaspTop10Rules = allVulnerabilityRules.filter(
  rule => rule.standards?.owasp && rule.standards.owasp.length > 0
);

/**
 * Injection category rules (SQL, Command, XSS, etc.).
 */
export const injectionRules = [
  ...sqlInjectionRules,
  ...xssRules,
  ...commandInjectionRules,
  ...prototypePollutionRules
];

/**
 * Authentication and access control rules.
 */
export const authRules = [
  ...authenticationRules,
  ...csrfRules
];

/**
 * Configuration and cryptographic rules.
 */
export const configRules = [
  ...securityMisconfigurationRules,
  ...hardcodedSecretsRules
];

/**
 * Rules by language mapping.
 */
export const rulesByLanguage = {
  javascript: allVulnerabilityRules.filter(
    rule => rule.languages.includes(SupportedLanguage.JAVASCRIPT) || rule.languages.includes(SupportedLanguage.TYPESCRIPT)
  ),
  typescript: allVulnerabilityRules.filter(
    rule => rule.languages.includes(SupportedLanguage.TYPESCRIPT) || rule.languages.includes(SupportedLanguage.JAVASCRIPT)
  ),
  python: allVulnerabilityRules.filter(
    rule => rule.languages.includes(SupportedLanguage.PYTHON)
  ),
  php: allVulnerabilityRules.filter(
    rule => rule.languages.includes(SupportedLanguage.PHP)
  ),
  java: allVulnerabilityRules.filter(
    rule => rule.languages.includes(SupportedLanguage.JAVA)
  ),
  csharp: allVulnerabilityRules.filter(
    rule => rule.languages.includes(SupportedLanguage.CSHARP)
  )
};

// ============================================================================
// STATISTICS AND METADATA
// ============================================================================

/**
 * Module statistics.
 */
export const moduleStats = {
  totalRules: allVulnerabilityRules.length,
  criticalRules: criticalRules.length,
  highSeverityRules: highSeverityRules.length,
  
  byCategory: {
    injection: injectionRules.length,
    authentication: authRules.length,
    configuration: configRules.length,
    ssrf: ssrfRules.length,
    pathTraversal: pathTraversalRules.length,
    deserialization: deserializationRules.length,
    fileUpload: fileUploadRules.length
  },
  
  byLanguage: {
    javascript: rulesByLanguage.javascript.length,
    python: rulesByLanguage.python.length,
    php: rulesByLanguage.php.length,
    java: rulesByLanguage.java.length,
    csharp: rulesByLanguage.csharp.length
  },
  
  version: '1.0.0'
};

// ============================================================================
// DEFAULT EXPORT
// ============================================================================

export default {
  rules: allVulnerabilityRules,
  criticalRules,
  highSeverityRules,
  owaspTop10Rules,
  rulesByLanguage,
  stats: moduleStats
};
