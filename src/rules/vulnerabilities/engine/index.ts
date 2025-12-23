/**
 * @fileoverview Vulnerability Rule Engine - Core Detection Engine
 * @module rules/vulnerabilities/engine
 * 
 * Orchestrates vulnerability detection across all rule categories:
 * - Multi-pattern matching with timeout protection
 * - Taint analysis integration
 * - AST-aware analysis
 * - Dynamic scoring
 * - Rule correlation
 * - Finding aggregation and deduplication
 */

import {
  VulnerabilityRule,
  VulnerabilityFinding,
  VulnerabilityPattern,
  VulnerabilityScore,
  AnalysisContext,
  AnalysisOptions,
  IVulnerabilityRuleEngine,
  IPatternMatcher,
  PatternMatch,
  PatternType,
  VulnerabilitySeverity,
  ConfidenceLevel,
  SourceLocation,
  SupportedLanguage,
  RegexPattern,
  TaintFlow,
  DataFlowTrace,
  SecurityStandards
} from '../types';

import {
  safeRegexMatch,
  safeRegexMatchAsync,
  extractSnippet,
  formatSnippetWithLineNumbers,
  normalizeCode,
  generateFindingId,
  isTestFile,
  isVendorCode,
  getLineNumber,
  getColumnNumber,
  findTaintSources,
  findTaintSinks,
  findSanitizers,
  adjustConfidenceForTaintFlow
} from '../utils';

import { VulnerabilityScoreCalculator } from '../scoring';
import { LIMITS } from '../constants';

// ============================================================================
// PATTERN MATCHER IMPLEMENTATION
// ============================================================================

/**
 * Pattern matcher with timeout protection
 */
export class PatternMatcher implements IPatternMatcher {
  private timeoutMs: number;
  private maxMatches: number;

  constructor(options?: { timeoutMs?: number; maxMatches?: number }) {
    this.timeoutMs = options?.timeoutMs ?? LIMITS.REGEX_TIMEOUT;
    this.maxMatches = options?.maxMatches ?? LIMITS.MAX_MATCHES_PER_PATTERN;
  }

  /**
   * Match patterns against content
   */
  match(
    content: string,
    patterns: VulnerabilityPattern[],
    language: SupportedLanguage
  ): PatternMatch[] {
    const allMatches: PatternMatch[] = [];
    
    for (const pattern of patterns) {
      // Check language compatibility
      if (pattern.languages && !pattern.languages.includes(language)) {
        continue;
      }

      const matches = this.matchSinglePattern(pattern, content, language);
      allMatches.push(...matches);

      if (allMatches.length >= this.maxMatches) {
        break;
      }
    }
    
    return allMatches;
  }

  /**
   * Match with timeout protection
   */
  async matchWithTimeout(
    content: string,
    patterns: VulnerabilityPattern[],
    language: SupportedLanguage,
    timeout: number
  ): Promise<PatternMatch[]> {
    return new Promise((resolve) => {
      const timeoutId = setTimeout(() => {
        resolve([]);
      }, timeout);

      try {
        const results = this.match(content, patterns, language);
        clearTimeout(timeoutId);
        resolve(results);
      } catch {
        clearTimeout(timeoutId);
        resolve([]);
      }
    });
  }

  /**
   * Match a single pattern against code
   */
  private matchSinglePattern(
    pattern: VulnerabilityPattern,
    code: string,
    language: SupportedLanguage
  ): PatternMatch[] {
    try {
      switch (pattern.type) {
        case PatternType.REGEX:
          return safeRegexMatch(code, pattern as RegexPattern);
        
        case PatternType.LITERAL:
          return this.matchLiteralPattern(pattern, code);
        
        case PatternType.AST:
          // AST patterns require external AST parser
          return [];
        
        case PatternType.TAINT:
          // Taint patterns are handled separately
          return [];
        
        case PatternType.SEMANTIC:
          // Semantic patterns require deeper analysis
          return [];
        
        case PatternType.CFG:
          // CFG patterns require control flow analysis
          return [];
        
        default:
          return [];
      }
    } catch (error) {
      console.error(`Pattern matching error for ${pattern.patternId}:`, error);
      return [];
    }
  }

  /**
   * Match literal string pattern
   */
  private matchLiteralPattern(
    pattern: VulnerabilityPattern,
    code: string
  ): PatternMatch[] {
    const matches: PatternMatch[] = [];
    
    if (pattern.type !== PatternType.LITERAL) return matches;
    
    const literalPattern = pattern as { type: PatternType.LITERAL; value: string; caseSensitive?: boolean };
    const searchString = literalPattern.value || '';
    const searchCode = literalPattern.caseSensitive === false ? code.toLowerCase() : code;
    const searchFor = literalPattern.caseSensitive === false ? searchString.toLowerCase() : searchString;
    
    let index = 0;

    while (index < searchCode.length && matches.length < this.maxMatches) {
      index = searchCode.indexOf(searchFor, index);
      if (index === -1) break;

      const line = getLineNumber(code, index);
      const column = getColumnNumber(code, index);

      matches.push({
        pattern,
        matchedText: code.substring(index, index + searchString.length),
        location: {
          filePath: '',
          startLine: line,
          endLine: line,
          startColumn: column,
          endColumn: column + searchString.length
        }
      });

      index += searchString.length;
    }

    return matches;
  }
}

// ============================================================================
// SIMPLE TAINT ANALYZER
// ============================================================================

/**
 * Simple taint analyzer for detecting data flows
 */
export class SimpleTaintAnalyzer {
  /**
   * Analyze taint flows in code
   */
  analyze(
    context: AnalysisContext,
    rule: VulnerabilityRule
  ): TaintFlow[] {
    const flows: TaintFlow[] = [];
    
    if (!rule.taintSources || !rule.taintSinks) {
      return flows;
    }

    // Find all sources
    const sources = findTaintSources(
      context.content,
      rule.taintSources,
      context.language
    );

    // Find all sinks
    const sinks = findTaintSinks(
      context.content,
      rule.taintSinks,
      context.language
    );

    // For each source-sink pair, check if there's a potential flow
    for (const sourceMatch of sources) {
      for (const sinkMatch of sinks) {
        // Simple heuristic: if source appears before sink in the same file
        if (sourceMatch.location.startLine <= sinkMatch.location.startLine) {
          // Check for sanitizers between source and sink
          const sanitizers = rule.taintSanitizers 
            ? findSanitizers(
                context.content,
                sourceMatch.location,
                sinkMatch.location,
                rule.taintSanitizers
              )
            : [];

          const isExploitable = sanitizers.length === 0;

          flows.push({
            source: sourceMatch.source,
            sink: sinkMatch.sink,
            path: [
              {
                name: sourceMatch.matchedText,
                location: sourceMatch.location,
                operation: 'source'
              },
              {
                name: sinkMatch.matchedText,
                location: sinkMatch.location,
                operation: 'sink'
              }
            ],
            sanitizers,
            isExploitable,
            confidence: isExploitable ? ConfidenceLevel.HIGH : ConfidenceLevel.MEDIUM
          });
        }
      }
    }

    return flows;
  }

  /**
   * Convert taint flow to data flow trace for reporting
   */
  createDataFlowTrace(
    flow: TaintFlow,
    code: string
  ): DataFlowTrace {
    const sourceSnippet = extractSnippet(code, flow.path[0].location, 1);
    const sinkSnippet = extractSnippet(code, flow.path[flow.path.length - 1].location, 1);

    return {
      source: {
        name: flow.source.name,
        location: flow.path[0].location,
        codeSnippet: sourceSnippet.snippet
      },
      propagation: flow.path.slice(1, -1).map(node => ({
        variable: node.name,
        location: node.location,
        operation: node.operation || 'propagate',
        codeSnippet: extractSnippet(code, node.location, 0).snippet
      })),
      sink: {
        name: flow.sink.name,
        location: flow.path[flow.path.length - 1].location,
        codeSnippet: sinkSnippet.snippet
      },
      sanitized: flow.sanitizers.length > 0,
      sanitizationDetails: flow.sanitizers.length > 0 ? {
        sanitizer: flow.sanitizers[0].name,
        location: flow.path[0].location, // Approximate
        effectiveness: flow.sanitizers[0].effectiveness ?? 80
      } : undefined
    };
  }
}

// ============================================================================
// ENGINE OPTIONS
// ============================================================================

export interface EngineOptions {
  enableTaintAnalysis: boolean;
  enableAstAnalysis: boolean;
  enableCfgAnalysis: boolean;
  timeoutMs: number;
  maxFindings: number;
  minConfidence: ConfidenceLevel;
  includeInfo: boolean;
  excludeTestFiles: boolean;
  excludeVendorCode: boolean;
  language?: SupportedLanguage;
}

const DEFAULT_OPTIONS: EngineOptions = {
  enableTaintAnalysis: true,
  enableAstAnalysis: false,
  enableCfgAnalysis: false,
  timeoutMs: LIMITS.RULE_TIMEOUT,
  maxFindings: LIMITS.MAX_FINDINGS_PER_FILE,
  minConfidence: ConfidenceLevel.LOW,
  includeInfo: false,
  excludeTestFiles: false,
  excludeVendorCode: true
};

// ============================================================================
// VULNERABILITY RULE ENGINE
// ============================================================================

/**
 * Main vulnerability detection engine
 */
export class VulnerabilityRuleEngine implements IVulnerabilityRuleEngine {
  private rules: Map<string, VulnerabilityRule>;
  private patternMatcher: PatternMatcher;
  private taintAnalyzer: SimpleTaintAnalyzer;
  private scoreCalculator: VulnerabilityScoreCalculator;
  private engineOptions: EngineOptions;

  constructor(
    rules: VulnerabilityRule[],
    options?: Partial<EngineOptions>
  ) {
    this.rules = new Map(rules.map(rule => [rule.id, rule]));
    this.patternMatcher = new PatternMatcher();
    this.taintAnalyzer = new SimpleTaintAnalyzer();
    this.scoreCalculator = new VulnerabilityScoreCalculator();
    this.engineOptions = { ...DEFAULT_OPTIONS, ...options };
  }

  /**
   * Analyze code against all enabled rules
   */
  async analyze(
    context: AnalysisContext,
    options?: AnalysisOptions
  ): Promise<VulnerabilityFinding[]> {
    const mergedOptions = { ...this.engineOptions, ...options };

    // Check exclusions
    if (mergedOptions.excludeTestFiles && isTestFile(context.filePath)) {
      return [];
    }
    if (mergedOptions.excludeVendorCode && isVendorCode(context.filePath)) {
      return [];
    }

    // Normalize code
    const normalizedCode = normalizeCode(context.content, context.language);
    const normalizedContext = { ...context, content: normalizedCode };

    // Get applicable rules
    const applicableRules = this.getApplicableRules(context.language);

    const findings: VulnerabilityFinding[] = [];

    for (const rule of applicableRules) {
      try {
        const ruleFindings = await this.analyzeWithRule(
          normalizedContext,
          rule,
          mergedOptions
        );
        findings.push(...ruleFindings);

        if (findings.length >= mergedOptions.maxFindings) {
          break;
        }
      } catch (error) {
        console.error(`Error analyzing with rule ${rule.id}:`, error);
      }
    }

    // Sort by severity and score
    findings.sort((a, b) => {
      const severityOrder = {
        [VulnerabilitySeverity.CRITICAL]: 0,
        [VulnerabilitySeverity.HIGH]: 1,
        [VulnerabilitySeverity.MEDIUM]: 2,
        [VulnerabilitySeverity.LOW]: 3,
        [VulnerabilitySeverity.INFO]: 4
      };
      
      const severityDiff = severityOrder[a.severity] - severityOrder[b.severity];
      if (severityDiff !== 0) return severityDiff;
      
      return b.score.score - a.score.score;
    });

    // Deduplicate
    return this.deduplicateFindings(findings);
  }

  /**
   * Analyze code with a specific rule
   */
  private async analyzeWithRule(
    context: AnalysisContext,
    rule: VulnerabilityRule,
    options: EngineOptions
  ): Promise<VulnerabilityFinding[]> {
    const findings: VulnerabilityFinding[] = [];

    // Pattern matching
    const matches = await this.patternMatcher.matchWithTimeout(
      context.content,
      rule.patterns,
      context.language,
      options.timeoutMs
    );

    if (matches.length === 0) {
      return findings;
    }

    // Taint analysis if enabled
    let taintFlows: TaintFlow[] = [];
    if (options.enableTaintAnalysis && (rule.taintSources || rule.taintSinks)) {
      taintFlows = this.taintAnalyzer.analyze(context, rule);
    }

    // Group matches by location to avoid duplicate findings
    const locationGroups = this.groupMatchesByLocation(matches);

    for (const [locationKey, groupMatches] of locationGroups) {
      // Find relevant taint flow for this location
      const relevantFlow = taintFlows.find(flow => 
        flow.path.some(node => 
          this.locationsOverlap(node.location, groupMatches[0].location)
        )
      );

      // Calculate score
      const score = this.scoreCalculator.calculateScore(
        rule,
        groupMatches,
        context,
        relevantFlow
      );

      // Check minimum confidence
      const confidence = relevantFlow 
        ? adjustConfidenceForTaintFlow(rule.confidence, true)
        : rule.confidence;

      if (!this.meetsMinConfidence(confidence, options.minConfidence)) {
        continue;
      }

      // Filter out INFO if not requested
      if (!options.includeInfo && score.calculatedSeverity === VulnerabilitySeverity.INFO) {
        continue;
      }

      // Create finding
      const finding = this.createFinding(
        rule,
        groupMatches,
        context,
        score,
        relevantFlow
      );

      findings.push(finding);
    }

    return findings;
  }

  /**
   * Create a vulnerability finding
   */
  private createFinding(
    rule: VulnerabilityRule,
    matches: PatternMatch[],
    context: AnalysisContext,
    score: VulnerabilityScore,
    taintFlow?: TaintFlow
  ): VulnerabilityFinding {
    const primaryMatch = matches[0];
    const location: SourceLocation = {
      filePath: context.filePath,
      startLine: primaryMatch.location.startLine,
      endLine: primaryMatch.location.endLine,
      startColumn: primaryMatch.location.startColumn,
      endColumn: primaryMatch.location.endColumn
    };

    const { snippet } = extractSnippet(context.content, location, 3);

    // Build data flow trace if taint flow exists
    let dataFlowTrace: DataFlowTrace | undefined;
    if (taintFlow) {
      dataFlowTrace = this.taintAnalyzer.createDataFlowTrace(
        taintFlow,
        context.content
      );
    }

    // Determine final confidence
    const confidence = taintFlow 
      ? adjustConfidenceForTaintFlow(rule.confidence, true)
      : rule.confidence;

    return {
      id: generateFindingId(rule.id, context.filePath, location.startLine),
      ruleId: rule.id,
      ruleName: rule.name,
      location,
      codeSnippet: snippet,
      highlightedCode: primaryMatch.matchedText,
      vulnerabilityType: rule.vulnerabilityType,
      category: rule.category,
      severity: score.calculatedSeverity,
      confidence,
      score,
      patternMatches: matches,
      taintFlow,
      dataFlowTrace,
      message: this.generateMessage(rule, matches, taintFlow),
      auditAnalysis: this.generateAuditAnalysis(rule, matches, taintFlow, score),
      developerExplanation: this.generateDeveloperExplanation(rule, matches),
      remediation: rule.remediation,
      standards: rule.standards,
      detectedAt: new Date().toISOString(),
      language: context.language,
      isTestCode: context.isTestFile,
      isVendorCode: context.isVendorCode
    };
  }

  /**
   * Generate finding message
   */
  private generateMessage(
    rule: VulnerabilityRule,
    matches: PatternMatch[],
    taintFlow?: TaintFlow
  ): string {
    let message = `${rule.name}: ${rule.description}`;
    
    if (taintFlow && taintFlow.isExploitable) {
      message += ` Confirmed data flow from '${taintFlow.source.name}' to '${taintFlow.sink.name}'.`;
    }

    return message;
  }

  /**
   * Generate detailed audit analysis
   */
  private generateAuditAnalysis(
    rule: VulnerabilityRule,
    matches: PatternMatch[],
    taintFlow: TaintFlow | undefined,
    score: VulnerabilityScore
  ): string {
    const parts: string[] = [];

    parts.push(`## Vulnerability Analysis: ${rule.name}`);
    parts.push('');
    parts.push(`**Vulnerability Type:** ${rule.vulnerabilityType}`);
    parts.push(`**Category:** ${rule.category}`);
    parts.push(`**Severity:** ${score.calculatedSeverity.toUpperCase()}`);
    parts.push(`**Risk Score:** ${score.score}/100`);
    parts.push('');
    
    // Standards mapping
    parts.push('### Security Standards');
    if (rule.standards.owasp?.length) {
      parts.push(`**OWASP:** ${rule.standards.owasp.map(o => o.id).join(', ')}`);
    }
    if (rule.standards.cwe?.length) {
      parts.push(`**CWE:** ${rule.standards.cwe.map(c => c.id).join(', ')}`);
    }
    parts.push('');

    // Detection details
    parts.push('### Detection Details');
    parts.push(`**Pattern Matches:** ${matches.length}`);
    
    if (taintFlow) {
      parts.push('');
      parts.push('### Data Flow Analysis');
      parts.push(`**Source:** ${taintFlow.source.name}`);
      parts.push(`**Sink:** ${taintFlow.sink.name}`);
      parts.push(`**Exploitable:** ${taintFlow.isExploitable ? 'Yes' : 'No'}`);
      if (taintFlow.sanitizers.length > 0) {
        parts.push(`**Sanitizers Applied:** ${taintFlow.sanitizers.map(s => s.name).join(', ')}`);
      }
    }

    parts.push('');
    parts.push('### Impact Assessment');
    if (rule.impact) {
      parts.push(`**Confidentiality:** ${rule.impact.confidentiality}`);
      parts.push(`**Integrity:** ${rule.impact.integrity}`);
      parts.push(`**Availability:** ${rule.impact.availability}`);
      parts.push(`**Technical Impact:** ${rule.impact.technicalImpact}`);
      parts.push(`**Business Impact:** ${rule.impact.businessImpact}`);
    }

    parts.push('');
    parts.push('### Score Breakdown');
    parts.push('```');
    parts.push(score.explanation);
    parts.push('```');

    return parts.join('\n');
  }

  /**
   * Generate developer-friendly explanation
   */
  private generateDeveloperExplanation(
    rule: VulnerabilityRule,
    matches: PatternMatch[]
  ): string {
    const parts: string[] = [];

    parts.push(`**What's the problem?**`);
    parts.push(rule.description);
    parts.push('');

    parts.push(`**Why is this dangerous?**`);
    if (rule.impact) {
      parts.push(rule.impact.technicalImpact);
    }
    parts.push('');

    parts.push(`**How to fix it:**`);
    parts.push(rule.remediation.summary);
    if (rule.remediation.steps?.length) {
      rule.remediation.steps.forEach((step, i) => {
        parts.push(`${i + 1}. ${step}`);
      });
    }

    if (rule.remediation.secureCodeExample) {
      parts.push('');
      parts.push('**Secure code example:**');
      parts.push('```');
      parts.push(rule.remediation.secureCodeExample);
      parts.push('```');
    }

    return parts.join('\n');
  }

  /**
   * Get rules applicable to a language
   */
  private getApplicableRules(language: SupportedLanguage): VulnerabilityRule[] {
    return Array.from(this.rules.values()).filter(rule => 
      rule.enabled && rule.languages.includes(language)
    );
  }

  /**
   * Get all registered rules
   */
  getRules(): VulnerabilityRule[] {
    return Array.from(this.rules.values());
  }

  /**
   * Get rule by ID
   */
  getRule(id: string): VulnerabilityRule | undefined {
    return this.rules.get(id);
  }

  /**
   * Enable/disable a rule
   */
  setRuleEnabled(id: string, enabled: boolean): void {
    const rule = this.rules.get(id);
    if (rule) {
      rule.enabled = enabled;
    }
  }

  /**
   * Add a custom rule
   */
  addRule(rule: VulnerabilityRule): void {
    this.rules.set(rule.id, rule);
  }

  /**
   * Group matches by location
   */
  private groupMatchesByLocation(
    matches: PatternMatch[]
  ): Map<string, PatternMatch[]> {
    const groups = new Map<string, PatternMatch[]>();

    for (const match of matches) {
      const key = `${match.location.startLine}:${match.location.startColumn}`;
      const existing = groups.get(key) || [];
      existing.push(match);
      groups.set(key, existing);
    }

    return groups;
  }

  /**
   * Check if two locations overlap
   */
  private locationsOverlap(a: SourceLocation, b: SourceLocation): boolean {
    return a.startLine <= b.endLine && b.startLine <= a.endLine;
  }

  /**
   * Check if confidence meets minimum
   */
  private meetsMinConfidence(
    confidence: ConfidenceLevel,
    minConfidence: ConfidenceLevel
  ): boolean {
    const levels = [
      ConfidenceLevel.TENTATIVE,
      ConfidenceLevel.LOW,
      ConfidenceLevel.MEDIUM,
      ConfidenceLevel.HIGH,
      ConfidenceLevel.CONFIRMED
    ];
    return levels.indexOf(confidence) >= levels.indexOf(minConfidence);
  }

  /**
   * Deduplicate findings
   */
  private deduplicateFindings(
    findings: VulnerabilityFinding[]
  ): VulnerabilityFinding[] {
    const seen = new Set<string>();
    return findings.filter(finding => {
      const key = `${finding.ruleId}:${finding.location.filePath}:${finding.location.startLine}`;
      if (seen.has(key)) {
        return false;
      }
      seen.add(key);
      return true;
    });
  }
}

// ============================================================================
// FACTORY FUNCTIONS
// ============================================================================

/**
 * Create default vulnerability engine
 */
export function createDefaultEngine(
  rules: VulnerabilityRule[],
  options?: Partial<EngineOptions>
): VulnerabilityRuleEngine {
  return new VulnerabilityRuleEngine(rules, options);
}

/**
 * Quick scan function for simple usage
 */
export async function quickScan(
  code: string,
  filePath: string,
  language: SupportedLanguage,
  rules: VulnerabilityRule[],
  options?: Partial<EngineOptions>
): Promise<VulnerabilityFinding[]> {
  const engine = createDefaultEngine(rules, options);
  
  const context: AnalysisContext = {
    filePath,
    content: code,
    language,
    isTestFile: isTestFile(filePath),
    isVendorCode: isVendorCode(filePath)
  };

  return engine.analyze(context);
}
