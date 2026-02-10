/**
 * Base Analyzer
 * Abstract base class for language-specific security analyzers
 * 
 * Implements Template Method Pattern for consistent analysis flow
 * Provides common utilities to reduce code duplication across analyzers
 */

import {
  Analyzer,
  ScannedFile,
  Finding,
  Rule,
  SupportedLanguage,
  Severity,
  ThreatType,
  FindingCategory,
  SecurityStandard
} from '../../types';
import { RuleEngine } from '../core/engine';
import { logger } from '../../utils/logger';
import { generateId, extractCodeContext } from '../../utils';
import { getStandardsForThreat } from '../../rules/standards';

/**
 * Configuration options for creating findings
 */
export interface CreateFindingOptions {
  file: ScannedFile;
  lineNum: number;
  title: string;
  description: string;
  severity: Severity;
  threatType: ThreatType;
  category?: FindingCategory;
  standards?: SecurityStandard[];
  remediation?: string;
  confidence?: number;
  tags?: string[];
  ruleId?: string;
}

/**
 * Pattern match result for shared pattern analysis
 */
export interface PatternMatchResult {
  pattern: RegExp;
  name: string;
  severity: Severity;
  description: string;
  recommendation: string;
  category?: string;
}

/**
 * Base Analyzer Class
 * Provides common functionality for all language analyzers
 * 
 * @example
 * class MyAnalyzer extends BaseAnalyzer {
 *   name = 'My Analyzer';
 *   languages = ['javascript'] as SupportedLanguage[];
 *   version = '1.0.0';
 *   
 *   protected async customAnalysis(file: ScannedFile): Promise<Finding[]> {
 *     // Language-specific analysis logic
 *     return [];
 *   }
 * }
 */
export abstract class BaseAnalyzer implements Analyzer {
  abstract name: string;
  abstract languages: SupportedLanguage[];
  abstract version: string;

  protected ruleEngine: RuleEngine;
  protected initialized: boolean = false;

  /**
   * Constructor with optional dependency injection for RuleEngine
   * @param ruleEngine - Optional RuleEngine instance (useful for testing)
   */
  constructor(ruleEngine?: RuleEngine) {
    this.ruleEngine = ruleEngine || new RuleEngine();
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // LIFECYCLE METHODS
  // ═══════════════════════════════════════════════════════════════════════════

  /**
   * Initialize the analyzer
   */
  async initialize(): Promise<void> {
    logger.debug(`Initializing ${this.name} analyzer...`);
    this.initialized = true;
  }

  /**
   * Cleanup resources
   */
  async cleanup(): Promise<void> {
    logger.debug(`Cleaning up ${this.name} analyzer...`);
    this.initialized = false;
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // TEMPLATE METHOD: analyze()
  // ═══════════════════════════════════════════════════════════════════════════

  /**
   * Main analysis method - Template Method Pattern
   * 
   * Defines the skeleton of the analysis algorithm:
   * 1. beforeAnalyze() - Hook for pre-processing
   * 2. Rule engine analysis
   * 3. performCustomAnalysis() - Language-specific analysis
   * 4. afterAnalyze() - Hook for post-processing
   * 
   * @param file - The file to analyze
   * @param rules - Security rules to apply
   * @returns Array of security findings
   */
  async analyze(file: ScannedFile, rules: Rule[]): Promise<Finding[]> {
    const findings: Finding[] = [];

    // Hook: Pre-processing
    await this.beforeAnalyze(file);

    // Step 1: Filter rules for this analyzer's languages
    const languageRules = this.filterRulesForLanguages(rules);

    // Step 2: Run rule engine analysis
    const ruleFindings = await this.ruleEngine.analyzeFile(file, languageRules);
    findings.push(...ruleFindings);

    // Step 3: Language-specific custom analysis
    const customFindings = await this.performCustomAnalysis(file);
    findings.push(...customFindings);

    // Hook: Post-processing
    const processedFindings = await this.afterAnalyze(findings, file);

    return processedFindings;
  }

  /**
   * Hook called before analysis begins
   * Override to add pre-processing logic
   */
  protected async beforeAnalyze(_file: ScannedFile): Promise<void> {
    // Default: no-op, subclasses can override
  }

  /**
   * Hook called after analysis completes
   * Override to add post-processing logic (e.g., deduplication, filtering)
   */
  protected async afterAnalyze(findings: Finding[], _file: ScannedFile): Promise<Finding[]> {
    // Default: return findings as-is, subclasses can override
    return findings;
  }

  /**
   * Language-specific analysis logic
   * 
   * Subclasses should override this method with their custom analysis.
   * This is used by the Template Method pattern in analyze().
   * 
   * Default implementation returns empty array for backward compatibility
   * during incremental migration. After migration, consider making this abstract.
   * 
   * @param _file - The file to analyze
   * @returns Array of findings from custom analysis
   */
  protected async performCustomAnalysis(_file: ScannedFile): Promise<Finding[]> {
    // Default implementation for backward compatibility
    // Subclasses override this with their language-specific analysis
    return [];
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // FINDING CREATION UTILITIES
  // ═══════════════════════════════════════════════════════════════════════════

  /**
   * Create a standardized Finding object
   * Centralizes Finding creation to ensure consistency across all analyzers
   * 
   * NOTE: Named 'buildFinding' to avoid conflict with existing 'createFinding' 
   * methods in subclasses during incremental migration
   * 
   * @param options - Finding configuration options
   * @returns A properly formatted Finding object
   */
  protected buildFinding(options: CreateFindingOptions): Finding {
    const {
      file,
      lineNum,
      title,
      description,
      severity,
      threatType,
      category = FindingCategory.VULNERABILITY,
      standards,
      remediation = 'Review and fix the identified issue.',
      confidence = 75,
      tags = [],
      ruleId
    } = options;

    const context = extractCodeContext(file.content, lineNum, 2);
    const primaryLanguage = this.languages[0] || 'unknown';

    return {
      id: generateId(),
      ruleId,
      title,
      description,
      severity,
      threatType,
      category,
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
      standards: standards || getStandardsForThreat(threatType),
      remediation,
      confidence,
      analyzer: this.name,
      timestamp: new Date(),
      tags: [primaryLanguage, ...tags]
    };
  }

  /**
   * Create a Finding from a pattern match
   * Simplified method for pattern-based detection
   */
  protected buildFindingFromPatternMatch(
    file: ScannedFile,
    lineNum: number,
    pattern: PatternMatchResult,
    additionalTags: string[] = []
  ): Finding {
    return this.buildFinding({
      file,
      lineNum,
      title: pattern.name,
      description: pattern.description,
      severity: pattern.severity,
      threatType: this.convertCategoryToThreatType(pattern.category || 'Vulnerability'),
      remediation: pattern.recommendation,
      confidence: 80,
      tags: [pattern.category?.toLowerCase().replace(/\s+/g, '-') || 'security', ...additionalTags]
    });
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // COMMON UTILITIES
  // ═══════════════════════════════════════════════════════════════════════════

  /**
   * Check if analyzer supports a language
   */
  supportsLanguage(language: SupportedLanguage): boolean {
    return this.languages.includes(language);
  }

  /**
   * Get analyzer info
   */
  getInfo(): { name: string; languages: SupportedLanguage[]; version: string } {
    return {
      name: this.name,
      languages: this.languages,
      version: this.version
    };
  }

  /**
   * Filter rules to only those applicable to this analyzer's languages
   */
  protected filterRulesForLanguages(rules: Rule[]): Rule[] {
    return rules.filter(rule =>
      this.languages.some(lang => rule.languages.includes(lang))
    );
  }

  /**
   * Calculate line number from character offset in content
   * @param content - File content
   * @param offset - Character offset
   * @returns 1-based line number
   */
  protected calculateLineNumber(content: string, offset: number): number {
    return content.substring(0, offset).split('\n').length;
  }

  /**
   * Mask sensitive data in code snippets for safe display
   * Replaces long strings (potential secrets) with masked versions
   * 
   * @param line - Line of code to mask
   * @returns Line with sensitive data masked
   */
  protected maskSecrets(line: string): string {
    // Mask strings longer than 12 characters that look like secrets
    return line.replace(/(["'])[A-Za-z0-9+/=_-]{12,}(["'])/g, (match, q1, q2) => {
      const inner = match.slice(1, -1);
      if (inner.length > 8) {
        return `${q1}${inner.substring(0, 4)}${'*'.repeat(8)}${q2}`;
      }
      return match;
    });
  }

  /**
   * Map vulnerability category string to ThreatType enum
   * Used for converting pattern categories to typed threat types
   * 
   * @param category - Category string from pattern
   * @returns Corresponding ThreatType enum value
   */
  protected convertCategoryToThreatType(category: string): ThreatType {
    const mapping: Record<string, ThreatType> = {
      'SQL Injection': ThreatType.SQL_INJECTION,
      'Command Injection': ThreatType.COMMAND_INJECTION,
      'XSS': ThreatType.XSS,
      'SSTI': ThreatType.INJECTION,
      'Path Traversal': ThreatType.PATH_TRAVERSAL,
      'XXE': ThreatType.XXE,
      'SSRF': ThreatType.SSRF,
      'Dangerous Function': ThreatType.DANGEROUS_FUNCTION,
      'Deserialization': ThreatType.INSECURE_DESERIALIZATION,
      'JNDI Injection': ThreatType.INJECTION,
      'Cryptography': ThreatType.WEAK_CRYPTOGRAPHY,
      'Credentials': ThreatType.HARDCODED_SECRETS,
      'Vulnerability': ThreatType.VULNERABILITY,
    };
    return mapping[category] || ThreatType.VULNERABILITY;
  }

  /**
   * Check if a line is a comment in the given language
   * Helps reduce false positives by skipping commented code
   * 
   * @param line - Line of code to check
   * @param language - Programming language
   * @returns true if line is a comment
   */
  protected isCommentLine(line: string, language?: string): boolean {
    const trimmed = line.trim();
    const lang = language || this.languages[0];

    switch (lang) {
      case 'python':
        return trimmed.startsWith('#');
      case 'javascript':
      case 'typescript':
      case 'java':
      case 'csharp':
      case 'c':
      case 'cpp':
      case 'php':
        return trimmed.startsWith('//') ||
          trimmed.startsWith('/*') ||
          trimmed.startsWith('*');
      default:
        return trimmed.startsWith('//') || trimmed.startsWith('#');
    }
  }

  /**
   * Extract logical blocks from source code
   * Default implementation for curly-brace languages (C, C++, C#, Java, JS, PHP)
   * 
   * @param content - File content
   * @returns Array of blocks with content and start line
   */
  protected extractLogicalBlocks(content: string): Array<{ content: string; startLine: number; name: string }> {
    const blocks: Array<{ content: string; startLine: number; name: string }> = [];
    const lines = content.split('\n');

    let currentBlockLines: string[] = [];
    let currentBlockStart = 1;
    let braceCount = 0;
    let inBlock = false;

    // Heuristic: identify blocks by top-level curly braces (functions/classes)
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      const lineNum = i + 1;

      const openBraces = (line.match(/\{/g) || []).length;
      const closeBraces = (line.match(/\}/g) || []).length;

      if (!inBlock && openBraces > 0 && braceCount === 0) {
        inBlock = true;
        currentBlockStart = lineNum;
        currentBlockLines = [line];
      } else if (inBlock) {
        currentBlockLines.push(line);
      } else {
        // Top-level lines (not in a named block)
        // Groups these into a 'global' block
        if (blocks.length === 0 || blocks[blocks.length - 1].name !== 'global') {
          blocks.push({ content: line, startLine: lineNum, name: 'global' });
        } else {
          blocks[blocks.length - 1].content += '\n' + line;
        }
      }

      braceCount += openBraces - closeBraces;

      if (inBlock && braceCount === 0 && closeBraces > 0) {
        const blockContent = currentBlockLines.join('\n');
        // Try to find a name for the block (heuristic)
        const nameMatch = currentBlockLines[0].match(/(?:class|function|public|private|static|void|int|string|async)\s+(\w+)/i);
        const name = nameMatch ? nameMatch[1] : 'anonymous-block';

        blocks.push({ content: blockContent, startLine: currentBlockStart, name });
        inBlock = false;
        currentBlockLines = [];
      }
    }

    return blocks.length > 0 ? blocks : [{ content, startLine: 1, name: 'file-content' }];
  }

  /**
   * Extract lines around a match for context
   * @param lines - Array of all lines
   * @param lineNum - 1-based line number of match
   * @param contextSize - Number of lines before/after to include
   * @returns Object with before, match, and after lines
   */
  protected extractContext(
    lines: string[],
    lineNum: number,
    contextSize: number = 2
  ): { before: string[]; line: string; after: string[] } {
    const index = lineNum - 1;
    return {
      before: lines.slice(Math.max(0, index - contextSize), index),
      line: lines[index] || '',
      after: lines.slice(index + 1, index + 1 + contextSize)
    };
  }
}

export default BaseAnalyzer;
