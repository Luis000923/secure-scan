/**
 * Rule Engine
 * Core engine for running security rules against code
 */

import {
  Rule,
  Finding,
  ScannedFile,
  Severity,
  ThreatType,
  FindingCategory,
  SourceLocation,
  CodeSnippet
} from '../../types';
import { generateId, extractCodeContext } from '../../utils';
import { getStandardsForThreat } from '../../rules/standards';
import { logger } from '../../utils/logger';

/**
 * Pattern match result
 */
interface PatternMatch {
  matched: boolean;
  line: number;
  column: number;
  matchedText: string;
  groups?: Record<string, string>;
}

/**
 * Rule Engine Class
 */
export class RuleEngine {
  private rules: Rule[];

  constructor() {
    this.rules = [];
  }

  /**
   * Load rules for analysis
   */
  loadRules(rules: Rule[]): void {
    this.rules = rules.filter(r => r.enabled);
    logger.info(`📋 Loaded ${this.rules.length} active rules`);
  }

  /**
   * Get rules for a specific language
   */
  getRulesForLanguage(language: string): Rule[] {
    return this.rules.filter(rule =>
      rule.languages.includes(language as any) ||
      rule.languages.includes('*' as any)
    );
  }

  /**
   * Run rules against a file
   */
  async analyzeFile(file: ScannedFile, rules?: Rule[]): Promise<Finding[]> {
    const findings: Finding[] = [];
    const applicableRules = rules || this.getRulesForLanguage(file.language || '');

    for (const rule of applicableRules) {
      try {
        const ruleFindings = await this.runRule(rule, file);
        findings.push(...ruleFindings);
      } catch (error) {
        logger.debug(`Error running rule ${rule.id}: ${error}`);
      }
    }

    return findings;
  }

  /**
   * Run a single rule against a file
   */
  private async runRule(rule: Rule, file: ScannedFile): Promise<Finding[]> {
    const findings: Finding[] = [];

    for (const pattern of rule.patterns) {
      if (pattern.type === 'regex') {
        const matches = this.matchRegex(file.content, pattern.pattern, pattern.flags);
        
        for (const match of matches) {
          const finding = this.createFinding(rule, file, match);
          findings.push(finding);
        }
      }
    }

    return findings;
  }

  /**
   * Match regex pattern against content
   */
  private matchRegex(content: string, pattern: string, flags: string = 'gim'): PatternMatch[] {
    const matches: PatternMatch[] = [];
    const lines = content.split('\n');
    
    try {
      const regex = new RegExp(pattern, flags);
      
      let lineOffset = 0;
      for (let lineNum = 0; lineNum < lines.length; lineNum++) {
        const line = lines[lineNum];
        let match: RegExpExecArray | null;
        
        // Reset regex for each line
        const lineRegex = new RegExp(pattern, flags.replace('g', '') + 'g');
        
        while ((match = lineRegex.exec(line)) !== null) {
          matches.push({
            matched: true,
            line: lineNum + 1, // 1-indexed
            column: match.index + 1,
            matchedText: match[0],
            groups: match.groups
          });
          
          // Prevent infinite loop on zero-width matches
          if (match[0].length === 0) {
            lineRegex.lastIndex++;
          }
        }
        
        lineOffset += line.length + 1;
      }
    } catch (error) {
      logger.debug(`Invalid regex pattern: ${pattern}`);
    }

    return matches;
  }

  /**
   * Create a finding from a rule match
   */
  private createFinding(rule: Rule, file: ScannedFile, match: PatternMatch): Finding {
    const context = extractCodeContext(file.content, match.line, 3);
    
    const location: SourceLocation = {
      file: file.relativePath,
      startLine: match.line,
      endLine: match.line,
      startColumn: match.column,
      endColumn: match.column + match.matchedText.length
    };

    const snippet: CodeSnippet = {
      code: context.code,
      contextBefore: context.contextBefore,
      contextAfter: context.contextAfter,
      highlight: {
        start: match.column - 1,
        end: match.column - 1 + match.matchedText.length
      }
    };

    return {
      id: generateId(),
      title: rule.name,
      description: rule.description,
      severity: rule.severity,
      threatType: rule.threatType,
      category: rule.category,
      location,
      snippet,
      standards: rule.standards.length > 0 
        ? rule.standards 
        : getStandardsForThreat(rule.threatType),
      remediation: rule.remediation,
      confidence: 85, // Default confidence for regex matches
      analyzer: 'rule-engine',
      timestamp: new Date(),
      tags: rule.tags
    };
  }

  /**
   * Deduplicate findings
   */
  deduplicateFindings(findings: Finding[]): Finding[] {
    const seen = new Set<string>();
    const unique: Finding[] = [];

    for (const finding of findings) {
      const key = `${finding.location.file}:${finding.location.startLine}:${finding.threatType}`;
      
      if (!seen.has(key)) {
        seen.add(key);
        unique.push(finding);
      }
    }

    return unique;
  }

  /**
   * Sort findings by severity
   */
  sortBySeverity(findings: Finding[]): Finding[] {
    const severityOrder: Record<Severity, number> = {
      [Severity.CRITICAL]: 0,
      [Severity.HIGH]: 1,
      [Severity.MEDIUM]: 2,
      [Severity.LOW]: 3,
      [Severity.INFO]: 4
    };

    return [...findings].sort((a, b) => 
      severityOrder[a.severity] - severityOrder[b.severity]
    );
  }
}

export default RuleEngine;
