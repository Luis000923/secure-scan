/**
 * @fileoverview Vulnerability Score Calculator
 * @module rules/vulnerabilities/scoring
 * 
 * Dynamic scoring system for vulnerability detection that calculates risk scores
 * based on multiple factors including pattern matches, taint analysis,
 * exploitability, impact, and context.
 */

import {
  VulnerabilityRule,
  VulnerabilityScore,
  VulnerabilityScoreBreakdown,
  VulnerabilitySeverity,
  PatternMatch,
  AnalysisContext,
  TaintFlow,
  IScoreCalculator,
  ConfidenceLevel,
  ImpactAssessment,
  ExploitabilityAssessment
} from '../types';
import {
  SCORE_THRESHOLDS,
  RISK_LEVELS,
  DEFAULT_SCORING_WEIGHTS,
  LIMITS
} from '../constants';

// ============================================================================
// SCORE CALCULATOR IMPLEMENTATION
// ============================================================================

/**
 * Vulnerability Score Calculator
 * Implements dynamic scoring based on multiple risk factors
 */
export class VulnerabilityScoreCalculator implements IScoreCalculator {
  private weights: typeof DEFAULT_SCORING_WEIGHTS;

  constructor(customWeights?: Partial<typeof DEFAULT_SCORING_WEIGHTS>) {
    this.weights = { ...DEFAULT_SCORING_WEIGHTS, ...customWeights };
  }

  /**
   * Calculate vulnerability score for a finding
   */
  calculateScore(
    rule: VulnerabilityRule,
    matches: PatternMatch[],
    context: AnalysisContext,
    taintFlow?: TaintFlow
  ): VulnerabilityScore {
    const breakdown = this.calculateBreakdown(rule, matches, context, taintFlow);
    const totalScore = this.calculateTotalScore(breakdown);
    const severity = this.scoreToSeverity(totalScore);
    const riskLevel = this.scoreToRiskLevel(totalScore);

    return {
      score: Math.round(totalScore),
      breakdown,
      calculatedSeverity: severity,
      riskLevel,
      explanation: this.generateExplanation(breakdown, matches.length, !!taintFlow)
    };
  }

  /**
   * Calculate score breakdown
   */
  private calculateBreakdown(
    rule: VulnerabilityRule,
    matches: PatternMatch[],
    context: AnalysisContext,
    taintFlow?: TaintFlow
  ): VulnerabilityScoreBreakdown {
    // Base score from rule definition
    const baseScore = rule.baseScore ?? this.getDefaultBaseScore(rule.severity);

    // Pattern match score
    const patternScore = this.calculatePatternScore(matches, rule);

    // Taint analysis score
    const taintScore = this.calculateTaintScore(taintFlow);

    // Exploitability score
    const exploitabilityScore = this.calculateExploitabilityScore(rule.exploitability);

    // Impact score
    const impactScore = this.calculateImpactScore(rule.impact);

    // Context score
    const contextScore = this.calculateContextScore(context, rule);

    // Correlation boost from related findings
    const correlationBoost = this.calculateCorrelationBoost(
      rule,
      context.previousFindings || [],
      context.relatedFindings || []
    );

    // False positive penalty
    const falsePositivePenalty = this.calculateFalsePositivePenalty(
      rule,
      context,
      matches
    );

    return {
      baseScore,
      patternScore,
      taintScore,
      exploitabilityScore,
      impactScore,
      contextScore,
      correlationBoost,
      falsePositivePenalty,
      totalScore: 0 // Will be calculated
    };
  }

  /**
   * Calculate total score from breakdown
   */
  private calculateTotalScore(breakdown: VulnerabilityScoreBreakdown): number {
    const weighted = (
      breakdown.baseScore * 0.25 +
      breakdown.patternScore * this.weights.patternCount +
      breakdown.taintScore * this.weights.taintFlow +
      breakdown.exploitabilityScore * this.weights.exploitability +
      breakdown.impactScore * this.weights.impact +
      breakdown.contextScore * this.weights.context +
      breakdown.correlationBoost
    );

    const penalized = weighted - breakdown.falsePositivePenalty;
    const total = Math.max(0, Math.min(100, penalized));
    
    // Update breakdown with total
    breakdown.totalScore = total;
    
    return total;
  }

  /**
   * Get default base score from severity
   */
  private getDefaultBaseScore(severity: VulnerabilitySeverity): number {
    switch (severity) {
      case VulnerabilitySeverity.CRITICAL: return 85;
      case VulnerabilitySeverity.HIGH: return 70;
      case VulnerabilitySeverity.MEDIUM: return 50;
      case VulnerabilitySeverity.LOW: return 30;
      case VulnerabilitySeverity.INFO: return 15;
      default: return 40;
    }
  }

  /**
   * Calculate score from pattern matches
   */
  private calculatePatternScore(
    matches: PatternMatch[],
    rule: VulnerabilityRule
  ): number {
    if (matches.length === 0) return 0;

    // Base score for having any match
    let score = 25;

    // Bonus for multiple matches (diminishing returns)
    const matchBonus = Math.min(matches.length * 3, 20);
    score += matchBonus;

    // Bonus for matches from different patterns
    const uniquePatterns = new Set(
      matches.map(m => m.pattern.patternId || JSON.stringify(m.pattern))
    );
    const diversityBonus = Math.min(uniquePatterns.size * 8, 15);
    score += diversityBonus;

    // Weight by pattern weights if defined
    const weightedSum = matches.reduce((sum, match) => {
      return sum + (match.pattern.weight ?? 1);
    }, 0);
    const avgWeight = weightedSum / matches.length;
    score *= avgWeight;

    return Math.min(score, 100);
  }

  /**
   * Calculate taint analysis score
   */
  private calculateTaintScore(taintFlow?: TaintFlow): number {
    if (!taintFlow) return 0;

    let score = 50; // Base score for having a taint flow

    // Boost for exploitable flows
    if (taintFlow.isExploitable) {
      score += 30;
    }

    // Boost based on confidence
    switch (taintFlow.confidence) {
      case ConfidenceLevel.CONFIRMED:
        score += 20;
        break;
      case ConfidenceLevel.HIGH:
        score += 15;
        break;
      case ConfidenceLevel.MEDIUM:
        score += 10;
        break;
      case ConfidenceLevel.LOW:
        score += 5;
        break;
    }

    // Penalty if sanitized
    if (taintFlow.sanitizers.length > 0) {
      // Reduce score based on sanitizer effectiveness
      const avgEffectiveness = taintFlow.sanitizers.reduce(
        (sum, s) => sum + (s.effectiveness ?? 80), 0
      ) / taintFlow.sanitizers.length;
      score -= avgEffectiveness * 0.5;
    }

    // Bonus for shorter paths (more direct = more likely exploitable)
    if (taintFlow.path.length <= 3) {
      score += 10;
    } else if (taintFlow.path.length <= 5) {
      score += 5;
    }

    return Math.max(0, Math.min(score, 100));
  }

  /**
   * Calculate exploitability score based on CVSS-like factors
   */
  private calculateExploitabilityScore(
    exploitability?: ExploitabilityAssessment
  ): number {
    if (!exploitability) return 50; // Default middle score

    let score = 0;

    // Attack Vector (0-40 points)
    switch (exploitability.attackVector) {
      case 'network':
        score += 40;
        break;
      case 'adjacent':
        score += 30;
        break;
      case 'local':
        score += 20;
        break;
      case 'physical':
        score += 10;
        break;
    }

    // Attack Complexity (0-20 points)
    switch (exploitability.attackComplexity) {
      case 'low':
        score += 20;
        break;
      case 'high':
        score += 10;
        break;
    }

    // Privileges Required (0-20 points)
    switch (exploitability.privilegesRequired) {
      case 'none':
        score += 20;
        break;
      case 'low':
        score += 15;
        break;
      case 'high':
        score += 5;
        break;
    }

    // User Interaction (0-20 points)
    switch (exploitability.userInteraction) {
      case 'none':
        score += 20;
        break;
      case 'required':
        score += 10;
        break;
    }

    // Known exploits bonus
    if (exploitability.knownExploits) {
      score = Math.min(score + 10, 100);
    }

    return score;
  }

  /**
   * Calculate impact score based on CIA triad
   */
  private calculateImpactScore(impact?: ImpactAssessment): number {
    if (!impact) return 50; // Default middle score

    let score = 0;

    // Confidentiality (0-33 points)
    switch (impact.confidentiality) {
      case 'high':
        score += 33;
        break;
      case 'low':
        score += 17;
        break;
    }

    // Integrity (0-33 points)
    switch (impact.integrity) {
      case 'high':
        score += 33;
        break;
      case 'low':
        score += 17;
        break;
    }

    // Availability (0-34 points)
    switch (impact.availability) {
      case 'high':
        score += 34;
        break;
      case 'low':
        score += 17;
        break;
    }

    // Scope change bonus
    if (impact.scope === 'changed') {
      score = Math.min(score + 10, 100);
    }

    return score;
  }

  /**
   * Calculate context-based score adjustments
   */
  private calculateContextScore(
    context: AnalysisContext,
    rule: VulnerabilityRule
  ): number {
    let score = 50; // Neutral base

    // Production code boost
    if (context.isProductionCode) {
      score += rule.contextConditions?.productionBoost ?? 15;
    }

    // Test code penalty
    if (context.isTestFile) {
      score -= rule.contextConditions?.testCodePenalty ?? 30;
    }

    // Vendor code penalty
    if (context.isVendorCode) {
      score -= 20;
    }

    // Sensitive data boost
    if (context.handlesSensitiveData) {
      score += rule.contextConditions?.sensitiveDataBoost ?? 20;
    }

    // File pattern adjustments
    if (rule.contextConditions?.filePatterns && context.filePath) {
      for (const { pattern, severityAdjustment } of rule.contextConditions.filePatterns) {
        if (new RegExp(pattern).test(context.filePath)) {
          score += severityAdjustment;
        }
      }
    }

    return Math.max(0, Math.min(score, 100));
  }

  /**
   * Calculate correlation boost from related findings
   */
  private calculateCorrelationBoost(
    rule: VulnerabilityRule,
    previousFindings: any[],
    relatedFindings: any[]
  ): number {
    if (!rule.correlation?.amplifyWith) return 0;

    let boost = 0;
    const allRelatedRuleIds = [
      ...previousFindings.map(f => f.ruleId),
      ...relatedFindings.map(f => f.ruleId)
    ];

    for (const amplifyRuleId of rule.correlation.amplifyWith) {
      if (allRelatedRuleIds.includes(amplifyRuleId)) {
        boost += rule.correlation.severityBoost ?? 10;
      }
    }

    return Math.min(boost, 30);
  }

  /**
   * Calculate false positive penalty
   */
  private calculateFalsePositivePenalty(
    rule: VulnerabilityRule,
    context: AnalysisContext,
    matches: PatternMatch[]
  ): number {
    let penalty = 0;

    // Check for false positive patterns
    if (rule.falsePositivePatterns && rule.falsePositivePatterns.length > 0) {
      for (const fpPattern of rule.falsePositivePatterns) {
        // Simple check - in real implementation, would use pattern matching
        penalty += 15;
      }
    }

    // Test file penalty
    if (context.isTestFile) {
      penalty += 10;
    }

    // Vendor code penalty
    if (context.isVendorCode) {
      penalty += 20;
    }

    return Math.min(penalty, 50);
  }

  /**
   * Convert score to severity level
   */
  private scoreToSeverity(score: number): VulnerabilitySeverity {
    if (score >= SCORE_THRESHOLDS.CRITICAL) return VulnerabilitySeverity.CRITICAL;
    if (score >= SCORE_THRESHOLDS.HIGH) return VulnerabilitySeverity.HIGH;
    if (score >= SCORE_THRESHOLDS.MEDIUM) return VulnerabilitySeverity.MEDIUM;
    if (score >= SCORE_THRESHOLDS.LOW) return VulnerabilitySeverity.LOW;
    return VulnerabilitySeverity.INFO;
  }

  /**
   * Convert score to risk level description
   */
  private scoreToRiskLevel(score: number): 'critical' | 'high' | 'medium' | 'low' | 'minimal' {
    if (score >= SCORE_THRESHOLDS.CRITICAL) return RISK_LEVELS.CRITICAL;
    if (score >= SCORE_THRESHOLDS.HIGH) return RISK_LEVELS.HIGH;
    if (score >= SCORE_THRESHOLDS.MEDIUM) return RISK_LEVELS.MEDIUM;
    if (score >= SCORE_THRESHOLDS.LOW) return RISK_LEVELS.LOW;
    return RISK_LEVELS.MINIMAL;
  }

  /**
   * Generate human-readable explanation of the score
   */
  private generateExplanation(
    breakdown: VulnerabilityScoreBreakdown,
    matchCount: number,
    hasTaintFlow: boolean
  ): string {
    const factors: string[] = [];

    factors.push(`Base rule score: ${breakdown.baseScore.toFixed(0)}`);
    
    if (matchCount > 0) {
      factors.push(`Pattern matches (${matchCount}): +${breakdown.patternScore.toFixed(0)}`);
    }

    if (hasTaintFlow) {
      factors.push(`Confirmed taint flow: +${breakdown.taintScore.toFixed(0)}`);
    }

    if (breakdown.exploitabilityScore > 50) {
      factors.push(`High exploitability: +${(breakdown.exploitabilityScore - 50).toFixed(0)}`);
    }

    if (breakdown.impactScore > 50) {
      factors.push(`High impact: +${(breakdown.impactScore - 50).toFixed(0)}`);
    }

    if (breakdown.contextScore > 50) {
      factors.push(`Context factors: +${(breakdown.contextScore - 50).toFixed(0)}`);
    } else if (breakdown.contextScore < 50) {
      factors.push(`Context factors: ${(breakdown.contextScore - 50).toFixed(0)}`);
    }

    if (breakdown.correlationBoost > 0) {
      factors.push(`Correlated findings: +${breakdown.correlationBoost.toFixed(0)}`);
    }

    if (breakdown.falsePositivePenalty > 0) {
      factors.push(`False positive indicators: -${breakdown.falsePositivePenalty.toFixed(0)}`);
    }

    factors.push(`Total score: ${breakdown.totalScore.toFixed(0)}/100`);

    return factors.join('\n');
  }

  /**
   * Calculate CVSS-like base score
   */
  calculateCvssBaseScore(
    impact: ImpactAssessment,
    exploitability: ExploitabilityAssessment
  ): number {
    const impactScore = this.calculateImpactScore(impact) / 100;
    const exploitabilityScore = this.calculateExploitabilityScore(exploitability) / 100;

    // Simplified CVSS-like formula
    const baseScore = Math.min(
      10,
      (impactScore * 6 + exploitabilityScore * 4)
    );

    return Math.round(baseScore * 10) / 10;
  }
}

// ============================================================================
// EXPORTS
// ============================================================================

export default VulnerabilityScoreCalculator;
