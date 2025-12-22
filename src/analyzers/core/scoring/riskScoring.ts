/**
 * Risk Scoring Engine
 * Calculates risk scores and severity levels for scan results
 */

import { Finding, Severity, ScanResult, FindingCategory } from '../../../types';
import { severityToNumber } from '../../../utils';

/**
 * Risk weights for different factors
 */
const SEVERITY_WEIGHTS: Record<Severity, number> = {
  [Severity.CRITICAL]: 100,
  [Severity.HIGH]: 70,
  [Severity.MEDIUM]: 40,
  [Severity.LOW]: 15,
  [Severity.INFO]: 5
};

/**
 * Category weights
 */
const CATEGORY_WEIGHTS: Record<FindingCategory, number> = {
  [FindingCategory.MALWARE]: 1.5,
  [FindingCategory.VULNERABILITY]: 1.0,
  [FindingCategory.CODE_SMELL]: 0.5,
  [FindingCategory.BEST_PRACTICE]: 0.3
};

/**
 * Risk level thresholds
 */
const RISK_THRESHOLDS = {
  safe: 10,
  low: 30,
  medium: 50,
  high: 75
};

/**
 * Risk Scoring Engine Class
 */
export class RiskScoringEngine {
  /**
   * Calculate overall risk score for findings
   */
  calculateRiskScore(findings: Finding[], totalFiles: number): number {
    if (findings.length === 0) {
      return 0;
    }

    let totalScore = 0;

    for (const finding of findings) {
      const severityWeight = SEVERITY_WEIGHTS[finding.severity];
      const categoryWeight = CATEGORY_WEIGHTS[finding.category];
      const confidenceMultiplier = finding.confidence / 100;

      totalScore += severityWeight * categoryWeight * confidenceMultiplier;
    }

    // Normalize score based on codebase size
    // More files = slightly lower weight per finding
    const sizeNormalizer = Math.log10(Math.max(totalFiles, 1)) + 1;
    
    // Calculate normalized score (0-100)
    const normalizedScore = Math.min(100, (totalScore / sizeNormalizer) / 2);

    return Math.round(normalizedScore);
  }

  /**
   * Determine risk level from score
   */
  getRiskLevel(score: number): 'safe' | 'low' | 'medium' | 'high' | 'critical' {
    if (score >= RISK_THRESHOLDS.high) return 'critical';
    if (score >= RISK_THRESHOLDS.medium) return 'high';
    if (score >= RISK_THRESHOLDS.low) return 'medium';
    if (score >= RISK_THRESHOLDS.safe) return 'low';
    return 'safe';
  }

  /**
   * Get severity distribution
   */
  getSeverityDistribution(findings: Finding[]): Record<Severity, number> {
    const distribution: Record<Severity, number> = {
      [Severity.CRITICAL]: 0,
      [Severity.HIGH]: 0,
      [Severity.MEDIUM]: 0,
      [Severity.LOW]: 0,
      [Severity.INFO]: 0
    };

    for (const finding of findings) {
      distribution[finding.severity]++;
    }

    return distribution;
  }

  /**
   * Get category distribution
   */
  getCategoryDistribution(findings: Finding[]): Record<FindingCategory, number> {
    const distribution: Record<FindingCategory, number> = {
      [FindingCategory.MALWARE]: 0,
      [FindingCategory.VULNERABILITY]: 0,
      [FindingCategory.CODE_SMELL]: 0,
      [FindingCategory.BEST_PRACTICE]: 0
    };

    for (const finding of findings) {
      distribution[finding.category]++;
    }

    return distribution;
  }

  /**
   * Get top affected files
   */
  getTopAffectedFiles(findings: Finding[], limit: number = 10): Array<{ file: string; count: number; criticalCount: number }> {
    const fileMap = new Map<string, { count: number; criticalCount: number }>();

    for (const finding of findings) {
      const current = fileMap.get(finding.location.file) || { count: 0, criticalCount: 0 };
      current.count++;
      if (finding.severity === Severity.CRITICAL || finding.severity === Severity.HIGH) {
        current.criticalCount++;
      }
      fileMap.set(finding.location.file, current);
    }

    return Array.from(fileMap.entries())
      .map(([file, stats]) => ({ file, ...stats }))
      .sort((a, b) => b.criticalCount - a.criticalCount || b.count - a.count)
      .slice(0, limit);
  }

  /**
   * Get threat type distribution
   */
  getThreatTypeDistribution(findings: Finding[]): Record<string, number> {
    const distribution: Record<string, number> = {};

    for (const finding of findings) {
      distribution[finding.threatType] = (distribution[finding.threatType] || 0) + 1;
    }

    return distribution;
  }

  /**
   * Calculate security posture metrics
   */
  calculateSecurityPosture(findings: Finding[], totalFiles: number, totalLines: number): {
    score: number;
    grade: string;
    findingsPerKLOC: number;
    criticalRatio: number;
  } {
    const score = 100 - this.calculateRiskScore(findings, totalFiles);
    
    // Calculate grade
    let grade: string;
    if (score >= 90) grade = 'A+';
    else if (score >= 85) grade = 'A';
    else if (score >= 80) grade = 'A-';
    else if (score >= 75) grade = 'B+';
    else if (score >= 70) grade = 'B';
    else if (score >= 65) grade = 'B-';
    else if (score >= 60) grade = 'C+';
    else if (score >= 55) grade = 'C';
    else if (score >= 50) grade = 'C-';
    else if (score >= 40) grade = 'D';
    else grade = 'F';

    // Findings per 1000 lines of code
    const kloc = totalLines / 1000;
    const findingsPerKLOC = kloc > 0 ? findings.length / kloc : 0;

    // Ratio of critical/high findings
    const criticalCount = findings.filter(f => 
      f.severity === Severity.CRITICAL || f.severity === Severity.HIGH
    ).length;
    const criticalRatio = findings.length > 0 ? criticalCount / findings.length : 0;

    return {
      score: Math.round(score),
      grade,
      findingsPerKLOC: Math.round(findingsPerKLOC * 100) / 100,
      criticalRatio: Math.round(criticalRatio * 100) / 100
    };
  }
}

export default RiskScoringEngine;
