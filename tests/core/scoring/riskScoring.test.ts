/**
 * Risk Scoring Engine Unit Tests
 * Tests for risk score calculation, level determination, distributions,
 * affected files ranking, and security posture metrics.
 */

import { RiskScoringEngine } from '../../../src/analyzers/core/scoring/riskScoring';
import { Severity, FindingCategory, ThreatType } from '../../../src/types';
import { createMockFinding } from '../../utils/testHelpers';

describe('RiskScoringEngine', () => {
    let scoring: RiskScoringEngine;

    beforeEach(() => {
        scoring = new RiskScoringEngine();
    });

    describe('calculateRiskScore()', () => {
        it('should return 0 for no findings', () => {
            const score = scoring.calculateRiskScore([], 10);
            expect(score).toBe(0);
        });

        it('should return higher score for critical findings', () => {
            const criticalFindings = [
                createMockFinding({ severity: Severity.CRITICAL, confidence: 90 }),
            ];
            const lowFindings = [
                createMockFinding({ severity: Severity.LOW, confidence: 90 }),
            ];

            const criticalScore = scoring.calculateRiskScore(criticalFindings, 10);
            const lowScore = scoring.calculateRiskScore(lowFindings, 10);

            expect(criticalScore).toBeGreaterThan(lowScore);
        });

        it('should weight malware findings higher', () => {
            const malwareFinding = [
                createMockFinding({
                    severity: Severity.HIGH,
                    category: FindingCategory.MALWARE,
                    confidence: 80,
                }),
            ];
            const vulnFinding = [
                createMockFinding({
                    severity: Severity.HIGH,
                    category: FindingCategory.VULNERABILITY,
                    confidence: 80,
                }),
            ];

            const malwareScore = scoring.calculateRiskScore(malwareFinding, 10);
            const vulnScore = scoring.calculateRiskScore(vulnFinding, 10);

            expect(malwareScore).toBeGreaterThan(vulnScore);
        });

        it('should normalize score based on project size', () => {
            const findings = [
                createMockFinding({ severity: Severity.MEDIUM, confidence: 80 }),
            ];

            const smallProject = scoring.calculateRiskScore(findings, 5);
            const largeProject = scoring.calculateRiskScore(findings, 1000);

            expect(smallProject).toBeGreaterThan(largeProject);
        });

        it('should cap score at 100', () => {
            const manyFindings = Array.from({ length: 50 }, () =>
                createMockFinding({ severity: Severity.CRITICAL, confidence: 100 })
            );

            const score = scoring.calculateRiskScore(manyFindings, 1);
            expect(score).toBeLessThanOrEqual(100);
        });

        it('should handle findings with undefined confidence', () => {
            const finding = createMockFinding({
                severity: Severity.MEDIUM,
                confidence: undefined as any,
            });

            const score = scoring.calculateRiskScore([finding], 10);
            expect(score).toBeGreaterThan(0);
        });
    });

    describe('getRiskLevel()', () => {
        it('should return safe for very low scores', () => {
            expect(scoring.getRiskLevel(5)).toBe('safe');
        });

        it('should return low for moderate scores', () => {
            expect(scoring.getRiskLevel(15)).toBe('low');
        });

        it('should return medium for mid-range scores', () => {
            expect(scoring.getRiskLevel(35)).toBe('medium');
        });

        it('should return high for high scores', () => {
            expect(scoring.getRiskLevel(55)).toBe('high');
        });

        it('should return critical for very high scores', () => {
            expect(scoring.getRiskLevel(80)).toBe('critical');
        });

        it('should return safe for 0', () => {
            expect(scoring.getRiskLevel(0)).toBe('safe');
        });
    });

    describe('getSeverityDistribution()', () => {
        it('should count findings by severity', () => {
            const findings = [
                createMockFinding({ severity: Severity.CRITICAL }),
                createMockFinding({ severity: Severity.CRITICAL }),
                createMockFinding({ severity: Severity.HIGH }),
                createMockFinding({ severity: Severity.MEDIUM }),
                createMockFinding({ severity: Severity.LOW }),
                createMockFinding({ severity: Severity.INFO }),
                createMockFinding({ severity: Severity.INFO }),
            ];

            const dist = scoring.getSeverityDistribution(findings);

            expect(dist[Severity.CRITICAL]).toBe(2);
            expect(dist[Severity.HIGH]).toBe(1);
            expect(dist[Severity.MEDIUM]).toBe(1);
            expect(dist[Severity.LOW]).toBe(1);
            expect(dist[Severity.INFO]).toBe(2);
        });

        it('should return all zeros for empty findings', () => {
            const dist = scoring.getSeverityDistribution([]);

            Object.values(dist).forEach(count => {
                expect(count).toBe(0);
            });
        });
    });

    describe('getCategoryDistribution()', () => {
        it('should count findings by category', () => {
            const findings = [
                createMockFinding({ category: FindingCategory.VULNERABILITY }),
                createMockFinding({ category: FindingCategory.VULNERABILITY }),
                createMockFinding({ category: FindingCategory.MALWARE }),
                createMockFinding({ category: FindingCategory.SECRET }),
            ];

            const dist = scoring.getCategoryDistribution(findings);

            expect(dist[FindingCategory.VULNERABILITY]).toBe(2);
            expect(dist[FindingCategory.MALWARE]).toBe(1);
            expect(dist[FindingCategory.SECRET]).toBe(1);
        });
    });

    describe('getTopAffectedFiles()', () => {
        it('should rank files by critical count then total count', () => {
            const findings = [
                createMockFinding({ location: { file: 'a.js', startLine: 1, endLine: 1 }, severity: Severity.CRITICAL }),
                createMockFinding({ location: { file: 'a.js', startLine: 2, endLine: 2 }, severity: Severity.CRITICAL }),
                createMockFinding({ location: { file: 'b.js', startLine: 1, endLine: 1 }, severity: Severity.LOW }),
                createMockFinding({ location: { file: 'b.js', startLine: 2, endLine: 2 }, severity: Severity.LOW }),
                createMockFinding({ location: { file: 'b.js', startLine: 3, endLine: 3 }, severity: Severity.LOW }),
            ];

            const top = scoring.getTopAffectedFiles(findings);
            expect(top[0].file).toBe('a.js');
            expect(top[0].criticalCount).toBe(2);
            expect(top[1].file).toBe('b.js');
            expect(top[1].count).toBe(3);
        });

        it('should respect limit parameter', () => {
            const findings = Array.from({ length: 20 }, (_, i) =>
                createMockFinding({ location: { file: `file${i}.js`, startLine: 1, endLine: 1 } })
            );

            const top = scoring.getTopAffectedFiles(findings, 5);
            expect(top).toHaveLength(5);
        });
    });

    describe('getThreatTypeDistribution()', () => {
        it('should count findings by threat type', () => {
            const findings = [
                createMockFinding({ threatType: ThreatType.SQL_INJECTION }),
                createMockFinding({ threatType: ThreatType.SQL_INJECTION }),
                createMockFinding({ threatType: ThreatType.XSS }),
            ];

            const dist = scoring.getThreatTypeDistribution(findings);
            expect(dist[ThreatType.SQL_INJECTION]).toBe(2);
            expect(dist[ThreatType.XSS]).toBe(1);
        });
    });

    describe('calculateSecurityPosture()', () => {
        it('should return A+ grade for no findings', () => {
            const posture = scoring.calculateSecurityPosture([], 100, 10000);
            expect(posture.grade).toBe('A+');
            expect(posture.score).toBe(100);
            expect(posture.findingsPerKLOC).toBe(0);
            expect(posture.criticalRatio).toBe(0);
        });

        it('should calculate findings per KLOC correctly', () => {
            const findings = Array.from({ length: 10 }, () =>
                createMockFinding({ severity: Severity.LOW })
            );

            const posture = scoring.calculateSecurityPosture(findings, 20, 5000);
            // 10 findings / 5 KLOC = 2.0
            expect(posture.findingsPerKLOC).toBe(2);
        });

        it('should calculate critical ratio', () => {
            const findings = [
                createMockFinding({ severity: Severity.CRITICAL }),
                createMockFinding({ severity: Severity.HIGH }),
                createMockFinding({ severity: Severity.LOW }),
                createMockFinding({ severity: Severity.LOW }),
            ];

            const posture = scoring.calculateSecurityPosture(findings, 10, 1000);
            expect(posture.criticalRatio).toBe(0.5); // 2/4
        });
    });
});
