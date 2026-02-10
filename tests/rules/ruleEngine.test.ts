/**
 * Rule Engine Unit Tests
 * Tests for rule loading, filtering, pattern matching, deduplication, and sorting.
 */

import { RuleEngine } from '../../src/analyzers/core/engine/ruleEngine';
import { Severity, ThreatType, FindingCategory } from '../../src/types';
import { createMockFile, createMockRule, createMockFinding } from '../utils/testHelpers';

// Mock logger
jest.mock('../../src/utils/logger', () => ({
    logger: {
        info: jest.fn(),
        warn: jest.fn(),
        debug: jest.fn(),
        error: jest.fn(),
    },
}));

describe('RuleEngine', () => {
    let engine: RuleEngine;

    beforeEach(() => {
        engine = new RuleEngine();
    });

    describe('loadRules()', () => {
        it('should load only enabled rules', () => {
            const rules = [
                createMockRule({ id: 'R1', enabled: true }),
                createMockRule({ id: 'R2', enabled: false }),
                createMockRule({ id: 'R3', enabled: true }),
            ];

            engine.loadRules(rules);
            const jsRules = engine.getRulesForLanguage('javascript');
            expect(jsRules.length).toBe(2);
        });

        it('should handle empty rules array', () => {
            engine.loadRules([]);
            const rules = engine.getRulesForLanguage('javascript');
            expect(rules).toHaveLength(0);
        });
    });

    describe('getRulesForLanguage()', () => {
        it('should return only rules for the specified language', () => {
            const rules = [
                createMockRule({ id: 'JS-001', languages: ['javascript'] }),
                createMockRule({ id: 'PY-001', languages: ['python'] }),
                createMockRule({ id: 'MULTI-001', languages: ['javascript', 'python'] }),
            ];

            engine.loadRules(rules);

            const jsRules = engine.getRulesForLanguage('javascript');
            expect(jsRules.length).toBe(2);
            expect(jsRules.map(r => r.id)).toContain('JS-001');
            expect(jsRules.map(r => r.id)).toContain('MULTI-001');
        });

        it('should return empty array for unsupported language', () => {
            engine.loadRules([
                createMockRule({ languages: ['javascript'] }),
            ]);

            const rules = engine.getRulesForLanguage('rust');
            expect(rules).toHaveLength(0);
        });
    });

    describe('analyzeFile()', () => {
        it('should detect SQL injection pattern', async () => {
            const sqlRule = createMockRule({
                id: 'SQL-001',
                name: 'SQL Injection',
                languages: ['javascript'],
                threatType: ThreatType.SQL_INJECTION,
                severity: Severity.HIGH,
                patterns: [{
                    type: 'regex',
                    pattern: 'query\\s*\\(.*\\+.*\\)',
                    flags: 'gi',
                }],
            });

            engine.loadRules([sqlRule]);

            const file = createMockFile(
                'const result = db.query("SELECT * FROM users WHERE id = " + userId);',
                { language: 'javascript' }
            );

            const findings = await engine.analyzeFile(file);
            expect(findings.length).toBeGreaterThanOrEqual(1);
            expect(findings[0].threatType).toBe(ThreatType.SQL_INJECTION);
        });

        it('should not match safe code', async () => {
            const sqlRule = createMockRule({
                id: 'SQL-002',
                patterns: [{
                    type: 'regex',
                    pattern: 'query\\s*\\(\\s*["\'].*["\']\\s*\\+',
                    flags: 'gi',
                }],
            });

            engine.loadRules([sqlRule]);

            const file = createMockFile(
                'const result = db.query("SELECT * FROM users WHERE id = ?", [userId]);',
                { language: 'javascript' }
            );

            const findings = await engine.analyzeFile(file);
            expect(findings).toHaveLength(0);
        });

        it('should handle files with no matching rules', async () => {
            engine.loadRules([
                createMockRule({ languages: ['python'] }),
            ]);

            const file = createMockFile('const x = 1;', { language: 'javascript' });
            const findings = await engine.analyzeFile(file);
            expect(findings).toHaveLength(0);
        });

        it('should handle regex errors gracefully', async () => {
            const badRule = createMockRule({
                patterns: [{
                    type: 'regex',
                    pattern: '(?<=invalid', // intentionally broken regex
                    flags: 'gi',
                }],
            });

            engine.loadRules([badRule]);

            const file = createMockFile('test code', { language: 'javascript' });
            // Should not throw
            const findings = await engine.analyzeFile(file);
            expect(findings).toHaveLength(0);
        });
    });

    describe('deduplicateFindings()', () => {
        it('should remove duplicate findings at same location', () => {
            const finding1 = createMockFinding({
                location: { file: 'test.js', startLine: 5, endLine: 5 },
                threatType: ThreatType.SQL_INJECTION,
            });
            const finding2 = createMockFinding({
                location: { file: 'test.js', startLine: 5, endLine: 5 },
                threatType: ThreatType.SQL_INJECTION,
            });
            const finding3 = createMockFinding({
                location: { file: 'test.js', startLine: 10, endLine: 10 },
                threatType: ThreatType.XSS,
            });

            const unique = engine.deduplicateFindings([finding1, finding2, finding3]);
            expect(unique).toHaveLength(2);
        });

        it('should keep findings with different threat types at same location', () => {
            const finding1 = createMockFinding({
                location: { file: 'test.js', startLine: 5, endLine: 5 },
                threatType: ThreatType.SQL_INJECTION,
            });
            const finding2 = createMockFinding({
                location: { file: 'test.js', startLine: 5, endLine: 5 },
                threatType: ThreatType.XSS,
            });

            const unique = engine.deduplicateFindings([finding1, finding2]);
            expect(unique).toHaveLength(2);
        });

        it('should handle empty findings array', () => {
            const unique = engine.deduplicateFindings([]);
            expect(unique).toHaveLength(0);
        });
    });

    describe('sortBySeverity()', () => {
        it('should sort critical first, then high, medium, low, info', () => {
            const findings = [
                createMockFinding({ severity: Severity.LOW }),
                createMockFinding({ severity: Severity.CRITICAL }),
                createMockFinding({ severity: Severity.MEDIUM }),
                createMockFinding({ severity: Severity.HIGH }),
                createMockFinding({ severity: Severity.INFO }),
            ];

            const sorted = engine.sortBySeverity(findings);
            expect(sorted[0].severity).toBe(Severity.CRITICAL);
            expect(sorted[1].severity).toBe(Severity.HIGH);
            expect(sorted[2].severity).toBe(Severity.MEDIUM);
            expect(sorted[3].severity).toBe(Severity.LOW);
            expect(sorted[4].severity).toBe(Severity.INFO);
        });

        it('should not mutate original array', () => {
            const findings = [
                createMockFinding({ severity: Severity.LOW }),
                createMockFinding({ severity: Severity.HIGH }),
            ];

            const sorted = engine.sortBySeverity(findings);
            expect(findings[0].severity).toBe(Severity.LOW); // original unchanged
            expect(sorted[0].severity).toBe(Severity.HIGH);
        });
    });
});
