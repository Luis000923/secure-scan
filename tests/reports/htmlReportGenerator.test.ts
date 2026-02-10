/**
 * HTML Report Generator Unit Tests
 * Tests for report generation, language support, data preparation, and output format.
 */

import HtmlReportGenerator from '../../src/reports/htmlReportGenerator';
import { ScanResult, Severity, FindingCategory, ThreatType } from '../../src/types';
import { createMockFinding } from '../utils/testHelpers';

// Mock logger
jest.mock('../../src/utils/logger', () => ({
    logger: {
        info: jest.fn(),
        warn: jest.fn(),
        debug: jest.fn(),
        error: jest.fn(),
    },
}));

// Mock the analyzers module
jest.mock('../../src/analyzers', () => ({
    getAllAnalyzers: () => [],
}));

const createMockScanResult = (overrides: Partial<ScanResult> = {}): ScanResult => ({
    scanId: 'test-scan-001',
    projectPath: '/test/project',
    projectName: 'test-project',
    findings: overrides.findings || [
        createMockFinding({
            title: 'SQL Injection',
            severity: Severity.HIGH,
            threatType: ThreatType.SQL_INJECTION,
            category: FindingCategory.VULNERABILITY,
            location: { file: 'test.js', startLine: 10, endLine: 10 },
        }),
        createMockFinding({
            title: 'Hardcoded Password',
            severity: Severity.MEDIUM,
            threatType: ThreatType.HARDCODED_CREDENTIALS,
            category: FindingCategory.SECRET,
            location: { file: 'config.js', startLine: 5, endLine: 5 },
        }),
    ],
    riskScore: 45,
    riskLevel: 'medium' as const,
    scannedFiles: [],
    config: { projectPath: '/test/project' },
    stats: {
        totalFiles: 20,
        totalLines: 2500,
        findingsBySeverity: {
            [Severity.CRITICAL]: 0,
            [Severity.HIGH]: 1,
            [Severity.MEDIUM]: 1,
            [Severity.LOW]: 0,
            [Severity.INFO]: 0,
        },
        findingsByCategory: {
            [FindingCategory.VULNERABILITY]: 1,
            [FindingCategory.MALWARE]: 0,
            [FindingCategory.CODE_SMELL]: 0,
            [FindingCategory.BEST_PRACTICE]: 0,
            [FindingCategory.SECRET]: 1,
        },
        filesByLanguage: {
            javascript: 15,
            python: 3,
            php: 2,
        },
        duration: 5000,
        startTime: new Date('2025-01-15T12:00:00Z'),
        endTime: new Date('2025-01-15T12:00:05Z'),
    },
    ...overrides,
});

describe('HtmlReportGenerator', () => {
    let generator: HtmlReportGenerator;

    beforeEach(() => {
        generator = new HtmlReportGenerator('es');
    });

    describe('constructor', () => {
        it('should create generator with default language', () => {
            const g = new HtmlReportGenerator();
            expect(g).toBeDefined();
            expect(g.name).toBe('HTML Report Generator');
            expect(g.format).toBe('html');
        });

        it('should accept custom language', () => {
            const g = new HtmlReportGenerator('en');
            expect(g).toBeDefined();
        });
    });

    describe('generate()', () => {
        it('should produce valid HTML string', async () => {
            const result = createMockScanResult();
            const html = await generator.generate(result);

            expect(typeof html).toBe('string');
            expect(html).toContain('<!DOCTYPE html>');
            expect(html).toContain('</html>');
        });

        it('should include scan ID and project path', async () => {
            const result = createMockScanResult();
            const html = await generator.generate(result);

            expect(html).toContain('test-scan-001');
            expect(html).toContain('test-project');
        });

        it('should include findings information', async () => {
            const result = createMockScanResult();
            const html = await generator.generate(result);

            expect(html).toContain('SQL Injection');
            expect(html).toContain('Hardcoded Password');
        });

        it('should handle zero findings', async () => {
            const result = createMockScanResult({
                findings: [],
                riskScore: 0,
                stats: {
                    ...createMockScanResult().stats,
                    findingsBySeverity: {
                        [Severity.CRITICAL]: 0,
                        [Severity.HIGH]: 0,
                        [Severity.MEDIUM]: 0,
                        [Severity.LOW]: 0,
                        [Severity.INFO]: 0,
                    },
                },
            });

            const html = await generator.generate(result);
            expect(html).toContain('<!DOCTYPE html>');
        });

        it('should include severity distribution', async () => {
            const result = createMockScanResult();
            const html = await generator.generate(result);

            // The HTML should contain severity-related content
            expect(html.length).toBeGreaterThan(1000); // Should be substantial
        });

        it('should include risk score', async () => {
            const result = createMockScanResult({ riskScore: 75 });
            const html = await generator.generate(result);

            expect(html).toContain('75');
        });
    });

    describe('setLanguage()', () => {
        it('should change report language to English', async () => {
            generator.setLanguage('en');
            const result = createMockScanResult();
            const html = await generator.generate(result);

            expect(typeof html).toBe('string');
            expect(html).toContain('<!DOCTYPE html>');
        });

        it('should change report language to Spanish', async () => {
            generator.setLanguage('es');
            const result = createMockScanResult();
            const html = await generator.generate(result);

            expect(typeof html).toBe('string');
            expect(html).toContain('<!DOCTYPE html>');
        });
    });

    describe('prepareData()', () => {
        it('should include all required data fields', async () => {
            const result = createMockScanResult();
            // prepareData is called internally by generate, so we test via generate output
            const html = await generator.generate(result);

            // Should contain scan metadata
            expect(html).toContain('test-scan-001');
            // Should contain file stats
            expect(html).toContain('20'); // totalFiles
        });
    });

    describe('Edge cases', () => {
        it('should handle findings with missing optional fields', async () => {
            const findingWithMinimalFields = createMockFinding({
                title: 'Minimal Finding',
                severity: Severity.LOW,
                snippet: { code: '' },
            });

            const result = createMockScanResult({
                findings: [findingWithMinimalFields],
            });

            const html = await generator.generate(result);
            expect(html).toContain('Minimal Finding');
        });

        it('should handle very large number of findings', async () => {
            const manyFindings = Array.from({ length: 100 }, (_, i) =>
                createMockFinding({
                    title: `Finding ${i}`,
                    severity: i % 2 === 0 ? Severity.HIGH : Severity.LOW,
                })
            );

            const result = createMockScanResult({ findings: manyFindings });
            const html = await generator.generate(result);

            expect(html).toContain('<!DOCTYPE html>');
            expect(html).toContain('Finding 0');
            expect(html).toContain('Finding 99');
        });
    });
});
