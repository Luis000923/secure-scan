/**
 * Integration Test
 * End-to-end scan test using SecurityScanner against the test-samples directory.
 * Validates the full pipeline: file scanning → analysis → scoring → report generation.
 */

import * as path from 'path';
import * as fs from 'fs';
import { SecurityScanner } from '../../src/analyzers/core/securityScanner';
import { ScanConfig, Severity, FindingCategory } from '../../src/types';

// Mock logger
jest.mock('../../src/utils/logger', () => ({
    logger: {
        info: jest.fn(),
        warn: jest.fn(),
        debug: jest.fn(),
        error: jest.fn(),
    },
    logScanStart: jest.fn(),
    logScanComplete: jest.fn(),
    logFinding: jest.fn(),
    setLogLevel: jest.fn(),
}));

// Increase timeout for integration tests
jest.setTimeout(60000);

describe('Integration: SecurityScanner E2E', () => {
    const testSamplesPath = path.resolve(__dirname, '../../test-samples');
    const hasTestSamples = fs.existsSync(testSamplesPath);

    const createScanConfig = (overrides: Partial<ScanConfig> = {}): ScanConfig => ({
        projectPath: testSamplesPath,
        minSeverity: Severity.INFO,
        ...overrides,
    });

    beforeAll(() => {
        if (!hasTestSamples) {
            console.warn('⚠️ test-samples directory not found. Integration tests will be skipped.');
        }
    });

    describe('Full Scan Pipeline', () => {
        it('should complete scan without errors', async () => {
            if (!hasTestSamples) return;

            const scanner = new SecurityScanner(createScanConfig());
            const result = await scanner.scan();

            expect(result).toBeDefined();
            expect(result.scanId).toBeTruthy();
            expect(result.projectPath).toBe(testSamplesPath);
            expect(result.stats.startTime).toBeInstanceOf(Date);
            expect(result.stats.duration).toBeGreaterThanOrEqual(0);
        });

        it('should find at least some vulnerabilities in test samples', async () => {
            if (!hasTestSamples) return;

            const scanner = new SecurityScanner(createScanConfig());
            const result = await scanner.scan();

            expect(result.findings.length).toBeGreaterThan(0);
        });

        it('should scan files and produce stats', async () => {
            if (!hasTestSamples) return;

            const scanner = new SecurityScanner(createScanConfig());
            const result = await scanner.scan();

            expect(result.stats.totalFiles).toBeGreaterThan(0);
            expect(result.stats.totalLines).toBeGreaterThan(0);
        });

        it('should produce findings with all required fields', async () => {
            if (!hasTestSamples) return;

            const scanner = new SecurityScanner(createScanConfig());
            const result = await scanner.scan();

            for (const finding of result.findings) {
                // Core required fields
                expect(finding.id).toBeTruthy();
                expect(finding.severity).toBeTruthy();
                expect(finding.location).toBeDefined();
                expect(finding.location.file).toBeTruthy();
                expect(finding.location.startLine).toBeGreaterThanOrEqual(1);
            }
        });

        it('should calculate risk score between 0 and 100', async () => {
            if (!hasTestSamples) return;

            const scanner = new SecurityScanner(createScanConfig());
            const result = await scanner.scan();

            expect(result.riskScore).toBeGreaterThanOrEqual(0);
            expect(result.riskScore).toBeLessThanOrEqual(100);
        });
    });

    describe('Language Filtering', () => {
        it('should filter by language when specified', async () => {
            if (!hasTestSamples) return;

            const scanner = new SecurityScanner(createScanConfig({
                languages: ['javascript'],
            }));
            const result = await scanner.scan();

            // All findings should be from JS files
            for (const finding of result.findings) {
                const ext = path.extname(finding.location.file);
                expect(['.js', '.jsx', '.mjs', '.cjs', '.ts', '.tsx', '']).toContain(ext);
            }
        });
    });

    describe('Severity Filtering', () => {
        it('should respect minimum severity filter', async () => {
            if (!hasTestSamples) return;

            const scanner = new SecurityScanner(createScanConfig({
                minSeverity: Severity.HIGH,
            }));
            const result = await scanner.scan();

            for (const finding of result.findings) {
                expect([Severity.CRITICAL, Severity.HIGH]).toContain(finding.severity);
            }
        });
    });

    describe('Error Handling', () => {
        it('should handle non-existent project path gracefully', async () => {
            const scanner = new SecurityScanner(createScanConfig({
                projectPath: '/nonexistent/path/xyz123',
            }));

            // Should either throw or return empty result, not crash
            try {
                const result = await scanner.scan();
                expect(result.findings).toHaveLength(0);
            } catch (error) {
                expect(error).toBeDefined();
            }
        });

        it('should handle empty directory gracefully', async () => {
            const tmpDir = path.join(__dirname, '../../tmp-test-empty');

            try {
                fs.mkdirSync(tmpDir, { recursive: true });

                const scanner = new SecurityScanner(createScanConfig({
                    projectPath: tmpDir,
                }));
                const result = await scanner.scan();

                expect(result.findings).toHaveLength(0);
                expect(result.stats.totalFiles).toBe(0);
            } finally {
                // Cleanup
                try {
                    fs.rmdirSync(tmpDir);
                } catch (_) {
                    // ignore cleanup errors
                }
            }
        });
    });

    describe('Stats Integrity', () => {
        it('should have consistent severity distribution', async () => {
            if (!hasTestSamples) return;

            const scanner = new SecurityScanner(createScanConfig());
            const result = await scanner.scan();

            const { findingsBySeverity } = result.stats;
            const totalFromDist = Object.values(findingsBySeverity).reduce((s, v) => s + v, 0);

            // Total from distribution should equal total findings
            expect(totalFromDist).toBe(result.findings.length);
        });
    });
});
