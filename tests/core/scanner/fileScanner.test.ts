/**
 * File Scanner Unit Tests
 * Tests for file discovery, filtering, processing, and language detection.
 */

import * as path from 'path';
import * as fs from 'fs';
import { FileScanner } from '../../../src/analyzers/core/scanner/fileScanner';
import { ScanConfig, Severity } from '../../../src/types';

// Mock logger
jest.mock('../../../src/utils/logger', () => ({
    logger: {
        info: jest.fn(),
        warn: jest.fn(),
        debug: jest.fn(),
        error: jest.fn(),
    },
}));

describe('FileScanner', () => {
    const testSamplesPath = path.resolve(__dirname, '../../../test-samples');

    const createConfig = (overrides: Partial<ScanConfig> = {}): ScanConfig => ({
        projectPath: testSamplesPath,
        minSeverity: Severity.INFO,
        ...overrides,
    });

    describe('constructor', () => {
        it('should create scanner with valid config', () => {
            const scanner = new FileScanner(createConfig());
            expect(scanner).toBeDefined();
        });
    });

    describe('scan()', () => {
        it('should find files in test-samples directory', async () => {
            if (!fs.existsSync(testSamplesPath)) {
                return; // Skip if test-samples doesn't exist
            }

            const scanner = new FileScanner(createConfig());
            const files = await scanner.scan();

            expect(files.length).toBeGreaterThan(0);
        });

        it('should detect language for scanned files', async () => {
            if (!fs.existsSync(testSamplesPath)) {
                return;
            }

            const scanner = new FileScanner(createConfig());
            const files = await scanner.scan();

            const filesWithLanguage = files.filter(f => f.language !== null);
            expect(filesWithLanguage.length).toBeGreaterThan(0);
        });

        it('should throw error for non-existent path', async () => {
            const scanner = new FileScanner(createConfig({
                projectPath: '/nonexistent/path/12345',
            }));

            await expect(scanner.scan()).rejects.toThrow();
        });

        it('should respect exclude patterns', async () => {
            if (!fs.existsSync(testSamplesPath)) {
                return;
            }

            const scanner = new FileScanner(createConfig({
                exclude: ['*.test.js'],
            }));
            const files = await scanner.scan();

            const testFiles = files.filter(f => f.relativePath.endsWith('.test.js'));
            expect(testFiles).toHaveLength(0);
        });

        it('should filter by specified languages', async () => {
            if (!fs.existsSync(testSamplesPath)) {
                return;
            }

            const scanner = new FileScanner(createConfig({
                languages: ['python'],
            }));
            const files = await scanner.scan();

            files.forEach(file => {
                expect(file.language).toBe('python');
            });
        });

        it('should respect maxFileSize', async () => {
            if (!fs.existsSync(testSamplesPath)) {
                return;
            }

            const scanner = new FileScanner(createConfig({
                maxFileSize: 100, // Very small limit
            }));
            const files = await scanner.scan();

            files.forEach(file => {
                expect(file.size).toBeLessThanOrEqual(100);
            });
        });

        it('should include file hash for each file', async () => {
            if (!fs.existsSync(testSamplesPath)) {
                return;
            }

            const scanner = new FileScanner(createConfig());
            const files = await scanner.scan();

            files.forEach(file => {
                expect(file.hash).toBeTruthy();
                expect(typeof file.hash).toBe('string');
            });
        });
    });

    describe('getFileStats()', () => {
        it('should group files by language', async () => {
            if (!fs.existsSync(testSamplesPath)) {
                return;
            }

            const scanner = new FileScanner(createConfig());
            const files = await scanner.scan();
            const stats = scanner.getFileStats(files);

            expect(typeof stats).toBe('object');
            const totalFromStats = Object.values(stats).reduce((sum, count) => sum + count, 0);
            expect(totalFromStats).toBe(files.length);
        });
    });
});
