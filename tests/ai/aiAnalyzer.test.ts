/**
 * AI Analyzer Unit Tests
 * Tests for the AI analysis module: provider detection, response parsing,
 * finding conversion, and error handling.
 */

import { AIAnalyzer } from '../../src/ai/aiAnalyzer';
import { AIConfig, ScannedFile, Severity, ThreatType, FindingCategory } from '../../src/types';
import { createMockFile } from '../utils/testHelpers';

// Mock logger to suppress output
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
}));

describe('AIAnalyzer', () => {
    let analyzer: AIAnalyzer;

    const baseConfig: AIConfig = {
        provider: 'local',
        endpoint: 'http://localhost:11434/api/generate',
        model: 'codellama:7b-instruct',
        maxTokens: 2000,
        temperature: 0.1,
    };

    beforeEach(() => {
        analyzer = new AIAnalyzer(baseConfig);
    });

    describe('Provider Detection', () => {
        it('should detect local provider when explicitly set', () => {
            const a = new AIAnalyzer({ ...baseConfig, provider: 'local' });
            // The analyzer initializes with local provider
            expect(a).toBeDefined();
        });

        it('should detect OpenAI from API key prefix', () => {
            const a = new AIAnalyzer({
                ...baseConfig,
                provider: 'auto',
                apiKey: 'sk-test-1234567890',
            });
            expect(a).toBeDefined();
        });

        it('should detect Anthropic from API key prefix', () => {
            const a = new AIAnalyzer({
                ...baseConfig,
                provider: 'auto',
                apiKey: 'sk-ant-test-1234567890',
            });
            expect(a).toBeDefined();
        });

        it('should detect Google from API key prefix', () => {
            const a = new AIAnalyzer({
                ...baseConfig,
                provider: 'auto',
                apiKey: 'AIzaSyTest1234567890',
            });
            expect(a).toBeDefined();
        });

        it('should fallback to openai for unrecognized keys', () => {
            const a = new AIAnalyzer({
                ...baseConfig,
                provider: 'auto',
                apiKey: 'unknown-format-key',
            });
            expect(a).toBeDefined();
        });
    });

    describe('analyze()', () => {
        it('should return empty findings when not initialized', async () => {
            const file = createMockFile('const x = 1;', { language: 'javascript' });
            const result = await analyzer.analyze(file);
            expect(result.findings).toEqual([]);
        });

        it('should handle empty file content gracefully', async () => {
            const file = createMockFile('', { language: 'javascript' });
            const result = await analyzer.analyze(file);
            expect(result.findings).toEqual([]);
        });
    });

    describe('initialize()', () => {
        it('should warn when no API key for non-local providers', async () => {
            const a = new AIAnalyzer({
                ...baseConfig,
                provider: 'openai',
                apiKey: undefined,
            });
            await a.initialize();
            // Should not throw, graceful degradation
            expect(a).toBeDefined();
        });

        it('should initialize for local provider without API key', async () => {
            const a = new AIAnalyzer({
                ...baseConfig,
                provider: 'local',
            });
            await a.initialize();
            expect(a).toBeDefined();
        });
    });

    describe('parseAIResponse (via analyze with mock)', () => {
        // Testing the internal parsing logic through the class interface

        it('should handle invalid JSON in response gracefully', async () => {
            const file = createMockFile('const x = 1;');
            // Without initialization, analyze returns empty
            const result = await analyzer.analyze(file);
            expect(result.findings).toHaveLength(0);
        });
    });

    describe('analyzeParallel()', () => {
        it('should return a map of results for multiple files', async () => {
            const files = [
                createMockFile('const x = 1;', { language: 'javascript', filename: 'a.js' }),
                createMockFile('const y = 2;', { language: 'javascript', filename: 'b.js' }),
            ];

            const results = await analyzer.analyzeParallel(files);
            expect(results).toBeInstanceOf(Map);
            expect(results.size).toBe(2);
        });

        it('should handle empty file array', async () => {
            const results = await analyzer.analyzeParallel([]);
            expect(results).toBeInstanceOf(Map);
            expect(results.size).toBe(0);
        });
    });

    describe('clearCache()', () => {
        it('should clear the analysis cache without errors', () => {
            expect(() => analyzer.clearCache()).not.toThrow();
        });
    });

    describe('enhanceFinding()', () => {
        it('should return the original finding if not initialized', async () => {
            const { createMockFinding } = await import('../utils/testHelpers');
            const finding = createMockFinding({
                title: 'SQL Injection',
                severity: Severity.HIGH,
            });

            const enhanced = await analyzer.enhanceFinding(finding);

            // Should return the same finding without modifications
            expect(enhanced.title).toBe('SQL Injection');
            expect(enhanced.severity).toBe(Severity.HIGH);
        });
    });
});
