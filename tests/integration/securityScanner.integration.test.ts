/**
 * Integration Tests for Security Scanner
 * End-to-end tests for the scanning pipeline
 */

import * as path from 'path';
import * as fs from 'fs';
import { Severity, FindingCategory } from '../../src/types';

// Mock logger to reduce noise
jest.mock('../../src/utils/logger', () => ({
  logger: {
    info: jest.fn(),
    debug: jest.fn(),
    warn: jest.fn(),
    error: jest.fn()
  },
  logScanStart: jest.fn(),
  logScanComplete: jest.fn(),
  logFinding: jest.fn(),
  setLogLevel: jest.fn()
}));

describe('Security Scanner Integration', () => {
  const testSamplesPath = path.resolve(__dirname, '../../test-samples');

  describe('Full Scan Pipeline', () => {
    it('should scan test-samples directory without errors', async () => {
      // Skip if test-samples doesn't exist
      if (!fs.existsSync(testSamplesPath)) {
        console.log('Skipping: test-samples directory not found');
        return;
      }

      const { SecurityScanner } = await import('../../src/analyzers/core/securityScanner');

      const scanner = new SecurityScanner({
        projectPath: testSamplesPath,
        minSeverity: Severity.INFO,
        verbose: false
      });

      const result = await scanner.scan();

      expect(result).toBeDefined();
      expect(result.findings).toBeDefined();
      expect(Array.isArray(result.findings)).toBe(true);
      expect(result.stats).toBeDefined();
      expect(result.riskScore).toBeDefined();
    });

    it('should detect vulnerabilities in vulnerable-sample.js', async () => {
      const jsFilePath = path.join(testSamplesPath, 'vulnerable-sample.js');
      
      if (!fs.existsSync(jsFilePath)) {
        console.log('Skipping: vulnerable-sample.js not found');
        return;
      }

      const { SecurityScanner } = await import('../../src/analyzers/core/securityScanner');

      const scanner = new SecurityScanner({
        projectPath: testSamplesPath,
        minSeverity: Severity.INFO,
        verbose: false
      });

      const result = await scanner.scan();

      // Should find at least some vulnerabilities
      expect(result.findings.length).toBeGreaterThan(0);

      // Check for expected vulnerability types
      const severities = result.findings.map((f: any) => f.severity);
      const categories = result.findings.map((f: any) => f.category);

      expect(categories).toContain(FindingCategory.VULNERABILITY);
    });

    it('should detect issues in Python files', async () => {
      const pyFilePath = path.join(testSamplesPath, 'vulnerable-sample.py');
      
      if (!fs.existsSync(pyFilePath)) {
        console.log('Skipping: vulnerable-sample.py not found');
        return;
      }

      const { SecurityScanner } = await import('../../src/analyzers/core/securityScanner');

      const scanner = new SecurityScanner({
        projectPath: testSamplesPath,
        languages: ['python'],
        minSeverity: Severity.INFO
      });

      const result = await scanner.scan();

      const pythonFindings = result.findings.filter((f: any) => 
        f.location.file.endsWith('.py')
      );

      expect(pythonFindings.length).toBeGreaterThan(0);
    });
  });

  describe('Severity Filtering', () => {
    it('should respect minSeverity filter', async () => {
      if (!fs.existsSync(testSamplesPath)) {
        return;
      }

      const { SecurityScanner } = await import('../../src/analyzers/core/securityScanner');

      const scanner = new SecurityScanner({
        projectPath: testSamplesPath,
        minSeverity: Severity.HIGH
      });

      const result = await scanner.scan();

      // All findings should be HIGH or CRITICAL
      for (const finding of result.findings) {
        expect([Severity.HIGH, Severity.CRITICAL]).toContain(finding.severity);
      }
    });
  });

  describe('Exclusion Patterns', () => {
    it('should exclude specified patterns', async () => {
      if (!fs.existsSync(testSamplesPath)) {
        return;
      }

      const { SecurityScanner } = await import('../../src/analyzers/core/securityScanner');

      const scanner = new SecurityScanner({
        projectPath: testSamplesPath,
        exclude: ['**/fake-node_modules/**', '**/*.json']
      });

      const result = await scanner.scan();

      // Should not have findings from excluded paths
      for (const finding of result.findings) {
        expect(finding.location.file).not.toContain('fake-node_modules');
        expect(finding.location.file).not.toMatch(/\.json$/);
      }
    });
  });

  describe('Risk Scoring', () => {
    it('should calculate risk score', async () => {
      if (!fs.existsSync(testSamplesPath)) {
        return;
      }

      const { SecurityScanner } = await import('../../src/analyzers/core/securityScanner');

      const scanner = new SecurityScanner({
        projectPath: testSamplesPath,
        minSeverity: Severity.INFO
      });

      const result = await scanner.scan();

      expect(result.riskScore).toBeDefined();
      expect(typeof result.riskScore).toBe('number');
      expect(result.riskScore).toBeGreaterThanOrEqual(0);
      expect(result.riskScore).toBeLessThanOrEqual(100);

      expect(result.riskLevel).toBeDefined();
      expect(['low', 'medium', 'high', 'critical']).toContain(result.riskLevel.toLowerCase());
    });
  });

  describe('Statistics', () => {
    it('should provide accurate statistics', async () => {
      if (!fs.existsSync(testSamplesPath)) {
        return;
      }

      const { SecurityScanner } = await import('../../src/analyzers/core/securityScanner');

      const scanner = new SecurityScanner({
        projectPath: testSamplesPath,
        minSeverity: Severity.INFO
      });

      const result = await scanner.scan();

      expect(result.stats).toBeDefined();
      expect(result.stats.totalFiles).toBeGreaterThan(0);
      expect(result.findings).toBeDefined();
      expect(result.stats.duration).toBeGreaterThan(0);
      expect(result.stats.findingsBySeverity).toBeDefined();
    });
  });
});
