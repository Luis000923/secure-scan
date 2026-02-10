/**
 * Unit Tests for JavaScript Analyzer
 * Tests JavaScript/TypeScript security analysis
 */

import { createMockFile, createMockRule, vulnerableSamples, safeSamples } from '../../utils/testHelpers';
import { Severity, ThreatType, FindingCategory } from '../../../src/types';

// Mock the logger to prevent console output during tests
jest.mock('../../../src/utils/logger', () => ({
  logger: {
    info: jest.fn(),
    debug: jest.fn(),
    warn: jest.fn(),
    error: jest.fn()
  }
}));

describe('JavaScript Analyzer', () => {
  let JavaScriptAnalyzer: any;
  let analyzer: any;

  beforeAll(async () => {
    // Dynamic import to allow mocking
    const module = await import('../../../src/analyzers/javascript/javascriptAnalyzer');
    JavaScriptAnalyzer = module.JavaScriptAnalyzer;
  });

  beforeEach(() => {
    analyzer = new JavaScriptAnalyzer();
  });

  afterEach(async () => {
    if (analyzer.cleanup) {
      await analyzer.cleanup();
    }
  });

  describe('initialization', () => {
    it('should have correct analyzer info', () => {
      expect(analyzer.name).toBe('JavaScript Analyzer');
      expect(analyzer.languages).toContain('javascript');
      expect(analyzer.languages).toContain('typescript');
      expect(analyzer.version).toBeDefined();
    });

    it('should support JavaScript and TypeScript', () => {
      expect(analyzer.supportsLanguage('javascript')).toBe(true);
      expect(analyzer.supportsLanguage('typescript')).toBe(true);
      expect(analyzer.supportsLanguage('python')).toBe(false);
    });
  });

  describe('SQL Injection Detection', () => {
    it('should detect string concatenation SQL injection', async () => {
      const file = createMockFile(vulnerableSamples.sqlInjection.javascript, {
        language: 'javascript',
        filename: 'vulnerable.js'
      });

      const rules = [
        createMockRule({
          id: 'JS-SQLI-001',
          name: 'SQL Injection via String Concatenation',
          severity: Severity.HIGH,
          threatType: ThreatType.SQL_INJECTION,
          patterns: [
            { type: 'regex', pattern: '(SELECT|INSERT|UPDATE|DELETE).*\\+.*\\w+', flags: 'gi' }
          ]
        })
      ];

      await analyzer.initialize();
      const findings = await analyzer.analyze(file, rules);

      expect(findings.length).toBeGreaterThanOrEqual(1);
      const sqliFinding = findings.find((f: any) => f.threatType === ThreatType.SQL_INJECTION);
      expect(sqliFinding).toBeDefined();
    });

    it('should NOT flag parameterized queries', async () => {
      const file = createMockFile(safeSamples.sqlInjection.javascript, {
        language: 'javascript'
      });

      const rules = [
        createMockRule({
          id: 'JS-SQLI-001',
          severity: Severity.HIGH,
          threatType: ThreatType.SQL_INJECTION,
          patterns: [
            { type: 'regex', pattern: '(SELECT|INSERT|UPDATE|DELETE).*\\+.*\\w+', flags: 'gi' }
          ]
        })
      ];

      await analyzer.initialize();
      const findings = await analyzer.analyze(file, rules);

      const sqliFinding = findings.find((f: any) => f.threatType === ThreatType.SQL_INJECTION);
      expect(sqliFinding).toBeUndefined();
    });
  });

  describe('XSS Detection', () => {
    it('should detect innerHTML usage', async () => {
      const file = createMockFile(vulnerableSamples.xss.javascript, {
        language: 'javascript'
      });

      const rules = [
        createMockRule({
          id: 'JS-XSS-001',
          name: 'XSS via innerHTML',
          severity: Severity.HIGH,
          threatType: ThreatType.XSS,
          patterns: [
            { type: 'regex', pattern: '\\.innerHTML\\s*=', flags: 'g' },
            { type: 'regex', pattern: 'document\\.write\\s*\\(', flags: 'g' }
          ]
        })
      ];

      await analyzer.initialize();
      const findings = await analyzer.analyze(file, rules);

      expect(findings.length).toBeGreaterThanOrEqual(1);
    });

    it('should NOT flag textContent usage', async () => {
      const file = createMockFile(safeSamples.xss.javascript, {
        language: 'javascript'
      });

      const rules = [
        createMockRule({
          id: 'JS-XSS-001',
          severity: Severity.HIGH,
          threatType: ThreatType.XSS,
          patterns: [
            { type: 'regex', pattern: '\\.innerHTML\\s*=', flags: 'g' }
          ]
        })
      ];

      await analyzer.initialize();
      const findings = await analyzer.analyze(file, rules);

      const xssFinding = findings.find((f: any) => f.threatType === ThreatType.XSS);
      expect(xssFinding).toBeUndefined();
    });
  });

  describe('Command Injection Detection', () => {
    it('should detect exec with user input', async () => {
      const file = createMockFile(vulnerableSamples.commandInjection.javascript, {
        language: 'javascript'
      });

      const rules = [
        createMockRule({
          id: 'JS-CMDI-001',
          name: 'Command Injection',
          severity: Severity.CRITICAL,
          threatType: ThreatType.COMMAND_INJECTION,
          patterns: [
            { type: 'regex', pattern: 'exec\\s*\\([^)]*\\+', flags: 'g' },
            { type: 'regex', pattern: 'exec\\s*\\(`[^`]*\\$\\{', flags: 'g' }
          ]
        })
      ];

      await analyzer.initialize();
      const findings = await analyzer.analyze(file, rules);

      expect(findings.length).toBeGreaterThanOrEqual(1);
    });
  });

  describe('Hardcoded Credentials Detection', () => {
    it('should detect hardcoded passwords', async () => {
      const file = createMockFile(vulnerableSamples.hardcodedCredentials.javascript, {
        language: 'javascript'
      });

      const rules = [
        createMockRule({
          id: 'JS-CRED-001',
          name: 'Hardcoded Credentials',
          severity: Severity.HIGH,
          threatType: ThreatType.HARDCODED_CREDENTIALS,
          patterns: [
            { type: 'regex', pattern: '(password|passwd|pwd|secret|apikey|api_key)\\s*[=:]\\s*["\'][^"\']+["\']', flags: 'gi' }
          ]
        })
      ];

      await analyzer.initialize();
      const findings = await analyzer.analyze(file, rules);

      expect(findings.length).toBeGreaterThanOrEqual(1);
    });
  });

  describe('Dangerous Function Detection', () => {
    it('should detect eval() usage', async () => {
      const file = createMockFile('eval(userInput);', { language: 'javascript' });

      const rules = [
        createMockRule({
          id: 'JS-EVAL-001',
          name: 'Dangerous eval()',
          severity: Severity.HIGH,
          threatType: ThreatType.DANGEROUS_FUNCTION,
          patterns: [
            { type: 'regex', pattern: '\\beval\\s*\\(', flags: 'g' }
          ]
        })
      ];

      await analyzer.initialize();
      const findings = await analyzer.analyze(file, rules);

      expect(findings.length).toBeGreaterThanOrEqual(1);
    });

    it('should detect Function constructor', async () => {
      const file = createMockFile('new Function(userCode)', { language: 'javascript' });

      const rules = [
        createMockRule({
          id: 'JS-FUNC-001',
          name: 'Dangerous Function constructor',
          severity: Severity.HIGH,
          threatType: ThreatType.DANGEROUS_FUNCTION,
          patterns: [
            { type: 'regex', pattern: 'new\\s+Function\\s*\\(', flags: 'g' }
          ]
        })
      ];

      await analyzer.initialize();
      const findings = await analyzer.analyze(file, rules);

      expect(findings.length).toBeGreaterThanOrEqual(1);
    });
  });
});
