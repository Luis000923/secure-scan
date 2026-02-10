/**
 * Unit Tests for Base Analyzer
 * Tests the abstract base analyzer functionality
 */

import { BaseAnalyzer } from '../../../src/analyzers/base/baseAnalyzer';
import { ScannedFile, Finding, Rule, SupportedLanguage, Severity, ThreatType, FindingCategory } from '../../../src/types';
import { createMockFile, createMockRule } from '../../utils/testHelpers';

// Concrete implementation for testing
class TestAnalyzer extends BaseAnalyzer {
  name = 'Test Analyzer';
  languages: SupportedLanguage[] = ['javascript', 'typescript'];
  version = '1.0.0';

  async analyze(file: ScannedFile, rules: Rule[]): Promise<Finding[]> {
    const findings: Finding[] = [];
    
    for (const rule of rules) {
      if (rule.patterns) {
        for (const rulePattern of rule.patterns) {
          if (rulePattern.type === 'regex') {
            const regex = new RegExp(rulePattern.pattern, rulePattern.flags);
            const matches = file.content.match(regex);
            if (matches) {
              findings.push({
                id: `${rule.id}-${Date.now()}`,
                ruleId: rule.id,
                title: rule.name,
                description: rule.description,
                severity: rule.severity,
                threatType: rule.threatType,
                category: rule.category,
                location: {
                  file: file.relativePath,
                  startLine: 1,
                  endLine: 1
                },
                snippet: { code: matches[0] },
                standards: rule.standards,
                remediation: rule.remediation,
                confidence: 80,
                tags: rule.tags,
                analyzer: this.name,
                timestamp: new Date()
              });
            }
          }
        }
      }
    }
    
    return findings;
  }
}

describe('BaseAnalyzer', () => {
  let analyzer: TestAnalyzer;

  beforeEach(() => {
    analyzer = new TestAnalyzer();
  });

  afterEach(async () => {
    await analyzer.cleanup();
  });

  describe('initialization', () => {
    it('should initialize successfully', async () => {
      await analyzer.initialize();
      expect((analyzer as any).initialized).toBe(true);
    });

    it('should have correct name and version', () => {
      expect(analyzer.name).toBe('Test Analyzer');
      expect(analyzer.version).toBe('1.0.0');
    });

    it('should report supported languages', () => {
      expect(analyzer.languages).toContain('javascript');
      expect(analyzer.languages).toContain('typescript');
    });
  });

  describe('supportsLanguage', () => {
    it('should return true for supported languages', () => {
      expect(analyzer.supportsLanguage('javascript')).toBe(true);
      expect(analyzer.supportsLanguage('typescript')).toBe(true);
    });

    it('should return false for unsupported languages', () => {
      expect(analyzer.supportsLanguage('python')).toBe(false);
      expect(analyzer.supportsLanguage('php')).toBe(false);
    });
  });

  describe('getInfo', () => {
    it('should return analyzer info', () => {
      const info = analyzer.getInfo();
      
      expect(info).toEqual({
        name: 'Test Analyzer',
        languages: ['javascript', 'typescript'],
        version: '1.0.0'
      });
    });
  });

  describe('analyze', () => {
    it('should detect patterns in code', async () => {
      const file = createMockFile('eval(userInput);', { language: 'javascript' });
      const rules = [
        createMockRule({
          id: 'JS-EVAL-001',
          name: 'Dangerous eval()',
          patterns: [{ type: 'regex', pattern: 'eval\\s*\\(', flags: 'g' }],
          severity: Severity.HIGH,
          threatType: ThreatType.DANGEROUS_FUNCTION
        })
      ];

      await analyzer.initialize();
      const findings = await analyzer.analyze(file, rules);

      expect(findings).toHaveLength(1);
      expect(findings[0].ruleId).toBe('JS-EVAL-001');
      expect(findings[0].severity).toBe(Severity.HIGH);
    });

    it('should return empty array for safe code', async () => {
      const file = createMockFile('const x = 1 + 2;', { language: 'javascript' });
      const rules = [
        createMockRule({
          patterns: [{ type: 'regex', pattern: 'eval\\s*\\(', flags: 'g' }]
        })
      ];

      await analyzer.initialize();
      const findings = await analyzer.analyze(file, rules);

      expect(findings).toHaveLength(0);
    });

    it('should handle multiple patterns', async () => {
      const file = createMockFile('eval(x); exec(cmd);', { language: 'javascript' });
      const rules = [
        createMockRule({
          id: 'MULTI-001',
          patterns: [
            { type: 'regex', pattern: 'eval\\s*\\(', flags: 'g' },
            { type: 'regex', pattern: 'exec\\s*\\(', flags: 'g' }
          ]
        })
      ];

      await analyzer.initialize();
      const findings = await analyzer.analyze(file, rules);

      expect(findings.length).toBeGreaterThanOrEqual(1);
    });
  });

  describe('cleanup', () => {
    it('should cleanup resources', async () => {
      await analyzer.initialize();
      expect((analyzer as any).initialized).toBe(true);
      
      await analyzer.cleanup();
      expect((analyzer as any).initialized).toBe(false);
    });
  });
});
