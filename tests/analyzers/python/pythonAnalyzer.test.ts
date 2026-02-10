/**
 * Unit Tests for Python Analyzer
 * Tests Python security analysis
 */

import { createMockFile, createMockRule, vulnerableSamples } from '../../utils/testHelpers';
import { Severity, ThreatType } from '../../../src/types';

// Mock the logger
jest.mock('../../../src/utils/logger', () => ({
  logger: {
    info: jest.fn(),
    debug: jest.fn(),
    warn: jest.fn(),
    error: jest.fn()
  }
}));

describe('Python Analyzer', () => {
  let PythonAnalyzer: any;
  let analyzer: any;

  beforeAll(async () => {
    const module = await import('../../../src/analyzers/python/pythonAnalyzer');
    PythonAnalyzer = module.PythonAnalyzer;
  });

  beforeEach(() => {
    analyzer = new PythonAnalyzer();
  });

  afterEach(async () => {
    if (analyzer.cleanup) {
      await analyzer.cleanup();
    }
  });

  describe('initialization', () => {
    it('should have correct analyzer info', () => {
      expect(analyzer.name).toBe('Python Analyzer');
      expect(analyzer.languages).toContain('python');
      expect(analyzer.version).toBeDefined();
    });

    it('should only support Python', () => {
      expect(analyzer.supportsLanguage('python')).toBe(true);
      expect(analyzer.supportsLanguage('javascript')).toBe(false);
    });
  });

  describe('SQL Injection Detection', () => {
    it('should detect string formatting SQL injection', async () => {
      const file = createMockFile(vulnerableSamples.sqlInjection.python, {
        language: 'python',
        filename: 'app.py'
      });

      const rules = [
        createMockRule({
          id: 'PY-SQLI-001',
          languages: ['python'],
          severity: Severity.HIGH,
          threatType: ThreatType.SQL_INJECTION,
          patterns: [
            { type: 'regex', pattern: '(SELECT|INSERT|UPDATE|DELETE).*\\+.*\\w+', flags: 'gi' },
            { type: 'regex', pattern: 'execute\\s*\\([^,)]+\\+', flags: 'g' }
          ]
        })
      ];

      await analyzer.initialize();
      const findings = await analyzer.analyze(file, rules);

      expect(findings.length).toBeGreaterThanOrEqual(1);
    });
  });

  describe('Command Injection Detection', () => {
    it('should detect os.system with user input', async () => {
      const file = createMockFile(vulnerableSamples.commandInjection.python, {
        language: 'python'
      });

      const rules = [
        createMockRule({
          id: 'PY-CMDI-001',
          languages: ['python'],
          severity: Severity.CRITICAL,
          threatType: ThreatType.COMMAND_INJECTION,
          patterns: [
            { type: 'regex', pattern: 'os\\.system\\s*\\([^)]*\\+', flags: 'g' },
            { type: 'regex', pattern: 'subprocess\\.call\\s*\\([^)]*shell\\s*=\\s*True', flags: 'g' }
          ]
        })
      ];

      await analyzer.initialize();
      const findings = await analyzer.analyze(file, rules);

      expect(findings.length).toBeGreaterThanOrEqual(1);
    });
  });

  describe('Insecure Deserialization Detection', () => {
    it('should detect pickle.loads usage', async () => {
      const file = createMockFile(`
        import pickle
        data = pickle.loads(user_data)
      `, { language: 'python' });

      const rules = [
        createMockRule({
          id: 'PY-DESER-001',
          languages: ['python'],
          severity: Severity.HIGH,
          threatType: ThreatType.INSECURE_DESERIALIZATION,
          patterns: [
            { type: 'regex', pattern: 'pickle\\.(loads|load)\\s*\\(', flags: 'g' }
          ]
        })
      ];

      await analyzer.initialize();
      const findings = await analyzer.analyze(file, rules);

      expect(findings.length).toBeGreaterThanOrEqual(1);
    });

    it('should detect yaml.load without Loader', async () => {
      const file = createMockFile(`
        import yaml
        config = yaml.load(user_input)
      `, { language: 'python' });

      const rules = [
        createMockRule({
          id: 'PY-YAML-001',
          languages: ['python'],
          severity: Severity.HIGH,
          threatType: ThreatType.INSECURE_DESERIALIZATION,
          patterns: [
            { type: 'regex', pattern: 'yaml\\.load\\s*\\([^)]*\\)(?!.*Loader)', flags: 'g' }
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
      const file = createMockFile('result = eval(user_code)', { language: 'python' });

      const rules = [
        createMockRule({
          id: 'PY-EVAL-001',
          languages: ['python'],
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

    it('should detect exec() usage', async () => {
      const file = createMockFile('exec(user_code)', { language: 'python' });

      const rules = [
        createMockRule({
          id: 'PY-EXEC-001',
          languages: ['python'],
          severity: Severity.HIGH,
          threatType: ThreatType.DANGEROUS_FUNCTION,
          patterns: [
            { type: 'regex', pattern: '\\bexec\\s*\\(', flags: 'g' }
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
      const file = createMockFile(vulnerableSamples.hardcodedCredentials.python, {
        language: 'python'
      });

      const rules = [
        createMockRule({
          id: 'PY-CRED-001',
          languages: ['python'],
          severity: Severity.HIGH,
          threatType: ThreatType.HARDCODED_CREDENTIALS,
          patterns: [
            { type: 'regex', pattern: '(password|passwd|secret|api_key)\\s*=\\s*["\'][^"\']+["\']', flags: 'gi' }
          ]
        })
      ];

      await analyzer.initialize();
      const findings = await analyzer.analyze(file, rules);

      expect(findings.length).toBeGreaterThanOrEqual(1);
    });
  });

  describe('Flask/Django Security', () => {
    it('should detect Flask debug mode', async () => {
      const file = createMockFile(`
        from flask import Flask
        app = Flask(__name__)
        app.run(debug=True)
      `, { language: 'python' });

      const rules = [
        createMockRule({
          id: 'PY-FLASK-001',
          languages: ['python'],
          severity: Severity.MEDIUM,
          threatType: ThreatType.SECURITY_MISCONFIGURATION,
          patterns: [
            { type: 'regex', pattern: '\\.run\\s*\\([^)]*debug\\s*=\\s*True', flags: 'g' }
          ]
        })
      ];

      await analyzer.initialize();
      const findings = await analyzer.analyze(file, rules);

      expect(findings.length).toBeGreaterThanOrEqual(1);
    });
  });
});
