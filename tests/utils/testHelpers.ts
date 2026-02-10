/**
 * Test Helper Utilities
 * Common utilities for testing secure-scan components
 */

import { 
  ScannedFile, 
  Finding, 
  Severity, 
  ThreatType, 
  FindingCategory,
  SupportedLanguage,
  Rule,
  RulePattern
} from '../../src/types';

/**
 * Create a mock scanned file for testing
 */
export function createMockFile(
  content: string,
  options: {
    language?: SupportedLanguage;
    filename?: string;
    path?: string;
  } = {}
): ScannedFile {
  const language = options.language || 'javascript';
  const filename = options.filename || `test.${getExtension(language)}`;
  const filePath = options.path || `/test/${filename}`;

  return {
    absolutePath: filePath,
    relativePath: filename,
    extension: getExtension(language),
    content,
    language,
    size: Buffer.byteLength(content, 'utf8'),
    lineCount: content.split('\n').length,
    hash: createSimpleHash(content)
  };
}

/**
 * Create a mock finding for testing
 */
export function createMockFinding(overrides: Partial<Finding> = {}): Finding {
  return {
    id: overrides.id || `FINDING-${Date.now()}`,
    ruleId: overrides.ruleId || 'TEST-001',
    title: overrides.title || 'Test Finding',
    description: overrides.description || 'Test finding description',
    severity: overrides.severity || Severity.MEDIUM,
    threatType: overrides.threatType || ThreatType.SQL_INJECTION,
    category: overrides.category || FindingCategory.VULNERABILITY,
    location: overrides.location || {
      file: 'test.js',
      startLine: 1,
      endLine: 1
    },
    snippet: overrides.snippet || {
      code: 'test code'
    },
    standards: overrides.standards || [],
    remediation: overrides.remediation || 'Fix the issue',
    confidence: overrides.confidence || 80,
    tags: overrides.tags || [],
    analyzer: overrides.analyzer || 'test-analyzer',
    timestamp: overrides.timestamp || new Date(),
    ...overrides
  };
}

/**
 * Create a mock rule for testing
 */
export function createMockRule(overrides: Partial<Rule> = {}): Rule {
  return {
    id: overrides.id || 'TEST-RULE-001',
    name: overrides.name || 'Test Rule',
    description: overrides.description || 'Test rule description',
    languages: overrides.languages || ['javascript'],
    threatType: overrides.threatType || ThreatType.SQL_INJECTION,
    category: overrides.category || FindingCategory.VULNERABILITY,
    severity: overrides.severity || Severity.MEDIUM,
    patterns: overrides.patterns || [
      {
        type: 'regex',
        pattern: 'test-pattern',
        flags: 'gi'
      }
    ],
    standards: overrides.standards || [],
    remediation: overrides.remediation || 'Fix the vulnerability',
    enabled: overrides.enabled !== undefined ? overrides.enabled : true,
    tags: overrides.tags || [],
    ...overrides
  };
}

/**
 * Create vulnerable code samples for testing
 */
export const vulnerableSamples = {
  sqlInjection: {
    javascript: `
      const query = "SELECT * FROM users WHERE id = " + userId;
      db.query(query);
    `,
    python: `
      query = "SELECT * FROM users WHERE id = " + user_id
      cursor.execute(query)
    `,
    php: `
      $query = "SELECT * FROM users WHERE id = " . $_GET['id'];
      mysqli_query($conn, $query);
    `
  },
  xss: {
    javascript: `
      element.innerHTML = userInput;
      document.write(data);
    `,
    php: `
      echo $_GET['input'];
      print $userInput;
    `
  },
  commandInjection: {
    javascript: `
      const { exec } = require('child_process');
      exec('ls ' + userInput);
    `,
    python: `
      import os
      os.system('ls ' + user_input)
    `,
    php: `
      exec('ls ' . $_GET['dir']);
      shell_exec($userCommand);
    `
  },
  hardcodedCredentials: {
    javascript: `
      const password = "admin123";
      const apiKey = "sk-1234567890abcdef";
    `,
    python: `
      password = "secret123"
      api_key = "AKIAIOSFODNN7EXAMPLE"
    `
  }
};

/**
 * Create safe code samples for testing (should not trigger findings)
 */
export const safeSamples = {
  sqlInjection: {
    javascript: `
      const query = "SELECT * FROM users WHERE id = ?";
      db.query(query, [userId]);
    `,
    python: `
      query = "SELECT * FROM users WHERE id = %s"
      cursor.execute(query, (user_id,))
    `
  },
  xss: {
    javascript: `
      element.textContent = userInput;
      const sanitized = DOMPurify.sanitize(data);
    `
  }
};

// Helper functions

function getExtension(language: SupportedLanguage): string {
  const extensions: Record<SupportedLanguage, string> = {
    javascript: 'js',
    typescript: 'ts',
    python: 'py',
    php: 'php',
    java: 'java',
    c: 'c',
    cpp: 'cpp',
    csharp: 'cs',
    dockerfile: 'Dockerfile',
    yaml: 'yaml',
    terraform: 'tf'
  };
  return extensions[language] || 'txt';
}

function createSimpleHash(content: string): string {
  let hash = 0;
  for (let i = 0; i < content.length; i++) {
    const char = content.charCodeAt(i);
    hash = ((hash << 5) - hash) + char;
    hash = hash & hash;
  }
  return Math.abs(hash).toString(16);
}

/**
 * Wait for a condition to be true
 */
export async function waitFor(
  condition: () => boolean | Promise<boolean>,
  timeout = 5000,
  interval = 100
): Promise<void> {
  const startTime = Date.now();
  while (Date.now() - startTime < timeout) {
    if (await condition()) {
      return;
    }
    await new Promise(resolve => setTimeout(resolve, interval));
  }
  throw new Error('Timeout waiting for condition');
}

/**
 * Create a temporary test directory structure
 */
export function createTestProjectStructure(): {
  projectPath: string;
  files: Map<string, string>;
} {
  return {
    projectPath: '/test-project',
    files: new Map([
      ['index.js', 'console.log("Hello");'],
      ['app.py', 'print("Hello")'],
      ['src/utils.js', 'export const helper = () => {};'],
      ['package.json', '{"name": "test", "version": "1.0.0"}']
    ])
  };
}
