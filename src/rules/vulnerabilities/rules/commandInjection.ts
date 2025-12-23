/**
 * @fileoverview Command Injection Detection Rules
 * @module rules/vulnerabilities/rules/commandInjection
 */

import {
  VulnerabilityRule,
  VulnerabilityType,
  VulnerabilityCategory,
  VulnerabilitySeverity,
  ConfidenceLevel,
  SupportedLanguage,
  PatternType
} from '../types';
import { OWASP_TOP_10_2021, CWE_REFERENCES } from '../constants';

export const commandInjectionRules: VulnerabilityRule[] = [
  {
    id: 'VUL-CMDI-001',
    name: 'Command Injection - exec() with User Input',
    description: 'Detects execution of shell commands with user-controlled input in Node.js.',
    version: '1.0.0',
    vulnerabilityType: VulnerabilityType.COMMAND_INJECTION,
    category: VulnerabilityCategory.INJECTION,
    languages: [SupportedLanguage.JAVASCRIPT, SupportedLanguage.TYPESCRIPT],
    severity: VulnerabilitySeverity.CRITICAL,
    confidence: ConfidenceLevel.HIGH,
    baseScore: 95,
    patterns: [
      {
        type: PatternType.REGEX,
        patternId: 'cmdi-exec-req',
        pattern: '(?:child_process\\.)?exec(?:Sync)?\\s*\\([^)]*req\\.',
        flags: 'gi',
        weight: 1.0,
        description: 'exec with request data'
      },
      {
        type: PatternType.REGEX,
        patternId: 'cmdi-exec-concat',
        pattern: '(?:child_process\\.)?exec(?:Sync)?\\s*\\([^)]*\\+',
        flags: 'gi',
        weight: 0.90,
        description: 'exec with string concatenation'
      },
      {
        type: PatternType.REGEX,
        patternId: 'cmdi-exec-template',
        pattern: '(?:child_process\\.)?exec(?:Sync)?\\s*\\(\\s*`[^`]*\\$\\{',
        flags: 'gi',
        weight: 0.95,
        description: 'exec with template literal'
      }
    ],
    impact: {
      confidentiality: 'high',
      integrity: 'high',
      availability: 'high',
      technicalImpact: 'Arbitrary command execution on the server. Full system compromise.',
      businessImpact: 'Complete server takeover, data breach, lateral movement.'
    },
    exploitability: {
      attackVector: 'network',
      attackComplexity: 'low',
      privilegesRequired: 'none',
      userInteraction: 'none',
      knownExploits: true
    },
    remediation: {
      summary: 'Use execFile() or spawn() with arguments array. Never pass user input to shell commands.',
      steps: [
        'Replace exec() with execFile() or spawn()',
        'Pass command arguments as array, not concatenated string',
        'Validate and sanitize user input',
        'Use allowlist for permitted commands'
      ],
      secureCodeExample: `// Secure: Using execFile with arguments array
const { execFile } = require('child_process');
execFile('ls', ['-la', sanitizedPath], (error, stdout) => {
  // handle output
});

// Secure: Using spawn with arguments
const { spawn } = require('child_process');
const ls = spawn('ls', ['-la', userDir]);`,
      effort: 'medium',
      priority: 'immediate'
    },
    standards: {
      owasp: [OWASP_TOP_10_2021.A03],
      cwe: [CWE_REFERENCES.CWE_78],
      sans: [{ rank: 3, cweId: 'CWE-78', category: 'OS Command Injection' }]
    },
    tags: ['command-injection', 'rce', 'nodejs', 'critical'],
    enabled: true
  },
  {
    id: 'VUL-CMDI-002',
    name: 'Command Injection - Python os.system/subprocess',
    description: 'Detects Python os.system() or subprocess calls with user input.',
    version: '1.0.0',
    vulnerabilityType: VulnerabilityType.COMMAND_INJECTION,
    category: VulnerabilityCategory.INJECTION,
    languages: [SupportedLanguage.PYTHON],
    severity: VulnerabilitySeverity.CRITICAL,
    confidence: ConfidenceLevel.HIGH,
    baseScore: 95,
    patterns: [
      {
        type: PatternType.REGEX,
        patternId: 'cmdi-os-system',
        pattern: 'os\\.system\\s*\\(\\s*(?:f[\'"]|[\'"].*%|[\'"].*\\.format|.*\\+)',
        flags: 'gi',
        weight: 1.0,
        description: 'os.system with formatted string'
      },
      {
        type: PatternType.REGEX,
        patternId: 'cmdi-subprocess-shell',
        pattern: 'subprocess\\.(?:call|run|Popen)\\s*\\([^)]*shell\\s*=\\s*True',
        flags: 'gi',
        weight: 0.95,
        description: 'subprocess with shell=True'
      },
      {
        type: PatternType.REGEX,
        patternId: 'cmdi-os-popen',
        pattern: 'os\\.popen\\s*\\(',
        flags: 'gi',
        weight: 0.90,
        description: 'os.popen usage'
      }
    ],
    impact: {
      confidentiality: 'high',
      integrity: 'high',
      availability: 'high',
      technicalImpact: 'Full server compromise via shell command execution.',
      businessImpact: 'System takeover, data exfiltration.'
    },
    exploitability: {
      attackVector: 'network',
      attackComplexity: 'low',
      privilegesRequired: 'none',
      userInteraction: 'none'
    },
    remediation: {
      summary: 'Use subprocess with shell=False and command list. Use shlex.quote() for any user input.',
      steps: [
        'Replace os.system() with subprocess.run()',
        'Use shell=False with command as list',
        'Quote user input with shlex.quote()',
        'Consider using high-level libraries instead'
      ],
      secureCodeExample: `import subprocess
import shlex

# Secure: Using list form without shell
subprocess.run(['ls', '-la', user_path], shell=False)

# If shell is needed, quote the input
safe_input = shlex.quote(user_input)
subprocess.run(f'echo {safe_input}', shell=True)`,
      effort: 'low',
      priority: 'immediate'
    },
    standards: {
      owasp: [OWASP_TOP_10_2021.A03],
      cwe: [CWE_REFERENCES.CWE_78]
    },
    tags: ['command-injection', 'python', 'subprocess', 'critical'],
    enabled: true
  },
  {
    id: 'VUL-CMDI-003',
    name: 'Command Injection - PHP system/exec/shell_exec',
    description: 'Detects PHP command execution functions with user input.',
    version: '1.0.0',
    vulnerabilityType: VulnerabilityType.COMMAND_INJECTION,
    category: VulnerabilityCategory.INJECTION,
    languages: [SupportedLanguage.PHP],
    severity: VulnerabilitySeverity.CRITICAL,
    confidence: ConfidenceLevel.HIGH,
    baseScore: 95,
    patterns: [
      {
        type: PatternType.REGEX,
        patternId: 'cmdi-php-system',
        pattern: '(?:system|exec|shell_exec|passthru|popen|proc_open)\\s*\\([^)]*\\$_(?:GET|POST|REQUEST)',
        flags: 'gi',
        weight: 1.0,
        description: 'Command function with superglobal'
      },
      {
        type: PatternType.REGEX,
        patternId: 'cmdi-php-backtick',
        pattern: '`[^`]*\\$[^`]*`',
        flags: 'g',
        weight: 0.95,
        description: 'Backtick operator with variable'
      }
    ],
    impact: {
      confidentiality: 'high',
      integrity: 'high',
      availability: 'high',
      technicalImpact: 'Complete server compromise.',
      businessImpact: 'Full system access to attacker.'
    },
    exploitability: {
      attackVector: 'network',
      attackComplexity: 'low',
      privilegesRequired: 'none',
      userInteraction: 'none',
      knownExploits: true
    },
    remediation: {
      summary: 'Use escapeshellarg() and escapeshellcmd(). Avoid command execution when possible.',
      steps: [
        'Escape all user input with escapeshellarg()',
        'Use escapeshellcmd() for entire command strings',
        'Consider PHP native functions instead of shell commands',
        'Disable dangerous functions in php.ini'
      ],
      secureCodeExample: `<?php
// Secure: Using escapeshellarg
$safe_input = escapeshellarg($_GET['filename']);
system("cat " . $safe_input);

// Better: Use PHP functions instead
$content = file_get_contents($validated_path);
?>`,
      effort: 'low',
      priority: 'immediate'
    },
    standards: {
      owasp: [OWASP_TOP_10_2021.A03],
      cwe: [CWE_REFERENCES.CWE_78]
    },
    tags: ['command-injection', 'php', 'rce', 'critical'],
    enabled: true
  },
  {
    id: 'VUL-CMDI-004',
    name: 'Command Injection - Java Runtime.exec',
    description: 'Detects Java Runtime.exec() with concatenated user input.',
    version: '1.0.0',
    vulnerabilityType: VulnerabilityType.COMMAND_INJECTION,
    category: VulnerabilityCategory.INJECTION,
    languages: [SupportedLanguage.JAVA],
    severity: VulnerabilitySeverity.CRITICAL,
    confidence: ConfidenceLevel.HIGH,
    baseScore: 95,
    patterns: [
      {
        type: PatternType.REGEX,
        patternId: 'cmdi-java-runtime',
        pattern: 'Runtime\\.getRuntime\\(\\)\\.exec\\s*\\([^)]*\\+',
        flags: 'gi',
        weight: 1.0,
        description: 'Runtime.exec with concatenation'
      },
      {
        type: PatternType.REGEX,
        patternId: 'cmdi-java-processbuilder',
        pattern: 'new\\s+ProcessBuilder\\s*\\([^)]*\\+',
        flags: 'gi',
        weight: 0.90,
        description: 'ProcessBuilder with concatenation'
      }
    ],
    impact: {
      confidentiality: 'high',
      integrity: 'high',
      availability: 'high',
      technicalImpact: 'Arbitrary command execution on server.',
      businessImpact: 'Complete system compromise.'
    },
    exploitability: {
      attackVector: 'network',
      attackComplexity: 'low',
      privilegesRequired: 'none',
      userInteraction: 'none'
    },
    remediation: {
      summary: 'Use ProcessBuilder with String array. Never concatenate user input into commands.',
      steps: [
        'Use ProcessBuilder with command array',
        'Validate input against allowlist',
        'Avoid shell interpretation by not using /bin/sh -c'
      ],
      secureCodeExample: `// Secure: Using ProcessBuilder with array
ProcessBuilder pb = new ProcessBuilder("ls", "-la", sanitizedPath);
Process p = pb.start();`,
      effort: 'medium',
      priority: 'immediate'
    },
    standards: {
      owasp: [OWASP_TOP_10_2021.A03],
      cwe: [CWE_REFERENCES.CWE_78]
    },
    tags: ['command-injection', 'java', 'runtime-exec', 'critical'],
    enabled: true
  }
];

export default commandInjectionRules;
