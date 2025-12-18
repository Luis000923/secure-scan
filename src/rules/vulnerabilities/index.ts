/**
 * Vulnerability Detection Rules
 * Patterns for detecting common security vulnerabilities
 */

import { Rule, Severity, ThreatType, FindingCategory } from '../../types';
import { getStandardsForThreat } from '../standards';

/**
 * SQL Injection Rules
 */
const sqlInjectionRules: Rule[] = [
  {
    id: 'VULN-SQL-001',
    name: 'Potential SQL Injection',
    description: 'Direct string concatenation in SQL query detected. User input may be directly interpolated into SQL statements, allowing attackers to modify queries.',
    languages: ['javascript', 'typescript', 'python', 'php', 'java', 'csharp'],
    threatType: ThreatType.SQL_INJECTION,
    category: FindingCategory.VULNERABILITY,
    severity: Severity.CRITICAL,
    standards: getStandardsForThreat(ThreatType.SQL_INJECTION),
    patterns: [
      {
        type: 'regex',
        pattern: '(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|EXEC|EXECUTE)\\s+.*\\+\\s*[\'"]?\\$?\\{?\\w+',
        flags: 'gi'
      },
      {
        type: 'regex',
        pattern: '\\.(query|execute|exec)\\s*\\(\\s*[\'"`].*\\$\\{',
        flags: 'gi'
      },
      {
        type: 'regex',
        pattern: 'f[\'"]SELECT.*{.*}',
        flags: 'gi'
      },
      {
        type: 'regex',
        pattern: '\\.format\\s*\\(.*\\).*(?:SELECT|INSERT|UPDATE|DELETE)',
        flags: 'gi'
      }
    ],
    remediation: 'Use parameterized queries or prepared statements. Never concatenate user input directly into SQL queries. Use ORM frameworks that handle escaping automatically.',
    enabled: true,
    tags: ['sql', 'injection', 'database', 'owasp-a03']
  }
];

/**
 * Command Injection Rules
 */
const commandInjectionRules: Rule[] = [
  {
    id: 'VULN-CMD-001',
    name: 'Command Injection via exec/system',
    description: 'Use of command execution functions with potentially unsanitized input. Attackers can inject malicious commands.',
    languages: ['javascript', 'typescript', 'python', 'php', 'java', 'csharp', 'c', 'cpp'],
    threatType: ThreatType.COMMAND_INJECTION,
    category: FindingCategory.VULNERABILITY,
    severity: Severity.CRITICAL,
    standards: getStandardsForThreat(ThreatType.COMMAND_INJECTION),
    patterns: [
      {
        type: 'regex',
        pattern: '\\bexec\\s*\\([^)]*\\$',
        flags: 'gi'
      },
      {
        type: 'regex',
        pattern: '\\bsystem\\s*\\([^)]*[\\$\\+]',
        flags: 'gi'
      },
      {
        type: 'regex',
        pattern: 'child_process\\.(exec|spawn|execSync)\\s*\\([^)]*\\+',
        flags: 'gi'
      },
      {
        type: 'regex',
        pattern: 'os\\.system\\s*\\([^)]*[\\+f\\"\']',
        flags: 'gi'
      },
      {
        type: 'regex',
        pattern: 'subprocess\\.(call|run|Popen)\\s*\\([^)]*shell\\s*=\\s*True',
        flags: 'gi'
      },
      {
        type: 'regex',
        pattern: 'Runtime\\.getRuntime\\(\\)\\.exec\\s*\\([^)]*\\+',
        flags: 'gi'
      },
      {
        type: 'regex',
        pattern: 'shell_exec\\s*\\([^)]*\\$',
        flags: 'gi'
      },
      {
        type: 'regex',
        pattern: 'passthru\\s*\\([^)]*\\$',
        flags: 'gi'
      }
    ],
    remediation: 'Avoid using shell commands with user input. If necessary, use allowlists for valid inputs, escape special characters, or use safer alternatives like specific library functions.',
    enabled: true,
    tags: ['command', 'injection', 'rce', 'owasp-a03']
  }
];

/**
 * XSS Rules
 */
const xssRules: Rule[] = [
  {
    id: 'VULN-XSS-001',
    name: 'Potential Cross-Site Scripting (XSS)',
    description: 'User input appears to be rendered directly in HTML without proper encoding, potentially allowing script injection.',
    languages: ['javascript', 'typescript', 'php'],
    threatType: ThreatType.XSS,
    category: FindingCategory.VULNERABILITY,
    severity: Severity.HIGH,
    standards: getStandardsForThreat(ThreatType.XSS),
    patterns: [
      {
        type: 'regex',
        pattern: 'innerHTML\\s*=\\s*[^;]*\\$',
        flags: 'gi'
      },
      {
        type: 'regex',
        pattern: 'document\\.write\\s*\\([^)]*\\+',
        flags: 'gi'
      },
      {
        type: 'regex',
        pattern: '\\$\\(.*\\)\\.html\\s*\\([^)]*\\+',
        flags: 'gi'
      },
      {
        type: 'regex',
        pattern: 'dangerouslySetInnerHTML',
        flags: 'gi'
      },
      {
        type: 'regex',
        pattern: 'v-html\\s*=',
        flags: 'gi'
      },
      {
        type: 'regex',
        pattern: 'echo\\s+\\$_(GET|POST|REQUEST)',
        flags: 'gi'
      }
    ],
    remediation: 'Always encode user input before rendering in HTML. Use textContent instead of innerHTML. Implement Content Security Policy (CSP). Use framework-provided escaping functions.',
    enabled: true,
    tags: ['xss', 'injection', 'frontend', 'owasp-a03']
  }
];

/**
 * Hardcoded Credentials Rules
 */
const credentialRules: Rule[] = [
  {
    id: 'VULN-CRED-001',
    name: 'Hardcoded Password',
    description: 'Password appears to be hardcoded in source code. This is a severe security risk as credentials may be exposed in version control.',
    languages: ['javascript', 'typescript', 'python', 'php', 'java', 'csharp', 'c', 'cpp'],
    threatType: ThreatType.HARDCODED_CREDENTIALS,
    category: FindingCategory.VULNERABILITY,
    severity: Severity.HIGH,
    standards: getStandardsForThreat(ThreatType.HARDCODED_CREDENTIALS),
    patterns: [
      {
        type: 'regex',
        pattern: '(?:password|passwd|pwd|secret)\\s*[=:]\\s*[\'"][^\'"]{4,}[\'"]',
        flags: 'gi'
      },
      {
        type: 'regex',
        pattern: '(?:api_key|apikey|api-key|access_token|auth_token)\\s*[=:]\\s*[\'"][^\'"]{8,}[\'"]',
        flags: 'gi'
      },
      {
        type: 'regex',
        pattern: '(?:aws_secret|aws_access)\\s*[=:]\\s*[\'"][^\'"]+[\'"]',
        flags: 'gi'
      },
      {
        type: 'regex',
        pattern: 'Bearer\\s+[A-Za-z0-9\\-_]+\\.[A-Za-z0-9\\-_]+\\.[A-Za-z0-9\\-_]+',
        flags: 'g'
      },
      {
        type: 'regex',
        pattern: '-----BEGIN\\s+(RSA\\s+)?PRIVATE\\s+KEY-----',
        flags: 'gi'
      }
    ],
    remediation: 'Never hardcode credentials in source code. Use environment variables, secret management systems (HashiCorp Vault, AWS Secrets Manager), or configuration files excluded from version control.',
    enabled: true,
    tags: ['credentials', 'secrets', 'hardcoded', 'owasp-a07']
  }
];

/**
 * Dangerous Function Rules
 */
const dangerousFunctionRules: Rule[] = [
  {
    id: 'VULN-FUNC-001',
    name: 'Dangerous eval() Usage',
    description: 'Use of eval() function detected. eval() executes arbitrary code and is extremely dangerous with user input.',
    languages: ['javascript', 'typescript', 'python', 'php'],
    threatType: ThreatType.DANGEROUS_FUNCTION,
    category: FindingCategory.VULNERABILITY,
    severity: Severity.HIGH,
    standards: getStandardsForThreat(ThreatType.DANGEROUS_FUNCTION),
    patterns: [
      {
        type: 'regex',
        pattern: '\\beval\\s*\\(',
        flags: 'g'
      },
      {
        type: 'regex',
        pattern: '\\bnew\\s+Function\\s*\\(',
        flags: 'g'
      },
      {
        type: 'regex',
        pattern: 'setTimeout\\s*\\(\\s*[\'"`]',
        flags: 'g'
      },
      {
        type: 'regex',
        pattern: 'setInterval\\s*\\(\\s*[\'"`]',
        flags: 'g'
      }
    ],
    remediation: 'Avoid using eval() and similar functions. Use JSON.parse() for JSON data. Use safer alternatives for dynamic code execution.',
    enabled: true,
    tags: ['eval', 'dangerous', 'code-execution', 'owasp-a03']
  }
];

/**
 * Path Traversal Rules
 */
const pathTraversalRules: Rule[] = [
  {
    id: 'VULN-PATH-001',
    name: 'Path Traversal Vulnerability',
    description: 'User input used in file path without proper validation. Attackers may access files outside the intended directory.',
    languages: ['javascript', 'typescript', 'python', 'php', 'java', 'csharp'],
    threatType: ThreatType.PATH_TRAVERSAL,
    category: FindingCategory.VULNERABILITY,
    severity: Severity.HIGH,
    standards: getStandardsForThreat(ThreatType.PATH_TRAVERSAL),
    patterns: [
      {
        type: 'regex',
        pattern: 'readFile(?:Sync)?\\s*\\([^)]*\\+',
        flags: 'gi'
      },
      {
        type: 'regex',
        pattern: 'path\\.(?:join|resolve)\\s*\\([^)]*req\\.',
        flags: 'gi'
      },
      {
        type: 'regex',
        pattern: 'open\\s*\\([^)]*\\+[^)]*[\'"]r',
        flags: 'gi'
      },
      {
        type: 'regex',
        pattern: 'file_get_contents\\s*\\([^)]*\\$',
        flags: 'gi'
      },
      {
        type: 'regex',
        pattern: 'include\\s*\\([^)]*\\$',
        flags: 'gi'
      }
    ],
    remediation: 'Validate and sanitize file paths. Use path.normalize() and check the resolved path starts with the intended base directory. Never use user input directly in file operations.',
    enabled: true,
    tags: ['path', 'traversal', 'lfi', 'owasp-a01']
  }
];

/**
 * Insecure Cryptography Rules
 */
const cryptoRules: Rule[] = [
  {
    id: 'VULN-CRYPTO-001',
    name: 'Weak Cryptographic Algorithm',
    description: 'Use of weak or deprecated cryptographic algorithm detected. MD5 and SHA1 are vulnerable to collision attacks.',
    languages: ['javascript', 'typescript', 'python', 'php', 'java', 'csharp'],
    threatType: ThreatType.INSECURE_CRYPTO,
    category: FindingCategory.VULNERABILITY,
    severity: Severity.MEDIUM,
    standards: getStandardsForThreat(ThreatType.INSECURE_CRYPTO),
    patterns: [
      {
        type: 'regex',
        pattern: 'createHash\\s*\\(\\s*[\'"](?:md5|sha1)[\'"]\\s*\\)',
        flags: 'gi'
      },
      {
        type: 'regex',
        pattern: 'hashlib\\.(?:md5|sha1)\\s*\\(',
        flags: 'gi'
      },
      {
        type: 'regex',
        pattern: 'md5\\s*\\(',
        flags: 'gi'
      },
      {
        type: 'regex',
        pattern: 'DES|3DES|RC4|RC2',
        flags: 'g'
      }
    ],
    remediation: 'Use strong cryptographic algorithms: SHA-256 or SHA-3 for hashing, AES-256 for encryption. Use bcrypt, scrypt, or Argon2 for password hashing.',
    enabled: true,
    tags: ['crypto', 'weak', 'hash', 'owasp-a02']
  },
  {
    id: 'VULN-CRYPTO-002',
    name: 'Weak Random Number Generation',
    description: 'Use of weak random number generator for security-sensitive operations. Math.random() and similar are not cryptographically secure.',
    languages: ['javascript', 'typescript', 'python', 'php', 'java'],
    threatType: ThreatType.WEAK_RANDOM,
    category: FindingCategory.VULNERABILITY,
    severity: Severity.MEDIUM,
    standards: getStandardsForThreat(ThreatType.WEAK_RANDOM),
    patterns: [
      {
        type: 'regex',
        pattern: 'Math\\.random\\s*\\(\\)',
        flags: 'g'
      },
      {
        type: 'regex',
        pattern: 'random\\.random\\s*\\(\\)',
        flags: 'g'
      },
      {
        type: 'regex',
        pattern: '\\brand\\s*\\(\\s*\\)',
        flags: 'g'
      }
    ],
    remediation: 'Use cryptographically secure random number generators: crypto.randomBytes() in Node.js, secrets module in Python, SecureRandom in Java.',
    enabled: true,
    tags: ['random', 'crypto', 'prng', 'owasp-a02']
  }
];

/**
 * Insecure Deserialization Rules
 */
const deserializationRules: Rule[] = [
  {
    id: 'VULN-DESER-001',
    name: 'Insecure Deserialization',
    description: 'Use of potentially unsafe deserialization detected. Deserializing untrusted data can lead to remote code execution.',
    languages: ['javascript', 'typescript', 'python', 'php', 'java', 'csharp'],
    threatType: ThreatType.INSECURE_DESERIALIZATION,
    category: FindingCategory.VULNERABILITY,
    severity: Severity.CRITICAL,
    standards: getStandardsForThreat(ThreatType.INSECURE_DESERIALIZATION),
    patterns: [
      {
        type: 'regex',
        pattern: 'pickle\\.loads?\\s*\\(',
        flags: 'gi'
      },
      {
        type: 'regex',
        pattern: 'yaml\\.load\\s*\\([^)]*(?!Loader)',
        flags: 'gi'
      },
      {
        type: 'regex',
        pattern: 'unserialize\\s*\\([^)]*\\$',
        flags: 'gi'
      },
      {
        type: 'regex',
        pattern: 'ObjectInputStream',
        flags: 'g'
      },
      {
        type: 'regex',
        pattern: 'BinaryFormatter\\.Deserialize',
        flags: 'gi'
      }
    ],
    remediation: 'Avoid deserializing untrusted data. Use safe serialization formats like JSON. If deserialization is necessary, validate data integrity and restrict allowed classes.',
    enabled: true,
    tags: ['deserialization', 'rce', 'owasp-a08']
  }
];

/**
 * Export all vulnerability rules
 */
export const vulnerabilityRules: Rule[] = [
  ...sqlInjectionRules,
  ...commandInjectionRules,
  ...xssRules,
  ...credentialRules,
  ...dangerousFunctionRules,
  ...pathTraversalRules,
  ...cryptoRules,
  ...deserializationRules
];

export default vulnerabilityRules;
