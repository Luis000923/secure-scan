/**
 * @fileoverview Hardcoded Secrets Detection Rules
 * @module rules/vulnerabilities/rules/hardcodedSecrets
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

export const hardcodedSecretsRules: VulnerabilityRule[] = [
  {
    id: 'VUL-SECRET-001',
    name: 'Hardcoded API Key',
    description: 'Detects hardcoded API keys in source code.',
    version: '1.0.0',
    vulnerabilityType: VulnerabilityType.HARDCODED_SECRETS,
    category: VulnerabilityCategory.SENSITIVE_DATA_EXPOSURE,
    languages: [
      SupportedLanguage.JAVASCRIPT, SupportedLanguage.TYPESCRIPT,
      SupportedLanguage.PYTHON, SupportedLanguage.PHP,
      SupportedLanguage.JAVA, SupportedLanguage.CSHARP
    ],
    severity: VulnerabilitySeverity.HIGH,
    confidence: ConfidenceLevel.MEDIUM,
    baseScore: 75,
    patterns: [
      {
        type: PatternType.REGEX,
        patternId: 'secret-api-key-assign',
        pattern: '(?:api[_-]?key|apikey|api[_-]?secret)\\s*[=:]\\s*[\'"][a-zA-Z0-9_\\-]{16,}[\'"]',
        flags: 'gi',
        weight: 0.95,
        description: 'API key assignment'
      },
      {
        type: PatternType.REGEX,
        patternId: 'secret-aws-key',
        pattern: 'AKIA[0-9A-Z]{16}',
        flags: 'g',
        weight: 1.0,
        description: 'AWS Access Key ID'
      },
      {
        type: PatternType.REGEX,
        patternId: 'secret-google-api',
        pattern: 'AIza[0-9A-Za-z\\-_]{35}',
        flags: 'g',
        weight: 1.0,
        description: 'Google API Key'
      },
      {
        type: PatternType.REGEX,
        patternId: 'secret-stripe-key',
        pattern: '(?:sk|pk)_(?:test|live)_[0-9a-zA-Z]{24,}',
        flags: 'g',
        weight: 1.0,
        description: 'Stripe API Key'
      },
      {
        type: PatternType.REGEX,
        patternId: 'secret-github-token',
        pattern: 'gh[pousr]_[A-Za-z0-9_]{36,}',
        flags: 'g',
        weight: 1.0,
        description: 'GitHub Token'
      }
    ],
    impact: {
      confidentiality: 'high',
      integrity: 'medium',
      availability: 'low',
      technicalImpact: 'Unauthorized access to external services.',
      businessImpact: 'Financial loss, data breach, service abuse.'
    },
    exploitability: {
      attackVector: 'network',
      attackComplexity: 'low',
      privilegesRequired: 'none',
      userInteraction: 'none'
    },
    remediation: {
      summary: 'Store secrets in environment variables or secret management systems.',
      steps: [
        'Remove hardcoded keys immediately',
        'Rotate compromised keys',
        'Use environment variables',
        'Implement secret management (Vault, AWS Secrets Manager)',
        'Add pre-commit hooks to prevent secret commits'
      ],
      secureCodeExample: `// Secure: Use environment variables
const apiKey = process.env.API_KEY;

// Python
api_key = os.environ.get('API_KEY')

// Java
String apiKey = System.getenv("API_KEY");`,
      effort: 'low',
      priority: 'high'
    },
    standards: {
      owasp: [OWASP_TOP_10_2021.A02],
      cwe: [CWE_REFERENCES.CWE_798]
    },
    tags: ['secrets', 'api-key', 'credentials'],
    enabled: true
  },
  {
    id: 'VUL-SECRET-002',
    name: 'Hardcoded Password',
    description: 'Detects hardcoded passwords in source code.',
    version: '1.0.0',
    vulnerabilityType: VulnerabilityType.HARDCODED_SECRETS,
    category: VulnerabilityCategory.SENSITIVE_DATA_EXPOSURE,
    languages: [
      SupportedLanguage.JAVASCRIPT, SupportedLanguage.TYPESCRIPT,
      SupportedLanguage.PYTHON, SupportedLanguage.PHP,
      SupportedLanguage.JAVA, SupportedLanguage.CSHARP
    ],
    severity: VulnerabilitySeverity.HIGH,
    confidence: ConfidenceLevel.MEDIUM,
    baseScore: 80,
    patterns: [
      {
        type: PatternType.REGEX,
        patternId: 'secret-password-assign',
        pattern: '(?:password|passwd|pwd|secret|credentials?)\\s*[=:]\\s*[\'"][^\'"]{4,}[\'"]',
        flags: 'gi',
        weight: 0.85,
        description: 'Password variable assignment'
      },
      {
        type: PatternType.REGEX,
        patternId: 'secret-db-connection',
        pattern: '(?:mysql|postgres|mongodb|redis):\\/\\/[^:]+:[^@]+@',
        flags: 'gi',
        weight: 1.0,
        description: 'Database connection string with credentials'
      },
      {
        type: PatternType.REGEX,
        patternId: 'secret-connection-password',
        pattern: '(?:password|pwd)\\s*=\\s*[\'"][^\'"]+[\'"]',
        flags: 'gi',
        weight: 0.80,
        description: 'Password in connection config'
      }
    ],
    impact: {
      confidentiality: 'high',
      integrity: 'high',
      availability: 'medium',
      technicalImpact: 'Unauthorized access to systems and databases.',
      businessImpact: 'Data breach, unauthorized access.'
    },
    exploitability: {
      attackVector: 'network',
      attackComplexity: 'low',
      privilegesRequired: 'none',
      userInteraction: 'none'
    },
    remediation: {
      summary: 'Use environment variables or secret management for credentials.',
      steps: [
        'Remove hardcoded passwords',
        'Change all exposed passwords immediately',
        'Use environment variables or config files outside repo',
        'Implement secret rotation',
        'Use connection pooling with credential providers'
      ],
      secureCodeExample: `// Node.js - Use environment variables
const dbConfig = {
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD
};

# Python - Use environment variables
import os
db_password = os.environ['DB_PASSWORD']`,
      effort: 'low',
      priority: 'immediate'
    },
    standards: {
      owasp: [OWASP_TOP_10_2021.A02],
      cwe: [CWE_REFERENCES.CWE_798, CWE_REFERENCES.CWE_259]
    },
    tags: ['secrets', 'password', 'credentials', 'database'],
    enabled: true
  },
  {
    id: 'VUL-SECRET-003',
    name: 'Hardcoded Private Key / Certificate',
    description: 'Detects hardcoded private keys or certificates in source code.',
    version: '1.0.0',
    vulnerabilityType: VulnerabilityType.HARDCODED_SECRETS,
    category: VulnerabilityCategory.SENSITIVE_DATA_EXPOSURE,
    languages: [
      SupportedLanguage.JAVASCRIPT, SupportedLanguage.TYPESCRIPT,
      SupportedLanguage.PYTHON, SupportedLanguage.PHP,
      SupportedLanguage.JAVA, SupportedLanguage.CSHARP
    ],
    severity: VulnerabilitySeverity.CRITICAL,
    confidence: ConfidenceLevel.HIGH,
    baseScore: 90,
    patterns: [
      {
        type: PatternType.REGEX,
        patternId: 'secret-private-key-begin',
        pattern: '-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----',
        flags: 'g',
        weight: 1.0,
        description: 'PEM private key header'
      },
      {
        type: PatternType.REGEX,
        patternId: 'secret-private-key-var',
        pattern: '(?:private[_-]?key|privatekey|priv[_-]?key)\\s*[=:]\\s*[\'"`]',
        flags: 'gi',
        weight: 0.90,
        description: 'Private key variable assignment'
      },
      {
        type: PatternType.REGEX,
        patternId: 'secret-jwt-secret',
        pattern: '(?:jwt[_-]?secret|jwt[_-]?key|signing[_-]?key)\\s*[=:]\\s*[\'"][a-zA-Z0-9+\\/=]{20,}[\'"]',
        flags: 'gi',
        weight: 0.95,
        description: 'JWT signing secret'
      }
    ],
    impact: {
      confidentiality: 'high',
      integrity: 'high',
      availability: 'medium',
      technicalImpact: 'Complete compromise of cryptographic security. Token forgery, MITM attacks.',
      businessImpact: 'Identity theft, data interception, authentication bypass.'
    },
    exploitability: {
      attackVector: 'network',
      attackComplexity: 'low',
      privilegesRequired: 'none',
      userInteraction: 'none'
    },
    remediation: {
      summary: 'Store private keys in secure key management systems. Never commit keys to source control.',
      steps: [
        'Remove private keys from source code immediately',
        'Revoke and rotate compromised keys/certificates',
        'Use HSM or cloud KMS for key storage',
        'Load keys from secure file paths or environment',
        'Add key patterns to .gitignore'
      ],
      secureCodeExample: `// Load private key from file (not in repo)
const fs = require('fs');
const privateKey = fs.readFileSync(process.env.PRIVATE_KEY_PATH);

// Use cloud KMS
const { KMSClient, SignCommand } = require('@aws-sdk/client-kms');
const kms = new KMSClient({});
await kms.send(new SignCommand({ KeyId: 'alias/my-key', ... }));`,
      effort: 'medium',
      priority: 'immediate'
    },
    standards: {
      owasp: [OWASP_TOP_10_2021.A02],
      cwe: [CWE_REFERENCES.CWE_321, CWE_REFERENCES.CWE_798]
    },
    tags: ['secrets', 'private-key', 'certificate', 'jwt', 'critical'],
    enabled: true
  },
  {
    id: 'VUL-SECRET-004',
    name: 'Hardcoded OAuth/Bearer Token',
    description: 'Detects hardcoded OAuth tokens or bearer tokens in source code.',
    version: '1.0.0',
    vulnerabilityType: VulnerabilityType.HARDCODED_SECRETS,
    category: VulnerabilityCategory.SENSITIVE_DATA_EXPOSURE,
    languages: [
      SupportedLanguage.JAVASCRIPT, SupportedLanguage.TYPESCRIPT,
      SupportedLanguage.PYTHON, SupportedLanguage.PHP,
      SupportedLanguage.JAVA, SupportedLanguage.CSHARP
    ],
    severity: VulnerabilitySeverity.HIGH,
    confidence: ConfidenceLevel.MEDIUM,
    baseScore: 80,
    patterns: [
      {
        type: PatternType.REGEX,
        patternId: 'secret-bearer-token',
        pattern: 'Bearer\\s+[a-zA-Z0-9\\-_.]{20,}',
        flags: 'g',
        weight: 0.95,
        description: 'Bearer token in code'
      },
      {
        type: PatternType.REGEX,
        patternId: 'secret-oauth-token',
        pattern: '(?:oauth[_-]?token|access[_-]?token|refresh[_-]?token)\\s*[=:]\\s*[\'"][a-zA-Z0-9\\-_.]{20,}[\'"]',
        flags: 'gi',
        weight: 0.95,
        description: 'OAuth token assignment'
      },
      {
        type: PatternType.REGEX,
        patternId: 'secret-slack-token',
        pattern: 'xox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24}',
        flags: 'g',
        weight: 1.0,
        description: 'Slack token'
      },
      {
        type: PatternType.REGEX,
        patternId: 'secret-discord-token',
        pattern: '[MN][A-Za-z\\d]{23,}\\.[\\w-]{6}\\.[\\w-]{27}',
        flags: 'g',
        weight: 1.0,
        description: 'Discord bot token'
      }
    ],
    impact: {
      confidentiality: 'high',
      integrity: 'medium',
      availability: 'low',
      technicalImpact: 'Account takeover, unauthorized API access.',
      businessImpact: 'Data breach, service abuse, reputational damage.'
    },
    exploitability: {
      attackVector: 'network',
      attackComplexity: 'low',
      privilegesRequired: 'none',
      userInteraction: 'none'
    },
    remediation: {
      summary: 'Use OAuth flows with token refresh. Store tokens securely outside source code.',
      steps: [
        'Remove tokens from source code',
        'Revoke compromised tokens',
        'Implement proper OAuth flow',
        'Store tokens in secure storage',
        'Use short-lived tokens with refresh'
      ],
      secureCodeExample: `// Store token in environment or secure storage
const token = process.env.OAUTH_TOKEN;

// Better: Use OAuth client credentials flow
const { ClientCredentials } = require('simple-oauth2');
const client = new ClientCredentials(config);
const token = await client.getToken({ scope: 'api' });`,
      effort: 'medium',
      priority: 'high'
    },
    standards: {
      owasp: [OWASP_TOP_10_2021.A02, OWASP_TOP_10_2021.A07],
      cwe: [CWE_REFERENCES.CWE_798]
    },
    tags: ['secrets', 'oauth', 'token', 'bearer'],
    enabled: true
  },
  {
    id: 'VUL-SECRET-005',
    name: 'Hardcoded Encryption Key',
    description: 'Detects hardcoded encryption keys and initialization vectors.',
    version: '1.0.0',
    vulnerabilityType: VulnerabilityType.HARDCODED_SECRETS,
    category: VulnerabilityCategory.CRYPTOGRAPHIC_FAILURE,
    languages: [
      SupportedLanguage.JAVASCRIPT, SupportedLanguage.TYPESCRIPT,
      SupportedLanguage.PYTHON, SupportedLanguage.PHP,
      SupportedLanguage.JAVA, SupportedLanguage.CSHARP
    ],
    severity: VulnerabilitySeverity.CRITICAL,
    confidence: ConfidenceLevel.MEDIUM,
    baseScore: 85,
    patterns: [
      {
        type: PatternType.REGEX,
        patternId: 'secret-encryption-key',
        pattern: '(?:encryption[_-]?key|aes[_-]?key|secret[_-]?key|cipher[_-]?key)\\s*[=:]\\s*[\'"][a-fA-F0-9]{32,}[\'"]',
        flags: 'gi',
        weight: 0.95,
        description: 'Encryption key assignment'
      },
      {
        type: PatternType.REGEX,
        patternId: 'secret-iv-vector',
        pattern: '(?:iv|initialization[_-]?vector|init[_-]?vector)\\s*[=:]\\s*[\'"][a-fA-F0-9]{16,}[\'"]',
        flags: 'gi',
        weight: 0.85,
        description: 'Hardcoded IV'
      },
      {
        type: PatternType.REGEX,
        patternId: 'secret-key-bytes',
        pattern: 'new\\s+(?:Uint8Array|Buffer)\\s*\\(\\s*\\[(?:\\s*0x[0-9a-fA-F]{1,2}\\s*,?){16,}\\]',
        flags: 'gi',
        weight: 0.90,
        description: 'Hardcoded key bytes'
      }
    ],
    impact: {
      confidentiality: 'high',
      integrity: 'high',
      availability: 'low',
      technicalImpact: 'All encrypted data can be decrypted. Encryption provides no protection.',
      businessImpact: 'Complete data exposure, regulatory violations.'
    },
    exploitability: {
      attackVector: 'network',
      attackComplexity: 'low',
      privilegesRequired: 'none',
      userInteraction: 'none'
    },
    remediation: {
      summary: 'Use key derivation functions and store master keys in KMS or HSM.',
      steps: [
        'Remove hardcoded encryption keys',
        'Re-encrypt all data with new keys',
        'Use KMS or HSM for key management',
        'Derive keys using PBKDF2, scrypt, or Argon2',
        'Rotate encryption keys regularly'
      ],
      secureCodeExample: `// Use KMS to get encryption key
const { KMSClient, GenerateDataKeyCommand } = require('@aws-sdk/client-kms');
const kms = new KMSClient({});
const { Plaintext } = await kms.send(new GenerateDataKeyCommand({
  KeyId: 'alias/my-data-key',
  KeySpec: 'AES_256'
}));

// Derive key from password
const crypto = require('crypto');
const key = crypto.scryptSync(password, salt, 32);`,
      effort: 'high',
      priority: 'immediate'
    },
    standards: {
      owasp: [OWASP_TOP_10_2021.A02],
      cwe: [CWE_REFERENCES.CWE_321, CWE_REFERENCES.CWE_798]
    },
    tags: ['secrets', 'encryption', 'aes', 'cryptography', 'critical'],
    enabled: true
  }
];

export default hardcodedSecretsRules;
