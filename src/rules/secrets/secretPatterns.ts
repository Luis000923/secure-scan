/**
 * Secrets Detection Rules
 * Comprehensive patterns for detecting hardcoded credentials and secrets
 */

import { Rule, Severity, ThreatType, FindingCategory } from '../../types';
import { getCWEStandard, getOWASPStandard } from '../standards';

/**
 * Secret pattern definition
 */
interface SecretPattern {
  id: string;
  name: string;
  pattern: RegExp;
  severity: Severity;
  description: string;
  remediation: string;
  falsePositiveFilters?: RegExp[];
}

/**
 * Comprehensive secret patterns
 */
export const SECRET_PATTERNS: SecretPattern[] = [
  // AWS Credentials
  {
    id: 'SECRET-AWS-ACCESS-KEY',
    name: 'AWS Access Key ID',
    pattern: /\b(AKIA[0-9A-Z]{16})\b/g,
    severity: Severity.CRITICAL,
    description: 'Detected an AWS Access Key ID. This could allow unauthorized access to AWS services.',
    remediation: 'Remove the hardcoded AWS key and use environment variables or AWS IAM roles instead.'
  },
  {
    id: 'SECRET-AWS-SECRET-KEY',
    name: 'AWS Secret Access Key',
    pattern: /(?:aws_secret_access_key|aws_secret_key|secret_access_key)\s*[=:]\s*['"]?([A-Za-z0-9/+=]{40})['"]?/gi,
    severity: Severity.CRITICAL,
    description: 'Detected an AWS Secret Access Key. This could allow full access to AWS services.',
    remediation: 'Remove the hardcoded secret and use AWS Secrets Manager or environment variables.'
  },
  {
    id: 'SECRET-AWS-MWS-KEY',
    name: 'AWS MWS Auth Token',
    pattern: /amzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/gi,
    severity: Severity.CRITICAL,
    description: 'Detected an Amazon MWS authentication token.',
    remediation: 'Rotate the MWS token and store securely in a secrets manager.'
  },

  // Google Cloud
  {
    id: 'SECRET-GCP-API-KEY',
    name: 'Google Cloud API Key',
    pattern: /AIza[0-9A-Za-z\-_]{35}/g,
    severity: Severity.HIGH,
    description: 'Detected a Google Cloud API key that could be used to access GCP services.',
    remediation: 'Restrict the API key in Google Cloud Console and use environment variables.'
  },
  {
    id: 'SECRET-GCP-SERVICE-ACCOUNT',
    name: 'Google Cloud Service Account',
    pattern: /"type"\s*:\s*"service_account"[\s\S]*?"private_key"\s*:\s*"-----BEGIN (RSA )?PRIVATE KEY-----/g,
    severity: Severity.CRITICAL,
    description: 'Detected a Google Cloud service account JSON key file.',
    remediation: 'Remove the service account key and use Workload Identity or Secret Manager.'
  },

  // GitHub
  {
    id: 'SECRET-GITHUB-TOKEN',
    name: 'GitHub Personal Access Token',
    pattern: /ghp_[0-9a-zA-Z]{36}/g,
    severity: Severity.CRITICAL,
    description: 'Detected a GitHub Personal Access Token (classic).',
    remediation: 'Revoke the token on GitHub and use environment variables or GitHub Apps.'
  },
  {
    id: 'SECRET-GITHUB-OAUTH',
    name: 'GitHub OAuth Access Token',
    pattern: /gho_[0-9a-zA-Z]{36}/g,
    severity: Severity.HIGH,
    description: 'Detected a GitHub OAuth access token.',
    remediation: 'Revoke the token and implement proper OAuth flow with token storage.'
  },
  {
    id: 'SECRET-GITHUB-APP',
    name: 'GitHub App Token',
    pattern: /(ghu|ghs)_[0-9a-zA-Z]{36}/g,
    severity: Severity.HIGH,
    description: 'Detected a GitHub App installation or user token.',
    remediation: 'Revoke and rotate the token. Store securely in a secrets manager.'
  },
  {
    id: 'SECRET-GITHUB-REFRESH',
    name: 'GitHub Refresh Token',
    pattern: /ghr_[0-9a-zA-Z]{36}/g,
    severity: Severity.HIGH,
    description: 'Detected a GitHub refresh token.',
    remediation: 'Revoke the token and implement secure token storage.'
  },

  // Slack
  {
    id: 'SECRET-SLACK-TOKEN',
    name: 'Slack Bot/User Token',
    pattern: /xox[baprs]-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*/g,
    severity: Severity.HIGH,
    description: 'Detected a Slack API token that could access workspace data.',
    remediation: 'Revoke the token in Slack workspace settings and use environment variables.'
  },
  {
    id: 'SECRET-SLACK-WEBHOOK',
    name: 'Slack Webhook URL',
    pattern: /https:\/\/hooks\.slack\.com\/services\/T[a-zA-Z0-9_]{8,12}\/B[a-zA-Z0-9_]{8,12}\/[a-zA-Z0-9_]{24}/g,
    severity: Severity.MEDIUM,
    description: 'Detected a Slack incoming webhook URL.',
    remediation: 'Regenerate the webhook URL and store in environment variables.'
  },

  // Stripe
  {
    id: 'SECRET-STRIPE-API-KEY',
    name: 'Stripe API Key',
    pattern: /sk_(live|test)_[0-9a-zA-Z]{24,}/g,
    severity: Severity.CRITICAL,
    description: 'Detected a Stripe API secret key. This could allow unauthorized payment operations.',
    remediation: 'Revoke the key in Stripe Dashboard and use environment variables.'
  },
  {
    id: 'SECRET-STRIPE-RESTRICTED',
    name: 'Stripe Restricted Key',
    pattern: /rk_(live|test)_[0-9a-zA-Z]{24,}/g,
    severity: Severity.HIGH,
    description: 'Detected a Stripe restricted API key.',
    remediation: 'Review key permissions and store securely.'
  },

  // Twilio
  {
    id: 'SECRET-TWILIO-API-KEY',
    name: 'Twilio API Key',
    pattern: /SK[0-9a-fA-F]{32}/g,
    severity: Severity.HIGH,
    description: 'Detected a Twilio API key that could send SMS/calls.',
    remediation: 'Revoke in Twilio Console and use environment variables.'
  },
  {
    id: 'SECRET-TWILIO-ACCOUNT-SID',
    name: 'Twilio Account SID',
    pattern: /AC[a-zA-Z0-9]{32}/g,
    severity: Severity.MEDIUM,
    description: 'Detected a Twilio Account SID.',
    remediation: 'Keep SID private and never expose with Auth Token.'
  },

  // Mailgun / Mailchimp
  {
    id: 'SECRET-MAILGUN-KEY',
    name: 'Mailgun API Key',
    pattern: /key-[0-9a-zA-Z]{32}/g,
    severity: Severity.HIGH,
    description: 'Detected a Mailgun API key.',
    remediation: 'Rotate the key and store in environment variables.'
  },
  {
    id: 'SECRET-MAILCHIMP-KEY',
    name: 'Mailchimp API Key',
    pattern: /[0-9a-f]{32}-us[0-9]{1,2}/g,
    severity: Severity.HIGH,
    description: 'Detected a Mailchimp API key.',
    remediation: 'Rotate the key in Mailchimp settings.'
  },

  // SendGrid
  {
    id: 'SECRET-SENDGRID-KEY',
    name: 'SendGrid API Key',
    pattern: /SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}/g,
    severity: Severity.HIGH,
    description: 'Detected a SendGrid API key.',
    remediation: 'Revoke and regenerate the key in SendGrid.'
  },

  // Firebase
  {
    id: 'SECRET-FIREBASE-KEY',
    name: 'Firebase API Key',
    pattern: /AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}/g,
    severity: Severity.HIGH,
    description: 'Detected a Firebase Cloud Messaging server key.',
    remediation: 'Rotate the key and restrict access in Firebase Console.'
  },

  // Private Keys
  {
    id: 'SECRET-PRIVATE-KEY-RSA',
    name: 'RSA Private Key',
    pattern: /-----BEGIN RSA PRIVATE KEY-----[\s\S]*?-----END RSA PRIVATE KEY-----/g,
    severity: Severity.CRITICAL,
    description: 'Detected an RSA private key. This could compromise encrypted communications.',
    remediation: 'Remove the private key from code and store in a secure key vault.'
  },
  {
    id: 'SECRET-PRIVATE-KEY-DSA',
    name: 'DSA Private Key',
    pattern: /-----BEGIN DSA PRIVATE KEY-----[\s\S]*?-----END DSA PRIVATE KEY-----/g,
    severity: Severity.CRITICAL,
    description: 'Detected a DSA private key.',
    remediation: 'Remove the private key from code and store in a secure key vault.'
  },
  {
    id: 'SECRET-PRIVATE-KEY-EC',
    name: 'EC Private Key',
    pattern: /-----BEGIN EC PRIVATE KEY-----[\s\S]*?-----END EC PRIVATE KEY-----/g,
    severity: Severity.CRITICAL,
    description: 'Detected an EC private key.',
    remediation: 'Remove the private key from code and store in a secure key vault.'
  },
  {
    id: 'SECRET-PRIVATE-KEY-OPENSSH',
    name: 'OpenSSH Private Key',
    pattern: /-----BEGIN OPENSSH PRIVATE KEY-----[\s\S]*?-----END OPENSSH PRIVATE KEY-----/g,
    severity: Severity.CRITICAL,
    description: 'Detected an OpenSSH private key.',
    remediation: 'Remove the private key from code and store in ~/.ssh with proper permissions.'
  },
  {
    id: 'SECRET-PRIVATE-KEY-PGP',
    name: 'PGP Private Key',
    pattern: /-----BEGIN PGP PRIVATE KEY BLOCK-----[\s\S]*?-----END PGP PRIVATE KEY BLOCK-----/g,
    severity: Severity.CRITICAL,
    description: 'Detected a PGP private key.',
    remediation: 'Remove the private key from code and store securely.'
  },

  // Generic Patterns
  {
    id: 'SECRET-PASSWORD-ASSIGN',
    name: 'Hardcoded Password',
    pattern: /(?:password|passwd|pwd|pass|secret)\s*[=:]\s*['"][^'"]{8,}['"]/gi,
    severity: Severity.HIGH,
    description: 'Detected a hardcoded password in the source code.',
    remediation: 'Use environment variables or a secrets manager for passwords.',
    falsePositiveFilters: [
      /password\s*[=:]\s*['"]\s*['"]/gi, // Empty password
      /password\s*[=:]\s*['"]<[^>]+>['"]/gi, // Placeholder
      /password\s*[=:]\s*['"]{{[^}]+}}['"]/gi, // Template
      /password\s*[=:]\s*['"]\$\{[^}]+\}['"]/gi, // Variable interpolation
    ]
  },
  {
    id: 'SECRET-API-KEY-GENERIC',
    name: 'Generic API Key',
    pattern: /(?:api[_-]?key|apikey|api[_-]?secret)\s*[=:]\s*['"][a-zA-Z0-9_\-]{20,}['"]/gi,
    severity: Severity.HIGH,
    description: 'Detected a possible API key assignment.',
    remediation: 'Use environment variables for API keys.',
    falsePositiveFilters: [
      /api[_-]?key\s*[=:]\s*['"]\s*['"]/gi,
      /api[_-]?key\s*[=:]\s*['"]YOUR[_-]?API[_-]?KEY['"]/gi,
      /api[_-]?key\s*[=:]\s*['"]<[^>]+>['"]/gi,
    ]
  },
  {
    id: 'SECRET-AUTH-TOKEN',
    name: 'Authorization Token',
    pattern: /(?:auth[_-]?token|access[_-]?token|bearer[_-]?token)\s*[=:]\s*['"][a-zA-Z0-9_\-\.]{20,}['"]/gi,
    severity: Severity.HIGH,
    description: 'Detected a hardcoded authorization token.',
    remediation: 'Use secure token storage and environment variables.'
  },

  // Database Connection Strings
  {
    id: 'SECRET-MONGODB-URI',
    name: 'MongoDB Connection String',
    pattern: /mongodb(\+srv)?:\/\/[^:]+:[^@]+@[^/]+/gi,
    severity: Severity.HIGH,
    description: 'Detected a MongoDB connection string with credentials.',
    remediation: 'Use environment variables for database connection strings.'
  },
  {
    id: 'SECRET-POSTGRES-URI',
    name: 'PostgreSQL Connection String',
    pattern: /postgres(ql)?:\/\/[^:]+:[^@]+@[^/]+/gi,
    severity: Severity.HIGH,
    description: 'Detected a PostgreSQL connection string with credentials.',
    remediation: 'Use environment variables for database connection strings.'
  },
  {
    id: 'SECRET-MYSQL-URI',
    name: 'MySQL Connection String',
    pattern: /mysql:\/\/[^:]+:[^@]+@[^/]+/gi,
    severity: Severity.HIGH,
    description: 'Detected a MySQL connection string with credentials.',
    remediation: 'Use environment variables for database connection strings.'
  },
  {
    id: 'SECRET-REDIS-URI',
    name: 'Redis Connection String',
    pattern: /redis:\/\/:[^@]+@[^/]+/gi,
    severity: Severity.HIGH,
    description: 'Detected a Redis connection string with password.',
    remediation: 'Use environment variables for Redis connections.'
  },

  // JWT Secrets
  {
    id: 'SECRET-JWT-SECRET',
    name: 'JWT Secret Key',
    pattern: /(?:jwt[_-]?secret|jwt[_-]?key)\s*[=:]\s*['"][^'"]{16,}['"]/gi,
    severity: Severity.HIGH,
    description: 'Detected a hardcoded JWT secret key.',
    remediation: 'Use environment variables and rotate JWT secrets regularly.'
  },

  // Encryption Keys
  {
    id: 'SECRET-ENCRYPTION-KEY',
    name: 'Encryption Key',
    pattern: /(?:encryption[_-]?key|secret[_-]?key|aes[_-]?key)\s*[=:]\s*['"][a-fA-F0-9]{32,}['"]/gi,
    severity: Severity.HIGH,
    description: 'Detected a hardcoded encryption key.',
    remediation: 'Use a key management service (KMS) for encryption keys.'
  },

  // NPM Token
  {
    id: 'SECRET-NPM-TOKEN',
    name: 'NPM Access Token',
    pattern: /(?:npm_|NPM_)[a-zA-Z0-9]{36}/g,
    severity: Severity.HIGH,
    description: 'Detected an NPM access token.',
    remediation: 'Revoke the token on npmjs.com and use environment variables.'
  },

  // PyPI Token
  {
    id: 'SECRET-PYPI-TOKEN',
    name: 'PyPI API Token',
    pattern: /pypi-[A-Za-z0-9_-]{100,}/g,
    severity: Severity.HIGH,
    description: 'Detected a PyPI API token.',
    remediation: 'Revoke the token on pypi.org and use environment variables.'
  },

  // Heroku
  {
    id: 'SECRET-HEROKU-API',
    name: 'Heroku API Key',
    pattern: /[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}/g,
    severity: Severity.MEDIUM,
    description: 'Detected a possible Heroku API key (UUID format).',
    remediation: 'Verify if this is a Heroku key and store in environment variables.',
    falsePositiveFilters: [
      /\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-5][0-9a-fA-F]{3}-[089ab][0-9a-fA-F]{3}-[0-9a-fA-F]{12}\b/g // Standard UUID
    ]
  },

  // Discord
  {
    id: 'SECRET-DISCORD-TOKEN',
    name: 'Discord Bot Token',
    pattern: /[MN][A-Za-z\d]{23,}\.[\w-]{6}\.[\w-]{27}/g,
    severity: Severity.HIGH,
    description: 'Detected a Discord bot token.',
    remediation: 'Regenerate the bot token in Discord Developer Portal.'
  },
  {
    id: 'SECRET-DISCORD-WEBHOOK',
    name: 'Discord Webhook URL',
    pattern: /https:\/\/discord(?:app)?\.com\/api\/webhooks\/[0-9]+\/[A-Za-z0-9_-]+/g,
    severity: Severity.MEDIUM,
    description: 'Detected a Discord webhook URL.',
    remediation: 'Regenerate the webhook and store securely.'
  },

  // Telegram
  {
    id: 'SECRET-TELEGRAM-TOKEN',
    name: 'Telegram Bot Token',
    pattern: /[0-9]{8,10}:[a-zA-Z0-9_-]{35}/g,
    severity: Severity.HIGH,
    description: 'Detected a Telegram bot token.',
    remediation: 'Revoke token via BotFather and store in environment variables.'
  },
];

/**
 * Convert secret patterns to rules
 */
export function getSecretRules(): Rule[] {
  return SECRET_PATTERNS.map(secretPattern => ({
    id: secretPattern.id,
    name: secretPattern.name,
    description: secretPattern.description,
    languages: ['javascript', 'typescript', 'python', 'php', 'java', 'c', 'cpp', 'csharp', 'yaml', 'dockerfile', 'terraform'],
    threatType: ThreatType.HARDCODED_CREDENTIALS,
    category: FindingCategory.VULNERABILITY,
    severity: secretPattern.severity,
    patterns: [{
      type: 'regex' as const,
      pattern: secretPattern.pattern.source,
      flags: secretPattern.pattern.flags
    }],
    standards: [
      getCWEStandard('CWE-798'),
      getCWEStandard('CWE-259'),
      getOWASPStandard('A07:2021')
    ],
    remediation: secretPattern.remediation,
    enabled: true,
    tags: ['secrets', 'credentials', 'hardcoded']
  }));
}

export default SECRET_PATTERNS;
