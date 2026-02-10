/**
 * Hardcoded Credentials Detection Patterns
 * Shared across all language analyzers
 */

import { Severity, ThreatType, FindingCategory, SecurityStandard } from '../../../types';

/**
 * Common credential variable names that indicate secrets
 */
export const CREDENTIAL_VARIABLE_NAMES = [
  'password',
  'passwd',
  'pwd',
  'secret',
  'api_key',
  'apikey',
  'api-key',
  'access_key',
  'accesskey',
  'auth_token',
  'authtoken',
  'token',
  'private_key',
  'privatekey',
  'secret_key',
  'secretkey',
  'encryption_key',
  'encryptionkey',
  'master_key',
  'masterkey',
  'db_password',
  'database_password',
  'mysql_password',
  'postgres_password',
  'redis_password',
  'mongo_password',
  'jwt_secret',
  'session_secret',
  'cookie_secret',
  'signing_key',
  'client_secret',
  'oauth_secret',
];

/**
 * Build regex pattern for credential detection
 * Works across JavaScript, Python, Java, C#, PHP
 */
export function buildCredentialPattern(language: string): RegExp {
  const varNames = CREDENTIAL_VARIABLE_NAMES.join('|');

  switch (language) {
    case 'javascript':
    case 'typescript':
      // const password = "value" or password: "value"
      return new RegExp(
        `(?:const|let|var)?\\s*(${varNames})\\s*[=:]\\s*["'\`]([^"'\`]{8,})["'\`]`,
        'gi'
      );

    case 'python':
      // password = "value" or PASSWORD = "value"
      return new RegExp(
        `\\b(${varNames})\\s*=\\s*["']([^"']{8,})["']`,
        'gi'
      );

    case 'java':
    case 'csharp':
      // String password = "value" or private String password = "value"
      return new RegExp(
        `(?:private|public|protected)?\\s*(?:static)?\\s*(?:final)?\\s*(?:String|string)\\s+(${varNames})\\s*=\\s*"([^"]{8,})"`,
        'gi'
      );

    case 'php':
      // $password = "value"
      return new RegExp(
        `\\$(${varNames})\\s*=\\s*["']([^"']{8,})["']`,
        'gi'
      );

    default:
      return new RegExp(
        `(${varNames})\\s*[=:]\\s*["']([^"']{8,})["']`,
        'gi'
      );
  }
}

/**
 * AWS credential patterns
 */
export const AWS_PATTERNS = {
  accessKeyId: {
    pattern: /\b(AKIA[0-9A-Z]{16})\b/g,
    name: 'ID de Clave de Acceso AWS',
    severity: Severity.CRITICAL,
  },
  secretAccessKey: {
    pattern: /(?:aws_secret_access_key|aws_secret_key|secret_access_key)\s*[=:]\s*["']?([A-Za-z0-9/+=]{40})["']?/gi,
    name: 'Clave de Acceso Secreta AWS',
    severity: Severity.CRITICAL,
  },
  mwsAuthToken: {
    pattern: /amzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/gi,
    name: 'Token de Autenticación AWS MWS',
    severity: Severity.CRITICAL,
  },
};

/**
 * API key patterns for various services
 */
export const API_KEY_PATTERNS = {
  googleApi: {
    pattern: /AIza[0-9A-Za-z\-_]{35}/g,
    name: 'Clave de API de Google',
    severity: Severity.HIGH,
  },
  githubToken: {
    pattern: /ghp_[0-9a-zA-Z]{36}/g,
    name: 'Token de Acceso Personal de GitHub',
    severity: Severity.CRITICAL,
  },
  githubOAuth: {
    pattern: /gho_[0-9a-zA-Z]{36}/g,
    name: 'Token OAuth de GitHub',
    severity: Severity.CRITICAL,
  },
  gitlabToken: {
    pattern: /glpat-[0-9a-zA-Z\-_]{20,}/g,
    name: 'Token de Acceso Personal de GitLab',
    severity: Severity.CRITICAL,
  },
  slackToken: {
    pattern: /xox[baprs]-[0-9a-zA-Z]{10,48}/g,
    name: 'Token de Slack',
    severity: Severity.HIGH,
  },
  slackWebhook: {
    pattern: /https:\/\/hooks\.slack\.com\/services\/T[0-9A-Z]{8,}\/B[0-9A-Z]{8,}\/[a-zA-Z0-9]{24}/g,
    name: 'Slack Webhook URL',
    severity: Severity.MEDIUM,
  },
  stripeKey: {
    pattern: /(?:sk|pk)_(?:live|test)_[0-9a-zA-Z]{24,}/g,
    name: 'Clave de API de Stripe',
    severity: Severity.CRITICAL,
  },
  twilioKey: {
    pattern: /SK[0-9a-fA-F]{32}/g,
    name: 'Twilio API Key',
    severity: Severity.HIGH,
  },
  sendgridKey: {
    pattern: /SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}/g,
    name: 'SendGrid API Key',
    severity: Severity.HIGH,
  },
  mailgunKey: {
    pattern: /key-[0-9a-zA-Z]{32}/g,
    name: 'Mailgun API Key',
    severity: Severity.HIGH,
  },
  npmToken: {
    pattern: /npm_[A-Za-z0-9]{36}/g,
    name: 'NPM Access Token',
    severity: Severity.HIGH,
  },
  herokuKey: {
    pattern: /[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}/g,
    name: 'Heroku API Key',
    severity: Severity.MEDIUM,
    // Note: This is a UUID pattern, high false positive rate
    falsePositiveHigh: true,
  },
  firebaseKey: {
    pattern: /AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}/g,
    name: 'Token de Firebase Cloud Messaging',
    severity: Severity.HIGH,
  },
  discordToken: {
    pattern: /[MN][A-Za-z\d]{23,}\.[\w-]{6}\.[\w-]{27}/g,
    name: 'Token de Bot de Discord',
    severity: Severity.HIGH,
  },
  discordWebhook: {
    pattern: /https:\/\/discord(?:app)?\.com\/api\/webhooks\/[0-9]+\/[A-Za-z0-9_-]+/g,
    name: 'Discord Webhook URL',
    severity: Severity.MEDIUM,
  },
  telegramToken: {
    pattern: /[0-9]{8,10}:[a-zA-Z0-9_-]{35}/g,
    name: 'Token de Bot de Telegram',
    severity: Severity.HIGH,
  },
};

/**
 * Azure credential patterns
 */
export const AZURE_PATTERNS = {
  subscriptionKey: {
    pattern: /(?:azure|subscription)[-_]?key\s*[=:]\s*["']?([a-f0-9]{32})["']?/gi,
    name: 'Clave de Suscripción de Azure',
    severity: Severity.CRITICAL,
  },
  storageAccountKey: {
    pattern: /AccountKey\s*=\s*([A-Za-z0-9+\/=]{88})/g,
    name: 'Clave de Cuenta de Almacenamiento de Azure',
    severity: Severity.CRITICAL,
  },
  connectionString: {
    pattern: /DefaultEndpointsProtocol=https?;AccountName=[^;]+;AccountKey=[A-Za-z0-9+\/=]{88}/g,
    name: 'Cadena de Conexión de Almacenamiento de Azure',
    severity: Severity.CRITICAL,
  },
  sasToken: {
    pattern: /\?(?:sv|sig)=[^&\s]+&(?:se|sp|spr|ss|srt|sr)=[^&\s]+(?:&[^&\s]+)*/g,
    name: 'Token SAS de Azure',
    severity: Severity.HIGH,
  },
  servicePrincipal: {
    pattern: /(?:AZURE_CLIENT_SECRET|client[-_]?secret)\s*[=:]\s*["']?([A-Za-z0-9~._-]{34,})["']?/gi,
    name: 'Secreto de Entidad de Servicio de Azure',
    severity: Severity.CRITICAL,
  },
  tenantId: {
    pattern: /(?:AZURE_TENANT_ID|tenant[-_]?id)\s*[=:]\s*["']?([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})["']?/gi,
    name: 'ID de Inquilino de Azure',
    severity: Severity.LOW,
  },
  cognitiveKey: {
    pattern: /(?:cognitive|speech|vision|language)[-_]?(?:key|api[-_]?key)\s*[=:]\s*["']?([a-f0-9]{32})["']?/gi,
    name: 'Clave de Azure Cognitive Services',
    severity: Severity.HIGH,
  },
};

/**
 * Google Cloud Platform (GCP) credential patterns
 */
export const GCP_PATTERNS = {
  serviceAccountKey: {
    pattern: /"type"\s*:\s*"service_account"[\s\S]*?"private_key"\s*:\s*"-----BEGIN/g,
    name: 'Archivo de Clave de Cuenta de Servicio GCP',
    severity: Severity.CRITICAL,
  },
  privateKeyId: {
    pattern: /"private_key_id"\s*:\s*"([a-f0-9]{40})"/g,
    name: 'ID de Clave Privada GCP',
    severity: Severity.HIGH,
  },
  clientEmail: {
    pattern: /"client_email"\s*:\s*"([^"]+@[^"]+\.iam\.gserviceaccount\.com)"/g,
    name: 'Email de Cuenta de Servicio GCP',
    severity: Severity.MEDIUM,
  },
  oauthClientSecret: {
    pattern: /client_secret['"]\s*:\s*['"]([A-Za-z0-9_-]{24})['"]/g,
    name: 'Secreto de Cliente OAuth GCP',
    severity: Severity.CRITICAL,
  },
  firebaseWebApiKey: {
    pattern: /apiKey\s*:\s*["']AIza[0-9A-Za-z-_]{35}["']/g,
    name: 'Clave de API Web de Firebase',
    severity: Severity.HIGH,
  },
};

/**
 * CI/CD platform credential patterns
 */
export const CICD_PATTERNS = {
  circleCiToken: {
    pattern: /circle[-_]?(?:ci[-_])?token\s*[=:]\s*["']?([a-f0-9]{40})["']?/gi,
    name: 'CircleCI API Token',
    severity: Severity.HIGH,
  },
  travisToken: {
    pattern: /travis[-_]?(?:ci[-_])?token\s*[=:]\s*["']?([A-Za-z0-9]{22})["']?/gi,
    name: 'Travis CI Token',
    severity: Severity.HIGH,
  },
  jenkinsToken: {
    pattern: /jenkins[-_]?(?:api[-_])?token\s*[=:]\s*["']?([a-f0-9]{32,})["']?/gi,
    name: 'Jenkins API Token',
    severity: Severity.HIGH,
  },
  githubActionsSecret: {
    pattern: /\$\{\{\s*secrets\.([A-Z_][A-Z0-9_]*)\s*\}\}/g,
    name: 'GitHub Actions Secret Reference',
    severity: Severity.LOW,
    // Reference, not actual secret
  },
  gitlabCiVariable: {
    pattern: /\$(?:CI_JOB_TOKEN|CI_REGISTRY_PASSWORD)/g,
    name: 'GitLab CI Variable Reference',
    severity: Severity.LOW,
  },
  bitbucketPipelines: {
    pattern: /BITBUCKET_(?:APP_PASSWORD|CLONE_KEY)\s*[=:]/g,
    name: 'Bitbucket Pipelines Secret',
    severity: Severity.MEDIUM,
  },
};

/**
 * Observability/Monitoring platform credential patterns
 */
export const OBSERVABILITY_PATTERNS = {
  datadogApiKey: {
    pattern: /(?:datadog|dd)[-_]?api[-_]?key\s*[=:]\s*["']?([a-f0-9]{32})["']?/gi,
    name: 'Datadog API Key',
    severity: Severity.HIGH,
  },
  datadogAppKey: {
    pattern: /(?:datadog|dd)[-_]?app(?:lication)?[-_]?key\s*[=:]\s*["']?([a-f0-9]{40})["']?/gi,
    name: 'Datadog Application Key',
    severity: Severity.HIGH,
  },
  newRelicApiKey: {
    pattern: /(?:new[-_]?relic|nr)[-_]?(?:api[-_])?key\s*[=:]\s*["']?(NRAK-[A-Z0-9]{27})["']?/gi,
    name: 'New Relic API Key',
    severity: Severity.HIGH,
  },
  newRelicLicenseKey: {
    pattern: /(?:new[-_]?relic|nr)[-_]?license[-_]?key\s*[=:]\s*["']?([a-f0-9]{40})["']?/gi,
    name: 'New Relic License Key',
    severity: Severity.HIGH,
  },
  sentryDsn: {
    pattern: /https:\/\/[a-f0-9]{32}@(?:o[0-9]+\.)?(?:ingest\.)?sentry\.io\/[0-9]+/g,
    name: 'Sentry DSN',
    severity: Severity.MEDIUM,
  },
  sentryAuthToken: {
    pattern: /sentry[-_]?auth[-_]?token\s*[=:]\s*["']?([a-f0-9]{64})["']?/gi,
    name: 'Sentry Auth Token',
    severity: Severity.HIGH,
  },
  splunkToken: {
    pattern: /splunk[-_]?(?:hec[-_])?token\s*[=:]\s*["']?([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})["']?/gi,
    name: 'Splunk HEC Token',
    severity: Severity.HIGH,
  },
  grafanaApiKey: {
    pattern: /grafana[-_]?(?:api[-_])?key\s*[=:]\s*["']?(eyJ[A-Za-z0-9_-]+)["']?/gi,
    name: 'Grafana API Key',
    severity: Severity.HIGH,
  },
  prometheusPassword: {
    pattern: /prometheus[-_]?(?:basic[-_]?auth[-_])?password\s*[=:]\s*["']?([^"'\s]+)["']?/gi,
    name: 'Prometheus Basic Auth Password',
    severity: Severity.HIGH,
  },
};

/**
 * HashiCorp and secrets management patterns
 */
export const SECRETS_MANAGEMENT_PATTERNS = {
  vaultToken: {
    pattern: /(?:VAULT_TOKEN|vault[-_]?token)\s*[=:]\s*["']?(hvs\.[A-Za-z0-9_-]{24,})["']?/gi,
    name: 'HashiCorp Vault Token',
    severity: Severity.CRITICAL,
  },
  vaultWrappedToken: {
    pattern: /hvs\.[A-Za-z0-9_-]{90,}/g,
    name: 'HashiCorp Vault Wrapped Token',
    severity: Severity.CRITICAL,
  },
  vaultAppRole: {
    pattern: /(?:VAULT_ROLE_ID|role[-_]?id)\s*[=:]\s*["']?([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})["']?/gi,
    name: 'HashiCorp Vault AppRole ID',
    severity: Severity.MEDIUM,
  },
  vaultSecretId: {
    pattern: /(?:VAULT_SECRET_ID|secret[-_]?id)\s*[=:]\s*["']?([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})["']?/gi,
    name: 'HashiCorp Vault Secret ID',
    severity: Severity.CRITICAL,
  },
  awsSecretsManager: {
    pattern: /secretsmanager:GetSecretValue.*arn:aws:secretsmanager:[^:]+:[^:]+:secret:([^\s"']+)/g,
    name: 'AWS Secrets Manager ARN',
    severity: Severity.LOW,
  },
  azureKeyVault: {
    pattern: /https:\/\/[a-zA-Z0-9-]+\.vault\.azure\.net\/secrets\/[^\/\s]+/g,
    name: 'Azure Key Vault Secret URL',
    severity: Severity.LOW,
  },
  gcpSecretManager: {
    pattern: /projects\/[^\/]+\/secrets\/[^\/]+\/versions\/[^\s"']+/g,
    name: 'GCP Secret Manager Reference',
    severity: Severity.LOW,
  },
};

/**
 * Payment and financial service credential patterns
 */
export const PAYMENT_PATTERNS = {
  paypalClientSecret: {
    pattern: /paypal[-_]?(?:client[-_])?secret\s*[=:]\s*["']?([A-Za-z0-9_-]{80})["']?/gi,
    name: 'PayPal Client Secret',
    severity: Severity.CRITICAL,
  },
  squareAccessToken: {
    pattern: /sq0atp-[A-Za-z0-9_-]{22}/g,
    name: 'Square Access Token',
    severity: Severity.CRITICAL,
  },
  squareApplicationSecret: {
    pattern: /sq0csp-[A-Za-z0-9_-]{43}/g,
    name: 'Square Application Secret',
    severity: Severity.CRITICAL,
  },
  braintreeAccessToken: {
    pattern: /access_token\$(?:production|sandbox)\$[a-z0-9]+\$[a-f0-9]{32}/g,
    name: 'Braintree Access Token',
    severity: Severity.CRITICAL,
  },
  plaidClientId: {
    pattern: /plaid[-_]?client[-_]?id\s*[=:]\s*["']?([a-f0-9]{24})["']?/gi,
    name: 'Plaid Client ID',
    severity: Severity.MEDIUM,
  },
  plaidSecret: {
    pattern: /plaid[-_]?secret\s*[=:]\s*["']?([a-f0-9]{30})["']?/gi,
    name: 'Plaid Secret',
    severity: Severity.CRITICAL,
  },
};

/**
 * Private key patterns
 */
export const PRIVATE_KEY_PATTERNS = {
  rsaPrivateKey: {
    pattern: /-----BEGIN RSA PRIVATE KEY-----[\s\S]*?-----END RSA PRIVATE KEY-----/g,
    name: 'Clave Privada RSA',
    severity: Severity.CRITICAL,
  },
  dsaPrivateKey: {
    pattern: /-----BEGIN DSA PRIVATE KEY-----[\s\S]*?-----END DSA PRIVATE KEY-----/g,
    name: 'Clave Privada DSA',
    severity: Severity.CRITICAL,
  },
  ecPrivateKey: {
    pattern: /-----BEGIN EC PRIVATE KEY-----[\s\S]*?-----END EC PRIVATE KEY-----/g,
    name: 'Clave Privada EC',
    severity: Severity.CRITICAL,
  },
  opensshPrivateKey: {
    pattern: /-----BEGIN OPENSSH PRIVATE KEY-----[\s\S]*?-----END OPENSSH PRIVATE KEY-----/g,
    name: 'Clave Privada OpenSSH',
    severity: Severity.CRITICAL,
  },
  pgpPrivateKey: {
    pattern: /-----BEGIN PGP PRIVATE KEY BLOCK-----[\s\S]*?-----END PGP PRIVATE KEY BLOCK-----/g,
    name: 'Clave Privada PGP',
    severity: Severity.CRITICAL,
  },
};

/**
 * Database connection string patterns
 */
export const DATABASE_PATTERNS = {
  mongodbUri: {
    pattern: /mongodb(?:\+srv)?:\/\/[^:]+:[^@]+@[^\s'"]+/g,
    name: 'Cadena de Conexión de MongoDB con Credenciales',
    severity: Severity.CRITICAL,
  },
  postgresUri: {
    pattern: /postgres(?:ql)?:\/\/[^:]+:[^@]+@[^\s'"]+/g,
    name: 'Cadena de Conexión de PostgreSQL con Credenciales',
    severity: Severity.CRITICAL,
  },
  mysqlUri: {
    pattern: /mysql:\/\/[^:]+:[^@]+@[^\s'"]+/g,
    name: 'Cadena de Conexión de MySQL con Credenciales',
    severity: Severity.CRITICAL,
  },
  redisUri: {
    pattern: /redis:\/\/[^:]+:[^@]+@[^\s'"]+/g,
    name: 'Cadena de Conexión de Redis con Credenciales',
    severity: Severity.HIGH,
  },
  sqlServerConnString: {
    pattern: /(?:Server|Data Source)=[^;]+;.*(?:Password|Pwd)=[^;]+/gi,
    name: 'Cadena de Conexión de SQL Server con Contraseña',
    severity: Severity.CRITICAL,
  },
};

/**
 * JWT patterns
 */
export const JWT_PATTERNS = {
  jwtToken: {
    pattern: /eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*/g,
    name: 'JSON Web Token',
    severity: Severity.MEDIUM,
    // JWTs in code may be for testing
    falsePositiveHigh: true,
  },
};

/**
 * Get security standards for credential findings
 */
export function getCredentialStandards(): SecurityStandard[] {
  return [
    {
      name: 'CWE',
      id: 'CWE-798',
      title: 'Use of Hard-coded Credentials',
      description: 'The software contains hard-coded credentials.',
      url: 'https://cwe.mitre.org/data/definitions/798.html'
    },
    {
      name: 'CWE',
      id: 'CWE-259',
      title: 'Use of Hard-coded Password',
      description: 'The software contains a hard-coded password.',
      url: 'https://cwe.mitre.org/data/definitions/259.html'
    },
    {
      name: 'OWASP',
      id: 'A07:2021',
      title: 'Identification and Authentication Failures',
      description: 'Confirmation of the user\'s identity, authentication, and session management.',
      url: 'https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/'
    }
  ];
}

/**
 * Get all credential patterns as an array for scanning
 */
export function getAllCredentialPatterns(): Array<{
  pattern: RegExp;
  name: string;
  severity: Severity;
  category: string;
}> {
  const patterns: Array<{
    pattern: RegExp;
    name: string;
    severity: Severity;
    category: string;
  }> = [];

  // Add AWS patterns
  for (const [key, value] of Object.entries(AWS_PATTERNS)) {
    patterns.push({
      ...value,
      category: 'AWS',
    });
  }

  // Add API key patterns
  for (const [key, value] of Object.entries(API_KEY_PATTERNS)) {
    if (!('falsePositiveHigh' in value) || !value.falsePositiveHigh) {
      patterns.push({
        pattern: value.pattern,
        name: value.name,
        severity: value.severity,
        category: 'API Keys',
      });
    }
  }

  // Add private key patterns
  for (const [key, value] of Object.entries(PRIVATE_KEY_PATTERNS)) {
    patterns.push({
      ...value,
      category: 'Private Keys',
    });
  }

  // Add database patterns
  for (const [key, value] of Object.entries(DATABASE_PATTERNS)) {
    patterns.push({
      ...value,
      category: 'Database',
    });
  }

  // Add Azure patterns
  for (const [key, value] of Object.entries(AZURE_PATTERNS)) {
    patterns.push({
      ...value,
      category: 'Azure',
    });
  }

  // Add GCP patterns
  for (const [key, value] of Object.entries(GCP_PATTERNS)) {
    patterns.push({
      ...value,
      category: 'GCP',
    });
  }

  // Add CI/CD patterns
  for (const [key, value] of Object.entries(CICD_PATTERNS)) {
    patterns.push({
      ...value,
      category: 'CI/CD',
    });
  }

  // Add Observability patterns
  for (const [key, value] of Object.entries(OBSERVABILITY_PATTERNS)) {
    patterns.push({
      ...value,
      category: 'Observability',
    });
  }

  // Add Secrets Management patterns
  for (const [key, value] of Object.entries(SECRETS_MANAGEMENT_PATTERNS)) {
    patterns.push({
      ...value,
      category: 'Secrets Management',
    });
  }

  // Add Payment patterns
  for (const [key, value] of Object.entries(PAYMENT_PATTERNS)) {
    patterns.push({
      ...value,
      category: 'Payment',
    });
  }

  return patterns;
}
