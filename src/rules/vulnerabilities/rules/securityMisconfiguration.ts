/**
 * @fileoverview Security Misconfiguration Detection Rules
 * @module rules/vulnerabilities/rules/securityMisconfiguration
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

export const securityMisconfigurationRules: VulnerabilityRule[] = [
  {
    id: 'VUL-MISCONFIG-001',
    name: 'Debug Mode Enabled in Production',
    description: 'Detects debug mode configurations that should not be in production.',
    version: '1.0.0',
    vulnerabilityType: VulnerabilityType.SECURITY_MISCONFIGURATION,
    category: VulnerabilityCategory.SECURITY_MISCONFIGURATION,
    languages: [
      SupportedLanguage.JAVASCRIPT, SupportedLanguage.TYPESCRIPT,
      SupportedLanguage.PYTHON, SupportedLanguage.PHP
    ],
    severity: VulnerabilitySeverity.MEDIUM,
    confidence: ConfidenceLevel.HIGH,
    baseScore: 55,
    patterns: [
      {
        type: PatternType.REGEX,
        patternId: 'misconfig-debug-true',
        pattern: '(?:debug|DEBUG)\\s*[=:]\\s*(?:true|True|1|[\'"]true[\'"])',
        flags: 'g',
        weight: 0.80,
        description: 'Debug mode enabled'
      },
      {
        type: PatternType.REGEX,
        patternId: 'misconfig-flask-debug',
        pattern: 'app\\.run\\s*\\([^)]*debug\\s*=\\s*True',
        flags: 'gi',
        weight: 0.95,
        description: 'Flask debug mode'
      },
      {
        type: PatternType.REGEX,
        patternId: 'misconfig-django-debug',
        pattern: 'DEBUG\\s*=\\s*True',
        flags: 'g',
        weight: 0.90,
        description: 'Django DEBUG setting'
      },
      {
        type: PatternType.REGEX,
        patternId: 'misconfig-php-display-errors',
        pattern: 'display_errors\\s*[=,]\\s*(?:1|On|true)',
        flags: 'gi',
        weight: 0.85,
        description: 'PHP display_errors enabled'
      }
    ],
    impact: {
      confidentiality: 'medium',
      integrity: 'low',
      availability: 'low',
      technicalImpact: 'Information disclosure, stack traces, internal paths, configuration details.',
      businessImpact: 'Information leakage aids targeted attacks.'
    },
    exploitability: {
      attackVector: 'network',
      attackComplexity: 'low',
      privilegesRequired: 'none',
      userInteraction: 'none'
    },
    remediation: {
      summary: 'Disable debug mode in production environments.',
      steps: [
        'Use environment variables for debug settings',
        'Set DEBUG=False in production',
        'Configure proper error handling and logging',
        'Use separate configuration files for environments'
      ],
      secureCodeExample: `# Flask - Use environment variable
app.run(debug=os.environ.get('FLASK_DEBUG', 'false').lower() == 'true')

# Django - Use environment variable
DEBUG = os.environ.get('DJANGO_DEBUG', 'False') == 'True'

// Node.js - Express
if (process.env.NODE_ENV !== 'development') {
  app.set('env', 'production');
}`,
      effort: 'low',
      priority: 'medium'
    },
    standards: {
      owasp: [OWASP_TOP_10_2021.A05],
      cwe: [CWE_REFERENCES.CWE_489]
    },
    tags: ['configuration', 'debug', 'information-disclosure'],
    enabled: true
  },
  {
    id: 'VUL-MISCONFIG-002',
    name: 'CORS Wildcard or Overly Permissive',
    description: 'Detects overly permissive CORS configurations.',
    version: '1.0.0',
    vulnerabilityType: VulnerabilityType.SECURITY_MISCONFIGURATION,
    category: VulnerabilityCategory.SECURITY_MISCONFIGURATION,
    languages: [SupportedLanguage.JAVASCRIPT, SupportedLanguage.TYPESCRIPT],
    severity: VulnerabilitySeverity.MEDIUM,
    confidence: ConfidenceLevel.HIGH,
    baseScore: 60,
    patterns: [
      {
        type: PatternType.REGEX,
        patternId: 'misconfig-cors-wildcard',
        pattern: 'Access-Control-Allow-Origin[\'"]?\\s*[,:]\\s*[\'"]\\*[\'"]',
        flags: 'gi',
        weight: 0.90,
        description: 'CORS Allow-Origin: *'
      },
      {
        type: PatternType.REGEX,
        patternId: 'misconfig-cors-origin-true',
        pattern: 'cors\\s*\\([^)]*origin\\s*:\\s*true',
        flags: 'gi',
        weight: 0.95,
        description: 'CORS origin: true (reflects any origin)'
      },
      {
        type: PatternType.REGEX,
        patternId: 'misconfig-cors-credentials-wildcard',
        pattern: 'credentials\\s*:\\s*true[^}]*origin\\s*:\\s*(?:true|[\'"]\\*[\'"])',
        flags: 'gi',
        weight: 1.0,
        description: 'CORS credentials with wildcard origin'
      }
    ],
    impact: {
      confidentiality: 'medium',
      integrity: 'medium',
      availability: 'low',
      technicalImpact: 'Cross-origin requests from any domain. Combined with credentials, allows data theft.',
      businessImpact: 'Data exfiltration, CSRF-like attacks.'
    },
    exploitability: {
      attackVector: 'network',
      attackComplexity: 'low',
      privilegesRequired: 'none',
      userInteraction: 'required'
    },
    remediation: {
      summary: 'Use explicit origin allowlist. Never use wildcard with credentials.',
      steps: [
        'Define explicit list of allowed origins',
        'Validate Origin header against allowlist',
        'Never combine credentials: true with origin: "*"',
        'Consider using origin callback function'
      ],
      secureCodeExample: `const corsOptions = {
  origin: function (origin, callback) {
    const allowedOrigins = ['https://app.example.com', 'https://admin.example.com'];
    if (!origin || allowedOrigins.includes(origin)) {
      callback(null, true);
    } else {
      callback(new Error('Not allowed by CORS'));
    }
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization']
};

app.use(cors(corsOptions));`,
      effort: 'low',
      priority: 'high'
    },
    standards: {
      owasp: [OWASP_TOP_10_2021.A05],
      cwe: [CWE_REFERENCES.CWE_942]
    },
    tags: ['configuration', 'cors', 'cross-origin'],
    enabled: true
  },
  {
    id: 'VUL-MISCONFIG-003',
    name: 'Missing Security Headers',
    description: 'Detects applications without important security headers.',
    version: '1.0.0',
    vulnerabilityType: VulnerabilityType.SECURITY_MISCONFIGURATION,
    category: VulnerabilityCategory.SECURITY_MISCONFIGURATION,
    languages: [SupportedLanguage.JAVASCRIPT, SupportedLanguage.TYPESCRIPT],
    severity: VulnerabilitySeverity.LOW,
    confidence: ConfidenceLevel.MEDIUM,
    baseScore: 40,
    patterns: [
      {
        type: PatternType.REGEX,
        patternId: 'misconfig-no-helmet',
        pattern: 'express\\s*\\(\\)(?![\\s\\S]*helmet)',
        flags: 'gi',
        weight: 0.70,
        description: 'Express without helmet'
      },
      {
        type: PatternType.REGEX,
        patternId: 'misconfig-helmet-disabled',
        pattern: 'helmet\\.(?:contentSecurityPolicy|xssFilter|noSniff)\\s*\\([^)]*enabled\\s*:\\s*false',
        flags: 'gi',
        weight: 0.85,
        description: 'Helmet protection disabled'
      }
    ],
    impact: {
      confidentiality: 'low',
      integrity: 'medium',
      availability: 'low',
      technicalImpact: 'Missing CSP allows XSS. Missing X-Frame-Options allows clickjacking.',
      businessImpact: 'Increased attack surface.'
    },
    exploitability: {
      attackVector: 'network',
      attackComplexity: 'medium',
      privilegesRequired: 'none',
      userInteraction: 'required'
    },
    remediation: {
      summary: 'Use helmet middleware and configure appropriate security headers.',
      steps: [
        'Install and use helmet middleware',
        'Configure Content-Security-Policy',
        'Enable X-Frame-Options',
        'Enable X-Content-Type-Options',
        'Configure Strict-Transport-Security for HTTPS'
      ],
      secureCodeExample: `const helmet = require('helmet');

app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'strict-dynamic'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      imgSrc: ["'self'", "data:", "https:"],
      connectSrc: ["'self'"],
      frameSrc: ["'none'"],
      objectSrc: ["'none'"]
    }
  },
  hsts: {
    maxAge: 31536000,
    includeSubDomains: true,
    preload: true
  }
}));`,
      effort: 'low',
      priority: 'medium'
    },
    standards: {
      owasp: [OWASP_TOP_10_2021.A05],
      cwe: [CWE_REFERENCES.CWE_693]
    },
    tags: ['configuration', 'headers', 'csp', 'helmet'],
    enabled: true
  },
  {
    id: 'VUL-MISCONFIG-004',
    name: 'Insecure TLS/SSL Configuration',
    description: 'Detects insecure SSL/TLS configurations.',
    version: '1.0.0',
    vulnerabilityType: VulnerabilityType.SECURITY_MISCONFIGURATION,
    category: VulnerabilityCategory.CRYPTOGRAPHIC_FAILURE,
    languages: [
      SupportedLanguage.JAVASCRIPT, SupportedLanguage.TYPESCRIPT,
      SupportedLanguage.PYTHON
    ],
    severity: VulnerabilitySeverity.HIGH,
    confidence: ConfidenceLevel.HIGH,
    baseScore: 75,
    patterns: [
      {
        type: PatternType.REGEX,
        patternId: 'misconfig-reject-unauthorized',
        pattern: 'rejectUnauthorized\\s*:\\s*false',
        flags: 'gi',
        weight: 1.0,
        description: 'TLS certificate validation disabled'
      },
      {
        type: PatternType.REGEX,
        patternId: 'misconfig-node-tls-reject',
        pattern: 'NODE_TLS_REJECT_UNAUTHORIZED\\s*[=:]\\s*[\'"]?0',
        flags: 'gi',
        weight: 1.0,
        description: 'Node TLS rejection disabled via env'
      },
      {
        type: PatternType.REGEX,
        patternId: 'misconfig-python-verify-false',
        pattern: 'verify\\s*=\\s*False',
        flags: 'gi',
        weight: 0.95,
        description: 'Python requests verify=False'
      },
      {
        type: PatternType.REGEX,
        patternId: 'misconfig-ssl-context-unverified',
        pattern: 'ssl\\._create_unverified_context',
        flags: 'gi',
        weight: 1.0,
        description: 'Python unverified SSL context'
      }
    ],
    impact: {
      confidentiality: 'high',
      integrity: 'high',
      availability: 'low',
      technicalImpact: 'Man-in-the-middle attacks. All TLS traffic can be intercepted.',
      businessImpact: 'Data interception, credential theft.'
    },
    exploitability: {
      attackVector: 'network',
      attackComplexity: 'medium',
      privilegesRequired: 'none',
      userInteraction: 'none'
    },
    remediation: {
      summary: 'Always verify TLS certificates in production. Use proper CA bundles.',
      steps: [
        'Remove rejectUnauthorized: false',
        'Remove verify=False from requests',
        'Use proper CA bundle for internal CAs',
        'Configure TLS 1.2+ only'
      ],
      secureCodeExample: `// Node.js - Proper TLS config
const https = require('https');
const options = {
  hostname: 'api.example.com',
  port: 443,
  // rejectUnauthorized defaults to true
  ca: fs.readFileSync('./internal-ca.pem') // For internal CAs
};

# Python - Proper TLS
import requests
response = requests.get('https://api.example.com', verify=True)
# For internal CA:
response = requests.get('https://internal.example.com', verify='/path/to/ca-bundle.crt')`,
      effort: 'low',
      priority: 'high'
    },
    standards: {
      owasp: [OWASP_TOP_10_2021.A02, OWASP_TOP_10_2021.A05],
      cwe: [CWE_REFERENCES.CWE_295]
    },
    tags: ['configuration', 'tls', 'ssl', 'certificate'],
    enabled: true
  },
  {
    id: 'VUL-MISCONFIG-005',
    name: 'Verbose Error Messages',
    description: 'Detects error handling that exposes stack traces or internal details.',
    version: '1.0.0',
    vulnerabilityType: VulnerabilityType.SECURITY_MISCONFIGURATION,
    category: VulnerabilityCategory.SECURITY_MISCONFIGURATION,
    languages: [SupportedLanguage.JAVASCRIPT, SupportedLanguage.TYPESCRIPT],
    severity: VulnerabilitySeverity.LOW,
    confidence: ConfidenceLevel.MEDIUM,
    baseScore: 35,
    patterns: [
      {
        type: PatternType.REGEX,
        patternId: 'misconfig-error-stack',
        pattern: 'res\\.(?:send|json)\\s*\\([^)]*(?:err\\.stack|error\\.stack|e\\.stack)',
        flags: 'gi',
        weight: 0.95,
        description: 'Stack trace sent in response'
      },
      {
        type: PatternType.REGEX,
        patternId: 'misconfig-error-message-direct',
        pattern: 'res\\.(?:send|json)\\s*\\([^)]*(?:err\\.message|error\\.message|e\\.message)',
        flags: 'gi',
        weight: 0.70,
        description: 'Raw error message in response'
      }
    ],
    impact: {
      confidentiality: 'low',
      integrity: 'none',
      availability: 'none',
      technicalImpact: 'Stack traces reveal file paths, library versions, internal logic.',
      businessImpact: 'Information aids targeted attacks.'
    },
    exploitability: {
      attackVector: 'network',
      attackComplexity: 'low',
      privilegesRequired: 'none',
      userInteraction: 'none'
    },
    remediation: {
      summary: 'Log detailed errors server-side. Return generic messages to clients.',
      steps: [
        'Log full error details server-side',
        'Return generic error messages to clients',
        'Include error reference ID for correlation',
        'Use error handling middleware'
      ],
      secureCodeExample: `// Express error handler
app.use((err, req, res, next) => {
  const errorId = crypto.randomUUID();
  
  // Log full details
  logger.error({
    id: errorId,
    error: err.message,
    stack: err.stack,
    path: req.path,
    method: req.method
  });
  
  // Return generic message
  res.status(err.status || 500).json({
    error: 'An error occurred',
    reference: errorId
  });
});`,
      effort: 'low',
      priority: 'low'
    },
    standards: {
      owasp: [OWASP_TOP_10_2021.A05],
      cwe: [CWE_REFERENCES.CWE_209]
    },
    tags: ['configuration', 'error-handling', 'information-disclosure'],
    enabled: true
  }
];

export default securityMisconfigurationRules;
