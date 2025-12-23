/**
 * @fileoverview Authentication and Session Vulnerabilities Detection Rules
 * @module rules/vulnerabilities/rules/authentication
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

export const authenticationRules: VulnerabilityRule[] = [
  {
    id: 'VUL-AUTH-001',
    name: 'Weak Password Hashing - MD5/SHA1',
    description: 'Detects use of weak hashing algorithms for passwords.',
    version: '1.0.0',
    vulnerabilityType: VulnerabilityType.BROKEN_AUTHENTICATION,
    category: VulnerabilityCategory.CRYPTOGRAPHIC_FAILURE,
    languages: [
      SupportedLanguage.JAVASCRIPT, SupportedLanguage.TYPESCRIPT,
      SupportedLanguage.PYTHON, SupportedLanguage.PHP,
      SupportedLanguage.JAVA, SupportedLanguage.CSHARP
    ],
    severity: VulnerabilitySeverity.HIGH,
    confidence: ConfidenceLevel.HIGH,
    baseScore: 80,
    patterns: [
      {
        type: PatternType.REGEX,
        patternId: 'auth-md5-password',
        pattern: '(?:md5|sha1)\\s*\\([^)]*(?:password|passwd|pwd)',
        flags: 'gi',
        weight: 1.0,
        description: 'MD5/SHA1 on password'
      },
      {
        type: PatternType.REGEX,
        patternId: 'auth-crypto-md5',
        pattern: 'createHash\\s*\\([\'"](?:md5|sha1)[\'"]\\)',
        flags: 'gi',
        weight: 0.90,
        description: 'crypto.createHash with weak algorithm'
      },
      {
        type: PatternType.REGEX,
        patternId: 'auth-hashlib-weak',
        pattern: 'hashlib\\.(?:md5|sha1)\\s*\\([^)]*(?:password|encode)',
        flags: 'gi',
        weight: 1.0,
        description: 'Python hashlib with weak hash'
      },
      {
        type: PatternType.REGEX,
        patternId: 'auth-messagedigest-weak',
        pattern: 'MessageDigest\\.getInstance\\s*\\([\'"](?:MD5|SHA-?1)[\'"]\\)',
        flags: 'gi',
        weight: 0.95,
        description: 'Java MessageDigest with weak algorithm'
      }
    ],
    impact: {
      confidentiality: 'high',
      integrity: 'medium',
      availability: 'low',
      technicalImpact: 'Password hashes can be cracked quickly using rainbow tables or GPU attacks.',
      businessImpact: 'Mass credential compromise, account takeover.'
    },
    exploitability: {
      attackVector: 'network',
      attackComplexity: 'low',
      privilegesRequired: 'none',
      userInteraction: 'none',
      knownExploits: true
    },
    remediation: {
      summary: 'Use bcrypt, scrypt, or Argon2 for password hashing.',
      steps: [
        'Replace MD5/SHA1 with bcrypt, scrypt, or Argon2id',
        'Use appropriate work factor (cost)',
        'Migrate existing password hashes on next login',
        'Salt is automatically handled by modern algorithms'
      ],
      secureCodeExample: `// Node.js - Use bcrypt
const bcrypt = require('bcrypt');
const hash = await bcrypt.hash(password, 12);
const isValid = await bcrypt.compare(password, hash);

# Python - Use bcrypt or argon2
import bcrypt
hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt(12))

// Java - Use BCrypt
String hash = BCrypt.hashpw(password, BCrypt.gensalt(12));`,
      effort: 'medium',
      priority: 'high'
    },
    standards: {
      owasp: [OWASP_TOP_10_2021.A02, OWASP_TOP_10_2021.A07],
      cwe: [CWE_REFERENCES.CWE_328, CWE_REFERENCES.CWE_916]
    },
    tags: ['authentication', 'password', 'hashing', 'cryptography'],
    enabled: true
  },
  {
    id: 'VUL-AUTH-002',
    name: 'Insecure Session Configuration',
    description: 'Detects insecure session cookie settings.',
    version: '1.0.0',
    vulnerabilityType: VulnerabilityType.BROKEN_AUTHENTICATION,
    category: VulnerabilityCategory.BROKEN_ACCESS_CONTROL,
    languages: [SupportedLanguage.JAVASCRIPT, SupportedLanguage.TYPESCRIPT],
    severity: VulnerabilitySeverity.MEDIUM,
    confidence: ConfidenceLevel.HIGH,
    baseScore: 60,
    patterns: [
      {
        type: PatternType.REGEX,
        patternId: 'auth-cookie-no-httponly',
        pattern: 'cookie\\s*[({][^}]*httpOnly\\s*:\\s*false',
        flags: 'gi',
        weight: 0.95,
        description: 'Cookie without httpOnly'
      },
      {
        type: PatternType.REGEX,
        patternId: 'auth-cookie-no-secure',
        pattern: 'cookie\\s*[({][^}]*secure\\s*:\\s*false',
        flags: 'gi',
        weight: 0.90,
        description: 'Cookie without secure flag'
      },
      {
        type: PatternType.REGEX,
        patternId: 'auth-session-no-samsite',
        pattern: 'session\\s*\\([^)]*(?!sameSite)',
        flags: 'gi',
        weight: 0.70,
        description: 'Session without sameSite'
      }
    ],
    impact: {
      confidentiality: 'high',
      integrity: 'medium',
      availability: 'low',
      technicalImpact: 'Session hijacking via XSS (no httpOnly) or MITM (no secure).',
      businessImpact: 'Account takeover, session theft.'
    },
    exploitability: {
      attackVector: 'network',
      attackComplexity: 'low',
      privilegesRequired: 'none',
      userInteraction: 'required'
    },
    remediation: {
      summary: 'Enable httpOnly, secure, and sameSite flags on session cookies.',
      steps: [
        'Set httpOnly: true to prevent JavaScript access',
        'Set secure: true to require HTTPS',
        'Set sameSite: "strict" or "lax" for CSRF protection',
        'Use short session expiration'
      ],
      secureCodeExample: `// Express session configuration
app.use(session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    secure: true,
    sameSite: 'strict',
    maxAge: 3600000 // 1 hour
  }
}));`,
      effort: 'low',
      priority: 'high'
    },
    standards: {
      owasp: [OWASP_TOP_10_2021.A07],
      cwe: [CWE_REFERENCES.CWE_614, CWE_REFERENCES.CWE_1004]
    },
    tags: ['authentication', 'session', 'cookie', 'csrf'],
    enabled: true
  },
  {
    id: 'VUL-AUTH-003',
    name: 'JWT None Algorithm',
    description: 'Detects JWT configuration that may allow "none" algorithm.',
    version: '1.0.0',
    vulnerabilityType: VulnerabilityType.BROKEN_AUTHENTICATION,
    category: VulnerabilityCategory.CRYPTOGRAPHIC_FAILURE,
    languages: [SupportedLanguage.JAVASCRIPT, SupportedLanguage.TYPESCRIPT],
    severity: VulnerabilitySeverity.CRITICAL,
    confidence: ConfidenceLevel.MEDIUM,
    baseScore: 90,
    patterns: [
      {
        type: PatternType.REGEX,
        patternId: 'auth-jwt-no-algorithm',
        pattern: 'jwt\\.verify\\s*\\([^)]*,\\s*null',
        flags: 'gi',
        weight: 1.0,
        description: 'JWT verify with null secret'
      },
      {
        type: PatternType.REGEX,
        patternId: 'auth-jwt-algorithms-none',
        pattern: 'algorithms\\s*:\\s*\\[[^\\]]*[\'"]none[\'"]',
        flags: 'gi',
        weight: 1.0,
        description: 'JWT algorithms includes none'
      },
      {
        type: PatternType.REGEX,
        patternId: 'auth-jwt-no-verify',
        pattern: 'jwt\\.decode\\s*\\([^)]*(?!verify)',
        flags: 'gi',
        weight: 0.80,
        description: 'JWT decode without verify'
      }
    ],
    impact: {
      confidentiality: 'high',
      integrity: 'high',
      availability: 'low',
      technicalImpact: 'Complete authentication bypass. Attacker can forge any JWT.',
      businessImpact: 'Full account takeover, privilege escalation.'
    },
    exploitability: {
      attackVector: 'network',
      attackComplexity: 'low',
      privilegesRequired: 'none',
      userInteraction: 'none',
      knownExploits: true
    },
    remediation: {
      summary: 'Always specify allowed algorithms explicitly. Never allow "none".',
      steps: [
        'Specify algorithms explicitly in verify options',
        'Never include "none" in allowed algorithms',
        'Use asymmetric algorithms (RS256) for distributed systems',
        'Validate issuer and audience claims'
      ],
      secureCodeExample: `const jwt = require('jsonwebtoken');

// Secure: Explicit algorithm
const decoded = jwt.verify(token, secret, {
  algorithms: ['HS256'],
  issuer: 'my-app',
  audience: 'my-users'
});

// For asymmetric keys
const decoded = jwt.verify(token, publicKey, {
  algorithms: ['RS256']
});`,
      effort: 'low',
      priority: 'immediate'
    },
    standards: {
      owasp: [OWASP_TOP_10_2021.A02, OWASP_TOP_10_2021.A07],
      cwe: [CWE_REFERENCES.CWE_327, CWE_REFERENCES.CWE_347]
    },
    tags: ['authentication', 'jwt', 'critical'],
    enabled: true
  },
  {
    id: 'VUL-AUTH-004',
    name: 'Missing Authentication Check',
    description: 'Detects routes or handlers that may lack authentication checks.',
    version: '1.0.0',
    vulnerabilityType: VulnerabilityType.BROKEN_ACCESS_CONTROL,
    category: VulnerabilityCategory.BROKEN_ACCESS_CONTROL,
    languages: [SupportedLanguage.JAVASCRIPT, SupportedLanguage.TYPESCRIPT],
    severity: VulnerabilitySeverity.HIGH,
    confidence: ConfidenceLevel.LOW,
    baseScore: 70,
    patterns: [
      {
        type: PatternType.REGEX,
        patternId: 'auth-route-no-middleware',
        pattern: 'app\\.(?:get|post|put|delete|patch)\\s*\\([\'"][^\'"]+[\'"]\\s*,\\s*(?:async\\s+)?\\(?(?:req|request)',
        flags: 'gi',
        weight: 0.60,
        description: 'Route without middleware'
      },
      {
        type: PatternType.REGEX,
        patternId: 'auth-admin-route',
        pattern: 'app\\.(?:get|post|put|delete)\\s*\\([\'"](?:/admin|/api/admin)',
        flags: 'gi',
        weight: 0.70,
        description: 'Admin route (verify auth)'
      }
    ],
    impact: {
      confidentiality: 'high',
      integrity: 'high',
      availability: 'medium',
      technicalImpact: 'Unauthorized access to sensitive functionality.',
      businessImpact: 'Data breach, privilege escalation.'
    },
    exploitability: {
      attackVector: 'network',
      attackComplexity: 'low',
      privilegesRequired: 'none',
      userInteraction: 'none'
    },
    remediation: {
      summary: 'Apply authentication middleware to all protected routes.',
      steps: [
        'Use authentication middleware on protected routes',
        'Apply authorization checks for role-based access',
        'Use global middleware with exclusion list',
        'Audit all routes for proper authentication'
      ],
      secureCodeExample: `const authMiddleware = require('./middleware/auth');
const adminMiddleware = require('./middleware/admin');

// Apply to individual routes
app.get('/api/users', authMiddleware, getUsers);

// Apply to all routes in a router
const adminRouter = express.Router();
adminRouter.use(authMiddleware, adminMiddleware);
adminRouter.get('/settings', getSettings);

// Global middleware with exclusions
app.use((req, res, next) => {
  const publicPaths = ['/login', '/register', '/public'];
  if (publicPaths.includes(req.path)) return next();
  return authMiddleware(req, res, next);
});`,
      effort: 'medium',
      priority: 'high'
    },
    standards: {
      owasp: [OWASP_TOP_10_2021.A01, OWASP_TOP_10_2021.A07],
      cwe: [CWE_REFERENCES.CWE_306, CWE_REFERENCES.CWE_862]
    },
    tags: ['authentication', 'authorization', 'access-control'],
    enabled: true
  },
  {
    id: 'VUL-AUTH-005',
    name: 'Timing Attack Vulnerable Comparison',
    description: 'Detects string comparisons for secrets that are vulnerable to timing attacks.',
    version: '1.0.0',
    vulnerabilityType: VulnerabilityType.BROKEN_AUTHENTICATION,
    category: VulnerabilityCategory.CRYPTOGRAPHIC_FAILURE,
    languages: [
      SupportedLanguage.JAVASCRIPT, SupportedLanguage.TYPESCRIPT,
      SupportedLanguage.PYTHON
    ],
    severity: VulnerabilitySeverity.MEDIUM,
    confidence: ConfidenceLevel.MEDIUM,
    baseScore: 55,
    patterns: [
      {
        type: PatternType.REGEX,
        patternId: 'auth-timing-token',
        pattern: '(?:token|secret|key|signature)\\s*(?:===?|!==?)\\s*(?:req\\.|user\\.|expected)',
        flags: 'gi',
        weight: 0.85,
        description: 'Direct secret comparison'
      },
      {
        type: PatternType.REGEX,
        patternId: 'auth-timing-password',
        pattern: '(?:password|hash)\\s*===?\\s*(?:stored|expected|user)',
        flags: 'gi',
        weight: 0.80,
        description: 'Direct password/hash comparison'
      }
    ],
    impact: {
      confidentiality: 'medium',
      integrity: 'medium',
      availability: 'low',
      technicalImpact: 'Secrets can be revealed byte-by-byte through timing analysis.',
      businessImpact: 'API key extraction, token forgery.'
    },
    exploitability: {
      attackVector: 'network',
      attackComplexity: 'high',
      privilegesRequired: 'none',
      userInteraction: 'none'
    },
    remediation: {
      summary: 'Use constant-time comparison functions for secret comparison.',
      steps: [
        'Use crypto.timingSafeEqual() in Node.js',
        'Use hmac.compare_digest() in Python',
        'Use MessageDigest.isEqual() in Java',
        'Ensure both values have same length before comparison'
      ],
      secureCodeExample: `// Node.js - Constant-time comparison
const crypto = require('crypto');

function safeCompare(a, b) {
  if (a.length !== b.length) return false;
  return crypto.timingSafeEqual(Buffer.from(a), Buffer.from(b));
}

# Python - Constant-time comparison
import hmac
def safe_compare(a, b):
    return hmac.compare_digest(a, b)`,
      effort: 'low',
      priority: 'medium'
    },
    standards: {
      owasp: [OWASP_TOP_10_2021.A02],
      cwe: [CWE_REFERENCES.CWE_208]
    },
    tags: ['authentication', 'timing-attack', 'cryptography'],
    enabled: true
  }
];

export default authenticationRules;
