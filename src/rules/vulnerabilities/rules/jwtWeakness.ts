/**
 * @fileoverview JWT Weakness Detection Rules
 * @module rules/vulnerabilities/rules/jwtWeakness
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

export const jwtWeaknessRules: VulnerabilityRule[] = [
    // =========================================================================
    // JWT ALG=NONE ATTACK
    // =========================================================================
    {
        id: 'VUL-JWT-001',
        name: 'JWT Algorithm None Attack',
        description: 'Detects JWT configurations allowing the "none" algorithm, which disables signature verification entirely.',
        version: '1.0.0',
        vulnerabilityType: VulnerabilityType.BROKEN_ACCESS_CONTROL,
        category: VulnerabilityCategory.CRYPTOGRAPHIC_FAILURE,
        languages: [SupportedLanguage.JAVASCRIPT, SupportedLanguage.TYPESCRIPT, SupportedLanguage.PYTHON],
        severity: VulnerabilitySeverity.CRITICAL,
        confidence: ConfidenceLevel.HIGH,
        baseScore: 95,
        patterns: [
            {
                type: PatternType.REGEX,
                patternId: 'jwt-alg-none',
                pattern: 'algorithms\\s*:\\s*\\[\\s*[\'"]none[\'"]',
                flags: 'gi',
                weight: 1.0,
                description: 'JWT algorithms includes "none"'
            },
            {
                type: PatternType.REGEX,
                patternId: 'jwt-algorithm-none',
                pattern: 'algorithm\\s*[=:]\\s*[\'"]none[\'"]',
                flags: 'gi',
                weight: 1.0,
                description: 'JWT algorithm set to "none"'
            },
            {
                type: PatternType.REGEX,
                patternId: 'jwt-verify-false',
                pattern: 'verify\\s*[=:]\\s*false|ignoreSignature\\s*[=:]\\s*true',
                flags: 'gi',
                weight: 0.90,
                description: 'JWT signature verification disabled'
            }
        ],
        impact: {
            confidentiality: 'high',
            integrity: 'high',
            availability: 'low',
            technicalImpact: 'Any user can forge valid JWT tokens, bypassing authentication and authorization entirely.',
            businessImpact: 'Complete authentication bypass, unauthorized access to all user accounts and data.'
        },
        exploitability: {
            attackVector: 'network',
            attackComplexity: 'low',
            privilegesRequired: 'none',
            userInteraction: 'none'
        },
        remediation: {
            summary: 'Never allow the "none" algorithm. Explicitly specify allowed algorithms.',
            steps: [
                'Remove "none" from allowed algorithms list',
                'Explicitly set algorithms: ["HS256"] or ["RS256"]',
                'Enable signature verification (default in most libraries)',
                'Consider using RS256 (asymmetric) for better security'
            ],
            secureCodeExample: `const jwt = require('jsonwebtoken');

// Always specify allowed algorithms explicitly
const decoded = jwt.verify(token, secret, {
  algorithms: ['HS256'],  // Never include 'none'
  issuer: 'your-app',
  audience: 'your-api'
});`,
            effort: 'low',
            priority: 'immediate'
        },
        standards: {
            owasp: [OWASP_TOP_10_2021.A02, OWASP_TOP_10_2021.A07],
            cwe: [CWE_REFERENCES.CWE_347]
        },
        tags: ['jwt', 'authentication', 'crypto', 'alg-none'],
        enabled: true
    },

    // =========================================================================
    // JWT HARDCODED SECRET
    // =========================================================================
    {
        id: 'VUL-JWT-002',
        name: 'JWT Hardcoded Secret',
        description: 'Detects JWT tokens signed with hardcoded secret strings instead of environment variables.',
        version: '1.0.0',
        vulnerabilityType: VulnerabilityType.HARDCODED_SECRETS,
        category: VulnerabilityCategory.CRYPTOGRAPHIC_FAILURE,
        languages: [SupportedLanguage.JAVASCRIPT, SupportedLanguage.TYPESCRIPT, SupportedLanguage.PYTHON],
        severity: VulnerabilitySeverity.HIGH,
        confidence: ConfidenceLevel.HIGH,
        baseScore: 80,
        patterns: [
            {
                type: PatternType.REGEX,
                patternId: 'jwt-sign-hardcoded',
                pattern: 'jwt\\.sign\\s*\\([^,]+,\\s*[\'"][^\'"]{4,}[\'"]',
                flags: 'gi',
                weight: 0.95,
                description: 'jwt.sign() with hardcoded string secret'
            },
            {
                type: PatternType.REGEX,
                patternId: 'jwt-verify-hardcoded',
                pattern: 'jwt\\.verify\\s*\\([^,]+,\\s*[\'"][^\'"]{4,}[\'"]',
                flags: 'gi',
                weight: 0.90,
                description: 'jwt.verify() with hardcoded string secret'
            },
            {
                type: PatternType.REGEX,
                patternId: 'jwt-secret-hardcoded',
                pattern: '(?:jwt[_-]?secret|JWT[_-]?SECRET)\\s*[=:]\\s*[\'"][^\'"]{4,}[\'"]',
                flags: 'g',
                weight: 0.85,
                description: 'JWT secret assigned as hardcoded string'
            }
        ],
        impact: {
            confidentiality: 'high',
            integrity: 'high',
            availability: 'low',
            technicalImpact: 'Hardcoded secret can be extracted from source code, allowing token forgery.',
            businessImpact: 'Authentication bypass if source is leaked or decompiled.'
        },
        exploitability: {
            attackVector: 'network',
            attackComplexity: 'medium',
            privilegesRequired: 'none',
            userInteraction: 'none'
        },
        remediation: {
            summary: 'Store JWT secrets in environment variables or a secrets manager. Never hardcode.',
            steps: [
                'Move secret to environment variable (process.env.JWT_SECRET)',
                'Use a secrets manager (AWS Secrets Manager, HashiCorp Vault)',
                'Use strong, random secrets (min 256-bit / 32 bytes)',
                'Rotate secrets periodically'
            ],
            secureCodeExample: `const jwt = require('jsonwebtoken');

// Good: secret from environment variable
const secret = process.env.JWT_SECRET;
if (!secret || secret.length < 32) {
  throw new Error('JWT_SECRET must be at least 32 characters');
}

const token = jwt.sign({ userId: user.id }, secret, {
  algorithm: 'HS256',
  expiresIn: '1h'
});`,
            effort: 'low',
            priority: 'high'
        },
        standards: {
            owasp: [OWASP_TOP_10_2021.A02],
            cwe: [CWE_REFERENCES.CWE_321, CWE_REFERENCES.CWE_798]
        },
        tags: ['jwt', 'hardcoded-secret', 'crypto', 'credentials'],
        enabled: true
    },

    // =========================================================================
    // JWT MISSING EXPIRATION
    // =========================================================================
    {
        id: 'VUL-JWT-003',
        name: 'JWT Missing Expiration',
        description: 'Detects jwt.sign() calls without expiresIn/exp claim, creating tokens that never expire.',
        version: '1.0.0',
        vulnerabilityType: VulnerabilityType.BROKEN_SESSION,
        category: VulnerabilityCategory.AUTHENTICATION,
        languages: [SupportedLanguage.JAVASCRIPT, SupportedLanguage.TYPESCRIPT],
        severity: VulnerabilitySeverity.MEDIUM,
        confidence: ConfidenceLevel.MEDIUM,
        baseScore: 50,
        patterns: [
            {
                type: PatternType.REGEX,
                patternId: 'jwt-sign-no-expiry',
                pattern: 'jwt\\.sign\\s*\\([^)]*\\)(?![\\s\\S]{0,100}(?:expiresIn|exp\\s*:))',
                flags: 'gi',
                weight: 0.70,
                description: 'jwt.sign() without expiresIn option'
            }
        ],
        falsePositivePatterns: [
            {
                type: PatternType.REGEX,
                patternId: 'jwt-has-expiry',
                pattern: 'jwt\\.sign\\s*\\([^)]*(?:expiresIn|exp\\s*:)',
                flags: 'gi',
                weight: 1.0,
                description: 'jwt.sign() with expiration'
            }
        ],
        impact: {
            confidentiality: 'medium',
            integrity: 'medium',
            availability: 'low',
            technicalImpact: 'Tokens without expiration remain valid indefinitely, even after password change or account compromise.',
            businessImpact: 'Persistent unauthorized access if tokens are leaked.'
        },
        exploitability: {
            attackVector: 'network',
            attackComplexity: 'medium',
            privilegesRequired: 'low',
            userInteraction: 'none'
        },
        remediation: {
            summary: 'Always set expiresIn when signing JWT tokens. Use short-lived access tokens with refresh tokens.',
            steps: [
                'Add expiresIn option to jwt.sign() (e.g. "15m" or "1h")',
                'Implement refresh token rotation for long sessions',
                'Consider adding "iat" (issued at) and "nbf" (not before) claims',
                'Implement token revocation for sensitive operations'
            ],
            secureCodeExample: `const jwt = require('jsonwebtoken');

// Always set expiration
const accessToken = jwt.sign(
  { userId: user.id, role: user.role },
  process.env.JWT_SECRET,
  {
    expiresIn: '15m',    // Short-lived access token
    issuer: 'your-app',
    audience: 'your-api'
  }
);

const refreshToken = jwt.sign(
  { userId: user.id, tokenVersion: user.tokenVersion },
  process.env.JWT_REFRESH_SECRET,
  { expiresIn: '7d' }   // Longer-lived refresh token
);`,
            effort: 'low',
            priority: 'medium'
        },
        standards: {
            owasp: [OWASP_TOP_10_2021.A07],
            cwe: [CWE_REFERENCES.CWE_613]
        },
        tags: ['jwt', 'session', 'expiration', 'authentication'],
        enabled: true
    }
];

export default jwtWeaknessRules;
