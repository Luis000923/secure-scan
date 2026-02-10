/**
 * @fileoverview Session and Cookie Security Detection Rules
 * @module rules/vulnerabilities/rules/sessionSecurity
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

export const sessionSecurityRules: VulnerabilityRule[] = [
    // =========================================================================
    // MISSING HttpOnly FLAG
    // =========================================================================
    {
        id: 'VUL-SESSION-001',
        name: 'Cookie Missing HttpOnly Flag',
        description: 'Detects cookies set without the HttpOnly flag, making them accessible to JavaScript and vulnerable to XSS-based theft.',
        version: '1.0.0',
        vulnerabilityType: VulnerabilityType.SECURITY_MISCONFIGURATION,
        category: VulnerabilityCategory.SESSION_MANAGEMENT,
        languages: [
            SupportedLanguage.JAVASCRIPT, SupportedLanguage.TYPESCRIPT,
            SupportedLanguage.PHP, SupportedLanguage.PYTHON
        ],
        severity: VulnerabilitySeverity.MEDIUM,
        confidence: ConfidenceLevel.HIGH,
        baseScore: 55,
        patterns: [
            {
                type: PatternType.REGEX,
                patternId: 'cookie-httponly-false',
                pattern: 'httpOnly\\s*:\\s*false',
                flags: 'gi',
                weight: 0.95,
                description: 'httpOnly explicitly set to false'
            },
            {
                type: PatternType.REGEX,
                patternId: 'cookie-express-no-httponly',
                pattern: 'res\\.cookie\\s*\\([^)]+\\{[^}]*(?!httpOnly)[^}]*\\}',
                flags: 'gi',
                weight: 0.60,
                description: 'Express res.cookie() without httpOnly'
            },
            {
                type: PatternType.REGEX,
                patternId: 'cookie-php-no-httponly',
                pattern: 'setcookie\\s*\\([^)]+false\\s*\\)\\s*;',
                flags: 'gi',
                weight: 0.50,
                description: 'PHP setcookie() possibly without httponly'
            }
        ],
        impact: {
            confidentiality: 'medium',
            integrity: 'low',
            availability: 'none',
            technicalImpact: 'Session cookies accessible via document.cookie, enabling session hijacking through XSS.',
            businessImpact: 'Account takeover through stolen session cookies.'
        },
        exploitability: {
            attackVector: 'network',
            attackComplexity: 'medium',
            privilegesRequired: 'none',
            userInteraction: 'required'
        },
        remediation: {
            summary: 'Set httpOnly: true on all session and sensitive cookies.',
            steps: [
                'Set httpOnly: true in cookie options',
                'Audit all res.cookie() and setcookie() calls',
                'Use session middleware with httpOnly enabled by default',
                'Consider using cookie prefixes (__Host-, __Secure-)'
            ],
            secureCodeExample: `// Express
res.cookie('session', token, {
  httpOnly: true,   // Not accessible via JavaScript
  secure: true,     // Only sent over HTTPS
  sameSite: 'strict',
  maxAge: 3600000   // 1 hour
});

// PHP
setcookie('session', $token, [
  'httponly' => true,
  'secure' => true,
  'samesite' => 'Strict',
  'expires' => time() + 3600
]);`,
            effort: 'low',
            priority: 'high'
        },
        standards: {
            owasp: [OWASP_TOP_10_2021.A05],
            cwe: [CWE_REFERENCES.CWE_1004]
        },
        tags: ['cookie', 'httponly', 'session', 'xss'],
        enabled: true
    },

    // =========================================================================
    // MISSING Secure FLAG
    // =========================================================================
    {
        id: 'VUL-SESSION-002',
        name: 'Cookie Missing Secure Flag',
        description: 'Detects cookies set without the Secure flag, allowing them to be sent over unencrypted HTTP connections.',
        version: '1.0.0',
        vulnerabilityType: VulnerabilityType.SECURITY_MISCONFIGURATION,
        category: VulnerabilityCategory.SESSION_MANAGEMENT,
        languages: [
            SupportedLanguage.JAVASCRIPT, SupportedLanguage.TYPESCRIPT,
            SupportedLanguage.PHP, SupportedLanguage.PYTHON
        ],
        severity: VulnerabilitySeverity.MEDIUM,
        confidence: ConfidenceLevel.HIGH,
        baseScore: 55,
        patterns: [
            {
                type: PatternType.REGEX,
                patternId: 'cookie-secure-false',
                pattern: 'secure\\s*:\\s*false',
                flags: 'gi',
                weight: 0.95,
                description: 'secure explicitly set to false'
            },
            {
                type: PatternType.REGEX,
                patternId: 'session-cookie-insecure',
                pattern: 'session\\s*\\(\\s*\\{[^}]*cookie\\s*:\\s*\\{[^}]*secure\\s*:\\s*false',
                flags: 'gi',
                weight: 0.95,
                description: 'Session cookie secure flag disabled'
            }
        ],
        impact: {
            confidentiality: 'high',
            integrity: 'low',
            availability: 'none',
            technicalImpact: 'Cookies transmitted in cleartext over HTTP, enabling interception via MITM attacks.',
            businessImpact: 'Session hijacking on public/shared networks.'
        },
        exploitability: {
            attackVector: 'adjacent',
            attackComplexity: 'medium',
            privilegesRequired: 'none',
            userInteraction: 'none'
        },
        remediation: {
            summary: 'Set secure: true on all session and sensitive cookies to restrict them to HTTPS.',
            steps: [
                'Set secure: true in cookie options',
                'Ensure the application is served over HTTPS',
                'Use HSTS to prevent HTTP downgrade',
                'Consider using __Secure- or __Host- cookie prefixes'
            ],
            secureCodeExample: `// Express session middleware
app.use(session({
  secret: process.env.SESSION_SECRET,
  cookie: {
    secure: true,      // Only sent over HTTPS
    httpOnly: true,
    sameSite: 'strict',
    maxAge: 3600000
  }
}));`,
            effort: 'low',
            priority: 'high'
        },
        standards: {
            owasp: [OWASP_TOP_10_2021.A05],
            cwe: [CWE_REFERENCES.CWE_614]
        },
        tags: ['cookie', 'secure', 'session', 'https'],
        enabled: true
    },

    // =========================================================================
    // SameSite=None WITHOUT Secure
    // =========================================================================
    {
        id: 'VUL-SESSION-003',
        name: 'Cookie SameSite=None Without Secure',
        description: 'Detects cookies with SameSite=None but without the Secure flag, which is rejected by modern browsers and indicates CSRF weakness.',
        version: '1.0.0',
        vulnerabilityType: VulnerabilityType.CSRF,
        category: VulnerabilityCategory.SESSION_MANAGEMENT,
        languages: [
            SupportedLanguage.JAVASCRIPT, SupportedLanguage.TYPESCRIPT,
            SupportedLanguage.PHP
        ],
        severity: VulnerabilitySeverity.MEDIUM,
        confidence: ConfidenceLevel.HIGH,
        baseScore: 55,
        patterns: [
            {
                type: PatternType.REGEX,
                patternId: 'samesite-none-no-secure',
                pattern: 'sameSite\\s*:\\s*[\'"](?:none|None)[\'"][^}]*secure\\s*:\\s*false',
                flags: 'gi',
                weight: 0.95,
                description: 'SameSite=None with secure=false'
            },
            {
                type: PatternType.REGEX,
                patternId: 'samesite-none-standalone',
                pattern: 'sameSite\\s*:\\s*[\'"](?:none|None)[\'"](?![\\s\\S]{0,100}secure\\s*:\\s*true)',
                flags: 'gi',
                weight: 0.75,
                description: 'SameSite=None without explicit secure=true nearby'
            }
        ],
        impact: {
            confidentiality: 'low',
            integrity: 'medium',
            availability: 'none',
            technicalImpact: 'SameSite=None allows cross-site cookie sending. Without Secure flag, modern browsers reject the cookie entirely.',
            businessImpact: 'CSRF vulnerability or broken functionality in modern browsers.'
        },
        exploitability: {
            attackVector: 'network',
            attackComplexity: 'low',
            privilegesRequired: 'none',
            userInteraction: 'required'
        },
        remediation: {
            summary: 'When using SameSite=None, always set Secure=true. Prefer SameSite=Strict or Lax when possible.',
            steps: [
                'If cross-site cookies are needed, set both SameSite=None AND Secure=true',
                'Prefer SameSite=Strict for session cookies',
                'Use SameSite=Lax as a good default for most cookies',
                'Only use SameSite=None for legitimate cross-site use cases (e.g. OAuth, embeds)'
            ],
            secureCodeExample: `// If cross-site cookie IS needed:
res.cookie('session', token, {
  sameSite: 'none',
  secure: true,      // REQUIRED with SameSite=None
  httpOnly: true
});

// If cross-site is NOT needed (recommended):
res.cookie('session', token, {
  sameSite: 'strict', // Best CSRF protection
  secure: true,
  httpOnly: true
});`,
            effort: 'low',
            priority: 'medium'
        },
        standards: {
            owasp: [OWASP_TOP_10_2021.A01, OWASP_TOP_10_2021.A05],
            cwe: [CWE_REFERENCES.CWE_352, CWE_REFERENCES.CWE_614]
        },
        tags: ['cookie', 'samesite', 'csrf', 'session'],
        enabled: true
    }
];

export default sessionSecurityRules;
