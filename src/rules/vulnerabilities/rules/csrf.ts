/**
 * @fileoverview CSRF (Cross-Site Request Forgery) Detection Rules
 * @module rules/vulnerabilities/rules/csrf
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

export const csrfRules: VulnerabilityRule[] = [
  {
    id: 'VUL-CSRF-001',
    name: 'Missing CSRF Protection - Express',
    description: 'Detects state-changing routes without CSRF protection in Express.',
    version: '1.0.0',
    vulnerabilityType: VulnerabilityType.CSRF,
    category: VulnerabilityCategory.BROKEN_ACCESS_CONTROL,
    languages: [SupportedLanguage.JAVASCRIPT, SupportedLanguage.TYPESCRIPT],
    severity: VulnerabilitySeverity.MEDIUM,
    confidence: ConfidenceLevel.MEDIUM,
    baseScore: 60,
    patterns: [
      {
        type: PatternType.REGEX,
        patternId: 'csrf-no-csurf',
        pattern: 'app\\.(?:post|put|patch|delete)\\s*\\([^)]+\\)(?![\\s\\S]*csrf)',
        flags: 'gi',
        weight: 0.70,
        description: 'State-changing route without CSRF mention'
      },
      {
        type: PatternType.REGEX,
        patternId: 'csrf-disabled',
        pattern: 'csrf\\s*[({][^}]*ignoreMethods\\s*:\\s*\\[[^\\]]*(?:POST|PUT|DELETE)',
        flags: 'gi',
        weight: 0.95,
        description: 'CSRF protection disabled for state-changing methods'
      }
    ],
    impact: {
      confidentiality: 'low',
      integrity: 'high',
      availability: 'low',
      technicalImpact: 'Attacker can perform actions on behalf of authenticated users.',
      businessImpact: 'Unauthorized transactions, account changes.'
    },
    exploitability: {
      attackVector: 'network',
      attackComplexity: 'low',
      privilegesRequired: 'none',
      userInteraction: 'required'
    },
    remediation: {
      summary: 'Implement CSRF tokens for all state-changing requests.',
      steps: [
        'Use csurf or csrf-csrf middleware',
        'Include CSRF token in forms and AJAX headers',
        'Validate token on all POST/PUT/PATCH/DELETE',
        'Use SameSite=Strict cookies as defense in depth'
      ],
      secureCodeExample: `const csrf = require('csurf');
const csrfProtection = csrf({ cookie: { sameSite: 'strict', httpOnly: true } });

// Apply to all routes
app.use(csrfProtection);

// Expose token to views
app.get('/form', (req, res) => {
  res.render('form', { csrfToken: req.csrfToken() });
});

// In form: <input type="hidden" name="_csrf" value="<%= csrfToken %>">

// For AJAX, set header:
// 'CSRF-Token': csrfToken`,
      effort: 'medium',
      priority: 'high'
    },
    standards: {
      owasp: [OWASP_TOP_10_2021.A01],
      cwe: [CWE_REFERENCES.CWE_352]
    },
    tags: ['csrf', 'session', 'express'],
    enabled: true
  },
  {
    id: 'VUL-CSRF-002',
    name: 'Missing CSRF Protection - Django',
    description: 'Detects views or forms without CSRF protection in Django.',
    version: '1.0.0',
    vulnerabilityType: VulnerabilityType.CSRF,
    category: VulnerabilityCategory.BROKEN_ACCESS_CONTROL,
    languages: [SupportedLanguage.PYTHON],
    severity: VulnerabilitySeverity.MEDIUM,
    confidence: ConfidenceLevel.HIGH,
    baseScore: 65,
    patterns: [
      {
        type: PatternType.REGEX,
        patternId: 'csrf-django-exempt',
        pattern: '@csrf_exempt',
        flags: 'g',
        weight: 0.95,
        description: 'CSRF protection exempted'
      },
      {
        type: PatternType.REGEX,
        patternId: 'csrf-django-disabled',
        pattern: 'CSRF_COOKIE_SECURE\\s*=\\s*False',
        flags: 'gi',
        weight: 0.80,
        description: 'CSRF cookie not secure'
      },
      {
        type: PatternType.REGEX,
        patternId: 'csrf-middleware-removed',
        pattern: '#.*CsrfViewMiddleware',
        flags: 'gi',
        weight: 1.0,
        description: 'CSRF middleware commented out'
      }
    ],
    impact: {
      confidentiality: 'low',
      integrity: 'high',
      availability: 'low',
      technicalImpact: 'Cross-site request forgery attacks possible.',
      businessImpact: 'Unauthorized actions on behalf of users.'
    },
    exploitability: {
      attackVector: 'network',
      attackComplexity: 'low',
      privilegesRequired: 'none',
      userInteraction: 'required'
    },
    remediation: {
      summary: 'Enable CSRF middleware. Avoid @csrf_exempt except for APIs with token auth.',
      steps: [
        'Ensure CsrfViewMiddleware is in MIDDLEWARE',
        'Remove unnecessary @csrf_exempt decorators',
        'Use {% csrf_token %} in all forms',
        'For APIs, use token-based auth instead of session'
      ],
      secureCodeExample: `# settings.py
MIDDLEWARE = [
    'django.middleware.csrf.CsrfViewMiddleware',
    # ...
]

CSRF_COOKIE_SECURE = True
CSRF_COOKIE_HTTPONLY = True
CSRF_COOKIE_SAMESITE = 'Strict'

# In templates
<form method="post">
    {% csrf_token %}
    ...
</form>

# For API views with proper token auth, csrf_exempt is acceptable
from rest_framework.decorators import api_view, authentication_classes
@api_view(['POST'])
@authentication_classes([TokenAuthentication])
def api_endpoint(request):
    pass`,
      effort: 'low',
      priority: 'high'
    },
    standards: {
      owasp: [OWASP_TOP_10_2021.A01],
      cwe: [CWE_REFERENCES.CWE_352]
    },
    tags: ['csrf', 'django', 'python'],
    enabled: true
  },
  {
    id: 'VUL-CSRF-003',
    name: 'Missing CSRF Protection - PHP',
    description: 'Detects PHP forms without CSRF token validation.',
    version: '1.0.0',
    vulnerabilityType: VulnerabilityType.CSRF,
    category: VulnerabilityCategory.BROKEN_ACCESS_CONTROL,
    languages: [SupportedLanguage.PHP],
    severity: VulnerabilitySeverity.MEDIUM,
    confidence: ConfidenceLevel.LOW,
    baseScore: 55,
    patterns: [
      {
        type: PatternType.REGEX,
        patternId: 'csrf-php-post-no-token',
        pattern: '\\$_POST\\s*\\[[\'"][^\'"]+[\'"]\\](?![\\s\\S]{0,200}(?:csrf|token|_token))',
        flags: 'gi',
        weight: 0.60,
        description: 'POST processing without token check nearby'
      },
      {
        type: PatternType.REGEX,
        patternId: 'csrf-php-form-no-token',
        pattern: '<form[^>]*method\\s*=\\s*[\'"]post[\'"][^>]*>(?![\\s\\S]{0,500}(?:csrf|token|_token))',
        flags: 'gi',
        weight: 0.50,
        description: 'Form without CSRF token'
      }
    ],
    impact: {
      confidentiality: 'low',
      integrity: 'high',
      availability: 'low',
      technicalImpact: 'State-changing actions can be triggered by malicious sites.',
      businessImpact: 'Unauthorized transactions.'
    },
    exploitability: {
      attackVector: 'network',
      attackComplexity: 'low',
      privilegesRequired: 'none',
      userInteraction: 'required'
    },
    remediation: {
      summary: 'Generate and validate CSRF tokens for all forms.',
      steps: [
        'Generate token in session and embed in forms',
        'Validate token on every POST request',
        'Regenerate token after use (one-time tokens)',
        'Use framework CSRF protection if available'
      ],
      secureCodeExample: `<?php
// Generate token
session_start();
if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

// In form
?>
<form method="post">
    <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($_SESSION['csrf_token']) ?>">
    ...
</form>

<?php
// Validate on submit
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!hash_equals($_SESSION['csrf_token'], $_POST['csrf_token'] ?? '')) {
        die('CSRF validation failed');
    }
    // Process form...
}
?>`,
      effort: 'medium',
      priority: 'high'
    },
    standards: {
      owasp: [OWASP_TOP_10_2021.A01],
      cwe: [CWE_REFERENCES.CWE_352]
    },
    tags: ['csrf', 'php', 'forms'],
    enabled: true
  }
];

export default csrfRules;
