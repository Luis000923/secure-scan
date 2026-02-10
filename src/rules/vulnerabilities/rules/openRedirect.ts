/**
 * @fileoverview Open Redirect Detection Rules
 * @module rules/vulnerabilities/rules/openRedirect
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

export const openRedirectRules: VulnerabilityRule[] = [
    // =========================================================================
    // OPEN REDIRECT - JavaScript / TypeScript (Express)
    // =========================================================================
    {
        id: 'VUL-REDIRECT-001',
        name: 'Open Redirect - Express/Node.js',
        description: 'Detects redirect calls using unvalidated user input in Express (res.redirect with req.query/body/params).',
        version: '1.0.0',
        vulnerabilityType: VulnerabilityType.BROKEN_ACCESS_CONTROL,
        category: VulnerabilityCategory.BROKEN_ACCESS_CONTROL,
        languages: [SupportedLanguage.JAVASCRIPT, SupportedLanguage.TYPESCRIPT],
        severity: VulnerabilitySeverity.MEDIUM,
        confidence: ConfidenceLevel.HIGH,
        baseScore: 60,
        patterns: [
            {
                type: PatternType.REGEX,
                patternId: 'redirect-req-query',
                pattern: 'res\\.redirect\\s*\\(\\s*req\\.(?:query|body|params)',
                flags: 'gi',
                weight: 0.95,
                description: 'res.redirect() with request data'
            },
            {
                type: PatternType.REGEX,
                patternId: 'redirect-user-var',
                pattern: 'res\\.redirect\\s*\\(\\s*(?:url|redirect|returnUrl|next|destination|goto|target|redir|return_to)\\b',
                flags: 'gi',
                weight: 0.80,
                description: 'res.redirect() with likely user-controlled variable'
            },
            {
                type: PatternType.REGEX,
                patternId: 'redirect-location-header',
                pattern: 'res\\.(?:set|setHeader)\\s*\\(\\s*[\'"]Location[\'"]\\s*,\\s*(?:req\\.|url|redirect)',
                flags: 'gi',
                weight: 0.90,
                description: 'Location header set from user input'
            }
        ],
        taintSources: [
            { id: 'src-query', name: 'req.query', pattern: /req\.query(?:\.\w+|\[)/, languages: [SupportedLanguage.JAVASCRIPT, SupportedLanguage.TYPESCRIPT], category: 'user_input' },
            { id: 'src-body', name: 'req.body', pattern: /req\.body(?:\.\w+|\[)/, languages: [SupportedLanguage.JAVASCRIPT, SupportedLanguage.TYPESCRIPT], category: 'user_input' },
            { id: 'src-params', name: 'req.params', pattern: /req\.params(?:\.\w+|\[)/, languages: [SupportedLanguage.JAVASCRIPT, SupportedLanguage.TYPESCRIPT], category: 'user_input' }
        ],
        taintSinks: [
            { id: 'sink-redirect', name: 'res.redirect', pattern: /res\.redirect\s*\(/, languages: [SupportedLanguage.JAVASCRIPT, SupportedLanguage.TYPESCRIPT], vulnerabilityType: VulnerabilityType.BROKEN_ACCESS_CONTROL }
        ],
        taintSanitizers: [
            { id: 'san-url-validate', name: 'URL validation', pattern: /new\s+URL\s*\(|url\.parse\s*\(|isValidUrl|validateUrl|allowedHosts|whitelist|allowlist/, protectsAgainst: [VulnerabilityType.BROKEN_ACCESS_CONTROL], effectiveness: 90 },
            { id: 'san-startswith', name: 'Path prefix check', pattern: /\.startsWith\s*\(\s*['"]\/(?!\/)/, protectsAgainst: [VulnerabilityType.BROKEN_ACCESS_CONTROL], effectiveness: 80 }
        ],
        impact: {
            confidentiality: 'low',
            integrity: 'medium',
            availability: 'none',
            technicalImpact: 'Attacker can redirect users to malicious sites, enabling phishing and credential theft.',
            businessImpact: 'Phishing attacks using trusted domain, credential theft, reputation damage.'
        },
        exploitability: {
            attackVector: 'network',
            attackComplexity: 'low',
            privilegesRequired: 'none',
            userInteraction: 'required'
        },
        remediation: {
            summary: 'Validate redirect URLs against an allowlist of trusted domains or restrict to relative paths.',
            steps: [
                'Use relative paths only (e.g. startsWith("/") and not startsWith("//"))',
                'Maintain an allowlist of trusted redirect domains',
                'Use new URL() to parse and validate the redirect target',
                'Never redirect to URLs from req.query/body directly'
            ],
            secureCodeExample: `// Safe: allowlist-based redirect
const ALLOWED_HOSTS = ['example.com', 'app.example.com'];

app.get('/redirect', (req, res) => {
  const target = req.query.url;
  try {
    const parsed = new URL(target, \`https://\${req.get('host')}\`);
    if (ALLOWED_HOSTS.includes(parsed.hostname)) {
      return res.redirect(parsed.href);
    }
  } catch {}
  res.redirect('/');
});`,
            effort: 'low',
            priority: 'high'
        },
        standards: {
            owasp: [OWASP_TOP_10_2021.A01],
            cwe: [{ id: 'CWE-601', title: 'URL Redirection to Untrusted Site', url: 'https://cwe.mitre.org/data/definitions/601.html' }]
        },
        tags: ['open-redirect', 'redirect', 'phishing', 'express'],
        enabled: true
    },

    // =========================================================================
    // OPEN REDIRECT - PHP
    // =========================================================================
    {
        id: 'VUL-REDIRECT-002',
        name: 'Open Redirect - PHP',
        description: 'Detects PHP header("Location: ...") redirects using unvalidated user input.',
        version: '1.0.0',
        vulnerabilityType: VulnerabilityType.BROKEN_ACCESS_CONTROL,
        category: VulnerabilityCategory.BROKEN_ACCESS_CONTROL,
        languages: [SupportedLanguage.PHP],
        severity: VulnerabilitySeverity.MEDIUM,
        confidence: ConfidenceLevel.HIGH,
        baseScore: 60,
        patterns: [
            {
                type: PatternType.REGEX,
                patternId: 'redirect-php-header-get',
                pattern: 'header\\s*\\(\\s*[\'"]Location:\\s*[\'"]\\s*\\.\\s*\\$_(?:GET|POST|REQUEST)',
                flags: 'gi',
                weight: 0.95,
                description: 'header(Location:) with $_GET/$_POST/$_REQUEST'
            },
            {
                type: PatternType.REGEX,
                patternId: 'redirect-php-header-var',
                pattern: 'header\\s*\\(\\s*[\'"]Location:\\s*\\$',
                flags: 'gi',
                weight: 0.75,
                description: 'header(Location:) with PHP variable'
            }
        ],
        impact: {
            confidentiality: 'low',
            integrity: 'medium',
            availability: 'none',
            technicalImpact: 'Unvalidated redirect enables phishing via the trusted domain.',
            businessImpact: 'Phishing, credential theft, reputation damage.'
        },
        exploitability: {
            attackVector: 'network',
            attackComplexity: 'low',
            privilegesRequired: 'none',
            userInteraction: 'required'
        },
        remediation: {
            summary: 'Validate redirect URLs against an allowlist or restrict to relative paths.',
            steps: [
                'Parse and validate the URL with parse_url()',
                'Check that the host is in an allowed list',
                'Prefer relative paths (starting with /)',
                'Never use $_GET/$_POST directly in header(Location:)'
            ],
            secureCodeExample: `<?php
$allowed = ['example.com', 'app.example.com'];
$url = $_GET['url'] ?? '/';
$parsed = parse_url($url);
if (isset($parsed['host']) && !in_array($parsed['host'], $allowed)) {
    $url = '/';
}
header('Location: ' . $url);
exit;
?>`,
            effort: 'low',
            priority: 'high'
        },
        standards: {
            owasp: [OWASP_TOP_10_2021.A01],
            cwe: [{ id: 'CWE-601', title: 'URL Redirection to Untrusted Site', url: 'https://cwe.mitre.org/data/definitions/601.html' }]
        },
        tags: ['open-redirect', 'redirect', 'phishing', 'php'],
        enabled: true
    },

    // =========================================================================
    // OPEN REDIRECT - Python (Flask / Django)
    // =========================================================================
    {
        id: 'VUL-REDIRECT-003',
        name: 'Open Redirect - Python (Flask/Django)',
        description: 'Detects Python redirect() with unvalidated user input from request args.',
        version: '1.0.0',
        vulnerabilityType: VulnerabilityType.BROKEN_ACCESS_CONTROL,
        category: VulnerabilityCategory.BROKEN_ACCESS_CONTROL,
        languages: [SupportedLanguage.PYTHON],
        severity: VulnerabilitySeverity.MEDIUM,
        confidence: ConfidenceLevel.HIGH,
        baseScore: 60,
        patterns: [
            {
                type: PatternType.REGEX,
                patternId: 'redirect-flask-args',
                pattern: 'redirect\\s*\\(\\s*request\\.(?:args|form|values)\\.get\\s*\\(',
                flags: 'gi',
                weight: 0.95,
                description: 'Flask redirect(request.args.get(...))'
            },
            {
                type: PatternType.REGEX,
                patternId: 'redirect-django-get',
                pattern: 'redirect\\s*\\(\\s*request\\.(?:GET|POST)\\.get\\s*\\(',
                flags: 'gi',
                weight: 0.95,
                description: 'Django redirect(request.GET.get(...))'
            },
            {
                type: PatternType.REGEX,
                patternId: 'redirect-httpresponse',
                pattern: 'HttpResponseRedirect\\s*\\(\\s*request\\.(?:GET|POST)',
                flags: 'gi',
                weight: 0.90,
                description: 'Django HttpResponseRedirect with request data'
            }
        ],
        impact: {
            confidentiality: 'low',
            integrity: 'medium',
            availability: 'none',
            technicalImpact: 'Unvalidated redirect enables phishing via the trusted domain.',
            businessImpact: 'Phishing, credential theft.'
        },
        exploitability: {
            attackVector: 'network',
            attackComplexity: 'low',
            privilegesRequired: 'none',
            userInteraction: 'required'
        },
        remediation: {
            summary: 'Validate redirect target against an allowlist or use url_has_allowed_host_and_scheme().',
            steps: [
                'Use Django url_has_allowed_host_and_scheme() before redirecting',
                'In Flask, parse the URL and check against allowed hosts',
                'Prefer relative paths (starting with /)',
                'Never pass request data directly to redirect()'
            ],
            secureCodeExample: `# Django
from django.utils.http import url_has_allowed_host_and_scheme

def login_redirect(request):
    next_url = request.GET.get('next', '/')
    if not url_has_allowed_host_and_scheme(next_url, allowed_hosts={request.get_host()}):
        next_url = '/'
    return redirect(next_url)

# Flask
from urllib.parse import urlparse
ALLOWED_HOSTS = {'example.com'}

@app.route('/redirect')
def safe_redirect():
    url = request.args.get('url', '/')
    parsed = urlparse(url)
    if parsed.netloc and parsed.netloc not in ALLOWED_HOSTS:
        url = '/'
    return redirect(url)`,
            effort: 'low',
            priority: 'high'
        },
        standards: {
            owasp: [OWASP_TOP_10_2021.A01],
            cwe: [{ id: 'CWE-601', title: 'URL Redirection to Untrusted Site', url: 'https://cwe.mitre.org/data/definitions/601.html' }]
        },
        tags: ['open-redirect', 'redirect', 'phishing', 'python', 'flask', 'django'],
        enabled: true
    }
];

export default openRedirectRules;
