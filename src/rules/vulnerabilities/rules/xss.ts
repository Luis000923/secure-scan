/**
 * @fileoverview Cross-Site Scripting (XSS) Detection Rules
 * @module rules/vulnerabilities/rules/xss
 * 
 * Comprehensive XSS detection for DOM-based, Reflected, and Stored XSS.
 * Covers multiple languages and frameworks.
 */

import {
  VulnerabilityRule,
  VulnerabilityType,
  VulnerabilityCategory,
  VulnerabilitySeverity,
  ConfidenceLevel,
  SupportedLanguage,
  PatternType,
  TaintSource,
  TaintSink,
  TaintSanitizer
} from '../types';
import { OWASP_TOP_10_2021, CWE_REFERENCES } from '../constants';

// ============================================================================
// TAINT DEFINITIONS FOR XSS
// ============================================================================

const xssSources: TaintSource[] = [
  // DOM Sources
  { id: 'dom-location', name: 'location', pattern: /(?:window\.)?location\.(?:search|hash|href|pathname)/g, languages: [SupportedLanguage.JAVASCRIPT, SupportedLanguage.TYPESCRIPT], category: 'user_input' },
  { id: 'dom-referrer', name: 'document.referrer', pattern: /document\.referrer/g, languages: [SupportedLanguage.JAVASCRIPT, SupportedLanguage.TYPESCRIPT], category: 'user_input' },
  { id: 'dom-url', name: 'document.URL', pattern: /document\.(?:URL|documentURI)/g, languages: [SupportedLanguage.JAVASCRIPT, SupportedLanguage.TYPESCRIPT], category: 'user_input' },
  { id: 'dom-cookie', name: 'document.cookie', pattern: /document\.cookie/g, languages: [SupportedLanguage.JAVASCRIPT, SupportedLanguage.TYPESCRIPT], category: 'user_input' },
  { id: 'dom-storage', name: 'localStorage/sessionStorage', pattern: /(?:local|session)Storage\.getItem\s*\(/g, languages: [SupportedLanguage.JAVASCRIPT, SupportedLanguage.TYPESCRIPT], category: 'user_input' },
  
  // Server Sources
  { id: 'js-req', name: 'req.body/query/params', pattern: /req\.(?:body|query|params)(?:\.\w+|\[\s*['"`]\w+['"`]\s*\])?/g, languages: [SupportedLanguage.JAVASCRIPT, SupportedLanguage.TYPESCRIPT], category: 'user_input' },
  { id: 'php-superglobals', name: '$_GET/$_POST', pattern: /\$_(?:GET|POST|REQUEST)\s*\[\s*['"`][^'"`]+['"`]\s*\]/g, languages: [SupportedLanguage.PHP], category: 'user_input' },
  { id: 'py-request', name: 'request.args/form', pattern: /request\.(?:args|form)\.get\s*\([^)]+\)/g, languages: [SupportedLanguage.PYTHON], category: 'user_input' },
  { id: 'java-param', name: 'getParameter', pattern: /(?:request\.)?getParameter\s*\([^)]+\)/g, languages: [SupportedLanguage.JAVA], category: 'user_input' }
];

const xssSinks: TaintSink[] = [
  // DOM Sinks
  { id: 'dom-innerhtml', name: 'innerHTML', pattern: /\.innerHTML\s*=(?!=)/g, languages: [SupportedLanguage.JAVASCRIPT, SupportedLanguage.TYPESCRIPT], vulnerabilityType: VulnerabilityType.XSS_DOM, dangerousArgs: [0] },
  { id: 'dom-outerhtml', name: 'outerHTML', pattern: /\.outerHTML\s*=(?!=)/g, languages: [SupportedLanguage.JAVASCRIPT, SupportedLanguage.TYPESCRIPT], vulnerabilityType: VulnerabilityType.XSS_DOM },
  { id: 'dom-write', name: 'document.write', pattern: /document\s*\.\s*write(?:ln)?\s*\(/g, languages: [SupportedLanguage.JAVASCRIPT, SupportedLanguage.TYPESCRIPT], vulnerabilityType: VulnerabilityType.XSS_DOM },
  { id: 'dom-inserthtml', name: 'insertAdjacentHTML', pattern: /\.insertAdjacentHTML\s*\(/g, languages: [SupportedLanguage.JAVASCRIPT, SupportedLanguage.TYPESCRIPT], vulnerabilityType: VulnerabilityType.XSS_DOM },
  
  // jQuery Sinks
  { id: 'jquery-html', name: '$.html()', pattern: /\$\([^)]*\)\s*\.\s*html\s*\([^)]+\)/g, languages: [SupportedLanguage.JAVASCRIPT, SupportedLanguage.TYPESCRIPT], vulnerabilityType: VulnerabilityType.XSS_DOM },
  { id: 'jquery-append', name: '$.append()', pattern: /\$\([^)]*\)\s*\.\s*(?:append|prepend|after|before)\s*\([^)]+\)/g, languages: [SupportedLanguage.JAVASCRIPT, SupportedLanguage.TYPESCRIPT], vulnerabilityType: VulnerabilityType.XSS_DOM },
  
  // React Sinks
  { id: 'react-dangerous', name: 'dangerouslySetInnerHTML', pattern: /dangerouslySetInnerHTML\s*=\s*\{/g, languages: [SupportedLanguage.JAVASCRIPT, SupportedLanguage.TYPESCRIPT], vulnerabilityType: VulnerabilityType.XSS_DOM },
  
  // Angular Sinks
  { id: 'angular-bypass', name: 'bypassSecurityTrust', pattern: /bypassSecurityTrust(?:Html|Script|Url|ResourceUrl|Style)\s*\(/g, languages: [SupportedLanguage.TYPESCRIPT], vulnerabilityType: VulnerabilityType.XSS_DOM },
  
  // Vue Sinks
  { id: 'vue-vhtml', name: 'v-html', pattern: /v-html\s*=\s*['"`]/g, languages: [SupportedLanguage.JAVASCRIPT, SupportedLanguage.TYPESCRIPT], vulnerabilityType: VulnerabilityType.XSS_DOM },
  
  // Server-side template sinks
  { id: 'php-echo', name: 'echo $_', pattern: /echo\s+\$_(?:GET|POST|REQUEST)/g, languages: [SupportedLanguage.PHP], vulnerabilityType: VulnerabilityType.XSS_REFLECTED },
  { id: 'php-print', name: 'print $_', pattern: /print\s+\$_(?:GET|POST|REQUEST)/g, languages: [SupportedLanguage.PHP], vulnerabilityType: VulnerabilityType.XSS_REFLECTED }
];

const xssSanitizers: TaintSanitizer[] = [
  { id: 'dompurify', name: 'DOMPurify', pattern: /DOMPurify\s*\.\s*sanitize\s*\(/g, protectsAgainst: [VulnerabilityType.XSS_DOM, VulnerabilityType.XSS_REFLECTED, VulnerabilityType.XSS_STORED], effectiveness: 98 },
  { id: 'textcontent', name: 'textContent', pattern: /\.textContent\s*=/g, protectsAgainst: [VulnerabilityType.XSS_DOM], effectiveness: 100 },
  { id: 'createtextnode', name: 'createTextNode', pattern: /createTextNode\s*\(/g, protectsAgainst: [VulnerabilityType.XSS_DOM], effectiveness: 100 },
  { id: 'encodeuri', name: 'encodeURIComponent', pattern: /encodeURIComponent\s*\(/g, protectsAgainst: [VulnerabilityType.XSS_DOM, VulnerabilityType.XSS_REFLECTED], effectiveness: 90 },
  { id: 'htmlspecialchars', name: 'htmlspecialchars', pattern: /htmlspecialchars\s*\(/g, languages: [SupportedLanguage.PHP], protectsAgainst: [VulnerabilityType.XSS_REFLECTED, VulnerabilityType.XSS_STORED], effectiveness: 95 },
  { id: 'htmlentities', name: 'htmlentities', pattern: /htmlentities\s*\(/g, languages: [SupportedLanguage.PHP], protectsAgainst: [VulnerabilityType.XSS_REFLECTED, VulnerabilityType.XSS_STORED], effectiveness: 95 },
  { id: 'strip-tags', name: 'strip_tags', pattern: /strip_tags\s*\(/g, languages: [SupportedLanguage.PHP], protectsAgainst: [VulnerabilityType.XSS_REFLECTED], effectiveness: 70 },
  { id: 'bleach', name: 'bleach.clean', pattern: /bleach\s*\.\s*clean\s*\(/g, languages: [SupportedLanguage.PYTHON], protectsAgainst: [VulnerabilityType.XSS_REFLECTED, VulnerabilityType.XSS_STORED], effectiveness: 95 },
  { id: 'escape', name: 'escape()', pattern: /\bescape\s*\(|markupsafe\.escape/g, protectsAgainst: [VulnerabilityType.XSS_REFLECTED, VulnerabilityType.XSS_STORED], effectiveness: 90 }
];

// ============================================================================
// XSS RULES
// ============================================================================

export const xssRules: VulnerabilityRule[] = [
  // ==========================================================================
  // DOM-based XSS Rules
  // ==========================================================================
  {
    id: 'VUL-XSS-001',
    name: 'DOM XSS - innerHTML with User Input',
    description: 'Detects assignment of user-controlled data to innerHTML, which can execute arbitrary JavaScript.',
    version: '1.0.0',
    vulnerabilityType: VulnerabilityType.XSS_DOM,
    category: VulnerabilityCategory.XSS,
    languages: [SupportedLanguage.JAVASCRIPT, SupportedLanguage.TYPESCRIPT],
    severity: VulnerabilitySeverity.HIGH,
    confidence: ConfidenceLevel.HIGH,
    baseScore: 80,
    patterns: [
      {
        type: PatternType.REGEX,
        patternId: 'xss-innerhtml-location',
        pattern: '\\.innerHTML\\s*=\\s*(?:.*location\\.|.*document\\.(?:URL|referrer|cookie))',
        flags: 'gi',
        weight: 1.0,
        description: 'innerHTML with DOM-based source'
      },
      {
        type: PatternType.REGEX,
        patternId: 'xss-innerhtml-var',
        pattern: '\\.innerHTML\\s*=\\s*[^;]*(?:\\+|`\\$\\{)',
        flags: 'gi',
        weight: 0.85,
        description: 'innerHTML with variable concatenation'
      },
      {
        type: PatternType.REGEX,
        patternId: 'xss-outerhtml',
        pattern: '\\.outerHTML\\s*=\\s*[^;]*(?:\\+|`\\$\\{)',
        flags: 'gi',
        weight: 0.85,
        description: 'outerHTML with variable'
      }
    ],
    taintSources: xssSources.filter(s => s.languages?.includes(SupportedLanguage.JAVASCRIPT)),
    taintSinks: xssSinks.filter(s => s.id.startsWith('dom-')),
    taintSanitizers: xssSanitizers,
    impact: {
      confidentiality: 'high',
      integrity: 'high',
      availability: 'low',
      technicalImpact: 'Arbitrary JavaScript execution in user browser. Session hijacking, credential theft, keylogging.',
      businessImpact: 'Account takeover, defacement, malware distribution.',
      affectedAssets: ['User Browser', 'User Session', 'User Credentials'],
      dataAtRisk: ['Session Tokens', 'Cookies', 'User Input']
    },
    exploitability: {
      attackVector: 'network',
      attackComplexity: 'low',
      privilegesRequired: 'none',
      userInteraction: 'required',
      knownExploits: true
    },
    vulnerableExamples: [
      {
        code: `const name = new URLSearchParams(location.search).get('name');
document.getElementById('greeting').innerHTML = 'Hello, ' + name;`,
        language: SupportedLanguage.JAVASCRIPT,
        isVulnerable: true,
        description: 'User input from URL directly assigned to innerHTML'
      }
    ],
    secureExamples: [
      {
        code: `const name = new URLSearchParams(location.search).get('name');
document.getElementById('greeting').textContent = 'Hello, ' + name;`,
        language: SupportedLanguage.JAVASCRIPT,
        isVulnerable: false,
        description: 'Using textContent instead of innerHTML',
        safetyExplanation: 'textContent does not parse HTML, treating input as plain text'
      }
    ],
    remediation: {
      summary: 'Use textContent, DOMPurify, or framework-safe methods instead of innerHTML.',
      steps: [
        'Replace innerHTML with textContent for plain text',
        'Use DOMPurify.sanitize() when HTML is required',
        'Use framework methods like React JSX or Angular templates',
        'Implement Content Security Policy (CSP)'
      ],
      secureCodeExample: `// Secure: Using textContent
element.textContent = userInput;

// Secure: Using DOMPurify when HTML needed
element.innerHTML = DOMPurify.sanitize(userInput);

// Secure: Using DOM APIs
const text = document.createTextNode(userInput);
element.appendChild(text);`,
      references: [
        'https://cheatsheetseries.owasp.org/cheatsheets/DOM_based_XSS_Prevention_Cheat_Sheet.html',
        'https://github.com/cure53/DOMPurify'
      ],
      effort: 'low',
      priority: 'high'
    },
    standards: {
      owasp: [OWASP_TOP_10_2021.A03],
      cwe: [CWE_REFERENCES.CWE_79],
      sans: [{ rank: 2, cweId: 'CWE-79', category: 'XSS' }]
    },
    tags: ['xss', 'dom-xss', 'javascript', 'client-side', 'high'],
    enabled: true
  },

  {
    id: 'VUL-XSS-002',
    name: 'DOM XSS - document.write with User Input',
    description: 'Detects document.write() with user-controlled data, which can inject malicious scripts.',
    version: '1.0.0',
    vulnerabilityType: VulnerabilityType.XSS_DOM,
    category: VulnerabilityCategory.XSS,
    languages: [SupportedLanguage.JAVASCRIPT, SupportedLanguage.TYPESCRIPT],
    severity: VulnerabilitySeverity.HIGH,
    confidence: ConfidenceLevel.HIGH,
    baseScore: 82,
    patterns: [
      {
        type: PatternType.REGEX,
        patternId: 'xss-docwrite-location',
        pattern: 'document\\.write(?:ln)?\\s*\\([^)]*(?:location|document\\.(?:URL|referrer))',
        flags: 'gi',
        weight: 1.0,
        description: 'document.write with DOM source'
      },
      {
        type: PatternType.REGEX,
        patternId: 'xss-docwrite-concat',
        pattern: 'document\\.write(?:ln)?\\s*\\([^)]*\\+',
        flags: 'gi',
        weight: 0.80,
        description: 'document.write with concatenation'
      }
    ],
    taintSources: xssSources,
    taintSinks: [{ id: 'dom-write', name: 'document.write', pattern: /document\.write/g, vulnerabilityType: VulnerabilityType.XSS_DOM }],
    taintSanitizers: xssSanitizers,
    impact: {
      confidentiality: 'high',
      integrity: 'high',
      availability: 'low',
      technicalImpact: 'Full page content manipulation, script injection.',
      businessImpact: 'Complete page takeover possible.'
    },
    exploitability: {
      attackVector: 'network',
      attackComplexity: 'low',
      privilegesRequired: 'none',
      userInteraction: 'required'
    },
    remediation: {
      summary: 'Avoid document.write entirely. Use DOM manipulation methods instead.',
      steps: [
        'Replace document.write with DOM APIs',
        'Use createElement and appendChild',
        'Implement CSP to block inline scripts'
      ],
      secureCodeExample: `// Instead of document.write, use:
const element = document.createElement('div');
element.textContent = sanitizedContent;
document.body.appendChild(element);`,
      effort: 'medium',
      priority: 'high'
    },
    standards: {
      owasp: [OWASP_TOP_10_2021.A03],
      cwe: [CWE_REFERENCES.CWE_79]
    },
    tags: ['xss', 'dom-xss', 'document-write', 'deprecated'],
    enabled: true
  },

  {
    id: 'VUL-XSS-003',
    name: 'DOM XSS - jQuery html() with User Input',
    description: 'Detects jQuery .html() method with user-controlled data.',
    version: '1.0.0',
    vulnerabilityType: VulnerabilityType.XSS_DOM,
    category: VulnerabilityCategory.XSS,
    languages: [SupportedLanguage.JAVASCRIPT, SupportedLanguage.TYPESCRIPT],
    severity: VulnerabilitySeverity.HIGH,
    confidence: ConfidenceLevel.MEDIUM,
    baseScore: 75,
    patterns: [
      {
        type: PatternType.REGEX,
        patternId: 'xss-jquery-html',
        pattern: '\\$\\([^)]+\\)\\.html\\s*\\([^)]*(?:location|document\\.|\\+|`\\$\\{)',
        flags: 'gi',
        weight: 0.90,
        description: 'jQuery .html() with dynamic content'
      },
      {
        type: PatternType.REGEX,
        patternId: 'xss-jquery-append',
        pattern: '\\$\\([^)]+\\)\\.(?:append|prepend|after|before)\\s*\\([^)]*(?:<|\\+.*<)',
        flags: 'gi',
        weight: 0.85,
        description: 'jQuery DOM insertion with HTML'
      }
    ],
    taintSources: xssSources,
    taintSinks: xssSinks.filter(s => s.id.startsWith('jquery-')),
    taintSanitizers: xssSanitizers,
    impact: {
      confidentiality: 'high',
      integrity: 'high',
      availability: 'low',
      technicalImpact: 'Script execution in user context.',
      businessImpact: 'Session theft, phishing attacks.'
    },
    exploitability: {
      attackVector: 'network',
      attackComplexity: 'low',
      privilegesRequired: 'none',
      userInteraction: 'required'
    },
    remediation: {
      summary: 'Use .text() instead of .html(), or sanitize with DOMPurify.',
      steps: [
        'Replace .html() with .text() for plain text',
        'Sanitize HTML with DOMPurify before using .html()',
        'Use .attr() carefully for attributes'
      ],
      secureCodeExample: `// Secure: Use .text() for plain text
$('#element').text(userInput);

// Secure: Sanitize if HTML is needed
$('#element').html(DOMPurify.sanitize(userInput));`,
      effort: 'low',
      priority: 'high'
    },
    standards: {
      owasp: [OWASP_TOP_10_2021.A03],
      cwe: [CWE_REFERENCES.CWE_79]
    },
    tags: ['xss', 'dom-xss', 'jquery', 'high'],
    enabled: true
  },

  // ==========================================================================
  // React/Angular/Vue XSS Rules
  // ==========================================================================
  {
    id: 'VUL-XSS-004',
    name: 'React XSS - dangerouslySetInnerHTML',
    description: 'Detects use of dangerouslySetInnerHTML with potentially unsafe content.',
    version: '1.0.0',
    vulnerabilityType: VulnerabilityType.XSS_DOM,
    category: VulnerabilityCategory.XSS,
    languages: [SupportedLanguage.JAVASCRIPT, SupportedLanguage.TYPESCRIPT],
    severity: VulnerabilitySeverity.HIGH,
    confidence: ConfidenceLevel.MEDIUM,
    baseScore: 70,
    patterns: [
      {
        type: PatternType.REGEX,
        patternId: 'xss-react-dangerous',
        pattern: 'dangerouslySetInnerHTML\\s*=\\s*\\{\\s*\\{\\s*__html\\s*:',
        flags: 'gi',
        weight: 0.85,
        description: 'dangerouslySetInnerHTML usage'
      },
      {
        type: PatternType.REGEX,
        patternId: 'xss-react-dangerous-prop',
        pattern: 'dangerouslySetInnerHTML\\s*=\\s*\\{[^}]*props\\.',
        flags: 'gi',
        weight: 0.95,
        description: 'dangerouslySetInnerHTML with props'
      }
    ],
    falsePositivePatterns: [
      {
        type: PatternType.REGEX,
        patternId: 'xss-react-sanitized',
        pattern: 'dangerouslySetInnerHTML.*DOMPurify\\.sanitize',
        flags: 'gis',
        description: 'Content is sanitized with DOMPurify'
      }
    ],
    impact: {
      confidentiality: 'high',
      integrity: 'high',
      availability: 'low',
      technicalImpact: 'XSS in React application context.',
      businessImpact: 'Component-level attack surface.'
    },
    exploitability: {
      attackVector: 'network',
      attackComplexity: 'low',
      privilegesRequired: 'none',
      userInteraction: 'required'
    },
    remediation: {
      summary: 'Avoid dangerouslySetInnerHTML. If required, always sanitize with DOMPurify.',
      steps: [
        'Use JSX for dynamic content instead',
        'If HTML is required, sanitize with DOMPurify',
        'Review all uses of dangerouslySetInnerHTML'
      ],
      secureCodeExample: `// Avoid: dangerouslySetInnerHTML
// <div dangerouslySetInnerHTML={{__html: userContent}} />

// Secure: Use JSX
<div>{userContent}</div>

// Secure: Sanitize if HTML needed
import DOMPurify from 'dompurify';
<div dangerouslySetInnerHTML={{__html: DOMPurify.sanitize(userContent)}} />`,
      effort: 'low',
      priority: 'high'
    },
    standards: {
      owasp: [OWASP_TOP_10_2021.A03],
      cwe: [CWE_REFERENCES.CWE_79]
    },
    tags: ['xss', 'react', 'dangerously-set-inner-html', 'high'],
    enabled: true
  },

  {
    id: 'VUL-XSS-005',
    name: 'Angular XSS - bypassSecurityTrust',
    description: 'Detects use of Angular DomSanitizer bypass methods without proper validation.',
    version: '1.0.0',
    vulnerabilityType: VulnerabilityType.XSS_DOM,
    category: VulnerabilityCategory.XSS,
    languages: [SupportedLanguage.TYPESCRIPT],
    severity: VulnerabilitySeverity.HIGH,
    confidence: ConfidenceLevel.HIGH,
    baseScore: 78,
    patterns: [
      {
        type: PatternType.REGEX,
        patternId: 'xss-angular-bypass-html',
        pattern: 'bypassSecurityTrustHtml\\s*\\(',
        flags: 'gi',
        weight: 0.95,
        description: 'bypassSecurityTrustHtml usage'
      },
      {
        type: PatternType.REGEX,
        patternId: 'xss-angular-bypass-script',
        pattern: 'bypassSecurityTrustScript\\s*\\(',
        flags: 'gi',
        weight: 1.0,
        description: 'bypassSecurityTrustScript usage'
      },
      {
        type: PatternType.REGEX,
        patternId: 'xss-angular-bypass-url',
        pattern: 'bypassSecurityTrust(?:Url|ResourceUrl)\\s*\\(',
        flags: 'gi',
        weight: 0.85,
        description: 'bypassSecurityTrustUrl usage'
      }
    ],
    impact: {
      confidentiality: 'high',
      integrity: 'high',
      availability: 'low',
      technicalImpact: 'Bypasses Angular built-in XSS protection.',
      businessImpact: 'Security control bypass.'
    },
    exploitability: {
      attackVector: 'network',
      attackComplexity: 'low',
      privilegesRequired: 'none',
      userInteraction: 'required'
    },
    remediation: {
      summary: 'Avoid bypass methods. If needed, validate and sanitize content first.',
      steps: [
        'Review necessity of bypassing sanitization',
        'Use DOMPurify before bypassing',
        'Implement strict input validation'
      ],
      secureCodeExample: `// Validate before bypassing
import DOMPurify from 'dompurify';

sanitizeAndTrust(html: string): SafeHtml {
  const clean = DOMPurify.sanitize(html);
  return this.sanitizer.bypassSecurityTrustHtml(clean);
}`,
      effort: 'medium',
      priority: 'high'
    },
    standards: {
      owasp: [OWASP_TOP_10_2021.A03],
      cwe: [CWE_REFERENCES.CWE_79]
    },
    tags: ['xss', 'angular', 'security-bypass', 'high'],
    enabled: true
  },

  // ==========================================================================
  // Reflected XSS Rules
  // ==========================================================================
  {
    id: 'VUL-XSS-006',
    name: 'Reflected XSS - PHP Echo User Input',
    description: 'Detects PHP code that echoes user input without proper escaping.',
    version: '1.0.0',
    vulnerabilityType: VulnerabilityType.XSS_REFLECTED,
    category: VulnerabilityCategory.XSS,
    languages: [SupportedLanguage.PHP],
    severity: VulnerabilitySeverity.HIGH,
    confidence: ConfidenceLevel.HIGH,
    baseScore: 80,
    patterns: [
      {
        type: PatternType.REGEX,
        patternId: 'xss-php-echo-get',
        pattern: 'echo\\s+\\$_GET\\s*\\[',
        flags: 'gi',
        weight: 1.0,
        description: 'Direct echo of $_GET'
      },
      {
        type: PatternType.REGEX,
        patternId: 'xss-php-echo-post',
        pattern: 'echo\\s+\\$_POST\\s*\\[',
        flags: 'gi',
        weight: 1.0,
        description: 'Direct echo of $_POST'
      },
      {
        type: PatternType.REGEX,
        patternId: 'xss-php-echo-request',
        pattern: 'echo\\s+\\$_REQUEST\\s*\\[',
        flags: 'gi',
        weight: 1.0,
        description: 'Direct echo of $_REQUEST'
      },
      {
        type: PatternType.REGEX,
        patternId: 'xss-php-print',
        pattern: 'print\\s+\\$_(?:GET|POST|REQUEST)\\s*\\[',
        flags: 'gi',
        weight: 1.0,
        description: 'Direct print of superglobal'
      },
      {
        type: PatternType.REGEX,
        patternId: 'xss-php-shortecho',
        pattern: '\\<\\?=\\s*\\$_(?:GET|POST|REQUEST)\\s*\\[',
        flags: 'gi',
        weight: 1.0,
        description: 'Short echo tag with superglobal'
      }
    ],
    taintSources: xssSources.filter(s => s.languages?.includes(SupportedLanguage.PHP)),
    taintSinks: xssSinks.filter(s => s.languages?.includes(SupportedLanguage.PHP)),
    taintSanitizers: xssSanitizers.filter(s => !s.languages || s.languages.includes(SupportedLanguage.PHP)),
    impact: {
      confidentiality: 'high',
      integrity: 'high',
      availability: 'low',
      technicalImpact: 'Script injection in response, session hijacking.',
      businessImpact: 'Account compromise, phishing.'
    },
    exploitability: {
      attackVector: 'network',
      attackComplexity: 'low',
      privilegesRequired: 'none',
      userInteraction: 'required',
      knownExploits: true
    },
    vulnerableExamples: [
      {
        code: `<?php
echo "Hello, " . $_GET['name'];
?>`,
        language: SupportedLanguage.PHP,
        isVulnerable: true,
        description: 'Direct output of user input'
      }
    ],
    remediation: {
      summary: 'Always use htmlspecialchars() or htmlentities() when outputting user data.',
      steps: [
        'Wrap all user output with htmlspecialchars()',
        'Use ENT_QUOTES flag for attribute contexts',
        'Consider using template engines with auto-escaping'
      ],
      secureCodeExample: `<?php
// Secure: Using htmlspecialchars
echo "Hello, " . htmlspecialchars($_GET['name'], ENT_QUOTES, 'UTF-8');

// Secure: Using htmlentities
echo "Hello, " . htmlentities($_GET['name'], ENT_QUOTES, 'UTF-8');
?>`,
      effort: 'low',
      priority: 'high'
    },
    standards: {
      owasp: [OWASP_TOP_10_2021.A03],
      cwe: [CWE_REFERENCES.CWE_79]
    },
    tags: ['xss', 'reflected-xss', 'php', 'high'],
    enabled: true
  },

  // ==========================================================================
  // Stored XSS Detection
  // ==========================================================================
  {
    id: 'VUL-XSS-007',
    name: 'Potential Stored XSS - Database to HTML',
    description: 'Detects patterns where database content is rendered to HTML without escaping.',
    version: '1.0.0',
    vulnerabilityType: VulnerabilityType.XSS_STORED,
    category: VulnerabilityCategory.XSS,
    languages: [SupportedLanguage.JAVASCRIPT, SupportedLanguage.TYPESCRIPT, SupportedLanguage.PHP, SupportedLanguage.PYTHON],
    severity: VulnerabilitySeverity.CRITICAL,
    confidence: ConfidenceLevel.MEDIUM,
    baseScore: 85,
    patterns: [
      {
        type: PatternType.REGEX,
        patternId: 'xss-stored-db-html-js',
        pattern: '\\.innerHTML\\s*=\\s*(?:data|result|row|record|item)(?:\\.|\\[)',
        flags: 'gi',
        weight: 0.80,
        description: 'Database result to innerHTML'
      },
      {
        type: PatternType.REGEX,
        patternId: 'xss-stored-render-body',
        pattern: '\\.(?:render|send)\\s*\\([^)]*\\{[^}]*(?:content|body|message|text)\\s*:',
        flags: 'gi',
        weight: 0.70,
        description: 'Rendering database content'
      }
    ],
    impact: {
      confidentiality: 'high',
      integrity: 'high',
      availability: 'low',
      scope: 'changed',
      technicalImpact: 'Persistent XSS affecting all users viewing the content.',
      businessImpact: 'Mass user compromise, worm propagation.',
      affectedAssets: ['All Users', 'Database Content'],
      dataAtRisk: ['All User Sessions', 'Stored Data']
    },
    exploitability: {
      attackVector: 'network',
      attackComplexity: 'low',
      privilegesRequired: 'low',
      userInteraction: 'required',
      knownExploits: true
    },
    remediation: {
      summary: 'Always sanitize content before storing and escape when rendering.',
      steps: [
        'Sanitize user input before storing in database',
        'Escape content when rendering to HTML',
        'Use Content Security Policy (CSP)',
        'Implement defense in depth with both input and output controls'
      ],
      secureCodeExample: `// Secure: Sanitize on input
const sanitized = DOMPurify.sanitize(userContent);
await db.save({ content: sanitized });

// Secure: Escape on output
element.textContent = dbContent;`,
      effort: 'medium',
      priority: 'immediate'
    },
    standards: {
      owasp: [OWASP_TOP_10_2021.A03],
      cwe: [CWE_REFERENCES.CWE_79]
    },
    tags: ['xss', 'stored-xss', 'persistent', 'critical'],
    enabled: true
  },

  // ==========================================================================
  // Template Injection XSS
  // ==========================================================================
  {
    id: 'VUL-XSS-008',
    name: 'Server-Side Template Injection Leading to XSS',
    description: 'Detects server-side template rendering with user input that may cause XSS.',
    version: '1.0.0',
    vulnerabilityType: VulnerabilityType.TEMPLATE_INJECTION,
    category: VulnerabilityCategory.XSS,
    languages: [SupportedLanguage.PYTHON, SupportedLanguage.JAVASCRIPT],
    severity: VulnerabilitySeverity.CRITICAL,
    confidence: ConfidenceLevel.HIGH,
    baseScore: 88,
    patterns: [
      {
        type: PatternType.REGEX,
        patternId: 'xss-ssti-python',
        pattern: 'render_template_string\\s*\\([^)]*request\\.',
        flags: 'gi',
        weight: 1.0,
        description: 'Flask render_template_string with request data'
      },
      {
        type: PatternType.REGEX,
        patternId: 'xss-ssti-jinja',
        pattern: 'Template\\s*\\([^)]*\\)\\.render\\s*\\(',
        flags: 'gi',
        weight: 0.90,
        description: 'Jinja2 Template render'
      },
      {
        type: PatternType.REGEX,
        patternId: 'xss-ssti-ejs',
        pattern: 'ejs\\.render\\s*\\([^,]+,\\s*\\{[^}]*req\\.',
        flags: 'gi',
        weight: 0.85,
        description: 'EJS render with request data'
      }
    ],
    impact: {
      confidentiality: 'high',
      integrity: 'high',
      availability: 'high',
      scope: 'changed',
      technicalImpact: 'Server-side code execution, not just XSS.',
      businessImpact: 'Complete server compromise.'
    },
    exploitability: {
      attackVector: 'network',
      attackComplexity: 'low',
      privilegesRequired: 'none',
      userInteraction: 'none',
      knownExploits: true
    },
    remediation: {
      summary: 'Never pass user input directly to template rendering. Use predefined templates.',
      steps: [
        'Use render_template with separate template files',
        'Pass user input as template variables, not template content',
        'Enable template auto-escaping'
      ],
      secureCodeExample: `# Secure: Use template files, not string rendering
from flask import render_template

@app.route('/hello')
def hello():
    name = request.args.get('name', '')
    return render_template('hello.html', name=name)`,
      effort: 'medium',
      priority: 'immediate'
    },
    standards: {
      owasp: [OWASP_TOP_10_2021.A03],
      cwe: [CWE_REFERENCES.CWE_79, CWE_REFERENCES.CWE_94]
    },
    tags: ['xss', 'ssti', 'template-injection', 'rce', 'critical'],
    enabled: true
  }
];

// ============================================================================
// EXPORTS
// ============================================================================

export default xssRules;
