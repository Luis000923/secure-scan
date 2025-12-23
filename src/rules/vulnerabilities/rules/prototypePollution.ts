/**
 * @fileoverview Prototype Pollution Detection Rules
 * @module rules/vulnerabilities/rules/prototypePollution
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

export const prototypePollutionRules: VulnerabilityRule[] = [
  {
    id: 'VUL-PROTO-001',
    name: 'Prototype Pollution - Unsafe Object Merge',
    description: 'Detects unsafe object merging that may lead to prototype pollution.',
    version: '1.0.0',
    vulnerabilityType: VulnerabilityType.PROTOTYPE_POLLUTION,
    category: VulnerabilityCategory.INJECTION,
    languages: [SupportedLanguage.JAVASCRIPT, SupportedLanguage.TYPESCRIPT],
    severity: VulnerabilitySeverity.HIGH,
    confidence: ConfidenceLevel.MEDIUM,
    baseScore: 75,
    patterns: [
      {
        type: PatternType.REGEX,
        patternId: 'proto-object-assign-req',
        pattern: 'Object\\.assign\\s*\\([^,]*,\\s*(?:req\\.|body|params|query)',
        flags: 'gi',
        weight: 0.90,
        description: 'Object.assign with user input'
      },
      {
        type: PatternType.REGEX,
        patternId: 'proto-spread-req',
        pattern: '\\{\\s*\\.\\.\\.(?:req\\.|body|params)',
        flags: 'gi',
        weight: 0.85,
        description: 'Spread operator with user input'
      },
      {
        type: PatternType.REGEX,
        patternId: 'proto-lodash-merge',
        pattern: '(?:_|lodash)\\.(?:merge|defaultsDeep|set)\\s*\\([^)]*(?:req\\.|body)',
        flags: 'gi',
        weight: 0.95,
        description: 'lodash merge/set with user input'
      },
      {
        type: PatternType.REGEX,
        patternId: 'proto-bracket-proto',
        pattern: '\\[[\'"]__proto__[\'"]\\]|\\[[\'"]constructor[\'"]\\]\\s*\\[[\'"]prototype[\'"]\\]',
        flags: 'g',
        weight: 1.0,
        description: 'Direct __proto__ or constructor.prototype access'
      }
    ],
    taintAnalysis: {
      sources: ['req.body', 'req.query', 'req.params', 'JSON.parse'],
      sinks: ['Object.assign', 'Object.defineProperty', '_.merge', '_.set', '_.defaultsDeep'],
      sanitizers: ['Object.create(null)', 'Object.freeze', 'hasOwnProperty']
    },
    impact: {
      confidentiality: 'medium',
      integrity: 'high',
      availability: 'medium',
      technicalImpact: 'Modify Object.prototype properties affecting all objects. May lead to RCE.',
      businessImpact: 'Denial of service, authentication bypass, RCE in some cases.'
    },
    exploitability: {
      attackVector: 'network',
      attackComplexity: 'medium',
      privilegesRequired: 'none',
      userInteraction: 'none',
      knownExploits: true
    },
    remediation: {
      summary: 'Validate object keys. Use Object.create(null) for dictionaries. Block __proto__ keys.',
      steps: [
        'Filter __proto__, constructor, prototype from user input',
        'Use Object.create(null) for user-controlled objects',
        'Freeze prototypes if possible',
        'Update vulnerable libraries (lodash < 4.17.12)',
        'Use Map instead of plain objects for dictionaries'
      ],
      secureCodeExample: `// Filter dangerous keys
function safeMerge(target, source) {
  const dangerous = ['__proto__', 'constructor', 'prototype'];
  
  for (const key of Object.keys(source)) {
    if (dangerous.includes(key)) continue;
    if (typeof source[key] === 'object' && source[key] !== null) {
      target[key] = safeMerge(target[key] || {}, source[key]);
    } else {
      target[key] = source[key];
    }
  }
  return target;
}

// Use Map for user-controlled data
const userSettings = new Map();
userSettings.set(req.body.key, req.body.value);

// Use Object.create(null)
const dict = Object.create(null);
dict[userKey] = userValue;`,
      effort: 'medium',
      priority: 'high'
    },
    standards: {
      owasp: [OWASP_TOP_10_2021.A03],
      cwe: [CWE_REFERENCES.CWE_1321]
    },
    tags: ['prototype-pollution', 'javascript', 'injection'],
    enabled: true
  },
  {
    id: 'VUL-PROTO-002',
    name: 'Prototype Pollution - JSON.parse with Reviver',
    description: 'Detects potentially unsafe JSON parsing patterns.',
    version: '1.0.0',
    vulnerabilityType: VulnerabilityType.PROTOTYPE_POLLUTION,
    category: VulnerabilityCategory.INJECTION,
    languages: [SupportedLanguage.JAVASCRIPT, SupportedLanguage.TYPESCRIPT],
    severity: VulnerabilitySeverity.MEDIUM,
    confidence: ConfidenceLevel.LOW,
    baseScore: 50,
    patterns: [
      {
        type: PatternType.REGEX,
        patternId: 'proto-json-parse-body',
        pattern: 'JSON\\.parse\\s*\\([^)]*(?:req\\.body|body|data)',
        flags: 'gi',
        weight: 0.70,
        description: 'JSON.parse on user data'
      }
    ],
    impact: {
      confidentiality: 'low',
      integrity: 'medium',
      availability: 'low',
      technicalImpact: 'Parsed JSON with __proto__ key can pollute prototypes.',
      businessImpact: 'Application behavior modification.'
    },
    exploitability: {
      attackVector: 'network',
      attackComplexity: 'medium',
      privilegesRequired: 'none',
      userInteraction: 'none'
    },
    remediation: {
      summary: 'Use JSON.parse with a reviver that filters dangerous keys.',
      steps: [
        'Use reviver function to filter dangerous keys',
        'Validate parsed object structure',
        'Consider using schema validation libraries'
      ],
      secureCodeExample: `// Safe JSON parsing with reviver
function safeJsonParse(str) {
  return JSON.parse(str, (key, value) => {
    if (key === '__proto__' || key === 'constructor') {
      return undefined;
    }
    return value;
  });
}

// With schema validation (e.g., Zod)
import { z } from 'zod';
const UserSchema = z.object({
  name: z.string(),
  email: z.string().email()
});

const userData = UserSchema.parse(JSON.parse(req.body));`,
      effort: 'low',
      priority: 'medium'
    },
    standards: {
      owasp: [OWASP_TOP_10_2021.A03],
      cwe: [CWE_REFERENCES.CWE_1321]
    },
    tags: ['prototype-pollution', 'json', 'javascript'],
    enabled: true
  },
  {
    id: 'VUL-PROTO-003',
    name: 'Prototype Pollution - Vulnerable Package Usage',
    description: 'Detects usage of packages known to have prototype pollution vulnerabilities.',
    version: '1.0.0',
    vulnerabilityType: VulnerabilityType.PROTOTYPE_POLLUTION,
    category: VulnerabilityCategory.KNOWN_VULNERABLE_COMPONENT,
    languages: [SupportedLanguage.JAVASCRIPT, SupportedLanguage.TYPESCRIPT],
    severity: VulnerabilitySeverity.HIGH,
    confidence: ConfidenceLevel.HIGH,
    baseScore: 70,
    patterns: [
      {
        type: PatternType.REGEX,
        patternId: 'proto-vulnerable-qs',
        pattern: 'require\\s*\\([\'"]qs[\'"]\\)',
        flags: 'g',
        weight: 0.70,
        description: 'qs package (check version for CVE-2022-24999)'
      },
      {
        type: PatternType.REGEX,
        patternId: 'proto-vulnerable-flat',
        pattern: 'require\\s*\\([\'"]flat[\'"]\\)',
        flags: 'g',
        weight: 0.80,
        description: 'flat package (vulnerable < 5.0.1)'
      },
      {
        type: PatternType.REGEX,
        patternId: 'proto-vulnerable-merge',
        pattern: 'require\\s*\\([\'"](?:deepmerge|deep-extend|merge-deep)[\'"]\\)',
        flags: 'g',
        weight: 0.75,
        description: 'Deep merge packages (verify versions)'
      }
    ],
    impact: {
      confidentiality: 'medium',
      integrity: 'high',
      availability: 'medium',
      technicalImpact: 'Known vulnerabilities in dependencies allow prototype pollution.',
      businessImpact: 'Exploitation via known CVEs.'
    },
    exploitability: {
      attackVector: 'network',
      attackComplexity: 'low',
      privilegesRequired: 'none',
      userInteraction: 'none',
      knownExploits: true
    },
    remediation: {
      summary: 'Update vulnerable packages to patched versions.',
      steps: [
        'Run npm audit or yarn audit',
        'Update lodash to >= 4.17.21',
        'Update qs to >= 6.10.3',
        'Update flat to >= 5.0.1',
        'Consider alternative packages without vulnerabilities'
      ],
      secureCodeExample: `// Update packages in package.json
{
  "dependencies": {
    "lodash": "^4.17.21",
    "qs": "^6.11.0",
    "flat": "^5.0.2"
  }
}

// Or use native alternatives
// Instead of lodash.merge:
const merged = { ...defaults, ...userOptions };

// Instead of qs:
const params = new URLSearchParams(queryString);`,
      effort: 'low',
      priority: 'high'
    },
    standards: {
      owasp: [OWASP_TOP_10_2021.A06],
      cwe: [CWE_REFERENCES.CWE_1321]
    },
    tags: ['prototype-pollution', 'dependencies', 'npm'],
    enabled: true
  }
];

export default prototypePollutionRules;
