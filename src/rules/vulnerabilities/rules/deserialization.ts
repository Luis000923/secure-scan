/**
 * @fileoverview Insecure Deserialization Detection Rules
 * @module rules/vulnerabilities/rules/deserialization
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

export const deserializationRules: VulnerabilityRule[] = [
  {
    id: 'VUL-DESER-001',
    name: 'Insecure Deserialization - Python pickle',
    description: 'Detects use of Python pickle module with untrusted data.',
    version: '1.0.0',
    vulnerabilityType: VulnerabilityType.INSECURE_DESERIALIZATION,
    category: VulnerabilityCategory.INJECTION,
    languages: [SupportedLanguage.PYTHON],
    severity: VulnerabilitySeverity.CRITICAL,
    confidence: ConfidenceLevel.HIGH,
    baseScore: 95,
    patterns: [
      {
        type: PatternType.REGEX,
        patternId: 'deser-pickle-load',
        pattern: 'pickle\\.loads?\\s*\\([^)]*(?:request\\.|input\\(|open\\(|socket)',
        flags: 'gi',
        weight: 1.0,
        description: 'pickle.load with untrusted input'
      },
      {
        type: PatternType.REGEX,
        patternId: 'deser-pickle-import',
        pattern: 'import\\s+pickle|from\\s+pickle\\s+import',
        flags: 'g',
        weight: 0.50,
        description: 'pickle import (needs review)'
      },
      {
        type: PatternType.REGEX,
        patternId: 'deser-yaml-load',
        pattern: 'yaml\\.(?:load|unsafe_load)\\s*\\([^)]*(?!Loader\\s*=\\s*yaml\\.SafeLoader)',
        flags: 'gi',
        weight: 0.95,
        description: 'yaml.load without SafeLoader'
      },
      {
        type: PatternType.REGEX,
        patternId: 'deser-marshal-load',
        pattern: 'marshal\\.loads?\\s*\\(',
        flags: 'gi',
        weight: 0.90,
        description: 'marshal.load usage'
      }
    ],
    impact: {
      confidentiality: 'high',
      integrity: 'high',
      availability: 'high',
      technicalImpact: 'Arbitrary code execution via crafted pickle payload.',
      businessImpact: 'Complete server compromise, RCE.'
    },
    exploitability: {
      attackVector: 'network',
      attackComplexity: 'low',
      privilegesRequired: 'none',
      userInteraction: 'none',
      knownExploits: true
    },
    remediation: {
      summary: 'Never unpickle untrusted data. Use JSON or other safe formats.',
      steps: [
        'Replace pickle with JSON for data serialization',
        'If pickle is required, use hmac to verify data integrity',
        'Use yaml.safe_load() instead of yaml.load()',
        'Restrict deserialization to known safe classes'
      ],
      secureCodeExample: `import json
import hmac
import hashlib

# Secure: Use JSON instead
data = json.loads(request.data)

# If pickle is absolutely required, verify integrity
def verify_and_load(data, signature, secret_key):
    expected_sig = hmac.new(secret_key, data, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(signature, expected_sig):
        raise ValueError("Data integrity check failed")
    return pickle.loads(data)  # Still risky, prefer JSON

# Secure YAML loading
import yaml
data = yaml.safe_load(yaml_content)`,
      effort: 'medium',
      priority: 'immediate'
    },
    standards: {
      owasp: [OWASP_TOP_10_2021.A08],
      cwe: [CWE_REFERENCES.CWE_502]
    },
    tags: ['deserialization', 'rce', 'python', 'pickle', 'critical'],
    enabled: true
  },
  {
    id: 'VUL-DESER-002',
    name: 'Insecure Deserialization - PHP unserialize',
    description: 'Detects use of PHP unserialize() with user-controlled data.',
    version: '1.0.0',
    vulnerabilityType: VulnerabilityType.INSECURE_DESERIALIZATION,
    category: VulnerabilityCategory.INJECTION,
    languages: [SupportedLanguage.PHP],
    severity: VulnerabilitySeverity.CRITICAL,
    confidence: ConfidenceLevel.HIGH,
    baseScore: 95,
    patterns: [
      {
        type: PatternType.REGEX,
        patternId: 'deser-php-unserialize',
        pattern: 'unserialize\\s*\\([^)]*\\$_(?:GET|POST|REQUEST|COOKIE)',
        flags: 'gi',
        weight: 1.0,
        description: 'unserialize with superglobal'
      },
      {
        type: PatternType.REGEX,
        patternId: 'deser-php-unserialize-var',
        pattern: 'unserialize\\s*\\(\\s*\\$[a-zA-Z_]',
        flags: 'g',
        weight: 0.80,
        description: 'unserialize with variable'
      }
    ],
    impact: {
      confidentiality: 'high',
      integrity: 'high',
      availability: 'high',
      technicalImpact: 'Object injection leading to RCE via magic methods (__wakeup, __destruct).',
      businessImpact: 'Complete server compromise.'
    },
    exploitability: {
      attackVector: 'network',
      attackComplexity: 'medium',
      privilegesRequired: 'none',
      userInteraction: 'none',
      knownExploits: true
    },
    remediation: {
      summary: 'Never unserialize user data. Use JSON or specify allowed_classes.',
      steps: [
        'Replace unserialize() with json_decode()',
        'If unserialize is required, use allowed_classes option',
        'Remove dangerous magic methods from classes',
        'Validate data structure after deserialization'
      ],
      secureCodeExample: `<?php
// Secure: Use JSON
$data = json_decode($_POST['data'], true);

// If unserialize required, restrict classes
$data = unserialize($serialized, ['allowed_classes' => ['SafeClass']]);

// Best: Avoid deserialization of user input entirely
?>`,
      effort: 'medium',
      priority: 'immediate'
    },
    standards: {
      owasp: [OWASP_TOP_10_2021.A08],
      cwe: [CWE_REFERENCES.CWE_502]
    },
    tags: ['deserialization', 'php', 'object-injection', 'critical'],
    enabled: true
  },
  {
    id: 'VUL-DESER-003',
    name: 'Insecure Deserialization - Java ObjectInputStream',
    description: 'Detects Java ObjectInputStream usage with untrusted data.',
    version: '1.0.0',
    vulnerabilityType: VulnerabilityType.INSECURE_DESERIALIZATION,
    category: VulnerabilityCategory.INJECTION,
    languages: [SupportedLanguage.JAVA],
    severity: VulnerabilitySeverity.CRITICAL,
    confidence: ConfidenceLevel.HIGH,
    baseScore: 95,
    patterns: [
      {
        type: PatternType.REGEX,
        patternId: 'deser-java-ois',
        pattern: 'new\\s+ObjectInputStream\\s*\\([^)]*(?:request|socket|input)',
        flags: 'gi',
        weight: 1.0,
        description: 'ObjectInputStream with external input'
      },
      {
        type: PatternType.REGEX,
        patternId: 'deser-java-readobject',
        pattern: '\\.readObject\\s*\\(',
        flags: 'g',
        weight: 0.70,
        description: 'readObject call'
      },
      {
        type: PatternType.REGEX,
        patternId: 'deser-java-xmldecoder',
        pattern: 'new\\s+XMLDecoder\\s*\\(',
        flags: 'gi',
        weight: 0.95,
        description: 'XMLDecoder usage (dangerous)'
      }
    ],
    impact: {
      confidentiality: 'high',
      integrity: 'high',
      availability: 'high',
      technicalImpact: 'RCE via gadget chains (Commons Collections, etc.).',
      businessImpact: 'Complete system compromise, lateral movement.'
    },
    exploitability: {
      attackVector: 'network',
      attackComplexity: 'low',
      privilegesRequired: 'none',
      userInteraction: 'none',
      knownExploits: true
    },
    remediation: {
      summary: 'Avoid Java serialization. Use JSON with Jackson. If required, use look-ahead deserialization.',
      steps: [
        'Replace Java serialization with JSON (Jackson, Gson)',
        'Use ValidatingObjectInputStream from Apache Commons IO',
        'Remove vulnerable libraries (old Commons Collections)',
        'Implement ObjectInputFilter (Java 9+)'
      ],
      secureCodeExample: `// Secure: Use JSON instead
ObjectMapper mapper = new ObjectMapper();
MyClass obj = mapper.readValue(jsonString, MyClass.class);

// If serialization required, use ObjectInputFilter (Java 9+)
ObjectInputFilter filter = ObjectInputFilter.Config.createFilter(
    "com.myapp.SafeClass;!*"
);
ObjectInputStream ois = new ObjectInputStream(inputStream);
ois.setObjectInputFilter(filter);`,
      effort: 'high',
      priority: 'immediate'
    },
    standards: {
      owasp: [OWASP_TOP_10_2021.A08],
      cwe: [CWE_REFERENCES.CWE_502]
    },
    tags: ['deserialization', 'java', 'rce', 'gadget-chain', 'critical'],
    enabled: true
  },
  {
    id: 'VUL-DESER-004',
    name: 'Insecure Deserialization - Node.js node-serialize',
    description: 'Detects use of dangerous Node.js serialization libraries.',
    version: '1.0.0',
    vulnerabilityType: VulnerabilityType.INSECURE_DESERIALIZATION,
    category: VulnerabilityCategory.INJECTION,
    languages: [SupportedLanguage.JAVASCRIPT, SupportedLanguage.TYPESCRIPT],
    severity: VulnerabilitySeverity.CRITICAL,
    confidence: ConfidenceLevel.HIGH,
    baseScore: 95,
    patterns: [
      {
        type: PatternType.REGEX,
        patternId: 'deser-node-serialize',
        pattern: 'require\\s*\\([\'"]node-serialize[\'"]\\)',
        flags: 'g',
        weight: 0.95,
        description: 'node-serialize import (vulnerable)'
      },
      {
        type: PatternType.REGEX,
        patternId: 'deser-serialize-unserialize',
        pattern: '\\.unserialize\\s*\\([^)]*(?:req\\.|body|cookie)',
        flags: 'gi',
        weight: 1.0,
        description: 'unserialize with user data'
      },
      {
        type: PatternType.REGEX,
        patternId: 'deser-js-yaml-unsafe',
        pattern: 'js-yaml.*\\.load\\s*\\([^)]*(?!\\{[^}]*schema)',
        flags: 'gi',
        weight: 0.85,
        description: 'js-yaml without safe schema'
      }
    ],
    impact: {
      confidentiality: 'high',
      integrity: 'high',
      availability: 'high',
      technicalImpact: 'RCE via IIFE (Immediately Invoked Function Expression) in serialized data.',
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
      summary: 'Remove node-serialize. Use JSON.parse() for data exchange.',
      steps: [
        'Remove node-serialize package',
        'Use native JSON.parse() and JSON.stringify()',
        'Use safe YAML parser with safeLoad',
        'Validate structure after parsing'
      ],
      secureCodeExample: `// Secure: Use native JSON
const data = JSON.parse(req.body.data);

// Validate structure
if (typeof data.name !== 'string' || typeof data.age !== 'number') {
  throw new Error('Invalid data structure');
}

// Safe YAML
const yaml = require('js-yaml');
const data = yaml.load(content, { schema: yaml.SAFE_SCHEMA });`,
      effort: 'low',
      priority: 'immediate'
    },
    standards: {
      owasp: [OWASP_TOP_10_2021.A08],
      cwe: [CWE_REFERENCES.CWE_502]
    },
    tags: ['deserialization', 'nodejs', 'rce', 'critical'],
    enabled: true
  }
];

export default deserializationRules;
