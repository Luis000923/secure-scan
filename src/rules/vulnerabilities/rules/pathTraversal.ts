/**
 * @fileoverview Path Traversal Detection Rules
 * @module rules/vulnerabilities/rules/pathTraversal
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

export const pathTraversalRules: VulnerabilityRule[] = [
  {
    id: 'VUL-PATH-001',
    name: 'Path Traversal - Node.js fs with User Input',
    description: 'Detects file system operations using unsanitized user input.',
    version: '1.0.0',
    vulnerabilityType: VulnerabilityType.PATH_TRAVERSAL,
    category: VulnerabilityCategory.INJECTION,
    languages: [SupportedLanguage.JAVASCRIPT, SupportedLanguage.TYPESCRIPT],
    severity: VulnerabilitySeverity.HIGH,
    confidence: ConfidenceLevel.HIGH,
    baseScore: 80,
    patterns: [
      {
        type: PatternType.REGEX,
        patternId: 'path-fs-req',
        pattern: '(?:fs\\.(?:readFile|writeFile|unlink|readdir|mkdir|rmdir|stat|access)|require\\s*\\()\\s*(?:Sync)?\\s*\\([^)]*(?:req\\.|params\\.|query\\.)',
        flags: 'gi',
        weight: 1.0,
        description: 'fs operation with request data'
      },
      {
        type: PatternType.REGEX,
        patternId: 'path-join-req',
        pattern: 'path\\.(?:join|resolve)\\s*\\([^)]*(?:req\\.|params\\.|query\\.)',
        flags: 'gi',
        weight: 0.85,
        description: 'path.join with user input'
      },
      {
        type: PatternType.REGEX,
        patternId: 'path-traversal-pattern',
        pattern: '(?:\\.\\.\\/|\\.\\.\\.\\\\)',
        flags: 'g',
        weight: 0.70,
        description: 'Literal path traversal pattern'
      }
    ],
    taintAnalysis: {
      sources: ['req.params', 'req.query', 'req.body', 'process.argv'],
      sinks: ['fs.readFile', 'fs.writeFile', 'fs.createReadStream', 'fs.createWriteStream', 'require'],
      sanitizers: ['path.basename', 'path.normalize', '.includes("..")', '.startsWith(allowedDir)']
    },
    impact: {
      confidentiality: 'high',
      integrity: 'medium',
      availability: 'low',
      technicalImpact: 'Read or write arbitrary files on the server.',
      businessImpact: 'Sensitive data exposure, configuration disclosure, code execution via file overwrite.'
    },
    exploitability: {
      attackVector: 'network',
      attackComplexity: 'low',
      privilegesRequired: 'none',
      userInteraction: 'none'
    },
    remediation: {
      summary: 'Validate file paths against allowed directories. Use path.basename() and verify the resolved path.',
      steps: [
        'Use path.basename() to extract filename only',
        'Resolve the full path and verify it starts with allowed directory',
        'Reject paths containing ".." or null bytes',
        'Use chroot or sandboxed file access'
      ],
      secureCodeExample: `const path = require('path');
const fs = require('fs');

const ALLOWED_DIR = '/app/uploads';

function readSafeFile(userPath) {
  const filename = path.basename(userPath);
  const fullPath = path.resolve(ALLOWED_DIR, filename);
  
  // Ensure path is within allowed directory
  if (!fullPath.startsWith(ALLOWED_DIR)) {
    throw new Error('Invalid path');
  }
  
  return fs.readFileSync(fullPath);
}`,
      effort: 'medium',
      priority: 'high'
    },
    standards: {
      owasp: [OWASP_TOP_10_2021.A01],
      cwe: [CWE_REFERENCES.CWE_22]
    },
    tags: ['path-traversal', 'lfi', 'file-access', 'nodejs'],
    enabled: true
  },
  {
    id: 'VUL-PATH-002',
    name: 'Path Traversal - Python open() with User Input',
    description: 'Detects Python file operations with user-controlled paths.',
    version: '1.0.0',
    vulnerabilityType: VulnerabilityType.PATH_TRAVERSAL,
    category: VulnerabilityCategory.INJECTION,
    languages: [SupportedLanguage.PYTHON],
    severity: VulnerabilitySeverity.HIGH,
    confidence: ConfidenceLevel.HIGH,
    baseScore: 80,
    patterns: [
      {
        type: PatternType.REGEX,
        patternId: 'path-python-open',
        pattern: 'open\\s*\\([^)]*(?:request\\.|input\\(|sys\\.argv|f[\'"])',
        flags: 'gi',
        weight: 0.95,
        description: 'open() with user input'
      },
      {
        type: PatternType.REGEX,
        patternId: 'path-python-pathlib',
        pattern: 'Path\\s*\\([^)]*(?:request\\.|input\\()',
        flags: 'gi',
        weight: 0.90,
        description: 'pathlib.Path with user input'
      },
      {
        type: PatternType.REGEX,
        patternId: 'path-python-send-file',
        pattern: 'send_file\\s*\\([^)]*(?:request\\.|\\+)',
        flags: 'gi',
        weight: 1.0,
        description: 'Flask send_file with user input'
      }
    ],
    taintAnalysis: {
      sources: ['request.args', 'request.form', 'request.files', 'sys.argv', 'input()'],
      sinks: ['open(', 'Path(', 'send_file(', 'send_from_directory('],
      sanitizers: ['os.path.basename', 'secure_filename', 'Path.resolve().is_relative_to']
    },
    impact: {
      confidentiality: 'high',
      integrity: 'medium',
      availability: 'low',
      technicalImpact: 'Arbitrary file read/write access.',
      businessImpact: 'Data breach, source code disclosure.'
    },
    exploitability: {
      attackVector: 'network',
      attackComplexity: 'low',
      privilegesRequired: 'none',
      userInteraction: 'none'
    },
    remediation: {
      summary: 'Use os.path.basename() or werkzeug.secure_filename(). Validate resolved paths.',
      steps: [
        'Extract basename from user input',
        'Use secure_filename() for uploads',
        'Verify resolved path is within allowed directory',
        'Use pathlib for safer path operations'
      ],
      secureCodeExample: `from pathlib import Path
from werkzeug.utils import secure_filename

UPLOAD_DIR = Path('/app/uploads')

def read_safe_file(user_path: str) -> bytes:
    filename = secure_filename(user_path)
    full_path = (UPLOAD_DIR / filename).resolve()
    
    if not full_path.is_relative_to(UPLOAD_DIR):
        raise ValueError('Invalid path')
    
    return full_path.read_bytes()`,
      effort: 'low',
      priority: 'high'
    },
    standards: {
      owasp: [OWASP_TOP_10_2021.A01],
      cwe: [CWE_REFERENCES.CWE_22]
    },
    tags: ['path-traversal', 'python', 'file-access'],
    enabled: true
  },
  {
    id: 'VUL-PATH-003',
    name: 'Path Traversal - PHP file_get_contents/include',
    description: 'Detects PHP file operations with user-controlled paths (LFI/RFI).',
    version: '1.0.0',
    vulnerabilityType: VulnerabilityType.PATH_TRAVERSAL,
    category: VulnerabilityCategory.INJECTION,
    languages: [SupportedLanguage.PHP],
    severity: VulnerabilitySeverity.CRITICAL,
    confidence: ConfidenceLevel.HIGH,
    baseScore: 90,
    patterns: [
      {
        type: PatternType.REGEX,
        patternId: 'path-php-include',
        pattern: '(?:include|require)(?:_once)?\\s*\\(?\\s*\\$_(?:GET|POST|REQUEST)',
        flags: 'gi',
        weight: 1.0,
        description: 'include/require with superglobal'
      },
      {
        type: PatternType.REGEX,
        patternId: 'path-php-file-get',
        pattern: 'file_get_contents\\s*\\([^)]*\\$_(?:GET|POST|REQUEST)',
        flags: 'gi',
        weight: 0.95,
        description: 'file_get_contents with user input'
      },
      {
        type: PatternType.REGEX,
        patternId: 'path-php-fopen',
        pattern: 'fopen\\s*\\([^)]*\\$_(?:GET|POST|REQUEST)',
        flags: 'gi',
        weight: 0.95,
        description: 'fopen with user input'
      }
    ],
    impact: {
      confidentiality: 'high',
      integrity: 'high',
      availability: 'medium',
      technicalImpact: 'LFI can lead to RCE via log poisoning or wrapper exploitation. RFI allows direct code execution.',
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
      summary: 'Never include files based on user input. Use allowlist and basename().',
      steps: [
        'Use allowlist of permitted files',
        'Use basename() to strip directory components',
        'Disable allow_url_include in php.ini',
        'Use realpath() and verify prefix'
      ],
      secureCodeExample: `<?php
$allowed_pages = ['home', 'about', 'contact'];
$page = basename($_GET['page'] ?? 'home');

if (!in_array($page, $allowed_pages, true)) {
    $page = 'home';
}

include __DIR__ . '/pages/' . $page . '.php';
?>`,
      effort: 'medium',
      priority: 'immediate'
    },
    standards: {
      owasp: [OWASP_TOP_10_2021.A01, OWASP_TOP_10_2021.A03],
      cwe: [CWE_REFERENCES.CWE_22, CWE_REFERENCES.CWE_98]
    },
    tags: ['path-traversal', 'lfi', 'rfi', 'php', 'critical'],
    enabled: true
  },
  {
    id: 'VUL-PATH-004',
    name: 'Path Traversal - Java File/Path with User Input',
    description: 'Detects Java file operations with user-controlled paths.',
    version: '1.0.0',
    vulnerabilityType: VulnerabilityType.PATH_TRAVERSAL,
    category: VulnerabilityCategory.INJECTION,
    languages: [SupportedLanguage.JAVA],
    severity: VulnerabilitySeverity.HIGH,
    confidence: ConfidenceLevel.HIGH,
    baseScore: 80,
    patterns: [
      {
        type: PatternType.REGEX,
        patternId: 'path-java-new-file',
        pattern: 'new\\s+File\\s*\\([^)]*(?:request\\.getParameter|\\+)',
        flags: 'gi',
        weight: 0.95,
        description: 'new File with user input'
      },
      {
        type: PatternType.REGEX,
        patternId: 'path-java-paths-get',
        pattern: 'Paths\\.get\\s*\\([^)]*(?:request\\.getParameter|\\+)',
        flags: 'gi',
        weight: 0.95,
        description: 'Paths.get with user input'
      },
      {
        type: PatternType.REGEX,
        patternId: 'path-java-fileinputstream',
        pattern: 'new\\s+FileInputStream\\s*\\([^)]*(?:request|\\+)',
        flags: 'gi',
        weight: 0.90,
        description: 'FileInputStream with dynamic path'
      }
    ],
    impact: {
      confidentiality: 'high',
      integrity: 'medium',
      availability: 'low',
      technicalImpact: 'Read or write files outside intended directory.',
      businessImpact: 'Data disclosure, configuration exposure.'
    },
    exploitability: {
      attackVector: 'network',
      attackComplexity: 'low',
      privilegesRequired: 'none',
      userInteraction: 'none'
    },
    remediation: {
      summary: 'Use Path.normalize() and verify canonical path starts with allowed directory.',
      steps: [
        'Normalize the path using Path.normalize()',
        'Get canonical path and verify it starts with base directory',
        'Use FilenameUtils.getName() for basename extraction',
        'Implement file access through a secure abstraction layer'
      ],
      secureCodeExample: `import java.nio.file.Path;
import java.nio.file.Paths;

public class SecureFileAccess {
    private static final Path BASE_DIR = Paths.get("/app/uploads").toAbsolutePath();
    
    public Path resolvePath(String userInput) throws SecurityException {
        Path resolved = BASE_DIR.resolve(userInput).normalize().toAbsolutePath();
        
        if (!resolved.startsWith(BASE_DIR)) {
            throw new SecurityException("Path traversal attempt detected");
        }
        
        return resolved;
    }
}`,
      effort: 'medium',
      priority: 'high'
    },
    standards: {
      owasp: [OWASP_TOP_10_2021.A01],
      cwe: [CWE_REFERENCES.CWE_22]
    },
    tags: ['path-traversal', 'java', 'file-access'],
    enabled: true
  }
];

export default pathTraversalRules;
