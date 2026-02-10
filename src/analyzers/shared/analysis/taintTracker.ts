/**
 * Taint Analysis Module
 * Tracks flow of untrusted data from sources to sinks
 * Core module for detecting injection vulnerabilities
 */

import { Severity, Finding, ThreatType, FindingCategory } from '../../../types';
import { ASTNode, CallInfo, VariableInfo, FunctionInfo } from './astAnalyzer';

/**
 * Taint source - where untrusted data enters the application
 */
export interface TaintSource {
  /** Identifier for this source type */
  id: string;
  /** Human-readable name */
  name: string;
  /** Pattern to match (function call, property access, etc.) */
  patterns: Array<{
    /** Type of pattern */
    type: 'call' | 'property' | 'parameter' | 'variable';
    /** Pattern to match */
    pattern: string | RegExp;
    /** Object the method is called on (for method calls) */
    object?: string | RegExp;
  }>;
  /** Severity when this source reaches a sink */
  severity: Severity;
  /** Description of this source */
  description: string;
}

/**
 * Taint sink - where untrusted data can cause harm
 */
export interface TaintSink {
  /** Identifier for this sink type */
  id: string;
  /** Human-readable name */
  name: string;
  /** Vulnerability category (e.g., 'SQL Injection', 'XSS') */
  category: string;
  /** Patterns to match sink calls/operations */
  patterns: Array<{
    /** Type of pattern */
    type: 'call' | 'property' | 'html' | 'eval';
    /** Pattern to match */
    pattern: string | RegExp;
    /** Object the method is called on */
    object?: string | RegExp;
    /** Which argument indices are vulnerable (0-indexed, -1 for all) */
    vulnerableArgs?: number[];
  }>;
  /** Severity level */
  severity: Severity;
  /** CWE reference */
  cwe: string;
  /** Description of the vulnerability */
  description: string;
  /** Recommendation for fixing */
  recommendation: string;
}

/**
 * Taint sanitizer - functions that make data safe
 */
export interface TaintSanitizer {
  /** Identifier */
  id: string;
  /** Human-readable name */
  name: string;
  /** What vulnerability types this sanitizes */
  sanitizes: string[]; // sink categories
  /** Patterns to match sanitizer calls */
  patterns: Array<{
    type: 'call' | 'property';
    pattern: string | RegExp;
    object?: string | RegExp;
  }>;
}

/**
 * Taint propagation rules
 */
export interface TaintPropagation {
  /** Operation type */
  type: 'assignment' | 'concatenation' | 'call' | 'property' | 'array' | 'object';
  /** Whether taint propagates through this operation */
  propagates: boolean;
  /** Special handling rules */
  rules?: {
    /** Only specific argument positions propagate */
    argPositions?: number[];
    /** Taint is cleared by this operation */
    clears?: boolean;
    /** Taint is transformed (e.g., encoding) */
    transforms?: string;
  };
}

/**
 * Tainted value tracking
 */
export interface TaintedValue {
  /** Variable/expression name */
  name: string;
  /** Source that introduced the taint */
  source: TaintSource;
  /** Line where taint was introduced */
  sourceLine: number;
  /** Current line (for tracking propagation) */
  currentLine: number;
  /** Scope where this value exists */
  scope: string;
  /** Path of propagation (for debugging) */
  propagationPath: Array<{
    line: number;
    operation: string;
    value: string;
  }>;
  /** Whether partially sanitized */
  partiallySanitized: string[];
  /** AST node reference */
  node?: ASTNode;
}

/**
 * Taint finding - when tainted data reaches a sink
 */
export interface TaintFinding {
  /** Source information */
  source: {
    name: string;
    line: number;
    variable: string;
  };
  /** Sink information */
  sink: {
    name: string;
    line: number;
    category: string;
    cwe: string;
  };
  /** Path from source to sink */
  path: Array<{
    line: number;
    code: string;
    operation: string;
  }>;
  /** Severity */
  severity: Severity;
  /** Description */
  description: string;
  /** Recommendation */
  recommendation: string;
}

/**
 * Language-specific taint configuration
 */
export interface TaintConfig {
  /** Language identifier */
  language: string;
  /** Sources for this language */
  sources: TaintSource[];
  /** Sinks for this language */
  sinks: TaintSink[];
  /** Sanitizers for this language */
  sanitizers: TaintSanitizer[];
  /** Custom propagation rules */
  propagation?: TaintPropagation[];
}

/**
 * Default taint sources by language
 */
export const DEFAULT_SOURCES: Record<string, TaintSource[]> = {
  javascript: [
    {
      id: 'js-req-body',
      name: 'Request Body',
      patterns: [
        { type: 'property', pattern: /^req\.body/, object: 'req' },
        { type: 'property', pattern: /^request\.body/, object: 'request' },
      ],
      severity: Severity.HIGH,
      description: 'User input from HTTP request body',
    },
    {
      id: 'js-req-query',
      name: 'Query Parameters',
      patterns: [
        { type: 'property', pattern: /^req\.query/, object: 'req' },
        { type: 'property', pattern: /^req\.params/, object: 'req' },
        { type: 'property', pattern: /^request\.query/, object: 'request' },
      ],
      severity: Severity.HIGH,
      description: 'User input from URL query parameters',
    },
    {
      id: 'js-req-headers',
      name: 'Request Headers',
      patterns: [
        { type: 'property', pattern: /^req\.headers/, object: 'req' },
        { type: 'property', pattern: /^request\.headers/, object: 'request' },
      ],
      severity: Severity.MEDIUM,
      description: 'User-controlled HTTP headers',
    },
    {
      id: 'js-url-params',
      name: 'URL Search Params',
      patterns: [
        { type: 'call', pattern: 'URLSearchParams', object: 'URL' },
        { type: 'property', pattern: /location\.(search|hash|href)/ },
      ],
      severity: Severity.HIGH,
      description: 'URL parameters from browser',
    },
    {
      id: 'js-dom-input',
      name: 'DOM Input',
      patterns: [
        { type: 'property', pattern: /\.value$/, object: /element|input|textarea/i },
        { type: 'property', pattern: /\.innerHTML$/ },
        { type: 'property', pattern: /\.textContent$/ },
      ],
      severity: Severity.HIGH,
      description: 'User input from DOM elements',
    },
    {
      id: 'js-websocket',
      name: 'WebSocket Message',
      patterns: [
        { type: 'parameter', pattern: 'message' },
        { type: 'property', pattern: /\.data$/, object: 'event' },
      ],
      severity: Severity.HIGH,
      description: 'Data received via WebSocket',
    },
  ],

  python: [
    {
      id: 'py-request-args',
      name: 'Request Arguments',
      patterns: [
        { type: 'property', pattern: /^request\.args/ },
        { type: 'property', pattern: /^request\.form/ },
        { type: 'property', pattern: /^request\.data/ },
        { type: 'property', pattern: /^request\.json/ },
        { type: 'call', pattern: 'request.get_json' },
      ],
      severity: Severity.HIGH,
      description: 'Flask request arguments',
    },
    {
      id: 'py-django-request',
      name: 'Django Request',
      patterns: [
        { type: 'property', pattern: /^request\.GET/ },
        { type: 'property', pattern: /^request\.POST/ },
        { type: 'property', pattern: /^request\.body/ },
      ],
      severity: Severity.HIGH,
      description: 'Django request data',
    },
    {
      id: 'py-stdin',
      name: 'Standard Input',
      patterns: [
        { type: 'call', pattern: 'input' },
        { type: 'property', pattern: /^sys\.stdin/ },
        { type: 'call', pattern: 'raw_input' },
      ],
      severity: Severity.MEDIUM,
      description: 'User input from stdin',
    },
    {
      id: 'py-env',
      name: 'Environment Variables',
      patterns: [
        { type: 'property', pattern: /^os\.environ/ },
        { type: 'call', pattern: 'os.getenv' },
      ],
      severity: Severity.LOW,
      description: 'Environment variables',
    },
    {
      id: 'py-argv',
      name: 'Command Arguments',
      patterns: [
        { type: 'property', pattern: /^sys\.argv/ },
      ],
      severity: Severity.MEDIUM,
      description: 'Command line arguments',
    },
  ],

  java: [
    {
      id: 'java-servlet-request',
      name: 'Servlet Request',
      patterns: [
        { type: 'call', pattern: 'getParameter', object: /request|HttpServletRequest/ },
        { type: 'call', pattern: 'getParameterValues', object: /request/ },
        { type: 'call', pattern: 'getQueryString', object: /request/ },
        { type: 'call', pattern: 'getHeader', object: /request/ },
      ],
      severity: Severity.HIGH,
      description: 'HTTP request parameters',
    },
    {
      id: 'java-spring-request',
      name: 'Spring Request',
      patterns: [
        { type: 'parameter', pattern: /@RequestParam/ },
        { type: 'parameter', pattern: /@PathVariable/ },
        { type: 'parameter', pattern: /@RequestBody/ },
        { type: 'parameter', pattern: /@RequestHeader/ },
      ],
      severity: Severity.HIGH,
      description: 'Spring MVC request binding',
    },
    {
      id: 'java-stdin',
      name: 'Standard Input',
      patterns: [
        { type: 'call', pattern: 'readLine', object: /BufferedReader|Scanner/ },
        { type: 'call', pattern: 'next', object: /Scanner/ },
      ],
      severity: Severity.MEDIUM,
      description: 'User input from stdin',
    },
  ],

  php: [
    {
      id: 'php-superglobals',
      name: 'PHP Superglobals',
      patterns: [
        { type: 'variable', pattern: /^\$_GET/ },
        { type: 'variable', pattern: /^\$_POST/ },
        { type: 'variable', pattern: /^\$_REQUEST/ },
        { type: 'variable', pattern: /^\$_COOKIE/ },
        { type: 'variable', pattern: /^\$_SERVER/ },
        { type: 'variable', pattern: /^\$_FILES/ },
      ],
      severity: Severity.HIGH,
      description: 'PHP superglobal variables',
    },
    {
      id: 'php-input',
      name: 'PHP Input',
      patterns: [
        { type: 'call', pattern: 'file_get_contents', object: 'php://input' },
        { type: 'call', pattern: 'fgets', object: 'STDIN' },
      ],
      severity: Severity.HIGH,
      description: 'PHP raw input',
    },
  ],

  csharp: [
    {
      id: 'cs-request',
      name: 'ASP.NET Request',
      patterns: [
        { type: 'property', pattern: /^Request\.QueryString/ },
        { type: 'property', pattern: /^Request\.Form/ },
        { type: 'property', pattern: /^Request\.Headers/ },
        { type: 'property', pattern: /^Request\.Cookies/ },
      ],
      severity: Severity.HIGH,
      description: 'ASP.NET request data',
    },
    {
      id: 'cs-mvc',
      name: 'ASP.NET MVC',
      patterns: [
        { type: 'parameter', pattern: /\[FromQuery\]/ },
        { type: 'parameter', pattern: /\[FromBody\]/ },
        { type: 'parameter', pattern: /\[FromForm\]/ },
        { type: 'parameter', pattern: /\[FromRoute\]/ },
      ],
      severity: Severity.HIGH,
      description: 'ASP.NET MVC model binding',
    },
  ],
};

/**
 * Default taint sinks by language
 */
export const DEFAULT_SINKS: Record<string, TaintSink[]> = {
  javascript: [
    {
      id: 'js-sql',
      name: 'SQL Query',
      category: 'SQL Injection',
      patterns: [
        { type: 'call', pattern: 'query', object: /mysql|pg|pool|connection|db/, vulnerableArgs: [0] },
        { type: 'call', pattern: 'execute', object: /connection|db/, vulnerableArgs: [0] },
        { type: 'call', pattern: 'raw', object: /knex|sequelize/, vulnerableArgs: [0] },
      ],
      severity: Severity.CRITICAL,
      cwe: 'CWE-89',
      description: 'SQL query execution with user input',
      recommendation: 'Use parameterized queries or prepared statements',
    },
    {
      id: 'js-eval',
      name: 'Code Evaluation',
      category: 'Code Injection',
      patterns: [
        { type: 'eval', pattern: 'eval', vulnerableArgs: [0] },
        { type: 'call', pattern: 'Function', vulnerableArgs: [-1] },
        { type: 'call', pattern: 'setTimeout', vulnerableArgs: [0] },
        { type: 'call', pattern: 'setInterval', vulnerableArgs: [0] },
      ],
      severity: Severity.CRITICAL,
      cwe: 'CWE-94',
      description: 'Dynamic code evaluation with user input',
      recommendation: 'Avoid eval() and dynamic code execution',
    },
    {
      id: 'js-xss',
      name: 'XSS Sink',
      category: 'XSS',
      patterns: [
        { type: 'property', pattern: 'innerHTML' },
        { type: 'property', pattern: 'outerHTML' },
        { type: 'call', pattern: 'write', object: 'document' },
        { type: 'call', pattern: 'writeln', object: 'document' },
        { type: 'call', pattern: 'html', object: /\$|\jQuery/ },
      ],
      severity: Severity.HIGH,
      cwe: 'CWE-79',
      description: 'HTML injection enabling XSS',
      recommendation: 'Use textContent or proper HTML encoding',
    },
    {
      id: 'js-cmd',
      name: 'Command Execution',
      category: 'Command Injection',
      patterns: [
        { type: 'call', pattern: 'exec', object: 'child_process', vulnerableArgs: [0] },
        { type: 'call', pattern: 'execSync', object: 'child_process', vulnerableArgs: [0] },
        { type: 'call', pattern: 'spawn', object: 'child_process', vulnerableArgs: [0, 1] },
      ],
      severity: Severity.CRITICAL,
      cwe: 'CWE-78',
      description: 'OS command execution with user input',
      recommendation: 'Use spawn with argument array, avoid shell: true',
    },
    {
      id: 'js-path',
      name: 'Path Traversal',
      category: 'Path Traversal',
      patterns: [
        { type: 'call', pattern: 'readFile', object: 'fs', vulnerableArgs: [0] },
        { type: 'call', pattern: 'readFileSync', object: 'fs', vulnerableArgs: [0] },
        { type: 'call', pattern: 'writeFile', object: 'fs', vulnerableArgs: [0] },
        { type: 'call', pattern: 'unlink', object: 'fs', vulnerableArgs: [0] },
      ],
      severity: Severity.HIGH,
      cwe: 'CWE-22',
      description: 'File operation with user-controlled path',
      recommendation: 'Validate and sanitize file paths, use path.resolve',
    },
  ],

  python: [
    {
      id: 'py-sql',
      name: 'SQL Query',
      category: 'SQL Injection',
      patterns: [
        { type: 'call', pattern: 'execute', object: /cursor|connection/, vulnerableArgs: [0] },
        { type: 'call', pattern: 'raw', object: /RawSQL|connection/, vulnerableArgs: [0] },
        { type: 'call', pattern: 'text', object: /sqlalchemy/, vulnerableArgs: [0] },
      ],
      severity: Severity.CRITICAL,
      cwe: 'CWE-89',
      description: 'SQL query with user input',
      recommendation: 'Use parameterized queries with placeholders',
    },
    {
      id: 'py-eval',
      name: 'Code Evaluation',
      category: 'Code Injection',
      patterns: [
        { type: 'call', pattern: 'eval', vulnerableArgs: [0] },
        { type: 'call', pattern: 'exec', vulnerableArgs: [0] },
        { type: 'call', pattern: 'compile', vulnerableArgs: [0] },
      ],
      severity: Severity.CRITICAL,
      cwe: 'CWE-94',
      description: 'Dynamic code execution',
      recommendation: 'Avoid eval/exec, use ast.literal_eval for data',
    },
    {
      id: 'py-cmd',
      name: 'Command Execution',
      category: 'Command Injection',
      patterns: [
        { type: 'call', pattern: 'system', object: 'os', vulnerableArgs: [0] },
        { type: 'call', pattern: 'popen', object: 'os', vulnerableArgs: [0] },
        { type: 'call', pattern: 'call', object: 'subprocess', vulnerableArgs: [0] },
        { type: 'call', pattern: 'run', object: 'subprocess', vulnerableArgs: [0] },
        { type: 'call', pattern: 'Popen', object: 'subprocess', vulnerableArgs: [0] },
      ],
      severity: Severity.CRITICAL,
      cwe: 'CWE-78',
      description: 'Command execution with user input',
      recommendation: 'Use subprocess with list args, shell=False',
    },
    {
      id: 'py-ssti',
      name: 'Template Injection',
      category: 'SSTI',
      patterns: [
        { type: 'call', pattern: 'render_template_string', vulnerableArgs: [0] },
        { type: 'call', pattern: 'Template', object: 'jinja2', vulnerableArgs: [0] },
        { type: 'call', pattern: 'from_string', object: /Template|Environment/, vulnerableArgs: [0] },
      ],
      severity: Severity.CRITICAL,
      cwe: 'CWE-1336',
      description: 'Template rendered with user input',
      recommendation: 'Use render_template with separate template files',
    },
  ],

  java: [
    {
      id: 'java-sql',
      name: 'SQL Query',
      category: 'SQL Injection',
      patterns: [
        { type: 'call', pattern: 'executeQuery', object: /Statement/, vulnerableArgs: [0] },
        { type: 'call', pattern: 'executeUpdate', object: /Statement/, vulnerableArgs: [0] },
        { type: 'call', pattern: 'createQuery', object: /EntityManager/, vulnerableArgs: [0] },
        { type: 'call', pattern: 'createNativeQuery', object: /EntityManager/, vulnerableArgs: [0] },
      ],
      severity: Severity.CRITICAL,
      cwe: 'CWE-89',
      description: 'SQL query with user input',
      recommendation: 'Use PreparedStatement with parameterized queries',
    },
    {
      id: 'java-cmd',
      name: 'Command Execution',
      category: 'Command Injection',
      patterns: [
        { type: 'call', pattern: 'exec', object: 'Runtime', vulnerableArgs: [0] },
        { type: 'call', pattern: 'command', object: 'ProcessBuilder', vulnerableArgs: [0] },
      ],
      severity: Severity.CRITICAL,
      cwe: 'CWE-78',
      description: 'Command execution with user input',
      recommendation: 'Use ProcessBuilder with argument list',
    },
    {
      id: 'java-jndi',
      name: 'JNDI Lookup',
      category: 'JNDI Injection',
      patterns: [
        { type: 'call', pattern: 'lookup', object: /Context|InitialContext/, vulnerableArgs: [0] },
      ],
      severity: Severity.CRITICAL,
      cwe: 'CWE-917',
      description: 'JNDI lookup with user input (Log4Shell vector)',
      recommendation: 'Never pass user input to JNDI lookup',
    },
  ],

  php: [
    {
      id: 'php-sql',
      name: 'SQL Query',
      category: 'SQL Injection',
      patterns: [
        { type: 'call', pattern: 'mysql_query', vulnerableArgs: [0] },
        { type: 'call', pattern: 'mysqli_query', vulnerableArgs: [1] },
        { type: 'call', pattern: 'query', object: /mysqli|PDO/, vulnerableArgs: [0] },
      ],
      severity: Severity.CRITICAL,
      cwe: 'CWE-89',
      description: 'SQL query with user input',
      recommendation: 'Use prepared statements with bound parameters',
    },
    {
      id: 'php-eval',
      name: 'Code Evaluation',
      category: 'Code Injection',
      patterns: [
        { type: 'call', pattern: 'eval', vulnerableArgs: [0] },
        { type: 'call', pattern: 'assert', vulnerableArgs: [0] },
        { type: 'call', pattern: 'create_function', vulnerableArgs: [1] },
        { type: 'call', pattern: 'preg_replace', vulnerableArgs: [1] }, // with /e modifier
      ],
      severity: Severity.CRITICAL,
      cwe: 'CWE-94',
      description: 'Dynamic code execution',
      recommendation: 'Avoid eval and assert with user input',
    },
    {
      id: 'php-cmd',
      name: 'Command Execution',
      category: 'Command Injection',
      patterns: [
        { type: 'call', pattern: 'exec', vulnerableArgs: [0] },
        { type: 'call', pattern: 'system', vulnerableArgs: [0] },
        { type: 'call', pattern: 'passthru', vulnerableArgs: [0] },
        { type: 'call', pattern: 'shell_exec', vulnerableArgs: [0] },
        { type: 'call', pattern: 'popen', vulnerableArgs: [0] },
        { type: 'call', pattern: 'proc_open', vulnerableArgs: [0] },
      ],
      severity: Severity.CRITICAL,
      cwe: 'CWE-78',
      description: 'Command execution with user input',
      recommendation: 'Use escapeshellarg/escapeshellcmd',
    },
    {
      id: 'php-include',
      name: 'File Inclusion',
      category: 'File Inclusion',
      patterns: [
        { type: 'call', pattern: 'include', vulnerableArgs: [0] },
        { type: 'call', pattern: 'include_once', vulnerableArgs: [0] },
        { type: 'call', pattern: 'require', vulnerableArgs: [0] },
        { type: 'call', pattern: 'require_once', vulnerableArgs: [0] },
      ],
      severity: Severity.CRITICAL,
      cwe: 'CWE-98',
      description: 'File inclusion with user input',
      recommendation: 'Validate against whitelist of allowed files',
    },
  ],

  csharp: [
    {
      id: 'cs-sql',
      name: 'SQL Query',
      category: 'SQL Injection',
      patterns: [
        { type: 'call', pattern: 'ExecuteReader', object: /SqlCommand/, vulnerableArgs: [-1] },
        { type: 'call', pattern: 'ExecuteNonQuery', object: /SqlCommand/, vulnerableArgs: [-1] },
        { type: 'call', pattern: 'ExecuteSqlRaw', object: /DbContext/, vulnerableArgs: [0] },
        { type: 'call', pattern: 'FromSqlRaw', vulnerableArgs: [0] },
      ],
      severity: Severity.CRITICAL,
      cwe: 'CWE-89',
      description: 'SQL query with user input',
      recommendation: 'Use SqlParameter for parameterized queries',
    },
    {
      id: 'cs-cmd',
      name: 'Command Execution',
      category: 'Command Injection',
      patterns: [
        { type: 'call', pattern: 'Start', object: 'Process', vulnerableArgs: [0] },
      ],
      severity: Severity.CRITICAL,
      cwe: 'CWE-78',
      description: 'Process execution with user input',
      recommendation: 'Validate and sanitize arguments, avoid UseShellExecute',
    },
  ],
};

/**
 * Default sanitizers by language
 */
export const DEFAULT_SANITIZERS: Record<string, TaintSanitizer[]> = {
  javascript: [
    {
      id: 'js-escape-html',
      name: 'HTML Escape',
      sanitizes: ['XSS'],
      patterns: [
        { type: 'call', pattern: 'escapeHtml' },
        { type: 'call', pattern: 'escape', object: /lodash|_|he/ },
        { type: 'call', pattern: 'encode', object: 'he' },
        { type: 'call', pattern: 'sanitize', object: /DOMPurify|sanitizeHtml/ },
      ],
    },
    {
      id: 'js-parameterized',
      name: 'Parameterized Query',
      sanitizes: ['SQL Injection'],
      patterns: [
        { type: 'call', pattern: 'prepare' },
        { type: 'call', pattern: 'query', object: /\$\d/ }, // Placeholder pattern
      ],
    },
  ],

  python: [
    {
      id: 'py-escape-html',
      name: 'HTML Escape',
      sanitizes: ['XSS'],
      patterns: [
        { type: 'call', pattern: 'escape', object: /html|markupsafe/ },
        { type: 'call', pattern: 'Markup' },
      ],
    },
    {
      id: 'py-shlex',
      name: 'Shell Escape',
      sanitizes: ['Command Injection'],
      patterns: [
        { type: 'call', pattern: 'quote', object: 'shlex' },
        { type: 'call', pattern: 'split', object: 'shlex' },
      ],
    },
  ],

  php: [
    {
      id: 'php-escape',
      name: 'HTML Escape',
      sanitizes: ['XSS'],
      patterns: [
        { type: 'call', pattern: 'htmlspecialchars' },
        { type: 'call', pattern: 'htmlentities' },
        { type: 'call', pattern: 'strip_tags' },
      ],
    },
    {
      id: 'php-sql-escape',
      name: 'SQL Escape',
      sanitizes: ['SQL Injection'],
      patterns: [
        { type: 'call', pattern: 'mysqli_real_escape_string' },
        { type: 'call', pattern: 'real_escape_string', object: 'mysqli' },
        { type: 'call', pattern: 'quote', object: 'PDO' },
      ],
    },
    {
      id: 'php-shell-escape',
      name: 'Shell Escape',
      sanitizes: ['Command Injection'],
      patterns: [
        { type: 'call', pattern: 'escapeshellarg' },
        { type: 'call', pattern: 'escapeshellcmd' },
      ],
    },
  ],

  java: [
    {
      id: 'java-prepared',
      name: 'Prepared Statement',
      sanitizes: ['SQL Injection'],
      patterns: [
        { type: 'call', pattern: 'prepareStatement' },
        { type: 'call', pattern: 'setParameter', object: /Query/ },
      ],
    },
    {
      id: 'java-esapi',
      name: 'ESAPI Encoder',
      sanitizes: ['XSS', 'SQL Injection', 'Command Injection'],
      patterns: [
        { type: 'call', pattern: 'encodeForHTML', object: 'ESAPI' },
        { type: 'call', pattern: 'encodeForSQL', object: 'ESAPI' },
        { type: 'call', pattern: 'encodeForOS', object: 'ESAPI' },
      ],
    },
  ],

  csharp: [
    {
      id: 'cs-encode',
      name: 'HTML Encode',
      sanitizes: ['XSS'],
      patterns: [
        { type: 'call', pattern: 'HtmlEncode', object: /HttpUtility|WebUtility|HtmlEncoder/ },
        { type: 'call', pattern: 'Encode', object: 'AntiXss' },
      ],
    },
    {
      id: 'cs-param',
      name: 'SQL Parameter',
      sanitizes: ['SQL Injection'],
      patterns: [
        { type: 'call', pattern: 'Add', object: 'Parameters' },
        { type: 'call', pattern: 'AddWithValue', object: 'Parameters' },
      ],
    },
  ],
};

/**
 * Main TaintTracker class
 */
export class TaintTracker {
  private sources: TaintSource[];
  private sinks: TaintSink[];
  private sanitizers: TaintSanitizer[];
  private taintedValues: Map<string, TaintedValue> = new Map();
  private findings: TaintFinding[] = [];

  constructor(config: TaintConfig) {
    this.sources = config.sources;
    this.sinks = config.sinks;
    this.sanitizers = config.sanitizers;
  }

  /**
   * Create a TaintTracker with default configuration for a language
   */
  static forLanguage(language: string): TaintTracker {
    return new TaintTracker({
      language,
      sources: DEFAULT_SOURCES[language] || [],
      sinks: DEFAULT_SINKS[language] || [],
      sanitizers: DEFAULT_SANITIZERS[language] || [],
    });
  }

  /**
   * Check if an expression matches a source pattern
   */
  isSource(expression: string): TaintSource | null {
    for (const source of this.sources) {
      for (const pattern of source.patterns) {
        if (this.matchesPattern(expression, pattern)) {
          return source;
        }
      }
    }
    return null;
  }

  /**
   * Check if an expression matches a sink pattern
   */
  isSink(expression: string): TaintSink | null {
    for (const sink of this.sinks) {
      for (const pattern of sink.patterns) {
        if (this.matchesPattern(expression, pattern)) {
          return sink;
        }
      }
    }
    return null;
  }

  /**
   * Check if an expression is a sanitizer
   */
  isSanitizer(expression: string, category: string): TaintSanitizer | null {
    for (const sanitizer of this.sanitizers) {
      if (!sanitizer.sanitizes.includes(category)) continue;
      
      for (const pattern of sanitizer.patterns) {
        if (this.matchesPattern(expression, pattern)) {
          return sanitizer;
        }
      }
    }
    return null;
  }

  /**
   * Track a new tainted value
   */
  trackTaint(variable: string, source: TaintSource, line: number, scope: string): void {
    this.taintedValues.set(`${scope}:${variable}`, {
      name: variable,
      source,
      sourceLine: line,
      currentLine: line,
      scope,
      propagationPath: [{ line, operation: 'source', value: variable }],
      partiallySanitized: [],
    });
  }

  /**
   * Check if a variable is tainted
   */
  isTainted(variable: string, scope: string): TaintedValue | null {
    // Check current scope
    const taint = this.taintedValues.get(`${scope}:${variable}`);
    if (taint) return taint;
    
    // Check global scope
    return this.taintedValues.get(`global:${variable}`) || null;
  }

  /**
   * Propagate taint through an assignment
   */
  propagateTaint(
    fromVar: string,
    toVar: string,
    line: number,
    scope: string,
    operation: string
  ): void {
    const sourceTaint = this.isTainted(fromVar, scope);
    if (!sourceTaint) return;

    const newTaint: TaintedValue = {
      ...sourceTaint,
      name: toVar,
      currentLine: line,
      propagationPath: [
        ...sourceTaint.propagationPath,
        { line, operation, value: `${fromVar} -> ${toVar}` },
      ],
    };

    this.taintedValues.set(`${scope}:${toVar}`, newTaint);
  }

  /**
   * Apply sanitization
   */
  sanitize(variable: string, scope: string, category: string): void {
    const taint = this.isTainted(variable, scope);
    if (!taint) return;

    taint.partiallySanitized.push(category);
    
    // If fully sanitized, remove taint
    // (simplified: would need to track which categories are still dangerous)
  }

  /**
   * Check if tainted data reaches a sink
   */
  checkSink(
    expression: string,
    arguments_: string[],
    line: number,
    scope: string
  ): TaintFinding | null {
    const sink = this.isSink(expression);
    if (!sink) return null;

    // Check arguments for taint
    for (let i = 0; i < arguments_.length; i++) {
      const arg = arguments_[i];
      const taint = this.isTainted(arg, scope);
      
      if (taint && !taint.partiallySanitized.includes(sink.category)) {
        const finding: TaintFinding = {
          source: {
            name: taint.source.name,
            line: taint.sourceLine,
            variable: taint.name,
          },
          sink: {
            name: sink.name,
            line,
            category: sink.category,
            cwe: sink.cwe,
          },
          path: taint.propagationPath.map(p => ({
            line: p.line,
            code: p.value,
            operation: p.operation,
          })),
          severity: sink.severity,
          description: sink.description,
          recommendation: sink.recommendation,
        };
        
        this.findings.push(finding);
        return finding;
      }
    }

    return null;
  }

  /**
   * Get all findings
   */
  getFindings(): TaintFinding[] {
    return [...this.findings];
  }

  /**
   * Clear all tracked state
   */
  reset(): void {
    this.taintedValues.clear();
    this.findings = [];
  }

  /**
   * Helper to match patterns
   */
  private matchesPattern(
    expression: string,
    pattern: { pattern: string | RegExp; type: string; object?: string | RegExp }
  ): boolean {
    const pat = pattern.pattern;
    
    if (pat instanceof RegExp) {
      return pat.test(expression);
    }
    
    return expression.includes(pat) || expression === pat;
  }
}

/**
 * Convert taint findings to standard Finding format
 */
export function taintFindingsToFindings(
  taintFindings: TaintFinding[],
  filePath: string,
  content: string,
  analyzerName: string = 'TaintTracker'
): Finding[] {
  return taintFindings.map(tf => {
    const lines = content.split('\n');
    const codeLine = lines[tf.sink.line - 1] || '';
    
    // Map category to ThreatType
    const threatTypeMap: Record<string, ThreatType> = {
      'SQL Injection': ThreatType.SQL_INJECTION,
      'Command Injection': ThreatType.COMMAND_INJECTION,
      'Path Traversal': ThreatType.PATH_TRAVERSAL,
      'XSS': ThreatType.XSS,
      'LDAP Injection': ThreatType.LDAP_INJECTION,
      'Insecure Deserialization': ThreatType.INSECURE_DESERIALIZATION,
      'SSTI': ThreatType.INJECTION,
      'JNDI Injection': ThreatType.INJECTION,
    };
    
    return {
      id: `taint-${tf.sink.cwe}-${tf.sink.line}`,
      ruleId: `TAINT-${tf.sink.cwe}`,
      title: `${tf.sink.category}: Tainted data reaches dangerous sink`,
      description: tf.description,
      severity: tf.severity,
      threatType: threatTypeMap[tf.sink.category] || ThreatType.INJECTION,
      category: FindingCategory.VULNERABILITY,
      location: {
        file: filePath,
        startLine: tf.sink.line,
        endLine: tf.sink.line,
        startColumn: 1,
        endColumn: codeLine.length,
      },
      snippet: {
        code: codeLine.trim(),
        contextBefore: lines[tf.sink.line - 2] || '',
        contextAfter: lines[tf.sink.line] || '',
      },
      standards: [
        {
          name: 'CWE',
          id: tf.sink.cwe,
          title: tf.sink.category,
          description: tf.description,
          url: `https://cwe.mitre.org/data/definitions/${tf.sink.cwe.replace('CWE-', '')}.html`,
        },
      ],
      remediation: tf.recommendation,
      confidence: 85,
      analyzer: analyzerName,
      timestamp: new Date(),
      tags: ['taint-analysis', tf.sink.category.toLowerCase().replace(/\s+/g, '-'), 'data-flow'],
    };
  });
}
