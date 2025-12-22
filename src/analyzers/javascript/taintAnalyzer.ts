/**
 * Taint Analysis Module for JavaScript/TypeScript
 * Tracks data flow from untrusted sources to dangerous sinks
 * 
 * Inspired by CodeQL's taint tracking methodology
 */

import { SourceLocation, Severity, ThreatType, FindingCategory, SecurityStandard } from '../../types';
import { getStandardsForThreat } from '../../rules/standards';

/**
 * Represents a taint source - where untrusted data enters
 */
export interface TaintSource {
  /** Source type identifier */
  type: string;
  /** Pattern to match the source */
  pattern: RegExp;
  /** Description of the source */
  description: string;
  /** Variable capture group index in regex */
  captureGroup?: number;
  /** Context hints for better detection */
  contextHints?: string[];
}

/**
 * Represents a taint sink - dangerous operations
 */
export interface TaintSink {
  /** Sink type identifier */
  type: string;
  /** Pattern to match the sink */
  pattern: RegExp;
  /** Threat type this sink can cause */
  threatType: ThreatType;
  /** Severity level */
  severity: Severity;
  /** Description of the vulnerability */
  description: string;
  /** CWE/OWASP references */
  standards?: SecurityStandard[];
  /** Remediation advice */
  remediation: string;
}

/**
 * Represents a taint flow from source to sink
 */
export interface TaintFlow {
  /** The source of tainted data */
  source: {
    type: string;
    variable: string;
    line: number;
    code: string;
  };
  /** The sink where tainted data is used */
  sink: {
    type: string;
    line: number;
    code: string;
    threatType: ThreatType;
    severity: Severity;
  };
  /** Intermediate steps (if any) */
  propagation: {
    variable: string;
    line: number;
    code: string;
  }[];
  /** Confidence score 0-100 */
  confidence: number;
}

/**
 * Taint sources - entry points for untrusted data
 */
export const TAINT_SOURCES: TaintSource[] = [
  // Express/Node.js request data
  {
    type: 'request_body',
    pattern: /\breq(?:uest)?\.body(?:\[['"`](\w+)['"`]\]|\.(\w+))?/g,
    description: 'User input from request body',
    contextHints: ['express', 'http', 'request']
  },
  {
    type: 'request_query',
    pattern: /\breq(?:uest)?\.query(?:\[['"`](\w+)['"`]\]|\.(\w+))?/g,
    description: 'User input from query string',
    contextHints: ['express', 'http', 'request']
  },
  {
    type: 'request_params',
    pattern: /\breq(?:uest)?\.params(?:\[['"`](\w+)['"`]\]|\.(\w+))?/g,
    description: 'User input from URL parameters',
    contextHints: ['express', 'http', 'request']
  },
  {
    type: 'request_headers',
    pattern: /\breq(?:uest)?\.headers(?:\[['"`](\w+)['"`]\]|\.(\w+))?/g,
    description: 'User-controlled HTTP headers',
    contextHints: ['express', 'http', 'request']
  },
  {
    type: 'request_cookies',
    pattern: /\breq(?:uest)?\.cookies(?:\[['"`](\w+)['"`]\]|\.(\w+))?/g,
    description: 'User-controlled cookies',
    contextHints: ['express', 'cookie']
  },
  // Browser APIs
  {
    type: 'url_location',
    pattern: /\b(?:window\.)?location\.(?:href|search|hash|pathname)/g,
    description: 'Browser URL location (user-controllable)',
    contextHints: ['browser', 'window', 'document']
  },
  {
    type: 'document_url',
    pattern: /\bdocument\.(?:URL|documentURI|referrer)/g,
    description: 'Document URL properties',
    contextHints: ['browser', 'document']
  },
  {
    type: 'url_search_params',
    pattern: /new\s+URLSearchParams\s*\([^)]*\)\.get\s*\(/g,
    description: 'URL search parameters',
    contextHints: ['browser', 'URL']
  },
  {
    type: 'local_storage',
    pattern: /\b(?:localStorage|sessionStorage)\.getItem\s*\(['"`](\w+)['"`]\)/g,
    description: 'Browser storage (potentially attacker-controlled)',
    contextHints: ['browser', 'storage']
  },
  {
    type: 'post_message',
    pattern: /\bevent\.data\b|\bmessage\.data\b/g,
    description: 'PostMessage data (cross-origin)',
    contextHints: ['postMessage', 'addEventListener', 'message']
  },
  // Environment variables
  {
    type: 'env_variable',
    pattern: /\bprocess\.env(?:\[['"`](\w+)['"`]\]|\.(\w+))/g,
    description: 'Environment variable (may contain sensitive data)',
    contextHints: ['node', 'process', 'env']
  },
  // Form data
  {
    type: 'form_data',
    pattern: /\b(?:formData|form)\.get\s*\(['"`](\w+)['"`]\)/g,
    description: 'Form input data',
    contextHints: ['form', 'FormData']
  },
  // File uploads
  {
    type: 'file_upload',
    pattern: /\breq(?:uest)?\.files?(?:\[['"`](\w+)['"`]\]|\.(\w+))?/g,
    description: 'Uploaded file data',
    contextHints: ['multer', 'upload', 'file']
  }
];

/**
 * Taint sinks - dangerous operations
 */
export const TAINT_SINKS: TaintSink[] = [
  // Code Execution (RCE)
  {
    type: 'eval',
    pattern: /\beval\s*\(/g,
    threatType: ThreatType.COMMAND_INJECTION,
    severity: Severity.CRITICAL,
    description: 'Direct code execution via eval()',
    remediation: 'Never use eval() with user input. Use safer alternatives like JSON.parse() for data.'
  },
  {
    type: 'function_constructor',
    pattern: /\bnew\s+Function\s*\(/g,
    threatType: ThreatType.COMMAND_INJECTION,
    severity: Severity.CRITICAL,
    description: 'Dynamic function creation (equivalent to eval)',
    remediation: 'Avoid new Function() with dynamic input. Use predefined functions instead.'
  },
  {
    type: 'setTimeout_string',
    pattern: /\bsetTimeout\s*\(\s*['"`]/g,
    threatType: ThreatType.COMMAND_INJECTION,
    severity: Severity.HIGH,
    description: 'setTimeout with string argument (eval-like)',
    remediation: 'Pass a function reference to setTimeout instead of a string.'
  },
  {
    type: 'setInterval_string',
    pattern: /\bsetInterval\s*\(\s*['"`]/g,
    threatType: ThreatType.COMMAND_INJECTION,
    severity: Severity.HIGH,
    description: 'setInterval with string argument (eval-like)',
    remediation: 'Pass a function reference to setInterval instead of a string.'
  },
  // Command Injection (OS)
  {
    type: 'child_process_exec',
    pattern: /\b(?:child_process\.)?exec\s*\(/g,
    threatType: ThreatType.COMMAND_INJECTION,
    severity: Severity.CRITICAL,
    description: 'OS command execution via exec()',
    remediation: 'Use execFile() with argument arrays instead of exec(). Validate and sanitize all inputs.'
  },
  {
    type: 'child_process_spawn_shell',
    pattern: /\bspawn\s*\([^)]+,\s*\{[^}]*shell\s*:\s*true/g,
    threatType: ThreatType.COMMAND_INJECTION,
    severity: Severity.CRITICAL,
    description: 'spawn() with shell option (vulnerable to injection)',
    remediation: 'Avoid shell: true in spawn(). Pass arguments as an array.'
  },
  {
    type: 'exec_sync',
    pattern: /\b(?:execSync|spawnSync)\s*\(/g,
    threatType: ThreatType.COMMAND_INJECTION,
    severity: Severity.CRITICAL,
    description: 'Synchronous command execution',
    remediation: 'Use execFileSync() with argument arrays. Never pass user input directly.'
  },
  // XSS Sinks
  {
    type: 'innerHTML',
    pattern: /\.innerHTML\s*=/g,
    threatType: ThreatType.XSS,
    severity: Severity.HIGH,
    description: 'DOM XSS via innerHTML assignment',
    remediation: 'Use textContent for text, or sanitize HTML with DOMPurify before innerHTML.'
  },
  {
    type: 'outerHTML',
    pattern: /\.outerHTML\s*=/g,
    threatType: ThreatType.XSS,
    severity: Severity.HIGH,
    description: 'DOM XSS via outerHTML assignment',
    remediation: 'Use textContent for text, or sanitize HTML with DOMPurify.'
  },
  {
    type: 'document_write',
    pattern: /\bdocument\.(?:write|writeln)\s*\(/g,
    threatType: ThreatType.XSS,
    severity: Severity.HIGH,
    description: 'DOM XSS via document.write()',
    remediation: 'Avoid document.write(). Use DOM methods like createElement() and textContent.'
  },
  {
    type: 'insertAdjacentHTML',
    pattern: /\.insertAdjacentHTML\s*\(/g,
    threatType: ThreatType.XSS,
    severity: Severity.HIGH,
    description: 'DOM XSS via insertAdjacentHTML()',
    remediation: 'Sanitize HTML content with DOMPurify before insertion.'
  },
  {
    type: 'jquery_html',
    pattern: /\$\([^)]+\)\.html\s*\(/g,
    threatType: ThreatType.XSS,
    severity: Severity.HIGH,
    description: 'DOM XSS via jQuery .html()',
    remediation: 'Use .text() for plain text, or sanitize with DOMPurify before .html().'
  },
  {
    type: 'jquery_append',
    pattern: /\$\([^)]+\)\.(?:append|prepend|after|before)\s*\(/g,
    threatType: ThreatType.XSS,
    severity: Severity.MEDIUM,
    description: 'Potential DOM XSS via jQuery DOM manipulation',
    remediation: 'Ensure HTML content is sanitized before DOM insertion.'
  },
  // SSRF Sinks
  {
    type: 'fetch',
    pattern: /\bfetch\s*\(/g,
    threatType: ThreatType.SECURITY_MISCONFIGURATION,
    severity: Severity.HIGH,
    description: 'Potential SSRF via fetch() with user-controlled URL',
    remediation: 'Validate and whitelist URLs before making requests. Block internal IP ranges.'
  },
  {
    type: 'axios_request',
    pattern: /\baxios(?:\.(?:get|post|put|delete|patch|request))?\s*\(/g,
    threatType: ThreatType.SECURITY_MISCONFIGURATION,
    severity: Severity.HIGH,
    description: 'Potential SSRF via axios with user-controlled URL',
    remediation: 'Validate and whitelist URLs before making requests.'
  },
  {
    type: 'http_request',
    pattern: /\b(?:http|https)\.(?:get|request)\s*\(/g,
    threatType: ThreatType.SECURITY_MISCONFIGURATION,
    severity: Severity.HIGH,
    description: 'Potential SSRF via Node.js HTTP module',
    remediation: 'Validate and whitelist URLs. Block requests to internal networks.'
  },
  // SQL Injection
  {
    type: 'sql_query',
    pattern: /\.query\s*\(\s*['"`](?:SELECT|INSERT|UPDATE|DELETE)/gi,
    threatType: ThreatType.SQL_INJECTION,
    severity: Severity.CRITICAL,
    description: 'Potential SQL injection via raw query',
    remediation: 'Use parameterized queries or prepared statements. Never concatenate user input.'
  },
  {
    type: 'sql_raw',
    pattern: /\.raw\s*\(\s*['"`]|\.unsafeRaw\s*\(/g,
    threatType: ThreatType.SQL_INJECTION,
    severity: Severity.CRITICAL,
    description: 'Raw SQL query execution',
    remediation: 'Avoid raw SQL. Use ORM methods or parameterized queries.'
  },
  // Path Traversal
  {
    type: 'fs_read',
    pattern: /\b(?:fs\.)?(?:readFile|readFileSync|createReadStream)\s*\(/g,
    threatType: ThreatType.PATH_TRAVERSAL,
    severity: Severity.HIGH,
    description: 'File read with potentially user-controlled path',
    remediation: 'Validate file paths. Use path.resolve() and check against base directory.'
  },
  {
    type: 'fs_write',
    pattern: /\b(?:fs\.)?(?:writeFile|writeFileSync|createWriteStream|appendFile)\s*\(/g,
    threatType: ThreatType.PATH_TRAVERSAL,
    severity: Severity.HIGH,
    description: 'File write with potentially user-controlled path',
    remediation: 'Validate file paths. Never use user input directly in file operations.'
  },
  // Deserialization
  {
    type: 'json_parse',
    pattern: /\bJSON\.parse\s*\(/g,
    threatType: ThreatType.INSECURE_DESERIALIZATION,
    severity: Severity.MEDIUM,
    description: 'JSON parsing (safe by itself, but check usage)',
    remediation: 'Validate JSON structure after parsing. Be careful with prototype pollution.'
  },
  {
    type: 'unserialize',
    pattern: /\b(?:unserialize|deserialize)\s*\(/g,
    threatType: ThreatType.INSECURE_DESERIALIZATION,
    severity: Severity.HIGH,
    description: 'Object deserialization (potential RCE)',
    remediation: 'Avoid deserializing untrusted data. Use safe serialization formats.'
  },
  // Header Injection
  {
    type: 'set_header',
    pattern: /\.setHeader\s*\(/g,
    threatType: ThreatType.SECURITY_MISCONFIGURATION,
    severity: Severity.MEDIUM,
    description: 'HTTP header injection if value is user-controlled',
    remediation: 'Validate header values. Remove newlines and control characters.'
  },
  // Redirect
  {
    type: 'redirect',
    pattern: /\.redirect\s*\(/g,
    threatType: ThreatType.SECURITY_MISCONFIGURATION,
    severity: Severity.MEDIUM,
    description: 'Open redirect if URL is user-controlled',
    remediation: 'Validate redirect URLs. Only allow relative paths or whitelisted domains.'
  }
];

/**
 * Represents a tracked tainted variable
 */
interface TaintedVariable {
  name: string;
  sourceType: string;
  sourceLine: number;
  sourceCode: string;
  assignments: { line: number; code: string }[];
}

/**
 * Taint Analyzer Class
 * Performs intra-procedural taint analysis for JavaScript/TypeScript
 */
export class TaintAnalyzer {
  private taintedVariables: Map<string, TaintedVariable> = new Map();
  private lines: string[] = [];
  private filePath: string = '';

  /**
   * Analyze code for taint flows
   */
  analyze(content: string, filePath: string): TaintFlow[] {
    this.lines = content.split('\n');
    this.filePath = filePath;
    this.taintedVariables.clear();

    const flows: TaintFlow[] = [];

    // Phase 1: Identify taint sources
    this.identifySources();

    // Phase 2: Track taint propagation
    this.trackPropagation();

    // Phase 3: Check sinks
    flows.push(...this.checkSinks());

    return flows;
  }

  /**
   * Phase 1: Identify all taint sources in the code
   */
  private identifySources(): void {
    for (let i = 0; i < this.lines.length; i++) {
      const line = this.lines[i];
      const lineNum = i + 1;

      // Check each source pattern
      for (const source of TAINT_SOURCES) {
        // Reset regex lastIndex
        source.pattern.lastIndex = 0;
        
        // Check for variable assignment from source
        const assignmentPatterns = [
          // const/let/var x = source
          new RegExp(`(?:const|let|var)\\s+(\\w+)\\s*=\\s*${source.pattern.source}`, 'g'),
          // x = source (reassignment)
          new RegExp(`(\\w+)\\s*=\\s*${source.pattern.source}`, 'g'),
          // destructuring: const { x } = req.body
          new RegExp(`(?:const|let|var)\\s*\\{([^}]+)\\}\\s*=\\s*${source.pattern.source.replace(/\(\?:[^)]+\)?\?/g, '')}`, 'g')
        ];

        for (const pattern of assignmentPatterns) {
          pattern.lastIndex = 0;
          let match;
          while ((match = pattern.exec(line)) !== null) {
            const varNames = match[1].split(',').map(v => v.trim().split(':')[0].trim());
            
            for (const varName of varNames) {
              if (varName && /^\w+$/.test(varName)) {
                this.taintedVariables.set(varName, {
                  name: varName,
                  sourceType: source.type,
                  sourceLine: lineNum,
                  sourceCode: line.trim(),
                  assignments: []
                });
              }
            }
          }
        }
      }
    }
  }

  /**
   * Phase 2: Track taint propagation through assignments
   */
  private trackPropagation(): void {
    for (let i = 0; i < this.lines.length; i++) {
      const line = this.lines[i];
      const lineNum = i + 1;

      // Check for propagation: y = taintedVar or y = something(taintedVar)
      for (const [taintedVar, taintInfo] of this.taintedVariables) {
        // Skip the original source line
        if (lineNum === taintInfo.sourceLine) continue;

        // Check if tainted variable is used in an assignment
        const propagationPattern = new RegExp(
          `(?:const|let|var)?\\s*(\\w+)\\s*=\\s*(?:[^;]*\\b${taintedVar}\\b[^;]*)`,
          'g'
        );

        let match;
        while ((match = propagationPattern.exec(line)) !== null) {
          const newVar = match[1];
          if (newVar && newVar !== taintedVar && /^\w+$/.test(newVar)) {
            // Propagate taint to new variable
            if (!this.taintedVariables.has(newVar)) {
              this.taintedVariables.set(newVar, {
                name: newVar,
                sourceType: taintInfo.sourceType,
                sourceLine: taintInfo.sourceLine,
                sourceCode: taintInfo.sourceCode,
                assignments: [{ line: lineNum, code: line.trim() }]
              });
            } else {
              // Add to existing tainted variable's propagation
              const existing = this.taintedVariables.get(newVar)!;
              existing.assignments.push({ line: lineNum, code: line.trim() });
            }
          }
        }
      }
    }
  }

  /**
   * Phase 3: Check if tainted data reaches sinks
   */
  private checkSinks(): TaintFlow[] {
    const flows: TaintFlow[] = [];

    for (let i = 0; i < this.lines.length; i++) {
      const line = this.lines[i];
      const lineNum = i + 1;

      // Check each sink pattern
      for (const sink of TAINT_SINKS) {
        sink.pattern.lastIndex = 0;
        
        if (sink.pattern.test(line)) {
          // Check if any tainted variable is used in this line
          for (const [varName, taintInfo] of this.taintedVariables) {
            const varPattern = new RegExp(`\\b${varName}\\b`);
            if (varPattern.test(line)) {
              // Found taint flow!
              flows.push({
                source: {
                  type: taintInfo.sourceType,
                  variable: taintInfo.name,
                  line: taintInfo.sourceLine,
                  code: taintInfo.sourceCode
                },
                sink: {
                  type: sink.type,
                  line: lineNum,
                  code: line.trim(),
                  threatType: sink.threatType,
                  severity: sink.severity
                },
                propagation: taintInfo.assignments.map(a => ({ ...a, variable: taintInfo.name })),
                confidence: this.calculateConfidence(taintInfo, sink, lineNum)
              });
            }
          }

          // Also check for direct source-to-sink (no intermediate variable)
          for (const source of TAINT_SOURCES) {
            source.pattern.lastIndex = 0;
            if (source.pattern.test(line)) {
              flows.push({
                source: {
                  type: source.type,
                  variable: 'direct',
                  line: lineNum,
                  code: line.trim()
                },
                sink: {
                  type: sink.type,
                  line: lineNum,
                  code: line.trim(),
                  threatType: sink.threatType,
                  severity: sink.severity
                },
                propagation: [],
                confidence: 95 // High confidence for direct flows
              });
            }
          }
        }
      }
    }

    // Deduplicate flows
    return this.deduplicateFlows(flows);
  }

  /**
   * Calculate confidence score for a taint flow
   */
  private calculateConfidence(
    taintInfo: TaintedVariable,
    sink: TaintSink,
    sinkLine: number
  ): number {
    let confidence = 70; // Base confidence

    // Higher confidence for shorter flows
    const distance = Math.abs(sinkLine - taintInfo.sourceLine);
    if (distance < 5) confidence += 15;
    else if (distance < 20) confidence += 10;
    else if (distance > 100) confidence -= 10;

    // Higher confidence for fewer propagation steps
    if (taintInfo.assignments.length === 0) confidence += 10;
    else if (taintInfo.assignments.length > 5) confidence -= 15;

    // Adjust based on sink severity
    if (sink.severity === Severity.CRITICAL) confidence += 5;

    // Cap confidence
    return Math.max(50, Math.min(100, confidence));
  }

  /**
   * Remove duplicate flows
   */
  private deduplicateFlows(flows: TaintFlow[]): TaintFlow[] {
    const seen = new Set<string>();
    return flows.filter(flow => {
      const key = `${flow.source.type}:${flow.source.line}:${flow.sink.type}:${flow.sink.line}`;
      if (seen.has(key)) return false;
      seen.add(key);
      return true;
    });
  }

  /**
   * Get human-readable description for a source type
   */
  static getSourceDescription(sourceType: string): string {
    const source = TAINT_SOURCES.find(s => s.type === sourceType);
    return source?.description || 'User-controlled input';
  }

  /**
   * Get sink information
   */
  static getSinkInfo(sinkType: string): TaintSink | undefined {
    return TAINT_SINKS.find(s => s.type === sinkType);
  }
}

export default TaintAnalyzer;
