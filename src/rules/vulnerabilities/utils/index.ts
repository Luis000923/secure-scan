/**
 * @fileoverview Vulnerability Detection Module - Utility Functions
 * @module rules/vulnerabilities/utils
 * 
 * Utility functions for vulnerability detection including safe regex matching,
 * snippet extraction, taint analysis helpers, and code normalization.
 */

import {
  SupportedLanguage,
  PatternMatch,
  SourceLocation,
  VulnerabilityPattern,
  RegexPattern,
  PatternType,
  TaintSource,
  TaintSink,
  TaintSanitizer,
  VulnerabilityType,
  ConfidenceLevel
} from '../types';
import { LIMITS } from '../constants';

// ============================================================================
// SAFE REGEX MATCHING
// ============================================================================

/**
 * Execute regex with timeout protection (ReDoS prevention)
 * 
 * @param code - Source code to match against
 * @param pattern - Regex pattern to match
 * @returns Array of pattern matches
 */
export function safeRegexMatch(
  code: string,
  pattern: RegexPattern
): PatternMatch[] {
  const matches: PatternMatch[] = [];
  const timeout = pattern.timeout ?? LIMITS.REGEX_TIMEOUT;
  const maxMatches = pattern.maxMatches ?? LIMITS.MAX_MATCHES_PER_PATTERN;
  
  try {
    const regex = new RegExp(pattern.pattern, pattern.flags ?? 'g');
    const startTime = Date.now();
    let match: RegExpExecArray | null;
    
    while ((match = regex.exec(code)) !== null) {
      // Check timeout
      if (Date.now() - startTime > timeout) {
        console.warn(`Regex timeout for pattern: ${pattern.patternId || pattern.pattern.substring(0, 50)}`);
        break;
      }
      
      // Check max matches
      if (matches.length >= maxMatches) {
        break;
      }
      
      const line = getLineNumber(code, match.index);
      const column = getColumnNumber(code, match.index);
      
      matches.push({
        pattern,
        matchedText: match[0],
        location: {
          filePath: '',
          startLine: line,
          endLine: line,
          startColumn: column,
          endColumn: column + match[0].length
        },
        captures: match.slice(1)
      });
      
      // Prevent infinite loops for zero-length matches
      if (match.index === regex.lastIndex) {
        regex.lastIndex++;
      }
    }
  } catch (error) {
    console.error(`Regex error for pattern ${pattern.patternId}:`, error);
  }
  
  return matches;
}

/**
 * Execute regex match with promise-based timeout
 * 
 * @param code - Source code to match against
 * @param pattern - Regex pattern to match
 * @param timeout - Timeout in milliseconds
 * @returns Promise of pattern matches
 */
export async function safeRegexMatchAsync(
  code: string,
  pattern: RegexPattern,
  timeout: number = LIMITS.REGEX_TIMEOUT
): Promise<PatternMatch[]> {
  return new Promise((resolve) => {
    const timeoutId = setTimeout(() => {
      resolve([]);
    }, timeout);
    
    try {
      const results = safeRegexMatch(code, pattern);
      clearTimeout(timeoutId);
      resolve(results);
    } catch {
      clearTimeout(timeoutId);
      resolve([]);
    }
  });
}

// ============================================================================
// LINE AND COLUMN UTILITIES
// ============================================================================

/**
 * Get line number from character index (1-based)
 * 
 * @param code - Source code
 * @param index - Character index
 * @returns Line number (1-based)
 */
export function getLineNumber(code: string, index: number): number {
  return code.substring(0, index).split('\n').length;
}

/**
 * Get column number from character index (0-based)
 * 
 * @param code - Source code
 * @param index - Character index
 * @returns Column number (0-based)
 */
export function getColumnNumber(code: string, index: number): number {
  const lastNewline = code.lastIndexOf('\n', index - 1);
  return index - lastNewline - 1;
}

/**
 * Get character index from line and column
 * 
 * @param code - Source code
 * @param line - Line number (1-based)
 * @param column - Column number (0-based)
 * @returns Character index
 */
export function getCharacterIndex(code: string, line: number, column: number): number {
  const lines = code.split('\n');
  let index = 0;
  
  for (let i = 0; i < line - 1 && i < lines.length; i++) {
    index += lines[i].length + 1; // +1 for newline
  }
  
  return index + column;
}

// ============================================================================
// SNIPPET EXTRACTION
// ============================================================================

/**
 * Extract code snippet with context
 * 
 * @param code - Full source code
 * @param location - Source location
 * @param contextLines - Number of context lines before/after
 * @returns Code snippet with context
 */
export function extractSnippet(
  code: string,
  location: SourceLocation,
  contextLines: number = 3
): { snippet: string; highlightStart: number; highlightEnd: number } {
  const lines = code.split('\n');
  
  const startLine = Math.max(1, location.startLine - contextLines);
  const endLine = Math.min(lines.length, location.endLine + contextLines);
  
  const snippetLines = lines.slice(startLine - 1, endLine);
  const snippet = snippetLines.join('\n');
  
  // Calculate highlight positions
  let highlightStart = 0;
  for (let i = startLine; i < location.startLine; i++) {
    highlightStart += lines[i - 1].length + 1;
  }
  highlightStart += location.startColumn ?? 0;
  
  let highlightEnd = highlightStart;
  for (let i = location.startLine; i <= location.endLine; i++) {
    if (i === location.endLine) {
      highlightEnd += (location.endColumn ?? lines[i - 1].length) - (i === location.startLine ? (location.startColumn ?? 0) : 0);
    } else {
      highlightEnd += lines[i - 1].length + 1 - (i === location.startLine ? (location.startColumn ?? 0) : 0);
    }
  }
  
  return { snippet, highlightStart, highlightEnd };
}

/**
 * Extract the specific line of code
 * 
 * @param code - Full source code
 * @param lineNumber - Line number (1-based)
 * @returns The line content
 */
export function extractLine(code: string, lineNumber: number): string {
  const lines = code.split('\n');
  if (lineNumber < 1 || lineNumber > lines.length) {
    return '';
  }
  return lines[lineNumber - 1];
}

/**
 * Format snippet for display with line numbers
 * 
 * @param snippet - Code snippet
 * @param startLine - Starting line number
 * @returns Formatted snippet with line numbers
 */
export function formatSnippetWithLineNumbers(snippet: string, startLine: number): string {
  const lines = snippet.split('\n');
  const maxLineNumWidth = String(startLine + lines.length - 1).length;
  
  return lines.map((line, i) => {
    const lineNum = String(startLine + i).padStart(maxLineNumWidth, ' ');
    return `${lineNum} | ${line}`;
  }).join('\n');
}

// ============================================================================
// CODE NORMALIZATION
// ============================================================================

/**
 * Normalize code for consistent analysis
 * 
 * @param code - Source code
 * @param language - Programming language
 * @returns Normalized code
 */
export function normalizeCode(code: string, language: SupportedLanguage): string {
  let normalized = code;
  
  // Normalize line endings
  normalized = normalized.replace(/\r\n/g, '\n').replace(/\r/g, '\n');
  
  // Truncate very long lines
  const lines = normalized.split('\n');
  normalized = lines.map(line => {
    if (line.length > LIMITS.MAX_LINE_LENGTH) {
      return line.substring(0, LIMITS.MAX_LINE_LENGTH) + '/* ... truncated */';
    }
    return line;
  }).join('\n');
  
  return normalized;
}

/**
 * Remove comments from code (approximate)
 * 
 * @param code - Source code
 * @param language - Programming language
 * @returns Code without comments
 */
export function removeComments(code: string, language: SupportedLanguage): string {
  let result = code;
  
  switch (language) {
    case SupportedLanguage.JAVASCRIPT:
    case SupportedLanguage.TYPESCRIPT:
    case SupportedLanguage.JAVA:
    case SupportedLanguage.CSHARP:
    case SupportedLanguage.CPP:
    case SupportedLanguage.C:
      // Remove single-line comments
      result = result.replace(/\/\/[^\n]*/g, '');
      // Remove multi-line comments (non-greedy)
      result = result.replace(/\/\*[\s\S]*?\*\//g, '');
      break;
      
    case SupportedLanguage.PYTHON:
    case SupportedLanguage.RUBY:
    case SupportedLanguage.SHELL:
    case SupportedLanguage.YAML:
      // Remove hash comments
      result = result.replace(/#[^\n]*/g, '');
      // Remove docstrings (Python)
      result = result.replace(/'''[\s\S]*?'''/g, '');
      result = result.replace(/"""[\s\S]*?"""/g, '');
      break;
      
    case SupportedLanguage.PHP:
      // Remove single-line comments (// and #)
      result = result.replace(/(?:\/\/|#)[^\n]*/g, '');
      // Remove multi-line comments
      result = result.replace(/\/\*[\s\S]*?\*\//g, '');
      break;
  }
  
  return result;
}

// ============================================================================
// STRING ANALYSIS
// ============================================================================

/**
 * Check if a string appears to be a SQL query
 * 
 * @param text - Text to check
 * @returns True if text looks like SQL
 */
export function looksLikeSql(text: string): boolean {
  const sqlKeywords = /\b(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|TRUNCATE|EXEC|EXECUTE|UNION|WHERE|FROM|INTO|VALUES|SET)\b/i;
  return sqlKeywords.test(text);
}

/**
 * Check if a string appears to be a shell command
 * 
 * @param text - Text to check
 * @returns True if text looks like a shell command
 */
export function looksLikeCommand(text: string): boolean {
  const commandPatterns = /\b(bash|sh|cmd|powershell|ls|dir|cat|rm|del|wget|curl|nc|netcat|chmod|chown|sudo|su)\b|\||\&\&|\|\|/i;
  return commandPatterns.test(text);
}

/**
 * Check if a string appears to be HTML
 * 
 * @param text - Text to check
 * @returns True if text looks like HTML
 */
export function looksLikeHtml(text: string): boolean {
  const htmlPatterns = /<\s*(?:script|img|iframe|a|div|span|input|form|button|svg|object|embed|link|style)[^>]*>/i;
  return htmlPatterns.test(text);
}

/**
 * Check if text contains user-controlled input indicators
 * 
 * @param text - Text to check
 * @param language - Programming language
 * @returns True if text contains user input patterns
 */
export function containsUserInput(text: string, language: SupportedLanguage): boolean {
  const patterns: Record<string, RegExp[]> = {
    javascript: [
      /req\.(body|query|params|headers|cookies)/,
      /\$\.(get|post|ajax)/,
      /location\.(search|hash|href)/,
      /document\.(cookie|referrer)/
    ],
    typescript: [
      /req\.(body|query|params|headers|cookies)/,
      /location\.(search|hash|href)/
    ],
    python: [
      /request\.(args|form|data|json|headers|cookies)/,
      /\binput\s*\(/,
      /sys\.argv/
    ],
    php: [
      /\$_(GET|POST|REQUEST|COOKIE|SERVER|FILES)\s*\[/
    ],
    java: [
      /getParameter|getHeader|getCookies|getInputStream|@RequestBody|@PathVariable/
    ],
    csharp: [
      /Request\.(Form|QueryString|Headers|Cookies)|FromBody|FromQuery|FromRoute/
    ]
  };
  
  const langPatterns = patterns[language] || [];
  return langPatterns.some(p => p.test(text));
}

// ============================================================================
// TAINT ANALYSIS HELPERS
// ============================================================================

/**
 * Find taint sources in code
 * 
 * @param code - Source code
 * @param sources - Taint source definitions
 * @param language - Programming language
 * @returns Array of found sources with locations
 */
export function findTaintSources(
  code: string,
  sources: TaintSource[],
  language: SupportedLanguage
): Array<{ source: TaintSource; location: SourceLocation; matchedText: string }> {
  const results: Array<{ source: TaintSource; location: SourceLocation; matchedText: string }> = [];
  
  for (const source of sources) {
    // Check language compatibility
    if (source.languages && !source.languages.includes(language)) {
      continue;
    }
    
    const pattern = typeof source.pattern === 'string' 
      ? new RegExp(source.pattern, 'g')
      : source.pattern;
    
    let match: RegExpExecArray | null;
    const regex = new RegExp(pattern.source, pattern.flags.includes('g') ? pattern.flags : pattern.flags + 'g');
    
    while ((match = regex.exec(code)) !== null) {
      const line = getLineNumber(code, match.index);
      const column = getColumnNumber(code, match.index);
      
      results.push({
        source,
        location: {
          filePath: '',
          startLine: line,
          endLine: line,
          startColumn: column,
          endColumn: column + match[0].length
        },
        matchedText: match[0]
      });
      
      if (results.length >= LIMITS.MAX_MATCHES_PER_PATTERN) {
        break;
      }
    }
  }
  
  return results;
}

/**
 * Find taint sinks in code
 * 
 * @param code - Source code
 * @param sinks - Taint sink definitions
 * @param language - Programming language
 * @returns Array of found sinks with locations
 */
export function findTaintSinks(
  code: string,
  sinks: TaintSink[],
  language: SupportedLanguage
): Array<{ sink: TaintSink; location: SourceLocation; matchedText: string }> {
  const results: Array<{ sink: TaintSink; location: SourceLocation; matchedText: string }> = [];
  
  for (const sink of sinks) {
    // Check language compatibility
    if (sink.languages && !sink.languages.includes(language)) {
      continue;
    }
    
    const pattern = typeof sink.pattern === 'string'
      ? new RegExp(sink.pattern, 'g')
      : sink.pattern;
    
    let match: RegExpExecArray | null;
    const regex = new RegExp(pattern.source, pattern.flags.includes('g') ? pattern.flags : pattern.flags + 'g');
    
    while ((match = regex.exec(code)) !== null) {
      const line = getLineNumber(code, match.index);
      const column = getColumnNumber(code, match.index);
      
      results.push({
        sink,
        location: {
          filePath: '',
          startLine: line,
          endLine: line,
          startColumn: column,
          endColumn: column + match[0].length
        },
        matchedText: match[0]
      });
      
      if (results.length >= LIMITS.MAX_MATCHES_PER_PATTERN) {
        break;
      }
    }
  }
  
  return results;
}

/**
 * Check if sanitization is present between source and sink
 * 
 * @param code - Source code
 * @param sourceLocation - Source location
 * @param sinkLocation - Sink location
 * @param sanitizers - Sanitizer definitions
 * @returns Found sanitizers between source and sink
 */
export function findSanitizers(
  code: string,
  sourceLocation: SourceLocation,
  sinkLocation: SourceLocation,
  sanitizers: TaintSanitizer[]
): TaintSanitizer[] {
  const found: TaintSanitizer[] = [];
  
  // Get code between source and sink
  const sourceIndex = getCharacterIndex(code, sourceLocation.startLine, sourceLocation.startColumn ?? 0);
  const sinkIndex = getCharacterIndex(code, sinkLocation.startLine, sinkLocation.startColumn ?? 0);
  
  // Handle both directions
  const start = Math.min(sourceIndex, sinkIndex);
  const end = Math.max(sourceIndex, sinkIndex);
  const codeBetween = code.substring(start, end);
  
  for (const sanitizer of sanitizers) {
    const pattern = typeof sanitizer.pattern === 'string'
      ? new RegExp(sanitizer.pattern, 'gi')
      : sanitizer.pattern;
    
    if (pattern.test(codeBetween)) {
      found.push(sanitizer);
    }
  }
  
  return found;
}

// ============================================================================
// CONTEXT DETECTION
// ============================================================================

/**
 * Check if code location is inside a test file
 * 
 * @param filePath - File path
 * @returns True if file is a test file
 */
export function isTestFile(filePath: string): boolean {
  const testPatterns = [
    /\.test\.[jt]sx?$/,
    /\.spec\.[jt]sx?$/,
    /_test\.[jt]sx?$/,
    /_spec\.[jt]sx?$/,
    /test_.*\.(py|js|ts)$/,
    /.*_test\.(py|js|ts)$/,
    /tests?\//i,
    /__tests__\//,
    /spec\//i
  ];
  
  return testPatterns.some(p => p.test(filePath));
}

/**
 * Check if code location is inside vendor/node_modules
 * 
 * @param filePath - File path
 * @returns True if file is vendor code
 */
export function isVendorCode(filePath: string): boolean {
  const vendorPatterns = [
    /node_modules\//,
    /vendor\//,
    /bower_components\//,
    /third_party\//,
    /external\//,
    /\.min\.js$/,
    /\.bundle\.js$/
  ];
  
  return vendorPatterns.some(p => p.test(filePath));
}

/**
 * Detect the programming language from file extension
 * 
 * @param filePath - File path
 * @returns Detected language or null
 */
export function detectLanguage(filePath: string): SupportedLanguage | null {
  const extension = filePath.split('.').pop()?.toLowerCase();
  
  const extensionMap: Record<string, SupportedLanguage> = {
    'js': SupportedLanguage.JAVASCRIPT,
    'jsx': SupportedLanguage.JAVASCRIPT,
    'mjs': SupportedLanguage.JAVASCRIPT,
    'cjs': SupportedLanguage.JAVASCRIPT,
    'ts': SupportedLanguage.TYPESCRIPT,
    'tsx': SupportedLanguage.TYPESCRIPT,
    'py': SupportedLanguage.PYTHON,
    'php': SupportedLanguage.PHP,
    'java': SupportedLanguage.JAVA,
    'c': SupportedLanguage.C,
    'h': SupportedLanguage.C,
    'cpp': SupportedLanguage.CPP,
    'cc': SupportedLanguage.CPP,
    'cxx': SupportedLanguage.CPP,
    'hpp': SupportedLanguage.CPP,
    'cs': SupportedLanguage.CSHARP,
    'rb': SupportedLanguage.RUBY,
    'go': SupportedLanguage.GO,
    'rs': SupportedLanguage.RUST,
    'sh': SupportedLanguage.SHELL,
    'bash': SupportedLanguage.SHELL,
    'ps1': SupportedLanguage.POWERSHELL,
    'dockerfile': SupportedLanguage.DOCKERFILE,
    'yaml': SupportedLanguage.YAML,
    'yml': SupportedLanguage.YAML,
    'tf': SupportedLanguage.TERRAFORM
  };
  
  return extensionMap[extension ?? ''] ?? null;
}

// ============================================================================
// CONFIDENCE CALCULATION
// ============================================================================

/**
 * Calculate confidence based on multiple factors
 * 
 * @param factors - Array of confidence factors (0-1)
 * @returns Combined confidence level
 */
export function calculateConfidence(factors: number[]): ConfidenceLevel {
  if (factors.length === 0) return ConfidenceLevel.TENTATIVE;
  
  const average = factors.reduce((sum, f) => sum + f, 0) / factors.length;
  
  if (average >= 0.95) return ConfidenceLevel.CONFIRMED;
  if (average >= 0.80) return ConfidenceLevel.HIGH;
  if (average >= 0.60) return ConfidenceLevel.MEDIUM;
  if (average >= 0.40) return ConfidenceLevel.LOW;
  return ConfidenceLevel.TENTATIVE;
}

/**
 * Boost confidence when taint flow is confirmed
 * 
 * @param baseConfidence - Base confidence level
 * @param hasTaintFlow - Whether taint flow was detected
 * @returns Adjusted confidence level
 */
export function adjustConfidenceForTaintFlow(
  baseConfidence: ConfidenceLevel,
  hasTaintFlow: boolean
): ConfidenceLevel {
  if (!hasTaintFlow) return baseConfidence;
  
  const levels: ConfidenceLevel[] = [
    ConfidenceLevel.TENTATIVE,
    ConfidenceLevel.LOW,
    ConfidenceLevel.MEDIUM,
    ConfidenceLevel.HIGH,
    ConfidenceLevel.CONFIRMED
  ];
  
  const currentIndex = levels.indexOf(baseConfidence);
  const newIndex = Math.min(currentIndex + 1, levels.length - 1);
  
  return levels[newIndex];
}

// ============================================================================
// UNIQUE ID GENERATION
// ============================================================================

/**
 * Generate unique finding ID
 * 
 * @param ruleId - Rule ID
 * @param filePath - File path
 * @param line - Line number
 * @returns Unique finding ID
 */
export function generateFindingId(
  ruleId: string,
  filePath: string,
  line: number
): string {
  const hash = simpleHash(`${ruleId}:${filePath}:${line}`);
  return `${ruleId}-${hash}`;
}

/**
 * Simple string hash function
 * 
 * @param str - String to hash
 * @returns Hash string
 */
function simpleHash(str: string): string {
  let hash = 0;
  for (let i = 0; i < str.length; i++) {
    const char = str.charCodeAt(i);
    hash = ((hash << 5) - hash) + char;
    hash = hash & hash; // Convert to 32-bit integer
  }
  return Math.abs(hash).toString(16).substring(0, 8);
}
