/**
 * Utility Functions for Secure-Scan
 */

import * as crypto from 'crypto';
import * as path from 'path';
import { SupportedLanguage, Severity } from '../types';

/**
 * Generate a unique ID
 */
export function generateId(): string {
  return `SS-${Date.now().toString(36)}-${crypto.randomBytes(4).toString('hex')}`;
}

/**
 * Calculate SHA256 hash of content
 */
export function calculateHash(content: string): string {
  return crypto.createHash('sha256').update(content).digest('hex');
}

/**
 * Get language from file extension
 */
export function getLanguageFromExtension(filePath: string): SupportedLanguage | null {
  const ext = path.extname(filePath).toLowerCase();
  
  const extensionMap: Record<string, SupportedLanguage> = {
    '.js': 'javascript',
    '.jsx': 'javascript',
    '.mjs': 'javascript',
    '.cjs': 'javascript',
    '.ts': 'typescript',
    '.tsx': 'typescript',
    '.py': 'python',
    '.pyw': 'python',
    '.php': 'php',
    '.phtml': 'php',
    '.php3': 'php',
    '.php4': 'php',
    '.php5': 'php',
    '.java': 'java',
    '.c': 'c',
    '.h': 'c',
    '.cpp': 'cpp',
    '.cc': 'cpp',
    '.cxx': 'cpp',
    '.hpp': 'cpp',
    '.hxx': 'cpp',
    '.cs': 'csharp',
    '.dockerfile': 'dockerfile',
    '.yaml': 'yaml',
    '.yml': 'yaml',
    '.tf': 'terraform',
    '.tfvars': 'terraform'
  };

  // Check for Dockerfile without extension
  if (path.basename(filePath).toLowerCase() === 'dockerfile') {
    return 'dockerfile';
  }

  return extensionMap[ext] || null;
}

/**
 * Check if file should be excluded
 */
export function shouldExclude(filePath: string, excludePatterns: string[]): boolean {
  const normalizedPath = filePath.replace(/\\/g, '/');
  
  const defaultExcludes = [
    'node_modules',
    'vendor',
    '.git',
    'dist',
    'build',
    'out',
    '__pycache__',
    '.venv',
    'venv',
    '.env',
    'coverage',
    '.nyc_output',
    '.next',
    '.nuxt'
  ];

  const allExcludes = [...defaultExcludes, ...excludePatterns];

  return allExcludes.some(pattern => {
    // Simple pattern matching
    if (normalizedPath.includes(`/${pattern}/`) || 
        normalizedPath.includes(`/${pattern}`) ||
        normalizedPath.startsWith(`${pattern}/`)) {
      return true;
    }
    return false;
  });
}

/**
 * Get file extension for syntax highlighting
 */
export function getHighlightLanguage(language: SupportedLanguage | null): string {
  const highlightMap: Record<SupportedLanguage, string> = {
    'javascript': 'javascript',
    'typescript': 'typescript',
    'python': 'python',
    'php': 'php',
    'java': 'java',
    'c': 'c',
    'cpp': 'cpp',
    'csharp': 'csharp',
    'dockerfile': 'dockerfile',
    'yaml': 'yaml',
    'terraform': 'hcl'
  };

  return language ? highlightMap[language] : 'plaintext';
}

/**
 * Extract code context around a line
 */
export function extractCodeContext(
  content: string,
  lineNumber: number,
  contextLines: number = 3
): { code: string; contextBefore: string; contextAfter: string } {
  const lines = content.split('\n');
  const targetLine = lineNumber - 1; // Convert to 0-indexed

  const startBefore = Math.max(0, targetLine - contextLines);
  const endAfter = Math.min(lines.length, targetLine + contextLines + 1);

  const contextBefore = lines.slice(startBefore, targetLine).join('\n');
  const code = lines[targetLine] || '';
  const contextAfter = lines.slice(targetLine + 1, endAfter).join('\n');

  return { code, contextBefore, contextAfter };
}

/**
 * Count lines in content
 */
export function countLines(content: string): number {
  return content.split('\n').length;
}

/**
 * Severity to numeric value for comparison
 */
export function severityToNumber(severity: Severity): number {
  const map: Record<Severity, number> = {
    [Severity.INFO]: 0,
    [Severity.LOW]: 1,
    [Severity.MEDIUM]: 2,
    [Severity.HIGH]: 3,
    [Severity.CRITICAL]: 4
  };
  return map[severity];
}

/**
 * Compare severities
 */
export function isHigherOrEqualSeverity(a: Severity, b: Severity): boolean {
  return severityToNumber(a) >= severityToNumber(b);
}

/**
 * Get severity color for reporting
 */
export function getSeverityColor(severity: Severity): string {
  const colors: Record<Severity, string> = {
    [Severity.INFO]: '#17a2b8',
    [Severity.LOW]: '#28a745',
    [Severity.MEDIUM]: '#ffc107',
    [Severity.HIGH]: '#fd7e14',
    [Severity.CRITICAL]: '#dc3545'
  };
  return colors[severity];
}

/**
 * Get severity badge class
 */
export function getSeverityBadge(severity: Severity): string {
  const badges: Record<Severity, string> = {
    [Severity.INFO]: 'badge-info',
    [Severity.LOW]: 'badge-success',
    [Severity.MEDIUM]: 'badge-warning',
    [Severity.HIGH]: 'badge-orange',
    [Severity.CRITICAL]: 'badge-danger'
  };
  return badges[severity];
}

/**
 * Format duration for display
 */
export function formatDuration(ms: number): string {
  if (ms < 1000) {
    return `${ms}ms`;
  }
  if (ms < 60000) {
    return `${(ms / 1000).toFixed(2)}s`;
  }
  const minutes = Math.floor(ms / 60000);
  const seconds = ((ms % 60000) / 1000).toFixed(0);
  return `${minutes}m ${seconds}s`;
}

/**
 * Escape HTML for safe display
 */
export function escapeHtml(text: string): string {
  const escapeMap: Record<string, string> = {
    '&': '&amp;',
    '<': '&lt;',
    '>': '&gt;',
    '"': '&quot;',
    "'": '&#039;'
  };
  return text.replace(/[&<>"']/g, char => escapeMap[char]);
}

/**
 * Truncate text with ellipsis
 */
export function truncate(text: string, maxLength: number): string {
  if (text.length <= maxLength) return text;
  return text.substring(0, maxLength - 3) + '...';
}

/**
 * Check if string looks like Base64
 */
export function isBase64Like(str: string): boolean {
  // Check if string looks like base64 encoded content
  if (str.length < 20) return false;
  const base64Regex = /^[A-Za-z0-9+/=]{20,}$/;
  return base64Regex.test(str.replace(/\s/g, ''));
}

/**
 * Check if string looks like hex encoded
 */
export function isHexEncoded(str: string): boolean {
  if (str.length < 20 || str.length % 2 !== 0) return false;
  const hexRegex = /^[0-9a-fA-F]+$/;
  return hexRegex.test(str);
}

/**
 * Calculate Shannon entropy of a string
 * High entropy suggests encrypted/compressed/obfuscated content
 */
export function calculateEntropy(str: string): number {
  if (str.length === 0) return 0;

  const frequencies: Record<string, number> = {};
  for (const char of str) {
    frequencies[char] = (frequencies[char] || 0) + 1;
  }

  let entropy = 0;
  const len = str.length;
  for (const count of Object.values(frequencies)) {
    const probability = count / len;
    entropy -= probability * Math.log2(probability);
  }

  return entropy;
}

/**
 * Check if code appears obfuscated based on entropy and patterns
 */
export function looksObfuscated(code: string): boolean {
  // Check entropy - obfuscated code tends to have higher entropy
  const entropy = calculateEntropy(code);
  if (entropy > 5.5) return true;

  // Check for common obfuscation patterns
  const obfuscationPatterns = [
    /\\x[0-9a-f]{2}/gi, // Hex escape sequences
    /\\u[0-9a-f]{4}/gi, // Unicode escape sequences
    /['"][^'"]{100,}['"]/g, // Very long strings
    /\b[a-z]{1}[0-9]{4,}\b/gi, // Variables like a12345
    /\(\s*function\s*\(\s*\)\s*{[\s\S]*}\s*\)\s*\(\s*\)/g, // IIFE obfuscation
    /eval\s*\(\s*atob\s*\(/gi, // eval(atob(...))
    /String\.fromCharCode/gi, // Character code generation
  ];

  let patternMatches = 0;
  for (const pattern of obfuscationPatterns) {
    if (pattern.test(code)) {
      patternMatches++;
    }
  }

  return patternMatches >= 2;
}
