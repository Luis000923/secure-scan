/**
 * C/C++ Analyzer
 * Specialized analyzer for C and C++ code
 * 
 * Uses Template Method pattern from BaseAnalyzer
 */

import { BaseAnalyzer } from '../base';
import { ScannedFile, Finding, SupportedLanguage, Severity, ThreatType, FindingCategory } from '../../types';

/**
 * C/C++ Analyzer Class
 */
export class CppAnalyzer extends BaseAnalyzer {
  name = 'C/C++ Analyzer';
  languages: SupportedLanguage[] = ['c', 'cpp'];
  version = '2.1.0';

  /**
   * Custom C/C++-specific analysis
   * Called by BaseAnalyzer.analyze() via Template Method pattern
   */
  protected async performCustomAnalysis(file: ScannedFile): Promise<Finding[]> {
    const findings: Finding[] = [];
    const lines = file.content.split('\n');

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      const lineNum = i + 1;

      // Check for dangerous functions
      if (this.checkDangerousFunctions(line)) {
        findings.push(this.buildFinding({
          file,
          lineNum,
          title: 'Use of Dangerous Function',
          description: 'This function is known to be vulnerable to buffer overflows.',
          severity: Severity.HIGH,
          threatType: ThreatType.DANGEROUS_FUNCTION
        }));
      }

      // Check for format string vulnerabilities
      if (this.checkFormatString(line)) {
        findings.push(this.buildFinding({
          file,
          lineNum,
          title: 'Format String Vulnerability',
          description: 'User-controlled format string can lead to arbitrary code execution.',
          severity: Severity.CRITICAL,
          threatType: ThreatType.DANGEROUS_FUNCTION
        }));
      }

      // Check for buffer overflow patterns
      if (this.checkBufferOverflow(line)) {
        findings.push(this.buildFinding({
          file,
          lineNum,
          title: 'Potential Buffer Overflow',
          description: 'Fixed-size buffer operation without proper bounds checking.',
          severity: Severity.HIGH,
          threatType: ThreatType.DANGEROUS_FUNCTION
        }));
      }

      // Check for command injection
      if (this.checkCommandInjection(line)) {
        findings.push(this.buildFinding({
          file,
          lineNum,
          title: 'Command Injection Risk',
          description: 'System/exec call with potentially user-controlled input.',
          severity: Severity.CRITICAL,
          threatType: ThreatType.COMMAND_INJECTION
        }));
      }

      // Check for integer overflow
      if (this.checkIntegerOverflow(line)) {
        findings.push(this.buildFinding({
          file,
          lineNum,
          title: 'Potential Integer Overflow',
          description: 'Arithmetic operation without overflow checking.',
          severity: Severity.MEDIUM,
          threatType: ThreatType.DANGEROUS_FUNCTION
        }));
      }

      // Check for use after free patterns
      if (this.checkUseAfterFree(line)) {
        findings.push(this.buildFinding({
          file,
          lineNum,
          title: 'Potential Use-After-Free',
          description: 'Pointer may be used after being freed.',
          severity: Severity.HIGH,
          threatType: ThreatType.DANGEROUS_FUNCTION
        }));
      }

      // Check for hardcoded IPs
      if (this.checkHardcodedIp(line)) {
        findings.push(this.buildFinding({
          file,
          lineNum,
          title: 'Hardcoded IP Address',
          description: 'Hardcoded IP addresses may indicate backdoor connections.',
          severity: Severity.MEDIUM,
          threatType: ThreatType.SUSPICIOUS_NETWORK
        }));
      }

      // Check for shellcode patterns
      if (this.checkShellcode(line)) {
        findings.push(this.buildFinding({
          file,
          lineNum,
          title: 'Potential Shellcode',
          description: 'Byte array resembles shellcode or encoded payload.',
          severity: Severity.CRITICAL,
          threatType: ThreatType.EMBEDDED_PAYLOAD
        }));
      }
    }

    return findings;
  }

  /**
   * Check for dangerous functions
   */
  private checkDangerousFunctions(line: string): boolean {
    const dangerous = [
      /\bgets\s*\(/,
      /\bstrcpy\s*\(/,
      /\bstrcat\s*\(/,
      /\bsprintf\s*\(/,
      /\bvsprintf\s*\(/,
      /\bscanf\s*\(\s*["']%s/,
      /\bfscanf\s*\([^,]+,\s*["']%s/,
      /\bsscanf\s*\([^,]+,\s*["']%s/,
      /\brealpath\s*\([^,]+,\s*NULL\s*\)/
    ];
    return dangerous.some(p => p.test(line));
  }

  /**
   * Check for format string vulnerabilities
   */
  private checkFormatString(line: string): boolean {
    const patterns = [
      /printf\s*\(\s*[a-zA-Z_][a-zA-Z0-9_]*\s*\)/,  // printf(var) without format
      /fprintf\s*\([^,]+,\s*[a-zA-Z_][a-zA-Z0-9_]*\s*\)/,
      /sprintf\s*\([^,]+,\s*[a-zA-Z_][a-zA-Z0-9_]*\s*\)/,
      /syslog\s*\([^,]+,\s*[a-zA-Z_][a-zA-Z0-9_]*\s*\)/
    ];
    return patterns.some(p => p.test(line));
  }

  /**
   * Check for buffer overflow patterns
   */
  private checkBufferOverflow(line: string): boolean {
    const patterns = [
      /char\s+\w+\s*\[\s*\d+\s*\]/,  // Fixed size buffer
      /memcpy\s*\([^,]+,[^,]+,[^)]*sizeof/,
      /strncpy\s*\([^,]+,[^,]+,\s*sizeof\s*\([^)]+\)\s*\)/
    ];
    
    // Only flag if combined with dangerous operations
    if (patterns.some(p => p.test(line))) {
      if (/\bstrcpy\b|\bstrcat\b|\bsprintf\b/.test(line)) {
        return true;
      }
    }
    return false;
  }

  /**
   * Check for command injection
   */
  private checkCommandInjection(line: string): boolean {
    const patterns = [
      /\bsystem\s*\([^)]*\+/,
      /\bsystem\s*\([^)]*[a-zA-Z_]\w*\s*\)/,
      /\bpopen\s*\([^)]*\+/,
      /\bexecl\s*\([^)]*\+/,
      /\bexecv\s*\([^)]*\+/,
      /\bShellExecute\s*\([^)]*\+/
    ];
    return patterns.some(p => p.test(line));
  }

  /**
   * Check for integer overflow
   */
  private checkIntegerOverflow(line: string): boolean {
    const patterns = [
      /malloc\s*\(\s*\w+\s*\*\s*\w+\s*\)/,  // malloc(a * b)
      /calloc\s*\(\s*\w+\s*,\s*\w+\s*\*\s*\w+\s*\)/,
      /realloc\s*\([^,]+,\s*\w+\s*\*\s*\w+\s*\)/
    ];
    return patterns.some(p => p.test(line));
  }

  /**
   * Check for use-after-free patterns
   */
  private checkUseAfterFree(line: string): boolean {
    // Simplified check - look for free followed by usage
    const patterns = [
      /free\s*\(\s*(\w+)\s*\).*\1/,  // free(ptr)...ptr
      /delete\s+(\w+).*\1->/  // delete ptr...ptr->
    ];
    return patterns.some(p => p.test(line));
  }

  /**
   * Check for hardcoded IPs
   */
  private checkHardcodedIp(line: string): boolean {
    // Check for IPv4 addresses that aren't localhost or private
    const ipPattern = /["']\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}["']/;
    if (ipPattern.test(line)) {
      // Exclude common safe IPs
      if (!/127\.0\.0\.1|0\.0\.0\.0|192\.168\.|10\.|172\.(?:1[6-9]|2[0-9]|3[01])\./.test(line)) {
        return true;
      }
    }
    return false;
  }

  /**
   * Check for shellcode patterns
   */
  private checkShellcode(line: string): boolean {
    const patterns = [
      /\\x[0-9a-f]{2}(?:\\x[0-9a-f]{2}){20,}/i,  // Hex escape sequences
      /\{0x[0-9a-f]{2}(?:,\s*0x[0-9a-f]{2}){20,}\}/i,  // Byte array
      /char\s+\w+\[\]\s*=\s*"\\x/i
    ];
    return patterns.some(p => p.test(line));
  }
}

export default CppAnalyzer;
