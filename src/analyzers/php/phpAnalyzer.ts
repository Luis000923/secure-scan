/**
 * PHP Analyzer
 * Specialized analyzer for PHP code
 */

import { BaseAnalyzer } from '../base';
import { ScannedFile, Finding, Rule, SupportedLanguage, Severity, ThreatType, FindingCategory } from '../../types';
import { generateId, extractCodeContext } from '../../utils';
import { getStandardsForThreat } from '../../rules/standards';

/**
 * PHP Analyzer Class
 */
export class PHPAnalyzer extends BaseAnalyzer {
  name = 'PHP Analyzer';
  languages: SupportedLanguage[] = ['php'];
  version = '1.0.0';

  /**
   * Analyze PHP file
   */
  async analyze(file: ScannedFile, rules: Rule[]): Promise<Finding[]> {
    const findings: Finding[] = [];

    // Filter rules for PHP
    const phpRules = rules.filter(r => r.languages.includes('php'));

    // Run rule engine
    const ruleFindings = await this.ruleEngine.analyzeFile(file, phpRules);
    findings.push(...ruleFindings);

    // Additional PHP-specific analysis
    const customFindings = await this.customAnalysis(file);
    findings.push(...customFindings);

    return findings;
  }

  /**
   * Custom PHP-specific analysis
   */
  private async customAnalysis(file: ScannedFile): Promise<Finding[]> {
    const findings: Finding[] = [];
    const lines = file.content.split('\n');

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      const lineNum = i + 1;

      // Check for dangerous functions
      if (this.checkDangerousFunctions(line)) {
        findings.push(this.createFinding(
          file,
          lineNum,
          'Dangerous PHP Function',
          'Use of a function that can execute arbitrary code or commands.',
          Severity.CRITICAL,
          ThreatType.DANGEROUS_FUNCTION
        ));
      }

      // Check for file inclusion vulnerabilities
      if (this.checkFileInclusion(line)) {
        findings.push(this.createFinding(
          file,
          lineNum,
          'Potential File Inclusion Vulnerability',
          'File include with user-controlled input can lead to LFI/RFI.',
          Severity.CRITICAL,
          ThreatType.PATH_TRAVERSAL
        ));
      }

      // Check for SQL injection patterns
      if (this.checkSqlInjection(line)) {
        findings.push(this.createFinding(
          file,
          lineNum,
          'Potential SQL Injection',
          'Direct variable interpolation in SQL query detected.',
          Severity.CRITICAL,
          ThreatType.SQL_INJECTION
        ));
      }

      // Check for XSS vulnerabilities
      if (this.checkXss(line)) {
        findings.push(this.createFinding(
          file,
          lineNum,
          'Potential Cross-Site Scripting (XSS)',
          'User input echoed without proper escaping.',
          Severity.HIGH,
          ThreatType.XSS
        ));
      }

      // Check for insecure session configuration
      if (this.checkInsecureSession(line)) {
        findings.push(this.createFinding(
          file,
          lineNum,
          'Insecure Session Configuration',
          'Session configuration may be insecure.',
          Severity.MEDIUM,
          ThreatType.SECURITY_MISCONFIGURATION
        ));
      }

      // Check for disable_functions bypass attempts
      if (this.checkBypassAttempts(line)) {
        findings.push(this.createFinding(
          file,
          lineNum,
          'Security Bypass Attempt',
          'Code attempts to bypass PHP security restrictions.',
          Severity.CRITICAL,
          ThreatType.BACKDOOR
        ));
      }

      // Check for web shell patterns
      if (this.checkWebShell(line)) {
        findings.push(this.createFinding(
          file,
          lineNum,
          'Web Shell Pattern Detected',
          'Code pattern consistent with a PHP web shell.',
          Severity.CRITICAL,
          ThreatType.BACKDOOR
        ));
      }
    }

    return findings;
  }

  /**
   * Check for dangerous functions
   */
  private checkDangerousFunctions(line: string): boolean {
    const dangerous = [
      /\bassert\s*\(\s*\$/,
      /\bpreg_replace\s*\([^)]*\/[^)]*e['"]/i,
      /\bcreate_function\s*\(/,
      /\barray_map\s*\(\s*['"]\w+['"],\s*\$/,
      /\barray_filter\s*\(\s*\$[^,]*,\s*['"]\w+['"]\)/,
      /\busort\s*\(\s*\$[^,]*,\s*['"]\w+['"]\)/,
      /\bregister_shutdown_function\s*\(\s*\$/,
      /\bregister_tick_function\s*\(\s*\$/
    ];
    return dangerous.some(p => p.test(line));
  }

  /**
   * Check for file inclusion vulnerabilities
   */
  private checkFileInclusion(line: string): boolean {
    const patterns = [
      /\b(?:include|require|include_once|require_once)\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE)/i,
      /\b(?:include|require|include_once|require_once)\s*\(\s*\$(?!_)[a-zA-Z_]/i,
      /\bfile_get_contents\s*\(\s*\$_/i,
      /\bfopen\s*\(\s*\$_/i,
      /\breadf(?:ile)?\s*\(\s*\$_/i
    ];
    return patterns.some(p => p.test(line));
  }

  /**
   * Check for SQL injection
   */
  private checkSqlInjection(line: string): boolean {
    const patterns = [
      /\$(?:query|sql)\s*=\s*["'].*\.\s*\$_(?:GET|POST|REQUEST)/i,
      /mysql_query\s*\([^)]*\.\s*\$_/i,
      /mysqli_query\s*\([^)]*\.\s*\$_/i,
      /\$(?:pdo|db|conn)->query\s*\([^)]*\.\s*\$_/i,
      /["']SELECT[^'"]*\.\s*\$_/i,
      /["']INSERT[^'"]*\.\s*\$_/i,
      /["']UPDATE[^'"]*\.\s*\$_/i,
      /["']DELETE[^'"]*\.\s*\$_/i
    ];
    return patterns.some(p => p.test(line));
  }

  /**
   * Check for XSS
   */
  private checkXss(line: string): boolean {
    const patterns = [
      /echo\s+\$_(?:GET|POST|REQUEST|COOKIE)/i,
      /print\s+\$_(?:GET|POST|REQUEST|COOKIE)/i,
      /<?=\s*\$_(?:GET|POST|REQUEST|COOKIE)/i,
      /echo\s+\$[a-zA-Z_]+[^;]*;\s*(?!.*htmlspecialchars|.*htmlentities|.*strip_tags)/
    ];
    return patterns.some(p => p.test(line));
  }

  /**
   * Check for insecure session configuration
   */
  private checkInsecureSession(line: string): boolean {
    const patterns = [
      /session\.cookie_httponly\s*=\s*(?:0|false|off)/i,
      /session\.cookie_secure\s*=\s*(?:0|false|off)/i,
      /session\.use_strict_mode\s*=\s*(?:0|false|off)/i,
      /ini_set\s*\(\s*['"]session\.cookie_httponly['"]\s*,\s*(?:0|false|'0'|'false')/i
    ];
    return patterns.some(p => p.test(line));
  }

  /**
   * Check for security bypass attempts
   */
  private checkBypassAttempts(line: string): boolean {
    const patterns = [
      /\bini_set\s*\(\s*['"]disable_functions['"]/i,
      /\bini_restore\s*\(/i,
      /\bputenv\s*\(\s*['"]LD_PRELOAD/i,
      /\bmail\s*\([^)]*-X\s/i,
      /\bimap_open\s*\([^)]*\\x00/i
    ];
    return patterns.some(p => p.test(line));
  }

  /**
   * Check for web shell patterns
   */
  private checkWebShell(line: string): boolean {
    const patterns = [
      /\$_(?:GET|POST|REQUEST)\s*\[[^\]]+\]\s*\(\s*\$_(?:GET|POST|REQUEST)/i,
      /eval\s*\(\s*(?:base64_decode|gzinflate|gzuncompress|str_rot13)\s*\(/i,
      /\$\w+\s*=\s*str_replace\s*\([^)]+\)\s*;\s*\$\w+\s*\(/,
      /\$\{\s*\$_(?:GET|POST|REQUEST)/i,
      /\$\w+\s*=\s*\$_(?:GET|POST|REQUEST)[^;]+;\s*@?\$\w+\s*\(/
    ];
    return patterns.some(p => p.test(line));
  }

  /**
   * Create generic finding
   */
  private createFinding(
    file: ScannedFile,
    lineNum: number,
    title: string,
    description: string,
    severity: Severity,
    threatType: ThreatType
  ): Finding {
    const context = extractCodeContext(file.content, lineNum, 2);

    return {
      id: generateId(),
      title,
      description,
      severity,
      threatType,
      category: FindingCategory.VULNERABILITY,
      location: {
        file: file.relativePath,
        startLine: lineNum,
        endLine: lineNum
      },
      snippet: {
        code: context.code,
        contextBefore: context.contextBefore,
        contextAfter: context.contextAfter
      },
      standards: getStandardsForThreat(threatType),
      remediation: 'Review and fix the identified issue.',
      confidence: 80,
      analyzer: this.name,
      timestamp: new Date(),
      tags: ['php']
    };
  }
}

export default PHPAnalyzer;
