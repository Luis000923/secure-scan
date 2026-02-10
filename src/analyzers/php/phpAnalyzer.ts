/**
 * PHP Analyzer
 * Specialized analyzer for PHP code with comprehensive security detection
 * Includes deserialization, XXE, SSRF, and web shell detection
 */

import { BaseAnalyzer } from '../base';
import { ScannedFile, Finding, SupportedLanguage, Severity, ThreatType, FindingCategory } from '../../types';
import { generateId } from '../../utils';
import {
  getInjectionPatterns,
  getInjectionStandards,
  buildWeakCryptoPatterns,
  getCryptoStandards,
  getDangerousFunctionPatterns,
  getSecurityStandards,
  getAllCredentialPatterns,
  getCredentialStandards
} from '../shared';

/**
 * PHP Analyzer Class
 */
export class PHPAnalyzer extends BaseAnalyzer {
  name = 'PHP Analyzer';
  languages: SupportedLanguage[] = ['php'];
  version = '2.1.0';

  // Pre-compiled shared patterns for PHP
  private injectionPatterns = getInjectionPatterns('php');
  private cryptoPatterns = buildWeakCryptoPatterns('php');
  private dangerousFunctionPatterns = getDangerousFunctionPatterns('php');
  private credentialPatterns = getAllCredentialPatterns();

  /**
   * Custom PHP-specific analysis
   * Improved: Analyzes logical blocks of code for better context
   */
  protected async performCustomAnalysis(file: ScannedFile): Promise<Finding[]> {
    const findings: Finding[] = [];
    const content = file.content;
    const lines = content.split('\n');

    // 1. Enhanced pattern-based analysis using shared patterns
    const sharedPatternFindings = this.analyzeWithSharedPatterns(file, content, lines);
    findings.push(...sharedPatternFindings);

    // 2. Block-based analysis
    const blocks = this.extractLogicalBlocks(content);
    for (const block of blocks) {
      const blockFindings = this.analyzeBlock(block, file);
      findings.push(...blockFindings);
    }

    return findings;
  }

  /**
   * Analyze a single logical block for PHP-specific vulnerabilities
   */
  private analyzeBlock(block: { content: string, startLine: number, name: string }, file: ScannedFile): Finding[] {
    const findings: Finding[] = [];
    const blockContent = block.content;
    const blockLines = blockContent.split('\n');

    const blockPatterns = [
      {
        pattern: /\b(?:include|require|include_once|require_once)\s*\([^)]*\$_(?:GET|POST|REQUEST)/gi,
        title: 'Potential File Inclusion Vulnerability',
        description: 'Directly including request parameters can lead to LFI/RFI.',
        severity: Severity.CRITICAL,
        threatType: ThreatType.PATH_TRAVERSAL
      },
      {
        pattern: /\$(?:query|sql)\s*=\s*["'].*?\$(?:_GET|_POST|_REQUEST)/gi,
        title: 'Inyección SQL Potencial',
        description: 'Interpolación directa de variables en consulta SQL detectada. Use sentencias preparadas.',
        severity: Severity.CRITICAL,
        threatType: ThreatType.SQL_INJECTION
      },
      {
        pattern: /\b(?:eval|assert|passthru|exec|system|shell_exec)\s*\([^)]*\$(?:_GET|_POST|_REQUEST)/gi,
        title: 'Función de PHP Peligrosa con Entrada de Usuario',
        description: 'Ejecutar código o comandos arbitrarios desde parámetros de solicitud es altamente peligroso.',
        severity: Severity.CRITICAL,
        threatType: ThreatType.DANGEROUS_FUNCTION
      },
      {
        pattern: /(?:echo|print|<?=)\s+[^;]*?(?:\$_GET|\$_POST|\$_REQUEST).*?(?!htmlspecialchars|htmlentities)/gi,
        title: 'XSS Potencial (Cross-Site Scripting)',
        description: 'Entrada de usuario mostrada sin el escape adecuado.',
        severity: Severity.HIGH,
        threatType: ThreatType.XSS
      },
      {
        pattern: /\$_(?:GET|POST|REQUEST)\s*\[[^\]]+\]\s*\(\s*\$_(?:GET|POST|REQUEST)/gi,
        title: 'Web Shell Potencial (Función Variable)',
        description: 'Patrón de código consistente con una shell web o puerta trasera de PHP.',
        severity: Severity.CRITICAL,
        threatType: ThreatType.BACKDOOR
      }
    ];

    for (const bp of blockPatterns) {
      let match;
      while ((match = bp.pattern.exec(blockContent)) !== null) {
        const relativeLineNum = blockContent.substring(0, match.index).split('\n').length;
        const absoluteLineNum = block.startLine + relativeLineNum - 1;
        const line = blockLines[relativeLineNum - 1] || '';

        if (this.isCommentLine(line, 'php')) continue;

        findings.push(this.buildFinding({
          file,
          lineNum: absoluteLineNum,
          title: bp.title,
          description: `${bp.description} (Found in ${block.name})`,
          severity: bp.severity,
          threatType: bp.threatType
        }));
      }
    }

    return findings;
  }

  /**
   * Analyze using shared patterns library
   */
  private analyzeWithSharedPatterns(file: ScannedFile, content: string, lines: string[]): Finding[] {
    const findings: Finding[] = [];

    // SQL Injection, Command Injection, XSS, Path Traversal patterns
    for (const pattern of this.injectionPatterns) {
      pattern.pattern.lastIndex = 0;
      let match;
      while ((match = pattern.pattern.exec(content)) !== null) {
        const lineNum = this.calculateLineNumber(content, match.index);
        findings.push({
          id: generateId(),
          title: pattern.name,
          description: pattern.description,
          severity: pattern.severity,
          threatType: this.convertCategoryToThreatType(pattern.category),
          category: FindingCategory.VULNERABILITY,
          location: {
            file: file.relativePath,
            startLine: lineNum,
            endLine: lineNum
          },
          snippet: { code: lines[lineNum - 1] || '' },
          standards: getInjectionStandards(pattern.category),
          remediation: pattern.recommendation,
          confidence: 80,
          analyzer: this.name,
          timestamp: new Date(),
          tags: ['php', pattern.category.toLowerCase().replace(/\s+/g, '-')]
        });
      }
    }

    // Weak cryptography detection
    for (const pattern of this.cryptoPatterns) {
      pattern.pattern.lastIndex = 0;
      let match;
      while ((match = pattern.pattern.exec(content)) !== null) {
        const lineNum = this.calculateLineNumber(content, match.index);
        findings.push({
          id: generateId(),
          title: pattern.name,
          description: pattern.description,
          severity: pattern.severity,
          threatType: ThreatType.WEAK_CRYPTOGRAPHY,
          category: FindingCategory.VULNERABILITY,
          location: {
            file: file.relativePath,
            startLine: lineNum,
            endLine: lineNum
          },
          snippet: { code: lines[lineNum - 1] || '' },
          standards: getCryptoStandards(),
          remediation: pattern.recommendation,
          confidence: 85,
          analyzer: this.name,
          timestamp: new Date(),
          tags: ['php', 'cryptography']
        });
      }
    }

    // Dangerous functions (XXE, SSRF, Deserialization)
    for (const pattern of this.dangerousFunctionPatterns) {
      pattern.pattern.lastIndex = 0;
      let match;
      while ((match = pattern.pattern.exec(content)) !== null) {
        const lineNum = this.calculateLineNumber(content, match.index);
        findings.push({
          id: generateId(),
          title: pattern.name,
          description: pattern.description,
          severity: pattern.severity,
          threatType: this.convertCategoryToThreatType(pattern.category),
          category: FindingCategory.VULNERABILITY,
          location: {
            file: file.relativePath,
            startLine: lineNum,
            endLine: lineNum
          },
          snippet: { code: lines[lineNum - 1] || '' },
          standards: getSecurityStandards(pattern.category),
          remediation: pattern.recommendation,
          confidence: 80,
          analyzer: this.name,
          timestamp: new Date(),
          tags: ['php', pattern.category.toLowerCase().replace(/\s+/g, '-')]
        });
      }
    }

    // Hardcoded credentials
    for (const pattern of this.credentialPatterns) {
      pattern.pattern.lastIndex = 0;
      let match;
      while ((match = pattern.pattern.exec(content)) !== null) {
        const lineNum = this.calculateLineNumber(content, match.index);
        const line = lines[lineNum - 1] || '';
        // Skip comments
        if (this.isCommentLine(line, 'php')) continue;

        findings.push({
          id: generateId(),
          title: 'Hardcoded Credential Detected',
          description: `${pattern.name}: Hardcoded secrets should not be in source code.`,
          severity: Severity.HIGH,
          threatType: ThreatType.HARDCODED_SECRETS,
          category: FindingCategory.SECRET,
          location: {
            file: file.relativePath,
            startLine: lineNum,
            endLine: lineNum
          },
          snippet: { code: this.maskSecrets(line) },
          standards: getCredentialStandards(),
          remediation: 'Use environment variables or a configuration file outside webroot.',
          confidence: 85,
          analyzer: this.name,
          timestamp: new Date(),
          tags: ['php', 'secrets', 'credential']
        });
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
}

export default PHPAnalyzer;
