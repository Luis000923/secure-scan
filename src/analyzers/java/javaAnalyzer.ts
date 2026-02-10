/**
 * Java Analyzer
 * Specialized analyzer for Java code with comprehensive security detection
 * Includes JNDI/Log4Shell, deserialization, and enterprise patterns
 * 
 * Extends BaseAnalyzer and implements performCustomAnalysis for Java-specific patterns
 */

import { BaseAnalyzer } from '../base';
import { ScannedFile, Finding, SupportedLanguage, Severity, ThreatType, FindingCategory } from '../../types';
import { generateId } from '../../utils';
import { getStandardsForThreat } from '../../rules/standards';
import {
  getInjectionPatterns,
  getInjectionStandards,
  buildWeakCryptoPatterns,
  getCryptoStandards,
  getDangerousFunctionPatterns,
  getSecurityStandards,
  getAllCredentialPatterns,
  getCredentialStandards,
  JNDI_PATTERNS
} from '../shared';

/**
 * Java Analyzer Class
 * 
 * Uses Template Method pattern from BaseAnalyzer.
 * Implements performCustomAnalysis() for Java-specific security detection.
 */
export class JavaAnalyzer extends BaseAnalyzer {
  name = 'Java Analyzer';
  languages: SupportedLanguage[] = ['java'];
  version = '2.1.0';

  // Pre-compiled shared patterns for Java
  private injectionPatterns = getInjectionPatterns('java');
  private cryptoPatterns = buildWeakCryptoPatterns('java');
  private dangerousFunctionPatterns = getDangerousFunctionPatterns('java');
  private credentialPatterns = getAllCredentialPatterns();

  /**
   * Java-specific analysis (Template Method hook)
   * Improved: Analyzes logical blocks of code for better context and fewer false positives
   */
  protected async performCustomAnalysis(file: ScannedFile): Promise<Finding[]> {
    const findings: Finding[] = [];
    const content = file.content;
    const lines = content.split('\n');

    // 1. Enhanced pattern-based analysis using shared patterns
    const sharedPatternFindings = this.analyzeWithSharedPatterns(file, content, lines);
    findings.push(...sharedPatternFindings);

    // 2. JNDI Injection (Log4Shell) detection
    const jndiFindings = this.checkJndiInjection(file, content, lines);
    findings.push(...jndiFindings);

    // 3. Block-based analysis
    const blocks = this.extractLogicalBlocks(content);
    for (const block of blocks) {
      const blockFindings = this.analyzeBlock(block, file);
      findings.push(...blockFindings);
    }

    return findings;
  }

  /**
   * Analyze a single logical block for Java-specific vulnerabilities
   */
  private analyzeBlock(block: { content: string, startLine: number, name: string }, file: ScannedFile): Finding[] {
    const findings: Finding[] = [];
    const blockContent = block.content;
    const blockLines = blockContent.split('\n');

    const blockPatterns = [
      {
        pattern: /ObjectInputStream\s*\([^)]*\).*?\.readObject\s*\(/gs,
        title: 'Deserialización Insegura',
        description: 'ObjectInputStream.readObject() puede ejecutar código arbitrario durante la deserialización.',
        severity: Severity.CRITICAL,
        threatType: ThreatType.INSECURE_DESERIALIZATION
      },
      {
        pattern: /(?:Runtime\.getRuntime\s*\(\s*\)\.exec|ProcessBuilder)\s*\([^)]*\+/g,
        title: 'Inyección de Comandos Potencial',
        description: 'La ejecución de comandos con concatenación dinámica de cadenas puede conducir a RCE.',
        severity: Severity.CRITICAL,
        threatType: ThreatType.COMMAND_INJECTION
      },
      {
        pattern: /Statement\s*\.\s*execute(?:Query|Update)?\s*\([^)]*\+/g,
        title: 'Inyección SQL Potencial',
        description: 'Consulta SQL con concatenación de cadenas. Use PreparedStatement en su lugar.',
        severity: Severity.CRITICAL,
        threatType: ThreatType.SQL_INJECTION
      },
      {
        pattern: /DocumentBuilderFactory\.newInstance\s*\(\s*\).*?(?!setFeature.*disallow-doctype-decl)/gs,
        title: 'Vulnerabilidad XXE Potencial',
        description: 'El analizador XML puede ser vulnerable a XXE si los DTD no están deshabilitados explícitamente.',
        severity: Severity.HIGH,
        threatType: ThreatType.DANGEROUS_FUNCTION
      },
      {
        pattern: /new\s+(?:File|FileInputStream|FileOutputStream)\s*\([^)]*\+/g,
        title: 'Salto de Directorio Potencial',
        description: 'Operación de archivo usando concatenación de rutas controladas por el usuario.',
        severity: Severity.HIGH,
        threatType: ThreatType.PATH_TRAVERSAL
      },
      {
        pattern: /SpelExpressionParser\s*\(\s*\).*?parseExpression\s*\([^)]*\+/gs,
        title: 'Inyección de Expresiones SpEL',
        description: 'El lenguaje de expresiones de Spring (SpEL) con concatenación de entrada de usuario puede conducir a RCE.',
        severity: Severity.CRITICAL,
        threatType: ThreatType.COMMAND_INJECTION
      }
    ];

    for (const bp of blockPatterns) {
      let match;
      while ((match = bp.pattern.exec(blockContent)) !== null) {
        const relativeLineNum = blockContent.substring(0, match.index).split('\n').length;
        const absoluteLineNum = block.startLine + relativeLineNum - 1;
        const line = blockLines[relativeLineNum - 1] || '';

        if (this.isCommentLine(line, 'java')) continue;

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

  // ═══════════════════════════════════════════════════════════════════════════
  // SHARED PATTERN ANALYSIS
  // ═══════════════════════════════════════════════════════════════════════════

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
          tags: ['java', pattern.category.toLowerCase().replace(/\s+/g, '-')]
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
          tags: ['java', 'cryptography']
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
          tags: ['java', pattern.category.toLowerCase().replace(/\s+/g, '-')]
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
        if (this.isCommentLine(line, 'java')) continue;

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
          remediation: 'Use environment variables, Spring Vault, or AWS Secrets Manager.',
          confidence: 85,
          analyzer: this.name,
          timestamp: new Date(),
          tags: ['java', 'secrets', 'credential']
        });
      }
    }

    return findings;
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // JNDI / LOG4SHELL DETECTION
  // ═══════════════════════════════════════════════════════════════════════════

  /**
   * Check for JNDI Injection vulnerabilities (Log4Shell CVE-2021-44228)
   */
  private checkJndiInjection(file: ScannedFile, content: string, lines: string[]): Finding[] {
    const findings: Finding[] = [];

    for (const pattern of JNDI_PATTERNS) {
      pattern.pattern.lastIndex = 0;
      let match;
      while ((match = pattern.pattern.exec(content)) !== null) {
        const lineNum = this.calculateLineNumber(content, match.index);
        findings.push({
          id: generateId(),
          title: pattern.name,
          description: pattern.description,
          severity: pattern.severity,
          threatType: ThreatType.INJECTION,
          category: FindingCategory.VULNERABILITY,
          location: {
            file: file.relativePath,
            startLine: lineNum,
            endLine: lineNum
          },
          snippet: { code: lines[lineNum - 1] || '' },
          standards: getSecurityStandards('JNDI Injection'),
          remediation: pattern.recommendation,
          confidence: 90,
          analyzer: this.name,
          timestamp: new Date(),
          tags: ['java', 'jndi', 'log4shell', 'cve-2021-44228']
        });
      }
    }

    // Additional Log4j specific patterns
    const log4jPatterns = [
      {
        pattern: /log4j.*1\.\d/gi,
        name: 'Log4j 1.x Detectado',
        severity: Severity.HIGH,
        description: 'Log4j 1.x está al final de su vida útil (EOL) y tiene vulnerabilidades conocidas.',
        recommendation: 'Actualice a Log4j 2.17.1 o posterior.',
      },
      {
        pattern: /org\.apache\.logging\.log4j.*[12]\.[0-9]+/gi,
        name: 'Necesaria Verificación de Versión de Log4j',
        severity: Severity.MEDIUM,
        description: 'Verifique que la versión de Log4j sea 2.17.1 o posterior para evitar Log4Shell.',
        recommendation: 'Actualice Log4j a 2.17.1+ y elimine la clase JndiLookup.',
      }
    ];

    for (const pattern of log4jPatterns) {
      pattern.pattern.lastIndex = 0;
      let match;
      while ((match = pattern.pattern.exec(content)) !== null) {
        const lineNum = this.calculateLineNumber(content, match.index);
        findings.push({
          id: generateId(),
          title: pattern.name,
          description: pattern.description,
          severity: pattern.severity,
          threatType: ThreatType.VULNERABLE_DEPENDENCY,
          category: FindingCategory.VULNERABILITY,
          location: {
            file: file.relativePath,
            startLine: lineNum,
            endLine: lineNum
          },
          snippet: { code: lines[lineNum - 1] || '' },
          standards: getSecurityStandards('JNDI Injection'),
          remediation: pattern.recommendation,
          confidence: 70,
          analyzer: this.name,
          timestamp: new Date(),
          tags: ['java', 'log4j', 'dependency']
        });
      }
    }

    return findings;
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // JAVA-SPECIFIC PATTERN CHECKERS
  // ═══════════════════════════════════════════════════════════════════════════

  /**
   * Check for deserialization sinks
   */
  private checkDeserializationSinks(line: string): boolean {
    const patterns = [
      /ObjectInputStream\s*\(/,
      /\.readObject\s*\(\s*\)/,
      /XMLDecoder\s*\(/,
      /XStream\s*\(\s*\)/,
      /ObjectMapper\s*\(\s*\).*enableDefaultTyping/
    ];
    return patterns.some(p => p.test(line));
  }

  /**
   * Check for Runtime.exec
   */
  private checkRuntimeExec(line: string): boolean {
    const patterns = [
      /Runtime\.getRuntime\s*\(\s*\)\.exec\s*\(/,
      /ProcessBuilder\s*\([^)]*\+/,
      /new\s+ProcessBuilder\s*\([^)]*\$/
    ];
    return patterns.some(p => p.test(line));
  }

  /**
   * Check for SQL injection
   */
  private checkSqlInjection(line: string): boolean {
    const patterns = [
      /Statement\s*\.\s*execute(?:Query|Update)?\s*\([^)]*\+/,
      /createStatement\s*\(\s*\).*execute/,
      /["']SELECT[^'"]*["']\s*\+/i,
      /["']INSERT[^'"]*["']\s*\+/i,
      /["']UPDATE[^'"]*["']\s*\+/i,
      /["']DELETE[^'"]*["']\s*\+/i
    ];
    return patterns.some(p => p.test(line));
  }

  /**
   * Check for XXE vulnerabilities
   */
  private checkXxe(line: string): boolean {
    const patterns = [
      /DocumentBuilderFactory\.newInstance\s*\(\s*\)/,
      /SAXParserFactory\.newInstance\s*\(\s*\)/,
      /XMLInputFactory\.newInstance\s*\(\s*\)/,
      /TransformerFactory\.newInstance\s*\(\s*\)/
    ];
    if (patterns.some(p => p.test(line))) {
      if (!/setFeature.*disallow-doctype-decl/i.test(line) &&
        !/setFeature.*external-general-entities/i.test(line)) {
        return true;
      }
    }
    return false;
  }

  /**
   * Check for path traversal
   */
  private checkPathTraversal(line: string): boolean {
    const patterns = [
      /new\s+File\s*\([^)]*\+/,
      /new\s+FileInputStream\s*\([^)]*\+/,
      /new\s+FileOutputStream\s*\([^)]*\+/,
      /Paths\.get\s*\([^)]*\+/,
      /Files\.(?:read|write|copy|move)\s*\([^)]*request/i
    ];
    return patterns.some(p => p.test(line));
  }

  /**
   * Check for insecure random
   */
  private checkInsecureRandom(line: string): boolean {
    return /new\s+Random\s*\(\s*\)/.test(line) && !/SecureRandom/.test(line);
  }

  /**
   * Check for weak crypto
   */
  private checkWeakCrypto(line: string): boolean {
    const patterns = [
      /Cipher\.getInstance\s*\(\s*["'](?:DES|DESede|RC2|RC4|Blowfish)["']/i,
      /MessageDigest\.getInstance\s*\(\s*["'](?:MD5|SHA-1|SHA1)["']/i,
      /KeyGenerator\.getInstance\s*\(\s*["'](?:DES|DESede)["']/i
    ];
    return patterns.some(p => p.test(line));
  }

  /**
   * Check for LDAP injection
   */
  private checkLdapInjection(line: string): boolean {
    const patterns = [
      /new\s+InitialDirContext\s*\([^)]*\+/,
      /ctx\.search\s*\([^)]*\+/,
      /SearchControls/
    ];
    return patterns.some(p => p.test(line)) && /\+\s*[a-zA-Z]/.test(line);
  }

  /**
   * Check for SpEL injection
   */
  private checkSpelInjection(line: string): boolean {
    const patterns = [
      /SpelExpressionParser\s*\(\s*\).*parseExpression\s*\([^)]*\+/,
      /ExpressionParser.*parseExpression\s*\([^)]*request/i
    ];
    return patterns.some(p => p.test(line));
  }
}

export default JavaAnalyzer;
