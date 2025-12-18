/**
 * Java Analyzer
 * Specialized analyzer for Java code
 */

import { BaseAnalyzer } from '../base';
import { ScannedFile, Finding, Rule, SupportedLanguage, Severity, ThreatType, FindingCategory } from '../../types';
import { generateId, extractCodeContext } from '../../utils';
import { getStandardsForThreat } from '../../rules/standards';

/**
 * Java Analyzer Class
 */
export class JavaAnalyzer extends BaseAnalyzer {
  name = 'Java Analyzer';
  languages: SupportedLanguage[] = ['java'];
  version = '1.0.0';

  /**
   * Analyze Java file
   */
  async analyze(file: ScannedFile, rules: Rule[]): Promise<Finding[]> {
    const findings: Finding[] = [];

    // Filter rules for Java
    const javaRules = rules.filter(r => r.languages.includes('java'));

    // Run rule engine
    const ruleFindings = await this.ruleEngine.analyzeFile(file, javaRules);
    findings.push(...ruleFindings);

    // Additional Java-specific analysis
    const customFindings = await this.customAnalysis(file);
    findings.push(...customFindings);

    return findings;
  }

  /**
   * Custom Java-specific analysis
   */
  private async customAnalysis(file: ScannedFile): Promise<Finding[]> {
    const findings: Finding[] = [];
    const lines = file.content.split('\n');

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      const lineNum = i + 1;

      // Check for ObjectInputStream deserialization
      if (this.checkDeserializationSinks(line)) {
        findings.push(this.createFinding(
          file,
          lineNum,
          'Unsafe Deserialization',
          'ObjectInputStream.readObject() can execute arbitrary code.',
          Severity.CRITICAL,
          ThreatType.INSECURE_DESERIALIZATION
        ));
      }

      // Check for Runtime.exec
      if (this.checkRuntimeExec(line)) {
        findings.push(this.createFinding(
          file,
          lineNum,
          'Potential Command Injection',
          'Runtime.exec() with dynamic input can lead to command injection.',
          Severity.CRITICAL,
          ThreatType.COMMAND_INJECTION
        ));
      }

      // Check for SQL injection patterns
      if (this.checkSqlInjection(line)) {
        findings.push(this.createFinding(
          file,
          lineNum,
          'Potential SQL Injection',
          'String concatenation in SQL query detected. Use PreparedStatement.',
          Severity.CRITICAL,
          ThreatType.SQL_INJECTION
        ));
      }

      // Check for XXE vulnerabilities
      if (this.checkXxe(line)) {
        findings.push(this.createFinding(
          file,
          lineNum,
          'Potential XXE Vulnerability',
          'XML parser may be vulnerable to XXE attacks.',
          Severity.HIGH,
          ThreatType.DANGEROUS_FUNCTION
        ));
      }

      // Check for path traversal
      if (this.checkPathTraversal(line)) {
        findings.push(this.createFinding(
          file,
          lineNum,
          'Potential Path Traversal',
          'File operations with user-controlled input detected.',
          Severity.HIGH,
          ThreatType.PATH_TRAVERSAL
        ));
      }

      // Check for insecure random
      if (this.checkInsecureRandom(line)) {
        findings.push(this.createFinding(
          file,
          lineNum,
          'Insecure Random Number Generator',
          'java.util.Random is not cryptographically secure.',
          Severity.MEDIUM,
          ThreatType.WEAK_RANDOM
        ));
      }

      // Check for weak crypto
      if (this.checkWeakCrypto(line)) {
        findings.push(this.createFinding(
          file,
          lineNum,
          'Weak Cryptographic Algorithm',
          'Use of weak or deprecated cryptographic algorithm.',
          Severity.MEDIUM,
          ThreatType.INSECURE_CRYPTO
        ));
      }

      // Check for LDAP injection
      if (this.checkLdapInjection(line)) {
        findings.push(this.createFinding(
          file,
          lineNum,
          'Potential LDAP Injection',
          'LDAP query with user-controlled input detected.',
          Severity.HIGH,
          ThreatType.LDAP_INJECTION
        ));
      }

      // Check for Spring Expression Language injection
      if (this.checkSpelInjection(line)) {
        findings.push(this.createFinding(
          file,
          lineNum,
          'SpEL Expression Injection',
          'Spring Expression Language with user input can lead to RCE.',
          Severity.CRITICAL,
          ThreatType.COMMAND_INJECTION
        ));
      }
    }

    return findings;
  }

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
    // Only flag if not followed by secure configuration
    if (patterns.some(p => p.test(line))) {
      // Check for secure configuration (simplified)
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
      confidence: 75,
      analyzer: this.name,
      timestamp: new Date(),
      tags: ['java']
    };
  }
}

export default JavaAnalyzer;
