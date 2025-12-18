/**
 * C# Analyzer
 * Specialized analyzer for C# code
 */

import { BaseAnalyzer } from '../base';
import { ScannedFile, Finding, Rule, SupportedLanguage, Severity, ThreatType, FindingCategory } from '../../types';
import { generateId, extractCodeContext } from '../../utils';
import { getStandardsForThreat } from '../../rules/standards';

/**
 * C# Analyzer Class
 */
export class CSharpAnalyzer extends BaseAnalyzer {
  name = 'C# Analyzer';
  languages: SupportedLanguage[] = ['csharp'];
  version = '1.0.0';

  /**
   * Analyze C# file
   */
  async analyze(file: ScannedFile, rules: Rule[]): Promise<Finding[]> {
    const findings: Finding[] = [];

    // Filter rules for C#
    const csRules = rules.filter(r => r.languages.includes('csharp'));

    // Run rule engine
    const ruleFindings = await this.ruleEngine.analyzeFile(file, csRules);
    findings.push(...ruleFindings);

    // Additional C#-specific analysis
    const customFindings = await this.customAnalysis(file);
    findings.push(...customFindings);

    return findings;
  }

  /**
   * Custom C#-specific analysis
   */
  private async customAnalysis(file: ScannedFile): Promise<Finding[]> {
    const findings: Finding[] = [];
    const lines = file.content.split('\n');

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      const lineNum = i + 1;

      // Check for SQL injection
      if (this.checkSqlInjection(line)) {
        findings.push(this.createFinding(
          file,
          lineNum,
          'Potential SQL Injection',
          'String concatenation in SQL query. Use parameterized queries.',
          Severity.CRITICAL,
          ThreatType.SQL_INJECTION
        ));
      }

      // Check for command injection
      if (this.checkCommandInjection(line)) {
        findings.push(this.createFinding(
          file,
          lineNum,
          'Command Injection Risk',
          'Process.Start with potentially user-controlled arguments.',
          Severity.CRITICAL,
          ThreatType.COMMAND_INJECTION
        ));
      }

      // Check for deserialization
      if (this.checkDeserialization(line)) {
        findings.push(this.createFinding(
          file,
          lineNum,
          'Insecure Deserialization',
          'BinaryFormatter and similar can execute arbitrary code.',
          Severity.CRITICAL,
          ThreatType.INSECURE_DESERIALIZATION
        ));
      }

      // Check for XXE
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

      // Check for LDAP injection
      if (this.checkLdapInjection(line)) {
        findings.push(this.createFinding(
          file,
          lineNum,
          'Potential LDAP Injection',
          'LDAP query with user-controlled input.',
          Severity.HIGH,
          ThreatType.LDAP_INJECTION
        ));
      }

      // Check for path traversal
      if (this.checkPathTraversal(line)) {
        findings.push(this.createFinding(
          file,
          lineNum,
          'Path Traversal Risk',
          'File operation with potentially user-controlled path.',
          Severity.HIGH,
          ThreatType.PATH_TRAVERSAL
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

      // Check for hardcoded credentials
      if (this.checkHardcodedCredentials(line)) {
        findings.push(this.createFinding(
          file,
          lineNum,
          'Hardcoded Credentials',
          'Credentials appear to be hardcoded in source code.',
          Severity.HIGH,
          ThreatType.HARDCODED_CREDENTIALS
        ));
      }

      // Check for unsafe reflection
      if (this.checkUnsafeReflection(line)) {
        findings.push(this.createFinding(
          file,
          lineNum,
          'Unsafe Reflection',
          'Type.GetType with user input can load malicious assemblies.',
          Severity.HIGH,
          ThreatType.DANGEROUS_FUNCTION
        ));
      }
    }

    return findings;
  }

  /**
   * Check for SQL injection
   */
  private checkSqlInjection(line: string): boolean {
    const patterns = [
      /SqlCommand\s*\([^)]*\+/,
      /ExecuteReader\s*\(\s*["'][^'"]*\+/,
      /ExecuteNonQuery\s*\(\s*["'][^'"]*\+/,
      /["']SELECT[^'"]*["']\s*\+/i,
      /["']INSERT[^'"]*["']\s*\+/i,
      /["']UPDATE[^'"]*["']\s*\+/i,
      /["']DELETE[^'"]*["']\s*\+/i,
      /FromSqlRaw\s*\([^)]*\+/
    ];
    return patterns.some(p => p.test(line));
  }

  /**
   * Check for command injection
   */
  private checkCommandInjection(line: string): boolean {
    const patterns = [
      /Process\.Start\s*\([^)]*\+/,
      /ProcessStartInfo\s*\{[^}]*Arguments\s*=\s*[^}]*\+/,
      /new\s+ProcessStartInfo\s*\([^)]*\+/
    ];
    return patterns.some(p => p.test(line));
  }

  /**
   * Check for insecure deserialization
   */
  private checkDeserialization(line: string): boolean {
    const patterns = [
      /BinaryFormatter\s*\(\s*\)/,
      /\.Deserialize\s*\(/,
      /NetDataContractSerializer/,
      /SoapFormatter/,
      /ObjectStateFormatter/,
      /LosFormatter/,
      /JavaScriptSerializer\s*\(\s*\).*Deserialize/
    ];
    return patterns.some(p => p.test(line));
  }

  /**
   * Check for XXE
   */
  private checkXxe(line: string): boolean {
    const patterns = [
      /XmlDocument\s*\(\s*\)/,
      /XmlTextReader\s*\(/,
      /new\s+XmlReaderSettings\s*\(\s*\)/
    ];
    if (patterns.some(p => p.test(line))) {
      // Check if DtdProcessing is properly configured
      if (!/DtdProcessing\s*=\s*DtdProcessing\.Prohibit/.test(line)) {
        return true;
      }
    }
    return false;
  }

  /**
   * Check for LDAP injection
   */
  private checkLdapInjection(line: string): boolean {
    const patterns = [
      /DirectorySearcher\s*\([^)]*\+/,
      /FindAll\s*\(\s*["'][^'"]*\+/,
      /Filter\s*=\s*["'][^'"]*\+/
    ];
    return patterns.some(p => p.test(line));
  }

  /**
   * Check for path traversal
   */
  private checkPathTraversal(line: string): boolean {
    const patterns = [
      /File\.(?:ReadAll|WriteAll|Open|Delete)\s*\([^)]*\+/,
      /new\s+FileStream\s*\([^)]*\+/,
      /Path\.Combine\s*\([^)]*Request\./i,
      /Directory\.(?:GetFiles|Delete|Create)\s*\([^)]*\+/
    ];
    return patterns.some(p => p.test(line));
  }

  /**
   * Check for weak crypto
   */
  private checkWeakCrypto(line: string): boolean {
    const patterns = [
      /\bMD5\.Create\s*\(\s*\)/,
      /\bSHA1\.Create\s*\(\s*\)/,
      /\bDES\.Create\s*\(\s*\)/,
      /\bTripleDES\.Create\s*\(\s*\)/,
      /\bRC2\.Create\s*\(\s*\)/
    ];
    return patterns.some(p => p.test(line));
  }

  /**
   * Check for hardcoded credentials
   */
  private checkHardcodedCredentials(line: string): boolean {
    const patterns = [
      /(?:password|pwd|passwd)\s*=\s*["'][^"']{4,}["']/i,
      /(?:connectionString|connStr).*(?:password|pwd)\s*=/i,
      /SqlConnection\s*\([^)]*password\s*=/i
    ];
    return patterns.some(p => p.test(line));
  }

  /**
   * Check for unsafe reflection
   */
  private checkUnsafeReflection(line: string): boolean {
    const patterns = [
      /Type\.GetType\s*\([^)]*\+/,
      /Assembly\.Load(?:From|File)?\s*\([^)]*\+/,
      /Activator\.CreateInstance\s*\([^)]*GetType/
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
      tags: ['csharp', 'dotnet']
    };
  }
}

export default CSharpAnalyzer;
