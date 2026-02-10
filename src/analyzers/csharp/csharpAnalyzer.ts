/**
 * C# Analyzer
 * Specialized analyzer for C# code with comprehensive security detection
 * Includes Razor injection, Entity Framework issues, and .NET-specific patterns
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
  getCredentialStandards
} from '../shared';

/**
 * C# Analyzer Class
 */
export class CSharpAnalyzer extends BaseAnalyzer {
  name = 'C# Analyzer';
  languages: SupportedLanguage[] = ['csharp'];
  version = '2.1.0';

  // Pre-compiled shared patterns for C#
  private injectionPatterns = getInjectionPatterns('csharp');
  private cryptoPatterns = buildWeakCryptoPatterns('csharp');
  private dangerousFunctionPatterns = getDangerousFunctionPatterns('csharp');
  private credentialPatterns = getAllCredentialPatterns();

  /**
   * Custom C#-specific analysis
   * Improved: Analyzes logical blocks of code for better context
   */
  protected async performCustomAnalysis(file: ScannedFile): Promise<Finding[]> {
    const findings: Finding[] = [];
    const content = file.content;
    const lines = content.split('\n');

    // 1. Enhanced pattern-based analysis using shared patterns
    const sharedPatternFindings = this.analyzeWithSharedPatterns(file, content, lines);
    findings.push(...sharedPatternFindings);

    // 2. Razor-specific and ASP.NET-specific checks
    const razorFindings = this.checkRazorInjection(file, content, lines);
    findings.push(...razorFindings);

    // 3. Block-based analysis
    const blocks = this.extractLogicalBlocks(content);
    for (const block of blocks) {
      const blockFindings = this.analyzeBlock(block, file);
      findings.push(...blockFindings);
    }

    return findings;
  }

  /**
   * Analyze a single logical block for C#-specific vulnerabilities
   */
  private analyzeBlock(block: { content: string, startLine: number, name: string }, file: ScannedFile): Finding[] {
    const findings: Finding[] = [];
    const blockContent = block.content;
    const blockLines = blockContent.split('\n');

    const blockPatterns = [
      {
        pattern: /SqlCommand\s*\([^)]*\+/g,
        title: 'Potential SQL Injection',
        description: 'String concatenation in SQL query. Use parameterized queries.',
        severity: Severity.CRITICAL,
        threatType: ThreatType.SQL_INJECTION
      },
      {
        pattern: /Process\.Start\s*\([^)]*\+/g,
        title: 'Riesgo de Inyección de Comandos',
        description: 'Process.Start con argumentos potencialmente controlados por el usuario.',
        severity: Severity.CRITICAL,
        threatType: ThreatType.COMMAND_INJECTION
      },
      {
        pattern: /(?:BinaryFormatter|NetDataContractSerializer|SoapFormatter)\.Deserialize\s*\(/g,
        title: 'Deserialización Insegura',
        description: 'Los formateadores inseguros pueden ejecutar código arbitrario durante la deserialización.',
        severity: Severity.CRITICAL,
        threatType: ThreatType.INSECURE_DESERIALIZATION
      },
      {
        pattern: /XmlDocument\s*\(\s*\).*?DtdProcessing\s*=\s*DtdProcessing\.Parse/gs,
        title: 'Vulnerabilidad XXE Potencial',
        description: 'El analizador XML con el procesamiento DTD habilitado es vulnerable a XXE.',
        severity: Severity.HIGH,
        threatType: ThreatType.DANGEROUS_FUNCTION
      },
      {
        pattern: /File\.(?:ReadAll|WriteAll|Open|Delete)\s*\([^)]*\+/g,
        title: 'Riesgo de Salto de Directorio',
        description: 'Operación de archivo con concatenación de ruta potencialmente controlada por el usuario.',
        severity: Severity.HIGH,
        threatType: ThreatType.PATH_TRAVERSAL
      },
      {
        pattern: /Type\.GetType\s*\([^)]*\+/g,
        title: 'Reflexión Insegura',
        description: 'Type.GetType con concatenación de cadenas puede cargar ensamblados maliciosos.',
        severity: Severity.HIGH,
        threatType: ThreatType.DANGEROUS_FUNCTION
      }
    ];

    for (const bp of blockPatterns) {
      let match;
      while ((match = bp.pattern.exec(blockContent)) !== null) {
        const relativeLineNum = blockContent.substring(0, match.index).split('\n').length;
        const absoluteLineNum = block.startLine + relativeLineNum - 1;
        const line = blockLines[relativeLineNum - 1] || '';

        if (this.isCommentLine(line, 'csharp')) continue;

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
          tags: ['csharp', pattern.category.toLowerCase().replace(/\s+/g, '-')]
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
          tags: ['csharp', 'cryptography']
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
          tags: ['csharp', pattern.category.toLowerCase().replace(/\s+/g, '-')]
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
        if (this.isCommentLine(line, 'csharp')) continue;

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
          remediation: 'Use Azure Key Vault, User Secrets, or IConfiguration with environment variables.',
          confidence: 85,
          analyzer: this.name,
          timestamp: new Date(),
          tags: ['csharp', 'secrets', 'credential']
        });
      }
    }

    return findings;
  }

  /**
   * Check for Razor-specific injection vulnerabilities
   */
  private checkRazorInjection(file: ScannedFile, content: string, lines: string[]): Finding[] {
    const findings: Finding[] = [];

    // Only check .cshtml and .razor files, or files with Razor patterns
    const isRazorFile = file.relativePath.endsWith('.cshtml') ||
      file.relativePath.endsWith('.razor') ||
      /@Html\./.test(content);

    if (!isRazorFile) return findings;

    const razorPatterns = [
      {
        pattern: /@Html\.Raw\s*\(/gi,
        name: 'XSS - Html.Raw',
        severity: Severity.HIGH,
        description: 'Html.Raw outputs unencoded HTML, vulnerable to XSS.',
        recommendation: 'Sanitize content before using Html.Raw or use normal Razor output.',
      },
      {
        pattern: /@\(\s*new\s+HtmlString\s*\(/gi,
        name: 'XSS - HtmlString',
        severity: Severity.HIGH,
        description: 'HtmlString bypasses automatic encoding.',
        recommendation: 'Avoid HtmlString with user input, sanitize if necessary.',
      },
      {
        pattern: /Response\.Write\s*\([^)]*Request\[/gi,
        name: 'XSS - Response.Write',
        severity: Severity.CRITICAL,
        description: 'Writing request data directly to response.',
        recommendation: 'Use HttpUtility.HtmlEncode or Razor syntax.',
      },
      {
        pattern: /ValidateInput\s*\(\s*false\s*\)/gi,
        name: 'Request Validation Disabled',
        severity: Severity.HIGH,
        description: 'ValidateInput(false) disables ASP.NET request validation.',
        recommendation: 'Keep request validation enabled, use [AllowHtml] selectively.',
      },
      {
        pattern: /@Html\.Action\s*\([^)]*Request\[/gi,
        name: 'Open Redirect via Html.Action',
        severity: Severity.MEDIUM,
        description: 'Html.Action with request parameters may allow open redirect.',
        recommendation: 'Validate action names against allowlist.',
      },
    ];

    for (const p of razorPatterns) {
      p.pattern.lastIndex = 0;
      let match;
      while ((match = p.pattern.exec(content)) !== null) {
        const lineNum = this.calculateLineNumber(content, match.index);
        findings.push({
          id: generateId(),
          title: p.name,
          description: p.description,
          severity: p.severity,
          threatType: ThreatType.XSS,
          category: FindingCategory.VULNERABILITY,
          location: {
            file: file.relativePath,
            startLine: lineNum,
            endLine: lineNum
          },
          snippet: { code: lines[lineNum - 1] || '' },
          standards: getInjectionStandards('XSS'),
          remediation: p.recommendation,
          confidence: 85,
          analyzer: this.name,
          timestamp: new Date(),
          tags: ['csharp', 'razor', 'xss']
        });
      }
    }

    // Entity Framework specific patterns
    const efPatterns = [
      {
        pattern: /\.FromSqlRaw\s*\(\s*\$"/gi,
        name: 'SQL Injection (EF FromSqlRaw)',
        severity: Severity.CRITICAL,
        description: 'String interpolation in FromSqlRaw is vulnerable to SQL injection.',
        recommendation: 'Use FromSqlInterpolated or pass parameters array to FromSqlRaw.',
      },
      {
        pattern: /\.ExecuteSqlRaw\s*\(\s*\$"/gi,
        name: 'SQL Injection (EF ExecuteSqlRaw)',
        severity: Severity.CRITICAL,
        description: 'String interpolation in ExecuteSqlRaw is vulnerable.',
        recommendation: 'Use ExecuteSqlInterpolated or pass parameters array.',
      },
    ];

    for (const p of efPatterns) {
      p.pattern.lastIndex = 0;
      let match;
      while ((match = p.pattern.exec(content)) !== null) {
        const lineNum = this.calculateLineNumber(content, match.index);
        findings.push({
          id: generateId(),
          title: p.name,
          description: p.description,
          severity: p.severity,
          threatType: ThreatType.SQL_INJECTION,
          category: FindingCategory.VULNERABILITY,
          location: {
            file: file.relativePath,
            startLine: lineNum,
            endLine: lineNum
          },
          snippet: { code: lines[lineNum - 1] || '' },
          standards: getInjectionStandards('SQL Injection'),
          remediation: p.recommendation,
          confidence: 90,
          analyzer: this.name,
          timestamp: new Date(),
          tags: ['csharp', 'entity-framework', 'sql-injection']
        });
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
}

export default CSharpAnalyzer;
