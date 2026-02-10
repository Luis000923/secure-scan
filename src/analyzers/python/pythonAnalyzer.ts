/**
 * Python Analyzer
 * Specialized analyzer for Python code with comprehensive security detection
 * 
 * Extends BaseAnalyzer and implements performCustomAnalysis for Python-specific patterns
 */

import { BaseAnalyzer, CreateFindingOptions } from '../base';
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
 * Python Analyzer Class
 * 
 * Uses Template Method pattern from BaseAnalyzer.
 * Implements performCustomAnalysis() for Python-specific security detection.
 */
export class PythonAnalyzer extends BaseAnalyzer {
  name = 'Python Analyzer';
  languages: SupportedLanguage[] = ['python'];
  version = '2.1.0';

  // Pre-compiled shared patterns for Python
  private injectionPatterns = getInjectionPatterns('python');
  private cryptoPatterns = buildWeakCryptoPatterns('python');
  private dangerousFunctionPatterns = getDangerousFunctionPatterns('python');
  private credentialPatterns = getAllCredentialPatterns();

  /**
   * Python-specific analysis (Template Method hook)
   * Improved: Analyzes logical blocks of code for better context and fewer false positives
   */
  protected async performCustomAnalysis(file: ScannedFile): Promise<Finding[]> {
    const findings: Finding[] = [];
    const content = file.content;
    const lines = content.split('\n');

    // 1. Enhanced pattern-based analysis using shared patterns (now uses whole-file multiline matching)
    const sharedPatternFindings = this.analyzeWithSharedPatterns(file, content, lines);
    findings.push(...sharedPatternFindings);

    // 2. Block-based analysis
    // Extract logical blocks (functions, classes, or top-level logical groups)
    const blocks = this.extractLogicalBlocks(content);

    for (const block of blocks) {
      // Analyze each block for Python-specific vulnerabilities
      const blockFindings = this.analyzeBlock(block, file);
      findings.push(...blockFindings);
    }

    // 3. Check for requirements.txt if exists
    if (file.relativePath.endsWith('requirements.txt')) {
      const reqFindings = this.analyzeRequirements(file);
      findings.push(...reqFindings);
    }

    return findings;
  }

  /**
   * Extract logical blocks from Python code
   * Overrides base implementation to use indentation-based logic
   */
  protected override extractLogicalBlocks(content: string): Array<{ content: string, startLine: number, name: string }> {
    const blocks: Array<{ content: string, startLine: number, name: string }> = [];
    const lines = content.split('\n');

    let currentBlockLines: string[] = [];
    let currentBlockStart = 1;
    let currentBlockName = 'top-level';

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      const lineNum = i + 1;
      const trimmed = line.trim();

      // Start of a new block (function or class)
      if (trimmed.startsWith('def ') || trimmed.startsWith('class ')) {
        // Save previous block
        if (currentBlockLines.length > 0) {
          blocks.push({
            content: currentBlockLines.join('\n'),
            startLine: currentBlockStart,
            name: currentBlockName
          });
        }
        // Start new block
        currentBlockLines = [line];
        currentBlockStart = lineNum;
        currentBlockName = trimmed.split('(')[0].split(':')[0].trim();
      } else {
        currentBlockLines.push(line);
      }
    }

    // Last block
    if (currentBlockLines.length > 0) {
      blocks.push({
        content: currentBlockLines.join('\n'),
        startLine: currentBlockStart,
        name: currentBlockName
      });
    }

    return blocks;
  }

  /**
   * Analyze a single logical block
   */
  private analyzeBlock(block: { content: string, startLine: number, name: string }, file: ScannedFile): Finding[] {
    const findings: Finding[] = [];
    const blockContent = block.content;
    const blockLines = blockContent.split('\n');

    // Define patterns to check within the block
    const blockPatterns = [
      {
        pattern: /pickle\.loads?\s*\(/g,
        title: 'Deserialización Pickle Insegura',
        description: 'Pickle puede ejecutar código arbitrario durante la deserialización.',
        severity: Severity.HIGH,
        threatType: ThreatType.INSECURE_DESERIALIZATION
      },
      {
        pattern: /yaml\.load\s*\((?![^)]*Loader\s*=\s*yaml\.SafeLoader)/g,
        title: 'Carga YAML Insegura',
        description: 'yaml.load() sin SafeLoader puede ejecutar código Python arbitrario.',
        severity: Severity.HIGH,
        threatType: ThreatType.INSECURE_DESERIALIZATION
      },
      {
        pattern: /subprocess\.(?:Popen|call|run|check_output|check_call)\s*\([^)]*shell\s*=\s*True/g,
        title: 'Subprocess con shell=True',
        description: 'Usar shell=True con subprocess puede conducir a la inyección de comandos.',
        severity: Severity.HIGH,
        threatType: ThreatType.COMMAND_INJECTION
      },
      {
        pattern: /\.extractall\s*\(/g,
        title: 'Riesgo de Salto de Directorio en Tarfile',
        description: 'Extraer archivos tar sin validación puede conducir a un salto de directorio.',
        severity: Severity.MEDIUM,
        threatType: ThreatType.PATH_TRAVERSAL
      },
      {
        pattern: /\bexec\s*\((?![^)]*['"])/g,
        title: 'Ejecución de Código Dinámico',
        description: 'exec() con entrada no literal puede ejecutar código arbitrario.',
        severity: Severity.CRITICAL,
        threatType: ThreatType.DANGEROUS_FUNCTION
      }
    ];

    for (const bp of blockPatterns) {
      let match;
      while ((match = bp.pattern.exec(blockContent)) !== null) {
        const relativeLineNum = blockContent.substring(0, match.index).split('\n').length;
        const absoluteLineNum = block.startLine + relativeLineNum - 1;
        const line = blockLines[relativeLineNum - 1] || '';

        // Skip false positives in comments
        if (this.isCommentLine(line, 'python')) continue;

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

    // SQL Injection, Command Injection, XSS, SSTI, Path Traversal
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
          tags: ['python', pattern.category.toLowerCase().replace(/\s+/g, '-')]
        });
      }
    }

    // Weak cryptography
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
          tags: ['python', 'cryptography']
        });
      }
    }

    // Dangerous functions (XXE, SSRF, Deserialization, etc.)
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
          tags: ['python', pattern.category.toLowerCase().replace(/\s+/g, '-')]
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
        // Skip false positives in comments
        if (line.trim().startsWith('#')) continue;

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
          remediation: 'Use environment variables or a secrets manager.',
          confidence: 85,
          analyzer: this.name,
          timestamp: new Date(),
          tags: ['python', 'secrets', 'credential']
        });
      }
    }

    return findings;
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // PYTHON-SPECIFIC PATTERN CHECKERS
  // ═══════════════════════════════════════════════════════════════════════════

  /**
   * Check for dangerous imports
   */
  private checkDangerousImports(line: string): boolean {
    const dangerousModules = [
      /^import\s+ctypes/,
      /^from\s+ctypes\s+import/,
      /^import\s+mmap/,
      /^import\s+pyHook/,
      /^import\s+pythoncom/,
      /^import\s+pynput/
    ];
    return dangerousModules.some(p => p.test(line.trim()));
  }

  /**
   * Check for pickle usage
   */
  private checkPickleUsage(line: string): boolean {
    return /pickle\.loads?\s*\(/.test(line) || /cPickle\.loads?\s*\(/.test(line);
  }

  /**
   * Check for unsafe YAML load
   */
  private checkUnsafeYamlLoad(line: string): boolean {
    if (/yaml\.load\s*\(/.test(line)) {
      if (!/Loader\s*=/.test(line) && !/yaml\.safe_load/.test(line)) {
        return true;
      }
    }
    return false;
  }

  /**
   * Check for subprocess with shell=True
   */
  private checkSubprocessShell(line: string): boolean {
    return /subprocess\.(?:Popen|call|run|check_output|check_call)\s*\([^)]*shell\s*=\s*True/.test(line);
  }

  /**
   * Check for tarfile extraction without validation
   */
  private checkTarfileTraversal(line: string): boolean {
    return /\.extractall\s*\(/.test(line) || /\.extract\s*\(/.test(line);
  }

  /**
   * Check for Flask debug mode
   */
  private checkFlaskDebug(line: string): boolean {
    return /app\.run\s*\([^)]*debug\s*=\s*True/.test(line) ||
      /DEBUG\s*=\s*True/.test(line);
  }

  /**
   * Check for Django settings issues
   */
  private checkDjangoSettings(line: string): boolean {
    const issues = [
      /DEBUG\s*=\s*True/,
      /SECRET_KEY\s*=\s*['"]/,
      /ALLOWED_HOSTS\s*=\s*\[\s*['"]?\*['"]?\s*\]/
    ];
    return issues.some(p => p.test(line));
  }

  /**
   * Check for compile/exec usage
   */
  private checkCompileExec(line: string): boolean {
    return /\bexec\s*\(/.test(line) || /\bcompile\s*\([^)]*['"]\bexec\b['"]\)/.test(line);
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // REQUIREMENTS.TXT ANALYSIS
  // ═══════════════════════════════════════════════════════════════════════════

  /**
   * Analyze requirements.txt
   */
  private analyzeRequirements(file: ScannedFile): Finding[] {
    const findings: Finding[] = [];
    const lines = file.content.split('\n');

    // Known vulnerable packages (simplified list)
    const vulnerablePackages: Record<string, { version: string; severity: Severity; description: string }> = {
      'pyyaml': { version: '<5.4', severity: Severity.HIGH, description: 'Ejecución de código arbitrario vía yaml.load()' },
      'django': { version: '<3.2.4', severity: Severity.HIGH, description: 'Múltiples vulnerabilidades de seguridad' },
      'flask': { version: '<2.0', severity: Severity.MEDIUM, description: 'Mejoras de seguridad en versiones más recientes' },
      'requests': { version: '<2.20.0', severity: Severity.MEDIUM, description: 'CVE-2018-18074 - Bypass de verificación HTTPS' }
    };

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i].trim().toLowerCase();
      for (const [pkg, info] of Object.entries(vulnerablePackages)) {
        if (line.startsWith(pkg + '==') || line.startsWith(pkg + '<') || line === pkg) {
          findings.push({
            id: generateId(),
            title: `Paquete Potencialmente Vulnerable: ${pkg}`,
            description: `${info.description}. Considere actualizar.`,
            severity: info.severity,
            threatType: ThreatType.VULNERABLE_DEPENDENCY,
            category: FindingCategory.VULNERABILITY,
            location: {
              file: file.relativePath,
              startLine: i + 1,
              endLine: i + 1
            },
            snippet: { code: lines[i] },
            standards: getStandardsForThreat(ThreatType.VULNERABLE_DEPENDENCY),
            remediation: `Actualice ${pkg} a la última versión segura.`,
            confidence: 60,
            analyzer: this.name,
            timestamp: new Date(),
            tags: ['dependency', 'vulnerable', 'python']
          });
        }
      }
    }

    return findings;
  }
}

export default PythonAnalyzer;
