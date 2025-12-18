/**
 * Python Analyzer
 * Specialized analyzer for Python code
 */

import { BaseAnalyzer } from '../base';
import { ScannedFile, Finding, Rule, SupportedLanguage, Severity, ThreatType, FindingCategory } from '../../types';
import { generateId, extractCodeContext, looksObfuscated } from '../../utils';
import { getStandardsForThreat } from '../../rules/standards';
import { logger } from '../../utils/logger';

/**
 * Python Analyzer Class
 */
export class PythonAnalyzer extends BaseAnalyzer {
  name = 'Python Analyzer';
  languages: SupportedLanguage[] = ['python'];
  version = '1.0.0';

  /**
   * Analyze Python file
   */
  async analyze(file: ScannedFile, rules: Rule[]): Promise<Finding[]> {
    const findings: Finding[] = [];

    // Filter rules for Python
    const pyRules = rules.filter(r => r.languages.includes('python'));

    // Run rule engine
    const ruleFindings = await this.ruleEngine.analyzeFile(file, pyRules);
    findings.push(...ruleFindings);

    // Additional Python-specific analysis
    const customFindings = await this.customAnalysis(file);
    findings.push(...customFindings);

    return findings;
  }

  /**
   * Custom Python-specific analysis
   */
  private async customAnalysis(file: ScannedFile): Promise<Finding[]> {
    const findings: Finding[] = [];
    const lines = file.content.split('\n');

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      const lineNum = i + 1;

      // Check for dangerous imports
      if (this.checkDangerousImports(line)) {
        findings.push(this.createFinding(
          file,
          lineNum,
          'Potentially Dangerous Import',
          'Import of a module commonly used in malware or exploits.',
          Severity.MEDIUM,
          ThreatType.DANGEROUS_FUNCTION
        ));
      }

      // Check for pickle usage
      if (this.checkPickleUsage(line)) {
        findings.push(this.createFinding(
          file,
          lineNum,
          'Insecure Pickle Deserialization',
          'Pickle can execute arbitrary code during deserialization.',
          Severity.HIGH,
          ThreatType.INSECURE_DESERIALIZATION
        ));
      }

      // Check for YAML unsafe load
      if (this.checkUnsafeYamlLoad(line)) {
        findings.push(this.createFinding(
          file,
          lineNum,
          'Insecure YAML Load',
          'yaml.load() without Loader can execute arbitrary Python code.',
          Severity.HIGH,
          ThreatType.INSECURE_DESERIALIZATION
        ));
      }

      // Check for subprocess shell=True
      if (this.checkSubprocessShell(line)) {
        findings.push(this.createFinding(
          file,
          lineNum,
          'Subprocess with shell=True',
          'Using shell=True with subprocess can lead to command injection.',
          Severity.HIGH,
          ThreatType.COMMAND_INJECTION
        ));
      }

      // Check for tarfile path traversal
      if (this.checkTarfileTraversal(line)) {
        findings.push(this.createFinding(
          file,
          lineNum,
          'Tarfile Path Traversal Risk',
          'Extracting tar files without validation can lead to path traversal.',
          Severity.MEDIUM,
          ThreatType.PATH_TRAVERSAL
        ));
      }

      // Check for Flask debug mode
      if (this.checkFlaskDebug(line)) {
        findings.push(this.createFinding(
          file,
          lineNum,
          'Flask Debug Mode Enabled',
          'Debug mode in production exposes the Werkzeug debugger.',
          Severity.HIGH,
          ThreatType.SECURITY_MISCONFIGURATION
        ));
      }

      // Check for Django settings vulnerabilities
      if (this.checkDjangoSettings(line)) {
        findings.push(this.createFinding(
          file,
          lineNum,
          'Insecure Django Configuration',
          'Insecure Django setting detected.',
          Severity.MEDIUM,
          ThreatType.SECURITY_MISCONFIGURATION
        ));
      }

      // Check for compile/exec with input
      if (this.checkCompileExec(line)) {
        findings.push(this.createFinding(
          file,
          lineNum,
          'Dynamic Code Compilation/Execution',
          'compile() or exec() may execute arbitrary code.',
          Severity.HIGH,
          ThreatType.DANGEROUS_FUNCTION
        ));
      }
    }

    // Check for requirements.txt if exists
    if (file.relativePath.endsWith('requirements.txt')) {
      const reqFindings = this.analyzeRequirements(file);
      findings.push(...reqFindings);
    }

    return findings;
  }

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
      // Check if Loader is specified
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

  /**
   * Analyze requirements.txt
   */
  private analyzeRequirements(file: ScannedFile): Finding[] {
    const findings: Finding[] = [];
    const lines = file.content.split('\n');

    // Known vulnerable packages (simplified list)
    const vulnerablePackages: Record<string, { version: string; severity: Severity; description: string }> = {
      'pyyaml': { version: '<5.4', severity: Severity.HIGH, description: 'Arbitrary code execution via yaml.load()' },
      'django': { version: '<3.2.4', severity: Severity.HIGH, description: 'Multiple security vulnerabilities' },
      'flask': { version: '<2.0', severity: Severity.MEDIUM, description: 'Security improvements in newer versions' },
      'requests': { version: '<2.20.0', severity: Severity.MEDIUM, description: 'CVE-2018-18074 - HTTPS verification bypass' }
    };

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i].trim().toLowerCase();
      for (const [pkg, info] of Object.entries(vulnerablePackages)) {
        if (line.startsWith(pkg + '==') || line.startsWith(pkg + '<') || line === pkg) {
          findings.push({
            id: generateId(),
            title: `Potentially Vulnerable Package: ${pkg}`,
            description: `${info.description}. Consider upgrading.`,
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
            remediation: `Upgrade ${pkg} to the latest secure version.`,
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
      tags: ['python']
    };
  }
}

export default PythonAnalyzer;
