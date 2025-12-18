/**
 * JavaScript/TypeScript Analyzer
 * Specialized analyzer for JavaScript and TypeScript code
 */

import { BaseAnalyzer } from '../base';
import { ScannedFile, Finding, Rule, SupportedLanguage, Severity, ThreatType, FindingCategory } from '../../types';
import { generateId, extractCodeContext, looksObfuscated, calculateEntropy } from '../../utils';
import { getStandardsForThreat } from '../../rules/standards';
import { logger } from '../../utils/logger';

/**
 * JavaScript Analyzer Class
 */
export class JavaScriptAnalyzer extends BaseAnalyzer {
  name = 'JavaScript Analyzer';
  languages: SupportedLanguage[] = ['javascript', 'typescript'];
  version = '1.0.0';

  /**
   * Analyze JavaScript/TypeScript file
   */
  async analyze(file: ScannedFile, rules: Rule[]): Promise<Finding[]> {
    const findings: Finding[] = [];

    // Filter rules for JS/TS
    const jsRules = rules.filter(r =>
      r.languages.includes('javascript') || r.languages.includes('typescript')
    );

    // Run rule engine
    const ruleFindings = await this.ruleEngine.analyzeFile(file, jsRules);
    findings.push(...ruleFindings);

    // Additional JS-specific analysis
    const customFindings = await this.customAnalysis(file);
    findings.push(...customFindings);

    return findings;
  }

  /**
   * Custom JavaScript-specific analysis
   */
  private async customAnalysis(file: ScannedFile): Promise<Finding[]> {
    const findings: Finding[] = [];
    const content = file.content;
    const lines = content.split('\n');

    // Check for obfuscated code
    if (looksObfuscated(content)) {
      findings.push(this.createObfuscationFinding(file));
    }

    // Check for suspicious patterns
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      const lineNum = i + 1;

      // Check for prototype pollution
      if (this.checkPrototypePollution(line)) {
        findings.push(this.createFinding(
          file,
          lineNum,
          'Prototype Pollution Risk',
          'Direct assignment to __proto__ or Object.prototype detected.',
          Severity.HIGH,
          ThreatType.DANGEROUS_FUNCTION
        ));
      }

      // Check for DOM XSS sinks
      if (this.checkDomXssSinks(line)) {
        findings.push(this.createFinding(
          file,
          lineNum,
          'Potential DOM-based XSS',
          'User-controllable data flows into DOM XSS sink.',
          Severity.HIGH,
          ThreatType.XSS
        ));
      }

      // Check for insecure postMessage
      if (this.checkInsecurePostMessage(line)) {
        findings.push(this.createFinding(
          file,
          lineNum,
          'Insecure postMessage Usage',
          'postMessage with wildcard origin or missing origin check.',
          Severity.MEDIUM,
          ThreatType.SECURITY_MISCONFIGURATION
        ));
      }
    }

    // Check for npm package.json postinstall scripts
    if (file.relativePath.endsWith('package.json')) {
      const packageFindings = await this.analyzePackageJson(file);
      findings.push(...packageFindings);
    }

    return findings;
  }

  /**
   * Check for prototype pollution patterns
   */
  private checkPrototypePollution(line: string): boolean {
    const patterns = [
      /__proto__\s*[=\[]/,
      /Object\.prototype\s*\./,
      /constructor\.prototype/,
      /\[['"]__proto__['"]\]/
    ];
    return patterns.some(p => p.test(line));
  }

  /**
   * Check for DOM XSS sinks
   */
  private checkDomXssSinks(line: string): boolean {
    const sinks = [
      /\.innerHTML\s*=\s*(?!['"`])/,
      /\.outerHTML\s*=\s*(?!['"`])/,
      /document\.write\s*\(/,
      /document\.writeln\s*\(/,
      /\.insertAdjacentHTML\s*\(/,
      /location\s*=\s*(?!['"`])/,
      /location\.href\s*=\s*(?!['"`])/
    ];
    return sinks.some(p => p.test(line));
  }

  /**
   * Check for insecure postMessage
   */
  private checkInsecurePostMessage(line: string): boolean {
    if (line.includes('postMessage')) {
      // Check for wildcard origin
      if (/postMessage\s*\([^)]+,\s*['"]\*['"]\)/.test(line)) {
        return true;
      }
    }
    if (line.includes('addEventListener') && line.includes('message')) {
      // Check for missing origin validation
      if (!/event\.origin|e\.origin|msg\.origin/.test(line)) {
        return true;
      }
    }
    return false;
  }

  /**
   * Analyze package.json for suspicious scripts
   */
  private async analyzePackageJson(file: ScannedFile): Promise<Finding[]> {
    const findings: Finding[] = [];

    try {
      const pkg = JSON.parse(file.content);

      // Check for suspicious lifecycle scripts
      const suspiciousScripts = ['preinstall', 'postinstall', 'preuninstall', 'postuninstall'];
      
      if (pkg.scripts) {
        for (const script of suspiciousScripts) {
          if (pkg.scripts[script]) {
            const scriptContent = pkg.scripts[script];
            
            // Check for obviously malicious patterns
            if (this.isSuspiciousNpmScript(scriptContent)) {
              findings.push({
                id: generateId(),
                title: 'Suspicious npm Lifecycle Script',
                description: `The ${script} script contains potentially malicious commands that run automatically during npm install.`,
                severity: Severity.HIGH,
                threatType: ThreatType.MALICIOUS_LOADER,
                category: FindingCategory.MALWARE,
                location: {
                  file: file.relativePath,
                  startLine: 1,
                  endLine: 1
                },
                snippet: {
                  code: `"${script}": "${scriptContent}"`
                },
                standards: getStandardsForThreat(ThreatType.MALICIOUS_LOADER),
                remediation: 'Review npm lifecycle scripts carefully. Remove if not needed. Use npm config set ignore-scripts true for untrusted packages.',
                confidence: 80,
                analyzer: this.name,
                timestamp: new Date(),
                tags: ['npm', 'supply-chain', 'malware']
              });
            }
          }
        }
      }
    } catch {
      // Not valid JSON, skip
    }

    return findings;
  }

  /**
   * Check if npm script looks suspicious
   */
  private isSuspiciousNpmScript(script: string): boolean {
    const suspiciousPatterns = [
      /curl\s+.*\|\s*(?:sh|bash)/i,
      /wget\s+.*\|\s*(?:sh|bash)/i,
      /node\s+-e\s+["'][^"']*(?:http|fetch|require)/i,
      /base64\s+-d/i,
      /eval\s*\(/i,
      /\$\(curl/i,
      /powershell\s+-/i
    ];
    return suspiciousPatterns.some(p => p.test(script));
  }

  /**
   * Create obfuscation finding
   */
  private createObfuscationFinding(file: ScannedFile): Finding {
    const entropy = calculateEntropy(file.content);
    return {
      id: generateId(),
      title: 'Heavily Obfuscated JavaScript Code',
      description: `This file contains heavily obfuscated code (entropy: ${entropy.toFixed(2)}). This is unusual for legitimate code and may hide malicious functionality.`,
      severity: Severity.HIGH,
      threatType: ThreatType.OBFUSCATED_CODE,
      category: FindingCategory.MALWARE,
      location: {
        file: file.relativePath,
        startLine: 1,
        endLine: Math.min(10, file.lineCount)
      },
      snippet: {
        code: file.content.substring(0, 200) + '...'
      },
      standards: getStandardsForThreat(ThreatType.OBFUSCATED_CODE),
      remediation: 'Deobfuscate and review the code. If this is a third-party library, verify its source and integrity.',
      confidence: 75,
      analyzer: this.name,
      timestamp: new Date(),
      tags: ['obfuscation', 'suspicious']
    };
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
      confidence: 70,
      analyzer: this.name,
      timestamp: new Date(),
      tags: ['javascript']
    };
  }
}

export default JavaScriptAnalyzer;
