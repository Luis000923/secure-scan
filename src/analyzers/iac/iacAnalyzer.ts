/**
 * Infrastructure as Code (IaC) Analyzer
 * Analyzes Dockerfile, YAML, Terraform, CI/CD configurations
 */

import { BaseAnalyzer } from '../base';
import { ScannedFile, Finding, Rule, SupportedLanguage, Severity, ThreatType, FindingCategory } from '../../types';
import { generateId, extractCodeContext } from '../../utils';
import { getStandardsForThreat } from '../../rules/standards';

/**
 * IaC Analyzer Class
 */
export class IaCAnalyzer extends BaseAnalyzer {
  name = 'IaC Analyzer';
  languages: SupportedLanguage[] = ['dockerfile', 'yaml', 'terraform'];
  version = '1.0.0';

  /**
   * Analyze IaC file
   */
  async analyze(file: ScannedFile, rules: Rule[]): Promise<Finding[]> {
    const findings: Finding[] = [];

    // Determine file type and analyze accordingly
    if (file.language === 'dockerfile' || file.relativePath.toLowerCase().includes('dockerfile')) {
      const dockerFindings = await this.analyzeDockerfile(file);
      findings.push(...dockerFindings);
    } else if (file.language === 'yaml' || file.extension === '.yml' || file.extension === '.yaml') {
      const yamlFindings = await this.analyzeYaml(file);
      findings.push(...yamlFindings);
    } else if (file.language === 'terraform') {
      const tfFindings = await this.analyzeTerraform(file);
      findings.push(...tfFindings);
    }

    return findings;
  }

  /**
   * Analyze Dockerfile
   */
  private async analyzeDockerfile(file: ScannedFile): Promise<Finding[]> {
    const findings: Finding[] = [];
    const lines = file.content.split('\n');

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i].trim();
      const lineNum = i + 1;

      // Check for running as root
      if (/^USER\s+root/i.test(line)) {
        findings.push(this.createFinding(
          file, lineNum,
          'Container Running as Root',
          'Running containers as root is a security risk.',
          Severity.MEDIUM,
          ThreatType.SECURITY_MISCONFIGURATION
        ));
      }

      // Check for latest tag
      if (/^FROM\s+\S+:latest/i.test(line) || /^FROM\s+[^:]+\s*$/i.test(line)) {
        findings.push(this.createFinding(
          file, lineNum,
          'Using Latest Tag',
          'Using "latest" tag can lead to unpredictable builds.',
          Severity.LOW,
          ThreatType.SECURITY_MISCONFIGURATION
        ));
      }

      // Check for secrets in ENV
      if (/^ENV\s+.*(?:PASSWORD|SECRET|KEY|TOKEN|API_KEY)\s*=/i.test(line)) {
        findings.push(this.createFinding(
          file, lineNum,
          'Secrets in Environment Variable',
          'Secrets should not be baked into images via ENV.',
          Severity.HIGH,
          ThreatType.HARDCODED_CREDENTIALS
        ));
      }

      // Check for ADD instead of COPY
      if (/^ADD\s+https?:\/\//i.test(line)) {
        findings.push(this.createFinding(
          file, lineNum,
          'ADD with Remote URL',
          'ADD with URL can introduce security risks. Use curl/wget with verification.',
          Severity.MEDIUM,
          ThreatType.SECURITY_MISCONFIGURATION
        ));
      }

      // Check for sudo usage
      if (/\bsudo\b/.test(line)) {
        findings.push(this.createFinding(
          file, lineNum,
          'Sudo in Dockerfile',
          'Using sudo in Dockerfile is unnecessary and may indicate issues.',
          Severity.LOW,
          ThreatType.SECURITY_MISCONFIGURATION
        ));
      }

      // Check for curl/wget piped to shell
      if (/(?:curl|wget)\s+[^|]*\|\s*(?:bash|sh)/i.test(line)) {
        findings.push(this.createFinding(
          file, lineNum,
          'Curl Pipe to Shell',
          'Piping curl/wget to shell is dangerous without verification.',
          Severity.HIGH,
          ThreatType.MALICIOUS_LOADER
        ));
      }

      // Check for privileged mode hints
      if (/--privileged|--cap-add/i.test(line)) {
        findings.push(this.createFinding(
          file, lineNum,
          'Privileged Container',
          'Privileged containers can access host resources.',
          Severity.HIGH,
          ThreatType.SECURITY_MISCONFIGURATION
        ));
      }
    }

    return findings;
  }

  /**
   * Analyze YAML (GitHub Actions, GitLab CI, etc.)
   */
  private async analyzeYaml(file: ScannedFile): Promise<Finding[]> {
    const findings: Finding[] = [];
    const lines = file.content.split('\n');
    const isGitHubActions = file.relativePath.includes('.github/workflows');
    const isGitLabCI = file.relativePath.includes('.gitlab-ci');

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      const lineNum = i + 1;

      // Check for secrets in plain text
      if (/(?:password|secret|api_key|token|key):\s*["']?[^${\s][^"'\s]+/i.test(line)) {
        findings.push(this.createFinding(
          file, lineNum,
          'Hardcoded Secret in YAML',
          'Secrets should use environment variables or secret management.',
          Severity.HIGH,
          ThreatType.HARDCODED_CREDENTIALS
        ));
      }

      // GitHub Actions specific checks
      if (isGitHubActions) {
        // Check for pull_request_target with checkout
        if (/pull_request_target/.test(line)) {
          findings.push(this.createFinding(
            file, lineNum,
            'pull_request_target Event',
            'pull_request_target with actions/checkout can be dangerous.',
            Severity.MEDIUM,
            ThreatType.SECURITY_MISCONFIGURATION
          ));
        }

        // Check for script injection
        if (/\$\{\{\s*github\.event\..*\.body\s*\}\}/.test(line) ||
            /\$\{\{\s*github\.event\..*\.title\s*\}\}/.test(line)) {
          findings.push(this.createFinding(
            file, lineNum,
            'Potential Script Injection',
            'Using untrusted input in run commands can lead to injection.',
            Severity.HIGH,
            ThreatType.COMMAND_INJECTION
          ));
        }

        // Check for third-party actions without pinning
        if (/uses:\s*\S+\/\S+@(?:main|master|v\d+)/.test(line)) {
          findings.push(this.createFinding(
            file, lineNum,
            'Unpinned GitHub Action',
            'Pin actions to commit SHA for supply chain security.',
            Severity.LOW,
            ThreatType.SECURITY_MISCONFIGURATION
          ));
        }
      }

      // Check for curl/wget to shell
      if (/(?:curl|wget)\s+[^|]*\|\s*(?:bash|sh)/i.test(line)) {
        findings.push(this.createFinding(
          file, lineNum,
          'Curl Pipe to Shell in CI',
          'Dangerous pattern that can execute malicious code.',
          Severity.HIGH,
          ThreatType.MALICIOUS_LOADER
        ));
      }
    }

    return findings;
  }

  /**
   * Analyze Terraform
   */
  private async analyzeTerraform(file: ScannedFile): Promise<Finding[]> {
    const findings: Finding[] = [];
    const lines = file.content.split('\n');

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      const lineNum = i + 1;

      // Check for hardcoded secrets
      if (/(?:password|secret|api_key|access_key|secret_key)\s*=\s*["'][^"'$]+["']/i.test(line)) {
        findings.push(this.createFinding(
          file, lineNum,
          'Hardcoded Secret in Terraform',
          'Use variables or secret management for sensitive values.',
          Severity.HIGH,
          ThreatType.HARDCODED_CREDENTIALS
        ));
      }

      // Check for open security groups
      if (/cidr_blocks\s*=\s*\[\s*["']0\.0\.0\.0\/0["']\s*\]/.test(line)) {
        findings.push(this.createFinding(
          file, lineNum,
          'Open Security Group',
          'Security group allows access from any IP address.',
          Severity.HIGH,
          ThreatType.SECURITY_MISCONFIGURATION
        ));
      }

      // Check for unencrypted storage
      if (/encrypted\s*=\s*false/i.test(line)) {
        findings.push(this.createFinding(
          file, lineNum,
          'Unencrypted Storage',
          'Storage resources should be encrypted at rest.',
          Severity.MEDIUM,
          ThreatType.SECURITY_MISCONFIGURATION
        ));
      }

      // Check for public access
      if (/publicly_accessible\s*=\s*true/i.test(line)) {
        findings.push(this.createFinding(
          file, lineNum,
          'Publicly Accessible Resource',
          'Resources should not be publicly accessible unless required.',
          Severity.HIGH,
          ThreatType.SECURITY_MISCONFIGURATION
        ));
      }

      // Check for HTTP instead of HTTPS
      if (/protocol\s*=\s*["']HTTP["']/i.test(line)) {
        findings.push(this.createFinding(
          file, lineNum,
          'HTTP Protocol Used',
          'Use HTTPS for secure communication.',
          Severity.MEDIUM,
          ThreatType.SECURITY_MISCONFIGURATION
        ));
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
      remediation: 'Review and fix the identified configuration issue.',
      confidence: 80,
      analyzer: this.name,
      timestamp: new Date(),
      tags: ['iac', 'infrastructure', 'devops']
    };
  }
}

export default IaCAnalyzer;
