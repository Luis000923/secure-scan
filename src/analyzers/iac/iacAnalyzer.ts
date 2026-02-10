/**
 * Infrastructure as Code (IaC) Analyzer
 * Analyzes Dockerfile, YAML, Terraform, Kubernetes, Helm, and CI/CD configurations
 * Enhanced with comprehensive cloud security patterns
 */

import { BaseAnalyzer } from '../base';
import { ScannedFile, Finding, SupportedLanguage, Severity, ThreatType, FindingCategory, SecurityStandard } from '../../types';
import { generateId } from '../../utils';
import { getStandardsForThreat } from '../../rules/standards';

/**
 * IaC Analyzer Class
 */
export class IaCAnalyzer extends BaseAnalyzer {
  name = 'IaC Analyzer';
  languages: SupportedLanguage[] = ['dockerfile', 'yaml', 'terraform'];
  version = '2.1.0';

  /**
   * Perform custom IaC-specific analysis
   * Template Method pattern - called by BaseAnalyzer.analyze()
   */
  protected async performCustomAnalysis(file: ScannedFile): Promise<Finding[]> {
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
        findings.push(this.buildFinding({
          file, lineNum,
          title: 'Container Running as Root',
          description: 'Running containers as root is a security risk.',
          severity: Severity.MEDIUM,
          threatType: ThreatType.SECURITY_MISCONFIGURATION
        }));
      }

      // Check for latest tag
      if (/^FROM\s+\S+:latest/i.test(line) || /^FROM\s+[^:]+\s*$/i.test(line)) {
        findings.push(this.buildFinding({
          file, lineNum,
          title: 'Using Latest Tag',
          description: 'Using "latest" tag can lead to unpredictable builds.',
          severity: Severity.LOW,
          threatType: ThreatType.SECURITY_MISCONFIGURATION
        }));
      }

      // Check for secrets in ENV
      if (/^ENV\s+.*(?:PASSWORD|SECRET|KEY|TOKEN|API_KEY)\s*=/i.test(line)) {
        findings.push(this.buildFinding({
          file, lineNum,
          title: 'Secrets in Environment Variable',
          description: 'Secrets should not be baked into images via ENV.',
          severity: Severity.HIGH,
          threatType: ThreatType.HARDCODED_CREDENTIALS
        }));
      }

      // Check for ADD instead of COPY
      if (/^ADD\s+https?:\/\//i.test(line)) {
        findings.push(this.buildFinding({
          file, lineNum,
          title: 'ADD with Remote URL',
          description: 'ADD with URL can introduce security risks. Use curl/wget with verification.',
          severity: Severity.MEDIUM,
          threatType: ThreatType.SECURITY_MISCONFIGURATION
        }));
      }

      // Check for sudo usage
      if (/\bsudo\b/.test(line)) {
        findings.push(this.buildFinding({
          file, lineNum,
          title: 'Sudo in Dockerfile',
          description: 'Using sudo in Dockerfile is unnecessary and may indicate issues.',
          severity: Severity.LOW,
          threatType: ThreatType.SECURITY_MISCONFIGURATION
        }));
      }

      // Check for curl/wget piped to shell
      if (/(?:curl|wget)\s+[^|]*\|\s*(?:bash|sh)/i.test(line)) {
        findings.push(this.buildFinding({
          file, lineNum,
          title: 'Curl Pipe to Shell',
          description: 'Piping curl/wget to shell is dangerous without verification.',
          severity: Severity.HIGH,
          threatType: ThreatType.MALICIOUS_LOADER
        }));
      }

      // Check for privileged mode hints
      if (/--privileged|--cap-add/i.test(line)) {
        findings.push(this.buildFinding({
          file, lineNum,
          title: 'Privileged Container',
          description: 'Privileged containers can access host resources.',
          severity: Severity.HIGH,
          threatType: ThreatType.SECURITY_MISCONFIGURATION
        }));
      }
    }

    return findings;
  }

  /**
   * Analyze YAML (GitHub Actions, GitLab CI, Kubernetes, Helm)
   */
  private async analyzeYaml(file: ScannedFile): Promise<Finding[]> {
    const findings: Finding[] = [];
    const lines = file.content.split('\n');
    const content = file.content;
    const isGitHubActions = file.relativePath.includes('.github/workflows');
    const isGitLabCI = file.relativePath.includes('.gitlab-ci');
    const isKubernetes = this.isKubernetesManifest(content);
    const isHelm = this.isHelmChart(file.relativePath, content);

    // Kubernetes-specific analysis
    if (isKubernetes || isHelm) {
      const k8sFindings = this.analyzeKubernetes(file, content, lines);
      findings.push(...k8sFindings);
    }

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      const lineNum = i + 1;

      // Check for secrets in plain text
      if (/(?:password|secret|api_key|token|key):\s*["']?[^${\s][^"'\s]+/i.test(line)) {
        findings.push(this.buildFinding({
          file, lineNum,
          title: 'Hardcoded Secret in YAML',
          description: 'Secrets should use environment variables or secret management.',
          severity: Severity.HIGH,
          threatType: ThreatType.HARDCODED_CREDENTIALS
        }));
      }

      // GitHub Actions specific checks
      if (isGitHubActions) {
        // Check for pull_request_target with checkout
        if (/pull_request_target/.test(line)) {
          findings.push(this.buildFinding({
            file, lineNum,
            title: 'pull_request_target Event',
            description: 'pull_request_target with actions/checkout can be dangerous.',
            severity: Severity.MEDIUM,
            threatType: ThreatType.SECURITY_MISCONFIGURATION
          }));
        }

        // Check for script injection
        if (/\$\{\{\s*github\.event\..*\.body\s*\}\}/.test(line) ||
            /\$\{\{\s*github\.event\..*\.title\s*\}\}/.test(line)) {
          findings.push(this.buildFinding({
            file, lineNum,
            title: 'Potential Script Injection',
            description: 'Using untrusted input in run commands can lead to injection.',
            severity: Severity.HIGH,
            threatType: ThreatType.COMMAND_INJECTION
          }));
        }

        // Check for third-party actions without pinning
        if (/uses:\s*\S+\/\S+@(?:main|master|v\d+)/.test(line)) {
          findings.push(this.buildFinding({
            file, lineNum,
            title: 'Unpinned GitHub Action',
            description: 'Pin actions to commit SHA for supply chain security.',
            severity: Severity.LOW,
            threatType: ThreatType.SECURITY_MISCONFIGURATION
          }));
        }
      }

      // Check for curl/wget to shell
      if (/(?:curl|wget)\s+[^|]*\|\s*(?:bash|sh)/i.test(line)) {
        findings.push(this.buildFinding({
          file, lineNum,
          title: 'Curl Pipe to Shell in CI',
          description: 'Dangerous pattern that can execute malicious code.',
          severity: Severity.HIGH,
          threatType: ThreatType.MALICIOUS_LOADER
        }));
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
        findings.push(this.buildFinding({
          file, lineNum,
          title: 'Hardcoded Secret in Terraform',
          description: 'Use variables or secret management for sensitive values.',
          severity: Severity.HIGH,
          threatType: ThreatType.HARDCODED_CREDENTIALS
        }));
      }

      // Check for open security groups
      if (/cidr_blocks\s*=\s*\[\s*["']0\.0\.0\.0\/0["']\s*\]/.test(line)) {
        findings.push(this.buildFinding({
          file, lineNum,
          title: 'Open Security Group',
          description: 'Security group allows access from any IP address.',
          severity: Severity.HIGH,
          threatType: ThreatType.SECURITY_MISCONFIGURATION
        }));
      }

      // Check for unencrypted storage
      if (/encrypted\s*=\s*false/i.test(line)) {
        findings.push(this.buildFinding({
          file, lineNum,
          title: 'Unencrypted Storage',
          description: 'Storage resources should be encrypted at rest.',
          severity: Severity.MEDIUM,
          threatType: ThreatType.SECURITY_MISCONFIGURATION
        }));
      }

      // Check for public access
      if (/publicly_accessible\s*=\s*true/i.test(line)) {
        findings.push(this.buildFinding({
          file, lineNum,
          title: 'Publicly Accessible Resource',
          description: 'Resources should not be publicly accessible unless required.',
          severity: Severity.HIGH,
          threatType: ThreatType.SECURITY_MISCONFIGURATION
        }));
      }

      // Check for HTTP instead of HTTPS
      if (/protocol\s*=\s*["']HTTP["']/i.test(line)) {
        findings.push(this.buildFinding({
          file, lineNum,
          title: 'HTTP Protocol Used',
          description: 'Use HTTPS for secure communication.',
          severity: Severity.MEDIUM,
          threatType: ThreatType.SECURITY_MISCONFIGURATION
        }));
      }
    }

    // AWS IAM policy analysis
    const iamFindings = this.analyzeAwsIam(file, file.content, lines);
    findings.push(...iamFindings);

    return findings;
  }

  /**
   * Analyze AWS IAM policies in Terraform
   */
  private analyzeAwsIam(file: ScannedFile, content: string, lines: string[]): Finding[] {
    const findings: Finding[] = [];

    const iamPatterns = [
      // Wildcard actions
      {
        pattern: /"Action":\s*\[?\s*["']\*["']/gi,
        name: 'IAM Wildcard Action',
        severity: Severity.CRITICAL,
        description: 'IAM policy allows all actions (*) which is overly permissive.',
        recommendation: 'Specify only required actions following least privilege.',
      },
      // Wildcard resources
      {
        pattern: /"Resource":\s*\[?\s*["']\*["']/gi,
        name: 'IAM Wildcard Resource',
        severity: Severity.HIGH,
        description: 'IAM policy applies to all resources (*).',
        recommendation: 'Specify specific resource ARNs.',
      },
      // Admin access
      {
        pattern: /arn:aws:iam::aws:policy\/AdministratorAccess/gi,
        name: 'Administrator Access Policy',
        severity: Severity.CRITICAL,
        description: 'AdministratorAccess policy grants full AWS access.',
        recommendation: 'Use custom least-privilege policies.',
      },
      // Assume role with *
      {
        pattern: /"Principal":\s*\{?\s*"AWS":\s*["']\*["']/gi,
        name: 'IAM Trust Policy Open Principal',
        severity: Severity.CRITICAL,
        description: 'Trust policy allows any AWS principal to assume role.',
        recommendation: 'Restrict Principal to specific accounts/roles.',
      },
      // S3 full access
      {
        pattern: /"Action":\s*\[?\s*["']s3:\*["']/gi,
        name: 'S3 Full Access',
        severity: Severity.HIGH,
        description: 'IAM policy grants full S3 access.',
        recommendation: 'Limit to specific S3 actions (s3:GetObject, s3:PutObject).',
      },
      // EC2 full access
      {
        pattern: /"Action":\s*\[?\s*["']ec2:\*["']/gi,
        name: 'EC2 Full Access',
        severity: Severity.HIGH,
        description: 'IAM policy grants full EC2 access.',
        recommendation: 'Limit to specific EC2 actions needed.',
      },
      // IAM full access
      {
        pattern: /"Action":\s*\[?\s*["']iam:\*["']/gi,
        name: 'IAM Full Access',
        severity: Severity.CRITICAL,
        description: 'IAM policy grants full IAM access (privilege escalation risk).',
        recommendation: 'Avoid granting iam:* - high privilege escalation risk.',
      },
      // PassRole without condition
      {
        pattern: /"Action":\s*\[?[^\]]*["']iam:PassRole["'][^\]]*\]?(?![^}]*"Condition")/gi,
        name: 'PassRole Without Condition',
        severity: Severity.MEDIUM,
        description: 'iam:PassRole without conditions can enable privilege escalation.',
        recommendation: 'Add Condition to restrict which roles can be passed.',
      },
      // KMS decrypt without condition
      {
        pattern: /"Action":\s*\[?[^\]]*["']kms:Decrypt["'][^\]]*\]?[^}]*"Resource":\s*\[?\s*["']\*["']/gi,
        name: 'KMS Decrypt All Keys',
        severity: Severity.HIGH,
        description: 'kms:Decrypt on all resources allows decrypting any key.',
        recommendation: 'Restrict to specific KMS key ARNs.',
      },
      // Lambda full access
      {
        pattern: /"Action":\s*\[?\s*["']lambda:\*["']/gi,
        name: 'Lambda Full Access',
        severity: Severity.HIGH,
        description: 'Full Lambda access can be used for code execution attacks.',
        recommendation: 'Limit to specific Lambda actions.',
      },
      // STS assume role *
      {
        pattern: /"Action":\s*\[?[^\]]*["']sts:AssumeRole["'][^\]]*\]?[^}]*"Resource":\s*\[?\s*["']\*["']/gi,
        name: 'Assume Any Role',
        severity: Severity.CRITICAL,
        description: 'Can assume any role in the account.',
        recommendation: 'Restrict to specific role ARNs.',
      },
      // NotAction usage
      {
        pattern: /"NotAction":/gi,
        name: 'NotAction Usage',
        severity: Severity.MEDIUM,
        description: 'NotAction can be confusing and lead to over-permissive policies.',
        recommendation: 'Use explicit Action lists instead of NotAction.',
      },
      // NotResource usage
      {
        pattern: /"NotResource":/gi,
        name: 'NotResource Usage',
        severity: Severity.MEDIUM,
        description: 'NotResource can lead to unintended access.',
        recommendation: 'Use explicit Resource ARNs instead of NotResource.',
      },
    ];

    for (const p of iamPatterns) {
      p.pattern.lastIndex = 0;
      let match;
      while ((match = p.pattern.exec(content)) !== null) {
        const lineNum = this.calculateLineNumber(content, match.index);
        findings.push(this.buildFinding({
          file,
          lineNum,
          title: p.name,
          description: p.description,
          severity: p.severity,
          threatType: ThreatType.SECURITY_MISCONFIGURATION,
          standards: this.getAwsIamStandards(),
          remediation: p.recommendation,
          confidence: 85,
          tags: ['aws', 'iam', 'terraform', 'iac']
        }));
      }
    }

    return findings;
  }

  /**
   * Get AWS IAM security standards
   */
  private getAwsIamStandards(): SecurityStandard[] {
    return [
      {
        name: 'CIS' as const,
        id: 'CIS-AWS',
        title: 'CIS AWS Foundations Benchmark',
        description: 'CIS security benchmark for AWS.',
        url: 'https://www.cisecurity.org/benchmark/amazon_web_services'
      },
      {
        name: 'AWS' as const,
        id: 'AWS-Well-Architected',
        title: 'AWS Well-Architected Security Pillar',
        description: 'AWS security best practices.',
        url: 'https://docs.aws.amazon.com/wellarchitected/latest/security-pillar/welcome.html'
      }
    ];
  }

  /**
   * Check if content is a Kubernetes manifest
   */
  private isKubernetesManifest(content: string): boolean {
    return /apiVersion:\s*\S+/.test(content) && /kind:\s*(?:Pod|Deployment|Service|StatefulSet|DaemonSet|Job|CronJob|ConfigMap|Secret|Ingress|NetworkPolicy|ServiceAccount|Role|RoleBinding|ClusterRole|ClusterRoleBinding)/i.test(content);
  }

  /**
   * Check if file is a Helm chart
   */
  private isHelmChart(relativePath: string, content: string): boolean {
    return relativePath.includes('/templates/') || 
           relativePath.endsWith('values.yaml') ||
           /\{\{\s*\.Values\./.test(content) ||
           /\{\{\s*include\s+/.test(content);
  }

  /**
   * Analyze Kubernetes manifests and Helm charts
   */
  private analyzeKubernetes(file: ScannedFile, content: string, lines: string[]): Finding[] {
    const findings: Finding[] = [];

    const k8sPatterns = [
      // Privileged containers
      {
        pattern: /privileged:\s*true/gi,
        name: 'Privileged Container',
        severity: Severity.CRITICAL,
        description: 'Privileged containers have full access to host resources.',
        recommendation: 'Set privileged: false unless absolutely necessary.',
      },
      // Running as root
      {
        pattern: /runAsUser:\s*0/gi,
        name: 'Container Running as Root',
        severity: Severity.HIGH,
        description: 'Container is configured to run as root user.',
        recommendation: 'Set runAsNonRoot: true and use a non-zero runAsUser.',
      },
      // Allow privilege escalation
      {
        pattern: /allowPrivilegeEscalation:\s*true/gi,
        name: 'Privilege Escalation Allowed',
        severity: Severity.HIGH,
        description: 'Container allows privilege escalation.',
        recommendation: 'Set allowPrivilegeEscalation: false.',
      },
      // Host network
      {
        pattern: /hostNetwork:\s*true/gi,
        name: 'Host Network Mode',
        severity: Severity.HIGH,
        description: 'Pod uses host network namespace.',
        recommendation: 'Avoid hostNetwork unless required for network monitoring.',
      },
      // Host PID
      {
        pattern: /hostPID:\s*true/gi,
        name: 'Host PID Namespace',
        severity: Severity.HIGH,
        description: 'Pod shares host PID namespace.',
        recommendation: 'Avoid hostPID: true.',
      },
      // Host IPC
      {
        pattern: /hostIPC:\s*true/gi,
        name: 'Host IPC Namespace',
        severity: Severity.MEDIUM,
        description: 'Pod shares host IPC namespace.',
        recommendation: 'Avoid hostIPC: true.',
      },
      // Capabilities - ALL
      {
        pattern: /capabilities:[\s\S]*?add:[\s\S]*?-\s*(?:ALL|SYS_ADMIN|NET_ADMIN)/gi,
        name: 'Dangerous Capabilities',
        severity: Severity.CRITICAL,
        description: 'Container has dangerous Linux capabilities.',
        recommendation: 'Drop all capabilities and add only what is needed.',
      },
      // No resource limits
      {
        pattern: /resources:\s*\{\}/gi,
        name: 'Missing Resource Limits',
        severity: Severity.MEDIUM,
        description: 'Container has no resource limits defined.',
        recommendation: 'Set CPU and memory limits to prevent DoS.',
      },
      // Read-only root filesystem
      {
        pattern: /readOnlyRootFilesystem:\s*false/gi,
        name: 'Writable Root Filesystem',
        severity: Severity.MEDIUM,
        description: 'Container has writable root filesystem.',
        recommendation: 'Set readOnlyRootFilesystem: true.',
      },
      // Service account tokens
      {
        pattern: /automountServiceAccountToken:\s*true/gi,
        name: 'Auto-mounted Service Account Token',
        severity: Severity.LOW,
        description: 'Service account token automatically mounted.',
        recommendation: 'Set automountServiceAccountToken: false if not needed.',
      },
      // Secrets in env
      {
        pattern: /value:\s*["']?(?:password|secret|key|token)[=:]/gi,
        name: 'Hardcoded Secret in Manifest',
        severity: Severity.HIGH,
        description: 'Secret appears to be hardcoded in manifest.',
        recommendation: 'Use Kubernetes Secrets or external secret management.',
      },
      // Default namespace
      {
        pattern: /namespace:\s*["']?default["']?/gi,
        name: 'Using Default Namespace',
        severity: Severity.LOW,
        description: 'Workload deployed to default namespace.',
        recommendation: 'Use dedicated namespaces for isolation.',
      },
      // No network policy
      {
        pattern: /kind:\s*Deployment[\s\S]*?(?!NetworkPolicy)/gi,
        name: 'Consider Network Policy',
        severity: Severity.INFO,
        description: 'No NetworkPolicy found for restricting traffic.',
        recommendation: 'Implement NetworkPolicy for network segmentation.',
      },
      // Latest tag
      {
        pattern: /image:\s*\S+:latest/gi,
        name: 'Using Latest Image Tag',
        severity: Severity.MEDIUM,
        description: 'Using latest tag leads to unpredictable deployments.',
        recommendation: 'Pin images to specific versions or digests.',
      },
      // No liveness/readiness probes
      {
        pattern: /containers:[\s\S]*?(?!livenessProbe)[\s\S]*?(?!readinessProbe)/gi,
        name: 'Missing Health Probes',
        severity: Severity.LOW,
        description: 'Container may lack liveness/readiness probes.',
        recommendation: 'Add livenessProbe and readinessProbe for reliability.',
      },
    ];

    for (const p of k8sPatterns) {
      p.pattern.lastIndex = 0;
      let match;
      while ((match = p.pattern.exec(content)) !== null) {
        const lineNum = this.calculateLineNumber(content, match.index);
        findings.push(this.buildFinding({
          file,
          lineNum,
          title: p.name,
          description: p.description,
          severity: p.severity,
          threatType: ThreatType.SECURITY_MISCONFIGURATION,
          standards: this.getK8sStandards(),
          remediation: p.recommendation,
          confidence: 85,
          tags: ['kubernetes', 'iac', 'container-security']
        }));
      }
    }

    // RBAC over-permissive patterns
    const rbacPatterns = [
      {
        pattern: /verbs:[\s\S]*?['"]\*['"]/gi,
        name: 'RBAC Wildcard Verbs',
        severity: Severity.HIGH,
        description: 'RBAC rule allows all verbs (*) on resources.',
        recommendation: 'Specify only required verbs (get, list, watch, etc.).',
      },
      {
        pattern: /resources:[\s\S]*?['"]\*['"]/gi,
        name: 'RBAC Wildcard Resources',
        severity: Severity.HIGH,
        description: 'RBAC rule applies to all resources (*).',
        recommendation: 'Specify only required resources.',
      },
      {
        pattern: /kind:\s*ClusterRoleBinding[\s\S]*?cluster-admin/gi,
        name: 'Cluster Admin Binding',
        severity: Severity.CRITICAL,
        description: 'Binding grants cluster-admin privileges.',
        recommendation: 'Avoid cluster-admin, use least-privilege roles.',
      },
    ];

    for (const p of rbacPatterns) {
      p.pattern.lastIndex = 0;
      let match;
      while ((match = p.pattern.exec(content)) !== null) {
        const lineNum = this.calculateLineNumber(content, match.index);
        findings.push(this.buildFinding({
          file,
          lineNum,
          title: p.name,
          description: p.description,
          severity: p.severity,
          threatType: ThreatType.SECURITY_MISCONFIGURATION,
          standards: this.getK8sStandards(),
          remediation: p.recommendation,
          confidence: 90,
          tags: ['kubernetes', 'rbac', 'iac']
        }));
      }
    }

    return findings;
  }

  /**
   * Get Kubernetes-specific security standards
   */
  private getK8sStandards(): SecurityStandard[] {
    return [
      {
        name: 'CIS' as const,
        id: 'CIS-K8s',
        title: 'CIS Kubernetes Benchmark',
        description: 'Center for Internet Security Kubernetes Benchmark.',
        url: 'https://www.cisecurity.org/benchmark/kubernetes'
      },
      {
        name: 'NSA' as const,
        id: 'NSA-CISA',
        title: 'NSA/CISA Kubernetes Hardening Guide',
        description: 'Kubernetes hardening guidance from NSA and CISA.',
        url: 'https://media.defense.gov/2022/Aug/29/2003066362/-1/-1/0/CTR_KUBERNETES_HARDENING_GUIDANCE_1.2_20220829.PDF'
      }
    ];
  }

}

export default IaCAnalyzer;
