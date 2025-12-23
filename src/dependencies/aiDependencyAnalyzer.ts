/**
 * AI Dependency Analyzer
 * Uses AI/ML for advanced dependency risk analysis
 */

import { AIConfig, Severity } from '../types';
import { 
  Dependency, 
  DependencyVulnerability,
  DependencyRiskCategory,
  DependencyRecommendation,
  SupplyChainRisk
} from './types';
import { logger } from '../utils/logger';
import { generateId } from '../utils';
import { getStandardsForDependencyRisk } from './detectors/securityStandards';

/**
 * AI Analysis Result for Dependencies
 */
export interface AIDependencyAnalysisResult {
  /** Risk assessment */
  riskAssessment: string;
  /** Confidence score (0-100) */
  confidence: number;
  /** Detected anomalies */
  anomalies: string[];
  /** Priority recommendations */
  priorityRecommendations: string[];
  /** Overall risk score (0-100) */
  overallRiskScore: number;
}

/**
 * AI Dependency Analyzer Class
 * Provides AI-powered analysis for dependencies
 */
export class AIDependencyAnalyzer {
  private config: AIConfig;
  private initialized: boolean = false;

  constructor(config: AIConfig) {
    this.config = config;
  }

  /**
   * Initialize AI analyzer
   */
  async initialize(): Promise<void> {
    if (!this.config.apiKey && this.config.provider !== 'local') {
      logger.warn('⚠️ AI API key not provided. AI dependency analysis will be limited.');
      return;
    }

    logger.info('🤖 Initializing AI dependency analyzer...');
    this.initialized = true;
  }

  /**
   * Analyze dependencies with AI
   */
  async analyzeDependencies(
    dependencies: Dependency[],
    existingVulnerabilities: DependencyVulnerability[]
  ): Promise<AIDependencyAnalysisResult> {
    if (!this.initialized) {
      return this.getDefaultResult();
    }

    try {
      switch (this.config.provider) {
        case 'openai':
          return await this.analyzeWithOpenAI(dependencies, existingVulnerabilities);
        case 'anthropic':
          return await this.analyzeWithAnthropic(dependencies, existingVulnerabilities);
        case 'local':
          return await this.analyzeWithLocal(dependencies, existingVulnerabilities);
        default:
          return this.getDefaultResult();
      }
    } catch (error) {
      logger.debug(`AI dependency analysis error: ${error}`);
      return this.getDefaultResult();
    }
  }

  /**
   * Analyze single dependency for anomalies
   */
  async analyzeForAnomalies(dependency: Dependency): Promise<DependencyVulnerability[]> {
    if (!this.initialized) {
      return [];
    }

    const vulnerabilities: DependencyVulnerability[] = [];

    try {
      const analysis = await this.analyzePackageMetadata(dependency);
      
      if (analysis.suspiciousPatterns.length > 0) {
        vulnerabilities.push({
          id: generateId(),
          dependency,
          severity: analysis.severity,
          category: DependencyRiskCategory.SUPPLY_CHAIN,
          title: `AI-Detected Anomaly: ${dependency.name}`,
          description: `AI analysis detected suspicious patterns in ${dependency.name}: ${analysis.suspiciousPatterns.join(', ')}`,
          supplyChainRisks: analysis.risks,
          standards: getStandardsForDependencyRisk(DependencyRiskCategory.SUPPLY_CHAIN),
          recommendation: DependencyRecommendation.REVIEW,
          recommendationDetails: analysis.recommendation,
          confidence: analysis.confidence,
          timestamp: new Date(),
          aiExplanation: analysis.explanation
        });
      }
    } catch (error) {
      logger.debug(`AI anomaly detection error for ${dependency.name}: ${error}`);
    }

    return vulnerabilities;
  }

  /**
   * Prioritize vulnerabilities using AI
   */
  async prioritizeVulnerabilities(
    vulnerabilities: DependencyVulnerability[]
  ): Promise<DependencyVulnerability[]> {
    if (!this.initialized || vulnerabilities.length === 0) {
      return vulnerabilities;
    }

    try {
      // Get AI-generated priority scores
      const prioritized = await this.getAIPrioritization(vulnerabilities);
      return prioritized;
    } catch (error) {
      logger.debug(`AI prioritization error: ${error}`);
      return vulnerabilities;
    }
  }

  /**
   * Generate AI explanation for a vulnerability
   */
  async generateExplanation(vulnerability: DependencyVulnerability): Promise<string> {
    if (!this.initialized) {
      return '';
    }

    try {
      const prompt = this.buildExplanationPrompt(vulnerability);
      const explanation = await this.callAI(prompt);
      return explanation;
    } catch (error) {
      logger.debug(`AI explanation error: ${error}`);
      return '';
    }
  }

  /**
   * Analyze with OpenAI
   */
  private async analyzeWithOpenAI(
    dependencies: Dependency[],
    vulnerabilities: DependencyVulnerability[]
  ): Promise<AIDependencyAnalysisResult> {
    const OpenAI = (await import('openai')).default;
    
    const client = new OpenAI({
      apiKey: this.config.apiKey
    });

    const prompt = this.buildAnalysisPrompt(dependencies, vulnerabilities);

    const response = await client.chat.completions.create({
      model: this.config.model || 'gpt-4',
      messages: [
        {
          role: 'system',
          content: this.getSystemPrompt()
        },
        {
          role: 'user',
          content: prompt
        }
      ],
      max_tokens: this.config.maxTokens || 2000,
      temperature: this.config.temperature || 0.1
    });

    const content = response.choices[0]?.message?.content;
    return this.parseAIResponse(content || '');
  }

  /**
   * Analyze with Anthropic
   */
  private async analyzeWithAnthropic(
    dependencies: Dependency[],
    vulnerabilities: DependencyVulnerability[]
  ): Promise<AIDependencyAnalysisResult> {
    const Anthropic = (await import('@anthropic-ai/sdk')).default;
    
    const client = new Anthropic({
      apiKey: this.config.apiKey
    });

    const prompt = this.buildAnalysisPrompt(dependencies, vulnerabilities);

    const response = await client.messages.create({
      model: this.config.model || 'claude-3-opus-20240229',
      max_tokens: this.config.maxTokens || 2000,
      system: this.getSystemPrompt(),
      messages: [
        {
          role: 'user',
          content: prompt
        }
      ]
    });

    const content = response.content[0]?.type === 'text' ? response.content[0].text : '';
    return this.parseAIResponse(content);
  }

  /**
   * Analyze with local model
   */
  private async analyzeWithLocal(
    dependencies: Dependency[],
    vulnerabilities: DependencyVulnerability[]
  ): Promise<AIDependencyAnalysisResult> {
    const endpoint = this.config.endpoint || 'http://localhost:11434/api/generate';
    const prompt = this.buildAnalysisPrompt(dependencies, vulnerabilities);

    const response = await fetch(endpoint, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        model: this.config.model || 'llama2',
        prompt: `${this.getSystemPrompt()}\n\n${prompt}`,
        stream: false
      })
    });

    const data = await response.json() as { response?: string };
    return this.parseAIResponse(data.response || '');
  }

  /**
   * Build analysis prompt
   */
  private buildAnalysisPrompt(
    dependencies: Dependency[],
    vulnerabilities: DependencyVulnerability[]
  ): string {
    const depSummary = dependencies.slice(0, 50).map(d => 
      `- ${d.name}@${d.version} (${d.ecosystem}, ${d.dependencyType})`
    ).join('\n');

    const vulnSummary = vulnerabilities.map(v =>
      `- ${v.title} (${v.severity}, ${v.category}): ${v.description.substring(0, 100)}...`
    ).join('\n');

    return `
Analyze the following project dependencies for security risks:

## Dependencies (${dependencies.length} total, showing first 50):
${depSummary}

## Known Vulnerabilities (${vulnerabilities.length}):
${vulnSummary || 'None detected'}

Please provide:
1. Overall risk assessment
2. Any suspicious patterns or anomalies
3. Priority recommendations for remediation
4. Risk score (0-100)

Respond in JSON format with keys: riskAssessment, anomalies (array), priorityRecommendations (array), overallRiskScore (number), confidence (number 0-100)
`;
  }

  /**
   * Build explanation prompt
   */
  private buildExplanationPrompt(vulnerability: DependencyVulnerability): string {
    return `
Explain this dependency vulnerability in simple terms:

Package: ${vulnerability.dependency.name}@${vulnerability.dependency.version}
Ecosystem: ${vulnerability.dependency.ecosystem}
Issue: ${vulnerability.title}
Description: ${vulnerability.description}
Severity: ${vulnerability.severity}
Category: ${vulnerability.category}

Provide:
1. What the vulnerability means
2. How it could be exploited
3. Immediate actions to take
4. Long-term recommendations

Keep the explanation concise and actionable.
`;
  }

  /**
   * Get system prompt
   */
  private getSystemPrompt(): string {
    return `You are a security expert specializing in Software Composition Analysis (SCA) and supply chain security. 
Your role is to analyze project dependencies for:
- Known vulnerabilities (CVEs)
- Supply chain risks (typosquatting, abandoned packages, suspicious releases)
- Malicious packages (backdoors, cryptominers, data exfiltration)
- Outdated or deprecated components

Provide clear, actionable recommendations following security best practices.
Reference OWASP, CWE, and MITRE ATT&CK frameworks where applicable.
Always prioritize critical and high-severity issues.`;
  }

  /**
   * Parse AI response
   */
  private parseAIResponse(content: string): AIDependencyAnalysisResult {
    try {
      // Try to extract JSON from the response
      const jsonMatch = content.match(/\{[\s\S]*\}/);
      if (jsonMatch) {
        const parsed = JSON.parse(jsonMatch[0]);
        return {
          riskAssessment: parsed.riskAssessment || 'Unable to assess',
          confidence: parsed.confidence || 50,
          anomalies: parsed.anomalies || [],
          priorityRecommendations: parsed.priorityRecommendations || [],
          overallRiskScore: parsed.overallRiskScore || 50
        };
      }
    } catch (error) {
      logger.debug(`Failed to parse AI response: ${error}`);
    }

    return this.getDefaultResult();
  }

  /**
   * Get default result when AI is unavailable
   */
  private getDefaultResult(): AIDependencyAnalysisResult {
    return {
      riskAssessment: 'AI analysis not available',
      confidence: 0,
      anomalies: [],
      priorityRecommendations: [],
      overallRiskScore: 0
    };
  }

  /**
   * Analyze package metadata for anomalies
   */
  private async analyzePackageMetadata(dependency: Dependency): Promise<{
    suspiciousPatterns: string[];
    risks: SupplyChainRisk[];
    severity: Severity;
    confidence: number;
    recommendation: string;
    explanation: string;
  }> {
    // Heuristic-based analysis (can be enhanced with actual package metadata)
    const suspiciousPatterns: string[] = [];
    const risks: SupplyChainRisk[] = [];
    
    // Check package name patterns
    const name = dependency.name.toLowerCase();
    
    // Check for suspicious naming patterns
    if (/^[a-z]+-[a-z]+-[a-z]+-[a-z]+$/.test(name)) {
      // Random-looking name pattern
      suspiciousPatterns.push('Unusual naming pattern');
    }
    
    // Check version for pre-release or suspicious versions
    const version = dependency.version;
    if (version.includes('alpha') || version.includes('beta') || version.includes('rc')) {
      suspiciousPatterns.push('Pre-release version in production');
    }
    
    // Check for 0.0.x versions
    if (/^0\.0\.\d+/.test(version)) {
      suspiciousPatterns.push('Very early version (0.0.x)');
      risks.push(SupplyChainRisk.NEW_PACKAGE);
    }

    const severity = suspiciousPatterns.length >= 2 ? Severity.MEDIUM : Severity.LOW;
    const confidence = 40 + (suspiciousPatterns.length * 20);

    return {
      suspiciousPatterns,
      risks,
      severity,
      confidence: Math.min(confidence, 90),
      recommendation: suspiciousPatterns.length > 0 
        ? `Review ${dependency.name} before using in production. Verify package authenticity and check for recent changes.`
        : 'No suspicious patterns detected.',
      explanation: suspiciousPatterns.length > 0
        ? `The package ${dependency.name} exhibits patterns that may indicate supply chain risk: ${suspiciousPatterns.join(', ')}`
        : ''
    };
  }

  /**
   * Get AI-based prioritization
   */
  private async getAIPrioritization(
    vulnerabilities: DependencyVulnerability[]
  ): Promise<DependencyVulnerability[]> {
    // For now, use heuristic-based prioritization
    // In production, this would call the AI model
    
    return vulnerabilities.sort((a, b) => {
      // Priority factors:
      // 1. Severity
      const severityOrder: Record<Severity, number> = {
        [Severity.CRITICAL]: 0,
        [Severity.HIGH]: 1,
        [Severity.MEDIUM]: 2,
        [Severity.LOW]: 3,
        [Severity.INFO]: 4
      };
      
      const severityDiff = severityOrder[a.severity] - severityOrder[b.severity];
      if (severityDiff !== 0) return severityDiff;
      
      // 2. Category priority (malicious > vulnerability > supply chain > outdated)
      const categoryOrder: Record<DependencyRiskCategory, number> = {
        [DependencyRiskCategory.MALICIOUS]: 0,
        [DependencyRiskCategory.VULNERABILITY]: 1,
        [DependencyRiskCategory.SUPPLY_CHAIN]: 2,
        [DependencyRiskCategory.OUTDATED]: 3,
        [DependencyRiskCategory.MAINTENANCE]: 4,
        [DependencyRiskCategory.LICENSE]: 5
      };
      
      const categoryDiff = categoryOrder[a.category] - categoryOrder[b.category];
      if (categoryDiff !== 0) return categoryDiff;
      
      // 3. Direct dependencies over transitive
      const depTypeOrder = { direct: 0, dev: 1, peer: 2, optional: 3, transitive: 4 };
      return (depTypeOrder[a.dependency.dependencyType] || 4) - 
             (depTypeOrder[b.dependency.dependencyType] || 4);
    });
  }

  /**
   * Call AI API
   */
  private async callAI(prompt: string): Promise<string> {
    switch (this.config.provider) {
      case 'openai':
        const OpenAI = (await import('openai')).default;
        const openaiClient = new OpenAI({ apiKey: this.config.apiKey });
        const openaiResponse = await openaiClient.chat.completions.create({
          model: this.config.model || 'gpt-4',
          messages: [
            { role: 'system', content: this.getSystemPrompt() },
            { role: 'user', content: prompt }
          ],
          max_tokens: 1000
        });
        return openaiResponse.choices[0]?.message?.content || '';

      case 'anthropic':
        const Anthropic = (await import('@anthropic-ai/sdk')).default;
        const anthropicClient = new Anthropic({ apiKey: this.config.apiKey });
        const anthropicResponse = await anthropicClient.messages.create({
          model: this.config.model || 'claude-3-opus-20240229',
          max_tokens: 1000,
          system: this.getSystemPrompt(),
          messages: [{ role: 'user', content: prompt }]
        });
        return anthropicResponse.content[0]?.type === 'text' 
          ? anthropicResponse.content[0].text 
          : '';

      default:
        return '';
    }
  }
}

export default AIDependencyAnalyzer;
