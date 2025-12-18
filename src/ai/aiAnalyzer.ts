/**
 * AI Analyzer Module
 * Uses AI/ML for advanced threat detection and analysis
 */

import { AIConfig, Finding, ScannedFile, Severity, ThreatType, FindingCategory } from '../types';
import { logger } from '../utils/logger';
import { generateId } from '../utils';
import { getStandardsForThreat } from '../rules/standards';

/**
 * AI Analysis Result
 */
interface AIAnalysisResult {
  findings: Finding[];
  explanation?: string;
  suggestedFixes?: string[];
  riskAssessment?: string;
}

/**
 * AI Analyzer Class
 * Provides AI-powered security analysis
 */
export class AIAnalyzer {
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
      logger.warn('⚠️ AI API key not provided. AI analysis will be limited.');
      return;
    }

    logger.info('🤖 Initializing AI analyzer...');
    this.initialized = true;
  }

  /**
   * Analyze code with AI
   */
  async analyze(file: ScannedFile): Promise<AIAnalysisResult> {
    if (!this.initialized) {
      return { findings: [] };
    }

    try {
      switch (this.config.provider) {
        case 'openai':
          return await this.analyzeWithOpenAI(file);
        case 'anthropic':
          return await this.analyzeWithAnthropic(file);
        case 'local':
          return await this.analyzeWithLocal(file);
        default:
          return { findings: [] };
      }
    } catch (error) {
      logger.debug(`AI analysis error: ${error}`);
      return { findings: [] };
    }
  }

  /**
   * Analyze with OpenAI
   */
  private async analyzeWithOpenAI(file: ScannedFile): Promise<AIAnalysisResult> {
    // Dynamic import to avoid issues if package not installed
    const OpenAI = (await import('openai')).default;
    
    const client = new OpenAI({
      apiKey: this.config.apiKey
    });

    const prompt = this.buildAnalysisPrompt(file);

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
    if (!content) {
      return { findings: [] };
    }

    return this.parseAIResponse(content, file);
  }

  /**
   * Analyze with Anthropic Claude
   */
  private async analyzeWithAnthropic(file: ScannedFile): Promise<AIAnalysisResult> {
    // Placeholder for Anthropic integration
    // Would use @anthropic-ai/sdk
    logger.debug('Anthropic integration not implemented yet');
    return { findings: [] };
  }

  /**
   * Analyze with local model
   */
  private async analyzeWithLocal(file: ScannedFile): Promise<AIAnalysisResult> {
    if (!this.config.endpoint) {
      logger.warn('Local AI endpoint not configured');
      return { findings: [] };
    }

    const prompt = this.buildAnalysisPrompt(file);

    try {
      const response = await fetch(this.config.endpoint, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          prompt: `${this.getSystemPrompt()}\n\n${prompt}`,
          max_tokens: this.config.maxTokens || 2000,
          temperature: this.config.temperature || 0.1
        })
      });

      const data = await response.json() as { response?: string; content?: string };
      return this.parseAIResponse(data.response || data.content || '', file);
    } catch (error) {
      logger.debug(`Local AI error: ${error}`);
      return { findings: [] };
    }
  }

  /**
   * Get system prompt for AI
   */
  private getSystemPrompt(): string {
    return `You are an expert security analyst specializing in static code analysis (SAST).
Your task is to analyze code for:
1. Security vulnerabilities (SQL injection, XSS, command injection, etc.)
2. Malicious code patterns (backdoors, keyloggers, data exfiltration)
3. Insecure configurations
4. Hardcoded credentials

For each finding, provide:
- Title: Brief description
- Severity: critical, high, medium, low, or info
- Type: vulnerability type (sql_injection, xss, backdoor, etc.)
- Line: approximate line number
- Description: detailed explanation
- Remediation: how to fix

Respond in JSON format:
{
  "findings": [
    {
      "title": "...",
      "severity": "...",
      "type": "...",
      "line": 123,
      "description": "...",
      "remediation": "..."
    }
  ],
  "riskAssessment": "Overall risk assessment",
  "explanation": "Summary of analysis"
}

Be precise and avoid false positives. Focus on real security issues.`;
  }

  /**
   * Build analysis prompt
   */
  private buildAnalysisPrompt(file: ScannedFile): string {
    // Truncate large files
    const maxLength = 8000;
    const content = file.content.length > maxLength 
      ? file.content.substring(0, maxLength) + '\n... (truncated)'
      : file.content;

    return `Analyze this ${file.language || 'unknown'} code file for security issues:

File: ${file.relativePath}
Language: ${file.language || 'unknown'}

\`\`\`
${content}
\`\`\`

Identify all security vulnerabilities and malicious code patterns.`;
  }

  /**
   * Parse AI response into findings
   */
  private parseAIResponse(response: string, file: ScannedFile): AIAnalysisResult {
    try {
      // Extract JSON from response
      const jsonMatch = response.match(/\{[\s\S]*\}/);
      if (!jsonMatch) {
        return { findings: [] };
      }

      const parsed = JSON.parse(jsonMatch[0]);
      const findings: Finding[] = [];

      for (const item of parsed.findings || []) {
        const finding = this.convertToFinding(item, file);
        if (finding) {
          findings.push(finding);
        }
      }

      return {
        findings,
        explanation: parsed.explanation,
        riskAssessment: parsed.riskAssessment
      };
    } catch (error) {
      logger.debug(`Failed to parse AI response: ${error}`);
      return { findings: [] };
    }
  }

  /**
   * Convert AI finding to Finding type
   */
  private convertToFinding(item: any, file: ScannedFile): Finding | null {
    if (!item.title || !item.severity) {
      return null;
    }

    const severity = this.parseSeverity(item.severity);
    const threatType = this.parseThreatType(item.type);
    const lineNum = parseInt(item.line) || 1;

    // Extract code context
    const lines = file.content.split('\n');
    const code = lines[lineNum - 1] || '';
    const contextBefore = lines.slice(Math.max(0, lineNum - 3), lineNum - 1).join('\n');
    const contextAfter = lines.slice(lineNum, Math.min(lines.length, lineNum + 2)).join('\n');

    return {
      id: generateId(),
      title: item.title,
      description: item.description || item.title,
      severity,
      threatType,
      category: this.ismalwareType(threatType) ? FindingCategory.MALWARE : FindingCategory.VULNERABILITY,
      location: {
        file: file.relativePath,
        startLine: lineNum,
        endLine: lineNum
      },
      snippet: {
        code,
        contextBefore,
        contextAfter
      },
      standards: getStandardsForThreat(threatType),
      remediation: item.remediation || 'Review and fix the identified issue.',
      confidence: 70,
      analyzer: 'AI Analyzer',
      timestamp: new Date(),
      tags: ['ai-detected'],
      aiExplanation: item.description,
      suggestedFix: item.remediation
    };
  }

  /**
   * Parse severity string
   */
  private parseSeverity(severity: string): Severity {
    const lower = severity.toLowerCase();
    if (lower.includes('critical')) return Severity.CRITICAL;
    if (lower.includes('high')) return Severity.HIGH;
    if (lower.includes('medium')) return Severity.MEDIUM;
    if (lower.includes('low')) return Severity.LOW;
    return Severity.INFO;
  }

  /**
   * Parse threat type string
   */
  private parseThreatType(type: string): ThreatType {
    const lower = (type || '').toLowerCase().replace(/[_-]/g, '');
    
    const typeMap: Record<string, ThreatType> = {
      'sqlinjection': ThreatType.SQL_INJECTION,
      'sqli': ThreatType.SQL_INJECTION,
      'commandinjection': ThreatType.COMMAND_INJECTION,
      'cmdi': ThreatType.COMMAND_INJECTION,
      'xss': ThreatType.XSS,
      'crosssitescripting': ThreatType.XSS,
      'csrf': ThreatType.CSRF,
      'deserialization': ThreatType.INSECURE_DESERIALIZATION,
      'hardcodedcredentials': ThreatType.HARDCODED_CREDENTIALS,
      'credentials': ThreatType.HARDCODED_CREDENTIALS,
      'pathtraversal': ThreatType.PATH_TRAVERSAL,
      'lfi': ThreatType.PATH_TRAVERSAL,
      'backdoor': ThreatType.BACKDOOR,
      'keylogger': ThreatType.KEYLOGGER,
      'cryptominer': ThreatType.CRYPTOMINER,
      'obfuscation': ThreatType.OBFUSCATED_CODE,
      'exfiltration': ThreatType.DATA_EXFILTRATION
    };

    return typeMap[lower] || ThreatType.DANGEROUS_FUNCTION;
  }

  /**
   * Check if threat type is malware
   */
  private ismalwareType(type: ThreatType): boolean {
    const malwareTypes = [
      ThreatType.BACKDOOR,
      ThreatType.KEYLOGGER,
      ThreatType.CRYPTOMINER,
      ThreatType.OBFUSCATED_CODE,
      ThreatType.EMBEDDED_PAYLOAD,
      ThreatType.REVERSE_SHELL,
      ThreatType.DATA_EXFILTRATION,
      ThreatType.MALICIOUS_LOADER
    ];
    return malwareTypes.includes(type);
  }

  /**
   * Enhance finding with AI explanation
   */
  async enhanceFinding(finding: Finding): Promise<Finding> {
    if (!this.initialized || !this.config.apiKey) {
      return finding;
    }

    try {
      const OpenAI = (await import('openai')).default;
      const client = new OpenAI({ apiKey: this.config.apiKey });

      const response = await client.chat.completions.create({
        model: this.config.model || 'gpt-4',
        messages: [
          {
            role: 'system',
            content: 'You are a security expert. Provide a clear, technical explanation of the security issue and a specific code fix.'
          },
          {
            role: 'user',
            content: `Explain this security finding and provide a fix:

Title: ${finding.title}
Type: ${finding.threatType}
Code:
\`\`\`
${finding.snippet.code}
\`\`\`

Provide a 2-3 sentence explanation and a corrected code example.`
          }
        ],
        max_tokens: 500,
        temperature: 0.2
      });

      const content = response.choices[0]?.message?.content;
      if (content) {
        finding.aiExplanation = content;
      }
    } catch (error) {
      logger.debug(`Failed to enhance finding: ${error}`);
    }

    return finding;
  }
}

export default AIAnalyzer;
