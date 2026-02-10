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
 * Raw finding structure returned by AI providers.
 * Used to validate and convert AI responses before creating typed Finding objects.
 */
interface RawAIFinding {
  title?: string;
  severity?: string;
  type?: string;
  line?: number | string;
  description?: string;
  remediation?: string;
}

/**
 * Google AI API response structure
 */
interface GoogleAIResponse {
  candidates?: Array<{
    content?: {
      parts?: Array<{
        text?: string;
      }>;
    };
  }>;
  error?: {
    code?: number;
    message?: string;
  };
}

/**
 * Ollama performance options
 */
interface OllamaOptions {
  num_predict: number;
  temperature: number;
  num_gpu?: number;
  num_thread?: number;
  num_ctx?: number;
  num_batch?: number;
  use_mmap?: boolean;
  use_mlock?: boolean;
}

/**
 * Detected AI Provider
 */
type DetectedProvider = 'openai' | 'anthropic' | 'google' | 'local';

/**
 * AI Analyzer Class
 * Provides AI-powered security analysis
 */
export class AIAnalyzer {
  private config: AIConfig;
  private initialized: boolean = false;
  private detectedProvider: DetectedProvider = 'openai';
  private static readonly MAX_RETRIES = 3;
  private static readonly BASE_RETRY_DELAY_MS = 1000;

  constructor(config: AIConfig) {
    this.config = config;
    // Auto-detect provider from API key if set to 'auto' or not specified correctly
    this.detectedProvider = this.detectProvider();
  }

  /**
   * Auto-detect AI provider from API key format
   */
  private detectProvider(): DetectedProvider {
    const apiKey = this.config.apiKey || '';
    const provider = this.config.provider;

    // If explicitly set to local, use local
    if (provider === 'local') {
      return 'local';
    }

    // Auto-detect from API key format
    if (apiKey.startsWith('sk-ant-') || apiKey.startsWith('sk-ant')) {
      logger.debug('🔍 Detected Anthropic API key');
      return 'anthropic';
    }

    if (apiKey.startsWith('AIzaSy') || apiKey.startsWith('AIza')) {
      logger.debug('🔍 Detected Google AI API key');
      return 'google';
    }

    if (apiKey.startsWith('sk-') || apiKey.startsWith('sk-proj-')) {
      logger.debug('🔍 Detected OpenAI API key');
      return 'openai';
    }

    // Fallback to configured provider or openai
    if (provider === 'google' || provider === 'gemini') {
      return 'google';
    }
    if (provider === 'anthropic') {
      return 'anthropic';
    }
    if (provider === 'openai') {
      return 'openai';
    }

    // Default to openai if we can't detect
    return 'openai';
  }

  /**
   * Initialize AI analyzer
   */
  async initialize(): Promise<void> {
    if (!this.config.apiKey && this.detectedProvider !== 'local') {
      logger.warn('⚠️ AI API key not provided. AI analysis will be limited.');
      return;
    }

    const providerName = this.detectedProvider === 'google' ? 'Google AI (Gemini)' :
      this.detectedProvider === 'anthropic' ? 'Anthropic (Claude)' :
        this.detectedProvider === 'openai' ? 'OpenAI (GPT)' : 'Local';

    logger.info(`🤖 Initializing AI analyzer with ${providerName}...`);
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
      switch (this.detectedProvider) {
        case 'openai':
          return await this.analyzeWithOpenAI(file);
        case 'anthropic':
          return await this.analyzeWithAnthropic(file);
        case 'google':
          return await this.analyzeWithGoogle(file);
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
   * Get the best model for the provider
   */
  private getModel(): string {
    if (this.config.model) {
      return this.config.model;
    }

    // Default models per provider
    switch (this.detectedProvider) {
      case 'openai':
        return 'gpt-4o'; // Latest and most capable
      case 'anthropic':
        return 'claude-3-sonnet-20240229';
      case 'google':
        return 'gemini-pro'; // Stable model for v1beta API
      default:
        return 'gpt-4';
    }
  }

  /**
   * Analyze with OpenAI (supports all GPT models)
   */
  private async analyzeWithOpenAI(file: ScannedFile): Promise<AIAnalysisResult> {
    // Dynamic import to avoid issues if package not installed
    const OpenAI = (await import('openai')).default;

    const client = new OpenAI({
      apiKey: this.config.apiKey
    });

    const prompt = this.buildAnalysisPrompt(file);
    const model = this.getModel();

    logger.debug(`Using OpenAI model: ${model}`);

    try {
      const response = await client.chat.completions.create({
        model: model,
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
    } catch (error: unknown) {
      const apiError = error as { status?: number; message?: string };
      if (apiError?.status === 429) {
        logger.warn('⚠️ OpenAI: Cuota excedida. Verifica tu plan en https://platform.openai.com/account/billing');
      } else if (apiError?.status === 401) {
        logger.warn('⚠️ OpenAI: API key inválida');
      } else {
        const message = apiError?.message || String(error);
        logger.debug(`OpenAI error: ${message}`);
      }
      return { findings: [] };
    }
  }

  /**
   * Analyze with Anthropic Claude
   */
  private async analyzeWithAnthropic(file: ScannedFile): Promise<AIAnalysisResult> {
    try {
      const Anthropic = (await import('@anthropic-ai/sdk')).default;

      const client = new Anthropic({
        apiKey: this.config.apiKey
      });

      const prompt = this.buildAnalysisPrompt(file);
      const model = this.getModel();

      logger.debug(`Using Anthropic model: ${model}`);

      const response = await client.messages.create({
        model: model,
        max_tokens: this.config.maxTokens || 2000,
        system: this.getSystemPrompt(),
        messages: [
          {
            role: 'user',
            content: prompt
          }
        ]
      });

      const content = response.content[0];
      if (!content || content.type !== 'text') {
        return { findings: [] };
      }

      return this.parseAIResponse(content.text, file);
    } catch (error) {
      logger.debug(`Anthropic analysis error: ${error}`);
      return { findings: [] };
    }
  }

  /**
   * Analyze with Google AI (Gemini)
   */
  private async analyzeWithGoogle(file: ScannedFile): Promise<AIAnalysisResult> {
    try {
      const prompt = this.buildAnalysisPrompt(file);
      const model = this.getModel();

      logger.debug(`Using Google AI model: ${model}`);

      // Use Google AI REST API directly
      const apiKey = this.config.apiKey;

      // Try v1 API first, fallback to v1beta
      const apis = [
        `https://generativelanguage.googleapis.com/v1/models/${model}:generateContent?key=${apiKey}`,
        `https://generativelanguage.googleapis.com/v1beta/models/${model}:generateContent?key=${apiKey}`
      ];

      let lastError: GoogleAIResponse['error'] | Error | null = null;

      for (const url of apis) {
        try {
          const response = await fetch(url, {
            method: 'POST',
            headers: {
              'Content-Type': 'application/json'
            },
            body: JSON.stringify({
              contents: [
                {
                  parts: [
                    {
                      text: `${this.getSystemPrompt()}\n\n${prompt}`
                    }
                  ]
                }
              ],
              generationConfig: {
                temperature: this.config.temperature || 0.1,
                maxOutputTokens: this.config.maxTokens || 2000
              }
            })
          });

          const data = await response.json() as GoogleAIResponse;

          if (!response.ok) {
            lastError = data.error;
            continue; // Try next API version
          }

          const content = data.candidates?.[0]?.content?.parts?.[0]?.text;

          if (!content) {
            return { findings: [] };
          }

          return this.parseAIResponse(content, file);
        } catch (e) {
          lastError = e as Error;
          continue;
        }
      }

      // If all APIs failed, show helpful message
      if (lastError) {
        const errorCode = (lastError as GoogleAIResponse['error'])?.code;
        if (errorCode === 404) {
          logger.warn(`⚠️ Google AI: Modelo "${model}" no disponible. Intenta con: gemini-pro`);
        } else if (errorCode === 403) {
          logger.warn('⚠️ Google AI: API key sin permisos. Habilita la API en Google Cloud Console.');
        } else if (errorCode === 429) {
          logger.warn('⚠️ Google AI: Cuota excedida. Espera un momento o verifica tu plan.');
        } else {
          logger.debug(`Google AI error: ${JSON.stringify(lastError)}`);
        }
      }

      return { findings: [] };
    } catch (error) {
      logger.debug(`Google AI analysis error: ${error}`);
      return { findings: [] };
    }
  }

  // Cache for local AI results
  private analysisCache: Map<string, AIAnalysisResult> = new Map();

  /**
   * Analyze with local model (Ollama compatible) - Optimized for performance
   */
  private async analyzeWithLocal(file: ScannedFile): Promise<AIAnalysisResult> {
    if (!this.config.endpoint) {
      logger.warn('Local AI endpoint not configured');
      return { findings: [] };
    }

    // Check cache first
    const perf = this.config.performance || {};
    if (perf.enableCache) {
      const cacheKey = `${file.hash}-${this.config.model}`;
      const cached = this.analysisCache.get(cacheKey);
      if (cached) {
        logger.debug(`⚡ Cache hit for ${file.relativePath}`);
        return cached;
      }
    }

    const prompt = this.buildAnalysisPrompt(file);
    const model = this.config.model || 'codellama:7b-instruct';

    try {
      logger.debug(`🤖 Usando modelo local: ${model}`);

      // Build Ollama options with performance tuning
      const ollamaOptions: OllamaOptions = {
        num_predict: this.config.maxTokens || 2000,
        temperature: this.config.temperature || 0.1,
      };

      // Apply performance settings
      if (perf.numGpuLayers !== undefined) {
        ollamaOptions.num_gpu = perf.numGpuLayers;
      }
      if (perf.numThreads !== undefined) {
        ollamaOptions.num_thread = perf.numThreads;
      }
      if (perf.contextSize !== undefined) {
        ollamaOptions.num_ctx = perf.contextSize;
      }
      if (perf.batchSize !== undefined) {
        ollamaOptions.num_batch = perf.batchSize;
      }
      if (perf.useMmap !== undefined) {
        ollamaOptions.use_mmap = perf.useMmap;
      }
      if (perf.useMlock !== undefined) {
        ollamaOptions.use_mlock = perf.useMlock;
      }

      // Use AbortController for timeout
      const controller = new AbortController();
      const timeout = perf.timeout || 120000; // 2 minutes default
      const timeoutId = setTimeout(() => controller.abort(), timeout);

      const response = await fetch(this.config.endpoint, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          model: model,
          prompt: `${this.getSystemPrompt()}\n\n${prompt}`,
          stream: false,
          options: ollamaOptions
        }),
        signal: controller.signal
      });

      clearTimeout(timeoutId);

      if (!response.ok) {
        const errorText = await response.text();
        logger.warn(`⚠️ Error del modelo local (${response.status}): ${errorText}`);
        return { findings: [] };
      }

      const data = await response.json() as { response?: string; content?: string; message?: { content?: string } };
      const content = data.response || data.content || data.message?.content || '';

      if (!content) {
        logger.debug('El modelo local no devolvió respuesta');
        return { findings: [] };
      }

      const result = this.parseAIResponse(content, file);

      // Store in cache
      if (perf.enableCache) {
        const cacheKey = `${file.hash}-${this.config.model}`;
        this.analysisCache.set(cacheKey, result);
      }

      return result;
    } catch (error: unknown) {
      const err = error as { name?: string; code?: string; message?: string };
      if (err.name === 'AbortError') {
        logger.warn(`⚠️ Timeout analizando ${file.relativePath}`);
      } else if (err.code === 'ECONNREFUSED') {
        logger.warn('⚠️ No se puede conectar al servidor local. ¿Está Ollama ejecutándose?');
        logger.info('💡 Inicia Ollama con: ollama serve');
      } else {
        logger.debug(`Local AI error: ${err.message || String(error)}`);
      }
      return { findings: [] };
    }
  }

  /**
   * Analyze multiple files in parallel (for local models)
   */
  async analyzeParallel(files: ScannedFile[]): Promise<Map<string, AIAnalysisResult>> {
    const results = new Map<string, AIAnalysisResult>();
    const parallelRequests = this.config.performance?.parallelRequests || 1;

    // Process in batches
    for (let i = 0; i < files.length; i += parallelRequests) {
      const batch = files.slice(i, i + parallelRequests);
      const batchPromises = batch.map(async (file) => {
        const result = await this.analyze(file);
        return { path: file.relativePath, result };
      });

      const batchResults = await Promise.all(batchPromises);
      for (const { path, result } of batchResults) {
        results.set(path, result);
      }
    }

    return results;
  }

  /**
   * Clear the analysis cache
   */
  clearCache(): void {
    this.analysisCache.clear();
    logger.debug('🗑️ AI analysis cache cleared');
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
   * Convert raw AI finding to typed Finding object.
   * Validates required fields before conversion.
   */
  private convertToFinding(item: RawAIFinding, file: ScannedFile): Finding | null {
    if (!item.title || !item.severity) {
      return null;
    }

    const severity = this.parseSeverity(item.severity);
    const threatType = this.parseThreatType(item.type || '');
    const lineNum = parseInt(String(item.line)) || 1;

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
