/**
 * Security Scanner Orchestrator
 * Main scanner that coordinates all analyzers
 */

import * as path from 'path';
import * as fs from 'fs';
import { 
  ScanConfig, 
  ScanResult, 
  Finding, 
  ScannedFile, 
  ScanStats,
  Severity,
  FindingCategory
} from '../types';
import { FileScanner } from '../core/scanner';
import { RuleEngine } from '../core/engine';
import { RiskScoringEngine } from '../core/scoring';
import { getAllRules, getEnabledRules } from '../rules';
import { getAllAnalyzers, initializeAnalyzers, cleanupAnalyzers, getAnalyzerForLanguage } from '../analyzers';
import { AIAnalyzer } from '../ai';
import { HtmlReportGenerator } from '../reports';
import { generateId, isHigherOrEqualSeverity } from '../utils';
import { logger, logScanStart, logScanComplete, logFinding } from '../utils/logger';

/**
 * Security Scanner Class
 * Main orchestrator for the SAST tool
 */
export class SecurityScanner {
  private config: ScanConfig;
  private fileScanner: FileScanner;
  private ruleEngine: RuleEngine;
  private riskScoring: RiskScoringEngine;
  private aiAnalyzer?: AIAnalyzer;

  constructor(config: ScanConfig) {
    this.config = this.normalizeConfig(config);
    this.fileScanner = new FileScanner(this.config);
    this.ruleEngine = new RuleEngine();
    this.riskScoring = new RiskScoringEngine();

    // Initialize AI analyzer if configured
    if (this.config.useAI && this.config.aiConfig) {
      this.aiAnalyzer = new AIAnalyzer(this.config.aiConfig);
    }
  }

  /**
   * Normalize and validate configuration
   */
  private normalizeConfig(config: ScanConfig): ScanConfig {
    return {
      ...config,
      projectPath: path.resolve(config.projectPath),
      exclude: config.exclude || [],
      minSeverity: config.minSeverity || Severity.INFO,
      verbose: config.verbose || false,
      maxFileSize: config.maxFileSize || 5 * 1024 * 1024,
      fileTimeout: config.fileTimeout || 30000
    };
  }

  /**
   * Run the security scan
   */
  async scan(): Promise<ScanResult> {
    const startTime = Date.now();
    const scanId = generateId();

    logScanStart(this.config.projectPath);

    try {
      // Initialize analyzers
      await initializeAnalyzers();
      if (this.aiAnalyzer) {
        await this.aiAnalyzer.initialize();
      }

      // Load rules
      const rules = getEnabledRules();
      this.ruleEngine.loadRules(rules);

      // Scan files
      logger.info('📂 Scanning project files...');
      const files = await this.fileScanner.scan();

      if (files.length === 0) {
        logger.warn('⚠️ No files found to analyze');
        return this.createEmptyResult(scanId, startTime);
      }

      // Analyze files
      logger.info('🔍 Analyzing code for vulnerabilities and malware...');
      const allFindings: Finding[] = [];

      for (let i = 0; i < files.length; i++) {
        const file = files[i];
        
        if (this.config.verbose) {
          logger.debug(`Analyzing: ${file.relativePath}`);
        }

        try {
          const fileFindings = await this.analyzeFile(file);
          allFindings.push(...fileFindings);

          // Log critical findings immediately
          for (const finding of fileFindings) {
            if (finding.severity === Severity.CRITICAL || finding.severity === Severity.HIGH) {
              logFinding(finding.severity, finding.title, finding.location.file, finding.location.startLine);
            }
          }
        } catch (error) {
          logger.debug(`Error analyzing ${file.relativePath}: ${error}`);
        }
      }

      // Deduplicate findings
      const uniqueFindings = this.ruleEngine.deduplicateFindings(allFindings);

      // Filter by minimum severity
      const filteredFindings = this.filterBySeverity(uniqueFindings);

      // Sort by severity
      const sortedFindings = this.ruleEngine.sortBySeverity(filteredFindings);

      // Calculate statistics
      const endTime = Date.now();
      const stats = this.calculateStats(files, sortedFindings, startTime, endTime);

      // Calculate risk score
      const riskScore = this.riskScoring.calculateRiskScore(sortedFindings, files.length);
      const riskLevel = this.riskScoring.getRiskLevel(riskScore);

      // Create result
      const result: ScanResult = {
        projectPath: this.config.projectPath,
        projectName: path.basename(this.config.projectPath),
        scanId,
        findings: sortedFindings,
        stats,
        riskScore,
        riskLevel,
        scannedFiles: files,
        config: this.config
      };

      logScanComplete(stats.totalFiles, sortedFindings.length, stats.duration, riskScore);

      // Generate report if output path specified
      if (this.config.outputPath) {
        await this.generateReport(result);
      }

      // Cleanup
      await cleanupAnalyzers();

      return result;

    } catch (error) {
      logger.error(`Scan failed: ${error}`);
      throw error;
    }
  }

  /**
   * Analyze a single file
   */
  private async analyzeFile(file: ScannedFile): Promise<Finding[]> {
    const findings: Finding[] = [];

    // Skip if no language detected
    if (!file.language) {
      return findings;
    }

    // Get language-specific analyzer
    const analyzer = getAnalyzerForLanguage(file.language);
    if (analyzer) {
      const rules = getEnabledRules().filter(r => 
        r.languages.includes(file.language!)
      );
      const analyzerFindings = await analyzer.analyze(file, rules);
      findings.push(...analyzerFindings);
    }

    // Run rule engine for generic patterns
    const ruleFindings = await this.ruleEngine.analyzeFile(file);
    findings.push(...ruleFindings);

    // AI analysis if enabled
    if (this.aiAnalyzer && this.config.useAI) {
      const aiResult = await this.aiAnalyzer.analyze(file);
      findings.push(...aiResult.findings);
    }

    return findings;
  }

  /**
   * Filter findings by minimum severity
   */
  private filterBySeverity(findings: Finding[]): Finding[] {
    if (!this.config.minSeverity) {
      return findings;
    }

    return findings.filter(f => 
      isHigherOrEqualSeverity(f.severity, this.config.minSeverity!)
    );
  }

  /**
   * Calculate scan statistics
   */
  private calculateStats(
    files: ScannedFile[],
    findings: Finding[],
    startTime: number,
    endTime: number
  ): ScanStats {
    const totalLines = files.reduce((sum, f) => sum + f.lineCount, 0);
    
    const filesByLanguage: Record<string, number> = {};
    for (const file of files) {
      const lang = file.language || 'unknown';
      filesByLanguage[lang] = (filesByLanguage[lang] || 0) + 1;
    }

    const findingsBySeverity = this.riskScoring.getSeverityDistribution(findings);
    const findingsByCategory = this.riskScoring.getCategoryDistribution(findings);

    return {
      totalFiles: files.length,
      totalLines,
      filesByLanguage,
      findingsBySeverity,
      findingsByCategory,
      duration: endTime - startTime,
      startTime: new Date(startTime),
      endTime: new Date(endTime)
    };
  }

  /**
   * Create empty result when no files found
   */
  private createEmptyResult(scanId: string, startTime: number): ScanResult {
    const endTime = Date.now();
    
    return {
      projectPath: this.config.projectPath,
      projectName: path.basename(this.config.projectPath),
      scanId,
      findings: [],
      stats: {
        totalFiles: 0,
        totalLines: 0,
        filesByLanguage: {},
        findingsBySeverity: {
          [Severity.CRITICAL]: 0,
          [Severity.HIGH]: 0,
          [Severity.MEDIUM]: 0,
          [Severity.LOW]: 0,
          [Severity.INFO]: 0
        },
        findingsByCategory: {
          [FindingCategory.MALWARE]: 0,
          [FindingCategory.VULNERABILITY]: 0,
          [FindingCategory.CODE_SMELL]: 0,
          [FindingCategory.BEST_PRACTICE]: 0
        },
        duration: endTime - startTime,
        startTime: new Date(startTime),
        endTime: new Date(endTime)
      },
      riskScore: 0,
      riskLevel: 'safe',
      scannedFiles: [],
      config: this.config
    };
  }

  /**
   * Generate report
   */
  private async generateReport(result: ScanResult): Promise<void> {
    if (!this.config.outputPath) return;

    const outputPath = path.resolve(this.config.outputPath);
    const ext = path.extname(outputPath).toLowerCase();

    if (ext === '.html' || ext === '') {
      // Pass the language configuration to the report generator
      const reportLanguage = this.config.language || 'es';
      const reportGenerator = new HtmlReportGenerator(reportLanguage);
      const finalPath = ext === '' ? `${outputPath}.html` : outputPath;
      await reportGenerator.saveReport(result, finalPath);
    } else if (ext === '.json') {
      fs.writeFileSync(outputPath, JSON.stringify(result, null, 2), 'utf-8');
      logger.info(`📁 Reporte JSON guardado en: ${outputPath}`);
    }
  }
}

export default SecurityScanner;
