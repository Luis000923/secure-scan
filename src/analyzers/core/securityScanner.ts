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
} from '../../types';
import { FileScanner } from './scanner';
import { RuleEngine } from './engine';
import { RiskScoringEngine } from './scoring';
import { getAllRules, getEnabledRules } from '../../rules';
import { getAllAnalyzers, initializeAnalyzers, cleanupAnalyzers, getAnalyzerForLanguage } from '../';
import { AIAnalyzer } from '../../ai';
import { HtmlReportGenerator } from '../../reports';
import { generateId, isHigherOrEqualSeverity } from '../../utils';
import { logger, logScanStart, logScanComplete, logFinding } from '../../utils/logger';

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
  private static readonly DEFAULT_BATCH_SIZE = 4;

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

      // Log available analyzers and their versions
      const allAnalyzers = getAllAnalyzers();
      logger.info(`🔧 Loaded ${allAnalyzers.length} security analyzers:`);
      for (const analyzer of allAnalyzers) {
        logger.info(`   • ${analyzer.name} v${analyzer.version} (${analyzer.languages.join(', ')})`);
      }

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

      // Analyze files with batch processing
      logger.info('🔍 Analyzing code for vulnerabilities and malware...');
      const allFindings: Finding[] = [];
      const batchSize = SecurityScanner.DEFAULT_BATCH_SIZE;
      let analyzedCount = 0;
      const failedFiles: string[] = [];

      for (let i = 0; i < files.length; i += batchSize) {
        const batch = files.slice(i, i + batchSize);
        const results = await Promise.allSettled(
          batch.map(file => this.analyzeFile(file))
        );

        for (let j = 0; j < results.length; j++) {
          const result = results[j];
          const file = batch[j];
          analyzedCount++;

          if (result.status === 'fulfilled') {
            allFindings.push(...result.value);

            // Log critical findings immediately
            for (const finding of result.value) {
              if (finding.severity === Severity.CRITICAL || finding.severity === Severity.HIGH || finding.category === FindingCategory.MALWARE) {
                logFinding(finding.severity, finding.title, finding.location.file, finding.location.startLine, finding.category);
              }
            }
          } else {
            failedFiles.push(file.relativePath);
            logger.debug(`Error analyzing ${file.relativePath}: ${result.reason}`);
          }
        }

        // Progress reporting
        if (this.config.verbose || files.length > 50) {
          const percent = Math.round((analyzedCount / files.length) * 100);
          logger.info(`📊 Progress: ${analyzedCount}/${files.length} files analyzed (${percent}%)`);
        }
      }

      // Report failed files summary
      if (failedFiles.length > 0) {
        logger.warn(`⚠️ ${failedFiles.length} file(s) could not be fully analyzed`);
        if (this.config.verbose) {
          for (const f of failedFiles) {
            logger.warn(`   • ${f}`);
          }
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
   * Analyze a single file.
   * Uses graceful degradation: if one analyzer fails, others continue.
   */
  private async analyzeFile(file: ScannedFile): Promise<Finding[]> {
    const findings: Finding[] = [];

    // Skip if no language detected
    if (!file.language) {
      return findings;
    }

    // Get language-specific analyzer — graceful degradation
    const analyzer = getAnalyzerForLanguage(file.language);
    if (analyzer) {
      try {
        if (this.config.verbose) {
          logger.debug(`Using ${analyzer.name} v${analyzer.version} for ${file.relativePath}`);
        }
        const rules = getEnabledRules().filter(r =>
          r.languages.includes(file.language!)
        );
        const analyzerFindings = await analyzer.analyze(file, rules);
        findings.push(...analyzerFindings);
      } catch (analyzerError) {
        logger.warn(`⚠️ Language analyzer failed for ${file.relativePath}: ${analyzerError}`);
        // Continue with other analyzers
      }
    }

    // Run rule engine for generic patterns — graceful degradation
    try {
      const ruleFindings = await this.ruleEngine.analyzeFile(file);
      findings.push(...ruleFindings);
    } catch (ruleError) {
      logger.warn(`⚠️ Rule engine failed for ${file.relativePath}: ${ruleError}`);
    }

    // AI analysis if enabled — graceful degradation
    if (this.aiAnalyzer && this.config.useAI) {
      try {
        const aiResult = await this.aiAnalyzer.analyze(file);
        findings.push(...aiResult.findings);
      } catch (aiError) {
        logger.debug(`AI analysis skipped for ${file.relativePath}: ${aiError}`);
      }
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
          [FindingCategory.BEST_PRACTICE]: 0,
          [FindingCategory.SECRET]: 0
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
