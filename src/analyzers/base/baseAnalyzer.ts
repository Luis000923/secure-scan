/**
 * Base Analyzer Interface
 * Abstract base class for language-specific analyzers
 */

import { Analyzer, ScannedFile, Finding, Rule, SupportedLanguage } from '../../types';
import { RuleEngine } from '../../core/engine';
import { logger } from '../../utils/logger';

/**
 * Base Analyzer Class
 * Provides common functionality for all language analyzers
 */
export abstract class BaseAnalyzer implements Analyzer {
  abstract name: string;
  abstract languages: SupportedLanguage[];
  abstract version: string;

  protected ruleEngine: RuleEngine;
  protected initialized: boolean = false;

  constructor() {
    this.ruleEngine = new RuleEngine();
  }

  /**
   * Initialize the analyzer
   */
  async initialize(): Promise<void> {
    logger.debug(`Initializing ${this.name} analyzer...`);
    this.initialized = true;
  }

  /**
   * Check if analyzer supports a language
   */
  supportsLanguage(language: SupportedLanguage): boolean {
    return this.languages.includes(language);
  }

  /**
   * Analyze a file
   */
  abstract analyze(file: ScannedFile, rules: Rule[]): Promise<Finding[]>;

  /**
   * Cleanup resources
   */
  async cleanup(): Promise<void> {
    logger.debug(`Cleaning up ${this.name} analyzer...`);
    this.initialized = false;
  }

  /**
   * Get analyzer info
   */
  getInfo(): { name: string; languages: SupportedLanguage[]; version: string } {
    return {
      name: this.name,
      languages: this.languages,
      version: this.version
    };
  }
}

export default BaseAnalyzer;
