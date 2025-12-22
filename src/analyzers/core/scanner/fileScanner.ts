/**
 * File Scanner Module
 * Scans directories and collects files for analysis
 */

import * as fs from 'fs';
import * as path from 'path';
import { glob } from 'glob';
import { ScannedFile, SupportedLanguage, ScanConfig } from '../../../types';
import { 
  getLanguageFromExtension, 
  shouldExclude, 
  calculateHash, 
  countLines,
  generateId 
} from '../../../utils';
import { logger } from '../../../utils/logger';

/**
 * Default file extensions to scan
 */
const DEFAULT_EXTENSIONS = [
  '.js', '.jsx', '.mjs', '.cjs',
  '.ts', '.tsx',
  '.py', '.pyw',
  '.php', '.phtml',
  '.java',
  '.c', '.h', '.cpp', '.cc', '.cxx', '.hpp',
  '.cs',
  '.yaml', '.yml',
  '.tf', '.tfvars'
];

/**
 * Default max file size (5MB)
 */
const DEFAULT_MAX_FILE_SIZE = 5 * 1024 * 1024;

/**
 * File Scanner Class
 */
export class FileScanner {
  private config: ScanConfig;
  private extensions: string[];

  constructor(config: ScanConfig) {
    this.config = config;
    this.extensions = DEFAULT_EXTENSIONS;
  }

  /**
   * Scan project directory for files
   */
  async scan(): Promise<ScannedFile[]> {
    const projectPath = path.resolve(this.config.projectPath);
    
    if (!fs.existsSync(projectPath)) {
      throw new Error(`Project path does not exist: ${projectPath}`);
    }

    const stats = fs.statSync(projectPath);
    if (!stats.isDirectory()) {
      throw new Error(`Project path is not a directory: ${projectPath}`);
    }

    logger.info(`🔍 Starting file scan in: ${projectPath}`);

    // Build glob pattern
    const patterns = this.extensions.map(ext => `**/*${ext}`);
    patterns.push('**/Dockerfile');
    patterns.push('**/.github/**/*.yml');
    patterns.push('**/.github/**/*.yaml');
    patterns.push('**/.gitlab-ci.yml');

    const files: ScannedFile[] = [];

    for (const pattern of patterns) {
      const matches = await glob(pattern, {
        cwd: projectPath,
        nodir: true,
        absolute: false,
        ignore: this.getIgnorePatterns()
      });

      for (const match of matches) {
        const absolutePath = path.join(projectPath, match);
        
        // Skip if already processed
        if (files.some(f => f.absolutePath === absolutePath)) {
          continue;
        }

        // Skip excluded paths
        if (shouldExclude(match, this.config.exclude || [])) {
          logger.debug(`Skipping excluded file: ${match}`);
          continue;
        }

        try {
          const scannedFile = await this.processFile(absolutePath, match, projectPath);
          if (scannedFile) {
            files.push(scannedFile);
          }
        } catch (error) {
          logger.warn(`Failed to process file: ${match} - ${error}`);
        }
      }
    }

    // Filter by language if specified
    let filteredFiles = files;
    if (this.config.languages && this.config.languages.length > 0) {
      filteredFiles = files.filter(f => 
        f.language && this.config.languages!.includes(f.language)
      );
    }

    logger.info(`📂 Found ${filteredFiles.length} files to analyze`);

    return filteredFiles;
  }

  /**
   * Process a single file
   */
  private async processFile(
    absolutePath: string,
    relativePath: string,
    projectPath: string
  ): Promise<ScannedFile | null> {
    const stats = fs.statSync(absolutePath);
    const maxSize = this.config.maxFileSize || DEFAULT_MAX_FILE_SIZE;

    // Skip files that are too large
    if (stats.size > maxSize) {
      logger.debug(`Skipping large file: ${relativePath} (${stats.size} bytes)`);
      return null;
    }

    // Read file content
    const content = fs.readFileSync(absolutePath, 'utf-8');
    
    // Detect language
    const language = getLanguageFromExtension(absolutePath);

    return {
      absolutePath,
      relativePath,
      extension: path.extname(absolutePath).toLowerCase(),
      language,
      size: stats.size,
      content,
      lineCount: countLines(content),
      hash: calculateHash(content)
    };
  }

  /**
   * Get ignore patterns for glob
   */
  private getIgnorePatterns(): string[] {
    const defaultIgnore = [
      '**/node_modules/**',
      '**/vendor/**',
      '**/.git/**',
      '**/dist/**',
      '**/build/**',
      '**/out/**',
      '**/__pycache__/**',
      '**/.venv/**',
      '**/venv/**',
      '**/coverage/**',
      '**/.nyc_output/**',
      '**/.next/**',
      '**/.nuxt/**',
      '**/target/**',
      '**/bin/**',
      '**/obj/**',
      '**/*.min.js',
      '**/*.bundle.js',
      '**/*.map'
    ];

    const customIgnore = (this.config.exclude || []).map((p: string) => `**/${p}/**`);

    return [...defaultIgnore, ...customIgnore];
  }

  /**
   * Get file statistics
   */
  getFileStats(files: ScannedFile[]): Record<string, number> {
    const stats: Record<string, number> = {};

    for (const file of files) {
      const lang = file.language || 'unknown';
      stats[lang] = (stats[lang] || 0) + 1;
    }

    return stats;
  }
}

export default FileScanner;
