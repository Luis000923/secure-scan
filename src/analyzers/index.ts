/**
 * Analyzers Module Exports
 * All language analyzers for the SAST tool
 */

export * from './base';
export * from './javascript';
export * from './python';
export * from './php';
export * from './java';
export * from './c-cpp';
export * from './csharp';
export * from './iac';

import { Analyzer, SupportedLanguage } from '../types';
import { JavaScriptAnalyzer } from './javascript';
import { PythonAnalyzer } from './python';
import { PHPAnalyzer } from './php';
import { JavaAnalyzer } from './java';
import { CppAnalyzer } from './c-cpp';
import { CSharpAnalyzer } from './csharp';
import { IaCAnalyzer } from './iac';

/**
 * Analyzer registry
 */
const analyzers: Analyzer[] = [
  new JavaScriptAnalyzer(),
  new PythonAnalyzer(),
  new PHPAnalyzer(),
  new JavaAnalyzer(),
  new CppAnalyzer(),
  new CSharpAnalyzer(),
  new IaCAnalyzer()
];

/**
 * Get all analyzers
 */
export function getAllAnalyzers(): Analyzer[] {
  return analyzers;
}

/**
 * Get analyzer for a specific language
 */
export function getAnalyzerForLanguage(language: SupportedLanguage): Analyzer | undefined {
  return analyzers.find(a => a.languages.includes(language));
}

/**
 * Initialize all analyzers
 */
export async function initializeAnalyzers(): Promise<void> {
  for (const analyzer of analyzers) {
    await analyzer.initialize();
  }
}

/**
 * Cleanup all analyzers
 */
export async function cleanupAnalyzers(): Promise<void> {
  for (const analyzer of analyzers) {
    await analyzer.cleanup();
  }
}
