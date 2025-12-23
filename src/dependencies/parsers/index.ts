/**
 * Dependency Parsers Module Exports
 */

export * from './base';
export * from './javascript';
export * from './python';
export * from './php';
export * from './java';
export * from './cpp';
export * from './csharp';

import { DependencyParser } from '../types';
import { JavaScriptDependencyParser } from './javascript';
import { PythonDependencyParser } from './python';
import { PHPDependencyParser } from './php';
import { JavaDependencyParser } from './java';
import { CppDependencyParser } from './cpp';
import { CSharpDependencyParser } from './csharp';

/**
 * All available dependency parsers
 */
const parsers: DependencyParser[] = [
  new JavaScriptDependencyParser(),
  new PythonDependencyParser(),
  new PHPDependencyParser(),
  new JavaDependencyParser(),
  new CppDependencyParser(),
  new CSharpDependencyParser()
];

/**
 * Get all dependency parsers
 */
export function getAllDependencyParsers(): DependencyParser[] {
  return parsers;
}

/**
 * Get parser for a specific file
 */
export function getParserForFile(fileName: string): DependencyParser | undefined {
  return parsers.find(p => p.supports(fileName));
}

/**
 * Get all supported manifest file names
 */
export function getSupportedManifestFiles(): string[] {
  const files: string[] = [];
  for (const parser of parsers) {
    files.push(...parser.supportedFiles);
  }
  return [...new Set(files)];
}
