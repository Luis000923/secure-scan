/**
 * Dependency Analysis Module Exports
 * Software Composition Analysis (SCA) for Secure-Scan
 */

// Types
export * from './types';

// Parsers
export * from './parsers';

// Detectors
export * from './detectors';

// Database
export * from './database';

// Main analyzer
export * from './dependencyAnalyzer';
export { default as DependencyAnalyzer } from './dependencyAnalyzer';

// AI Analyzer
export * from './aiDependencyAnalyzer';
export { default as AIDependencyAnalyzer } from './aiDependencyAnalyzer';

// Installed Dependencies Scanner (Malware Detection)
export * from './installed';
