/**
 * JavaScript/TypeScript Analyzer Module Exports
 * 
 * Advanced SAST analyzer with:
 * - AST-based vulnerability detection
 * - Taint analysis (source-to-sink tracking)
 * - Malware detection (cryptominers, stealers, backdoors)
 * - Package.json security analysis
 * 
 * @version 2.0.0
 */

// Main analyzer
export * from './javascriptAnalyzer';
export { JavaScriptAnalyzer as default } from './javascriptAnalyzer';

// Taint analysis module
export { 
  TaintAnalyzer, 
  TaintFlow, 
  TaintSource, 
  TaintSink,
  TAINT_SOURCES,
  TAINT_SINKS 
} from './taintAnalyzer';

// AST utilities module
export { 
  ASTUtils, 
  DangerousCall, 
  DangerousPatternType,
  ASTParseOptions,
  ASTLocation,
  ASTPattern,
  ASTContext
} from './astUtils';

// Malware detection module
export { 
  MalwareDetector, 
  MalwareMatch, 
  MalwareType 
} from './malwareDetector';

// Package.json analyzer module
export { 
  PackageJsonAnalyzer, 
  PackageJsonFinding, 
  PackageJsonFindingType 
} from './packageJsonAnalyzer';
