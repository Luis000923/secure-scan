/**
 * Shared Analysis Module
 * Provides AST analysis, taint tracking, and data flow analysis infrastructure
 * for all language analyzers
 */

// AST Analysis
export {
  ASTNode,
  FunctionInfo,
  VariableInfo,
  CallInfo,
  ImportInfo,
  ClassInfo,
  ASTParseResult,
  ASTQuery,
  IASTAnalyzer,
  BaseASTAnalyzer,
  SECURITY_AST_QUERIES,
  extractCallsWithRegex,
} from './astAnalyzer';

// Taint Tracking
export {
  TaintSource,
  TaintSink,
  TaintSanitizer,
  TaintedValue,
  TaintFinding,
  TaintConfig,
  DEFAULT_SOURCES,
  DEFAULT_SINKS,
  DEFAULT_SANITIZERS,
  TaintTracker,
  taintFindingsToFindings,
} from './taintTracker';

// Data Flow Analysis
export {
  DFGNodeType,
  DFGNode,
  ReachingDefinition,
  UseDefChain,
  DefUseChain,
  DataFlowResult,
  BasicBlock,
  CFG,
  VariableState,
  DataFlowAnalyzer,
  extractDataFlowWithRegex,
  SecurityDataFlowResult,
  analyzeSecurityDataFlow,
} from './dataFlowAnalyzer';
