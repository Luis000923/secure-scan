/**
 * Abstract AST Analyzer Module
 * Provides common interfaces and utilities for AST-based analysis
 * across multiple programming languages
 */

import { Finding, Severity, SecurityStandard } from '../../../types';

/**
 * AST Node representation - language agnostic
 */
export interface ASTNode {
  /** Type of the node (e.g., 'FunctionDeclaration', 'CallExpression') */
  type: string;
  /** Starting line number (1-indexed) */
  startLine: number;
  /** Ending line number (1-indexed) */
  endLine: number;
  /** Starting column (0-indexed) */
  startColumn: number;
  /** Ending column (0-indexed) */
  endColumn: number;
  /** Raw source code of this node */
  source?: string;
  /** Child nodes */
  children: ASTNode[];
  /** Parent node reference */
  parent?: ASTNode;
  /** Additional metadata specific to the node type */
  metadata: Record<string, unknown>;
}

/**
 * Function/Method information extracted from AST
 */
export interface FunctionInfo {
  /** Function name */
  name: string;
  /** Parameter names and types */
  parameters: Array<{
    name: string;
    type?: string;
    defaultValue?: string;
  }>;
  /** Return type if available */
  returnType?: string;
  /** Starting line */
  startLine: number;
  /** Ending line */
  endLine: number;
  /** Whether it's async */
  isAsync: boolean;
  /** Whether it's a generator */
  isGenerator: boolean;
  /** Class name if method */
  className?: string;
  /** Decorators/annotations */
  decorators: string[];
  /** The AST node for this function */
  node: ASTNode;
}

/**
 * Variable/Assignment information
 */
export interface VariableInfo {
  /** Variable name */
  name: string;
  /** Inferred or declared type */
  type?: string;
  /** Scope (function name, class name, or 'global') */
  scope: string;
  /** Line where declared */
  line: number;
  /** Initial value if determinable */
  initialValue?: string;
  /** Whether it's a constant */
  isConst: boolean;
  /** AST node */
  node: ASTNode;
}

/**
 * Call site information
 */
export interface CallInfo {
  /** Function/method being called */
  callee: string;
  /** Object the method is called on (if method call) */
  object?: string;
  /** Full qualified name */
  qualifiedName: string;
  /** Arguments (as source code strings) */
  arguments: string[];
  /** Line number */
  line: number;
  /** Column */
  column: number;
  /** Whether it's a method call */
  isMethodCall: boolean;
  /** AST node */
  node: ASTNode;
}

/**
 * Import/require information
 */
export interface ImportInfo {
  /** Module/package being imported */
  module: string;
  /** Imported names */
  imports: Array<{
    name: string;
    alias?: string;
    isDefault: boolean;
    isNamespace: boolean;
  }>;
  /** Line number */
  line: number;
  /** Is dynamic import */
  isDynamic: boolean;
}

/**
 * Class information
 */
export interface ClassInfo {
  /** Class name */
  name: string;
  /** Parent class names */
  extends: string[];
  /** Implemented interfaces */
  implements: string[];
  /** Methods */
  methods: FunctionInfo[];
  /** Properties */
  properties: VariableInfo[];
  /** Decorators/annotations */
  decorators: string[];
  /** Start line */
  startLine: number;
  /** End line */
  endLine: number;
  /** AST node */
  node: ASTNode;
}

/**
 * Result of AST parsing
 */
export interface ASTParseResult {
  /** Whether parsing succeeded */
  success: boolean;
  /** Error message if failed */
  error?: string;
  /** Root AST node */
  root?: ASTNode;
  /** All functions/methods */
  functions: FunctionInfo[];
  /** All classes */
  classes: ClassInfo[];
  /** All imports */
  imports: ImportInfo[];
  /** All variables in global scope */
  globalVariables: VariableInfo[];
  /** All function calls */
  calls: CallInfo[];
  /** Language detected/used */
  language: string;
}

/**
 * Query for finding specific nodes
 */
export interface ASTQuery {
  /** Node type to match */
  type?: string | string[];
  /** Name pattern (regex or string) */
  name?: string | RegExp;
  /** Parent type */
  parentType?: string;
  /** Has specific child type */
  hasChildType?: string;
  /** Custom predicate */
  predicate?: (node: ASTNode) => boolean;
}

/**
 * Interface for language-specific AST analyzers
 */
export interface IASTAnalyzer {
  /** Language this analyzer supports */
  readonly language: string;
  
  /** Supported file extensions */
  readonly fileExtensions: string[];

  /**
   * Parse source code into AST
   * @param sourceCode The source code to parse
   * @param filePath Optional file path for error messages
   */
  parse(sourceCode: string, filePath?: string): Promise<ASTParseResult>;

  /**
   * Find nodes matching a query
   * @param root Root node to search from
   * @param query Query criteria
   */
  findNodes(root: ASTNode, query: ASTQuery): ASTNode[];

  /**
   * Get all function/method calls in the code
   * @param parseResult Parsed AST result
   */
  getCalls(parseResult: ASTParseResult): CallInfo[];

  /**
   * Get all imports/requires
   * @param parseResult Parsed AST result
   */
  getImports(parseResult: ASTParseResult): ImportInfo[];

  /**
   * Check if a call is to a dangerous function
   * @param call Call information
   * @param dangerousFunctions List of dangerous function patterns
   */
  isDangerousCall(call: CallInfo, dangerousFunctions: string[]): boolean;

  /**
   * Get the scope of a node
   * @param node The node to get scope for
   */
  getScope(node: ASTNode): string;

  /**
   * Check if a node is inside a try-catch block
   * @param node The node to check
   */
  isInTryCatch(node: ASTNode): boolean;
}

/**
 * Abstract base class for AST analyzers
 */
export abstract class BaseASTAnalyzer implements IASTAnalyzer {
  abstract readonly language: string;
  abstract readonly fileExtensions: string[];

  abstract parse(sourceCode: string, filePath?: string): Promise<ASTParseResult>;

  /**
   * Default implementation of findNodes using depth-first traversal
   */
  findNodes(root: ASTNode, query: ASTQuery): ASTNode[] {
    const results: ASTNode[] = [];
    
    const traverse = (node: ASTNode) => {
      if (this.nodeMatchesQuery(node, query)) {
        results.push(node);
      }
      for (const child of node.children) {
        traverse(child);
      }
    };

    traverse(root);
    return results;
  }

  /**
   * Check if a node matches the query
   */
  protected nodeMatchesQuery(node: ASTNode, query: ASTQuery): boolean {
    // Type check
    if (query.type) {
      const types = Array.isArray(query.type) ? query.type : [query.type];
      if (!types.includes(node.type)) {
        return false;
      }
    }

    // Name check
    if (query.name) {
      const nodeName = this.getNodeName(node);
      if (!nodeName) return false;
      
      if (query.name instanceof RegExp) {
        if (!query.name.test(nodeName)) return false;
      } else {
        if (nodeName !== query.name) return false;
      }
    }

    // Parent type check
    if (query.parentType && node.parent) {
      if (node.parent.type !== query.parentType) return false;
    }

    // Has child type check
    if (query.hasChildType) {
      const hasChild = node.children.some(c => c.type === query.hasChildType);
      if (!hasChild) return false;
    }

    // Custom predicate
    if (query.predicate && !query.predicate(node)) {
      return false;
    }

    return true;
  }

  /**
   * Get the name of a node if applicable
   */
  protected abstract getNodeName(node: ASTNode): string | null;

  getCalls(parseResult: ASTParseResult): CallInfo[] {
    return parseResult.calls;
  }

  getImports(parseResult: ASTParseResult): ImportInfo[] {
    return parseResult.imports;
  }

  isDangerousCall(call: CallInfo, dangerousFunctions: string[]): boolean {
    const callName = call.qualifiedName.toLowerCase();
    return dangerousFunctions.some(dangerous => {
      const normalizedDangerous = dangerous.toLowerCase();
      return callName === normalizedDangerous || 
             callName.endsWith(`.${normalizedDangerous}`) ||
             callName.startsWith(`${normalizedDangerous}.`);
    });
  }

  getScope(node: ASTNode): string {
    let current: ASTNode | undefined = node.parent;
    while (current) {
      if (this.isScopeNode(current)) {
        return this.getScopeName(current);
      }
      current = current.parent;
    }
    return 'global';
  }

  /**
   * Check if a node creates a new scope
   */
  protected abstract isScopeNode(node: ASTNode): boolean;

  /**
   * Get the name of a scope node
   */
  protected abstract getScopeName(node: ASTNode): string;

  isInTryCatch(node: ASTNode): boolean {
    let current: ASTNode | undefined = node.parent;
    while (current) {
      if (this.isTryCatchNode(current)) {
        return true;
      }
      current = current.parent;
    }
    return false;
  }

  /**
   * Check if a node is a try-catch statement
   */
  protected abstract isTryCatchNode(node: ASTNode): boolean;
}

/**
 * Security-focused AST query patterns
 */
export const SECURITY_AST_QUERIES: Record<string, ASTQuery> = {
  /** Find all eval-like calls */
  evalCalls: {
    type: 'CallExpression',
    name: /^(eval|exec|compile|Function)$/,
  },
  
  /** Find all require/import calls */
  dynamicImports: {
    type: ['CallExpression', 'ImportExpression'],
    name: /^(require|import|__import__)$/,
  },
  
  /** Find all dangerous deserialization */
  deserialization: {
    type: 'CallExpression',
    name: /^(unserialize|pickle\.loads?|ObjectInputStream|BinaryFormatter)$/,
  },
  
  /** Find all SQL query constructions */
  sqlQueries: {
    type: 'CallExpression',
    name: /^(execute|executeQuery|query|raw|RawSQL)$/,
  },
  
  /** Find all HTTP requests */
  httpRequests: {
    type: 'CallExpression',
    name: /^(fetch|axios|request|http\.get|urllib|requests\.get)$/,
  },
  
  /** Find all file operations */
  fileOperations: {
    type: 'CallExpression',
    name: /^(open|fopen|readFile|writeFile|createWriteStream|file_get_contents)$/,
  },
  
  /** Find all command executions */
  commandExecution: {
    type: 'CallExpression',
    name: /^(exec|spawn|system|popen|subprocess|child_process|Process\.Start)$/,
  },
};

/**
 * Utility to create a simple regex-based fallback parser
 * when full AST parsing is not available
 */
export function createSimpleParser(language: string): Partial<ASTParseResult> {
  return {
    success: false,
    error: `Full AST parsing not available for ${language}, using regex fallback`,
    functions: [],
    classes: [],
    imports: [],
    globalVariables: [],
    calls: [],
    language,
  };
}

/**
 * Extract function calls using regex (fallback when AST not available)
 */
export function extractCallsWithRegex(
  sourceCode: string,
  pattern: RegExp
): Array<{ name: string; line: number; match: string }> {
  const results: Array<{ name: string; line: number; match: string }> = [];
  const lines = sourceCode.split('\n');
  
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    let match: RegExpExecArray | null;
    
    // Reset regex state
    const regex = new RegExp(pattern.source, pattern.flags);
    while ((match = regex.exec(line)) !== null) {
      results.push({
        name: match[1] || match[0],
        line: i + 1,
        match: match[0],
      });
    }
  }
  
  return results;
}
