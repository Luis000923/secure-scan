/**
 * Data Flow Analysis Module
 * Provides intra-procedural data flow analysis for security scanning
 */

import { ASTNode, FunctionInfo, VariableInfo, CallInfo } from './astAnalyzer';

/**
 * Data flow node types
 */
export type DFGNodeType = 
  | 'entry'
  | 'exit'
  | 'assignment'
  | 'call'
  | 'condition'
  | 'return'
  | 'parameter'
  | 'phi'    // For SSA-style merging
  | 'use'
  | 'definition';

/**
 * A node in the data flow graph
 */
export interface DFGNode {
  /** Unique identifier */
  id: string;
  /** Type of node */
  type: DFGNodeType;
  /** Variable name being defined or used */
  variable?: string;
  /** Value or expression */
  expression?: string;
  /** Line number */
  line: number;
  /** Column */
  column: number;
  /** Predecessor nodes (where data flows from) */
  predecessors: DFGNode[];
  /** Successor nodes (where data flows to) */
  successors: DFGNode[];
  /** AST node reference */
  astNode?: ASTNode;
  /** Additional metadata */
  metadata: Record<string, unknown>;
}

/**
 * Reaching definition - tracks where a variable was last defined
 */
export interface ReachingDefinition {
  /** Variable name */
  variable: string;
  /** Definition site (line number) */
  definitionLine: number;
  /** Definition node */
  definitionNode: DFGNode;
  /** Whether this is a parameter */
  isParameter: boolean;
  /** The expression/value assigned */
  value?: string;
}

/**
 * Use-Definition chain entry
 */
export interface UseDefChain {
  /** The use site */
  use: {
    line: number;
    variable: string;
    node: DFGNode;
  };
  /** Definitions that reach this use */
  definitions: ReachingDefinition[];
}

/**
 * Definition-Use chain entry
 */
export interface DefUseChain {
  /** The definition site */
  definition: ReachingDefinition;
  /** Uses that this definition reaches */
  uses: Array<{
    line: number;
    variable: string;
    node: DFGNode;
  }>;
}

/**
 * Data flow analysis result
 */
export interface DataFlowResult {
  /** Entry node of the function/scope */
  entry: DFGNode;
  /** Exit node of the function/scope */
  exit: DFGNode;
  /** All nodes in the data flow graph */
  nodes: DFGNode[];
  /** Reaching definitions at each program point */
  reachingDefinitions: Map<number, ReachingDefinition[]>;
  /** Use-Definition chains */
  useDefChains: UseDefChain[];
  /** Definition-Use chains */
  defUseChains: DefUseChain[];
  /** Variables that may be used uninitialized */
  uninitializedUses: Array<{ variable: string; line: number }>;
}

/**
 * Basic block for control flow
 */
export interface BasicBlock {
  /** Block identifier */
  id: string;
  /** First line in block */
  startLine: number;
  /** Last line in block */
  endLine: number;
  /** Statements/nodes in this block */
  nodes: DFGNode[];
  /** Predecessor blocks */
  predecessors: BasicBlock[];
  /** Successor blocks */
  successors: BasicBlock[];
  /** Is entry block */
  isEntry: boolean;
  /** Is exit block */
  isExit: boolean;
}

/**
 * Control Flow Graph for a function
 */
export interface CFG {
  /** Entry block */
  entry: BasicBlock;
  /** Exit block */
  exit: BasicBlock;
  /** All blocks */
  blocks: BasicBlock[];
  /** Function this CFG represents */
  function: FunctionInfo;
}

/**
 * Variable state tracker for data flow
 */
export interface VariableState {
  /** Variable name */
  name: string;
  /** Current status */
  status: 'undefined' | 'defined' | 'maybe-defined' | 'tainted';
  /** Line where last defined */
  lastDefinedLine?: number;
  /** Taint source if tainted */
  taintSource?: string;
}

/**
 * Data Flow Analyzer class
 */
export class DataFlowAnalyzer {
  private nodeCounter: number = 0;

  /**
   * Create a new DFG node
   */
  private createNode(
    type: DFGNodeType,
    line: number,
    column: number = 0,
    options: Partial<DFGNode> = {}
  ): DFGNode {
    return {
      id: `dfg_${this.nodeCounter++}`,
      type,
      line,
      column,
      predecessors: [],
      successors: [],
      metadata: {},
      ...options,
    };
  }

  /**
   * Connect two nodes (add edge)
   */
  private connect(from: DFGNode, to: DFGNode): void {
    if (!from.successors.includes(to)) {
      from.successors.push(to);
    }
    if (!to.predecessors.includes(from)) {
      to.predecessors.push(from);
    }
  }

  /**
   * Perform reaching definitions analysis
   * A classic data flow analysis that tracks where each variable was last defined
   */
  analyzeReachingDefinitions(nodes: DFGNode[], entry: DFGNode): Map<number, ReachingDefinition[]> {
    const result = new Map<number, ReachingDefinition[]>();
    
    // Initialize
    const allDefinitions: ReachingDefinition[] = [];
    for (const node of nodes) {
      if (node.type === 'definition' || node.type === 'assignment' || node.type === 'parameter') {
        if (node.variable) {
          allDefinitions.push({
            variable: node.variable,
            definitionLine: node.line,
            definitionNode: node,
            isParameter: node.type === 'parameter',
            value: node.expression,
          });
        }
      }
    }

    // Worklist algorithm
    const worklist: DFGNode[] = [entry];
    const inSets = new Map<string, Set<ReachingDefinition>>();
    const outSets = new Map<string, Set<ReachingDefinition>>();

    // Initialize sets
    for (const node of nodes) {
      inSets.set(node.id, new Set());
      outSets.set(node.id, new Set());
    }

    while (worklist.length > 0) {
      const node = worklist.shift()!;
      
      // IN[n] = union of OUT[p] for all predecessors p
      const inSet = new Set<ReachingDefinition>();
      for (const pred of node.predecessors) {
        const predOut = outSets.get(pred.id);
        if (predOut) {
          for (const def of predOut) {
            inSet.add(def);
          }
        }
      }
      inSets.set(node.id, inSet);

      // OUT[n] = GEN[n] union (IN[n] - KILL[n])
      const outSet = new Set<ReachingDefinition>();
      
      // Add GEN (definitions created at this node)
      if ((node.type === 'definition' || node.type === 'assignment' || node.type === 'parameter') && node.variable) {
        const newDef: ReachingDefinition = {
          variable: node.variable,
          definitionLine: node.line,
          definitionNode: node,
          isParameter: node.type === 'parameter',
          value: node.expression,
        };
        outSet.add(newDef);
      }

      // Add IN - KILL (definitions not killed by this node)
      for (const def of inSet) {
        // Definition is killed if this node redefines the same variable
        if (node.variable !== def.variable) {
          outSet.add(def);
        }
      }

      // Check if OUT changed
      const prevOut = outSets.get(node.id);
      const changed = !this.setsEqual(prevOut!, outSet);
      
      if (changed) {
        outSets.set(node.id, outSet);
        // Add successors to worklist
        for (const succ of node.successors) {
          if (!worklist.includes(succ)) {
            worklist.push(succ);
          }
        }
      }
    }

    // Convert to result format
    for (const node of nodes) {
      const inSet = inSets.get(node.id);
      if (inSet) {
        result.set(node.line, Array.from(inSet));
      }
    }

    return result;
  }

  /**
   * Build Use-Definition chains
   */
  buildUseDefChains(nodes: DFGNode[], reachingDefs: Map<number, ReachingDefinition[]>): UseDefChain[] {
    const chains: UseDefChain[] = [];

    for (const node of nodes) {
      if (node.type === 'use' && node.variable) {
        const reaching = reachingDefs.get(node.line) || [];
        const matchingDefs = reaching.filter(d => d.variable === node.variable);
        
        chains.push({
          use: {
            line: node.line,
            variable: node.variable,
            node,
          },
          definitions: matchingDefs,
        });
      }
    }

    return chains;
  }

  /**
   * Build Definition-Use chains
   */
  buildDefUseChains(nodes: DFGNode[], useDefChains: UseDefChain[]): DefUseChain[] {
    const defMap = new Map<string, DefUseChain>();

    // Initialize from all definition nodes
    for (const node of nodes) {
      if ((node.type === 'definition' || node.type === 'assignment' || node.type === 'parameter') && node.variable) {
        const key = `${node.variable}:${node.line}`;
        if (!defMap.has(key)) {
          defMap.set(key, {
            definition: {
              variable: node.variable,
              definitionLine: node.line,
              definitionNode: node,
              isParameter: node.type === 'parameter',
              value: node.expression,
            },
            uses: [],
          });
        }
      }
    }

    // Populate uses from use-def chains
    for (const udChain of useDefChains) {
      for (const def of udChain.definitions) {
        const key = `${def.variable}:${def.definitionLine}`;
        const duChain = defMap.get(key);
        if (duChain) {
          duChain.uses.push(udChain.use);
        }
      }
    }

    return Array.from(defMap.values());
  }

  /**
   * Detect potentially uninitialized variable uses
   */
  detectUninitializedUses(
    nodes: DFGNode[],
    reachingDefs: Map<number, ReachingDefinition[]>,
    parameters: string[]
  ): Array<{ variable: string; line: number }> {
    const uninitialized: Array<{ variable: string; line: number }> = [];

    for (const node of nodes) {
      if (node.type === 'use' && node.variable) {
        const reaching = reachingDefs.get(node.line) || [];
        const hasDefinition = reaching.some(
          d => d.variable === node.variable
        );
        const isParameter = parameters.includes(node.variable);

        if (!hasDefinition && !isParameter) {
          uninitialized.push({
            variable: node.variable,
            line: node.line,
          });
        }
      }
    }

    return uninitialized;
  }

  /**
   * Perform complete data flow analysis for a function
   */
  analyzeFunction(
    functionInfo: FunctionInfo,
    nodes: DFGNode[]
  ): DataFlowResult {
    // Create entry and exit nodes
    const entry = this.createNode('entry', functionInfo.startLine);
    const exit = this.createNode('exit', functionInfo.endLine);

    // Extract parameter names
    const paramNames = functionInfo.parameters.map(p => p.name);

    // Create parameter definition nodes
    for (let i = 0; i < functionInfo.parameters.length; i++) {
      const param = functionInfo.parameters[i];
      const paramNode = this.createNode('parameter', functionInfo.startLine, 0, {
        variable: param.name,
        expression: `param:${i}`,
      });
      this.connect(entry, paramNode);
    }

    // Perform reaching definitions
    const reachingDefs = this.analyzeReachingDefinitions(nodes, entry);

    // Build chains
    const useDefChains = this.buildUseDefChains(nodes, reachingDefs);
    const defUseChains = this.buildDefUseChains(nodes, useDefChains);

    // Detect uninitialized uses
    const uninitializedUses = this.detectUninitializedUses(nodes, reachingDefs, paramNames);

    return {
      entry,
      exit,
      nodes: [entry, ...nodes, exit],
      reachingDefinitions: reachingDefs,
      useDefChains,
      defUseChains,
      uninitializedUses,
    };
  }

  /**
   * Find all paths between two nodes (for taint tracking)
   */
  findPaths(
    from: DFGNode,
    to: DFGNode,
    maxDepth: number = 50
  ): DFGNode[][] {
    const paths: DFGNode[][] = [];
    const visited = new Set<string>();

    const dfs = (current: DFGNode, path: DFGNode[], depth: number): void => {
      if (depth > maxDepth) return;
      if (current.id === to.id) {
        paths.push([...path, current]);
        return;
      }
      if (visited.has(current.id)) return;

      visited.add(current.id);
      path.push(current);

      for (const succ of current.successors) {
        dfs(succ, path, depth + 1);
      }

      path.pop();
      visited.delete(current.id);
    };

    dfs(from, [], 0);
    return paths;
  }

  /**
   * Check if variable is live at a point (has future uses)
   */
  isLiveAt(
    variable: string,
    line: number,
    defUseChains: DefUseChain[]
  ): boolean {
    for (const chain of defUseChains) {
      if (chain.definition.variable === variable && chain.definition.definitionLine <= line) {
        // Check if there are uses after this line
        const futureUses = chain.uses.filter(u => u.line > line);
        if (futureUses.length > 0) {
          return true;
        }
      }
    }
    return false;
  }

  /**
   * Get all variables used at a specific line
   */
  getVariablesUsedAtLine(line: number, useDefChains: UseDefChain[]): string[] {
    return useDefChains
      .filter(c => c.use.line === line)
      .map(c => c.use.variable);
  }

  /**
   * Get definition sites for a variable at a specific use
   */
  getDefinitionSites(
    variable: string,
    useLine: number,
    reachingDefs: Map<number, ReachingDefinition[]>
  ): number[] {
    const reaching = reachingDefs.get(useLine) || [];
    return reaching
      .filter(d => d.variable === variable)
      .map(d => d.definitionLine);
  }

  /**
   * Compare two sets for equality
   */
  private setsEqual<T>(a: Set<T>, b: Set<T>): boolean {
    if (a.size !== b.size) return false;
    for (const item of a) {
      if (!b.has(item)) return false;
    }
    return true;
  }
}

/**
 * Simple regex-based data flow extraction for when full AST is not available
 */
export function extractDataFlowWithRegex(
  sourceCode: string,
  language: string
): { definitions: Array<{ variable: string; line: number; value: string }>, uses: Array<{ variable: string; line: number }> } {
  const definitions: Array<{ variable: string; line: number; value: string }> = [];
  const uses: Array<{ variable: string; line: number }> = [];
  const lines = sourceCode.split('\n');

  // Language-specific patterns
  const patterns: Record<string, { assignment: RegExp; identifier: RegExp }> = {
    javascript: {
      assignment: /(?:const|let|var)?\s*(\w+)\s*=\s*(.+?)(?:;|$)/g,
      identifier: /\b([a-zA-Z_]\w*)\b/g,
    },
    python: {
      assignment: /(\w+)\s*=\s*(.+?)$/gm,
      identifier: /\b([a-zA-Z_]\w*)\b/g,
    },
    java: {
      assignment: /(?:\w+\s+)?(\w+)\s*=\s*(.+?);/g,
      identifier: /\b([a-zA-Z_]\w*)\b/g,
    },
    php: {
      assignment: /\$(\w+)\s*=\s*(.+?);/g,
      identifier: /\$([a-zA-Z_]\w*)/g,
    },
    csharp: {
      assignment: /(?:var|\w+)\s+(\w+)\s*=\s*(.+?);/g,
      identifier: /\b([a-zA-Z_]\w*)\b/g,
    },
  };

  const langPatterns = patterns[language] || patterns.javascript;
  const keywords = new Set([
    'if', 'else', 'for', 'while', 'do', 'switch', 'case', 'break', 'continue',
    'return', 'function', 'class', 'const', 'let', 'var', 'new', 'this',
    'true', 'false', 'null', 'undefined', 'import', 'export', 'from',
    'try', 'catch', 'finally', 'throw', 'async', 'await', 'yield',
    'def', 'elif', 'except', 'pass', 'with', 'lambda', 'None', 'True', 'False',
    'public', 'private', 'protected', 'static', 'final', 'void', 'int', 'string',
  ]);

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const lineNum = i + 1;

    // Extract assignments
    const assignRegex = new RegExp(langPatterns.assignment.source, 'g');
    let match: RegExpExecArray | null;
    
    while ((match = assignRegex.exec(line)) !== null) {
      const varName = match[1];
      const value = match[2];
      if (!keywords.has(varName)) {
        definitions.push({ variable: varName, line: lineNum, value });
      }
    }

    // Extract identifier uses (simplified)
    const idRegex = new RegExp(langPatterns.identifier.source, 'g');
    while ((match = idRegex.exec(line)) !== null) {
      const varName = match[1];
      if (!keywords.has(varName)) {
        // Check if this is not a definition (right side of =)
        const beforeMatch = line.substring(0, match.index);
        if (!beforeMatch.match(/(?:const|let|var|def|function|class|=)\s*$/)) {
          uses.push({ variable: varName, line: lineNum });
        }
      }
    }
  }

  return { definitions, uses };
}

/**
 * Security-focused data flow analysis
 * Tracks flow from sources to sinks
 */
export interface SecurityDataFlowResult {
  /** Tainted variable flows */
  taintedFlows: Array<{
    source: { variable: string; line: number; type: string };
    sink: { variable: string; line: number; type: string };
    path: number[];
  }>;
  /** Variables that are never used */
  deadStores: Array<{ variable: string; line: number }>;
  /** Potential null dereferences */
  nullDereferences: Array<{ variable: string; line: number }>;
}

/**
 * Perform security-focused data flow analysis
 */
export function analyzeSecurityDataFlow(
  sourceCode: string,
  language: string,
  sources: string[],
  sinks: string[]
): SecurityDataFlowResult {
  const { definitions, uses } = extractDataFlowWithRegex(sourceCode, language);
  
  const result: SecurityDataFlowResult = {
    taintedFlows: [],
    deadStores: [],
    nullDereferences: [],
  };

  // Find tainted sources
  const taintedVars = new Map<string, { line: number; type: string }>();
  
  for (const def of definitions) {
    for (const source of sources) {
      if (def.value.includes(source)) {
        taintedVars.set(def.variable, { line: def.line, type: source });
      }
    }
  }

  // Track taint propagation through assignments
  for (const def of definitions) {
    for (const [taintedVar, taintInfo] of taintedVars) {
      if (def.value.includes(taintedVar)) {
        taintedVars.set(def.variable, taintInfo);
      }
    }
  }

  // Check if tainted vars reach sinks
  for (const def of definitions) {
    if (taintedVars.has(def.variable)) {
      for (const sink of sinks) {
        if (def.value.includes(sink)) {
          const taintInfo = taintedVars.get(def.variable)!;
          result.taintedFlows.push({
            source: { 
              variable: def.variable, 
              line: taintInfo.line, 
              type: taintInfo.type 
            },
            sink: { 
              variable: def.variable, 
              line: def.line, 
              type: sink 
            },
            path: [taintInfo.line, def.line],
          });
        }
      }
    }
  }

  // Find dead stores (defined but never used)
  const usedVars = new Set(uses.map(u => u.variable));
  for (const def of definitions) {
    if (!usedVars.has(def.variable)) {
      result.deadStores.push({
        variable: def.variable,
        line: def.line,
      });
    }
  }

  return result;
}
