/**
 * AST Utilities for JavaScript/TypeScript Analysis
 * Provides AST parsing and traversal utilities using Babel Parser
 * 
 * Inspired by Semgrep's AST pattern matching
 */

import * as parser from '@babel/parser';
import traverse, { NodePath } from '@babel/traverse';
import * as t from '@babel/types';

/**
 * AST Parse Options
 */
export interface ASTParseOptions {
  /** Source type (script, module, unambiguous) */
  sourceType?: 'script' | 'module' | 'unambiguous';
  /** Enable TypeScript parsing */
  typescript?: boolean;
  /** Enable JSX parsing */
  jsx?: boolean;
  /** Allow return outside function */
  allowReturnOutsideFunction?: boolean;
  /** Error recovery mode */
  errorRecovery?: boolean;
}

/**
 * AST Node Location
 */
export interface ASTLocation {
  startLine: number;
  endLine: number;
  startColumn: number;
  endColumn: number;
}

/**
 * Dangerous call detected in AST
 */
export interface DangerousCall {
  /** Name of the dangerous function/method */
  name: string;
  /** Full call expression code */
  code: string;
  /** Location in source */
  location: ASTLocation;
  /** Type of dangerous pattern */
  patternType: DangerousPatternType;
  /** Arguments passed to the call */
  arguments: string[];
  /** Caller object (for method calls) */
  callee?: string;
  /** Additional context */
  context?: string;
}

/**
 * Types of dangerous patterns
 */
export enum DangerousPatternType {
  CODE_EXECUTION = 'code_execution',
  COMMAND_INJECTION = 'command_injection',
  PROTOTYPE_POLLUTION = 'prototype_pollution',
  XSS_SINK = 'xss_sink',
  DYNAMIC_REQUIRE = 'dynamic_require',
  INSECURE_RANDOM = 'insecure_random',
  HARDCODED_SECRET = 'hardcoded_secret',
  DANGEROUS_REGEX = 'dangerous_regex',
  UNSAFE_ASSIGNMENT = 'unsafe_assignment',
  NETWORK_REQUEST = 'network_request',
  FILE_OPERATION = 'file_operation',
  CRYPTO_WEAKNESS = 'crypto_weakness'
}

/**
 * AST Pattern definition
 */
export interface ASTPattern {
  /** Pattern type */
  type: DangerousPatternType;
  /** Description of the pattern */
  description: string;
  /** Matcher function */
  matcher: (path: NodePath, context: ASTContext) => boolean;
  /** Extract relevant information */
  extractor?: (path: NodePath) => Partial<DangerousCall>;
}

/**
 * AST Analysis Context
 */
export interface ASTContext {
  /** Current file path */
  filePath: string;
  /** Source content */
  source: string;
  /** Detected imports/requires */
  imports: Map<string, string>;
  /** Is this TypeScript? */
  isTypeScript: boolean;
  /** Is this JSX? */
  isJSX: boolean;
}

/**
 * Dangerous function calls to detect
 */
const DANGEROUS_FUNCTIONS = new Map<string, DangerousPatternType>([
  // Code execution
  ['eval', DangerousPatternType.CODE_EXECUTION],
  ['Function', DangerousPatternType.CODE_EXECUTION],
  ['execScript', DangerousPatternType.CODE_EXECUTION],
  // Command injection
  ['exec', DangerousPatternType.COMMAND_INJECTION],
  ['execSync', DangerousPatternType.COMMAND_INJECTION],
  ['spawn', DangerousPatternType.COMMAND_INJECTION],
  ['spawnSync', DangerousPatternType.COMMAND_INJECTION],
  ['execFile', DangerousPatternType.COMMAND_INJECTION],
  ['execFileSync', DangerousPatternType.COMMAND_INJECTION],
  ['fork', DangerousPatternType.COMMAND_INJECTION],
  // Insecure random
  ['Math.random', DangerousPatternType.INSECURE_RANDOM],
]);

/**
 * Dangerous method calls to detect (callee.method)
 */
const DANGEROUS_METHODS = new Map<string, Map<string, DangerousPatternType>>([
  ['child_process', new Map([
    ['exec', DangerousPatternType.COMMAND_INJECTION],
    ['execSync', DangerousPatternType.COMMAND_INJECTION],
    ['spawn', DangerousPatternType.COMMAND_INJECTION],
    ['spawnSync', DangerousPatternType.COMMAND_INJECTION],
  ])],
  ['document', new Map([
    ['write', DangerousPatternType.XSS_SINK],
    ['writeln', DangerousPatternType.XSS_SINK],
  ])],
  ['fs', new Map([
    ['readFile', DangerousPatternType.FILE_OPERATION],
    ['readFileSync', DangerousPatternType.FILE_OPERATION],
    ['writeFile', DangerousPatternType.FILE_OPERATION],
    ['writeFileSync', DangerousPatternType.FILE_OPERATION],
    ['unlink', DangerousPatternType.FILE_OPERATION],
    ['unlinkSync', DangerousPatternType.FILE_OPERATION],
  ])],
]);

/**
 * AST Utilities Class
 */
export class ASTUtils {
  private ast: t.File | null = null;
  private source: string = '';
  private context: ASTContext | null = null;

  /**
   * Parse source code to AST
   */
  parse(source: string, options: ASTParseOptions = {}): t.File | null {
    this.source = source;
    
    const parseOptions: parser.ParserOptions = {
      sourceType: options.sourceType || 'unambiguous',
      allowReturnOutsideFunction: options.allowReturnOutsideFunction ?? true,
      errorRecovery: options.errorRecovery ?? true,
      plugins: [
        'decorators-legacy',
        'classProperties',
        'classPrivateProperties',
        'classPrivateMethods',
        'exportDefaultFrom',
        'exportNamespaceFrom',
        'dynamicImport',
        'nullishCoalescingOperator',
        'optionalChaining',
        'optionalCatchBinding',
        'objectRestSpread',
        'numericSeparator',
        'bigInt',
        'asyncGenerators',
        'functionBind',
        'throwExpressions',
        'partialApplication',
        'topLevelAwait',
      ]
    };

    // Add TypeScript plugin if needed
    if (options.typescript) {
      parseOptions.plugins!.push('typescript');
    }

    // Add JSX plugin if needed
    if (options.jsx) {
      parseOptions.plugins!.push('jsx');
    }

    try {
      this.ast = parser.parse(source, parseOptions);
      return this.ast;
    } catch (error) {
      // Try with error recovery
      try {
        parseOptions.errorRecovery = true;
        this.ast = parser.parse(source, parseOptions);
        return this.ast;
      } catch {
        return null;
      }
    }
  }

  /**
   * Safe AST parsing with automatic feature detection
   */
  safeParse(source: string, filePath: string): t.File | null {
    const isTypeScript = /\.tsx?$/i.test(filePath);
    const isJSX = /\.[jt]sx$/i.test(filePath) || source.includes('React') || /<\w+[^>]*>/.test(source);

    return this.parse(source, {
      typescript: isTypeScript,
      jsx: isJSX,
      sourceType: 'unambiguous',
      errorRecovery: true
    });
  }

  /**
   * Find all dangerous calls in the AST
   */
  findDangerousCalls(filePath: string): DangerousCall[] {
    if (!this.ast) return [];

    const calls: DangerousCall[] = [];
    const imports = this.extractImports();
    
    this.context = {
      filePath,
      source: this.source,
      imports,
      isTypeScript: /\.tsx?$/i.test(filePath),
      isJSX: /\.[jt]sx$/i.test(filePath)
    };

    try {
      traverse(this.ast, {
        CallExpression: (path) => {
          const call = this.analyzeCallExpression(path);
          if (call) calls.push(call);
        },
        NewExpression: (path) => {
          const call = this.analyzeNewExpression(path);
          if (call) calls.push(call);
        },
        AssignmentExpression: (path) => {
          const call = this.analyzeAssignment(path);
          if (call) calls.push(call);
        },
        MemberExpression: (path) => {
          const call = this.analyzeMemberExpression(path);
          if (call) calls.push(call);
        }
      });
    } catch {
      // Traversal error, return what we have
    }

    return calls;
  }

  /**
   * Analyze a call expression for dangerous patterns
   */
  private analyzeCallExpression(path: NodePath<t.CallExpression>): DangerousCall | null {
    const node = path.node;
    const callee = node.callee;

    // Direct function call: eval(), Function(), etc.
    if (t.isIdentifier(callee)) {
      const funcName = callee.name;
      const patternType = DANGEROUS_FUNCTIONS.get(funcName);
      
      if (patternType) {
        return {
          name: funcName,
          code: this.getNodeCode(node),
          location: this.getLocation(node),
          patternType,
          arguments: this.extractArguments(node.arguments)
        };
      }

      // Dynamic require
      if (funcName === 'require' && node.arguments.length > 0) {
        const arg = node.arguments[0];
        if (!t.isStringLiteral(arg)) {
          return {
            name: 'require',
            code: this.getNodeCode(node),
            location: this.getLocation(node),
            patternType: DangerousPatternType.DYNAMIC_REQUIRE,
            arguments: this.extractArguments(node.arguments),
            context: 'Dynamic require with non-literal argument'
          };
        }
      }
    }

    // Method call: obj.method()
    if (t.isMemberExpression(callee)) {
      const result = this.analyzeMemberCall(node, callee);
      if (result) return result;
    }

    return null;
  }

  /**
   * Analyze a method call (obj.method())
   */
  private analyzeMemberCall(
    node: t.CallExpression,
    callee: t.MemberExpression
  ): DangerousCall | null {
    let objectName = '';
    let methodName = '';

    // Get object name
    if (t.isIdentifier(callee.object)) {
      objectName = callee.object.name;
    } else if (t.isMemberExpression(callee.object) && t.isIdentifier(callee.object.property)) {
      // Handle child_process.exec
      objectName = this.getMemberExpressionName(callee.object);
    }

    // Get method name
    if (t.isIdentifier(callee.property)) {
      methodName = callee.property.name;
    } else if (t.isStringLiteral(callee.property)) {
      methodName = callee.property.value;
    }

    // Check for dangerous methods
    const moduleMethods = DANGEROUS_METHODS.get(objectName);
    if (moduleMethods) {
      const patternType = moduleMethods.get(methodName);
      if (patternType) {
        return {
          name: methodName,
          code: this.getNodeCode(node),
          location: this.getLocation(node),
          patternType,
          arguments: this.extractArguments(node.arguments),
          callee: objectName
        };
      }
    }

    // Check for Math.random
    if (objectName === 'Math' && methodName === 'random') {
      return {
        name: 'Math.random',
        code: this.getNodeCode(node),
        location: this.getLocation(node),
        patternType: DangerousPatternType.INSECURE_RANDOM,
        arguments: [],
        callee: 'Math'
      };
    }

    // Check for DOM XSS sinks
    const xssMethods = ['write', 'writeln'];
    if (objectName === 'document' && xssMethods.includes(methodName)) {
      return {
        name: methodName,
        code: this.getNodeCode(node),
        location: this.getLocation(node),
        patternType: DangerousPatternType.XSS_SINK,
        arguments: this.extractArguments(node.arguments),
        callee: 'document'
      };
    }

    return null;
  }

  /**
   * Analyze new expression: new Function(), etc.
   */
  private analyzeNewExpression(path: NodePath<t.NewExpression>): DangerousCall | null {
    const node = path.node;
    
    if (t.isIdentifier(node.callee)) {
      const className = node.callee.name;
      
      // new Function(...) is like eval
      if (className === 'Function') {
        return {
          name: 'new Function',
          code: this.getNodeCode(node),
          location: this.getLocation(node),
          patternType: DangerousPatternType.CODE_EXECUTION,
          arguments: this.extractArguments(node.arguments)
        };
      }

      // new WebAssembly.Instance with potentially malicious wasm
      if (className === 'WebAssembly') {
        return {
          name: 'new WebAssembly',
          code: this.getNodeCode(node),
          location: this.getLocation(node),
          patternType: DangerousPatternType.CODE_EXECUTION,
          arguments: this.extractArguments(node.arguments),
          context: 'WebAssembly instantiation - verify source'
        };
      }
    }

    return null;
  }

  /**
   * Analyze assignment for dangerous patterns
   */
  private analyzeAssignment(path: NodePath<t.AssignmentExpression>): DangerousCall | null {
    const node = path.node;
    
    // Check for innerHTML/outerHTML assignment
    if (t.isMemberExpression(node.left)) {
      const property = node.left.property;
      let propName = '';
      
      if (t.isIdentifier(property)) {
        propName = property.name;
      } else if (t.isStringLiteral(property)) {
        propName = property.value;
      }

      const xssSinks = ['innerHTML', 'outerHTML'];
      if (xssSinks.includes(propName)) {
        return {
          name: propName,
          code: this.getNodeCode(node),
          location: this.getLocation(node),
          patternType: DangerousPatternType.XSS_SINK,
          arguments: [this.getNodeCode(node.right)]
        };
      }

      // Check for prototype pollution
      if (propName === '__proto__' || 
          (t.isIdentifier(property) && property.name === 'prototype')) {
        return {
          name: '__proto__',
          code: this.getNodeCode(node),
          location: this.getLocation(node),
          patternType: DangerousPatternType.PROTOTYPE_POLLUTION,
          arguments: [this.getNodeCode(node.right)]
        };
      }
    }

    return null;
  }

  /**
   * Analyze member expression for dangerous patterns
   */
  private analyzeMemberExpression(path: NodePath<t.MemberExpression>): DangerousCall | null {
    const node = path.node;
    
    // Check for prototype access
    if (t.isIdentifier(node.property) && node.property.name === '__proto__') {
      // Skip if already analyzed as assignment
      if (t.isAssignmentExpression(path.parent)) return null;
      
      return {
        name: '__proto__',
        code: this.getNodeCode(node),
        location: this.getLocation(node),
        patternType: DangerousPatternType.PROTOTYPE_POLLUTION,
        arguments: []
      };
    }

    // Check for bracket notation with __proto__
    if (t.isStringLiteral(node.property) && node.property.value === '__proto__') {
      return {
        name: '__proto__',
        code: this.getNodeCode(node),
        location: this.getLocation(node),
        patternType: DangerousPatternType.PROTOTYPE_POLLUTION,
        arguments: []
      };
    }

    return null;
  }

  /**
   * Extract imports/requires from the AST
   */
  private extractImports(): Map<string, string> {
    const imports = new Map<string, string>();
    if (!this.ast) return imports;

    try {
      traverse(this.ast, {
        ImportDeclaration: (path) => {
          const source = path.node.source.value;
          for (const specifier of path.node.specifiers) {
            if (t.isImportDefaultSpecifier(specifier) || t.isImportNamespaceSpecifier(specifier)) {
              imports.set(specifier.local.name, source);
            } else if (t.isImportSpecifier(specifier)) {
              imports.set(specifier.local.name, source);
            }
          }
        },
        VariableDeclarator: (path) => {
          const node = path.node;
          if (t.isCallExpression(node.init) && 
              t.isIdentifier(node.init.callee) && 
              node.init.callee.name === 'require' &&
              node.init.arguments.length > 0 &&
              t.isStringLiteral(node.init.arguments[0])) {
            
            const source = node.init.arguments[0].value;
            if (t.isIdentifier(node.id)) {
              imports.set(node.id.name, source);
            } else if (t.isObjectPattern(node.id)) {
              for (const prop of node.id.properties) {
                if (t.isObjectProperty(prop) && t.isIdentifier(prop.value)) {
                  imports.set(prop.value.name, source);
                }
              }
            }
          }
        }
      });
    } catch {
      // Ignore traversal errors
    }

    return imports;
  }

  /**
   * Get the source code for a node
   */
  private getNodeCode(node: t.Node): string {
    if (node.start !== null && node.start !== undefined && 
        node.end !== null && node.end !== undefined) {
      return this.source.substring(node.start, node.end);
    }
    return '';
  }

  /**
   * Get location information for a node
   */
  private getLocation(node: t.Node): ASTLocation {
    return {
      startLine: node.loc?.start.line || 1,
      endLine: node.loc?.end.line || 1,
      startColumn: node.loc?.start.column || 0,
      endColumn: node.loc?.end.column || 0
    };
  }

  /**
   * Extract arguments as strings
   */
  private extractArguments(args: (t.Expression | t.SpreadElement | t.ArgumentPlaceholder)[]): string[] {
    return args.map(arg => {
      if (t.isSpreadElement(arg)) {
        return `...${this.getNodeCode(arg.argument)}`;
      }
      return this.getNodeCode(arg);
    });
  }

  /**
   * Get full name of member expression
   */
  private getMemberExpressionName(node: t.MemberExpression): string {
    const parts: string[] = [];
    
    let current: t.Node = node;
    while (t.isMemberExpression(current)) {
      if (t.isIdentifier(current.property)) {
        parts.unshift(current.property.name);
      } else if (t.isStringLiteral(current.property)) {
        parts.unshift(current.property.value);
      }
      current = current.object;
    }
    
    if (t.isIdentifier(current)) {
      parts.unshift(current.name);
    }
    
    return parts.join('.');
  }

  /**
   * Find all string literals that look like hardcoded secrets
   */
  findHardcodedSecrets(): DangerousCall[] {
    const secrets: DangerousCall[] = [];
    if (!this.ast) return secrets;

    const secretPatterns = [
      { pattern: /^(api[_-]?key|apikey)\s*[:=]\s*['"`]([^'"`]{10,})['"`]/i, name: 'API Key' },
      { pattern: /^(secret|password|passwd|pwd)\s*[:=]\s*['"`]([^'"`]{6,})['"`]/i, name: 'Password/Secret' },
      { pattern: /^(token|access[_-]?token|auth[_-]?token)\s*[:=]\s*['"`]([^'"`]{10,})['"`]/i, name: 'Token' },
      { pattern: /^(private[_-]?key)\s*[:=]\s*['"`]([^'"`]{20,})['"`]/i, name: 'Private Key' },
    ];

    const stringLiteralPatterns = [
      { pattern: /^(sk[_-]live[_-][a-zA-Z0-9]{24,})$/, name: 'Stripe Secret Key' },
      { pattern: /^(sk[_-]test[_-][a-zA-Z0-9]{24,})$/, name: 'Stripe Test Key' },
      { pattern: /^(ghp_[a-zA-Z0-9]{36})$/, name: 'GitHub Personal Access Token' },
      { pattern: /^(gho_[a-zA-Z0-9]{36})$/, name: 'GitHub OAuth Token' },
      { pattern: /^(glpat-[a-zA-Z0-9-_]{20,})$/, name: 'GitLab Personal Access Token' },
      { pattern: /^(xox[baprs]-[0-9]{10,13}-[a-zA-Z0-9-]+)$/, name: 'Slack Token' },
      { pattern: /^(AKIA[0-9A-Z]{16})$/, name: 'AWS Access Key ID' },
      { pattern: /^(eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+)$/, name: 'JWT Token' },
    ];

    try {
      traverse(this.ast, {
        StringLiteral: (path) => {
          const value = path.node.value;
          
          for (const { pattern, name } of stringLiteralPatterns) {
            if (pattern.test(value)) {
              secrets.push({
                name,
                code: `"${value.substring(0, 20)}..."`,
                location: this.getLocation(path.node),
                patternType: DangerousPatternType.HARDCODED_SECRET,
                arguments: [],
                context: `Hardcoded ${name} detected`
              });
            }
          }
        },
        VariableDeclarator: (path) => {
          if (t.isIdentifier(path.node.id) && t.isStringLiteral(path.node.init)) {
            const varName = path.node.id.name.toLowerCase();
            const value = path.node.init.value;
            
            for (const { pattern, name } of secretPatterns) {
              const testStr = `${varName}="${value}"`;
              if (pattern.test(testStr) && value.length >= 8) {
                secrets.push({
                  name,
                  code: `${path.node.id.name} = "${value.substring(0, 10)}..."`,
                  location: this.getLocation(path.node),
                  patternType: DangerousPatternType.HARDCODED_SECRET,
                  arguments: [],
                  context: `Potential hardcoded ${name}`
                });
              }
            }
          }
        }
      });
    } catch {
      // Ignore traversal errors
    }

    return secrets;
  }

  /**
   * Find ReDoS-vulnerable regex patterns
   */
  findDangerousRegex(): DangerousCall[] {
    const dangerous: DangerousCall[] = [];
    if (!this.ast) return dangerous;

    // Patterns that can cause ReDoS
    const redosPatterns = [
      /(\+|\*)\1/, // Nested quantifiers like (a+)+ 
      /\([^)]*\+[^)]*\)\+/, // (a+)+
      /\([^)]*\*[^)]*\)\*/, // (a*)*
      /\([^)]*\+[^)]*\)\*/, // (a+)*
      /\([^)]*\*[^)]*\)\+/, // (a*)+
    ];

    try {
      traverse(this.ast, {
        RegExpLiteral: (path) => {
          const pattern = path.node.pattern;
          
          for (const redos of redosPatterns) {
            if (redos.test(pattern)) {
              dangerous.push({
                name: 'ReDoS Pattern',
                code: `/${pattern}/${path.node.flags}`,
                location: this.getLocation(path.node),
                patternType: DangerousPatternType.DANGEROUS_REGEX,
                arguments: [],
                context: 'Potential ReDoS vulnerability'
              });
              break;
            }
          }
        },
        NewExpression: (path) => {
          if (t.isIdentifier(path.node.callee) && 
              path.node.callee.name === 'RegExp' &&
              path.node.arguments.length > 0 &&
              t.isStringLiteral(path.node.arguments[0])) {
            
            const pattern = path.node.arguments[0].value;
            
            for (const redos of redosPatterns) {
              if (redos.test(pattern)) {
                dangerous.push({
                  name: 'ReDoS Pattern',
                  code: `new RegExp("${pattern}")`,
                  location: this.getLocation(path.node),
                  patternType: DangerousPatternType.DANGEROUS_REGEX,
                  arguments: [pattern],
                  context: 'Potential ReDoS vulnerability'
                });
                break;
              }
            }
          }
        }
      });
    } catch {
      // Ignore traversal errors
    }

    return dangerous;
  }

  /**
   * Check if code contains anti-debugging techniques
   */
  findAntiDebugging(): DangerousCall[] {
    const detected: DangerousCall[] = [];
    if (!this.ast) return detected;

    try {
      traverse(this.ast, {
        MemberExpression: (path) => {
          // Check for debugger detection via console timing
          if (t.isIdentifier(path.node.object) && 
              path.node.object.name === 'console' &&
              t.isIdentifier(path.node.property)) {
            
            // Look for timing-based detection
            const parent = path.parent;
            if (t.isCallExpression(parent)) {
              const funcParent = path.findParent(p => t.isFunctionDeclaration(p.node) || t.isFunctionExpression(p.node));
              // Check context for anti-debugging patterns (unused for now)
              void funcParent;
            }
          }
        },
        DebuggerStatement: (path) => {
          // Multiple debugger statements can be used to annoy debuggers
          detected.push({
            name: 'debugger',
            code: 'debugger',
            location: this.getLocation(path.node),
            patternType: DangerousPatternType.CODE_EXECUTION,
            arguments: [],
            context: 'Debugger statement detected'
          });
        }
      });
    } catch {
      // Ignore traversal errors
    }

    return detected;
  }
}

export default ASTUtils;
