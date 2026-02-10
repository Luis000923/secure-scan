/**
 * JavaScript/TypeScript Security Analyzer v2.0
 * Advanced SAST analyzer with AST-based detection, taint analysis, and malware detection
 * 
 * Features:
 * - AST-based vulnerability detection (Babel Parser)
 * - Taint analysis (source-to-sink tracking)
 * - Malware detection (cryptominers, stealers, backdoors, etc.)
 * - Package.json security analysis
 * - OWASP/CWE compliance
 * 
 * @version 2.0.0
 * @author Secure-Scan Team
 */

import { BaseAnalyzer } from '../base';
import {
  ScannedFile,
  Finding,
  Rule,
  SupportedLanguage,
  Severity,
  ThreatType,
  FindingCategory,
  SecurityStandard
} from '../../types';
import { generateId, extractCodeContext, looksObfuscated, calculateEntropy } from '../../utils';
import { getStandardsForThreat } from '../../rules/standards';
import { logger } from '../../utils/logger';

// Import specialized modules
import { TaintAnalyzer, TaintFlow, TAINT_SOURCES, TAINT_SINKS } from './taintAnalyzer';
import { ASTUtils, DangerousCall, DangerousPatternType } from './astUtils';
import { MalwareDetector, MalwareMatch, MalwareType } from './malwareDetector';
import { PackageJsonAnalyzer, PackageJsonFinding } from './packageJsonAnalyzer';

/**
 * Analysis options for the JavaScript Analyzer
 */
export interface JSAnalyzerOptions {
  /** Enable AST-based analysis */
  enableAST?: boolean;
  /** Enable taint analysis */
  enableTaintAnalysis?: boolean;
  /** Enable malware detection */
  enableMalwareDetection?: boolean;
  /** Enable package.json analysis */
  enablePackageAnalysis?: boolean;
  /** Maximum file size to analyze (bytes) */
  maxFileSize?: number;
  /** Timeout per file (ms) */
  fileTimeout?: number;
  /** Minimum confidence to report (0-100) */
  minConfidence?: number;
}

/**
 * Default analyzer options
 */
const DEFAULT_OPTIONS: JSAnalyzerOptions = {
  enableAST: true,
  enableTaintAnalysis: true,
  enableMalwareDetection: true,
  enablePackageAnalysis: true,
  maxFileSize: 5 * 1024 * 1024, // 5MB
  fileTimeout: 30000, // 30 seconds
  minConfidence: 60
};

/**
 * Placeholder/example values that should not trigger hardcoded credential alerts
 */
const CREDENTIAL_PLACEHOLDER_PATTERNS = /^(?:password123|changeme|xxx+|TODO|your[-_]?(?:api[-_]?key|secret|password|token)[-_]?here|example|test|dummy|placeholder|CHANGE[-_]?ME|replace[-_]?me|insert[-_]?here|\*+|<.*>)$/i;

/**
 * Lines that are type definitions / schemas and should not trigger credential alerts
 */
const SCHEMA_LINE_PATTERNS = /(?:type\s|interface\s|schema|validator|joi\.|yup\.|zod\.|PropTypes|\bdescribe\s*\(|\@param|\@type|\@property)/i;

/**
 * Patterns indicating vendor/minified/bundled file paths
 */
const VENDOR_PATH_PATTERNS = /(?:node_modules|vendor|dist|build|bundle|\bmin\b|\.min\.)/i;

/**
 * Vulnerability patterns for regex-based fallback detection
 */
interface VulnerabilityPattern {
  id: string;
  name: string;
  pattern: RegExp;
  severity: Severity;
  threatType: ThreatType;
  category: FindingCategory;
  description: string;
  remediation: string;
  confidence: number;
  tags: string[];
}

/**
 * Vulnerability patterns database (regex fallback)
 */
const VULNERABILITY_PATTERNS: VulnerabilityPattern[] = [
  // === CODE EXECUTION ===
  {
    id: 'JS-EXEC-001',
    name: 'Uso de eval()',
    pattern: /\beval\s*\(\s*(?!['"`])/g,
    severity: Severity.CRITICAL,
    threatType: ThreatType.COMMAND_INJECTION,
    category: FindingCategory.VULNERABILITY,
    description: 'El uso de eval() con contenido dinámico puede conducir a la inyección de código.',
    remediation: 'Evite eval(). Use JSON.parse() para datos JSON o alternativas más seguras.',
    confidence: 85,
    tags: ['injection', 'rce', 'owasp-a03']
  },
  {
    id: 'JS-EXEC-002',
    name: 'Constructor de Función',
    pattern: /\bnew\s+Function\s*\(/g,
    severity: Severity.CRITICAL,
    threatType: ThreatType.COMMAND_INJECTION,
    category: FindingCategory.VULNERABILITY,
    description: 'new Function() es equivalente a eval() y puede ejecutar código arbitrario.',
    remediation: 'Use funciones predefinidas en lugar de crearlas dinámicamente.',
    confidence: 85,
    tags: ['injection', 'rce', 'owasp-a03']
  },
  {
    id: 'JS-EXEC-003',
    name: 'setTimeout/setInterval con Cadena',
    pattern: /\bset(?:Timeout|Interval)\s*\(\s*['"`][^'"`]+['"`]/g,
    severity: Severity.HIGH,
    threatType: ThreatType.COMMAND_INJECTION,
    category: FindingCategory.VULNERABILITY,
    description: 'setTimeout/setInterval con argumento de cadena actúa como eval().',
    remediation: 'Pase una referencia de función en lugar de una cadena.',
    confidence: 80,
    tags: ['injection', 'owasp-a03']
  },

  // === COMMAND INJECTION ===
  {
    id: 'JS-CMD-001',
    name: 'exec() de child_process',
    pattern: /(?:child_process\.)?exec\s*\(\s*(?!['"`])/g,
    severity: Severity.CRITICAL,
    threatType: ThreatType.COMMAND_INJECTION,
    category: FindingCategory.VULNERABILITY,
    description: 'exec() con una cadena de comando dinámica es vulnerable a la inyección de comandos.',
    remediation: 'Use execFile() con un array de argumentos en lugar de exec().',
    confidence: 80,
    tags: ['injection', 'rce', 'owasp-a03']
  },
  {
    id: 'JS-CMD-002',
    name: 'spawn con shell: true',
    pattern: /spawn\s*\([^)]*shell\s*:\s*true/g,
    severity: Severity.HIGH,
    threatType: ThreatType.COMMAND_INJECTION,
    category: FindingCategory.VULNERABILITY,
    description: 'spawn() con la opción shell es vulnerable a la inyección de comandos.',
    remediation: 'Elimine shell: true y pase los argumentos como un array.',
    confidence: 85,
    tags: ['injection', 'rce', 'owasp-a03']
  },

  // === XSS VULNERABILITIES ===
  {
    id: 'JS-XSS-001',
    name: 'Asignación innerHTML',
    pattern: /\.innerHTML\s*=\s*(?!['"`]<)/g,
    severity: Severity.HIGH,
    threatType: ThreatType.XSS,
    category: FindingCategory.VULNERABILITY,
    description: 'La asignación directa de innerHTML con contenido dinámico permite XSS.',
    remediation: 'Use textContent para texto, o sanitice con DOMPurify.',
    confidence: 75,
    tags: ['xss', 'dom', 'owasp-a03']
  },
  {
    id: 'JS-XSS-002',
    name: 'document.write()',
    pattern: /document\.write(?:ln)?\s*\(/g,
    severity: Severity.HIGH,
    threatType: ThreatType.XSS,
    category: FindingCategory.VULNERABILITY,
    description: 'document.write() con contenido dinámico es vulnerable a XSS.',
    remediation: 'Use métodos de manipulación del DOM como createElement() y textContent.',
    confidence: 80,
    tags: ['xss', 'dom', 'owasp-a03']
  },
  {
    id: 'JS-XSS-003',
    name: 'insertAdjacentHTML()',
    pattern: /\.insertAdjacentHTML\s*\(/g,
    severity: Severity.HIGH,
    threatType: ThreatType.XSS,
    category: FindingCategory.VULNERABILITY,
    description: 'insertAdjacentHTML() con contenido no sanitizado permite XSS.',
    remediation: 'Sanitice el contenido HTML con DOMPurify antes de la inserción.',
    confidence: 75,
    tags: ['xss', 'dom', 'owasp-a03']
  },
  {
    id: 'JS-XSS-004',
    name: 'jQuery .html()',
    pattern: /\$\([^)]+\)\.html\s*\(\s*(?!['"`]<)/g,
    severity: Severity.HIGH,
    threatType: ThreatType.XSS,
    category: FindingCategory.VULNERABILITY,
    description: 'jQuery .html() con contenido dinámico es vulnerable a XSS.',
    remediation: 'Use .text() para contenido de texto o sanitice antes de .html().',
    confidence: 70,
    tags: ['xss', 'jquery', 'owasp-a03']
  },

  // === PROTOTYPE POLLUTION ===
  {
    id: 'JS-PP-001',
    name: 'Acceso a __proto__',
    pattern: /\[['"`]?__proto__['"`]?\]|\.__proto__\b/g,
    severity: Severity.HIGH,
    threatType: ThreatType.DANGEROUS_FUNCTION,
    category: FindingCategory.VULNERABILITY,
    description: 'El acceso directo a __proto__ puede conducir a la polución de prototipos.',
    remediation: 'Use Object.create(null) para objetos seguros o valide las claves.',
    confidence: 85,
    tags: ['prototype-pollution', 'owasp-a03']
  },
  {
    id: 'JS-PP-002',
    name: 'Object.prototype Modification',
    pattern: /Object\.prototype\s*\.\s*\w+\s*=/g,
    severity: Severity.HIGH,
    threatType: ThreatType.DANGEROUS_FUNCTION,
    category: FindingCategory.VULNERABILITY,
    description: 'Modifying Object.prototype affects all objects.',
    remediation: 'Avoid modifying built-in prototypes.',
    confidence: 90,
    tags: ['prototype-pollution', 'owasp-a03']
  },
  {
    id: 'JS-PP-003',
    name: 'constructor.prototype Access',
    pattern: /constructor\s*\.\s*prototype/g,
    severity: Severity.MEDIUM,
    threatType: ThreatType.DANGEROUS_FUNCTION,
    category: FindingCategory.VULNERABILITY,
    description: 'El acceso a constructor.prototype puede indicar una polución de prototipos.',
    remediation: 'Valide y sanitice cualquier acceso dinámico a propiedades.',
    confidence: 70,
    tags: ['prototype-pollution', 'owasp-a03']
  },

  // === INSECURE RANDOMNESS ===
  {
    id: 'JS-RAND-001',
    name: 'Math.random() para Seguridad',
    pattern: /(?:token|secret|key|password|salt|nonce|iv)\s*[=:]\s*[^;{]*Math\.random/gi,
    severity: Severity.HIGH,
    threatType: ThreatType.WEAK_RANDOM,
    category: FindingCategory.VULNERABILITY,
    description: 'Math.random() no es criptográficamente seguro.',
    remediation: 'Use crypto.randomBytes() o crypto.getRandomValues().',
    confidence: 80,
    tags: ['crypto', 'random', 'owasp-a02']
  },

  // === HARDCODED CREDENTIALS ===
  {
    id: 'JS-CRED-001',
    name: 'Contraseña Hardcoded',
    pattern: /(?:password|passwd|pwd)\s*[=:]\s*['"`][^'"`]{6,}['"`]/gi,
    severity: Severity.HIGH,
    threatType: ThreatType.HARDCODED_CREDENTIALS,
    category: FindingCategory.VULNERABILITY,
    description: 'Se detectó una contraseña hardcoded en el código fuente.',
    remediation: 'Use variables de entorno o un gestor de secretos.',
    confidence: 75,
    tags: ['credentials', 'secrets', 'owasp-a07']
  },
  {
    id: 'JS-CRED-002',
    name: 'Clave de API Hardcoded',
    pattern: /(?:api[_-]?key|apikey)\s*[=:]\s*['"`][a-zA-Z0-9_-]{20,}['"`]/gi,
    severity: Severity.HIGH,
    threatType: ThreatType.HARDCODED_CREDENTIALS,
    category: FindingCategory.VULNERABILITY,
    description: 'Se detectó una clave de API hardcoded en el código fuente.',
    remediation: 'Use variables de entorno o un gestor de secretos.',
    confidence: 80,
    tags: ['credentials', 'secrets', 'owasp-a07']
  },
  {
    id: 'JS-CRED-003',
    name: 'Secreto/Token Hardcoded',
    pattern: /(?:secret|token|auth)\s*[=:]\s*['"`][a-zA-Z0-9_-]{20,}['"`]/gi,
    severity: Severity.HIGH,
    threatType: ThreatType.HARDCODED_CREDENTIALS,
    category: FindingCategory.VULNERABILITY,
    description: 'Se detectó un secreto o token hardcoded en el código fuente.',
    remediation: 'Use variables de entorno o un gestor de secretos.',
    confidence: 75,
    tags: ['credentials', 'secrets', 'owasp-a07']
  },

  // === INSECURE CRYPTO ===
  {
    id: 'JS-CRYPTO-001',
    name: 'Uso de MD5',
    pattern: /(?:createHash|crypto)\s*\(\s*['"`]md5['"`]\s*\)/gi,
    severity: Severity.MEDIUM,
    threatType: ThreatType.INSECURE_CRYPTO,
    category: FindingCategory.VULNERABILITY,
    description: 'MD5 está criptográficamente roto y no debe ser usado.',
    remediation: 'Use SHA-256 o superior para hashing.',
    confidence: 90,
    tags: ['crypto', 'hash', 'owasp-a02']
  },
  {
    id: 'JS-CRYPTO-002',
    name: 'Uso de SHA1',
    pattern: /(?:createHash|crypto)\s*\(\s*['"`]sha1['"`]\s*\)/gi,
    severity: Severity.MEDIUM,
    threatType: ThreatType.INSECURE_CRYPTO,
    category: FindingCategory.VULNERABILITY,
    description: 'SHA-1 está deprecado para uso criptográfico.',
    remediation: 'Use SHA-256 o superior para hashing.',
    confidence: 85,
    tags: ['crypto', 'hash', 'owasp-a02']
  },
  {
    id: 'JS-CRYPTO-003',
    name: 'Uso de DES/3DES',
    pattern: /(?:createCipher|createDecipher)\s*\(\s*['"`](?:des|3des|des-ede3)['"`]/gi,
    severity: Severity.HIGH,
    threatType: ThreatType.INSECURE_CRYPTO,
    category: FindingCategory.VULNERABILITY,
    description: 'DES y 3DES son algoritmos de cifrado obsoletos.',
    remediation: 'Use AES-256-GCM para el cifrado.',
    confidence: 90,
    tags: ['crypto', 'encryption', 'owasp-a02']
  },

  // === PATH TRAVERSAL ===
  {
    id: 'JS-PATH-001',
    name: 'Salto de Directorio en Lectura de Archivo',
    pattern: /(?:readFile|readFileSync|createReadStream)\s*\([^)]*(?:req\.(?:body|query|params)|process\.argv)/gi,
    severity: Severity.HIGH,
    threatType: ThreatType.PATH_TRAVERSAL,
    category: FindingCategory.VULNERABILITY,
    description: 'La lectura de archivos con una ruta controlada por el usuario permite el salto de directorio.',
    remediation: 'Valide las rutas con path.resolve() y verifíquelas contra el directorio base.',
    confidence: 80,
    tags: ['path-traversal', 'file', 'owasp-a01']
  },

  // === SQL INJECTION ===
  {
    id: 'JS-SQL-001',
    name: 'Concatenación de Consulta SQL',
    pattern: /\.query\s*\(\s*['"`](?:SELECT|INSERT|UPDATE|DELETE)[^'"]*\+/gi,
    severity: Severity.CRITICAL,
    threatType: ThreatType.SQL_INJECTION,
    category: FindingCategory.VULNERABILITY,
    description: 'Una consulta SQL con concatenación de cadenas es vulnerable a la inyección.',
    remediation: 'Use consultas parametrizadas o sentencias preparadas.',
    confidence: 85,
    tags: ['sqli', 'injection', 'owasp-a03']
  },
  {
    id: 'JS-SQL-002',
    name: 'Template Literal SQL',
    pattern: /\.query\s*\(\s*`(?:SELECT|INSERT|UPDATE|DELETE)[^`]*\$\{/gi,
    severity: Severity.CRITICAL,
    threatType: ThreatType.SQL_INJECTION,
    category: FindingCategory.VULNERABILITY,
    description: 'Una consulta SQL con interpolación de template literal es vulnerable.',
    remediation: 'Use consultas parametrizadas o sentencias preparadas.',
    confidence: 85,
    tags: ['sqli', 'injection', 'owasp-a03']
  },

  // === SSRF ===
  {
    id: 'JS-SSRF-001',
    name: 'SSRF en fetch()',
    pattern: /fetch\s*\(\s*(?:req\.(?:body|query|params)|`[^`]*\$\{)/gi,
    severity: Severity.HIGH,
    threatType: ThreatType.SECURITY_MISCONFIGURATION,
    category: FindingCategory.VULNERABILITY,
    description: 'fetch() con una URL controlada por el usuario permite ataques SSRF.',
    remediation: 'Valide y ponga en lista blanca las URLs antes de realizar solicitudes.',
    confidence: 75,
    tags: ['ssrf', 'owasp-a10']
  },

  // === INSECURE CONFIGURATION ===
  {
    id: 'JS-CONFIG-001',
    name: 'Comodín en CORS',
    pattern: /(?:cors|Access-Control-Allow-Origin)\s*[=:]\s*['"*]/gi,
    severity: Severity.MEDIUM,
    threatType: ThreatType.SECURITY_MISCONFIGURATION,
    category: FindingCategory.VULNERABILITY,
    description: 'CORS con origen comodín permite que cualquier dominio acceda a la API.',
    remediation: 'Especifique los orígenes permitidos explícitamente.',
    confidence: 80,
    tags: ['cors', 'config', 'owasp-a05']
  },
  {
    id: 'JS-CONFIG-002',
    name: 'Protección CSRF Deshabilitada',
    pattern: /csrf\s*:\s*false|csrfProtection\s*=\s*false/gi,
    severity: Severity.HIGH,
    threatType: ThreatType.CSRF,
    category: FindingCategory.VULNERABILITY,
    description: 'La protección CSRF está explícitamente deshabilitada.',
    remediation: 'Habilite la protección CSRF para operaciones que cambian el estado.',
    confidence: 90,
    tags: ['csrf', 'config', 'owasp-a05']
  },
  {
    id: 'JS-CONFIG-003',
    name: 'Configuración de Cookies Insegura',
    pattern: /(?:secure|httpOnly)\s*:\s*false/gi,
    severity: Severity.MEDIUM,
    threatType: ThreatType.SECURITY_MISCONFIGURATION,
    category: FindingCategory.VULNERABILITY,
    description: 'Los flags de seguridad de las cookies están explícitamente deshabilitados.',
    remediation: 'Establezca secure: true y httpOnly: true para las cookies de sesión.',
    confidence: 85,
    tags: ['cookie', 'config', 'owasp-a05']
  },

  // === POSTMESSAGE VULNERABILITIES ===
  {
    id: 'JS-PM-001',
    name: 'Origen Comodín en postMessage',
    pattern: /postMessage\s*\([^)]+,\s*['"]\*['"]\s*\)/g,
    severity: Severity.MEDIUM,
    threatType: ThreatType.SECURITY_MISCONFIGURATION,
    category: FindingCategory.VULNERABILITY,
    description: 'postMessage con origen "*" puede filtrar datos a cualquier origen.',
    remediation: 'Especifique el origen de destino explícitamente.',
    confidence: 90,
    tags: ['postmessage', 'origin', 'owasp-a05']
  },
  {
    id: 'JS-PM-002',
    name: 'Falta Verificación de Origen',
    pattern: /addEventListener\s*\(\s*['"`]message['"`][^}]*(?:eval|innerHTML|document\.write)/g,
    severity: Severity.HIGH,
    threatType: ThreatType.XSS,
    category: FindingCategory.VULNERABILITY,
    description: 'El manejador de eventos message sin verificación de origen permite XSS.',
    remediation: 'Valide siempre event.origin antes de procesar mensajes.',
    confidence: 75,
    tags: ['postmessage', 'xss', 'owasp-a03']
  },

  // === DANGEROUS PATTERNS ===
  {
    id: 'JS-DANGER-001',
    name: 'Sentencia debugger',
    pattern: /\bdebugger\s*;/g,
    severity: Severity.LOW,
    threatType: ThreatType.SECURITY_MISCONFIGURATION,
    category: FindingCategory.CODE_SMELL,
    description: 'La sentencia debugger debe eliminarse en producción.',
    remediation: 'Elimine las sentencias debugger antes del despliegue.',
    confidence: 100,
    tags: ['debug', 'cleanup']
  },
  {
    id: 'JS-DANGER-002',
    name: 'console.log en Producción',
    pattern: /console\.(?:log|debug|trace)\s*\([^)]*(?:password|secret|token|key)/gi,
    severity: Severity.MEDIUM,
    threatType: ThreatType.INFORMATION_DISCLOSURE,
    category: FindingCategory.VULNERABILITY,
    description: 'Registrar datos sensibles puede exponer credenciales.',
    remediation: 'Elimine o redacte los datos sensibles de los registros.',
    confidence: 70,
    tags: ['logging', 'secrets', 'owasp-a09']
  }
];

/**
 * JavaScript/TypeScript Analyzer Class v2.0
 */
export class JavaScriptAnalyzer extends BaseAnalyzer {
  name = 'JavaScript Analyzer';
  languages: SupportedLanguage[] = ['javascript', 'typescript'];
  version = '2.0.0';

  // Specialized analyzers
  private taintAnalyzer: TaintAnalyzer;
  private astUtils: ASTUtils;
  private malwareDetector: MalwareDetector;
  private packageJsonAnalyzer: PackageJsonAnalyzer;

  // Configuration
  private options: JSAnalyzerOptions;

  constructor(options: JSAnalyzerOptions = {}) {
    super();
    this.options = { ...DEFAULT_OPTIONS, ...options };

    // Initialize specialized analyzers
    this.taintAnalyzer = new TaintAnalyzer();
    this.astUtils = new ASTUtils();
    this.malwareDetector = new MalwareDetector();
    this.packageJsonAnalyzer = new PackageJsonAnalyzer();
  }

  /**
   * Initialize the analyzer
   */
  async initialize(): Promise<void> {
    await super.initialize();
    logger.debug('JavaScript Analyzer v2.0 initialized with AST, Taint, and Malware detection');
  }

  /**
   * Main analysis entry point
   */
  async analyze(file: ScannedFile, rules: Rule[]): Promise<Finding[]> {
    const findings: Finding[] = [];
    const startTime = Date.now();

    try {
      // Skip files that are too large
      if (file.size > this.options.maxFileSize!) {
        logger.warn(`Skipping ${file.relativePath}: file too large (${file.size} bytes)`);
        return findings;
      }

      // Skip minified/vendor files (high avg line length + vendor path)
      if (this.isMinifiedOrVendor(file)) {
        logger.debug(`Skipping ${file.relativePath}: minified or vendor file`);
        return findings;
      }

      // Filter rules for JS/TS
      const jsRules = rules.filter(r =>
        r.languages.includes('javascript') || r.languages.includes('typescript')
      );

      // Run rule engine (inherited from BaseAnalyzer)
      const ruleFindings = await this.ruleEngine.analyzeFile(file, jsRules);
      findings.push(...ruleFindings);

      // Special handling for package.json
      if (file.relativePath.endsWith('package.json')) {
        const pkgFindings = await this.analyzePackageJson(file);
        findings.push(...pkgFindings);
        return this.filterByConfidence(findings);
      }

      // Run parallel analysis for code files
      const analysisPromises: Promise<Finding[]>[] = [];

      // 1. Pattern-based vulnerability detection (fast, always run)
      analysisPromises.push(this.runPatternAnalysis(file));

      // 2. AST-based analysis (accurate, optional)
      if (this.options.enableAST) {
        analysisPromises.push(this.runASTAnalysis(file));
      }

      // 3. Taint analysis (complex, optional)
      if (this.options.enableTaintAnalysis) {
        analysisPromises.push(this.runTaintAnalysis(file));
      }

      // 4. Malware detection (comprehensive, optional)
      if (this.options.enableMalwareDetection) {
        analysisPromises.push(this.runMalwareAnalysis(file));
      }

      // 5. Obfuscation detection
      analysisPromises.push(this.checkObfuscation(file));

      // Wait for all analyses with timeout
      const results = await Promise.race([
        Promise.all(analysisPromises),
        this.timeout(this.options.fileTimeout!)
      ]) as Finding[][];

      // Flatten results
      for (const result of results) {
        findings.push(...result);
      }

      // Deduplicate findings
      const deduped = this.deduplicateFindings(findings);

      // Filter by confidence
      const filtered = this.filterByConfidence(deduped);

      const elapsed = Date.now() - startTime;
      logger.debug(`Analyzed ${file.relativePath} in ${elapsed}ms, found ${filtered.length} issues`);

      return filtered;

    } catch (error) {
      logger.error(`Error analyzing ${file.relativePath}:`, error);
      return findings;
    }
  }

  /**
   * Run pattern-based vulnerability detection
   */
  private async runPatternAnalysis(file: ScannedFile): Promise<Finding[]> {
    const findings: Finding[] = [];
    const lines = file.content.split('\n');

    for (const vuln of VULNERABILITY_PATTERNS) {
      // Reset regex state
      vuln.pattern.lastIndex = 0;

      let match;
      while ((match = vuln.pattern.exec(file.content)) !== null) {
        // Find line number
        const beforeMatch = file.content.substring(0, match.index);
        const lineNum = beforeMatch.split('\n').length;
        const currentLine = lines[lineNum - 1] || '';

        // FP reduction: skip matches inside comments
        if (this.isInsideComment(currentLine, file.content, match.index)) {
          continue;
        }

        // FP reduction: smarter hardcoded credential detection
        if (vuln.threatType === ThreatType.HARDCODED_CREDENTIALS) {
          if (this.isCredentialFalsePositive(currentLine, match[0])) {
            continue;
          }
        }

        // FP reduction: context-aware innerHTML/XSS detection
        if (vuln.id === 'JS-XSS-001' && this.isXSSFalsePositive(currentLine)) {
          continue;
        }

        const context = extractCodeContext(file.content, lineNum, 2);

        findings.push({
          id: generateId(),
          title: vuln.name,
          description: vuln.description,
          severity: vuln.severity,
          threatType: vuln.threatType,
          category: vuln.category,
          location: {
            file: file.relativePath,
            startLine: lineNum,
            endLine: lineNum
          },
          snippet: {
            code: context.code,
            contextBefore: context.contextBefore,
            contextAfter: context.contextAfter
          },
          standards: getStandardsForThreat(vuln.threatType),
          remediation: vuln.remediation,
          confidence: vuln.confidence,
          analyzer: this.name,
          timestamp: new Date(),
          tags: vuln.tags
        });
      }
    }

    return findings;
  }

  /**
   * Run AST-based analysis
   */
  private async runASTAnalysis(file: ScannedFile): Promise<Finding[]> {
    const findings: Finding[] = [];

    try {
      // Parse the file
      const ast = this.astUtils.safeParse(file.content, file.relativePath);
      if (!ast) {
        logger.debug(`Could not parse ${file.relativePath} for AST analysis`);
        return findings;
      }

      // Find dangerous calls
      const dangerousCalls = this.astUtils.findDangerousCalls(file.relativePath);
      for (const call of dangerousCalls) {
        findings.push(this.dangerousCallToFinding(call, file));
      }

      // Find hardcoded secrets
      const secrets = this.astUtils.findHardcodedSecrets();
      for (const secret of secrets) {
        findings.push(this.dangerousCallToFinding(secret, file));
      }

      // Find dangerous regex patterns
      const regexIssues = this.astUtils.findDangerousRegex();
      for (const regex of regexIssues) {
        findings.push(this.dangerousCallToFinding(regex, file));
      }

    } catch (error) {
      logger.debug(`AST analysis failed for ${file.relativePath}:`, error);
    }

    return findings;
  }

  /**
   * Run taint analysis
   */
  private async runTaintAnalysis(file: ScannedFile): Promise<Finding[]> {
    const findings: Finding[] = [];

    try {
      const flows = this.taintAnalyzer.analyze(file.content, file.relativePath);

      for (const flow of flows) {
        findings.push(this.taintFlowToFinding(flow, file));
      }
    } catch (error) {
      logger.debug(`Taint analysis failed for ${file.relativePath}:`, error);
    }

    return findings;
  }

  /**
   * Run malware detection
   */
  private async runMalwareAnalysis(file: ScannedFile): Promise<Finding[]> {
    const findings: Finding[] = [];

    try {
      const matches = this.malwareDetector.scan(file.content, file.relativePath);

      for (const match of matches) {
        findings.push(this.malwareMatchToFinding(match, file));
      }
    } catch (error) {
      logger.debug(`Malware analysis failed for ${file.relativePath}:`, error);
    }

    return findings;
  }

  /**
   * Analyze package.json for security issues
   */
  private async analyzePackageJson(file: ScannedFile): Promise<Finding[]> {
    const findings: Finding[] = [];

    if (!this.options.enablePackageAnalysis) {
      return findings;
    }

    try {
      const pkgFindings = this.packageJsonAnalyzer.analyze(file.content, file.relativePath);

      for (const finding of pkgFindings) {
        findings.push(this.packageFindingToFinding(finding, file));
      }
    } catch (error) {
      logger.debug(`Package.json analysis failed for ${file.relativePath}:`, error);
    }

    return findings;
  }

  /**
   * Check for obfuscated code
   */
  private async checkObfuscation(file: ScannedFile): Promise<Finding[]> {
    const findings: Finding[] = [];

    if (looksObfuscated(file.content)) {
      const entropy = calculateEntropy(file.content);

      findings.push({
        id: generateId(),
        title: 'Heavily Obfuscated Code',
        description: `This file contains heavily obfuscated code (entropy: ${entropy.toFixed(2)}). This is unusual for legitimate code and may hide malicious functionality.`,
        severity: Severity.HIGH,
        threatType: ThreatType.OBFUSCATED_CODE,
        category: FindingCategory.MALWARE,
        location: {
          file: file.relativePath,
          startLine: 1,
          endLine: Math.min(10, file.lineCount)
        },
        snippet: {
          code: file.content.substring(0, 200) + '...'
        },
        standards: getStandardsForThreat(ThreatType.OBFUSCATED_CODE),
        remediation: 'Deobfuscate and review the code. If this is a third-party library, verify its source and integrity.',
        confidence: 75,
        analyzer: this.name,
        timestamp: new Date(),
        tags: ['obfuscation', 'suspicious']
      });
    }

    return findings;
  }

  /**
   * Convert DangerousCall to Finding
   */
  private dangerousCallToFinding(call: DangerousCall, file: ScannedFile): Finding {
    const threatTypeMap: Record<DangerousPatternType, ThreatType> = {
      [DangerousPatternType.CODE_EXECUTION]: ThreatType.COMMAND_INJECTION,
      [DangerousPatternType.COMMAND_INJECTION]: ThreatType.COMMAND_INJECTION,
      [DangerousPatternType.PROTOTYPE_POLLUTION]: ThreatType.DANGEROUS_FUNCTION,
      [DangerousPatternType.XSS_SINK]: ThreatType.XSS,
      [DangerousPatternType.DYNAMIC_REQUIRE]: ThreatType.DANGEROUS_FUNCTION,
      [DangerousPatternType.INSECURE_RANDOM]: ThreatType.WEAK_RANDOM,
      [DangerousPatternType.HARDCODED_SECRET]: ThreatType.HARDCODED_CREDENTIALS,
      [DangerousPatternType.DANGEROUS_REGEX]: ThreatType.DANGEROUS_FUNCTION,
      [DangerousPatternType.UNSAFE_ASSIGNMENT]: ThreatType.DANGEROUS_FUNCTION,
      [DangerousPatternType.NETWORK_REQUEST]: ThreatType.SUSPICIOUS_NETWORK,
      [DangerousPatternType.FILE_OPERATION]: ThreatType.PATH_TRAVERSAL,
      [DangerousPatternType.CRYPTO_WEAKNESS]: ThreatType.INSECURE_CRYPTO
    };

    const severityMap: Record<DangerousPatternType, Severity> = {
      [DangerousPatternType.CODE_EXECUTION]: Severity.CRITICAL,
      [DangerousPatternType.COMMAND_INJECTION]: Severity.CRITICAL,
      [DangerousPatternType.PROTOTYPE_POLLUTION]: Severity.HIGH,
      [DangerousPatternType.XSS_SINK]: Severity.HIGH,
      [DangerousPatternType.DYNAMIC_REQUIRE]: Severity.MEDIUM,
      [DangerousPatternType.INSECURE_RANDOM]: Severity.MEDIUM,
      [DangerousPatternType.HARDCODED_SECRET]: Severity.HIGH,
      [DangerousPatternType.DANGEROUS_REGEX]: Severity.MEDIUM,
      [DangerousPatternType.UNSAFE_ASSIGNMENT]: Severity.MEDIUM,
      [DangerousPatternType.NETWORK_REQUEST]: Severity.MEDIUM,
      [DangerousPatternType.FILE_OPERATION]: Severity.MEDIUM,
      [DangerousPatternType.CRYPTO_WEAKNESS]: Severity.MEDIUM
    };

    const context = extractCodeContext(file.content, call.location.startLine, 2);

    return {
      id: generateId(),
      title: `AST: ${call.name}`,
      description: call.context || `Dangerous ${call.patternType.replace(/_/g, ' ')} detected via AST analysis`,
      severity: severityMap[call.patternType] || Severity.MEDIUM,
      threatType: threatTypeMap[call.patternType] || ThreatType.DANGEROUS_FUNCTION,
      category: FindingCategory.VULNERABILITY,
      location: {
        file: file.relativePath,
        startLine: call.location.startLine,
        endLine: call.location.endLine,
        startColumn: call.location.startColumn,
        endColumn: call.location.endColumn
      },
      snippet: {
        code: call.code,
        contextBefore: context.contextBefore,
        contextAfter: context.contextAfter
      },
      standards: getStandardsForThreat(threatTypeMap[call.patternType] || ThreatType.DANGEROUS_FUNCTION),
      remediation: 'Review and fix the identified security issue.',
      confidence: 85,
      analyzer: `${this.name} (AST)`,
      timestamp: new Date(),
      tags: ['ast', call.patternType]
    };
  }

  /**
   * Convert TaintFlow to Finding
   */
  private taintFlowToFinding(flow: TaintFlow, file: ScannedFile): Finding {
    const sourceDesc = TaintAnalyzer.getSourceDescription(flow.source.type);
    const sinkInfo = TaintAnalyzer.getSinkInfo(flow.sink.type);

    const context = extractCodeContext(file.content, flow.sink.line, 2);

    // Build detailed description with flow path
    let description = `Tainted data from ${sourceDesc} flows to ${flow.sink.type} sink.`;
    if (flow.propagation.length > 0) {
      description += ` The data passes through ${flow.propagation.length} intermediate assignments.`;
    }

    return {
      id: generateId(),
      title: `Taint Flow: ${flow.source.type} → ${flow.sink.type}`,
      description,
      severity: flow.sink.severity,
      threatType: flow.sink.threatType,
      category: FindingCategory.VULNERABILITY,
      location: {
        file: file.relativePath,
        startLine: flow.sink.line,
        endLine: flow.sink.line
      },
      snippet: {
        code: flow.sink.code,
        contextBefore: context.contextBefore,
        contextAfter: context.contextAfter
      },
      standards: getStandardsForThreat(flow.sink.threatType),
      remediation: sinkInfo?.remediation || 'Validate and sanitize all user input before use.',
      confidence: flow.confidence,
      analyzer: `${this.name} (Taint)`,
      timestamp: new Date(),
      tags: ['taint-analysis', flow.source.type, flow.sink.type]
    };
  }

  /**
   * Convert MalwareMatch to Finding
   */
  private malwareMatchToFinding(match: MalwareMatch, file: ScannedFile): Finding {
    const context = extractCodeContext(file.content, match.line, 2);

    return {
      id: generateId(),
      title: `Malware: ${match.name}`,
      description: match.description,
      severity: match.severity,
      threatType: MalwareDetector.getThreatType(match.type),
      category: FindingCategory.MALWARE,
      location: {
        file: file.relativePath,
        startLine: match.line,
        endLine: match.line
      },
      snippet: {
        code: match.code,
        contextBefore: context.contextBefore,
        contextAfter: context.contextAfter
      },
      standards: getStandardsForThreat(MalwareDetector.getThreatType(match.type)),
      remediation: match.remediation,
      confidence: match.confidence,
      analyzer: `${this.name} (Malware)`,
      timestamp: new Date(),
      tags: ['malware', match.type, ...(match.mitreAttack || [])]
    };
  }

  /**
   * Convert PackageJsonFinding to Finding
   */
  private packageFindingToFinding(pkgFinding: PackageJsonFinding, file: ScannedFile): Finding {
    return {
      id: generateId(),
      title: pkgFinding.name,
      description: pkgFinding.description,
      severity: pkgFinding.severity,
      threatType: pkgFinding.threatType,
      category: pkgFinding.category,
      location: {
        file: file.relativePath,
        startLine: 1,
        endLine: 1
      },
      snippet: {
        code: `"${pkgFinding.field}": "${pkgFinding.value.substring(0, 100)}"`
      },
      standards: getStandardsForThreat(pkgFinding.threatType),
      remediation: pkgFinding.remediation,
      confidence: pkgFinding.confidence,
      analyzer: `${this.name} (Package)`,
      timestamp: new Date(),
      tags: ['package-json', pkgFinding.type]
    };
  }

  /**
   * Deduplicate findings based on location and type
   */
  private deduplicateFindings(findings: Finding[]): Finding[] {
    const seen = new Map<string, Finding>();

    for (const finding of findings) {
      const key = `${finding.location.file}:${finding.location.startLine}:${finding.threatType}`;

      if (!seen.has(key)) {
        seen.set(key, finding);
      } else {
        // Keep the one with higher confidence
        const existing = seen.get(key)!;
        if (finding.confidence > existing.confidence) {
          seen.set(key, finding);
        }
      }
    }
    return Array.from(seen.values());
  }

  /**
   * Filter findings by minimum confidence
   */
  private filterByConfidence(findings: Finding[]): Finding[] {
    return findings.filter(f => f.confidence >= this.options.minConfidence!);
  }

  // =========================================================================
  // FALSE POSITIVE REDUCTION HELPERS
  // =========================================================================

  /**
   * Check if a match position is inside a comment (// or block comment)
   */
  private isInsideComment(line: string, fullContent: string, matchIndex: number): boolean {
    const trimmed = line.trimStart();
    // Single-line comment
    if (trimmed.startsWith('//')) return true;
    // Line is inside a block comment: check if there's an unclosed /* before match
    const before = fullContent.substring(0, matchIndex);
    const lastOpen = before.lastIndexOf('/*');
    const lastClose = before.lastIndexOf('*/');
    if (lastOpen > lastClose) return true;
    // JSDoc or block comment line
    if (trimmed.startsWith('*') || trimmed.startsWith('/**')) return true;
    return false;
  }

  /**
   * Check if a hardcoded credential match is a false positive
   */
  private isCredentialFalsePositive(line: string, matchedText: string): boolean {
    // Skip type definitions, schemas, validators
    if (SCHEMA_LINE_PATTERNS.test(line)) return true;

    // Extract the quoted value from the match
    const valueMatch = matchedText.match(/[=:]\s*['"`]([^'"`]*)['"`]/);
    if (valueMatch) {
      const value = valueMatch[1];
      // Skip placeholder/example values
      if (CREDENTIAL_PLACEHOLDER_PATTERNS.test(value)) return true;
      // Skip very short values (likely not real credentials)
      if (value.length < 4) return true;
      // Skip values that are template expressions like ${...}
      if (value.includes('${') || value.includes('process.env')) return true;
    }

    return false;
  }

  /**
   * Check if an innerHTML match is a false positive
   */
  private isXSSFalsePositive(line: string): boolean {
    // Skip if the value is a pure string literal (static HTML)
    if (/\.innerHTML\s*=\s*['"`]<[^'"`]*>['"`]\s*;?$/.test(line.trim())) return true;
    // Skip if DOMPurify or sanitize is called on the same line
    if (/DOMPurify\.sanitize|sanitize\s*\(|escape\s*\(|textContent/.test(line)) return true;
    return false;
  }

  /**
   * Check if a file is minified or from a vendor directory
   */
  private isMinifiedOrVendor(file: ScannedFile): boolean {
    // Check path for vendor patterns
    if (VENDOR_PATH_PATTERNS.test(file.relativePath)) return true;
    // Check if file is likely minified (avg line length > 300)
    if (file.lineCount > 0) {
      const avgLineLength = file.content.length / file.lineCount;
      if (avgLineLength > 300) return true;
    }
    return false;
  }

  /**
   * Create a timeout promise
   */
  private timeout(ms: number): Promise<Finding[][]> {
    return new Promise((_, reject) => {
      setTimeout(() => reject(new Error('Analysis timeout')), ms);
    });
  }
}

export default JavaScriptAnalyzer;
