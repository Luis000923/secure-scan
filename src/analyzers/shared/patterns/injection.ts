/**
 * Injection Detection Patterns
 * SQL Injection, Command Injection, XSS, and other injection vulnerabilities
 * Shared across all language analyzers
 */

import { Severity, SecurityStandard } from '../../../types';

/**
 * SQL Injection patterns by language
 */
export const SQL_INJECTION_PATTERNS: Record<string, Array<{
  pattern: RegExp;
  name: string;
  severity: Severity;
  description: string;
  recommendation: string;
}>> = {
  python: [
    {
      pattern: /cursor\.execute\s*\(\s*(?:f["']|["'].*%|["'].*\.format\s*\(|["'].*\+)/gi,
      name: 'Inyección SQL (cursor.execute)',
      severity: Severity.CRITICAL,
      description: 'La interpolación de cadenas en una consulta SQL permite la inyección SQL.',
      recommendation: 'Use consultas parametrizadas: cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))',
    },
    {
      pattern: /\.execute\s*\(\s*["'].*\+.*["']\s*\+/gi,
      name: 'Inyección SQL (concatenación de cadenas)',
      severity: Severity.CRITICAL,
      description: 'La concatenación de cadenas en una consulta SQL permite la inyección SQL.',
      recommendation: 'Use consultas parametrizadas con marcadores de posición.',
    },
    {
      pattern: /\.raw\s*\(\s*(?:f["']|["'].*%|["'].*\.format\s*\()/gi,
      name: 'Inyección SQL (Django raw)',
      severity: Severity.CRITICAL,
      description: 'SQL crudo con formateo de cadenas en Django ORM.',
      recommendation: 'Use métodos del ORM de Django o el método RawSQL con el parámetro params.',
    },
    {
      pattern: /\.extra\s*\(\s*(?:where|select|tables)\s*=\s*\[.*%/gi,
      name: 'Inyección SQL (Django extra)',
      severity: Severity.HIGH,
      description: 'El uso de extra() en Django con formateo de cadenas es vulnerable.',
      recommendation: 'Evite extra() o use el parámetro params para una interpolación segura.',
    },
    {
      pattern: /text\s*\(\s*(?:f["']|["'].*%)/gi,
      name: 'Inyección SQL (SQLAlchemy text)',
      severity: Severity.CRITICAL,
      description: 'Uso de text() en SQLAlchemy con formateo de cadenas.',
      recommendation: 'Use text().bindparams() para consultas parametrizadas.',
    },
  ],

  java: [
    {
      pattern: /(?:executeQuery|executeUpdate|execute)\s*\(\s*["'].*\+/gi,
      name: 'Inyección SQL (Statement)',
      severity: Severity.CRITICAL,
      description: 'Concatenación de cadenas en consulta SQL usando Statement.',
      recommendation: 'Use PreparedStatement con consultas parametrizadas.',
    },
    {
      pattern: /createQuery\s*\(\s*["'].*\+/gi,
      name: 'Inyección SQL (JPA/Hibernate)',
      severity: Severity.CRITICAL,
      description: 'Concatenación de cadenas en consulta JPA/Hibernate.',
      recommendation: 'Use parámetros nombrados o parámetros posicionales.',
    },
    {
      pattern: /createNativeQuery\s*\(\s*["'].*\+/gi,
      name: 'Inyección SQL (Consulta Nativa)',
      severity: Severity.CRITICAL,
      description: 'Concatenación de cadenas en consulta SQL nativa.',
      recommendation: 'Use setParameter() con consultas nativas parametrizadas.',
    },
    {
      pattern: /String\.format\s*\(\s*["'](?:SELECT|INSERT|UPDATE|DELETE)/gi,
      name: 'Inyección SQL (String.format)',
      severity: Severity.CRITICAL,
      description: 'String.format() utilizado para construir consultas SQL.',
      recommendation: 'Use PreparedStatement con setParameter().',
    },
  ],

  csharp: [
    {
      pattern: /new\s+SqlCommand\s*\(\s*(?:\$"|".*\+|string\.Format)/gi,
      name: 'Inyección SQL (SqlCommand)',
      severity: Severity.CRITICAL,
      description: 'Interpolación de cadenas en SqlCommand.',
      recommendation: 'Use consultas parametrizadas con SqlParameter.',
    },
    {
      pattern: /\.ExecuteSqlRaw\s*\(\s*(?:\$"|".*\+)/gi,
      name: 'Inyección SQL (EF Core Raw)',
      severity: Severity.CRITICAL,
      description: 'Interpolación de cadenas en ExecuteSqlRaw.',
      recommendation: 'Use ExecuteSqlInterpolated o FromSqlRaw parametrizado.',
    },
    {
      pattern: /\.FromSqlRaw\s*\(\s*(?:\$"|".*\+)/gi,
      name: 'Inyección SQL (EF FromSqlRaw)',
      severity: Severity.CRITICAL,
      description: 'Interpolación de cadenas en FromSqlRaw.',
      recommendation: 'Use FromSqlInterpolated o pase un array de parámetros.',
    },
    {
      pattern: /ExecuteReader\s*\(\s*["'].*\+/gi,
      name: 'Inyección SQL (ExecuteReader)',
      severity: Severity.CRITICAL,
      description: 'Concatenación de cadenas antes de ExecuteReader.',
      recommendation: 'Use consultas parametrizadas con DbParameter.',
    },
  ],

  php: [
    {
      pattern: /mysqli?_query\s*\(\s*\$\w+\s*,\s*["'].*\.\s*\$/gi,
      name: 'Inyección SQL (mysqli_query)',
      severity: Severity.CRITICAL,
      description: 'Concatenación de variables en mysqli_query.',
      recommendation: 'Use sentencias preparadas con mysqli_prepare().',
    },
    {
      pattern: /->query\s*\(\s*["'].*\.\s*\$/gi,
      name: 'Inyección SQL (PDO query)',
      severity: Severity.CRITICAL,
      description: 'Concatenación de variables en consulta PDO.',
      recommendation: 'Use PDO::prepare() con parámetros vinculados.',
    },
    {
      pattern: /->exec\s*\(\s*["'].*\.\s*\$/gi,
      name: 'Inyección SQL (PDO exec)',
      severity: Severity.CRITICAL,
      description: 'Concatenación de variables en PDO exec.',
      recommendation: 'Use PDO::prepare() con parámetros vinculados.',
    },
    {
      pattern: /\$\w+\s*=\s*["'](?:SELECT|INSERT|UPDATE|DELETE).*["']\s*\.\s*\$/gi,
      name: 'Inyección SQL (construcción de consulta)',
      severity: Severity.CRITICAL,
      description: 'Construcción de consulta SQL con concatenación de cadenas.',
      recommendation: 'Use sentencias preparadas con marcadores de posición.',
    },
  ],

  javascript: [
    {
      pattern: /\.query\s*\(\s*`[^`]*\$\{/gi,
      name: 'Inyección SQL (plantilla literal)',
      severity: Severity.CRITICAL,
      description: 'Uso de plantilla literal en consulta de base de datos.',
      recommendation: 'Use consultas parametrizadas con marcadores de posición.',
    },
    {
      pattern: /\.query\s*\(\s*["'].*\+/gi,
      name: 'Inyección SQL (concatenación)',
      severity: Severity.CRITICAL,
      description: 'Concatenación de cadenas en consulta de base de datos.',
      recommendation: 'Use consultas parametrizadas: query("SELECT * FROM users WHERE id = ?", [userId])',
    },
    {
      pattern: /\.raw\s*\(\s*`[^`]*\$\{/gi,
      name: 'Inyección SQL (consulta raw)',
      severity: Severity.CRITICAL,
      description: 'Plantilla literal en consulta SQL raw.',
      recommendation: 'Use la parametrización integrada del ORM.',
    },
  ],
};

/**
 * Command Injection patterns by language
 */
export const COMMAND_INJECTION_PATTERNS: Record<string, Array<{
  pattern: RegExp;
  name: string;
  severity: Severity;
  description: string;
  recommendation: string;
}>> = {
  python: [
    {
      pattern: /os\.system\s*\(\s*(?:f["']|["'].*%|["'].*\.format|.*\+)/gi,
      name: 'Inyección de Comandos (os.system)',
      severity: Severity.CRITICAL,
      description: 'os.system con entrada controlada por el usuario.',
      recommendation: 'Use subprocess con shell=False y una lista de argumentos.',
    },
    {
      pattern: /subprocess\.(?:call|run|Popen)\s*\([^)]*shell\s*=\s*True/gi,
      name: 'Inyección de Comandos (subprocess shell)',
      severity: Severity.HIGH,
      description: 'subprocess con shell=True permite la inyección de comandos.',
      recommendation: 'Use shell=False y pase los argumentos como una lista.',
    },
    {
      pattern: /os\.popen\s*\(/gi,
      name: 'Inyección de Comandos (os.popen)',
      severity: Severity.HIGH,
      description: 'os.popen es vulnerable a la inyección de comandos.',
      recommendation: 'Use subprocess.run con shell=False.',
    },
    {
      pattern: /eval\s*\(/gi,
      name: 'Inyección de Código (eval)',
      severity: Severity.CRITICAL,
      description: 'eval() ejecuta código Python arbitrario.',
      recommendation: 'Evite eval(). Use ast.literal_eval() para datos.',
    },
    {
      pattern: /exec\s*\(/gi,
      name: 'Inyección de Código (exec)',
      severity: Severity.CRITICAL,
      description: 'exec() ejecuta código Python arbitrario.',
      recommendation: 'Evite exec(). Refactorice para usar alternativas seguras.',
    },
  ],

  java: [
    {
      pattern: /Runtime\.getRuntime\(\)\.exec\s*\(\s*["'].*\+/gi,
      name: 'Command Injection (Runtime.exec)',
      severity: Severity.CRITICAL,
      description: 'String concatenation in Runtime.exec().',
      recommendation: 'Use ProcessBuilder with separate arguments.',
    },
    {
      pattern: /new\s+ProcessBuilder\s*\(\s*["'].*\+/gi,
      name: 'Command Injection (ProcessBuilder)',
      severity: Severity.CRITICAL,
      description: 'String concatenation in ProcessBuilder.',
      recommendation: 'Pass arguments as separate array elements.',
    },
  ],

  csharp: [
    {
      pattern: /Process\.Start\s*\(\s*(?:\$"|".*\+)/gi,
      name: 'Command Injection (Process.Start)',
      severity: Severity.CRITICAL,
      description: 'String interpolation in Process.Start.',
      recommendation: 'Use ProcessStartInfo with separate arguments.',
    },
  ],

  php: [
    {
      pattern: /\b(system|exec|shell_exec|passthru|popen|proc_open)\s*\(\s*\$/gi,
      name: 'Command Injection',
      severity: Severity.CRITICAL,
      description: 'User input in command execution function.',
      recommendation: 'Use escapeshellarg() and escapeshellcmd(), or avoid shell commands.',
    },
    {
      pattern: /`[^`]*\$/gi,
      name: 'Command Injection (backticks)',
      severity: Severity.CRITICAL,
      description: 'Variable in backtick execution.',
      recommendation: 'Avoid backtick operator with user input.',
    },
  ],

  javascript: [
    {
      pattern: /child_process\.(?:exec|execSync)\s*\(\s*`[^`]*\$\{/gi,
      name: 'Command Injection (child_process)',
      severity: Severity.CRITICAL,
      description: 'Template literal in child_process.exec.',
      recommendation: 'Use execFile or spawn with argument array.',
    },
    {
      pattern: /child_process\.(?:exec|execSync)\s*\(\s*["'].*\+/gi,
      name: 'Command Injection (concatenation)',
      severity: Severity.CRITICAL,
      description: 'String concatenation in command execution.',
      recommendation: 'Use child_process.execFile or spawn with argument array.',
    },
    {
      pattern: /\beval\s*\(/gi,
      name: 'Code Injection (eval)',
      severity: Severity.CRITICAL,
      description: 'eval() executes arbitrary JavaScript code.',
      recommendation: 'Avoid eval(). Use JSON.parse() for JSON data.',
    },
    {
      pattern: /new\s+Function\s*\(/gi,
      name: 'Code Injection (Function constructor)',
      severity: Severity.HIGH,
      description: 'Function constructor is similar to eval().',
      recommendation: 'Avoid dynamic function creation with user input.',
    },
  ],
};

/**
 * XSS (Cross-Site Scripting) patterns by language
 */
export const XSS_PATTERNS: Record<string, Array<{
  pattern: RegExp;
  name: string;
  severity: Severity;
  description: string;
  recommendation: string;
}>> = {
  python: [
    {
      pattern: /\|\s*safe\b/gi,
      name: 'XSS (Jinja2 safe filter)',
      severity: Severity.HIGH,
      description: 'Marking content as safe bypasses HTML escaping.',
      recommendation: 'Avoid |safe filter with user-controlled content.',
    },
    {
      pattern: /\{%\s*autoescape\s+(?:false|off)\s*%\}/gi,
      name: 'XSS (autoescape disabled)',
      severity: Severity.HIGH,
      description: 'Disabling autoescape allows XSS.',
      recommendation: 'Keep autoescape enabled for user content.',
    },
    {
      pattern: /Markup\s*\(/gi,
      name: 'XSS (Flask Markup)',
      severity: Severity.MEDIUM,
      description: 'Markup() marks content as safe HTML.',
      recommendation: 'Only use Markup() with sanitized content.',
    },
    {
      pattern: /mark_safe\s*\(/gi,
      name: 'XSS (Django mark_safe)',
      severity: Severity.MEDIUM,
      description: 'mark_safe() bypasses Django HTML escaping.',
      recommendation: 'Only use mark_safe() with sanitized content.',
    },
  ],

  java: [
    {
      pattern: /\.getParameter\s*\([^)]+\)(?!.*(?:encode|escape|sanitize))/gi,
      name: 'Potential XSS (unescaped parameter)',
      severity: Severity.MEDIUM,
      description: 'Request parameter may be output without encoding.',
      recommendation: 'Use OWASP Encoder or similar for output encoding.',
    },
    {
      pattern: /response\.getWriter\(\)\.(?:write|print|println)\s*\(\s*(?:request\.getParameter|.*\+)/gi,
      name: 'XSS (direct output)',
      severity: Severity.HIGH,
      description: 'Writing user input directly to response.',
      recommendation: 'HTML encode output using OWASP Java Encoder.',
    },
  ],

  csharp: [
    {
      pattern: /@Html\.Raw\s*\(/gi,
      name: 'XSS (Html.Raw)',
      severity: Severity.HIGH,
      description: 'Html.Raw outputs unencoded content.',
      recommendation: 'Avoid Html.Raw with user content, or sanitize first.',
    },
    {
      pattern: /HtmlString\s*\(/gi,
      name: 'XSS (HtmlString)',
      severity: Severity.MEDIUM,
      description: 'HtmlString bypasses automatic encoding.',
      recommendation: 'Sanitize content before creating HtmlString.',
    },
  ],

  php: [
    {
      pattern: /echo\s+\$(?:_GET|_POST|_REQUEST|_COOKIE)/gi,
      name: 'XSS (direct echo)',
      severity: Severity.CRITICAL,
      description: 'Echoing superglobal directly without encoding.',
      recommendation: 'Use htmlspecialchars() or htmlentities().',
    },
    {
      pattern: /print\s+\$(?:_GET|_POST|_REQUEST|_COOKIE)/gi,
      name: 'XSS (direct print)',
      severity: Severity.CRITICAL,
      description: 'Printing superglobal directly without encoding.',
      recommendation: 'Use htmlspecialchars() or htmlentities().',
    },
  ],

  javascript: [
    {
      pattern: /\.innerHTML\s*=/gi,
      name: 'XSS (innerHTML)',
      severity: Severity.MEDIUM,
      description: 'innerHTML can execute scripts in HTML.',
      recommendation: 'Use textContent or sanitize with DOMPurify.',
    },
    {
      pattern: /\.outerHTML\s*=/gi,
      name: 'XSS (outerHTML)',
      severity: Severity.MEDIUM,
      description: 'outerHTML can execute scripts in HTML.',
      recommendation: 'Use textContent or sanitize with DOMPurify.',
    },
    {
      pattern: /document\.write\s*\(/gi,
      name: 'XSS (document.write)',
      severity: Severity.HIGH,
      description: 'document.write can insert malicious HTML.',
      recommendation: 'Use DOM manipulation methods instead.',
    },
    {
      pattern: /\$\([^)]+\)\.html\s*\(/gi,
      name: 'XSS (jQuery .html())',
      severity: Severity.MEDIUM,
      description: 'jQuery .html() can execute scripts.',
      recommendation: 'Use .text() or sanitize content first.',
    },
  ],
};

/**
 * SSTI (Server-Side Template Injection) patterns
 */
export const SSTI_PATTERNS: Record<string, Array<{
  pattern: RegExp;
  name: string;
  severity: Severity;
  description: string;
  recommendation: string;
}>> = {
  python: [
    {
      pattern: /render_template_string\s*\(/gi,
      name: 'SSTI (render_template_string)',
      severity: Severity.CRITICAL,
      description: 'render_template_string with user input enables SSTI.',
      recommendation: 'Use render_template() with separate template files.',
    },
    {
      pattern: /Template\s*\(\s*(?:request\.|.*\+|f["'])/gi,
      name: 'SSTI (Jinja2 Template)',
      severity: Severity.CRITICAL,
      description: 'Creating Jinja2 Template from user input.',
      recommendation: 'Use predefined template files.',
    },
    {
      pattern: /Environment\s*\([^)]*loader\s*=\s*None/gi,
      name: 'SSTI (Jinja2 no loader)',
      severity: Severity.HIGH,
      description: 'Jinja2 without FileSystemLoader may use string templates.',
      recommendation: 'Always use a secure template loader.',
    },
  ],

  java: [
    {
      pattern: /Velocity\.evaluate\s*\(/gi,
      name: 'SSTI (Velocity)',
      severity: Severity.CRITICAL,
      description: 'Velocity.evaluate with user input enables SSTI.',
      recommendation: 'Use template files, not string evaluation.',
    },
    {
      pattern: /Freemarker.*new\s+Template\s*\(\s*["'][^"']+["']\s*,\s*new\s+StringReader/gi,
      name: 'SSTI (Freemarker)',
      severity: Severity.CRITICAL,
      description: 'Freemarker template from string input.',
      recommendation: 'Load templates from the filesystem.',
    },
  ],
};

/**
 * Path Traversal patterns
 */
export const PATH_TRAVERSAL_PATTERNS: Record<string, Array<{
  pattern: RegExp;
  name: string;
  severity: Severity;
  description: string;
  recommendation: string;
}>> = {
  python: [
    {
      pattern: /open\s*\(\s*(?:request\.|.*\+|f["'])/gi,
      name: 'Salto de Directorio (open)',
      severity: Severity.HIGH,
      description: 'Apertura de archivo con ruta controlada por el usuario.',
      recommendation: 'Valide y normalice las rutas, use os.path.basename().',
    },
    {
      pattern: /send_file\s*\(\s*(?:request\.|.*\+|f["'])/gi,
      name: 'Salto de Directorio (send_file)',
      severity: Severity.HIGH,
      description: 'send_file de Flask con ruta controlada por el usuario.',
      recommendation: 'Use send_from_directory con un nombre de archivo validado.',
    },
  ],

  java: [
    {
      pattern: /new\s+File\s*\(\s*(?:request\.getParameter|.*\+)/gi,
      name: 'Path Traversal (File)',
      severity: Severity.HIGH,
      description: 'File path from user input.',
      recommendation: 'Validate path, use canonical path comparison.',
    },
    {
      pattern: /Paths\.get\s*\(\s*(?:request\.getParameter|.*\+)/gi,
      name: 'Path Traversal (Paths.get)',
      severity: Severity.HIGH,
      description: 'Path from user input.',
      recommendation: 'Validate and normalize paths.',
    },
  ],

  php: [
    {
      pattern: /(?:include|require|include_once|require_once)\s*\(\s*\$/gi,
      name: 'Path Traversal / LFI',
      severity: Severity.CRITICAL,
      description: 'Include with user-controlled path (Local File Inclusion).',
      recommendation: 'Use whitelist of allowed files.',
    },
    {
      pattern: /file_get_contents\s*\(\s*\$/gi,
      name: 'Path Traversal (file_get_contents)',
      severity: Severity.HIGH,
      description: 'file_get_contents with user-controlled path.',
      recommendation: 'Validate and sanitize the file path.',
    },
  ],

  javascript: [
    {
      pattern: /\bfs\.(?:readFile|readFileSync|writeFile|writeFileSync)\s*\(\s*(?:req\.|`[^`]*\$\{|.*\+)/gi,
      name: 'Salto de Directorio (fs)',
      severity: Severity.HIGH,
      description: 'Operación de archivo con ruta controlada por el usuario.',
      recommendation: 'Use path.resolve() y valide contra un directorio base.',
    },
    {
      pattern: /res\.sendFile\s*\(\s*(?:req\.|`[^`]*\$\{|.*\+)/gi,
      name: 'Salto de Directorio (sendFile)',
      severity: Severity.HIGH,
      description: 'sendFile con ruta controlada por el usuario.',
      recommendation: 'Use express.static() o valide las rutas.',
    },
  ],
};

/**
 * Get injection patterns for a specific language
 */
export function getInjectionPatterns(language: string): Array<{
  pattern: RegExp;
  name: string;
  severity: Severity;
  description: string;
  recommendation: string;
  category: string;
}> {
  const patterns: Array<{
    pattern: RegExp;
    name: string;
    severity: Severity;
    description: string;
    recommendation: string;
    category: string;
  }> = [];

  // Add SQL injection patterns
  if (SQL_INJECTION_PATTERNS[language]) {
    patterns.push(...SQL_INJECTION_PATTERNS[language].map(p => ({ ...p, category: 'SQL Injection' })));
  }

  // Add command injection patterns
  if (COMMAND_INJECTION_PATTERNS[language]) {
    patterns.push(...COMMAND_INJECTION_PATTERNS[language].map(p => ({ ...p, category: 'Command Injection' })));
  }

  // Add XSS patterns
  if (XSS_PATTERNS[language]) {
    patterns.push(...XSS_PATTERNS[language].map(p => ({ ...p, category: 'XSS' })));
  }

  // Add SSTI patterns
  if (SSTI_PATTERNS[language]) {
    patterns.push(...SSTI_PATTERNS[language].map(p => ({ ...p, category: 'SSTI' })));
  }

  // Add path traversal patterns
  if (PATH_TRAVERSAL_PATTERNS[language]) {
    patterns.push(...PATH_TRAVERSAL_PATTERNS[language].map(p => ({ ...p, category: 'Path Traversal' })));
  }

  return patterns;
}

/**
 * NoSQL Injection patterns by language
 * Covers MongoDB, CouchDB, DynamoDB, Redis, Cassandra
 */
export const NOSQL_INJECTION_PATTERNS: Record<string, Array<{
  pattern: RegExp;
  name: string;
  severity: Severity;
  description: string;
  recommendation: string;
  cwe: string;
}>> = {
  python: [
    {
      pattern: /\.find\s*\(\s*\{[^}]*\$where\s*:/gi,
      name: 'NoSQL Injection (MongoDB $where)',
      severity: Severity.CRITICAL,
      description: 'MongoDB $where clause can execute arbitrary JavaScript.',
      recommendation: 'Avoid $where, use query operators instead.',
      cwe: 'CWE-943',
    },
    {
      pattern: /\.find\s*\(\s*(?:json\.loads|eval|ast\.literal_eval)\s*\(/gi,
      name: 'NoSQL Injection (dynamic query)',
      severity: Severity.CRITICAL,
      description: 'Dynamic query construction allows NoSQL injection.',
      recommendation: 'Validate and sanitize input before building queries.',
      cwe: 'CWE-943',
    },
    {
      pattern: /\$(?:regex|where|expr|function)\s*:\s*(?:f["']|["'].*\+|request\.|input\()/gi,
      name: 'NoSQL Injection (operator injection)',
      severity: Severity.HIGH,
      description: 'User input in MongoDB operators can bypass authentication.',
      recommendation: 'Whitelist allowed operators and validate input types.',
      cwe: 'CWE-943',
    },
    {
      pattern: /redis\.(?:execute_command|eval)\s*\(\s*(?:f["']|["'].*\+)/gi,
      name: 'Redis Command Injection',
      severity: Severity.CRITICAL,
      description: 'Unsanitized input in Redis commands allows injection.',
      recommendation: 'Use parameterized Redis commands.',
      cwe: 'CWE-943',
    },
  ],

  javascript: [
    {
      pattern: /\.find\s*\(\s*\{[^}]*\$where\s*:/gi,
      name: 'NoSQL Injection (MongoDB $where)',
      severity: Severity.CRITICAL,
      description: 'MongoDB $where clause can execute arbitrary JavaScript.',
      recommendation: 'Avoid $where, use query operators instead.',
      cwe: 'CWE-943',
    },
    {
      pattern: /\.find\s*\(\s*JSON\.parse\s*\(/gi,
      name: 'NoSQL Injection (JSON.parse in query)',
      severity: Severity.CRITICAL,
      description: 'Parsing user input directly into MongoDB query.',
      recommendation: 'Validate structure and types of parsed JSON.',
      cwe: 'CWE-943',
    },
    {
      pattern: /\{[^}]*\$(?:gt|gte|lt|lte|ne|in|nin|regex|exists|type)\s*:\s*req\./gi,
      name: 'NoSQL Injection (operator from request)',
      severity: Severity.HIGH,
      description: 'User-controlled operators allow query manipulation.',
      recommendation: 'Validate input types and whitelist operators.',
      cwe: 'CWE-943',
    },
    {
      pattern: /Model\.find\s*\(\s*req\.(?:body|query|params)/gi,
      name: 'NoSQL Injection (direct request to query)',
      severity: Severity.CRITICAL,
      description: 'Request data passed directly to Mongoose query.',
      recommendation: 'Validate and sanitize request data before querying.',
      cwe: 'CWE-943',
    },
    {
      pattern: /dynamodb\.(?:query|scan|getItem|putItem)\s*\([^)]*(?:req\.|user\.|input)/gi,
      name: 'NoSQL Injection (DynamoDB)',
      severity: Severity.HIGH,
      description: 'User input in DynamoDB query parameters.',
      recommendation: 'Validate and sanitize all DynamoDB parameters.',
      cwe: 'CWE-943',
    },
  ],

  java: [
    {
      pattern: /BasicDBObject\s*\(\s*(?:"\$where"|"\$regex")/gi,
      name: 'NoSQL Injection (MongoDB Java)',
      severity: Severity.CRITICAL,
      description: 'Dangerous MongoDB operators in query.',
      recommendation: 'Avoid $where, validate all query parameters.',
      cwe: 'CWE-943',
    },
    {
      pattern: /Filters\.(?:regex|where)\s*\([^)]*\+/gi,
      name: 'NoSQL Injection (MongoDB Filters)',
      severity: Severity.HIGH,
      description: 'String concatenation in MongoDB filter.',
      recommendation: 'Use parameterized filters.',
      cwe: 'CWE-943',
    },
    {
      pattern: /Document\.parse\s*\([^)]*\+/gi,
      name: 'NoSQL Injection (Document.parse)',
      severity: Severity.CRITICAL,
      description: 'Parsing user-controlled string as MongoDB document.',
      recommendation: 'Build documents programmatically.',
      cwe: 'CWE-943',
    },
  ],

  php: [
    {
      pattern: /\$mongo->(?:find|findOne|aggregate)\s*\(\s*(?:json_decode|\$_(?:GET|POST|REQUEST))/gi,
      name: 'NoSQL Injection (MongoDB PHP)',
      severity: Severity.CRITICAL,
      description: 'User input directly in MongoDB query.',
      recommendation: 'Validate and sanitize all query parameters.',
      cwe: 'CWE-943',
    },
    {
      pattern: /\[['"]?\$where['"]?\s*=>/gi,
      name: 'NoSQL Injection ($where operator)',
      severity: Severity.CRITICAL,
      description: 'MongoDB $where operator allows JavaScript execution.',
      recommendation: 'Avoid $where, use standard query operators.',
      cwe: 'CWE-943',
    },
  ],

  csharp: [
    {
      pattern: /BsonDocument\.Parse\s*\([^)]*\+/gi,
      name: 'NoSQL Injection (BsonDocument.Parse)',
      severity: Severity.CRITICAL,
      description: 'Parsing user-controlled string as BSON document.',
      recommendation: 'Build BSON documents using BsonDocument constructor.',
      cwe: 'CWE-943',
    },
    {
      pattern: /FilterDefinition.*\$where/gi,
      name: 'NoSQL Injection ($where in filter)',
      severity: Severity.CRITICAL,
      description: 'MongoDB $where operator allows arbitrary JavaScript.',
      recommendation: 'Use FilterDefinitionBuilder methods instead.',
      cwe: 'CWE-943',
    },
  ],
};

/**
 * LDAP Injection patterns by language
 */
export const LDAP_INJECTION_PATTERNS: Record<string, Array<{
  pattern: RegExp;
  name: string;
  severity: Severity;
  description: string;
  recommendation: string;
  cwe: string;
}>> = {
  python: [
    {
      pattern: /ldap\.search\s*\([^)]*(?:f["']|["'].*%|["'].*\.format\s*\(|["'].*\+)/gi,
      name: 'LDAP Injection (search)',
      severity: Severity.HIGH,
      description: 'String interpolation in LDAP search filter.',
      recommendation: 'Use ldap.filter.escape_filter_chars() to sanitize input.',
      cwe: 'CWE-90',
    },
    {
      pattern: /ldap3\.(?:Connection|Server).*search\s*\([^)]*\+/gi,
      name: 'LDAP Injection (ldap3)',
      severity: Severity.HIGH,
      description: 'Unsanitized input in ldap3 search query.',
      recommendation: 'Use ldap3.utils.conv.escape_filter_chars().',
      cwe: 'CWE-90',
    },
    {
      pattern: /\(\s*(?:cn|uid|mail|sn|givenName)\s*=\s*(?:f["']|%s|.*\+)/gi,
      name: 'LDAP Injection (filter construction)',
      severity: Severity.HIGH,
      description: 'Dynamic LDAP filter construction without escaping.',
      recommendation: 'Escape special LDAP characters: *, (, ), \\, NUL.',
      cwe: 'CWE-90',
    },
  ],

  java: [
    {
      pattern: /(?:DirContext|InitialDirContext)\.search\s*\([^)]*\+/gi,
      name: 'LDAP Injection (DirContext)',
      severity: Severity.HIGH,
      description: 'String concatenation in LDAP search filter.',
      recommendation: 'Use SearchControls with parameterized filters.',
      cwe: 'CWE-90',
    },
    {
      pattern: /new\s+SearchControls.*setSearchFilter\s*\([^)]*\+/gi,
      name: 'LDAP Injection (SearchControls)',
      severity: Severity.HIGH,
      description: 'Dynamic filter in SearchControls.',
      recommendation: 'Sanitize input using ESAPI.encoder().encodeForLDAP().',
      cwe: 'CWE-90',
    },
    {
      pattern: /LdapQueryBuilder.*filter\s*\([^)]*String\.format/gi,
      name: 'LDAP Injection (Spring LDAP)',
      severity: Severity.HIGH,
      description: 'String.format in Spring LDAP query.',
      recommendation: 'Use LdapQueryBuilder with proper encoding.',
      cwe: 'CWE-90',
    },
  ],

  php: [
    {
      pattern: /ldap_search\s*\([^)]*\$_(?:GET|POST|REQUEST)/gi,
      name: 'LDAP Injection (ldap_search)',
      severity: Severity.HIGH,
      description: 'User input directly in LDAP search filter.',
      recommendation: 'Use ldap_escape() to sanitize input.',
      cwe: 'CWE-90',
    },
    {
      pattern: /ldap_(?:bind|search|read)\s*\([^)]*\.\s*\$/gi,
      name: 'LDAP Injection (string concat)',
      severity: Severity.HIGH,
      description: 'String concatenation in LDAP query.',
      recommendation: 'Use ldap_escape() for all user input.',
      cwe: 'CWE-90',
    },
  ],

  csharp: [
    {
      pattern: /DirectorySearcher.*Filter\s*=\s*(?:\$"|".*\+|string\.Format)/gi,
      name: 'LDAP Injection (DirectorySearcher)',
      severity: Severity.HIGH,
      description: 'Dynamic filter in DirectorySearcher.',
      recommendation: 'Use parameterized searches or encode input.',
      cwe: 'CWE-90',
    },
    {
      pattern: /new\s+DirectoryEntry\s*\([^)]*\+/gi,
      name: 'LDAP Injection (DirectoryEntry)',
      severity: Severity.HIGH,
      description: 'String concatenation in LDAP path.',
      recommendation: 'Validate and encode LDAP distinguished names.',
      cwe: 'CWE-90',
    },
  ],

  javascript: [
    {
      pattern: /ldapjs\.createClient.*search\s*\([^)]*\+/gi,
      name: 'LDAP Injection (ldapjs)',
      severity: Severity.HIGH,
      description: 'String concatenation in ldapjs search.',
      recommendation: 'Use ldapjs.parseDN() and proper escaping.',
      cwe: 'CWE-90',
    },
    {
      pattern: /filter:\s*['"`]\([^)]*=\s*\$\{/gi,
      name: 'LDAP Injection (template literal)',
      severity: Severity.HIGH,
      description: 'Template literal in LDAP filter.',
      recommendation: 'Escape LDAP special characters before interpolation.',
      cwe: 'CWE-90',
    },
  ],
};

/**
 * XPath Injection patterns by language
 */
export const XPATH_INJECTION_PATTERNS: Record<string, Array<{
  pattern: RegExp;
  name: string;
  severity: Severity;
  description: string;
  recommendation: string;
  cwe: string;
}>> = {
  python: [
    {
      pattern: /\.xpath\s*\(\s*(?:f["']|["'].*%|["'].*\.format\s*\(|["'].*\+)/gi,
      name: 'XPath Injection',
      severity: Severity.HIGH,
      description: 'String interpolation in XPath query.',
      recommendation: 'Use XPath variables or parameterized queries.',
      cwe: 'CWE-643',
    },
    {
      pattern: /etree\.XPath\s*\(\s*(?:f["']|["'].*%)/gi,
      name: 'XPath Injection (lxml)',
      severity: Severity.HIGH,
      description: 'Dynamic XPath expression construction.',
      recommendation: 'Use lxml XPath with variables parameter.',
      cwe: 'CWE-643',
    },
  ],

  java: [
    {
      pattern: /XPathFactory.*evaluate\s*\([^)]*\+/gi,
      name: 'XPath Injection (XPathFactory)',
      severity: Severity.HIGH,
      description: 'String concatenation in XPath expression.',
      recommendation: 'Use XPathVariableResolver for user input.',
      cwe: 'CWE-643',
    },
    {
      pattern: /\.compile\s*\(\s*["']\/\/.*\+/gi,
      name: 'XPath Injection (compile)',
      severity: Severity.HIGH,
      description: 'Dynamic XPath expression.',
      recommendation: 'Precompile XPath and use variables.',
      cwe: 'CWE-643',
    },
  ],

  php: [
    {
      pattern: /->xpath\s*\(\s*["'].*\.\s*\$/gi,
      name: 'XPath Injection',
      severity: Severity.HIGH,
      description: 'String concatenation in XPath query.',
      recommendation: 'Sanitize input, escape single quotes and special chars.',
      cwe: 'CWE-643',
    },
    {
      pattern: /DOMXPath.*query\s*\([^)]*\$_(?:GET|POST|REQUEST)/gi,
      name: 'XPath Injection (DOMXPath)',
      severity: Severity.HIGH,
      description: 'User input directly in XPath query.',
      recommendation: 'Validate and sanitize all XPath input.',
      cwe: 'CWE-643',
    },
  ],

  csharp: [
    {
      pattern: /\.SelectNodes?\s*\(\s*(?:\$"|".*\+|string\.Format)/gi,
      name: 'XPath Injection (SelectNodes)',
      severity: Severity.HIGH,
      description: 'Dynamic XPath in SelectNodes/SelectSingleNode.',
      recommendation: 'Use XPathNavigator with compiled expressions.',
      cwe: 'CWE-643',
    },
    {
      pattern: /XPathExpression\.Compile\s*\([^)]*\+/gi,
      name: 'XPath Injection (Compile)',
      severity: Severity.HIGH,
      description: 'String concatenation in XPath compilation.',
      recommendation: 'Validate input and use XPath variables.',
      cwe: 'CWE-643',
    },
  ],

  javascript: [
    {
      pattern: /document\.evaluate\s*\([^)]*\+/gi,
      name: 'XPath Injection (document.evaluate)',
      severity: Severity.HIGH,
      description: 'String concatenation in XPath query.',
      recommendation: 'Sanitize input before XPath construction.',
      cwe: 'CWE-643',
    },
    {
      pattern: /xpath\.select\s*\(\s*[`'"].*\$\{/gi,
      name: 'XPath Injection (template literal)',
      severity: Severity.HIGH,
      description: 'Template literal in XPath expression.',
      recommendation: 'Escape XPath special characters.',
      cwe: 'CWE-643',
    },
  ],
};

/**
 * GraphQL Injection patterns
 */
export const GRAPHQL_INJECTION_PATTERNS: Record<string, Array<{
  pattern: RegExp;
  name: string;
  severity: Severity;
  description: string;
  recommendation: string;
  cwe: string;
}>> = {
  javascript: [
    {
      pattern: /graphql\s*\(\s*[`'"].*\$\{(?!.*variables)/gi,
      name: 'GraphQL Injection (template literal)',
      severity: Severity.HIGH,
      description: 'Direct string interpolation in GraphQL query.',
      recommendation: 'Use GraphQL variables instead of string interpolation.',
      cwe: 'CWE-943',
    },
    {
      pattern: /query\s*:\s*[`'"].*\+\s*(?:req\.|user\.|input)/gi,
      name: 'GraphQL Injection (concatenation)',
      severity: Severity.HIGH,
      description: 'String concatenation in GraphQL query.',
      recommendation: 'Use parameterized queries with variables.',
      cwe: 'CWE-943',
    },
    {
      pattern: /depthLimit\s*:\s*(?:undefined|null|0|false)/gi,
      name: 'GraphQL DoS (no depth limit)',
      severity: Severity.MEDIUM,
      description: 'GraphQL queries without depth limit allow DoS.',
      recommendation: 'Configure appropriate depthLimit (e.g., 10).',
      cwe: 'CWE-400',
    },
    {
      pattern: /introspection\s*:\s*true/gi,
      name: 'GraphQL Introspection Enabled',
      severity: Severity.LOW,
      description: 'GraphQL introspection exposes schema in production.',
      recommendation: 'Disable introspection in production.',
      cwe: 'CWE-200',
    },
    {
      pattern: /validationRules\s*:\s*\[\s*\]/gi,
      name: 'GraphQL Validation Disabled',
      severity: Severity.HIGH,
      description: 'Empty validation rules allow malformed queries.',
      recommendation: 'Use default validation rules.',
      cwe: 'CWE-20',
    },
  ],

  python: [
    {
      pattern: /graphql\s*\(\s*(?:f["']|["'].*%|["'].*\.format)/gi,
      name: 'GraphQL Injection',
      severity: Severity.HIGH,
      description: 'String formatting in GraphQL query.',
      recommendation: 'Use GraphQL variables parameter.',
      cwe: 'CWE-943',
    },
    {
      pattern: /execute\s*\(\s*["'].*\+.*query/gi,
      name: 'GraphQL Injection (execute)',
      severity: Severity.HIGH,
      description: 'Dynamic GraphQL query construction.',
      recommendation: 'Use parameterized queries with variables.',
      cwe: 'CWE-943',
    },
  ],

  java: [
    {
      pattern: /GraphQL\.newGraphQL.*execute\s*\([^)]*\+/gi,
      name: 'GraphQL Injection (Java)',
      severity: Severity.HIGH,
      description: 'String concatenation in GraphQL execution.',
      recommendation: 'Use variables parameter in ExecutionInput.',
      cwe: 'CWE-943',
    },
  ],

  php: [
    {
      pattern: /GraphQL::executeQuery\s*\([^)]*\.\s*\$/gi,
      name: 'GraphQL Injection (PHP)',
      severity: Severity.HIGH,
      description: 'String concatenation in GraphQL query.',
      recommendation: 'Use variables parameter.',
      cwe: 'CWE-943',
    },
  ],

  csharp: [
    {
      pattern: /ExecuteAsync\s*\(\s*(?:\$"|".*\+|string\.Format).*query/gi,
      name: 'GraphQL Injection (C#)',
      severity: Severity.HIGH,
      description: 'Dynamic GraphQL query construction.',
      recommendation: 'Use Inputs parameter for variables.',
      cwe: 'CWE-943',
    },
  ],
};

/**
 * ReDoS (Regular Expression Denial of Service) patterns
 */
export const REDOS_PATTERNS: Record<string, Array<{
  pattern: RegExp;
  name: string;
  severity: Severity;
  description: string;
  recommendation: string;
  cwe: string;
}>> = {
  // Language-agnostic patterns that indicate potential ReDoS
  common: [
    {
      pattern: /\(\s*[^)]*[+*]\s*\)\s*[+*]/gi,
      name: 'ReDoS (nested quantifiers)',
      severity: Severity.MEDIUM,
      description: 'Nested quantifiers (e.g., (a+)+) can cause catastrophic backtracking.',
      recommendation: 'Simplify regex or use atomic groups/possessive quantifiers.',
      cwe: 'CWE-1333',
    },
    {
      pattern: /\(\s*[^)]*\|\s*[^)]*\)\s*[+*]/gi,
      name: 'ReDoS (alternation with quantifier)',
      severity: Severity.MEDIUM,
      description: 'Alternation with quantifier (e.g., (a|a)+) can cause exponential backtracking.',
      recommendation: 'Avoid ambiguous alternations in quantified groups.',
      cwe: 'CWE-1333',
    },
    {
      pattern: /\[[^\]]*\]\s*[+*]\s*\[[^\]]*\]\s*[+*]/gi,
      name: 'ReDoS (overlapping character classes)',
      severity: Severity.MEDIUM,
      description: 'Overlapping character classes with quantifiers can cause ReDoS.',
      recommendation: 'Make character classes mutually exclusive.',
      cwe: 'CWE-1333',
    },
    {
      pattern: /\\s\*.*\\s\*/gi,
      name: 'ReDoS (greedy whitespace)',
      severity: Severity.LOW,
      description: 'Multiple greedy whitespace matches can cause performance issues.',
      recommendation: 'Use non-greedy quantifiers or specific counts.',
      cwe: 'CWE-1333',
    },
  ],

  javascript: [
    {
      pattern: /new\s+RegExp\s*\(\s*(?:req\.|user\.|input)/gi,
      name: 'ReDoS (user-controlled regex)',
      severity: Severity.HIGH,
      description: 'User input used to construct regular expression.',
      recommendation: 'Never build regex from user input, or use re2 library.',
      cwe: 'CWE-1333',
    },
    {
      pattern: /\.match\s*\(\s*new\s+RegExp\s*\(\s*\w+\s*\)/gi,
      name: 'ReDoS (dynamic regex)',
      severity: Severity.MEDIUM,
      description: 'Dynamic regex construction may be vulnerable.',
      recommendation: 'Validate regex complexity or use re2 library.',
      cwe: 'CWE-1333',
    },
  ],

  python: [
    {
      pattern: /re\.compile\s*\(\s*(?:f["']|["'].*%|.*\+)/gi,
      name: 'ReDoS (user-controlled regex)',
      severity: Severity.HIGH,
      description: 'Dynamic regex pattern may be vulnerable to ReDoS.',
      recommendation: 'Use google-re2 or validate regex complexity.',
      cwe: 'CWE-1333',
    },
    {
      pattern: /re\.(?:match|search|findall)\s*\(\s*(?:input|request|user)/gi,
      name: 'ReDoS (user input in regex)',
      severity: Severity.HIGH,
      description: 'User input used as regex pattern.',
      recommendation: 'Use re2 library or validate input complexity.',
      cwe: 'CWE-1333',
    },
  ],

  java: [
    {
      pattern: /Pattern\.compile\s*\([^)]*\+/gi,
      name: 'ReDoS (dynamic Pattern)',
      severity: Severity.MEDIUM,
      description: 'Dynamic regex pattern compilation.',
      recommendation: 'Validate regex complexity or precompile patterns.',
      cwe: 'CWE-1333',
    },
  ],

  php: [
    {
      pattern: /preg_(?:match|replace)\s*\(\s*["']?[^,]*\$_/gi,
      name: 'ReDoS (user-controlled regex)',
      severity: Severity.HIGH,
      description: 'User input in preg pattern.',
      recommendation: 'Never use user input in regex patterns.',
      cwe: 'CWE-1333',
    },
  ],
};

/**
 * Get security standards for injection findings
 */
export function getInjectionStandards(category: string): SecurityStandard[] {
  const standards: Record<string, SecurityStandard[]> = {
    'SQL Injection': [
      {
        name: 'CWE',
        id: 'CWE-89',
        title: 'SQL Injection',
        description: 'Improper Neutralization of Special Elements used in an SQL Command.',
        url: 'https://cwe.mitre.org/data/definitions/89.html'
      },
      {
        name: 'OWASP',
        id: 'A03:2021',
        title: 'Injection',
        description: 'Injection flaws occur when untrusted data is sent to an interpreter.',
        url: 'https://owasp.org/Top10/A03_2021-Injection/'
      }
    ],
    'Command Injection': [
      {
        name: 'CWE',
        id: 'CWE-78',
        title: 'OS Command Injection',
        description: 'Improper Neutralization of Special Elements used in an OS Command.',
        url: 'https://cwe.mitre.org/data/definitions/78.html'
      },
      {
        name: 'OWASP',
        id: 'A03:2021',
        title: 'Injection',
        description: 'Injection flaws occur when untrusted data is sent to an interpreter.',
        url: 'https://owasp.org/Top10/A03_2021-Injection/'
      }
    ],
    'XSS': [
      {
        name: 'CWE',
        id: 'CWE-79',
        title: 'Cross-site Scripting (XSS)',
        description: 'Improper Neutralization of Input During Web Page Generation.',
        url: 'https://cwe.mitre.org/data/definitions/79.html'
      },
      {
        name: 'OWASP',
        id: 'A03:2021',
        title: 'Injection',
        description: 'XSS is now part of the Injection category.',
        url: 'https://owasp.org/Top10/A03_2021-Injection/'
      }
    ],
    'SSTI': [
      {
        name: 'CWE',
        id: 'CWE-1336',
        title: 'Server-Side Template Injection',
        description: 'Improper Neutralization of Special Elements in Template Engine.',
        url: 'https://cwe.mitre.org/data/definitions/1336.html'
      },
      {
        name: 'OWASP',
        id: 'A03:2021',
        title: 'Injection',
        description: 'Template injection is a form of injection attack.',
        url: 'https://owasp.org/Top10/A03_2021-Injection/'
      }
    ],
    'Path Traversal': [
      {
        name: 'CWE',
        id: 'CWE-22',
        title: 'Path Traversal',
        description: 'Improper Limitation of a Pathname to a Restricted Directory.',
        url: 'https://cwe.mitre.org/data/definitions/22.html'
      },
      {
        name: 'OWASP',
        id: 'A01:2021',
        title: 'Broken Access Control',
        description: 'Path traversal allows unauthorized file access.',
        url: 'https://owasp.org/Top10/A01_2021-Broken_Access_Control/'
      }
    ],
    'NoSQL Injection': [
      {
        name: 'CWE',
        id: 'CWE-943',
        title: 'NoSQL Injection',
        description: 'Improper Neutralization of Special Elements in Data Query Logic.',
        url: 'https://cwe.mitre.org/data/definitions/943.html'
      },
      {
        name: 'OWASP',
        id: 'A03:2021',
        title: 'Injection',
        description: 'NoSQL injection is a form of injection attack targeting NoSQL databases.',
        url: 'https://owasp.org/Top10/A03_2021-Injection/'
      }
    ],
    'LDAP Injection': [
      {
        name: 'CWE',
        id: 'CWE-90',
        title: 'LDAP Injection',
        description: 'Improper Neutralization of Special Elements used in an LDAP Query.',
        url: 'https://cwe.mitre.org/data/definitions/90.html'
      },
      {
        name: 'OWASP',
        id: 'A03:2021',
        title: 'Injection',
        description: 'LDAP injection allows manipulation of directory queries.',
        url: 'https://owasp.org/Top10/A03_2021-Injection/'
      }
    ],
    'XPath Injection': [
      {
        name: 'CWE',
        id: 'CWE-643',
        title: 'XPath Injection',
        description: 'Improper Neutralization of Data within XPath Expressions.',
        url: 'https://cwe.mitre.org/data/definitions/643.html'
      },
      {
        name: 'OWASP',
        id: 'A03:2021',
        title: 'Injection',
        description: 'XPath injection allows manipulation of XML queries.',
        url: 'https://owasp.org/Top10/A03_2021-Injection/'
      }
    ],
    'GraphQL Injection': [
      {
        name: 'CWE',
        id: 'CWE-943',
        title: 'GraphQL Injection',
        description: 'Improper Neutralization of Special Elements in GraphQL queries.',
        url: 'https://cwe.mitre.org/data/definitions/943.html'
      },
      {
        name: 'OWASP',
        id: 'A03:2021',
        title: 'Injection',
        description: 'GraphQL injection can manipulate query structure.',
        url: 'https://owasp.org/Top10/A03_2021-Injection/'
      }
    ],
    'ReDoS': [
      {
        name: 'CWE',
        id: 'CWE-1333',
        title: 'ReDoS',
        description: 'Inefficient Regular Expression Complexity.',
        url: 'https://cwe.mitre.org/data/definitions/1333.html'
      },
      {
        name: 'OWASP',
        id: 'A06:2021',
        title: 'Vulnerable and Outdated Components',
        description: 'ReDoS can cause denial of service through regex complexity.',
        url: 'https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/'
      }
    ],
  };

  return standards[category] || [];
}
