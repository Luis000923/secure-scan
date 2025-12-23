/**
 * @fileoverview Vulnerability Detection Module - Constants
 * @module rules/vulnerabilities/constants
 * 
 * Thresholds, limits, and configuration constants for vulnerability detection.
 */

// ============================================================================
// SCORE THRESHOLDS
// ============================================================================

/**
 * Score thresholds for severity classification
 */
export const SCORE_THRESHOLDS = {
  CRITICAL: 90,
  HIGH: 70,
  MEDIUM: 50,
  LOW: 30,
  INFO: 0
} as const;

/**
 * Risk level descriptions
 */
export const RISK_LEVELS = {
  CRITICAL: 'critical',
  HIGH: 'high',
  MEDIUM: 'medium',
  LOW: 'low',
  MINIMAL: 'minimal'
} as const;

/**
 * Confidence thresholds
 */
export const CONFIDENCE_THRESHOLDS = {
  CONFIRMED: 0.95,
  HIGH: 0.80,
  MEDIUM: 0.60,
  LOW: 0.40,
  TENTATIVE: 0.20
} as const;

// ============================================================================
// LIMITS
// ============================================================================

/**
 * Engine limits for performance and safety
 */
export const LIMITS = {
  /** Maximum regex execution time in ms */
  REGEX_TIMEOUT: 100,
  /** Maximum rule execution time in ms */
  RULE_TIMEOUT: 5000,
  /** Maximum file size to analyze in bytes */
  MAX_FILE_SIZE: 5 * 1024 * 1024, // 5MB
  /** Maximum AST nodes to analyze */
  MAX_AST_NODES: 100000,
  /** Maximum matches per pattern */
  MAX_MATCHES_PER_PATTERN: 100,
  /** Maximum findings per file */
  MAX_FINDINGS_PER_FILE: 500,
  /** Maximum taint flow depth */
  MAX_TAINT_DEPTH: 50,
  /** Maximum line length to analyze */
  MAX_LINE_LENGTH: 10000
} as const;

// ============================================================================
// DEFAULT SCORING WEIGHTS
// ============================================================================

/**
 * Default weights for vulnerability scoring
 */
export const DEFAULT_SCORING_WEIGHTS = {
  taintFlow: 0.30,
  patternCount: 0.15,
  exploitability: 0.20,
  impact: 0.20,
  context: 0.15
} as const;

// ============================================================================
// TAINT SOURCES BY LANGUAGE
// ============================================================================

/**
 * Common taint sources for JavaScript/TypeScript
 */
export const JS_TAINT_SOURCES = {
  // Express.js
  'req.body': { pattern: /req\.body(?:\.\w+|\[\s*['"`]\w+['"`]\s*\])?/g, category: 'user_input' },
  'req.query': { pattern: /req\.query(?:\.\w+|\[\s*['"`]\w+['"`]\s*\])?/g, category: 'user_input' },
  'req.params': { pattern: /req\.params(?:\.\w+|\[\s*['"`]\w+['"`]\s*\])?/g, category: 'user_input' },
  'req.headers': { pattern: /req\.headers(?:\.\w+|\[\s*['"`]\w+['"`]\s*\])?/g, category: 'user_input' },
  'req.cookies': { pattern: /req\.cookies(?:\.\w+|\[\s*['"`]\w+['"`]\s*\])?/g, category: 'user_input' },
  
  // Browser
  'location': { pattern: /(?:window\.)?location\.(?:search|hash|href|pathname)/g, category: 'user_input' },
  'document.URL': { pattern: /document\.(?:URL|documentURI|baseURI)/g, category: 'user_input' },
  'document.referrer': { pattern: /document\.referrer/g, category: 'user_input' },
  'document.cookie': { pattern: /document\.cookie/g, category: 'user_input' },
  
  // Forms
  'FormData': { pattern: /new\s+FormData\s*\(/g, category: 'user_input' },
  'URLSearchParams': { pattern: /new\s+URLSearchParams\s*\(/g, category: 'user_input' },
  
  // DOM
  'innerHTML': { pattern: /\.innerHTML/g, category: 'user_input' },
  'innerText': { pattern: /\.innerText/g, category: 'user_input' },
  'textContent': { pattern: /\.textContent/g, category: 'user_input' },
  'value': { pattern: /\.value\b/g, category: 'user_input' },
  
  // Environment
  'process.env': { pattern: /process\.env(?:\.\w+|\[\s*['"`]\w+['"`]\s*\])?/g, category: 'environment' }
} as const;

/**
 * Common taint sources for Python
 */
export const PYTHON_TAINT_SOURCES = {
  // Flask
  'request.args': { pattern: /request\.args\.get\s*\(/g, category: 'user_input' },
  'request.form': { pattern: /request\.form\.get\s*\(/g, category: 'user_input' },
  'request.data': { pattern: /request\.(?:data|json|get_json\(\))/g, category: 'user_input' },
  'request.headers': { pattern: /request\.headers\.get\s*\(/g, category: 'user_input' },
  'request.cookies': { pattern: /request\.cookies\.get\s*\(/g, category: 'user_input' },
  
  // Django
  'GET': { pattern: /request\.GET\.get\s*\(/g, category: 'user_input' },
  'POST': { pattern: /request\.POST\.get\s*\(/g, category: 'user_input' },
  
  // Standard input
  'input': { pattern: /\binput\s*\(/g, category: 'user_input' },
  'raw_input': { pattern: /\braw_input\s*\(/g, category: 'user_input' },
  'sys.argv': { pattern: /sys\.argv/g, category: 'user_input' },
  
  // File
  'open': { pattern: /\bopen\s*\(/g, category: 'file' },
  'read': { pattern: /\.read\s*\(/g, category: 'file' },
  
  // Environment
  'os.environ': { pattern: /os\.environ(?:\.get\s*\(|\[)/g, category: 'environment' },
  'os.getenv': { pattern: /os\.getenv\s*\(/g, category: 'environment' }
} as const;

/**
 * Common taint sources for PHP
 */
export const PHP_TAINT_SOURCES = {
  '$_GET': { pattern: /\$_GET\s*\[/g, category: 'user_input' },
  '$_POST': { pattern: /\$_POST\s*\[/g, category: 'user_input' },
  '$_REQUEST': { pattern: /\$_REQUEST\s*\[/g, category: 'user_input' },
  '$_COOKIE': { pattern: /\$_COOKIE\s*\[/g, category: 'user_input' },
  '$_FILES': { pattern: /\$_FILES\s*\[/g, category: 'user_input' },
  '$_SERVER': { pattern: /\$_SERVER\s*\[/g, category: 'user_input' },
  '$_ENV': { pattern: /\$_ENV\s*\[/g, category: 'environment' },
  'file_get_contents': { pattern: /file_get_contents\s*\(/g, category: 'file' },
  'fread': { pattern: /fread\s*\(/g, category: 'file' }
} as const;

/**
 * Common taint sources for Java
 */
export const JAVA_TAINT_SOURCES = {
  'getParameter': { pattern: /\.getParameter\s*\(/g, category: 'user_input' },
  'getParameterValues': { pattern: /\.getParameterValues\s*\(/g, category: 'user_input' },
  'getHeader': { pattern: /\.getHeader\s*\(/g, category: 'user_input' },
  'getCookies': { pattern: /\.getCookies\s*\(/g, category: 'user_input' },
  'getInputStream': { pattern: /\.getInputStream\s*\(/g, category: 'user_input' },
  'getReader': { pattern: /\.getReader\s*\(/g, category: 'user_input' },
  'getPathVariable': { pattern: /@PathVariable/g, category: 'user_input' },
  'getRequestBody': { pattern: /@RequestBody/g, category: 'user_input' },
  'System.getenv': { pattern: /System\.getenv\s*\(/g, category: 'environment' },
  'System.getProperty': { pattern: /System\.getProperty\s*\(/g, category: 'environment' }
} as const;

/**
 * Common taint sources for C#
 */
export const CSHARP_TAINT_SOURCES = {
  'Request.Form': { pattern: /Request\.Form\[/g, category: 'user_input' },
  'Request.QueryString': { pattern: /Request\.QueryString\[/g, category: 'user_input' },
  'Request.Headers': { pattern: /Request\.Headers\[/g, category: 'user_input' },
  'Request.Cookies': { pattern: /Request\.Cookies\[/g, category: 'user_input' },
  'FromBody': { pattern: /\[FromBody\]/g, category: 'user_input' },
  'FromQuery': { pattern: /\[FromQuery\]/g, category: 'user_input' },
  'FromRoute': { pattern: /\[FromRoute\]/g, category: 'user_input' },
  'Environment.GetEnvironmentVariable': { pattern: /Environment\.GetEnvironmentVariable\s*\(/g, category: 'environment' },
  'Console.ReadLine': { pattern: /Console\.ReadLine\s*\(/g, category: 'user_input' }
} as const;

// ============================================================================
// DANGEROUS SINKS BY VULNERABILITY TYPE
// ============================================================================

/**
 * SQL Injection sinks
 */
export const SQL_INJECTION_SINKS = {
  // Generic SQL
  'query': /\.query\s*\(/g,
  'execute': /\.execute\s*\(/g,
  'exec': /\.exec\s*\(/g,
  'raw': /\.raw\s*\(/g,
  'rawQuery': /\.rawQuery\s*\(/g,
  
  // JavaScript
  'mysql.query': /mysql\s*\.\s*query\s*\(/g,
  'pg.query': /(?:pool|client)\s*\.\s*query\s*\(/g,
  'sequelize.query': /sequelize\s*\.\s*query\s*\(/g,
  
  // Python
  'cursor.execute': /cursor\s*\.\s*execute\s*\(/g,
  'cursor.executemany': /cursor\s*\.\s*executemany\s*\(/g,
  
  // PHP
  'mysql_query': /mysql_query\s*\(/g,
  'mysqli_query': /mysqli_query\s*\(/g,
  'pg_query': /pg_query\s*\(/g,
  'PDO::query': /->query\s*\(/g,
  
  // Java
  'Statement.execute': /(?:Statement|PreparedStatement)\s*\.\s*execute(?:Query|Update)?\s*\(/g,
  'createQuery': /\.createQuery\s*\(/g,
  'createNativeQuery': /\.createNativeQuery\s*\(/g,
  
  // C#
  'SqlCommand': /new\s+SqlCommand\s*\(/g,
  'ExecuteReader': /\.ExecuteReader\s*\(/g,
  'ExecuteNonQuery': /\.ExecuteNonQuery\s*\(/g,
  'ExecuteScalar': /\.ExecuteScalar\s*\(/g
} as const;

/**
 * Command Injection sinks
 */
export const COMMAND_INJECTION_SINKS = {
  // JavaScript
  'exec': /(?:child_process\s*\.\s*)?exec\s*\(/g,
  'execSync': /(?:child_process\s*\.\s*)?execSync\s*\(/g,
  'spawn': /(?:child_process\s*\.\s*)?spawn\s*\(/g,
  'spawnSync': /(?:child_process\s*\.\s*)?spawnSync\s*\(/g,
  'execFile': /(?:child_process\s*\.\s*)?execFile\s*\(/g,
  
  // Python
  'os.system': /os\s*\.\s*system\s*\(/g,
  'os.popen': /os\s*\.\s*popen\s*\(/g,
  'subprocess': /subprocess\s*\.\s*(?:call|run|Popen|check_output)\s*\(/g,
  'commands': /commands\s*\.\s*(?:getoutput|getstatusoutput)\s*\(/g,
  
  // PHP
  'php_system': /\bsystem\s*\(/g,
  'php_exec': /\bexec\s*\(/g,
  'shell_exec': /shell_exec\s*\(/g,
  'passthru': /passthru\s*\(/g,
  'popen': /popen\s*\(/g,
  'proc_open': /proc_open\s*\(/g,
  'backtick': /`[^`]*\$[^`]*`/g,
  
  // Java
  'Runtime.exec': /Runtime\s*\.\s*getRuntime\s*\(\s*\)\s*\.\s*exec\s*\(/g,
  'ProcessBuilder': /new\s+ProcessBuilder\s*\(/g,
  
  // C#
  'Process.Start': /Process\s*\.\s*Start\s*\(/g
} as const;

/**
 * XSS sinks
 */
export const XSS_SINKS = {
  // DOM
  'innerHTML': /\.innerHTML\s*=/g,
  'outerHTML': /\.outerHTML\s*=/g,
  'document.write': /document\s*\.\s*write(?:ln)?\s*\(/g,
  'insertAdjacentHTML': /\.insertAdjacentHTML\s*\(/g,
  
  // jQuery
  'html': /\$\([^)]*\)\s*\.\s*html\s*\(/g,
  'append': /\$\([^)]*\)\s*\.\s*(?:append|prepend|after|before)\s*\(/g,
  
  // React (dangerous)
  'dangerouslySetInnerHTML': /dangerouslySetInnerHTML\s*=\s*\{/g,
  
  // Angular
  'bypassSecurityTrustHtml': /bypassSecurityTrust(?:Html|Script|Url|ResourceUrl)/g,
  
  // Vue
  'v-html': /v-html\s*=/g,
  
  // Template engines (server-side)
  'render_template_string': /render_template_string\s*\(/g,
  'Jinja2': /Template\s*\([^)]*\)\s*\.\s*render\s*\(/g,
  
  // PHP
  'echo': /echo\s+\$_(?:GET|POST|REQUEST)/g,
  'print': /print\s+\$_(?:GET|POST|REQUEST)/g
} as const;

/**
 * Path Traversal sinks
 */
export const PATH_TRAVERSAL_SINKS = {
  // JavaScript
  'readFile': /(?:fs\s*\.\s*)?read(?:File|FileSync)\s*\(/g,
  'writeFile': /(?:fs\s*\.\s*)?write(?:File|FileSync)\s*\(/g,
  'createReadStream': /(?:fs\s*\.\s*)?createReadStream\s*\(/g,
  'createWriteStream': /(?:fs\s*\.\s*)?createWriteStream\s*\(/g,
  'unlink': /(?:fs\s*\.\s*)?unlink(?:Sync)?\s*\(/g,
  'readdir': /(?:fs\s*\.\s*)?readdir(?:Sync)?\s*\(/g,
  'stat': /(?:fs\s*\.\s*)?stat(?:Sync)?\s*\(/g,
  'access': /(?:fs\s*\.\s*)?access(?:Sync)?\s*\(/g,
  'sendFile': /\.sendFile\s*\(/g,
  'download': /\.download\s*\(/g,
  'res.render': /res\s*\.\s*render\s*\(/g,
  
  // Python
  'open': /\bopen\s*\(/g,
  'os.path.join': /os\s*\.\s*path\s*\.\s*join\s*\(/g,
  'shutil': /shutil\s*\.\s*(?:copy|move|rmtree)\s*\(/g,
  'send_file': /send_file\s*\(/g,
  
  // PHP
  'include': /\b(?:include|include_once|require|require_once)\s*[\s(]/g,
  'file_get_contents': /file_get_contents\s*\(/g,
  'file_put_contents': /file_put_contents\s*\(/g,
  'fopen': /fopen\s*\(/g,
  'readfile': /readfile\s*\(/g,
  'file': /\bfile\s*\(/g,
  
  // Java
  'FileInputStream': /new\s+FileInputStream\s*\(/g,
  'FileOutputStream': /new\s+FileOutputStream\s*\(/g,
  'FileReader': /new\s+FileReader\s*\(/g,
  'Files.read': /Files\s*\.\s*read(?:AllBytes|AllLines|String)\s*\(/g,
  
  // C#
  'File.Read': /File\s*\.\s*Read(?:AllText|AllBytes|AllLines)\s*\(/g,
  'File.Write': /File\s*\.\s*Write(?:AllText|AllBytes|AllLines)\s*\(/g,
  'StreamReader': /new\s+StreamReader\s*\(/g
} as const;

/**
 * SSRF sinks
 */
export const SSRF_SINKS = {
  // JavaScript
  'fetch': /\bfetch\s*\(/g,
  'axios': /axios\s*\.(?:get|post|put|delete|patch|request)\s*\(/g,
  'request': /\brequest\s*\(/g,
  'http.request': /https?\s*\.\s*(?:get|request)\s*\(/g,
  'got': /\bgot\s*\(/g,
  'node-fetch': /\bfetch\s*\(/g,
  
  // Python
  'requests': /requests\s*\.(?:get|post|put|delete|patch)\s*\(/g,
  'urllib': /urllib\s*\.\s*(?:request\s*\.\s*)?(?:urlopen|Request)\s*\(/g,
  'httplib': /http\.client\s*\.\s*HTTPConnection\s*\(/g,
  'aiohttp': /aiohttp\s*\.\s*(?:ClientSession|request)\s*\(/g,
  
  // PHP
  'curl': /curl_(?:exec|init|setopt)\s*\(/g,
  'file_get_contents': /file_get_contents\s*\(\s*\$/g,
  'fopen_url': /fopen\s*\(\s*['"]https?:/g,
  
  // Java
  'URL.openConnection': /(?:URL|URI)\s*\.\s*open(?:Connection|Stream)\s*\(/g,
  'HttpClient_java': /HttpClient\s*\.(?:newHttpClient|send)\s*\(/g,
  'RestTemplate': /RestTemplate\s*\.(?:getForObject|postForObject|exchange)\s*\(/g,
  
  // C#
  'HttpClient_csharp': /HttpClient\s*\.(?:GetAsync|PostAsync|SendAsync)\s*\(/g,
  'WebRequest': /WebRequest\s*\.Create\s*\(/g,
  'WebClient': /WebClient\s*\.(?:Download|Upload)(?:String|Data|File)\s*\(/g
} as const;

/**
 * Deserialization sinks
 */
export const DESERIALIZATION_SINKS = {
  // JavaScript
  'JSON.parse': /JSON\s*\.\s*parse\s*\(/g,
  'eval': /\beval\s*\(/g,
  'Function': /new\s+Function\s*\(/g,
  'deserialize': /deserialize\s*\(/g,
  'js_unserialize': /unserialize\s*\(/g,
  
  // Python
  'pickle': /pickle\s*\.(?:load|loads)\s*\(/g,
  'yaml.load': /yaml\s*\.\s*(?:load|unsafe_load)\s*\(/g,
  'marshal': /marshal\s*\.(?:load|loads)\s*\(/g,
  'shelve': /shelve\s*\.\s*open\s*\(/g,
  
  // PHP
  'php_unserialize': /\bunserialize\s*\(/g,
  
  // Java
  'ObjectInputStream': /ObjectInputStream\s*\.readObject\s*\(/g,
  'XMLDecoder': /XMLDecoder\s*\.readObject\s*\(/g,
  'XStream': /XStream\s*\.fromXML\s*\(/g,
  
  // C#
  'BinaryFormatter': /BinaryFormatter\s*\.Deserialize\s*\(/g,
  'XmlSerializer': /XmlSerializer\s*\.Deserialize\s*\(/g,
  'JsonConvert': /JsonConvert\s*\.DeserializeObject\s*\(/g,
  'DataContractSerializer': /DataContractSerializer\s*\.ReadObject\s*\(/g
} as const;

// ============================================================================
// SANITIZERS
// ============================================================================

/**
 * Common sanitizers for SQL Injection
 */
export const SQL_SANITIZERS = {
  'parameterized': /\?\s*,|:\w+|@\w+|\$\d+/g,
  'preparedStatement': /prepare(?:d)?(?:Statement)?\s*\(/gi,
  'escape': /escape(?:String|Id|Literal)?\s*\(/gi,
  'quote': /quote\s*\(/gi,
  'sanitize': /sanitize\s*\(/gi,
  'bindParam': /bind(?:Param|Value)\s*\(/gi,
  'placeholders': /%s|%d|\?\?/g
} as const;

/**
 * Common sanitizers for XSS
 */
export const XSS_SANITIZERS = {
  'htmlEncode': /(?:html)?(?:encode|escape|entities)\s*\(/gi,
  'sanitizeHtml': /sanitize(?:Html)?\s*\(/gi,
  'DOMPurify': /DOMPurify\s*\.\s*sanitize\s*\(/g,
  'escapeHtml': /escapeHtml\s*\(/gi,
  'textContent': /\.textContent\s*=/g,
  'createTextNode': /createTextNode\s*\(/g,
  'encodeURIComponent': /encodeURIComponent\s*\(/g,
  'htmlspecialchars': /htmlspecialchars\s*\(/g,
  'strip_tags': /strip_tags\s*\(/g,
  'bleach': /bleach\s*\.\s*clean\s*\(/g
} as const;

/**
 * Common sanitizers for Command Injection
 */
export const COMMAND_SANITIZERS = {
  'escapeshellarg': /escapeshellarg\s*\(/g,
  'escapeshellcmd': /escapeshellcmd\s*\(/g,
  'shlex.quote': /shlex\s*\.\s*quote\s*\(/g,
  'shellescape': /shellescape\s*\(/gi,
  'ProcessBuilder': /new\s+ProcessBuilder\s*\(\s*\[/g // Array form is safer
} as const;

/**
 * Common sanitizers for Path Traversal
 */
export const PATH_SANITIZERS = {
  'basename': /(?:path\s*\.\s*)?basename\s*\(/gi,
  'normalize': /(?:path\s*\.\s*)?normalize\s*\(/gi,
  'realpath': /realpath\s*\(/gi,
  'resolve': /(?:path\s*\.\s*)?resolve\s*\(/gi,
  'isAbsolute': /(?:path\s*\.\s*)?isAbsolute\s*\(/gi,
  'startsWith': /\.startsWith\s*\(/g,
  'includes': /\.includes\s*\(\s*['"`]\.\.['"`]\s*\)/g
} as const;

// ============================================================================
// SECURITY STANDARD REFERENCES
// ============================================================================

/**
 * OWASP Top 10 2021 mapping
 */
export const OWASP_TOP_10_2021 = {
  A01: { id: 'A01:2021', name: 'Broken Access Control', url: 'https://owasp.org/Top10/A01_2021-Broken_Access_Control/' },
  A02: { id: 'A02:2021', name: 'Cryptographic Failures', url: 'https://owasp.org/Top10/A02_2021-Cryptographic_Failures/' },
  A03: { id: 'A03:2021', name: 'Injection', url: 'https://owasp.org/Top10/A03_2021-Injection/' },
  A04: { id: 'A04:2021', name: 'Insecure Design', url: 'https://owasp.org/Top10/A04_2021-Insecure_Design/' },
  A05: { id: 'A05:2021', name: 'Security Misconfiguration', url: 'https://owasp.org/Top10/A05_2021-Security_Misconfiguration/' },
  A06: { id: 'A06:2021', name: 'Vulnerable and Outdated Components', url: 'https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/' },
  A07: { id: 'A07:2021', name: 'Identification and Authentication Failures', url: 'https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/' },
  A08: { id: 'A08:2021', name: 'Software and Data Integrity Failures', url: 'https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/' },
  A09: { id: 'A09:2021', name: 'Security Logging and Monitoring Failures', url: 'https://owasp.org/Top10/A09_2021-Security_Logging_and_Monitoring_Failures/' },
  A10: { id: 'A10:2021', name: 'Server-Side Request Forgery (SSRF)', url: 'https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/' }
} as const;

/**
 * Common CWE references
 */
export const CWE_REFERENCES = {
  // Injection
  CWE_89: { id: 'CWE-89', title: 'SQL Injection', url: 'https://cwe.mitre.org/data/definitions/89.html' },
  CWE_78: { id: 'CWE-78', title: 'OS Command Injection', url: 'https://cwe.mitre.org/data/definitions/78.html' },
  CWE_79: { id: 'CWE-79', title: 'Cross-site Scripting (XSS)', url: 'https://cwe.mitre.org/data/definitions/79.html' },
  CWE_94: { id: 'CWE-94', title: 'Code Injection', url: 'https://cwe.mitre.org/data/definitions/94.html' },
  CWE_90: { id: 'CWE-90', title: 'LDAP Injection', url: 'https://cwe.mitre.org/data/definitions/90.html' },
  CWE_91: { id: 'CWE-91', title: 'XML Injection', url: 'https://cwe.mitre.org/data/definitions/91.html' },
  
  // XSS subtypes
  CWE_80: { id: 'CWE-80', title: 'Improper Neutralization of Script-Related HTML Tags', url: 'https://cwe.mitre.org/data/definitions/80.html' },
  
  // Request Forgery
  CWE_352: { id: 'CWE-352', title: 'Cross-Site Request Forgery (CSRF)', url: 'https://cwe.mitre.org/data/definitions/352.html' },
  CWE_918: { id: 'CWE-918', title: 'Server-Side Request Forgery (SSRF)', url: 'https://cwe.mitre.org/data/definitions/918.html' },
  
  // Deserialization
  CWE_502: { id: 'CWE-502', title: 'Deserialization of Untrusted Data', url: 'https://cwe.mitre.org/data/definitions/502.html' },
  CWE_1321: { id: 'CWE-1321', title: 'Prototype Pollution', url: 'https://cwe.mitre.org/data/definitions/1321.html' },
  
  // File Handling
  CWE_22: { id: 'CWE-22', title: 'Path Traversal', url: 'https://cwe.mitre.org/data/definitions/22.html' },
  CWE_434: { id: 'CWE-434', title: 'Unrestricted Upload of File with Dangerous Type', url: 'https://cwe.mitre.org/data/definitions/434.html' },
  CWE_73: { id: 'CWE-73', title: 'External Control of File Name or Path', url: 'https://cwe.mitre.org/data/definitions/73.html' },
  CWE_98: { id: 'CWE-98', title: 'Improper Control of Filename for Include/Require Statement', url: 'https://cwe.mitre.org/data/definitions/98.html' },
  
  // Authentication
  CWE_798: { id: 'CWE-798', title: 'Use of Hard-coded Credentials', url: 'https://cwe.mitre.org/data/definitions/798.html' },
  CWE_287: { id: 'CWE-287', title: 'Improper Authentication', url: 'https://cwe.mitre.org/data/definitions/287.html' },
  CWE_384: { id: 'CWE-384', title: 'Session Fixation', url: 'https://cwe.mitre.org/data/definitions/384.html' },
  CWE_613: { id: 'CWE-613', title: 'Insufficient Session Expiration', url: 'https://cwe.mitre.org/data/definitions/613.html' },
  CWE_259: { id: 'CWE-259', title: 'Use of Hard-coded Password', url: 'https://cwe.mitre.org/data/definitions/259.html' },
  CWE_306: { id: 'CWE-306', title: 'Missing Authentication for Critical Function', url: 'https://cwe.mitre.org/data/definitions/306.html' },
  CWE_862: { id: 'CWE-862', title: 'Missing Authorization', url: 'https://cwe.mitre.org/data/definitions/862.html' },
  CWE_614: { id: 'CWE-614', title: 'Sensitive Cookie in HTTPS Session Without Secure Attribute', url: 'https://cwe.mitre.org/data/definitions/614.html' },
  CWE_1004: { id: 'CWE-1004', title: 'Sensitive Cookie Without HttpOnly Flag', url: 'https://cwe.mitre.org/data/definitions/1004.html' },
  CWE_347: { id: 'CWE-347', title: 'Improper Verification of Cryptographic Signature', url: 'https://cwe.mitre.org/data/definitions/347.html' },
  CWE_916: { id: 'CWE-916', title: 'Use of Password Hash With Insufficient Computational Effort', url: 'https://cwe.mitre.org/data/definitions/916.html' },
  CWE_208: { id: 'CWE-208', title: 'Observable Timing Discrepancy', url: 'https://cwe.mitre.org/data/definitions/208.html' },
  
  // Cryptography
  CWE_327: { id: 'CWE-327', title: 'Use of a Broken or Risky Cryptographic Algorithm', url: 'https://cwe.mitre.org/data/definitions/327.html' },
  CWE_328: { id: 'CWE-328', title: 'Reversible One-Way Hash', url: 'https://cwe.mitre.org/data/definitions/328.html' },
  CWE_330: { id: 'CWE-330', title: 'Use of Insufficiently Random Values', url: 'https://cwe.mitre.org/data/definitions/330.html' },
  CWE_326: { id: 'CWE-326', title: 'Inadequate Encryption Strength', url: 'https://cwe.mitre.org/data/definitions/326.html' },
  CWE_321: { id: 'CWE-321', title: 'Use of Hard-coded Cryptographic Key', url: 'https://cwe.mitre.org/data/definitions/321.html' },
  CWE_295: { id: 'CWE-295', title: 'Improper Certificate Validation', url: 'https://cwe.mitre.org/data/definitions/295.html' },
  
  // Access Control
  CWE_284: { id: 'CWE-284', title: 'Improper Access Control', url: 'https://cwe.mitre.org/data/definitions/284.html' },
  CWE_639: { id: 'CWE-639', title: 'Authorization Bypass Through User-Controlled Key', url: 'https://cwe.mitre.org/data/definitions/639.html' },
  
  // Information Disclosure
  CWE_200: { id: 'CWE-200', title: 'Exposure of Sensitive Information', url: 'https://cwe.mitre.org/data/definitions/200.html' },
  CWE_209: { id: 'CWE-209', title: 'Generation of Error Message Containing Sensitive Information', url: 'https://cwe.mitre.org/data/definitions/209.html' },
  CWE_532: { id: 'CWE-532', title: 'Insertion of Sensitive Information into Log File', url: 'https://cwe.mitre.org/data/definitions/532.html' },
  
  // Configuration
  CWE_16: { id: 'CWE-16', title: 'Configuration', url: 'https://cwe.mitre.org/data/definitions/16.html' },
  CWE_942: { id: 'CWE-942', title: 'Permissive Cross-domain Policy with Untrusted Domains', url: 'https://cwe.mitre.org/data/definitions/942.html' },
  CWE_489: { id: 'CWE-489', title: 'Active Debug Code', url: 'https://cwe.mitre.org/data/definitions/489.html' },
  CWE_693: { id: 'CWE-693', title: 'Protection Mechanism Failure', url: 'https://cwe.mitre.org/data/definitions/693.html' }
} as const;

// ============================================================================
// PATTERN COLLECTIONS
// ============================================================================

/**
 * Hardcoded secrets patterns
 */
export const HARDCODED_SECRETS_PATTERNS = {
  // API Keys
  aws_access_key: /(?:AWS|aws)?[_-]?(?:ACCESS|access)?[_-]?KEY[_-]?ID\s*[=:]\s*['"]?[A-Z0-9]{20}['"]?/g,
  aws_secret_key: /(?:AWS|aws)?[_-]?SECRET[_-]?(?:ACCESS)?[_-]?KEY\s*[=:]\s*['"]?[A-Za-z0-9/+=]{40}['"]?/g,
  generic_api_key: /(?:api[_-]?key|apikey|api_secret)\s*[=:]\s*['"][a-zA-Z0-9_\-]{16,}['"]/gi,
  github_token: /(?:gh[pousr]|github)[_-]?(?:token|pat|key)\s*[=:]\s*['"]?[a-zA-Z0-9_]{36,}['"]?/gi,
  slack_token: /xox[baprs]-[0-9]{10,}-[a-zA-Z0-9-]+/g,
  stripe_key: /(?:sk|pk)_(?:test|live)_[a-zA-Z0-9]{24,}/g,
  
  // Passwords
  password_assignment: /(?:password|passwd|pwd|secret)\s*[=:]\s*['"][^'"]{8,}['"]/gi,
  
  // Private keys
  private_key: /-----BEGIN\s+(?:RSA|DSA|EC|OPENSSH|ENCRYPTED)?\s*PRIVATE\s+KEY-----/g,
  
  // Connection strings
  connection_string: /(?:mongodb|postgres|mysql|redis):\/\/[^:]+:[^@]+@[^\s'"]+/gi,
  
  // JWT secrets
  jwt_secret: /(?:jwt[_-]?secret|secret[_-]?key)\s*[=:]\s*['"][a-zA-Z0-9_\-]{16,}['"]/gi
} as const;

/**
 * Dangerous function patterns
 */
export const DANGEROUS_FUNCTIONS = {
  // JavaScript/TypeScript
  eval: /\beval\s*\(/g,
  function_constructor: /new\s+Function\s*\(/g,
  settimeout_string: /setTimeout\s*\(\s*['"`]/g,
  setinterval_string: /setInterval\s*\(\s*['"`]/g,
  
  // PHP
  php_eval: /\beval\s*\(\s*\$/g,
  php_create_function: /create_function\s*\(/g,
  php_assert: /\bassert\s*\(\s*\$/g,
  php_preg_replace_e: /preg_replace\s*\(\s*['"].*\/e['"]/g,
  
  // Python
  python_eval: /\beval\s*\(/g,
  python_exec: /\bexec\s*\(/g,
  python_compile: /\bcompile\s*\(/g
} as const;

/**
 * Weak cryptography patterns
 */
export const WEAK_CRYPTO_PATTERNS = {
  // Weak algorithms
  md5: /\bMD5\b|\.md5\s*\(|hashlib\.md5/gi,
  sha1: /\bSHA1\b|\.sha1\s*\(|hashlib\.sha1|SHA-1/gi,
  des: /\bDES\b|DESede|TripleDES/gi,
  rc4: /\bRC4\b|ARCFOUR/gi,
  
  // Weak modes
  ecb_mode: /ECB|MODE_ECB/gi,
  
  // Weak random
  math_random: /Math\.random\s*\(\)/g,
  random_random: /random\.random\s*\(\)/g,
  rand_function: /\brand\s*\(\s*\)/g
} as const;
