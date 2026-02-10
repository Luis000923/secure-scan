/**
 * Common Utility Patterns and Functions
 * Shared across all language analyzers
 */

import { Severity, Finding, SecurityStandard } from '../../../types';

/**
 * Common dangerous functions by language
 */
export const DANGEROUS_FUNCTIONS: Record<string, Array<{
  pattern: RegExp;
  name: string;
  severity: Severity;
  description: string;
  recommendation: string;
  cwe: string;
}>> = {
  python: [
    {
      pattern: /pickle\.(?:loads?|dumps?)\s*\(/gi,
      name: 'Deserialización Insegura (pickle)',
      severity: Severity.HIGH,
      description: 'pickle puede ejecutar código arbitrario durante la deserialización.',
      recommendation: 'Use JSON u otros formatos seguros para datos no confiables.',
      cwe: 'CWE-502',
    },
    {
      pattern: /yaml\.(?:load|unsafe_load)\s*\(/gi,
      name: 'Carga de YAML Insegura',
      severity: Severity.HIGH,
      description: 'yaml.load puede ejecutar código arbitrario.',
      recommendation: 'Use yaml.safe_load() en su lugar.',
      cwe: 'CWE-502',
    },
    {
      pattern: /marshal\.loads?\s*\(/gi,
      name: 'Deserialización Insegura (marshal)',
      severity: Severity.HIGH,
      description: 'marshal no es seguro contra datos maliciosos.',
      recommendation: 'Use JSON o pickle con verificación hmac.',
      cwe: 'CWE-502',
    },
    {
      pattern: /shelve\.open\s*\(/gi,
      name: 'Deserialización Insegura (shelve)',
      severity: Severity.MEDIUM,
      description: 'shelve utiliza pickle internamente.',
      recommendation: 'Evite shelve con fuentes de datos no confiables.',
      cwe: 'CWE-502',
    },
    {
      pattern: /\bassert\b/gi,
      name: 'Assert en Producción',
      severity: Severity.LOW,
      description: 'Las aserciones se pueden desactivar con el flag -O.',
      recommendation: 'Use un manejo de errores adecuado en lugar de assert.',
      cwe: 'CWE-617',
    },
  ],

  java: [
    {
      pattern: /ObjectInputStream\s*\(/gi,
      name: 'Deserialización Insegura',
      severity: Severity.HIGH,
      description: 'La deserialización de Java puede conducir a RCE.',
      recommendation: 'Use ObjectInputFilter o evite la serialización de Java.',
      cwe: 'CWE-502',
    },
    {
      pattern: /XMLDecoder\s*\(/gi,
      name: 'Deserialización XML Insegura',
      severity: Severity.CRITICAL,
      description: 'XMLDecoder puede ejecutar código arbitrario.',
      recommendation: 'Evite XMLDecoder, use alternativas más seguras.',
      cwe: 'CWE-502',
    },
    {
      pattern: /readObject\s*\(\s*\)/gi,
      name: 'Deserialización Insegura (readObject)',
      severity: Severity.HIGH,
      description: 'readObject en datos no confiables puede conducir a RCE.',
      recommendation: 'Valide los flujos de entrada, use deserialización look-ahead.',
      cwe: 'CWE-502',
    },
  ],

  csharp: [
    {
      pattern: /BinaryFormatter\.Deserialize/gi,
      name: 'Deserialización Insegura (BinaryFormatter)',
      severity: Severity.CRITICAL,
      description: 'BinaryFormatter es inseguro y está deprecado.',
      recommendation: 'Use System.Text.Json o DataContractSerializer.',
      cwe: 'CWE-502',
    },
    {
      pattern: /JavaScriptSerializer\s*\(\s*\)\.Deserialize/gi,
      name: 'Deserialización Insegura (JavaScriptSerializer)',
      severity: Severity.HIGH,
      description: 'JavaScriptSerializer con manejo de tipos es vulnerable.',
      recommendation: 'Use System.Text.Json con manejo estricto de tipos.',
      cwe: 'CWE-502',
    },
    {
      pattern: /TypeNameHandling\s*=\s*TypeNameHandling\.(?:All|Auto|Objects|Arrays)/gi,
      name: 'Deserialización JSON Insegura (Newtonsoft)',
      severity: Severity.CRITICAL,
      description: 'TypeNameHandling permite ataques de tipos.',
      recommendation: 'Use TypeNameHandling.None o un SerializationBinder personalizado.',
      cwe: 'CWE-502',
    },
  ],

  php: [
    {
      pattern: /unserialize\s*\(/gi,
      name: 'Deserialización Insegura (unserialize)',
      severity: Severity.HIGH,
      description: 'unserialize en la entrada del usuario puede conducir a la ejecución de código.',
      recommendation: 'Use JSON o especifique el parámetro allowed_classes.',
      cwe: 'CWE-502',
    },
    {
      pattern: /\b(eval|assert)\s*\(\s*\$/gi,
      name: 'Inyección de Código',
      severity: Severity.CRITICAL,
      description: 'eval/assert con entrada del usuario ejecuta código arbitrario.',
      recommendation: 'Evite eval/assert por completo.',
      cwe: 'CWE-94',
    },
    {
      pattern: /preg_replace\s*\([^,]*\/[^\/]*e[^\/]*\//gi,
      name: 'Inyección de Código (preg_replace /e)',
      severity: Severity.CRITICAL,
      description: 'preg_replace con el modificador /e ejecuta código.',
      recommendation: 'Use preg_replace_callback en su lugar.',
      cwe: 'CWE-94',
    },
    {
      pattern: /extract\s*\(\s*\$(?:_GET|_POST|_REQUEST)/gi,
      name: 'Inyección de Variables (extract)',
      severity: Severity.HIGH,
      description: 'extract en superglobales puede sobrescribir variables.',
      recommendation: 'Acceda a los elementos del array directamente en su lugar.',
      cwe: 'CWE-621',
    },
  ],

  javascript: [
    {
      pattern: /JSON\.parse\s*\([^)]*\)/gi,
      name: 'Análisis de JSON',
      severity: Severity.INFO,
      description: 'Asegúrese de que JSON.parse tenga un manejo adecuado de errores.',
      recommendation: 'Envuélvalo en try-catch y valide la estructura.',
      cwe: 'CWE-20',
    },
    {
      pattern: /require\s*\(\s*[^"'`]/gi,
      name: 'Require Dinámico',
      severity: Severity.MEDIUM,
      description: 'El require dinámico puede cargar módulos maliciosos.',
      recommendation: 'Use importaciones estáticas o valide las rutas de los módulos.',
      cwe: 'CWE-829',
    },
    {
      pattern: /vm\.runIn(?:This|New)?Context\s*\(/gi,
      name: 'Riesgo de Escape de Sandbox',
      severity: Severity.HIGH,
      description: 'El módulo vm no es un sandbox de seguridad.',
      recommendation: 'Use isolated-vm para código no confiable.',
      cwe: 'CWE-265',
    },
  ],
};

/**
 * XXE (XML External Entity) patterns
 */
export const XXE_PATTERNS: Record<string, Array<{
  pattern: RegExp;
  name: string;
  severity: Severity;
  description: string;
  recommendation: string;
}>> = {
  python: [
    {
      pattern: /etree\.parse\s*\(/gi,
      name: 'XXE (ElementTree)',
      severity: Severity.HIGH,
      description: 'ElementTree may be vulnerable to XXE.',
      recommendation: 'Use defusedxml library instead.',
    },
    {
      pattern: /xml\.dom\.minidom\.parse/gi,
      name: 'XXE (minidom)',
      severity: Severity.HIGH,
      description: 'minidom is vulnerable to XXE.',
      recommendation: 'Use defusedxml.minidom instead.',
    },
    {
      pattern: /xml\.sax\.parse/gi,
      name: 'XXE (SAX)',
      severity: Severity.HIGH,
      description: 'xml.sax is vulnerable to XXE.',
      recommendation: 'Use defusedxml.sax instead.',
    },
    {
      pattern: /lxml\.etree\.parse\s*\([^)]*resolve_entities\s*=\s*True/gi,
      name: 'XXE (lxml entities)',
      severity: Severity.CRITICAL,
      description: 'lxml with resolve_entities=True is vulnerable.',
      recommendation: 'Set resolve_entities=False.',
    },
  ],

  java: [
    {
      pattern: /DocumentBuilderFactory\.newInstance\s*\(\s*\)(?!.*setFeature)/gi,
      name: 'XXE (DocumentBuilder)',
      severity: Severity.HIGH,
      description: 'DocumentBuilder without feature restrictions is vulnerable.',
      recommendation: 'Disable external entities and DTDs.',
    },
    {
      pattern: /SAXParserFactory\.newInstance\s*\(\s*\)(?!.*setFeature)/gi,
      name: 'XXE (SAXParser)',
      severity: Severity.HIGH,
      description: 'SAXParser without feature restrictions is vulnerable.',
      recommendation: 'Disable external entities and DTDs.',
    },
    {
      pattern: /XMLInputFactory\.newInstance\s*\(\s*\)(?!.*setProperty)/gi,
      name: 'XXE (StAX)',
      severity: Severity.HIGH,
      description: 'StAX parser without restrictions is vulnerable.',
      recommendation: 'Set IS_SUPPORTING_EXTERNAL_ENTITIES to false.',
    },
  ],

  csharp: [
    {
      pattern: /XmlReader\.Create\s*\([^)]*\)(?!.*XmlReaderSettings)/gi,
      name: 'XXE (XmlReader)',
      severity: Severity.MEDIUM,
      description: 'XmlReader may be vulnerable to XXE.',
      recommendation: 'Use XmlReaderSettings with DtdProcessing.Prohibit.',
    },
    {
      pattern: /new\s+XmlDocument\s*\(\s*\)/gi,
      name: 'XXE (XmlDocument)',
      severity: Severity.MEDIUM,
      description: 'XmlDocument may process DTDs by default.',
      recommendation: 'Set XmlResolver to null.',
    },
    {
      pattern: /DtdProcessing\s*=\s*DtdProcessing\.Parse/gi,
      name: 'XXE (DTD Processing)',
      severity: Severity.HIGH,
      description: 'DTD processing enabled.',
      recommendation: 'Use DtdProcessing.Prohibit.',
    },
  ],

  php: [
    {
      pattern: /simplexml_load_string\s*\([^)]*LIBXML_NOENT/gi,
      name: 'XXE (SimpleXML entities)',
      severity: Severity.CRITICAL,
      description: 'LIBXML_NOENT enables entity expansion.',
      recommendation: 'Remove LIBXML_NOENT flag.',
    },
    {
      pattern: /DOMDocument.*loadXML\s*\([^)]*\)(?!.*libxml_disable_entity_loader)/gi,
      name: 'XXE (DOMDocument)',
      severity: Severity.HIGH,
      description: 'DOMDocument may be vulnerable to XXE.',
      recommendation: 'Call libxml_disable_entity_loader(true) before parsing.',
    },
  ],
};

/**
 * SSRF (Server-Side Request Forgery) patterns
 */
export const SSRF_PATTERNS: Record<string, Array<{
  pattern: RegExp;
  name: string;
  severity: Severity;
  description: string;
  recommendation: string;
}>> = {
  python: [
    {
      pattern: /requests\.(?:get|post|put|delete|patch|head)\s*\(\s*(?:request\.|.*\+|f["'])/gi,
      name: 'SSRF (requests)',
      severity: Severity.HIGH,
      description: 'HTTP request with user-controlled URL.',
      recommendation: 'Validate URLs against allowlist of domains.',
    },
    {
      pattern: /urllib\.request\.urlopen\s*\(\s*(?:request\.|.*\+|f["'])/gi,
      name: 'SSRF (urllib)',
      severity: Severity.HIGH,
      description: 'urllib with user-controlled URL.',
      recommendation: 'Validate URLs and restrict to allowed hosts.',
    },
    {
      pattern: /httpx\.(?:get|post|put|delete)\s*\(\s*(?:request\.|.*\+|f["'])/gi,
      name: 'SSRF (httpx)',
      severity: Severity.HIGH,
      description: 'httpx request with user-controlled URL.',
      recommendation: 'Validate URLs against allowlist.',
    },
  ],

  java: [
    {
      pattern: /new\s+URL\s*\(\s*(?:request\.getParameter|.*\+)/gi,
      name: 'SSRF (URL)',
      severity: Severity.HIGH,
      description: 'URL from user input.',
      recommendation: 'Validate against allowlist of hosts.',
    },
    {
      pattern: /HttpClient.*\.send\s*\(/gi,
      name: 'SSRF (HttpClient)',
      severity: Severity.MEDIUM,
      description: 'Check HttpClient target URL source.',
      recommendation: 'Validate request URLs.',
    },
  ],

  php: [
    {
      pattern: /curl_setopt\s*\([^,]+,\s*CURLOPT_URL\s*,\s*\$/gi,
      name: 'SSRF (cURL)',
      severity: Severity.HIGH,
      description: 'cURL with user-controlled URL.',
      recommendation: 'Validate URLs against allowlist.',
    },
    {
      pattern: /file_get_contents\s*\(\s*["']https?:\/\/.*\$/gi,
      name: 'SSRF (file_get_contents)',
      severity: Severity.HIGH,
      description: 'HTTP request with user-controlled URL.',
      recommendation: 'Validate URLs against allowlist.',
    },
  ],

  javascript: [
    {
      pattern: /fetch\s*\(\s*(?:req\.|`[^`]*\$\{|.*\+)/gi,
      name: 'SSRF (fetch)',
      severity: Severity.HIGH,
      description: 'fetch with user-controlled URL.',
      recommendation: 'Validate URLs against allowlist.',
    },
    {
      pattern: /axios\.(?:get|post|put|delete)\s*\(\s*(?:req\.|`[^`]*\$\{|.*\+)/gi,
      name: 'SSRF (axios)',
      severity: Severity.HIGH,
      description: 'axios with user-controlled URL.',
      recommendation: 'Validate URLs against allowlist.',
    },
    {
      pattern: /http\.request\s*\(\s*(?:req\.|`[^`]*\$\{|.*\+)/gi,
      name: 'SSRF (http.request)',
      severity: Severity.HIGH,
      description: 'HTTP request with user-controlled options.',
      recommendation: 'Validate host and port.',
    },
  ],
};

/**
 * Java-specific JNDI injection patterns (Log4Shell, etc.)
 */
export const JNDI_PATTERNS: Array<{
  pattern: RegExp;
  name: string;
  severity: Severity;
  description: string;
  recommendation: string;
}> = [
    {
      pattern: /InitialContext\s*\(\s*\)\.lookup\s*\(\s*(?:request\.|.*\+)/gi,
      name: 'Inyección JNDI',
      severity: Severity.CRITICAL,
      description: 'La búsqueda JNDI con entrada controlada por el usuario permite RCE.',
      recommendation: 'Nunca pase la entrada de usuario a la búsqueda JNDI.',
    },
    {
      pattern: /ctx\.lookup\s*\(\s*(?:request\.|.*\+)/gi,
      name: 'Inyección JNDI (Contexto)',
      severity: Severity.CRITICAL,
      description: 'Búsqueda JNDI con entrada controlada por el usuario.',
      recommendation: 'Valide y sanitice los nombres JNDI.',
    },
    {
      pattern: /logger\.(?:info|warn|error|debug|trace|fatal)\s*\(\s*(?:request\.|.*\+.*request\.)/gi,
      name: 'Inyección de Log (Log4Shell potencial)',
      severity: Severity.HIGH,
      description: 'Registrar la entrada del usuario puede habilitar Log4Shell (CVE-2021-44228).',
      recommendation: 'Actualice Log4j a 2.17+, sanitice los datos registrados.',
    },
    {
      pattern: /\$\{jndi:/gi,
      name: 'Cadena de Búsqueda JNDI',
      severity: Severity.CRITICAL,
      description: 'Se detectó un patrón de búsqueda JNDI (indicador de Log4Shell).',
      recommendation: 'Elimine las búsquedas JNDI, actualice Log4j.',
    },
  ];

/**
 * Race Condition patterns by language (CWE-362, CWE-367)
 */
export const RACE_CONDITION_PATTERNS: Record<string, Array<{
  pattern: RegExp;
  name: string;
  severity: Severity;
  description: string;
  recommendation: string;
  cwe: string;
}>> = {
  python: [
    {
      pattern: /if\s+os\.path\.exists\s*\([^)]+\)\s*:[\s\S]*?open\s*\(/gi,
      name: 'TOCTOU Race Condition (file exists)',
      severity: Severity.MEDIUM,
      description: 'Time-of-check to time-of-use race condition on file.',
      recommendation: 'Use try/except with atomic operations instead.',
      cwe: 'CWE-367',
    },
    {
      pattern: /if\s+not\s+os\.path\.exists\s*\([^)]+\)\s*:[\s\S]*?os\.makedirs?\s*\(/gi,
      name: 'TOCTOU Race Condition (makedirs)',
      severity: Severity.MEDIUM,
      description: 'Race condition between exists check and directory creation.',
      recommendation: 'Use os.makedirs with exist_ok=True.',
      cwe: 'CWE-367',
    },
    {
      pattern: /threading\.Thread\s*\([^)]*\)(?![\s\S]*?(?:Lock|Semaphore|RLock|Condition))/gi,
      name: 'Thread without Synchronization',
      severity: Severity.MEDIUM,
      description: 'Thread created without apparent synchronization primitive.',
      recommendation: 'Use threading.Lock or other synchronization.',
      cwe: 'CWE-362',
    },
    {
      pattern: /multiprocessing\.(?:Pool|Process)\s*\([^)]*shared/gi,
      name: 'Shared State in Multiprocessing',
      severity: Severity.MEDIUM,
      description: 'Shared state in multiprocessing may cause race conditions.',
      recommendation: 'Use multiprocessing.Manager or Queue for safe sharing.',
      cwe: 'CWE-362',
    },
  ],

  java: [
    {
      pattern: /new\s+File\s*\([^)]+\)\.exists\s*\(\s*\)[\s\S]*?new\s+FileOutputStream/gi,
      name: 'TOCTOU Race Condition (file)',
      severity: Severity.MEDIUM,
      description: 'Race condition between existence check and file access.',
      recommendation: 'Use atomic file operations or Files.createFile().',
      cwe: 'CWE-367',
    },
    {
      pattern: /if\s*\(\s*!\s*\w+\.exists\s*\(\s*\)\s*\)\s*\{[\s\S]*?\.mkdirs?\s*\(\s*\)/gi,
      name: 'TOCTOU Race Condition (mkdir)',
      severity: Severity.MEDIUM,
      description: 'Race condition between check and directory creation.',
      recommendation: 'Use Files.createDirectories() which is atomic.',
      cwe: 'CWE-367',
    },
    {
      pattern: /(?<!synchronized\s)void\s+\w+\s*\([^)]*\)[\s\S]*?this\.\w+\s*(?:\+\+|--|\+=|-=)/gi,
      name: 'Unsynchronized Shared State',
      severity: Severity.MEDIUM,
      description: 'Instance field modified without synchronization.',
      recommendation: 'Use synchronized or AtomicInteger.',
      cwe: 'CWE-362',
    },
    {
      pattern: /HashMap\s*<[^>]+>\s*\w+\s*=\s*new\s+HashMap.*(?:Thread|Runnable)/gi,
      name: 'Non-Thread-Safe Collection',
      severity: Severity.MEDIUM,
      description: 'HashMap used in multi-threaded context.',
      recommendation: 'Use ConcurrentHashMap or Collections.synchronizedMap.',
      cwe: 'CWE-362',
    },
  ],

  javascript: [
    {
      pattern: /fs\.existsSync\s*\([^)]+\)[\s\S]*?fs\.(?:readFile|writeFile|unlink)/gi,
      name: 'TOCTOU Race Condition (fs)',
      severity: Severity.MEDIUM,
      description: 'Race condition between existence check and file operation.',
      recommendation: 'Use try/catch with direct operation instead.',
      cwe: 'CWE-367',
    },
    {
      pattern: /if\s*\(\s*!fs\.existsSync\s*\([^)]+\)\s*\)\s*\{[\s\S]*?fs\.mkdirSync/gi,
      name: 'TOCTOU Race Condition (mkdir)',
      severity: Severity.MEDIUM,
      description: 'Race condition in directory creation.',
      recommendation: 'Use fs.mkdirSync with { recursive: true }.',
      cwe: 'CWE-367',
    },
    {
      pattern: /(?:setInterval|setTimeout)\s*\(\s*(?:async\s*)?\([^)]*\)\s*=>\s*\{[\s\S]*?(?:await|\.then)/gi,
      name: 'Potential Async Race Condition',
      severity: Severity.LOW,
      description: 'Timer with async operations may have race conditions.',
      recommendation: 'Use proper synchronization or debouncing.',
      cwe: 'CWE-362',
    },
  ],

  csharp: [
    {
      pattern: /if\s*\(\s*!?File\.Exists\s*\([^)]+\)\s*\)[\s\S]*?File\.(?:Open|Create|Write|Read)/gi,
      name: 'TOCTOU Race Condition (File)',
      severity: Severity.MEDIUM,
      description: 'Race condition between existence check and file operation.',
      recommendation: 'Use try/catch with direct file operation.',
      cwe: 'CWE-367',
    },
    {
      pattern: /if\s*\(\s*!Directory\.Exists\s*\([^)]+\)\s*\)[\s\S]*?Directory\.Create/gi,
      name: 'TOCTOU Race Condition (Directory)',
      severity: Severity.MEDIUM,
      description: 'Race condition in directory creation.',
      recommendation: 'Use Directory.CreateDirectory which handles existence.',
      cwe: 'CWE-367',
    },
    {
      pattern: /static\s+\w+\s+\w+\s*(?:=|;)[\s\S]*?(?:Task|Thread|async)/gi,
      name: 'Static Field in Async Context',
      severity: Severity.MEDIUM,
      description: 'Static field may be shared across threads.',
      recommendation: 'Use AsyncLocal<T> or proper synchronization.',
      cwe: 'CWE-362',
    },
  ],

  php: [
    {
      pattern: /if\s*\(\s*!?file_exists\s*\([^)]+\)\s*\)\s*\{[\s\S]*?(?:fopen|file_put_contents|unlink)/gi,
      name: 'TOCTOU Race Condition',
      severity: Severity.MEDIUM,
      description: 'Race condition between file_exists and file operation.',
      recommendation: 'Use atomic operations or file locking.',
      cwe: 'CWE-367',
    },
    {
      pattern: /flock\s*\(\s*\$\w+\s*,\s*LOCK_(?:SH|EX)\s*\)\s*(?!.*LOCK_UN)/gi,
      name: 'File Lock Not Released',
      severity: Severity.LOW,
      description: 'File lock acquired but may not be released.',
      recommendation: 'Ensure flock with LOCK_UN is called.',
      cwe: 'CWE-667',
    },
  ],

  cpp: [
    {
      pattern: /if\s*\(\s*access\s*\([^)]+\)\s*==\s*0\s*\)[\s\S]*?open\s*\(/gi,
      name: 'TOCTOU Race Condition (access)',
      severity: Severity.HIGH,
      description: 'Race condition between access() check and open().',
      recommendation: 'Open file directly and check result.',
      cwe: 'CWE-367',
    },
    {
      pattern: /if\s*\(\s*stat\s*\([^)]+\)\s*==\s*0\s*\)[\s\S]*?(?:open|fopen|unlink)/gi,
      name: 'TOCTOU Race Condition (stat)',
      severity: Severity.HIGH,
      description: 'Race condition between stat() and file operation.',
      recommendation: 'Use atomic operations.',
      cwe: 'CWE-367',
    },
    {
      pattern: /pthread_create\s*\([^)]*\)(?![\s\S]*?pthread_mutex)/gi,
      name: 'Thread without Mutex',
      severity: Severity.MEDIUM,
      description: 'Thread created without apparent mutex usage.',
      recommendation: 'Use pthread_mutex for shared resources.',
      cwe: 'CWE-362',
    },
    {
      pattern: /std::thread\s*\([^)]*\)(?![\s\S]*?(?:std::mutex|std::lock_guard|std::unique_lock))/gi,
      name: 'Thread without Lock',
      severity: Severity.MEDIUM,
      description: 'std::thread without apparent locking.',
      recommendation: 'Use std::mutex with std::lock_guard.',
      cwe: 'CWE-362',
    },
  ],
};

/**
 * Integer Overflow patterns by language (CWE-190)
 */
export const INTEGER_OVERFLOW_PATTERNS: Record<string, Array<{
  pattern: RegExp;
  name: string;
  severity: Severity;
  description: string;
  recommendation: string;
  cwe: string;
}>> = {
  cpp: [
    {
      pattern: /\w+\s*\+\s*\w+\s*>\s*(?:INT_MAX|UINT_MAX|SIZE_MAX)/gi,
      name: 'Integer Overflow Check After Addition',
      severity: Severity.HIGH,
      description: 'Overflow check after addition is too late.',
      recommendation: 'Check before operation: if (a > INT_MAX - b).',
      cwe: 'CWE-190',
    },
    {
      pattern: /malloc\s*\(\s*\w+\s*\*\s*\w+\s*\)/gi,
      name: 'Integer Overflow in malloc',
      severity: Severity.HIGH,
      description: 'Multiplication in malloc may overflow.',
      recommendation: 'Use calloc() or check for overflow before multiply.',
      cwe: 'CWE-190',
    },
    {
      pattern: /new\s+\w+\s*\[\s*\w+\s*\*\s*\w+\s*\]/gi,
      name: 'Integer Overflow in new[]',
      severity: Severity.HIGH,
      description: 'Array size calculation may overflow.',
      recommendation: 'Validate size before allocation.',
      cwe: 'CWE-190',
    },
    {
      pattern: /\(\s*(?:int|short|char)\s*\)\s*\w+\s*(?:\*|\+)/gi,
      name: 'Integer Truncation',
      severity: Severity.MEDIUM,
      description: 'Cast to smaller type may cause truncation.',
      recommendation: 'Validate value fits in target type.',
      cwe: 'CWE-197',
    },
    {
      pattern: /(?:size_t|unsigned)\s+\w+\s*=\s*-/gi,
      name: 'Negative Value to Unsigned',
      severity: Severity.MEDIUM,
      description: 'Negative value assigned to unsigned type.',
      recommendation: 'Validate value is non-negative.',
      cwe: 'CWE-195',
    },
  ],

  java: [
    {
      pattern: /\(\s*int\s*\)\s*\w+\.\s*(?:length|size)\s*\(\s*\)\s*\*/gi,
      name: 'Integer Overflow in Size Calculation',
      severity: Severity.MEDIUM,
      description: 'Size multiplication may overflow int.',
      recommendation: 'Use Math.multiplyExact() or long arithmetic.',
      cwe: 'CWE-190',
    },
    {
      pattern: /new\s+byte\s*\[\s*\w+\s*\*\s*\w+\s*\]/gi,
      name: 'Integer Overflow in Array Allocation',
      severity: Severity.MEDIUM,
      description: 'Array size calculation may overflow.',
      recommendation: 'Use Math.multiplyExact() for size calculation.',
      cwe: 'CWE-190',
    },
  ],

  csharp: [
    {
      pattern: /new\s+byte\s*\[\s*\w+\s*\*\s*\w+\s*\]/gi,
      name: 'Integer Overflow in Array Allocation',
      severity: Severity.MEDIUM,
      description: 'Array size calculation may overflow.',
      recommendation: 'Use checked block or validate size.',
      cwe: 'CWE-190',
    },
    {
      pattern: /\(\s*int\s*\)\s*\w+\s*(?:\*|\+)/gi,
      name: 'Unchecked Integer Cast',
      severity: Severity.LOW,
      description: 'Cast without overflow checking.',
      recommendation: 'Use checked { } block for arithmetic.',
      cwe: 'CWE-190',
    },
  ],

  python: [
    // Python has arbitrary precision integers, but numpy/ctypes can overflow
    {
      pattern: /np\.(?:int8|int16|int32|uint8|uint16|uint32)\s*\(\s*\w+\s*\*\s*\w+\s*\)/gi,
      name: 'NumPy Integer Overflow',
      severity: Severity.MEDIUM,
      description: 'NumPy fixed-width integers can overflow.',
      recommendation: 'Use np.int64 or check bounds.',
      cwe: 'CWE-190',
    },
    {
      pattern: /ctypes\.c_(?:int|short|byte)\s*\(\s*\w+\s*\*\s*\w+\s*\)/gi,
      name: 'ctypes Integer Overflow',
      severity: Severity.MEDIUM,
      description: 'ctypes fixed-width integers can overflow.',
      recommendation: 'Validate values before creating ctypes integers.',
      cwe: 'CWE-190',
    },
  ],

  javascript: [
    {
      pattern: /\w+\s*<<\s*(?:[2-9][0-9]|[3-9][0-9])/gi,
      name: 'Bit Shift Overflow',
      severity: Severity.MEDIUM,
      description: 'Bit shift by large amount may cause unexpected results.',
      recommendation: 'Use BigInt for large values.',
      cwe: 'CWE-190',
    },
    {
      pattern: /Number\.MAX_SAFE_INTEGER\s*\+/gi,
      name: 'Integer Precision Loss',
      severity: Severity.MEDIUM,
      description: 'Operations beyond MAX_SAFE_INTEGER lose precision.',
      recommendation: 'Use BigInt for large integer arithmetic.',
      cwe: 'CWE-190',
    },
  ],
};

/**
 * Get all dangerous function patterns for a language
 */
export function getDangerousFunctionPatterns(language: string): Array<{
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

  // Add dangerous functions
  if (DANGEROUS_FUNCTIONS[language]) {
    patterns.push(...DANGEROUS_FUNCTIONS[language].map(p => ({
      pattern: p.pattern,
      name: p.name,
      severity: p.severity,
      description: p.description,
      recommendation: p.recommendation,
      category: 'Dangerous Function',
    })));
  }

  // Add XXE patterns
  if (XXE_PATTERNS[language]) {
    patterns.push(...XXE_PATTERNS[language].map(p => ({ ...p, category: 'XXE' })));
  }

  // Add SSRF patterns
  if (SSRF_PATTERNS[language]) {
    patterns.push(...SSRF_PATTERNS[language].map(p => ({ ...p, category: 'SSRF' })));
  }

  // Add JNDI patterns for Java
  if (language === 'java') {
    patterns.push(...JNDI_PATTERNS.map(p => ({ ...p, category: 'JNDI Injection' })));
  }

  // Add Race Condition patterns
  if (RACE_CONDITION_PATTERNS[language]) {
    patterns.push(...RACE_CONDITION_PATTERNS[language].map(p => ({ ...p, category: 'Race Condition' })));
  }

  // Add Integer Overflow patterns
  if (INTEGER_OVERFLOW_PATTERNS[language]) {
    patterns.push(...INTEGER_OVERFLOW_PATTERNS[language].map(p => ({ ...p, category: 'Integer Overflow' })));
  }

  return patterns;
}

/**
 * Calculate line number from character offset
 */
export function calculateLineNumber(content: string, offset: number): number {
  const lines = content.substring(0, offset).split('\n');
  return lines.length;
}

/**
 * Extract code context around a finding
 */
export function extractCodeContext(content: string, offset: number, contextLines: number = 2): string {
  const lines = content.split('\n');
  const lineNumber = calculateLineNumber(content, offset);
  const start = Math.max(0, lineNumber - contextLines - 1);
  const end = Math.min(lines.length, lineNumber + contextLines);
  return lines.slice(start, end).join('\n');
}

/**
 * Check if position is within a comment or string
 */
export function isInCommentOrString(content: string, offset: number, language: string): boolean {
  const before = content.substring(0, offset);

  // Simple heuristics - can be improved with proper parsing
  switch (language) {
    case 'python':
      // Check for single-line comment
      const pythonLine = before.split('\n').pop() || '';
      if (pythonLine.includes('#')) {
        const hashIndex = pythonLine.indexOf('#');
        const offsetInLine = pythonLine.length;
        if (hashIndex < offsetInLine) return true;
      }
      // Check for triple quotes (simplified)
      const tripleQuotes = (before.match(/"""/g) || []).length;
      if (tripleQuotes % 2 === 1) return true;
      break;

    case 'javascript':
    case 'typescript':
    case 'java':
    case 'csharp':
    case 'php':
    case 'c':
    case 'cpp':
      // Check for single-line comment
      const line = before.split('\n').pop() || '';
      if (line.includes('//')) {
        const commentIndex = line.indexOf('//');
        const offsetInLine = line.length;
        if (commentIndex < offsetInLine) return true;
      }
      // Check for multi-line comment (simplified)
      const openComments = (before.match(/\/\*/g) || []).length;
      const closeComments = (before.match(/\*\//g) || []).length;
      if (openComments > closeComments) return true;
      break;
  }

  return false;
}

/**
 * Normalize language name
 */
export function normalizeLanguage(language: string): string {
  const normalized = language.toLowerCase();
  const languageMap: Record<string, string> = {
    'js': 'javascript',
    'ts': 'typescript',
    'py': 'python',
    'rb': 'ruby',
    'cs': 'csharp',
    'c#': 'csharp',
    'c++': 'cpp',
    'cc': 'cpp',
    'cxx': 'cpp',
  };
  return languageMap[normalized] || normalized;
}

/**
 * Get common security standards based on category
 */
export function getSecurityStandards(category: string): SecurityStandard[] {
  const standards: Record<string, SecurityStandard[]> = {
    'Dangerous Function': [
      {
        name: 'CWE',
        id: 'CWE-676',
        title: 'Use of Potentially Dangerous Function',
        description: 'The program invokes a potentially dangerous function.',
        url: 'https://cwe.mitre.org/data/definitions/676.html'
      }
    ],
    'XXE': [
      {
        name: 'CWE',
        id: 'CWE-611',
        title: 'XML External Entity Reference',
        description: 'Improper Restriction of XML External Entity Reference.',
        url: 'https://cwe.mitre.org/data/definitions/611.html'
      },
      {
        name: 'OWASP',
        id: 'A05:2021',
        title: 'Security Misconfiguration',
        description: 'XXE is a form of security misconfiguration.',
        url: 'https://owasp.org/Top10/A05_2021-Security_Misconfiguration/'
      }
    ],
    'SSRF': [
      {
        name: 'CWE',
        id: 'CWE-918',
        title: 'Server-Side Request Forgery (SSRF)',
        description: 'The web server receives a URL and retrieves contents without validation.',
        url: 'https://cwe.mitre.org/data/definitions/918.html'
      },
      {
        name: 'OWASP',
        id: 'A10:2021',
        title: 'Server-Side Request Forgery',
        description: 'SSRF flaws occur when fetching a remote resource without validation.',
        url: 'https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_(SSRF)/'
      }
    ],
    'JNDI Injection': [
      {
        name: 'CWE',
        id: 'CWE-917',
        title: 'Expression Language Injection',
        description: 'Improper neutralization of special elements in expression language.',
        url: 'https://cwe.mitre.org/data/definitions/917.html'
      },
      {
        name: 'CVE',
        id: 'CVE-2021-44228',
        title: 'Log4Shell',
        description: 'Apache Log4j2 JNDI features allow remote code execution.',
        url: 'https://nvd.nist.gov/vuln/detail/CVE-2021-44228'
      }
    ],
    'Deserialization': [
      {
        name: 'CWE',
        id: 'CWE-502',
        title: 'Deserialization of Untrusted Data',
        description: 'The application deserializes untrusted data without verification.',
        url: 'https://cwe.mitre.org/data/definitions/502.html'
      },
      {
        name: 'OWASP',
        id: 'A08:2021',
        title: 'Software and Data Integrity Failures',
        description: 'Insecure deserialization is part of integrity failures.',
        url: 'https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/'
      }
    ],
    'Race Condition': [
      {
        name: 'CWE',
        id: 'CWE-362',
        title: 'Race Condition',
        description: 'Concurrent execution using shared resource with improper synchronization.',
        url: 'https://cwe.mitre.org/data/definitions/362.html'
      },
      {
        name: 'CWE',
        id: 'CWE-367',
        title: 'TOCTOU Race Condition',
        description: 'Time-of-check Time-of-use race condition.',
        url: 'https://cwe.mitre.org/data/definitions/367.html'
      }
    ],
    'Integer Overflow': [
      {
        name: 'CWE',
        id: 'CWE-190',
        title: 'Integer Overflow or Wraparound',
        description: 'Integer calculation produces value outside valid range.',
        url: 'https://cwe.mitre.org/data/definitions/190.html'
      },
      {
        name: 'CWE',
        id: 'CWE-197',
        title: 'Numeric Truncation Error',
        description: 'Truncation error when casting to smaller type.',
        url: 'https://cwe.mitre.org/data/definitions/197.html'
      }
    ],
  };

  return standards[category] || [];
}
