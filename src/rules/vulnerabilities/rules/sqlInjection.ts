/**
 * @fileoverview SQL Injection Detection Rules
 * @module rules/vulnerabilities/rules/sqlInjection
 * 
 * Comprehensive SQL injection detection for multiple languages and frameworks.
 * Detects string concatenation in SQL queries, unsafe query building, and
 * missing parameterized queries.
 */

import {
  VulnerabilityRule,
  VulnerabilityType,
  VulnerabilityCategory,
  VulnerabilitySeverity,
  ConfidenceLevel,
  SupportedLanguage,
  PatternType,
  TaintSource,
  TaintSink,
  TaintSanitizer
} from '../types';
import { OWASP_TOP_10_2021, CWE_REFERENCES } from '../constants';

// ============================================================================
// TAINT DEFINITIONS FOR SQL INJECTION
// ============================================================================

const sqlInjectionSources: TaintSource[] = [
  // JavaScript/Node.js
  { id: 'js-req-body', name: 'req.body', pattern: /req\.body(?:\.\w+|\[\s*['"`]\w+['"`]\s*\])?/g, languages: [SupportedLanguage.JAVASCRIPT, SupportedLanguage.TYPESCRIPT], category: 'user_input' },
  { id: 'js-req-query', name: 'req.query', pattern: /req\.query(?:\.\w+|\[\s*['"`]\w+['"`]\s*\])?/g, languages: [SupportedLanguage.JAVASCRIPT, SupportedLanguage.TYPESCRIPT], category: 'user_input' },
  { id: 'js-req-params', name: 'req.params', pattern: /req\.params(?:\.\w+|\[\s*['"`]\w+['"`]\s*\])?/g, languages: [SupportedLanguage.JAVASCRIPT, SupportedLanguage.TYPESCRIPT], category: 'user_input' },
  
  // Python/Flask/Django
  { id: 'py-request-args', name: 'request.args', pattern: /request\.args\.get\s*\([^)]+\)/g, languages: [SupportedLanguage.PYTHON], category: 'user_input' },
  { id: 'py-request-form', name: 'request.form', pattern: /request\.form\.get\s*\([^)]+\)/g, languages: [SupportedLanguage.PYTHON], category: 'user_input' },
  { id: 'py-request-json', name: 'request.json', pattern: /request\.(?:json|get_json\(\))(?:\.\w+|\[\s*['"`]\w+['"`]\s*\])?/g, languages: [SupportedLanguage.PYTHON], category: 'user_input' },
  
  // PHP
  { id: 'php-get', name: '$_GET', pattern: /\$_GET\s*\[\s*['"`][^'"`]+['"`]\s*\]/g, languages: [SupportedLanguage.PHP], category: 'user_input' },
  { id: 'php-post', name: '$_POST', pattern: /\$_POST\s*\[\s*['"`][^'"`]+['"`]\s*\]/g, languages: [SupportedLanguage.PHP], category: 'user_input' },
  { id: 'php-request', name: '$_REQUEST', pattern: /\$_REQUEST\s*\[\s*['"`][^'"`]+['"`]\s*\]/g, languages: [SupportedLanguage.PHP], category: 'user_input' },
  
  // Java
  { id: 'java-param', name: 'getParameter', pattern: /(?:request\.)?getParameter\s*\([^)]+\)/g, languages: [SupportedLanguage.JAVA], category: 'user_input' },
  { id: 'java-path-var', name: '@PathVariable', pattern: /@PathVariable(?:\s*\([^)]*\))?\s+\w+\s+\w+/g, languages: [SupportedLanguage.JAVA], category: 'user_input' },
  
  // C#
  { id: 'csharp-query', name: 'Request.QueryString', pattern: /Request\.QueryString\s*\[\s*['"`][^'"`]+['"`]\s*\]/g, languages: [SupportedLanguage.CSHARP], category: 'user_input' },
  { id: 'csharp-form', name: 'Request.Form', pattern: /Request\.Form\s*\[\s*['"`][^'"`]+['"`]\s*\]/g, languages: [SupportedLanguage.CSHARP], category: 'user_input' }
];

const sqlInjectionSinks: TaintSink[] = [
  // JavaScript
  { id: 'js-query', name: 'query()', pattern: /\.query\s*\(\s*['"`]|\.query\s*\(\s*\w+\s*\+/g, languages: [SupportedLanguage.JAVASCRIPT, SupportedLanguage.TYPESCRIPT], vulnerabilityType: VulnerabilityType.SQL_INJECTION },
  { id: 'js-raw', name: 'raw()', pattern: /\.raw\s*\(\s*['"`]|\.raw\s*\(\s*\w+/g, languages: [SupportedLanguage.JAVASCRIPT, SupportedLanguage.TYPESCRIPT], vulnerabilityType: VulnerabilityType.SQL_INJECTION },
  
  // Python
  { id: 'py-execute', name: 'cursor.execute', pattern: /cursor\.execute\s*\(\s*(?:f['"`]|['"`].*%|['"`].*\.format)/g, languages: [SupportedLanguage.PYTHON], vulnerabilityType: VulnerabilityType.SQL_INJECTION },
  { id: 'py-raw', name: 'raw()', pattern: /\.raw\s*\(\s*(?:f['"`]|['"`].*%)/g, languages: [SupportedLanguage.PYTHON], vulnerabilityType: VulnerabilityType.SQL_INJECTION },
  
  // PHP
  { id: 'php-query', name: 'mysql_query', pattern: /(?:mysql_query|mysqli_query|pg_query)\s*\(\s*(?:\$\w+\s*\.|\s*['"`].*\$)/g, languages: [SupportedLanguage.PHP], vulnerabilityType: VulnerabilityType.SQL_INJECTION },
  { id: 'php-pdo-query', name: 'PDO::query', pattern: /->query\s*\(\s*(?:\$\w+\s*\.|\s*['"`].*\$)/g, languages: [SupportedLanguage.PHP], vulnerabilityType: VulnerabilityType.SQL_INJECTION },
  
  // Java
  { id: 'java-statement', name: 'Statement.execute', pattern: /(?:execute(?:Query|Update)?)\s*\(\s*(?:\w+\s*\+|['"`].*\+)/g, languages: [SupportedLanguage.JAVA], vulnerabilityType: VulnerabilityType.SQL_INJECTION },
  { id: 'java-create-query', name: 'createQuery', pattern: /create(?:Native)?Query\s*\(\s*(?:\w+\s*\+|['"`].*\+)/g, languages: [SupportedLanguage.JAVA], vulnerabilityType: VulnerabilityType.SQL_INJECTION },
  
  // C#
  { id: 'csharp-command', name: 'SqlCommand', pattern: /new\s+SqlCommand\s*\(\s*(?:\w+\s*\+|['"`].*\+)/g, languages: [SupportedLanguage.CSHARP], vulnerabilityType: VulnerabilityType.SQL_INJECTION },
  { id: 'csharp-execute', name: 'ExecuteReader', pattern: /Execute(?:Reader|NonQuery|Scalar)\s*\(/g, languages: [SupportedLanguage.CSHARP], vulnerabilityType: VulnerabilityType.SQL_INJECTION }
];

const sqlInjectionSanitizers: TaintSanitizer[] = [
  { id: 'parameterized', name: 'Parameterized Query', pattern: /\?\s*,|:\w+|@\w+|\$\d+/g, protectsAgainst: [VulnerabilityType.SQL_INJECTION], effectiveness: 100 },
  { id: 'prepared', name: 'Prepared Statement', pattern: /prepare(?:d)?(?:Statement)?\s*\(/gi, protectsAgainst: [VulnerabilityType.SQL_INJECTION], effectiveness: 100 },
  { id: 'escape', name: 'Escape Function', pattern: /escape(?:String|Id|Literal)?\s*\(/gi, protectsAgainst: [VulnerabilityType.SQL_INJECTION], effectiveness: 85 },
  { id: 'quote', name: 'Quote Function', pattern: /->quote\s*\(/gi, protectsAgainst: [VulnerabilityType.SQL_INJECTION], effectiveness: 90 },
  { id: 'bind', name: 'Bind Parameters', pattern: /bind(?:Param|Value)\s*\(/gi, protectsAgainst: [VulnerabilityType.SQL_INJECTION], effectiveness: 100 }
];

// ============================================================================
// SQL INJECTION RULES
// ============================================================================

export const sqlInjectionRules: VulnerabilityRule[] = [
  // ==========================================================================
  // JavaScript/TypeScript SQL Injection Rules
  // ==========================================================================
  {
    id: 'VUL-SQLI-001',
    name: 'SQL Injection - String Concatenation in Query',
    description: 'Detects SQL queries built using string concatenation with user input, which can lead to SQL injection attacks.',
    version: '1.0.0',
    vulnerabilityType: VulnerabilityType.SQL_INJECTION,
    category: VulnerabilityCategory.INJECTION,
    languages: [SupportedLanguage.JAVASCRIPT, SupportedLanguage.TYPESCRIPT],
    severity: VulnerabilitySeverity.CRITICAL,
    confidence: ConfidenceLevel.HIGH,
    baseScore: 90,
    patterns: [
      {
        type: PatternType.REGEX,
        patternId: 'sqli-concat-query',
        pattern: '\\.query\\s*\\(\\s*[\'"`](?:SELECT|INSERT|UPDATE|DELETE|DROP).*\\+',
        flags: 'gi',
        weight: 1.0,
        description: 'SQL query with string concatenation'
      },
      {
        type: PatternType.REGEX,
        patternId: 'sqli-template-literal',
        pattern: '\\.query\\s*\\(\\s*`[^`]*\\$\\{[^}]+\\}[^`]*`\\s*\\)',
        flags: 'gi',
        weight: 0.95,
        description: 'SQL query with template literal interpolation'
      },
      {
        type: PatternType.REGEX,
        patternId: 'sqli-req-body-concat',
        pattern: '(?:SELECT|INSERT|UPDATE|DELETE).*\\+\\s*req\\.(?:body|query|params)',
        flags: 'gi',
        weight: 1.0,
        description: 'Direct concatenation of request data in SQL'
      }
    ],
    taintSources: sqlInjectionSources.filter(s => 
      s.languages?.includes(SupportedLanguage.JAVASCRIPT) || 
      s.languages?.includes(SupportedLanguage.TYPESCRIPT)
    ),
    taintSinks: sqlInjectionSinks.filter(s =>
      s.languages?.includes(SupportedLanguage.JAVASCRIPT) ||
      s.languages?.includes(SupportedLanguage.TYPESCRIPT)
    ),
    taintSanitizers: sqlInjectionSanitizers,
    impact: {
      confidentiality: 'high',
      integrity: 'high',
      availability: 'high',
      technicalImpact: 'Attackers can read, modify, or delete arbitrary data in the database. May lead to complete database compromise.',
      businessImpact: 'Data breach, data loss, regulatory fines, reputation damage.',
      affectedAssets: ['Database', 'User Data', 'Application Data'],
      dataAtRisk: ['PII', 'Credentials', 'Financial Data']
    },
    exploitability: {
      attackVector: 'network',
      attackComplexity: 'low',
      privilegesRequired: 'none',
      userInteraction: 'none',
      knownExploits: true
    },
    vulnerableExamples: [
      {
        code: `const userId = req.query.id;
const query = "SELECT * FROM users WHERE id = " + userId;
db.query(query);`,
        language: SupportedLanguage.JAVASCRIPT,
        isVulnerable: true,
        description: 'User input directly concatenated in SQL query'
      },
      {
        code: `const name = req.body.name;
db.query(\`SELECT * FROM products WHERE name = '\${name}'\`);`,
        language: SupportedLanguage.JAVASCRIPT,
        isVulnerable: true,
        description: 'Template literal with unsanitized user input'
      }
    ],
    secureExamples: [
      {
        code: `const userId = req.query.id;
db.query("SELECT * FROM users WHERE id = ?", [userId]);`,
        language: SupportedLanguage.JAVASCRIPT,
        isVulnerable: false,
        description: 'Using parameterized query with placeholders',
        safetyExplanation: 'Parameters are properly escaped by the database driver'
      }
    ],
    remediation: {
      summary: 'Use parameterized queries or prepared statements instead of string concatenation.',
      steps: [
        'Replace string concatenation with parameterized queries',
        'Use ORM/query builders that automatically escape parameters',
        'Implement input validation as defense in depth',
        'Apply principle of least privilege to database accounts'
      ],
      secureCodeExample: `// Secure: Using parameterized query
db.query("SELECT * FROM users WHERE id = ?", [userId]);

// Secure: Using an ORM like Sequelize
const user = await User.findOne({ where: { id: userId } });`,
      references: [
        'https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html',
        'https://owasp.org/www-community/attacks/SQL_Injection'
      ],
      effort: 'low',
      priority: 'immediate'
    },
    standards: {
      owasp: [OWASP_TOP_10_2021.A03],
      cwe: [CWE_REFERENCES.CWE_89],
      sans: [{ rank: 1, cweId: 'CWE-89', category: 'Injection' }]
    },
    tags: ['sql-injection', 'injection', 'database', 'critical', 'owasp-top-10'],
    enabled: true
  },

  // ==========================================================================
  // Python SQL Injection Rules
  // ==========================================================================
  {
    id: 'VUL-SQLI-002',
    name: 'SQL Injection - Python F-String in Query',
    description: 'Detects SQL queries built using Python f-strings or format() with user input.',
    version: '1.0.0',
    vulnerabilityType: VulnerabilityType.SQL_INJECTION,
    category: VulnerabilityCategory.INJECTION,
    languages: [SupportedLanguage.PYTHON],
    severity: VulnerabilitySeverity.CRITICAL,
    confidence: ConfidenceLevel.HIGH,
    baseScore: 90,
    patterns: [
      {
        type: PatternType.REGEX,
        patternId: 'sqli-python-fstring',
        pattern: 'cursor\\.execute\\s*\\(\\s*f[\'"](?:SELECT|INSERT|UPDATE|DELETE).*\\{',
        flags: 'gi',
        weight: 1.0,
        description: 'SQL query using f-string interpolation'
      },
      {
        type: PatternType.REGEX,
        patternId: 'sqli-python-format',
        pattern: 'cursor\\.execute\\s*\\(\\s*[\'"](?:SELECT|INSERT|UPDATE|DELETE).*%s.*\\.format\\s*\\(',
        flags: 'gi',
        weight: 0.95,
        description: 'SQL query using .format()'
      },
      {
        type: PatternType.REGEX,
        patternId: 'sqli-python-percent',
        pattern: 'cursor\\.execute\\s*\\(\\s*[\'"](?:SELECT|INSERT|UPDATE|DELETE).*%s.*%\\s*\\(',
        flags: 'gi',
        weight: 0.95,
        description: 'SQL query using % formatting'
      }
    ],
    taintSources: sqlInjectionSources.filter(s => s.languages?.includes(SupportedLanguage.PYTHON)),
    taintSinks: sqlInjectionSinks.filter(s => s.languages?.includes(SupportedLanguage.PYTHON)),
    taintSanitizers: sqlInjectionSanitizers,
    impact: {
      confidentiality: 'high',
      integrity: 'high',
      availability: 'high',
      technicalImpact: 'Full database access and potential server compromise.',
      businessImpact: 'Data breach and regulatory violations.'
    },
    exploitability: {
      attackVector: 'network',
      attackComplexity: 'low',
      privilegesRequired: 'none',
      userInteraction: 'none'
    },
    vulnerableExamples: [
      {
        code: `user_id = request.args.get('id')
cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")`,
        language: SupportedLanguage.PYTHON,
        isVulnerable: true,
        description: 'F-string used in SQL query'
      }
    ],
    remediation: {
      summary: 'Use parameterized queries with tuple or dict parameters.',
      steps: [
        'Replace f-strings with parameterized queries',
        'Use SQLAlchemy ORM for database operations',
        'Never use string formatting for SQL queries'
      ],
      secureCodeExample: `# Secure: Using parameterized query
cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))

# Secure: Using SQLAlchemy ORM
user = session.query(User).filter(User.id == user_id).first()`,
      references: [
        'https://www.psycopg.org/docs/usage.html#passing-parameters-to-sql-queries'
      ],
      effort: 'low',
      priority: 'immediate'
    },
    standards: {
      owasp: [OWASP_TOP_10_2021.A03],
      cwe: [CWE_REFERENCES.CWE_89]
    },
    tags: ['sql-injection', 'python', 'flask', 'django', 'critical'],
    enabled: true
  },

  // ==========================================================================
  // PHP SQL Injection Rules
  // ==========================================================================
  {
    id: 'VUL-SQLI-003',
    name: 'SQL Injection - PHP Variable in Query',
    description: 'Detects SQL queries with PHP variables directly embedded, indicating potential SQL injection.',
    version: '1.0.0',
    vulnerabilityType: VulnerabilityType.SQL_INJECTION,
    category: VulnerabilityCategory.INJECTION,
    languages: [SupportedLanguage.PHP],
    severity: VulnerabilitySeverity.CRITICAL,
    confidence: ConfidenceLevel.HIGH,
    baseScore: 92,
    patterns: [
      {
        type: PatternType.REGEX,
        patternId: 'sqli-php-mysql-query',
        pattern: '(?:mysql_query|mysqli_query)\\s*\\(\\s*[\'"](?:SELECT|INSERT|UPDATE|DELETE).*\\$_(?:GET|POST|REQUEST)',
        flags: 'gi',
        weight: 1.0,
        description: 'Direct use of superglobal in mysql_query'
      },
      {
        type: PatternType.REGEX,
        patternId: 'sqli-php-pdo-exec',
        pattern: '->(?:query|exec)\\s*\\(\\s*[\'"](?:SELECT|INSERT|UPDATE|DELETE).*\\$',
        flags: 'gi',
        weight: 0.95,
        description: 'Variable interpolation in PDO query'
      },
      {
        type: PatternType.REGEX,
        patternId: 'sqli-php-concat',
        pattern: '(?:mysql_query|mysqli_query|->query)\\s*\\([^)]*\\.\\s*\\$_(?:GET|POST|REQUEST)',
        flags: 'gi',
        weight: 1.0,
        description: 'Concatenation of superglobal in SQL'
      }
    ],
    taintSources: sqlInjectionSources.filter(s => s.languages?.includes(SupportedLanguage.PHP)),
    taintSinks: sqlInjectionSinks.filter(s => s.languages?.includes(SupportedLanguage.PHP)),
    taintSanitizers: sqlInjectionSanitizers,
    impact: {
      confidentiality: 'high',
      integrity: 'high',
      availability: 'high',
      technicalImpact: 'Database compromise, potential code execution via SQL features.',
      businessImpact: 'Massive data breach potential.'
    },
    exploitability: {
      attackVector: 'network',
      attackComplexity: 'low',
      privilegesRequired: 'none',
      userInteraction: 'none',
      knownExploits: true
    },
    vulnerableExamples: [
      {
        code: `$id = $_GET['id'];
$result = mysql_query("SELECT * FROM users WHERE id = '$id'");`,
        language: SupportedLanguage.PHP,
        isVulnerable: true,
        description: 'Direct use of $_GET in SQL query'
      }
    ],
    remediation: {
      summary: 'Use PDO with prepared statements or mysqli with parameterized queries.',
      steps: [
        'Migrate from mysql_* to PDO or mysqli',
        'Use prepared statements with bound parameters',
        'Implement input validation and type casting'
      ],
      secureCodeExample: `// Secure: Using PDO prepared statement
$stmt = $pdo->prepare("SELECT * FROM users WHERE id = :id");
$stmt->execute(['id' => $_GET['id']]);

// Secure: Using mysqli prepared statement  
$stmt = $mysqli->prepare("SELECT * FROM users WHERE id = ?");
$stmt->bind_param("i", $_GET['id']);
$stmt->execute();`,
      effort: 'medium',
      priority: 'immediate'
    },
    standards: {
      owasp: [OWASP_TOP_10_2021.A03],
      cwe: [CWE_REFERENCES.CWE_89]
    },
    tags: ['sql-injection', 'php', 'critical', 'legacy'],
    enabled: true
  },

  // ==========================================================================
  // Java SQL Injection Rules
  // ==========================================================================
  {
    id: 'VUL-SQLI-004',
    name: 'SQL Injection - Java Statement with Concatenation',
    description: 'Detects Java Statement objects with string concatenation instead of PreparedStatement.',
    version: '1.0.0',
    vulnerabilityType: VulnerabilityType.SQL_INJECTION,
    category: VulnerabilityCategory.INJECTION,
    languages: [SupportedLanguage.JAVA],
    severity: VulnerabilitySeverity.CRITICAL,
    confidence: ConfidenceLevel.HIGH,
    baseScore: 90,
    patterns: [
      {
        type: PatternType.REGEX,
        patternId: 'sqli-java-statement',
        pattern: 'executeQuery\\s*\\(\\s*[\'"](?:SELECT|INSERT|UPDATE|DELETE).*\\+',
        flags: 'gi',
        weight: 1.0,
        description: 'Statement.executeQuery with concatenation'
      },
      {
        type: PatternType.REGEX,
        patternId: 'sqli-java-create-statement',
        pattern: 'createStatement\\s*\\(\\s*\\).*execute(?:Query|Update)?\\s*\\([^)]*\\+',
        flags: 'gis',
        weight: 0.95,
        description: 'createStatement followed by concatenated query'
      },
      {
        type: PatternType.REGEX,
        patternId: 'sqli-java-native-query',
        pattern: 'createNativeQuery\\s*\\(\\s*[\'"].*\\+',
        flags: 'gi',
        weight: 0.90,
        description: 'JPA native query with concatenation'
      }
    ],
    taintSources: sqlInjectionSources.filter(s => s.languages?.includes(SupportedLanguage.JAVA)),
    taintSinks: sqlInjectionSinks.filter(s => s.languages?.includes(SupportedLanguage.JAVA)),
    taintSanitizers: sqlInjectionSanitizers,
    impact: {
      confidentiality: 'high',
      integrity: 'high',
      availability: 'high',
      technicalImpact: 'Full database compromise possible.',
      businessImpact: 'Data theft and manipulation.'
    },
    exploitability: {
      attackVector: 'network',
      attackComplexity: 'low',
      privilegesRequired: 'none',
      userInteraction: 'none'
    },
    vulnerableExamples: [
      {
        code: `String userId = request.getParameter("id");
Statement stmt = conn.createStatement();
ResultSet rs = stmt.executeQuery("SELECT * FROM users WHERE id = " + userId);`,
        language: SupportedLanguage.JAVA,
        isVulnerable: true,
        description: 'Statement with concatenated user input'
      }
    ],
    remediation: {
      summary: 'Use PreparedStatement with parameter binding.',
      steps: [
        'Replace Statement with PreparedStatement',
        'Use ? placeholders and setXxx() methods',
        'Consider using JPA Criteria API or named parameters'
      ],
      secureCodeExample: `// Secure: Using PreparedStatement
String userId = request.getParameter("id");
PreparedStatement pstmt = conn.prepareStatement("SELECT * FROM users WHERE id = ?");
pstmt.setString(1, userId);
ResultSet rs = pstmt.executeQuery();

// Secure: Using JPA with parameters
Query query = em.createQuery("SELECT u FROM User u WHERE u.id = :id");
query.setParameter("id", userId);`,
      effort: 'low',
      priority: 'immediate'
    },
    standards: {
      owasp: [OWASP_TOP_10_2021.A03],
      cwe: [CWE_REFERENCES.CWE_89]
    },
    tags: ['sql-injection', 'java', 'jdbc', 'critical'],
    enabled: true
  },

  // ==========================================================================
  // C# SQL Injection Rules
  // ==========================================================================
  {
    id: 'VUL-SQLI-005',
    name: 'SQL Injection - C# SqlCommand with Concatenation',
    description: 'Detects SqlCommand with string concatenation instead of parameterized queries.',
    version: '1.0.0',
    vulnerabilityType: VulnerabilityType.SQL_INJECTION,
    category: VulnerabilityCategory.INJECTION,
    languages: [SupportedLanguage.CSHARP],
    severity: VulnerabilitySeverity.CRITICAL,
    confidence: ConfidenceLevel.HIGH,
    baseScore: 90,
    patterns: [
      {
        type: PatternType.REGEX,
        patternId: 'sqli-csharp-sqlcommand',
        pattern: 'new\\s+SqlCommand\\s*\\(\\s*[\'"](?:SELECT|INSERT|UPDATE|DELETE).*\\+',
        flags: 'gi',
        weight: 1.0,
        description: 'SqlCommand constructor with concatenation'
      },
      {
        type: PatternType.REGEX,
        patternId: 'sqli-csharp-commandtext',
        pattern: '\\.CommandText\\s*=\\s*[\'"](?:SELECT|INSERT|UPDATE|DELETE).*\\+',
        flags: 'gi',
        weight: 0.95,
        description: 'CommandText property with concatenation'
      },
      {
        type: PatternType.REGEX,
        patternId: 'sqli-csharp-interpolation',
        pattern: 'new\\s+SqlCommand\\s*\\(\\s*\\$[\'"](?:SELECT|INSERT|UPDATE|DELETE).*\\{',
        flags: 'gi',
        weight: 1.0,
        description: 'SqlCommand with string interpolation'
      }
    ],
    taintSources: sqlInjectionSources.filter(s => s.languages?.includes(SupportedLanguage.CSHARP)),
    taintSinks: sqlInjectionSinks.filter(s => s.languages?.includes(SupportedLanguage.CSHARP)),
    taintSanitizers: sqlInjectionSanitizers,
    impact: {
      confidentiality: 'high',
      integrity: 'high',
      availability: 'high',
      technicalImpact: 'Database server compromise possible.',
      businessImpact: 'Data breach and service disruption.'
    },
    exploitability: {
      attackVector: 'network',
      attackComplexity: 'low',
      privilegesRequired: 'none',
      userInteraction: 'none'
    },
    vulnerableExamples: [
      {
        code: `string userId = Request.QueryString["id"];
SqlCommand cmd = new SqlCommand("SELECT * FROM Users WHERE Id = " + userId, conn);
SqlDataReader reader = cmd.ExecuteReader();`,
        language: SupportedLanguage.CSHARP,
        isVulnerable: true,
        description: 'SqlCommand with concatenated user input'
      }
    ],
    remediation: {
      summary: 'Use SqlCommand with SqlParameter or Entity Framework.',
      steps: [
        'Add parameters using SqlCommand.Parameters',
        'Use Entity Framework or Dapper with parameterized queries',
        'Implement input validation as additional defense'
      ],
      secureCodeExample: `// Secure: Using SqlParameters
string userId = Request.QueryString["id"];
SqlCommand cmd = new SqlCommand("SELECT * FROM Users WHERE Id = @id", conn);
cmd.Parameters.AddWithValue("@id", userId);
SqlDataReader reader = cmd.ExecuteReader();

// Secure: Using Entity Framework
var user = context.Users.FirstOrDefault(u => u.Id == userId);`,
      effort: 'low',
      priority: 'immediate'
    },
    standards: {
      owasp: [OWASP_TOP_10_2021.A03],
      cwe: [CWE_REFERENCES.CWE_89]
    },
    tags: ['sql-injection', 'csharp', 'dotnet', 'ado-net', 'critical'],
    enabled: true
  },

  // ==========================================================================
  // NoSQL Injection Rule
  // ==========================================================================
  {
    id: 'VUL-SQLI-006',
    name: 'NoSQL Injection - MongoDB Query',
    description: 'Detects potential NoSQL injection in MongoDB queries built with user input.',
    version: '1.0.0',
    vulnerabilityType: VulnerabilityType.NOSQL_INJECTION,
    category: VulnerabilityCategory.INJECTION,
    languages: [SupportedLanguage.JAVASCRIPT, SupportedLanguage.TYPESCRIPT, SupportedLanguage.PYTHON],
    severity: VulnerabilitySeverity.HIGH,
    confidence: ConfidenceLevel.MEDIUM,
    baseScore: 75,
    patterns: [
      {
        type: PatternType.REGEX,
        patternId: 'nosqli-find-body',
        pattern: '\\.find(?:One)?\\s*\\(\\s*(?:req\\.(?:body|query)|\\{[^}]*req\\.)',
        flags: 'gi',
        weight: 0.90,
        description: 'MongoDB find with request data'
      },
      {
        type: PatternType.REGEX,
        patternId: 'nosqli-where',
        pattern: '\\$where\\s*:\\s*[\'"`].*\\+',
        flags: 'gi',
        weight: 1.0,
        description: '$where operator with concatenation'
      },
      {
        type: PatternType.REGEX,
        patternId: 'nosqli-json-parse',
        pattern: 'JSON\\.parse\\s*\\(\\s*req\\.',
        flags: 'gi',
        weight: 0.85,
        description: 'Parsing user input as query object'
      }
    ],
    impact: {
      confidentiality: 'high',
      integrity: 'high',
      availability: 'low',
      technicalImpact: 'Database query manipulation, data extraction.',
      businessImpact: 'Unauthorized data access.'
    },
    exploitability: {
      attackVector: 'network',
      attackComplexity: 'low',
      privilegesRequired: 'none',
      userInteraction: 'none'
    },
    vulnerableExamples: [
      {
        code: `const user = await User.findOne({ 
  username: req.body.username, 
  password: req.body.password 
});`,
        language: SupportedLanguage.JAVASCRIPT,
        isVulnerable: true,
        description: 'Direct use of request body in MongoDB query - allows {$gt: ""} injection'
      }
    ],
    remediation: {
      summary: 'Validate and sanitize input, use explicit field selection.',
      steps: [
        'Validate input types before using in queries',
        'Use mongo-sanitize or similar library',
        'Avoid $where operator with user input',
        'Use explicit type casting for query parameters'
      ],
      secureCodeExample: `// Secure: Type validation
const username = String(req.body.username);
const password = String(req.body.password);
const user = await User.findOne({ username, password });`,
      effort: 'low',
      priority: 'high'
    },
    standards: {
      owasp: [OWASP_TOP_10_2021.A03],
      cwe: [CWE_REFERENCES.CWE_89]
    },
    tags: ['nosql-injection', 'mongodb', 'javascript', 'high'],
    enabled: true
  }
];

// ============================================================================
// EXPORTS
// ============================================================================

export default sqlInjectionRules;
