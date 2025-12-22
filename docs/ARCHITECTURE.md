# 🏗️ Arquitectura Técnica - Secure-Scan

## Visión General

Secure-Scan es una herramienta profesional de **Análisis Estático de Seguridad de Aplicaciones (SAST)** diseñada con una arquitectura modular, extensible y de nivel empresarial.

## Diagrama de Arquitectura

```
┌─────────────────────────────────────────────────────────────────┐
│                           CLI Core                               │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────────────┐   │
│  │   Commands   │  │   Options    │  │   Config Loader      │   │
│  └──────────────┘  └──────────────┘  └──────────────────────┘   │
└─────────────────────────────┬───────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                      Security Scanner                            │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │                    Orchestrator                           │   │
│  │  - Coordina todos los módulos                            │   │
│  │  - Gestiona el flujo de análisis                         │   │
│  │  - Combina resultados                                     │   │
│  └──────────────────────────────────────────────────────────┘   │
└──────────┬────────────────┬────────────────┬────────────────────┘
           │                │                │
           ▼                ▼                ▼
┌──────────────────┐ ┌──────────────┐ ┌──────────────────┐
│   File Scanner   │ │ Rule Engine  │ │  AI Analyzer     │
│                  │ │              │ │                  │
│ - Escanea dirs   │ │ - Patterns   │ │ - OpenAI/Claude  │
│ - Detecta langs  │ │ - Regex      │ │ - Modelos locales│
│ - Lee archivos   │ │ - AST        │ │ - Mejora reglas  │
└──────────────────┘ └──────────────┘ └──────────────────┘
           │                │                │
           └────────────────┴────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────────┐
│                    Language Analyzers (Plugins)                  │
│  ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────┐   │
│  │   JS    │ │ Python  │ │   PHP   │ │  Java   │ │  C/C++  │   │
│  └─────────┘ └─────────┘ └─────────┘ └─────────┘ └─────────┘   │
│  ┌─────────┐ ┌─────────────────────────────────────────────┐   │
│  │   C#    │ │               IaC Analyzer                   │   │
│  └─────────┘ │ (Dockerfile, YAML, Terraform, CI/CD)        │   │
│              └─────────────────────────────────────────────┘   │
└─────────────────────────────┬───────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                      Risk Scoring Engine                         │
│  - Calcula puntuación de riesgo (0-100)                         │
│  - Pondera por severidad y categoría                            │
│  - Genera métricas de seguridad                                 │
└─────────────────────────────┬───────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                      Report Generator                            │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────────────┐   │
│  │   HTML       │  │    JSON      │  │     SARIF (futuro)   │   │
│  └──────────────┘  └──────────────┘  └──────────────────────┘   │
└─────────────────────────────────────────────────────────────────┘
```

## Componentes Principales

### 1. CLI Core (`src/cli/`)

Punto de entrada de la aplicación. Maneja:
- Parsing de argumentos
- Configuración de opciones
- Invocación del scanner
- Formato de salida

**Comandos:**
- `scan <path>` - Escanea un proyecto
- `init` - Crea archivo de configuración
- `rules` - Lista reglas disponibles

### 2. File Scanner (`src/analyzers/core/scanner/`)

Responsable de:
- Escanear directorios recursivamente
- Detectar lenguajes por extensión
- Leer y procesar archivos
- Filtrar por patrones de exclusión
- Calcular hashes de archivos

### 3. Rule Engine (`src/analyzers/core/engine/`)

Motor de reglas que:
- Carga reglas de detección
- Ejecuta patrones regex contra código
- Genera findings con contexto
- Soporta AST (futuro)

### 4. Language Analyzers (`src/analyzers/`)

Plugins especializados por lenguaje:

| Analizador | Lenguajes | Capacidades Especiales |
|------------|-----------|------------------------|
| JavaScript | JS, TS | npm audit, prototype pollution, DOM XSS |
| Python | Python | pickle, YAML, Django/Flask |
| PHP | PHP | Web shells, file inclusion, SQL |
| Java | Java | Deserialization, XXE, SpEL |
| C/C++ | C, C++ | Buffer overflow, format string |
| C# | C# | .NET vulnerabilities, LDAP |
| IaC | Docker, YAML, TF | Container security, CI/CD |

### 5. AI Analyzer (`src/ai/`)

Análisis potenciado por IA:
- Integración con OpenAI GPT-4
- Soporte para Anthropic Claude
- Modelos locales (Ollama, llama.cpp)
- Mejora de explicaciones
- Detección de patrones complejos

### 6. Risk Scoring (`src/analyzers/core/scoring/`)

Sistema de puntuación:
- Calcula score 0-100
- Pondera por severidad (Critical=100, Info=5)
- Multiplica por categoría (Malware=1.5x)
- Normaliza por tamaño del proyecto

### 7. Report Generator (`src/reports/`)

Genera reportes profesionales:
- HTML con diseño moderno
- JSON para integración
- SARIF para IDEs (futuro)

## Flujo de Datos

```
Entrada: Ruta del proyecto
           │
           ▼
    ┌──────────────┐
    │ File Scanner │ ──▶ Lista de archivos con contenido
    └──────────────┘
           │
           ▼
    ┌──────────────┐
    │ Detección de │ ──▶ Asigna lenguaje a cada archivo
    │   Lenguaje   │
    └──────────────┘
           │
           ▼
    ┌──────────────────────────────────────┐
    │    Análisis Paralelo                  │
    │  ┌────────────┐  ┌────────────────┐  │
    │  │   Rules    │  │   Analyzers    │  │
    │  │  (Regex)   │  │  (Por lenguaje)│  │
    │  └────────────┘  └────────────────┘  │
    │         │               │            │
    │         └───────┬───────┘            │
    │                 ▼                    │
    │  ┌────────────────────────────────┐  │
    │  │         AI Analyzer            │  │
    │  │   (si está habilitado)         │  │
    │  └────────────────────────────────┘  │
    └──────────────────┬───────────────────┘
                       │
                       ▼
              ┌──────────────┐
              │ Deduplicación│ ──▶ Elimina findings duplicados
              └──────────────┘
                       │
                       ▼
              ┌──────────────┐
              │ Scoring      │ ──▶ Calcula riesgo
              └──────────────┘
                       │
                       ▼
              ┌──────────────┐
              │   Report     │ ──▶ Genera HTML/JSON
              │  Generator   │
              └──────────────┘
                       │
                       ▼
              Salida: Reporte + Exit Code
```

## Estructura de un Finding

```typescript
interface Finding {
  id: string;           // Identificador único
  title: string;        // Título del hallazgo
  description: string;  // Descripción detallada
  severity: Severity;   // critical | high | medium | low | info
  threatType: ThreatType;  // sql_injection, xss, backdoor, etc.
  category: FindingCategory;  // vulnerability | malware
  location: {
    file: string;       // Ruta del archivo
    startLine: number;  // Línea inicial
    endLine: number;    // Línea final
  };
  snippet: {
    code: string;       // Código vulnerable
    contextBefore: string;  // Contexto anterior
    contextAfter: string;   // Contexto posterior
  };
  standards: SecurityStandard[];  // OWASP, CWE, MITRE
  remediation: string;  // Cómo corregir
  confidence: number;   // 0-100
  analyzer: string;     // Qué analizador lo detectó
  tags: string[];       // Etiquetas
}
```

## Estándares de Seguridad

Cada finding se mapea a:

| Estándar | Descripción | Ejemplo |
|----------|-------------|---------|
| OWASP Top 10 | Top vulnerabilidades web | A03:2021 - Injection |
| CWE | Common Weakness Enumeration | CWE-79 (XSS) |
| MITRE ATT&CK | Tácticas y técnicas de atacantes | T1059 - Command Interpreter |
| SANS Top 25 | Errores de software más peligrosos | SANS-3 - SQL Injection |

## Reglas de Detección

### Estructura de una Regla

```typescript
interface Rule {
  id: string;           // VULN-SQL-001
  name: string;         // SQL Injection
  description: string;  // Descripción
  languages: SupportedLanguage[];  // Lenguajes
  threatType: ThreatType;
  severity: Severity;
  patterns: RulePattern[];  // Patrones de detección
  remediation: string;
  enabled: boolean;
  tags: string[];
}
```

### Tipos de Patrones

1. **Regex** - Expresiones regulares
2. **AST** - Análisis de árbol sintáctico (futuro)
3. **Semantic** - Análisis semántico con IA

## Extensibilidad

### Añadir nuevo analizador

1. Crear clase que extienda `BaseAnalyzer`
2. Implementar método `analyze()`
3. Registrar en `src/analyzers/index.ts`

```typescript
export class NewLanguageAnalyzer extends BaseAnalyzer {
  name = 'New Language Analyzer';
  languages = ['newlang'];
  version = '1.0.0';

  async analyze(file: ScannedFile, rules: Rule[]): Promise<Finding[]> {
    // Implementación
  }
}
```

### Añadir nuevas reglas

1. Crear archivo en `src/rules/vulnerabilities/` o `src/rules/malware/`
2. Definir reglas con patrones
3. Exportar en `index.ts`

## Seguridad del Propio Scanner

⚠️ **Restricciones de seguridad:**

1. **Solo lectura** - El scanner nunca modifica archivos
2. **Sin ejecución** - No ejecuta código del proyecto
3. **Sin compilación** - No compila ni interpreta
4. **Sandbox** - Puede ejecutarse en Docker

## Roadmap de Desarrollo

### Fase 1 ✅
- Análisis estático básico
- Reglas regex
- Reportes HTML

### Fase 2 ✅
- Integración IA
- Multi-lenguaje
- CLI avanzado

### Fase 3 ✅
- Análisis AST
- Análisis de IaC (Dockerfile, YAML, Terraform)
- Detección de malware

### Fase 4 ✅
- Análisis de dependencias (SCA)
- Software Composition Analysis
- Detección de CVEs, typosquatting, paquetes maliciosos
- Soporte para npm, pip, composer, maven, nuget, vcpkg

### Fase 5 (Futuro)
- Dashboard web
- API REST
- Multi-tenant SaaS

### Fase 6 (Futuro)
- DAST (análisis dinámico)
- IAST (instrumentación)
- RASP (protección runtime)
