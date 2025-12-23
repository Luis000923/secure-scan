# PROMPT – Diseño y Mejora del Módulo de Reglas de Vulnerabilidades
## Secure-Scan – src/rules/vulnerabilities

Asume el rol combinado de:

- AppSec Engineer
- Security Architect
- SAST Engine Designer
- Auditor de Seguridad

con experiencia en herramientas SAST empresariales, OWASP, CWE, MITRE ATT&CK y análisis estático avanzado.

---

## 🎯 Objetivo General

Diseñar e implementar el módulo `src/rules/vulnerabilities`, encargado de la **detección avanzada de vulnerabilidades de seguridad** en proyectos de software, sin ejecutar el código.

El módulo debe priorizar:

- Alta cobertura de reglas
- Alta precisión (mínimos falsos positivos)
- Detección temprana
- Explicaciones claras (auditoría + developer-friendly)
- Soporte multi-lenguaje
- Escalabilidad y arquitectura modular

---

## 🧩 Alcance del Módulo

El módulo debe detectar:

### 🔹 Vulnerabilidades de código
- Errores de validación de entrada
- Flujos peligrosos de datos
- Uso inseguro de APIs

### 🔹 Configuración insegura
- Archivos YAML / JSON / ENV
- Configuraciones débiles o peligrosas

### 🔹 Infraestructura
- Dockerfiles
- CI/CD pipelines
- Archivos de automatización

---

## 📚 Estándares Obligatorios

Cada regla de vulnerabilidad DEBE mapearse cuando aplique a:

- OWASP Top 10
- CWE
- SANS Top 25
- MITRE ATT&CK
- CVEs reales (si existen)

---

## 🗂️ Clasificación de Vulnerabilidades

Las vulnerabilidades deben organizarse por:

- Tipo:
  - Injection
  - XSS
  - Auth / Session
  - Configuración
  - Deserialización
  - Path / File
- Lenguaje:
  - JavaScript / TypeScript
  - Python
  - PHP
  - Java
  - C / C++
  - C#

---

## 🧪 Vulnerabilidades a Implementar Inicialmente

Crear reglas dedicadas para:

- SQL Injection
- Command Injection
- XSS (DOM, Reflected, Stored)
- CSRF
- SSRF
- Insecure Deserialization
- Path Traversal
- Prototype Pollution
- Insecure Authentication / Session
- Hardcoded Secrets
- Unsafe File Upload
- Security Misconfigurations

---

## 🔍 Nivel de Análisis Técnico

El análisis debe ser **híbrido**, combinando:

- Regex (fallback)
- AST
- CFG / Call Graph
- Taint Analysis (fuentes → sinks)

Ejemplos de flujos reales a detectar:
- `req.body → exec`
- `userInput → innerHTML`
- `env → system()`

Se permite introducir **nuevos analizadores** además de reutilizar los existentes.

---

## 🧱 Arquitectura del Módulo (Requisito Crítico)

### Principios

- Arquitectura modular
- Separación clara entre:
  - Definición de reglas
  - Lógica de detección
  - Engine de ejecución

### Modelo de Regla

Cada vulnerabilidad debe tener:
- Un archivo de **regla**
- Un archivo de **detector**

Las reglas deben poder:
- Tener múltiples patrones
- Ajustar severidad según contexto
- Correlacionarse con reglas de malware

---

## 📁 Estructura de Carpetas Esperada

Usar estructura **flat** dentro de `/vulnerabilities`, con un punto central:

src/rules/vulnerabilities/
├── index.ts # Registro central de reglas
├── vulnerabilityRule.ts # Interfaces base
├── engine.ts # Rule engine reutilizable
├── sqlInjection.ts
├── xss.ts
├── csrf.ts
├── ssrf.ts
├── misconfig.ts
└── tests/


---

## ⚖️ Severidad y Scoring

La severidad será **mixta**:

- Base definida en la regla
- Ajustada dinámicamente por contexto

Implementar `vulnerabilityScore` considerando:
- Explotabilidad
- Impacto técnico
- Impacto al negocio
- Contexto (prod vs dev)

---

## 📊 Hallazgos y Reportes

Cada hallazgo DEBE incluir:

- Fragmento exacto del código vulnerable
- Flujo de datos detectado
- Severidad final
- Vulnerability score
- Referencias OWASP / CWE
- Explicación nivel auditoría
- Contexto entendible para desarrolladores

---

## 🧪 Calidad del Código y Testing

El código generado debe:

- Seguir principios SOLID
- Ser extensible y mantenible
- Permitir testing aislado por regla

Tests requeridos:
- Golden tests con código vulnerable real
- Casos límite para falsos positivos

---

## ⚡ Performance y Seguridad

El motor de vulnerabilidades debe incluir:

- Timeouts por regla
- Límite de nodos AST analizados
- Protección contra ReDoS
- Ejecución paralela segura

No degradar precisión aunque el archivo sea grande o minificado.

---

## ✅ Resultado Esperado

Un módulo de vulnerabilidades:

- De nivel enterprise
- Comparable a SAST comerciales
- Modular, extensible y auditable
- Preparado para escalar a SaaS

⚠️ El análisis debe ser estrictamente estático. Nunca ejecutar código analizado.
