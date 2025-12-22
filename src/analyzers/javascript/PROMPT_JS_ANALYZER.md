🔐 PROMPT — Mejora Avanzada del Módulo JavaScript
Secure-Scan | javascriptAnalyzer.ts
🎯 Rol del Agente

Actúa simultáneamente como:

Senior JavaScript Security Engineer

Malware Analyst especializado en JavaScript / npm

Application Security Lead (AppSec)

Arquitecto SAST Enterprise

Toma decisiones técnicas profesionales, priorizando precisión, cobertura, performance y seguridad, sin violar principios éticos ni legales.

🧠 Contexto del Proyecto

Secure-Scan es una herramienta de Análisis Estático de Seguridad de Aplicaciones (SAST) que analiza repositorios de código sin ejecutarlos, diseñada para detectar:

Vulnerabilidades OWASP

Código malicioso

Amenazas de supply chain

El archivo javascriptAnalyzer.ts es un módulo especializado en JavaScript y TypeScript, y debe mejorarse de forma incremental, manteniendo compatibilidad con BaseAnalyzer.

🎯 Objetivo de Esta Mejora

Mejorar TODOS los aspectos del módulo:

✅ Detección avanzada de malware

✅ Detección profunda de vulnerabilidades OWASP

✅ Mayor precisión (reducción de falsos positivos)

✅ Mayor cobertura (más técnicas y casos reales)

✅ Mejor performance, sin sacrificar exactitud

🧩 Enfoque Técnico Obligatorio
🔍 Tipo de Análisis

Análisis híbrido, con prioridad en:

AST (principal)

Regex / firmas solo como fallback

📐 Herramientas Conceptuales a Emular

No integrar directamente, pero diseñar el análisis inspirado en:

Semgrep → estructura AST y patrones semánticos

YARA → firmas de malware (regex controladas)

CodeQL → flujos peligrosos (taint analysis)

🌳 AST y Parsing

Usar Babel Parser para JavaScript y TypeScript

Migrar reglas críticas (XSS, RCE, Prototype Pollution) a AST

Evitar detecciones basadas solo en strings cuando sea posible

🔁 Taint Analysis (Obligatorio)

Implementar taint analysis básico pero efectivo, capaz de detectar flujos reales:

Fuentes (Sources)

req.body

req.query

req.params

process.env

localStorage

document.location

postMessage

Sinks (Sinks)

innerHTML

document.write

eval

Function()

child_process.exec

spawn

execFile

fetch / axios (SSRF)

Detectar flujos como:

req.body → innerHTML

process.env → exec

🦠 Malware a Detectar (Cobertura Total)
Tipos

Supply-chain malware (npm)

Cryptominers JS

Stealers (cookies, tokens, localStorage)

Backdoors lógicos

Droppers / loaders

Payloads ofuscados

Técnicas

Base64 → decode → eval

new Function()

WebAssembly sospechoso

Anti-debugging JS

Código auto-modificable

Uso anómalo de encoding / crypto

📦 Análisis Profundo de package.json

Analizar estáticamente:

scripts

dependencies

devDependencies

engines

preinstall / postinstall

Detectar:

Typosquatting

Paquetes abandonados

Scripts ofuscados

Comandos peligrosos (curl | sh, powershell, eval)

🧠 Uso de Inteligencia Artificial

La IA debe apoyar en:

Clasificación de severidad

Detección de patrones no triviales

Reducción de falsos positivos

Explicación del hallazgo

Debe poder analizar:

Fragmentos de código

Metadatos

Ambos combinados

El diseño debe permitir IA local o por API, de forma desacoplada.

📊 Hallazgos y Reportes

Cada hallazgo debe incluir:

Código vulnerable exacto

Contexto y snippet

Call stack aproximado (si aplica)

Referencias OWASP / CWE automáticas

Categoría:

Malware

Vulnerabilidad

Severidad justificada

Recomendación + ejemplo de fix seguro

El lenguaje debe ser:

Profesional (auditoría)

Comprensible para desarrolladores

⚙️ Performance y Seguridad

Implementar:

🔁 Análisis paralelo

⏱️ Timeouts solo si se detectan bucles anómalos

🧠 Límites de memoria, priorizando precisión

Protecciones contra:

Código altamente ofuscado

ReDoS por regex

Archivos excesivamente grandes

🧪 Calidad del Código

El código generado debe:

Seguir principios SOLID

Ser 100% testeable

Incluir tests unitarios

Mantener compatibilidad con BaseAnalyzer

Se permite introducir:

Nuevas clases

Nuevas interfaces

Helpers reutilizables

🚀 Instrucción Final

Mejora incrementalmente el archivo javascriptAnalyzer.ts, documentando cada decisión técnica, agregando detección avanzada de malware y vulnerabilidades, sin ejecutar código analizado y manteniendo el enfoque SAST enterprise.

Prioridad:

Seguridad

Precisión

Cobertura

Performance