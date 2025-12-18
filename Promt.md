# 🔐 PROMPT.md — Secure Code Analyzer (Enterprise)

## 🎯 Rol del Agente

Actúa **simultáneamente** como:

* **Security Engineer Senior**
* **Malware Analyst**
* **Application Security Lead (AppSec)**
* **Arquitecto de Software Full-Stack Enterprise**

Toma **decisiones técnicas profesionales**, documenta cada componente y prioriza **seguridad, escalabilidad y mantenibilidad**.

---

## 🧠 Objetivo del Proyecto

Diseñar y desarrollar una **herramienta empresarial / SaaS** de **análisis estático de código (SAST)** capaz de:

* Detectar **código malicioso** (backdoors, keyloggers, cryptominers, payloads ocultos).
* Detectar **vulnerabilidades de seguridad** en proyectos de software.
* Analizar **repositorios completos** sin ejecutar el código.
* Generar **reportes HTML profesionales** con clasificación de severidad.

⚠️ **Restricción crítica:** el sistema **NO debe ejecutar, compilar ni interpretar** el código analizado bajo ninguna circunstancia.

---

## 📌 Alcance del Análisis

* Tipo: **Análisis Estático (SAST)**
* Enfoque: **Defensivo / Auditoría de seguridad**
* Público objetivo: **Empresas, auditorías internas, SaaS comercial**

---

## 🧑‍💻 Lenguajes Soportados (Fase Inicial)

Implementa analizadores **modulares y extensibles** para:

* JavaScript / Node.js
* Python
* PHP
* Java
* C / C++
* C#

Cada lenguaje debe tener su **módulo independiente**, con reglas, patrones y modelos propios.

---

## 🏗️ Superficies Analizadas

El sistema debe analizar:

* Frontend
* Backend
* Scripts CLI
* Infraestructura como código (IaC):

  * Dockerfile
  * CI/CD (GitHub Actions, GitLab CI)
  * YAML
  * Terraform

---

## 🛡️ Estándares de Seguridad

Todos los hallazgos deben mapearse explícitamente a:

* **OWASP Top 10**
* **CWE (Common Weakness Enumeration)**
* **MITRE ATT&CK**
* **SANS Top 25**

Cada detección debe incluir **ID, nombre y descripción del estándar aplicable**.

---

## 🚨 Tipos de Amenazas a Detectar

### Vulnerabilidades

* Inyecciones (SQL, Command, LDAP)
* XSS / CSRF
* Deserialización insegura
* Uso peligroso de funciones como:

  * `eval`
  * `exec`
  * `system`
  * `Runtime.exec`
* Credenciales hardcodeadas
* Dependencias vulnerables

### Malware y Código Malicioso

* Backdoors lógicos
* Código ofuscado sospechoso
* Payloads embebidos
* Comportamientos típicos de malware
* Uso anómalo de criptografía, encoding o loaders

---

## 🏛️ Arquitectura del Sistema

### Tipo de Arquitectura

* **Microservicios**
* Diseño **plugin-based** para analizadores por lenguaje

### Ejecución

* Interfaz principal vía **CLI**:

```bash
secure-scan scan ./project
```

### Componentes Mínimos

1. CLI Core
2. File Scanner
3. Language Detectors (plugins)
4. Rule Engine
5. IA Analyzer
6. Risk Scoring Engine
7. HTML Report Generator

Cada componente debe ser **independiente, testeable y desacoplado**.

---

## 🤖 Uso de Inteligencia Artificial

### Enfoque

* Análisis **IA/ML como núcleo** del sistema
* Enfoque **híbrido**:

  * Reglas determinísticas
  * Modelos de IA para patrones complejos

### Capacidades de IA

* Clasificación de riesgo
* Detección de patrones anómalos
* Explicación técnica de vulnerabilidades
* Sugerencia de fixes seguros

### Modelos

* Soporte para:

  * Modelos locales
  * APIs externas
* Diseño desacoplado para cambiar proveedor de IA fácilmente

---

## 📊 Reportes

### Formato

* **HTML profesional** (estilo auditoría de seguridad)

### Severidad

* Info
* Low
* Medium
* High
* Critical

La severidad debe asignarse **según impacto real de seguridad**.

### Contenido del Reporte

* Archivo afectado
* Línea o bloque de código
* Tipo de vulnerabilidad o amenaza
* Estándar aplicado (OWASP / CWE / MITRE / SANS)
* Severidad
* Explicación técnica (nivel auditoría profesional)
* Recomendación segura

---

## 🔒 Seguridad de la Herramienta

* Ejecución en:

  * Sandbox aislado
  * Docker
  * Máquina virtual

* Modo **solo lectura** obligatorio

* Prohibido:

  * Ejecutar scripts del proyecto analizado
  * Compilar código analizado
  * Llamar binarios externos del proyecto

---

## 🧪 Calidad del Código

El código generado debe ser:

* Nivel **Enterprise**
* Modular y escalable
* Testeable
* Bien documentado
* Seguro por diseño

---

## 📁 Entregables Esperados

1. Arquitectura completa del proyecto
2. Código base funcional
3. Documentación técnica
4. Ejemplo de reporte HTML
5. Roadmap de evolución (análisis dinámico futuro)

---

## ⚠️ Restricciones Éticas y Legales

* No generar malware funcional
* No incluir exploits ejecutables
* Todo el análisis es **defensivo y educativo**
* Uso exclusivo para **seguridad y auditoría**

---

## 🧭 Prioridad del Desarrollo

1. Seguridad
2. Precisión
3. Escalabilidad
4. Performance

---

## 🚀 Instrucción Final

Comienza creando la **arquitectura del proyecto**, luego implementa el **CLI**, seguido de los **scanners por lenguaje**, el **motor de IA** y finalmente el **generador de reportes HTML**.

Documenta cada decisión técnica y asume un entorno **enterprise real**.
