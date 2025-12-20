# 🔐 Secure-Scan: Herramienta SAST Profesional

[![Licencia: MIT](https://img.shields.io/badge/Licencia-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Versión Node.js](https://img.shields.io/badge/node-%3E%3D18.0.0-brightgreen)](https://nodejs.org)
[![Idioma](https://img.shields.io/badge/Idioma-Español%20%7C%20English-blue.svg)](#-idiomas)

**Secure-Scan** es una herramienta profesional de **Análisis Estático de Seguridad de Aplicaciones (SAST)** diseñada para detectar vulnerabilidades y código malicioso en repositorios de código sin ejecutarlos.

## 🎯 Características Principales

### 🔍 Análisis de Código Fuente
- ✅ **Análisis Estático Puro** - Sin ejecución, compilación ni interpretación de código
- 🔍 **Detección de Vulnerabilidades** - SQL Injection, XSS, CSRF, Command Injection, Path Traversal, etc.
- 🦠 **Detección de Malware** - Backdoors, keyloggers, cryptominers, web shells, payloads ocultos
- 🌐 **Multi-lenguaje** - JavaScript, Python, PHP, Java, C/C++, C#, IaC (Docker, Terraform, Kubernetes)

### 📦 Análisis de Composición de Software (SCA)
- 📋 **Análisis de Manifiestos** - package.json, requirements.txt, composer.json, pom.xml, etc.
- 🔓 **Detección de CVEs** - Vulnerabilidades conocidas en dependencias
- ⚠️ **Typosquatting** - Detecta paquetes maliciosos con nombres similares
- 🔐 **Análisis de Lock Files** - package-lock.json, yarn.lock, composer.lock, Pipfile.lock

### 🔬 Escaneo de Dependencias Instaladas (NUEVO)
- 📂 **Escaneo de node_modules** - Análisis profundo de paquetes npm/yarn instalados
- 🐍 **Escaneo de venv/site-packages** - Paquetes Python instalados
- 🐘 **Escaneo de vendor** - Dependencias PHP Composer
- 🦠 **Detección de Malware en Dependencias**:
  - 🚪 Backdoors (reverse shells, conexiones C2, robo de SSH keys)
  - ⛏️ Cryptominers (minería de criptomonedas oculta)
  - 🔓 Data Stealers (robo de credenciales, variables de entorno, tokens)
  - 📥 Malicious Loaders (descarga de payloads remotos)
  - 🔐 Código Ofuscado (base64 eval, hex encoding, anti-análisis)
  - 📤 Exfiltración de Datos (DNS tunneling, HTTP POST de datos)
  - 🛡️ Técnicas Anti-Análisis (detección de debuggers, sandbox evasion)
- ✅ **Verificación de Integridad** - Compara versiones instaladas vs lock files
- ⚡ **Análisis de Post-Install Scripts** - Detecta scripts maliciosos en hooks

### 📊 Reportes y Estándares
- 📊 **Reportes HTML Profesionales** - Estilo auditoría de seguridad
- 🤖 **IA Integrada** - Análisis inteligente con modelos locales o en la nube
- 📋 **Mapeo a Estándares** - OWASP Top 10, CWE, MITRE ATT&CK, SANS Top 25
- 🌍 **Multiidioma** - Reportes en español (por defecto) o inglés
- 📈 **Puntuación de Riesgo** - Score 0-100 basado en severidad y cantidad de hallazgos

## 🏗️ Arquitectura

```
secure-scan/
├── src/
│   ├── cli/                    # Interfaz de línea de comandos
│   ├── core/                   # Núcleo del sistema
│   │   ├── scanner/            # Escáner de archivos
│   │   ├── engine/             # Motor de reglas
│   │   └── scoring/            # Motor de puntuación de riesgo
│   ├── analyzers/              # Analizadores por lenguaje (plugins)
│   │   ├── javascript/
│   │   ├── python/
│   │   ├── php/
│   │   ├── java/
│   │   ├── c-cpp/
│   │   ├── csharp/
│   │   └── iac/                # Infraestructura como Código
│   ├── dependencies/           # Análisis de Dependencias (SCA)
│   │   ├── parsers/            # Parsers por ecosistema (npm, pip, composer, etc.)
│   │   ├── detectors/          # Detectores de vulnerabilidades
│   │   ├── database/           # Base de datos CVE y paquetes maliciosos
│   │   └── installed/          # Escáner de dependencias instaladas (malware)
│   ├── rules/                  # Reglas de detección
│   │   ├── vulnerabilities/
│   │   └── malware/
│   ├── ai/                     # Motor de IA
│   ├── reports/                # Generador de reportes
│   ├── i18n/                   # Traducciones (español/inglés)
│   ├── types/                  # Definiciones TypeScript
│   └── utils/                  # Utilidades
├── test-samples/               # Archivos de prueba
└── docs/                       # Documentación
```

## 🚀 Instalación

### Opción 1: Instalación Global (Recomendada)

```bash
# Clonar el repositorio
git clone https://github.com/your-org/secure-scan.git
cd secure-scan

# Instalar dependencias y compilar
npm install

# Instalar globalmente
npm link

# Verificar instalación
secure-scan --version

# Alternativa para Windows con Ollama (IA Local)OPCIÓNAL
#LAS APIS KEYS DE IA DEBEN DE SER DE PAGA, A MENOS QUE USES IA LOCAL COMO OLLAMA(GPT,GEMINI)
winget install Ollama.Ollama

# Descargar un modelo optimizado para código
ollama pull codellama:7b-instruc

# Ejecutar el servidor Ollama (si no está en ejecución)
ollama serve
```

### Opción 2: Usar con npx

```bash
# Ejecutar directamente sin instalar
npx secure-scan scan ./mi-proyecto
```

### Opción 3: Instalación desde npm (próximamente)

```bash
npm install -g secure-scan
```

## 📖 Uso
### VISO MODIFICAR EL ARCHIVO secure-scan.config.json PARA CONFIGURAR LA HERRAMIENTA SEGÚN TUS NECESIDADES.
### Escaneo Básico

```bash
# Escanear un proyecto
secure-scan scan ./mi-proyecto

# O usando la ruta completa
secure-scan scan "C:\Users\TuUsuario\Proyectos\mi-proyecto"
```

### Opciones Disponibles

```bash
# Escanear con reporte HTML personalizado
secure-scan scan ./proyecto -o ./mi-reporte

# Modo verbose (más detalles)
secure-scan scan ./proyecto -v

# Usar análisis de IA (requiere API key)
secure-scan scan ./proyecto --ai --api-key TU_API_KEY

# Especificar lenguajes
secure-scan scan ./proyecto --languages javascript,python

# Reporte en inglés
secure-scan scan ./proyecto --lang en

# Reporte en español (por defecto)
secure-scan scan ./proyecto --lang es
```

### Combinación de Opciones

Puedes combinar múltiples opciones en un solo comando:

```bash
# Escaneo completo con IA, verbose y reporte personalizado
secure-scan scan ./proyecto -v --ai --api-key "TU_API_KEY" -o "./reporte-seguridad"

# Escaneo con IA local (Ollama), lenguajes específicos y reporte en inglés
secure-scan scan ./proyecto --ai --ai-provider local -o "./security-report" --lang en --languages javascript,python

# Escaneo rápido solo críticos con salida JSON
secure-scan scan ./proyecto --min-severity critical --json

# Escaneo completo excluyendo carpetas
secure-scan scan ./proyecto -v --exclude "tests,docs,examples" -o "./audit-report"
```

### Referencia de Opciones

| Opción | Alias | Descripción | Ejemplo |
|--------|-------|-------------|---------|
| `--output` | `-o` | Ruta del reporte HTML | `-o ./reporte` |
| `--verbose` | `-v` | Salida detallada | `-v` |
| `--ai` | - | Habilitar análisis IA | `--ai` |
| `--api-key` | - | API key (auto-detecta proveedor) | `--api-key "sk-..."` |
| `--ai-provider` | - | Proveedor IA (openai, anthropic, google, gemini, local, auto) | `--ai-provider google` |
| `--ai-model` | - | Modelo de IA | `--ai-model gpt-4o` |
| `--languages` | `-l` | Lenguajes a escanear | `--languages js,py` |
| `--exclude` | `-e` | Patrones a excluir | `--exclude "test,docs"` |
| `--min-severity` | - | Severidad mínima | `--min-severity high` |
| `--lang` | - | Idioma del reporte (es/en) | `--lang en` |
| `--json` | - | Salida en formato JSON | `--json` |
| `--max-file-size` | - | Tamaño máximo de archivo | `--max-file-size 10485760` |

### Proveedores de IA Soportados

La herramienta **auto-detecta el proveedor** basándose en el formato de tu API key:

| Proveedor | Prefijo API Key | Modelos Disponibles |
|-----------|-----------------|---------------------|
| **OpenAI** | `sk-` o `sk-proj-` | `gpt-4o`, `gpt-4-turbo`, `gpt-4`, `gpt-3.5-turbo`, `o1-preview`, `o1-mini` |
| **Anthropic** | `sk-ant-` | `claude-3-opus`, `claude-3-sonnet`, `claude-3-haiku` |
| **Google AI** | `AIzaSy` | `gemini-1.5-pro`, `gemini-1.5-flash`, `gemini-pro` |
| **Local** | N/A | Cualquier modelo via Ollama, LM Studio, etc. |

```bash
# OpenAI (auto-detectado)
secure-scan scan ./proyecto --ai --api-key "sk-proj-abc123..."

# Google Gemini (auto-detectado)
secure-scan scan ./proyecto --ai --api-key "AIzaSyAbc123..."

# Anthropic Claude (auto-detectado)
secure-scan scan ./proyecto --ai --api-key "sk-ant-abc123..."

# Especificar modelo manualmente
secure-scan scan ./proyecto --ai --api-key "sk-..." --ai-model gpt-4o

# IA Local con Ollama (sin API key)
secure-scan scan ./proyecto --ai --ai-provider local
```

### Comandos Adicionales

```bash
# Ver ayuda
secure-scan --help

# Ver versión
secure-scan --version

# Inicializar configuración
secure-scan init

# Listar reglas disponibles
secure-scan rules

# Filtrar reglas por lenguaje
secure-scan rules -l python
```

## 🦠 Detección de Malware en Dependencias

Secure-Scan escanea las dependencias instaladas en busca de código malicioso. Actualmente detecta **17 patrones de malware**:

### Categorías de Malware Detectado

| Categoría | Descripción | Ejemplos |
|-----------|-------------|----------|
| 🚪 **Backdoors** | Acceso remoto no autorizado | Reverse shells, conexiones C2, robo de SSH keys |
| ⛏️ **Cryptominers** | Minería de criptomonedas | APIs de Stratum, CoinHive, MoneroOcean |
| 🔓 **Data Stealers** | Robo de información | Credenciales, tokens, variables de entorno |
| 📥 **Loaders** | Descarga de payloads | eval(require('http').get), dynamic imports |
| 🔐 **Ofuscación** | Código oculto | Base64 + eval, hex encoding, char codes |
| 📤 **Exfiltración** | Envío de datos | DNS tunneling, HTTP POST, WebSockets |
| 🛡️ **Anti-Análisis** | Evasión de detección | Anti-debug, sandbox detection |
| 📁 **File System** | Acceso sospechoso | /etc/passwd, ~/.ssh, credential stores |

### Directorios Escaneados

```
📂 node_modules/      → Paquetes npm/yarn
📂 vendor/            → Dependencias PHP Composer  
📂 venv/              → Entornos virtuales Python
📂 site-packages/     → Paquetes Python globales
📂 .venv/             → Entornos virtuales alternativos
```

### Verificación de Integridad

El escáner también verifica que las versiones instaladas coincidan con las declaradas en los lock files:

- ✅ `package-lock.json` vs `node_modules/*/package.json`
- ✅ `yarn.lock` vs `node_modules/*/package.json`
- ✅ `composer.lock` vs `vendor/*/composer.json`
- ✅ `Pipfile.lock` vs `venv/lib/python*/site-packages/`

## 🌍 Idiomas

Secure-Scan soporta reportes en múltiples idiomas:

| Idioma | Código | Por Defecto |
|--------|--------|-------------|
| 🇪🇸 Español | `es` | ✅ Sí |
| 🇬🇧 Inglés | `en` | No |

```bash
# Reporte en español (por defecto)
secure-scan scan ./proyecto -o reporte

# Reporte en inglés
secure-scan scan ./proyecto -o report --lang en
```

## 📊 Niveles de Severidad

| Nivel | Descripción |
|-------|-------------|
| 🔵 Info | Información relevante, buenas prácticas |
| 🟢 Bajo | Riesgo bajo, impacto limitado |
| 🟡 Medio | Riesgo moderado, requiere atención |
| 🟠 Alto | Riesgo alto, corregir pronto |
| 🔴 Crítico | Riesgo crítico, corregir inmediatamente |

## 🛡️ Estándares de Seguridad

Todos los hallazgos se mapean a estándares reconocidos:

| Estándar | Descripción | Uso |
|----------|-------------|-----|
| **OWASP Top 10** | Top 10 riesgos de seguridad web | Vulnerabilidades web |
| **CWE** | Common Weakness Enumeration | Debilidades de código |
| **MITRE ATT&CK** | Tácticas y Técnicas de Atacantes | Detección de malware |
| **SANS Top 25** | Errores de Software Más Peligrosos | Priorización |

### Ejemplos de Mapeo

| Hallazgo | CWE | OWASP | MITRE ATT&CK |
|----------|-----|-------|--------------|
| SQL Injection | CWE-89 | A03:2021 | T1190 |
| XSS | CWE-79 | A03:2021 | T1059.007 |
| Reverse Shell | CWE-506 | - | T1059, T1571 |
| Cryptominer | CWE-400 | - | T1496 |
| Data Exfiltration | CWE-200 | - | T1041 |

## 🔧 Configuración

Crea un archivo `secure-scan.config.json` en la raíz del proyecto:

```json
{
  "exclude": ["node_modules", "dist", "vendor"],
  "languages": ["javascript", "python", "php"],
  "minSeverity": "low",
  "language": "es",
  "ai": {
    "enabled": false,
    "provider": "openai",
    "model": "gpt-4"
  },
  "rules": {
    "disabled": [],
    "custom": []
  }
}
```

### Opciones de Configuración

| Opción | Descripción | Valor por Defecto |
|--------|-------------|-------------------|
| `exclude` | Patrones a excluir | `["node_modules", "dist"]` |
| `languages` | Lenguajes a analizar | Todos |
| `minSeverity` | Severidad mínima | `low` |
| `language` | Idioma del reporte | `es` |
| `ai.enabled` | Habilitar análisis IA | `false` |

## 🤖 Uso de Modelos de IA Locales

Secure-Scan soporta el uso de **modelos de IA locales** para análisis de seguridad sin depender de APIs externas.

### Configuración para IA Local

Modifica la sección `ai` en `secure-scan.config.json`:

```json
{
  "ai": {
    "enabled": true,
    "provider": "local",
    "endpoint": "http://localhost:11434/api/generate",
    "enhanceFindings": true,
    "generateSummary": true,
    "maxTokens": 4096,
    "temperature": 0.1
  }
}
```

### Herramientas de IA Local Compatibles

| Herramienta | Endpoint por Defecto | Modelos Recomendados |
|-------------|---------------------|----------------------|
| **Ollama** | `http://localhost:11434/api/generate` | `codellama`, `llama3`, `mistral`, `deepseek-coder` |
| **LM Studio** | `http://localhost:1234/v1/completions` | Cualquier modelo GGUF |
| **LocalAI** | `http://localhost:8080/v1/completions` | Compatible con OpenAI API |
| **text-generation-webui** | `http://localhost:5000/api/generate` | Varios formatos |

### Ejemplo con Ollama (Recomendado)

1. **Instalar Ollama**: Descarga desde [ollama.ai](https://ollama.ai)

2. **Descargar un modelo optimizado para código**:
   ```bash
   # CodeLlama - especializado en código
   ollama pull codellama
   
   # DeepSeek Coder - excelente para análisis de seguridad
   ollama pull deepseek-coder
   
   # Mistral - buen balance rendimiento/calidad
   ollama pull mistral
   ```

3. **Ollama se ejecuta automáticamente** en `http://localhost:11434`

4. **Ejecutar escaneo con IA local**:
   ```bash
   secure-scan scan ./mi-proyecto --ai
   ```

### Ejemplo con LM Studio

1. Descarga [LM Studio](https://lmstudio.ai/)
2. Descarga un modelo GGUF (ej: `codellama-7b-instruct.Q4_K_M.gguf`)
3. Inicia el servidor local en LM Studio
4. Configura el endpoint:
   ```json
   {
     "ai": {
       "enabled": true,
       "provider": "local",
       "endpoint": "http://localhost:1234/v1/completions"
     }
   }
   ```

### Ventajas de IA Local

- 🔒 **Privacidad total** - Tu código nunca sale de tu máquina
- 💰 **Sin costos** - No requiere suscripciones ni API keys
- ⚡ **Sin límites** - Analiza todo el código que necesites
- 🌐 **Offline** - Funciona sin conexión a internet

## 📈 Hoja de Ruta

- [x] Fase 1: Análisis estático básico (JavaScript, Python, PHP, Java, C/C++, C#)
- [x] Fase 2: Integración de IA (OpenAI, Anthropic, modelos locales con Ollama)
- [x] Fase 3: Soporte multiidioma (reportes en español/inglés)
- [x] Fase 4: Análisis de dependencias (SCA)
  - [x] Parsers para 6 ecosistemas (npm, pip, composer, maven, nuget, go)
  - [x] Detección de CVEs y vulnerabilidades conocidas
  - [x] Detección de typosquatting
  - [x] **Escaneo de dependencias instaladas con detección de malware**
  - [x] **17 patrones de malware (backdoors, cryptominers, stealers, etc.)**
  - [x] **Verificación de integridad (lock files vs instalados)**
- [ ] Fase 5: Integración CI/CD (GitHub Actions, GitLab CI, Azure DevOps)
- [ ] Fase 6: Análisis dinámico (DAST)
- [ ] Fase 7: Dashboard web en tiempo real

## ⚠️ Advertencias de Seguridad

- Esta herramienta **NUNCA** ejecuta código del proyecto analizado
- Diseñada exclusivamente para **auditoría defensiva**
- No genera ni contiene malware funcional
- Uso responsable y ético únicamente

## 💻 Ejemplo de Salida

```
🔐 Secure-Scan v2.0.0

📂 Escaneando: ./mi-proyecto
🔍 Archivos analizados: 156
📏 Líneas de código: 24,853
⏱️  Tiempo: 2.34s

📊 Resultados del Escaneo:
┌──────────────────────────────────────────────────────────────┐
│  🔴 Crítico: 5    │  🟠 Alto: 12    │  🟡 Medio: 23         │
│  🟢 Bajo: 8       │  🔵 Info: 3     │  Total: 51            │
└──────────────────────────────────────────────────────────────┘

📦 Dependencias Analizadas:
┌──────────────────────────────────────────────────────────────┐
│  📋 Manifiestos: 3      │  📦 Paquetes: 847               │
│  🔓 CVEs: 12            │  🦠 Malware: 0                   │
│  ⚠️  Typosquatting: 1   │  ✅ Integridad: OK              │
└──────────────────────────────────────────────────────────────┘

📈 Puntuación de Riesgo: 72/100 (Alto)

📄 Reporte generado: ./security-report.html
```

## 📄 Licencia

MIT License - Ver [LICENSE](LICENSE)

## 🤝 Contribuir

1. Fork el repositorio
2. Crea una rama (`git checkout -b feature/nueva-funcionalidad`)
3. Commit tus cambios (`git commit -m 'Añadir nueva funcionalidad'`)
4. Push a la rama (`git push origin feature/nueva-funcionalidad`)
5. Abre un Pull Request

## 📞 Soporte

- 📧 Email: soporte@secure-scan.dev
- 🐛 Issues: [GitHub Issues](https://github.com/your-org/secure-scan/issues)
- 📖 Documentación: [docs/](docs/)

---

**Desarrollado con ❤️ para la comunidad de seguridad**

---
**Autor:** Luis000923