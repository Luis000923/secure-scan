# 🔐 Secure-Scan

[![CI](https://github.com/Luis000923/secure-scan/actions/workflows/ci.yml/badge.svg)](https://github.com/Luis000923/secure-scan/actions/workflows/ci.yml)
[![Licencia: MIT](https://img.shields.io/badge/Licencia-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Versión Node.js](https://img.shields.io/badge/node-%3E%3D18.0.0-brightgreen)](https://nodejs.org)
[![Idioma](https://img.shields.io/badge/Idioma-Español%20%7C%20English-blue.svg)](#-idiomas)

**Secure-Scan** es una herramienta de **Análisis Estático de Seguridad de Aplicaciones (SAST)** diseñada para detectar vulnerabilidades y código malicioso en repositorios de código sin ejecutarlos.

## 🎯 Características Principales

- ✅ **Análisis Estático Puro** - Sin ejecución, compilación ni interpretación de código
- 🔍 **Detección de Vulnerabilidades** - SQL Injection, XSS, CSRF, Command Injection, etc.
- 🦠 **Detección de Malware** - Backdoors, keyloggers, cryptominers, payloads ocultos
- 🌐 **Multi-lenguaje** - JavaScript, Python, PHP, Java, C/C++, C#
- 📊 **Reportes HTML Profesionales** - Estilo auditoría de seguridad
- 🤖 **IA Integrada** - Análisis inteligente de patrones complejos
- 📋 **Mapeo a Estándares** - OWASP Top 10, CWE, MITRE ATT&CK, SANS Top 25
- 🌍 **Multiidioma** - Reportes en español (por defecto) o inglés


## 🚀 Instalación

### Opción 1: Instalación Global (Recomendada)

```bash
npm install -g secure-scan
```
Así se evitan usar la clonación del repositorio.

### Desinstalar la herramienta
```bash
npm uninstall -g secure-scan
```

### Opción 2: Clonar el repositorio
```bash
git clone https://github.com/Luis000923/secure-scan.git
cd secure-scan
```

Instalar dependencias y compilar:
```bash
npm install
```

Instalar globalmente:
```bash
npm link
```

### Verificar instalación
```bash
secure -V
secure --version
```

## 📖 Uso

> **AVISO:** Modificar el archivo `secure-scan.config.json` para configurar la herramienta según tus necesidades.

### Escaneo Básico

```bash
# Escanear un proyecto
secure scan ./mi-proyecto

# O usando la ruta completa
secure scan "C:\Users\TuUsuario\Proyectos\mi-proyecto"

# Personalizar escaneos con
secure init
```

### Comando Sugerido
```bash
secure scan "ruta-proyecto-analizar" -v --ai --ai-provider local -o "ruta-resultado-escaneo\nombre-resultado"
```

### Opciones Disponibles

```bash
# Escanear con reporte HTML personalizado
secure scan ./proyecto -o ./mi-reporte

# Modo verbose (más detalles)
secure scan ./proyecto -v

# Usar análisis de IA (requiere API key)
secure scan ./proyecto --ai --api-key TU_API_KEY

# Especificar lenguajes
secure scan ./proyecto --languages javascript,python

# Reporte en inglés
secure scan ./proyecto --lang en

# Reporte en español (por defecto)
secure scan ./proyecto --lang es
```

### Comandos Adicionales

```bash
# Ver ayuda
secure --help

# Ver versión
secure --version

# Inicializar configuración
secure init

# Listar reglas disponibles
secure rules

# Filtrar reglas por lenguaje
secure rules -l python
```


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

## 🌍 Idiomas

Secure-Scan soporta reportes en múltiples idiomas:

| Idioma | Código | Por Defecto |
|--------|--------|-------------|
| 🇪🇸 Español | `es` | ✅ Sí |
| 🇬🇧 Inglés | `en` | No |

```bash
# Reporte en español (por defecto)
secure scan ./proyecto -o reporte

# Reporte en inglés
secure scan ./proyecto -o report --lang en
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

Todos los hallazgos se mapean a:

- **OWASP Top 10** - Open Web Application Security Project
- **CWE** - Common Weakness Enumeration (Enumeración de Debilidades Comunes)
- **MITRE ATT&CK** - Tácticas y Técnicas de Atacantes
- **SANS Top 25** - Errores de Software Más Peligrosos

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
   secure scan ./mi-proyecto --ai
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

- [x] Fase 1: Análisis estático básico
- [x] Fase 2: Integración de IA
- [x] Fase 3: Soporte multiidioma (español/inglés)
- [ ] Fase 4: Análisis de dependencias

## ⚠️ Advertencias de Seguridad

- Esta herramienta **NUNCA** ejecuta código del proyecto analizado
- Diseñada exclusivamente para **auditoría defensiva**
- No genera ni contiene malware funcional
- Uso responsable y ético únicamente

## 📄 Licencia

MIT License - Ver [LICENSE](LICENSE)

## 🤝 Contribuir

1. Fork el repositorio
2. Crea una rama (`git checkout -b feature/nueva-funcionalidad`)
3. Commit tus cambios (`git commit -m 'Añadir nueva funcionalidad'`)
4. Push a la rama (`git push origin feature/nueva-funcionalidad`)
5. Abre un Pull Request

- 📖 Documentación: [docs/](docs/)

---

**Desarrollado con ❤️ para la comunidad de seguridad**
