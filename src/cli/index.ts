#!/usr/bin/env node
/**
 * Secure-Scan CLI
 * Herramienta de Análisis Estático de Seguridad de Aplicaciones
 */

import { Command } from 'commander';
import chalk from 'chalk';
import ora from 'ora';
import * as path from 'path';
import * as fs from 'fs';

import { SecurityScanner } from '../analyzers/core/securityScanner';
import { ScanConfig, Severity, SupportedLanguage } from '../types';
import { setLogLevel } from '../utils/logger';

/**
 * Typed options for the scan command
 */
interface ScanCommandOptions {
  output?: string;
  languages?: string;
  exclude?: string;
  minSeverity: string;
  ai?: boolean;
  aiProvider: string;
  aiModel?: string;
  aiEndpoint?: string;
  apiKey?: string;
  verbose?: boolean;
  json?: boolean;
  maxFileSize: string;
  lang: string;
  fixSuggestions?: boolean;
}

/**
 * Typed options for the rules command
 */
interface RulesCommandOptions {
  language?: string;
}

// Información del paquete
const packageJson = require('../../package.json');

// Crear programa CLI
const program = new Command();

program
  .name('secure-scan')
  .version(packageJson.version)
  .description(chalk.cyan('🔐 Secure-Scan - Herramienta de Análisis Estático de Seguridad'));

/**
 * Scan command
 */
program
  .command('scan <path>')
  .description('Escanear un proyecto en busca de vulnerabilidades y código malicioso')
  .option('-o, --output <file>', 'Ruta del archivo de reporte (HTML o JSON)')
  .option('-l, --languages <langs>', 'Lista de lenguajes separados por coma')
  .option('-e, --exclude <patterns>', 'Patrones a excluir separados por coma')
  .option('--min-severity <level>', 'Severidad mínima a reportar (info, low, medium, high, critical)', 'info')
  .option('--ai', 'Habilitar análisis con IA')
  .option('--ai-provider <provider>', 'Proveedor de IA (openai, anthropic, google, gemini, local, auto)', 'auto')
  .option('--ai-model <model>', 'Modelo de IA a usar (gpt-4o, gpt-4, gpt-3.5-turbo, claude-3-sonnet, gemini-1.5-flash, etc.)')
  .option('--ai-endpoint <url>', 'URL del endpoint para IA local (default: http://localhost:11434/api/generate)')
  .option('-v, --verbose', 'Mostrar salida detallada')
  .option('--json', 'Mostrar resultados como JSON en stdout')
  .option('--max-file-size <bytes>', 'Tamaño máximo de archivo a escanear (en bytes)', '5242880')
  .option('--lang <language>', 'Idioma del reporte: es (español) o en (inglés)', 'es')
  .option('--api-key <key>', '[DEPRECADO] API key para IA (use variables de entorno en su lugar)')
  .option('--fix-suggestions', 'Mostrar sugerencias de corrección en la consola')
  .action(async (projectPath: string, options: ScanCommandOptions) => {
    try {
      // Validate project path
      const resolvedPath = path.resolve(projectPath);
      if (!fs.existsSync(resolvedPath)) {
        console.error(chalk.red(`❌ Error: La ruta no existe: ${resolvedPath}`));
        process.exit(1);
      }

      // Warn about deprecated --api-key flag
      if (options.apiKey) {
        console.warn(chalk.yellow('⚠️  [DEPRECADO] El flag --api-key expone credenciales en la lista de procesos.'));
        console.warn(chalk.yellow('   Use variables de entorno en su lugar:'));
        console.warn(chalk.gray('   export OPENAI_API_KEY="sk-..."'));
        console.warn('');
      }

      // Set log level
      if (options.verbose) {
        setLogLevel('debug');
      }

      // Parse languages
      let languages: SupportedLanguage[] | undefined;
      if (options.languages) {
        languages = options.languages.split(',').map((l: string) => l.trim().toLowerCase()) as SupportedLanguage[];
      }

      // Parse exclude patterns
      const exclude = options.exclude ? options.exclude.split(',').map((p: string) => p.trim()) : [];

      // Parse severity
      const severityMap: Record<string, Severity> = {
        'info': Severity.INFO,
        'low': Severity.LOW,
        'medium': Severity.MEDIUM,
        'high': Severity.HIGH,
        'critical': Severity.CRITICAL
      };
      const minSeverity = severityMap[options.minSeverity.toLowerCase()] || Severity.INFO;

      // Parse language option
      const reportLang = options.lang === 'en' ? 'en' : 'es';

      // Build config
      // Default endpoint for local AI (Ollama)
      const defaultLocalEndpoint = 'http://localhost:11434/api/generate';
      const defaultLocalModel = 'codellama:7b-instruct';

      // Get API key — prefer env vars, allow deprecated --api-key as fallback
      const getApiKey = (): string | undefined => {
        // Check for provider-specific keys first
        const providerKeys: Record<string, string[]> = {
          'openai': ['OPENAI_API_KEY'],
          'anthropic': ['ANTHROPIC_API_KEY'],
          'google': ['GOOGLE_API_KEY', 'GEMINI_API_KEY'],
          'gemini': ['GOOGLE_API_KEY', 'GEMINI_API_KEY'],
          'auto': ['OPENAI_API_KEY', 'ANTHROPIC_API_KEY', 'GOOGLE_API_KEY', 'GEMINI_API_KEY']
        };

        const keysToCheck = providerKeys[options.aiProvider] || providerKeys['auto'];

        for (const envVar of keysToCheck) {
          const key = process.env[envVar];
          if (key) {
            return key;
          }
        }

        // Fallback to deprecated --api-key flag
        if (options.apiKey) {
          return options.apiKey;
        }

        return undefined;
      };

      // Warn if AI is enabled but no API key is found
      const apiKey = options.ai ? getApiKey() : undefined;
      if (options.ai && !apiKey && options.aiProvider !== 'local') {
        console.warn(chalk.yellow('⚠️  Advertencia: Análisis con IA habilitado pero no se encontró API key.'));
        console.warn(chalk.yellow('   Configure una de las siguientes variables de entorno:'));
        console.warn(chalk.gray('   • OPENAI_API_KEY     - Para OpenAI GPT'));
        console.warn(chalk.gray('   • ANTHROPIC_API_KEY  - Para Anthropic Claude'));
        console.warn(chalk.gray('   • GOOGLE_API_KEY     - Para Google Gemini'));
        console.warn(chalk.yellow('   O use --ai-provider local para modelos locales.'));
        console.warn('');
      }

      const config: ScanConfig = {
        projectPath: resolvedPath,
        outputPath: options.output,
        languages,
        exclude,
        minSeverity,
        useAI: options.ai,
        verbose: options.verbose,
        maxFileSize: parseInt(options.maxFileSize),
        language: reportLang,
        aiConfig: options.ai ? {
          provider: options.aiProvider as 'openai' | 'anthropic' | 'google' | 'gemini' | 'local' | 'auto',
          apiKey: apiKey,
          model: options.aiModel || (options.aiProvider === 'local' ? defaultLocalModel : undefined),
          endpoint: options.aiEndpoint || (options.aiProvider === 'local' ? defaultLocalEndpoint : undefined)
        } : undefined
      };

      // Run scan
      const spinner = ora('Inicializando escaneo de seguridad...').start();

      const scanner = new SecurityScanner(config);

      spinner.text = 'Escaneando archivos...';
      const result = await scanner.scan();

      spinner.succeed('¡Escaneo completado!');

      // Output results
      if (options.json) {
        console.log(JSON.stringify(result, null, 2));
      } else {
        // Print summary
        console.log('');
        console.log(chalk.cyan('═'.repeat(60)));
        console.log(chalk.cyan.bold('📊 Resumen del Escaneo'));
        console.log(chalk.cyan('═'.repeat(60)));
        console.log(`   📁 Archivos escaneados: ${chalk.yellow(result.stats.totalFiles)}`);
        console.log(`   📝 Líneas de código: ${chalk.yellow(result.stats.totalLines)}`);
        console.log(`   🔍 Hallazgos: ${chalk.yellow(result.findings.length)}`);
        console.log(`   ⏱️  Duración: ${chalk.yellow((result.stats.duration / 1000).toFixed(2) + 's')}`);
        console.log('');

        // Severity breakdown
        const { findingsBySeverity } = result.stats;
        console.log(chalk.bold('   Desglose por Severidad:'));
        console.log(`   ${chalk.bgRed.white(' CRÍTICO ')} ${findingsBySeverity.critical || 0}`);
        console.log(`   ${chalk.red(' ALTO ')} ${findingsBySeverity.high || 0}`);
        console.log(`   ${chalk.yellow(' MEDIO ')} ${findingsBySeverity.medium || 0}`);
        console.log(`   ${chalk.green(' BAJO ')} ${findingsBySeverity.low || 0}`);
        console.log(`   ${chalk.blue(' INFO ')} ${findingsBySeverity.info || 0}`);
        console.log('');

        // Language breakdown
        const { filesByLanguage } = result.stats;
        const langEntries = Object.entries(filesByLanguage).sort(([, a], [, b]) => b - a);
        if (langEntries.length > 0) {
          console.log(chalk.bold('   Archivos por Lenguaje:'));
          for (const [lang, count] of langEntries) {
            console.log(`   ${chalk.gray('•')} ${lang}: ${chalk.yellow(String(count))}`);
          }
          console.log('');
        }

        // Risk score
        const riskColor = result.riskScore >= 70 ? chalk.red :
          result.riskScore >= 40 ? chalk.yellow : chalk.green;
        console.log(`   📈 Puntuación de Riesgo: ${riskColor(result.riskScore + '/100')} (${result.riskLevel.toUpperCase()})`);

        // Report location - ensure correct extension is shown
        if (options.output) {
          let reportPath = path.resolve(options.output);
          const ext = path.extname(reportPath).toLowerCase();
          // Add .html extension if no extension provided
          if (ext === '') {
            reportPath = `${reportPath}.html`;
          }
          console.log('');
          console.log(`   📄 Reporte guardado en: ${chalk.cyan(reportPath)}`);
        }

        console.log(chalk.cyan('═'.repeat(60)));
        console.log('');

        // Exit with error code if critical findings
        if (findingsBySeverity.critical > 0) {
          process.exit(2);
        } else if (findingsBySeverity.high > 0) {
          process.exit(1);
        }
      }

    } catch (error) {
      console.error(chalk.red(`❌ Error en el escaneo: ${error}`));
      process.exit(1);
    }
  });

/**
 * Init command - create config file
 */
program
  .command('init')
  .description('Inicializar configuración de secure-scan en el directorio actual')
  .action(() => {
    const configPath = path.join(process.cwd(), 'secure-scan.config.json');

    if (fs.existsSync(configPath)) {
      console.log(chalk.yellow('⚠️ El archivo de configuración ya existe: secure-scan.config.json'));
      return;
    }

    const defaultConfig = {
      "$schema": "https://raw.githubusercontent.com/Sobdev/secure-scan/main/schema.json",
      version: "1.0.0",

      scan: {
        languages: [
          "javascript",
          "typescript",
          "python",
          "php",
          "java",
          "c",
          "cpp",
          "csharp",
          "dockerfile",
          "yaml",
          "terraform"
        ],
        exclude: [
          "node_modules",
          "dist",
          "vendor",
          ".git"
        ],
        include: [],
        maxFileSize: 1048576,
        maxFiles: 10000,
        followSymlinks: false
      },

      rules: {
        enabled: true,
        categories: {
          vulnerability: true,
          malware: true
        },
        severity: {
          critical: true,
          high: true,
          medium: true,
          low: true,
          info: false
        },
        customRulesPath: null,
        disabledRules: []
      },

      ai: {
        enabled: false,
        provider: "local",
        model: "codellama:7b-instruct",
        apiKey: null,
        endpoint: "http://localhost:11434/api/generate",
        enhanceFindings: true,
        generateSummary: true,
        maxTokens: 4096,
        temperature: 0.1,
        performance: {
          parallelRequests: 2,
          numGpuLayers: -1,
          numThreads: 8,
          contextSize: 4096,
          batchSize: 512,
          enableCache: true,
          useMmap: true,
          useMlock: false,
          timeout: 120000
        }
      },

      output: {
        format: "html",
        path: "./secure-scan-report",
        filename: "security-report",
        includeSource: true,
        groupBy: "severity",
        sortBy: "severity"
      },

      scoring: {
        enabled: true,
        weights: {
          critical: 100,
          high: 50,
          medium: 20,
          low: 5,
          info: 1
        },
        categoryMultipliers: {
          vulnerability: 1.0,
          malware: 1.5
        },
        thresholds: {
          fail: 70,
          warn: 40
        }
      },

      performance: {
        parallelism: 4,
        timeout: 300000,
        cacheEnabled: true,
        cachePath: ".secure-scan-cache"
      },

      integrations: {
        git: {
          enabled: true,
          scanOnlyChanged: false,
          baseBranch: "main"
        },
        sarif: {
          enabled: false,
          path: "./results.sarif"
        }
      },

      logging: {
        level: "info",
        file: null,
        colors: true
      }
    };

    fs.writeFileSync(configPath, JSON.stringify(defaultConfig, null, 2));
    console.log(chalk.green('✅ Archivo secure-scan.config.json creado'));
  });

/**
 * List rules command
 */
program
  .command('rules')
  .description('Listar todas las reglas de seguridad disponibles')
  .option('-l, --language <lang>', 'Filtrar por lenguaje')
  .action(async (options: RulesCommandOptions) => {
    const { getAllRules } = await import('../rules');
    let rules = getAllRules();

    if (options.language) {
      rules = rules.filter(r => r.languages.includes(options.language as SupportedLanguage));
    }

    console.log(chalk.cyan('\n📋 Reglas de Seguridad Disponibles\n'));
    console.log(chalk.gray('─'.repeat(80)));

    for (const rule of rules) {
      const severityColor = {
        critical: chalk.red,
        high: chalk.red,
        medium: chalk.yellow,
        low: chalk.green,
        info: chalk.blue
      }[rule.severity] || chalk.white;

      console.log(`${chalk.bold(rule.id)} ${severityColor(`[${rule.severity.toUpperCase()}]`)}`);
      console.log(`  ${rule.name}`);
      console.log(`  ${chalk.gray(rule.languages.join(', '))}`);
      console.log('');
    }

    console.log(chalk.gray('─'.repeat(80)));
    console.log(`Total: ${rules.length} reglas\n`);
  });

/**
 * Comando de versión
 */
program
  .command('version')
  .description('Mostrar información de versión')
  .action(() => {
    console.log(chalk.cyan(`\n🔐 Secure-Scan v${packageJson.version}`));
    console.log(chalk.gray('Herramienta de Análisis Estático de Seguridad (SAST)\n'));
  });

// Procesar argumentos
program.parse();

// Mostrar ayuda si no hay comando
if (process.argv.length === 2) {
  console.log(chalk.cyan(`
  🔐 Secure-Scan - Herramienta SAST
  
  Detecta vulnerabilidades y código malicioso en tus proyectos.
  
  Uso:
    secure-scan scan <ruta> [opciones]
    secure-scan init
    secure-scan rules
    secure-scan --help
  
  Example:
    secure-scan scan ./my-project --output report.html
  `));
}
