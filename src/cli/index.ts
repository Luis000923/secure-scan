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

import { SecurityScanner } from '../core/securityScanner';
import { ScanConfig, Severity, SupportedLanguage } from '../types';
import { setLogLevel } from '../utils/logger';

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
  .option('--api-key <key>', 'API key para el proveedor de IA (auto-detecta OpenAI, Anthropic, Google)')
  .option('--ai-provider <provider>', 'Proveedor de IA (openai, anthropic, google, gemini, local, auto)', 'auto')
  .option('--ai-model <model>', 'Modelo de IA a usar (gpt-4o, gpt-4, gpt-3.5-turbo, claude-3-sonnet, gemini-1.5-flash, etc.)')
  .option('--ai-endpoint <url>', 'URL del endpoint para IA local (default: http://localhost:11434/api/generate)')
  .option('-v, --verbose', 'Mostrar salida detallada')
  .option('--json', 'Mostrar resultados como JSON en stdout')
  .option('--max-file-size <bytes>', 'Tamaño máximo de archivo a escanear (en bytes)', '5242880')
  .option('--lang <language>', 'Idioma del reporte: es (español) o en (inglés)', 'es')
  .action(async (projectPath: string, options: any) => {
    try {
      // Validate project path
      const resolvedPath = path.resolve(projectPath);
      if (!fs.existsSync(resolvedPath)) {
        console.error(chalk.red(`❌ Error: La ruta no existe: ${resolvedPath}`));
        process.exit(1);
      }

      // Set log level
      if (options.verbose) {
        setLogLevel('debug');
      }

      // Parse languages
      let languages: SupportedLanguage[] | undefined;
      if (options.languages) {
        languages = options.languages.split(',').map((l: string) => l.trim().toLowerCase());
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
          provider: options.aiProvider,
          apiKey: options.apiKey || process.env.OPENAI_API_KEY,
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
      exclude: ['node_modules', 'dist', 'vendor', '.git'],
      languages: ['javascript', 'typescript', 'python', 'php', 'java', 'c', 'cpp', 'csharp'],
      minSeverity: 'low',
      language: 'es',
      ai: {
        enabled: false,
        provider: 'openai',
        model: 'gpt-4'
      },
      rules: {
        disabled: [],
        custom: []
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
  .action(async (options: any) => {
    const { getAllRules } = await import('../rules');
    let rules = getAllRules();

    if (options.language) {
      rules = rules.filter(r => r.languages.includes(options.language));
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
