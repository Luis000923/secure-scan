/**
 * Utilidad de Logging
 * Registro basado en Winston para entornos de producción
 */

import winston from 'winston';
import chalk from 'chalk';

const { combine, timestamp, printf, colorize } = winston.format;

/**
 * Custom log format for console output
 */
const consoleFormat = printf(({ level, message, timestamp }) => {
  const icons: Record<string, string> = {
    error: '❌',
    warn: '⚠️',
    info: 'ℹ️',
    debug: '🔍',
    verbose: '📝'
  };
  
  const icon = icons[level] || '';
  return `${chalk.gray(timestamp)} ${icon} ${message}`;
});

/**
 * Custom log format for file output
 */
const fileFormat = printf(({ level, message, timestamp }) => {
  return `${timestamp} [${level.toUpperCase()}] ${message}`;
});

/**
 * Create logger instance
 */
export const logger = winston.createLogger({
  level: process.env.LOG_LEVEL || 'info',
  format: combine(
    timestamp({ format: 'YYYY-MM-DD HH:mm:ss' })
  ),
  transports: [
    // Console transport with colors
    new winston.transports.Console({
      format: combine(
        colorize(),
        consoleFormat
      )
    })
  ]
});

/**
 * Add file transport for production
 */
export function enableFileLogging(logDir: string): void {
  logger.add(new winston.transports.File({
    filename: `${logDir}/error.log`,
    level: 'error',
    format: fileFormat
  }));
  
  logger.add(new winston.transports.File({
    filename: `${logDir}/combined.log`,
    format: fileFormat
  }));
}

/**
 * Set log level
 */
export function setLogLevel(level: string): void {
  logger.level = level;
}

/**
 * Registrar inicio de escaneo
 */
export function logScanStart(projectPath: string): void {
  logger.info(chalk.cyan('═'.repeat(60)));
  logger.info(chalk.cyan.bold('🔐 Secure-Scan - Herramienta SAST'));
  logger.info(chalk.cyan('═'.repeat(60)));
  logger.info(`📁 Scanning project: ${chalk.yellow(projectPath)}`);
  logger.info(chalk.gray('─'.repeat(60)));
}

/**
 * Log scan progress
 */
export function logProgress(current: number, total: number, fileName: string): void {
  const percent = Math.round((current / total) * 100);
  const bar = '█'.repeat(Math.floor(percent / 5)) + '░'.repeat(20 - Math.floor(percent / 5));
  logger.info(`[${bar}] ${percent}% - ${fileName}`);
}

/**
 * Log finding
 */
export function logFinding(severity: string, title: string, file: string, line: number): void {
  const severityColors: Record<string, (str: string) => string> = {
    critical: chalk.bgRed.white,
    high: chalk.red,
    medium: chalk.yellow,
    low: chalk.green,
    info: chalk.blue
  };
  
  const colorFn = severityColors[severity] || chalk.white;
  logger.info(`${colorFn(`[${severity.toUpperCase()}]`)} ${title} at ${chalk.cyan(file)}:${chalk.yellow(line)}`);
}

/**
 * Log scan complete
 */
export function logScanComplete(
  totalFiles: number,
  totalFindings: number,
  duration: number,
  riskScore: number
): void {
  logger.info(chalk.gray('─'.repeat(60)));
  logger.info(chalk.cyan.bold('📊 Scan Complete'));
  logger.info(`   📁 Files scanned: ${chalk.yellow(totalFiles)}`);
  logger.info(`   🔍 Findings: ${chalk.yellow(totalFindings)}`);
  logger.info(`   ⏱️  Duration: ${chalk.yellow(`${(duration / 1000).toFixed(2)}s`)}`);
  logger.info(`   📈 Risk Score: ${getRiskScoreDisplay(riskScore)}`);
  logger.info(chalk.cyan('═'.repeat(60)));
}

/**
 * Get colored risk score display
 */
function getRiskScoreDisplay(score: number): string {
  if (score >= 80) return chalk.bgRed.white(` ${score}/100 CRITICAL `);
  if (score >= 60) return chalk.red(`${score}/100 HIGH`);
  if (score >= 40) return chalk.yellow(`${score}/100 MEDIUM`);
  if (score >= 20) return chalk.green(`${score}/100 LOW`);
  return chalk.blue(`${score}/100 SAFE`);
}

export default logger;
