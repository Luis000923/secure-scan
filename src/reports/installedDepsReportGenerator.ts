/**
 * Installed Dependencies Report Generator
 * Generates HTML report section for installed dependencies malware scan
 */

import {
  InstalledDependenciesScanResult,
  InstalledMalwareFinding,
  IntegrityIssue,
  SuspiciousScriptFinding
} from '../dependencies/installed/types';
import { MalwareIndicator } from '../dependencies/types';
import { Severity } from '../types';

/**
 * Generate HTML section for installed dependencies analysis
 */
export function generateInstalledDependenciesSection(
  result: InstalledDependenciesScanResult,
  language: string = 'es'
): string {
  const t = getTranslations(language);
  
  return `
    <!-- Installed Dependencies Malware Analysis Section -->
    <section class="installed-deps-section" id="installed-deps">
      <h2 class="section-title">
        <span class="section-icon">🔍</span>
        ${t.title}
      </h2>
      
      ${generateInstalledSummary(result, t)}
      
      ${result.malwareFindings.length > 0 ? generateMalwareFindings(result.malwareFindings, t) : ''}
      
      ${result.integrityIssues.length > 0 ? generateIntegrityIssues(result.integrityIssues, t) : ''}
      
      ${result.suspiciousScripts.length > 0 ? generateSuspiciousScripts(result.suspiciousScripts, t) : ''}
      
      ${generateScannedFolders(result, t)}
    </section>
    
    ${getInstalledDepsStyles()}
  `;
}

/**
 * Generate summary section
 */
function generateInstalledSummary(result: InstalledDependenciesScanResult, t: any): string {
  const stats = result.stats;
  
  const totalIssues = stats.malwareFindingsCount + stats.integrityIssuesCount + stats.suspiciousScriptsCount;
  const statusClass = totalIssues === 0 ? 'status-secure' : 
                      stats.malwareFindingsCount > 0 ? 'status-critical' : 'status-warning';
  const statusIcon = totalIssues === 0 ? '✅' : 
                     stats.malwareFindingsCount > 0 ? '🚨' : '⚠️';
  const statusText = totalIssues === 0 ? t.noMalwareFound : 
                     stats.malwareFindingsCount > 0 ? t.malwareDetected : t.issuesFound;

  return `
    <div class="installed-summary">
      <div class="summary-status ${statusClass}">
        <span class="status-icon">${statusIcon}</span>
        <span class="status-text">${statusText}</span>
      </div>
      
      <div class="summary-stats">
        <div class="stat-box">
          <span class="stat-value">${stats.totalPackagesFound}</span>
          <span class="stat-label">${t.packagesScanned}</span>
        </div>
        <div class="stat-box">
          <span class="stat-value">${stats.totalFilesScanned.toLocaleString()}</span>
          <span class="stat-label">${t.filesScanned}</span>
        </div>
        <div class="stat-box ${stats.malwareFindingsCount > 0 ? 'stat-critical' : ''}">
          <span class="stat-value">${stats.malwareFindingsCount}</span>
          <span class="stat-label">${t.malwareFindings}</span>
        </div>
        <div class="stat-box ${stats.integrityIssuesCount > 0 ? 'stat-warning' : ''}">
          <span class="stat-value">${stats.integrityIssuesCount}</span>
          <span class="stat-label">${t.integrityIssues}</span>
        </div>
        <div class="stat-box">
          <span class="stat-value">${formatDuration(stats.duration)}</span>
          <span class="stat-label">${t.scanTime}</span>
        </div>
      </div>
    </div>
  `;
}

/**
 * Generate malware findings section
 */
function generateMalwareFindings(findings: InstalledMalwareFinding[], t: any): string {
  const findingsByIndicator = groupByIndicator(findings);
  
  return `
    <div class="malware-findings">
      <h3 class="subsection-title">
        <span class="subsection-icon">🦠</span>
        ${t.malwareFindingsTitle}
      </h3>
      
      ${Object.entries(findingsByIndicator).map(([indicator, items]) => `
        <div class="indicator-group">
          <h4 class="indicator-title">
            ${getIndicatorIcon(indicator as MalwareIndicator)}
            ${getIndicatorName(indicator as MalwareIndicator, t)}
            <span class="indicator-count">(${items.length})</span>
          </h4>
          
          ${items.map(finding => `
            <div class="malware-finding severity-${finding.severity}">
              <div class="finding-header">
                <span class="severity-badge ${finding.severity}">${finding.severity.toUpperCase()}</span>
                <span class="finding-title">${finding.title}</span>
                <span class="confidence-badge">${finding.confidence}% ${t.confidence}</span>
              </div>
              
              <div class="finding-details">
                <div class="detail-row">
                  <span class="detail-label">${t.package}:</span>
                  <span class="detail-value package-name">${finding.package.name}@${finding.package.version}</span>
                </div>
                <div class="detail-row">
                  <span class="detail-label">${t.file}:</span>
                  <span class="detail-value file-path">${finding.filePath}</span>
                </div>
                ${finding.lineNumber ? `
                  <div class="detail-row">
                    <span class="detail-label">${t.line}:</span>
                    <span class="detail-value">${finding.lineNumber}</span>
                  </div>
                ` : ''}
                <div class="detail-row">
                  <span class="detail-label">${t.description}:</span>
                  <span class="detail-value">${finding.description}</span>
                </div>
              </div>
              
              ${finding.codeSnippet ? `
                <div class="code-snippet">
                  <pre><code>${escapeHtml(finding.codeSnippet)}</code></pre>
                </div>
              ` : ''}
              
              <div class="finding-recommendation">
                <span class="recommendation-icon">💡</span>
                <span class="recommendation-text">${finding.recommendation}</span>
              </div>
              
              ${finding.standards.length > 0 ? `
                <div class="finding-standards">
                  ${finding.standards.map(s => `
                    <span class="standard-badge ${s.standard.toLowerCase()}">${s.standard} ${s.id}</span>
                  `).join('')}
                </div>
              ` : ''}
            </div>
          `).join('')}
        </div>
      `).join('')}
    </div>
  `;
}

/**
 * Generate integrity issues section
 */
function generateIntegrityIssues(issues: IntegrityIssue[], t: any): string {
  return `
    <div class="integrity-issues">
      <h3 class="subsection-title">
        <span class="subsection-icon">🔐</span>
        ${t.integrityIssuesTitle}
      </h3>
      
      <table class="integrity-table">
        <thead>
          <tr>
            <th>${t.package}</th>
            <th>${t.issueType}</th>
            <th>${t.severity}</th>
            <th>${t.expected}</th>
            <th>${t.actual}</th>
            <th>${t.description}</th>
          </tr>
        </thead>
        <tbody>
          ${issues.map(issue => `
            <tr class="severity-${issue.severity}">
              <td class="package-name">${issue.packageName}</td>
              <td><span class="issue-type-badge ${issue.issueType}">${formatIssueType(issue.issueType, t)}</span></td>
              <td><span class="severity-badge ${issue.severity}">${issue.severity.toUpperCase()}</span></td>
              <td>${issue.expected || '-'}</td>
              <td>${issue.actual || '-'}</td>
              <td>${issue.description}</td>
            </tr>
          `).join('')}
        </tbody>
      </table>
    </div>
  `;
}

/**
 * Generate suspicious scripts section
 */
function generateSuspiciousScripts(scripts: SuspiciousScriptFinding[], t: any): string {
  return `
    <div class="suspicious-scripts">
      <h3 class="subsection-title">
        <span class="subsection-icon">⚠️</span>
        ${t.suspiciousScriptsTitle}
      </h3>
      
      ${scripts.map(script => `
        <div class="script-finding severity-${script.severity}">
          <div class="script-header">
            <span class="severity-badge ${script.severity}">${script.severity.toUpperCase()}</span>
            <span class="package-name">${script.packageName}</span>
            <span class="script-type">${script.script.type}</span>
          </div>
          
          <div class="script-command">
            <code>${escapeHtml(script.script.command)}</code>
          </div>
          
          <div class="script-description">${script.description}</div>
          
          ${script.riskIndicators.length > 0 ? `
            <div class="risk-indicators">
              <span class="indicators-label">${t.riskIndicators}:</span>
              ${script.riskIndicators.map(ri => `
                <span class="risk-indicator">${ri}</span>
              `).join('')}
            </div>
          ` : ''}
        </div>
      `).join('')}
    </div>
  `;
}

/**
 * Generate scanned folders section
 */
function generateScannedFolders(result: InstalledDependenciesScanResult, t: any): string {
  return `
    <div class="scanned-folders">
      <h3 class="subsection-title">
        <span class="subsection-icon">📁</span>
        ${t.scannedFolders}
      </h3>
      
      <table class="folders-table">
        <thead>
          <tr>
            <th>${t.folder}</th>
            <th>${t.type}</th>
            <th>${t.ecosystem}</th>
            <th>${t.packages}</th>
            <th>${t.size}</th>
            <th>${t.filesScanned}</th>
          </tr>
        </thead>
        <tbody>
          ${result.scannedFolders.map(folder => `
            <tr>
              <td class="folder-path">${folder.path}</td>
              <td>${folder.type}</td>
              <td><span class="ecosystem-badge ${folder.ecosystem}">${folder.ecosystem}</span></td>
              <td>${folder.packageCount}</td>
              <td>${formatBytes(folder.totalSizeBytes)}</td>
              <td>${folder.filesScanned.toLocaleString()}</td>
            </tr>
          `).join('')}
        </tbody>
      </table>
    </div>
  `;
}

/**
 * Get translations
 */
function getTranslations(language: string): any {
  const translations: Record<string, any> = {
    es: {
      title: 'Análisis de Malware en Dependencias Instaladas',
      noMalwareFound: 'No se detectó malware en las dependencias instaladas',
      malwareDetected: '¡MALWARE DETECTADO en dependencias!',
      issuesFound: 'Se encontraron problemas en las dependencias',
      packagesScanned: 'Paquetes escaneados',
      filesScanned: 'Archivos analizados',
      malwareFindings: 'Hallazgos de malware',
      integrityIssues: 'Problemas de integridad',
      scanTime: 'Tiempo de escaneo',
      malwareFindingsTitle: 'Detecciones de Malware',
      integrityIssuesTitle: 'Problemas de Integridad',
      suspiciousScriptsTitle: 'Scripts Post-Instalación Sospechosos',
      scannedFolders: 'Carpetas Escaneadas',
      package: 'Paquete',
      file: 'Archivo',
      line: 'Línea',
      description: 'Descripción',
      confidence: 'confianza',
      issueType: 'Tipo',
      severity: 'Severidad',
      expected: 'Esperado',
      actual: 'Encontrado',
      folder: 'Carpeta',
      type: 'Tipo',
      ecosystem: 'Ecosistema',
      packages: 'Paquetes',
      size: 'Tamaño',
      riskIndicators: 'Indicadores de riesgo',
      // Indicator names
      backdoor: 'Puerta trasera',
      cryptominer: 'Criptominero',
      stealer: 'Robo de datos',
      loader: 'Cargador de malware',
      obfuscated: 'Código ofuscado',
      data_exfiltration: 'Exfiltración de datos',
      known_malware: 'Malware conocido',
      // Issue types
      version_mismatch: 'Versión diferente',
      hash_mismatch: 'Hash diferente',
      unexpected_package: 'Paquete inesperado',
      missing_package: 'Paquete faltante',
      tampered: 'Manipulado'
    },
    en: {
      title: 'Installed Dependencies Malware Analysis',
      noMalwareFound: 'No malware detected in installed dependencies',
      malwareDetected: 'MALWARE DETECTED in dependencies!',
      issuesFound: 'Issues found in dependencies',
      packagesScanned: 'Packages scanned',
      filesScanned: 'Files analyzed',
      malwareFindings: 'Malware findings',
      integrityIssues: 'Integrity issues',
      scanTime: 'Scan time',
      malwareFindingsTitle: 'Malware Detections',
      integrityIssuesTitle: 'Integrity Issues',
      suspiciousScriptsTitle: 'Suspicious Post-Install Scripts',
      scannedFolders: 'Scanned Folders',
      package: 'Package',
      file: 'File',
      line: 'Line',
      description: 'Description',
      confidence: 'confidence',
      issueType: 'Type',
      severity: 'Severity',
      expected: 'Expected',
      actual: 'Found',
      folder: 'Folder',
      type: 'Type',
      ecosystem: 'Ecosystem',
      packages: 'Packages',
      size: 'Size',
      riskIndicators: 'Risk indicators',
      // Indicator names
      backdoor: 'Backdoor',
      cryptominer: 'Cryptominer',
      stealer: 'Data stealer',
      loader: 'Malware loader',
      obfuscated: 'Obfuscated code',
      data_exfiltration: 'Data exfiltration',
      known_malware: 'Known malware',
      // Issue types
      version_mismatch: 'Version mismatch',
      hash_mismatch: 'Hash mismatch',
      unexpected_package: 'Unexpected package',
      missing_package: 'Missing package',
      tampered: 'Tampered'
    }
  };

  return translations[language] || translations.es;
}

/**
 * Get indicator icon
 */
function getIndicatorIcon(indicator: MalwareIndicator): string {
  const icons: Record<MalwareIndicator, string> = {
    [MalwareIndicator.BACKDOOR]: '🚪',
    [MalwareIndicator.CRYPTOMINER]: '⛏️',
    [MalwareIndicator.STEALER]: '🔓',
    [MalwareIndicator.LOADER]: '📥',
    [MalwareIndicator.OBFUSCATED]: '🔣',
    [MalwareIndicator.DATA_EXFILTRATION]: '📤',
    [MalwareIndicator.KNOWN_MALWARE]: '☠️'
  };
  return icons[indicator] || '⚠️';
}

/**
 * Get indicator name
 */
function getIndicatorName(indicator: MalwareIndicator, t: any): string {
  const key = indicator.toLowerCase();
  return t[key] || indicator;
}

/**
 * Format issue type
 */
function formatIssueType(type: string, t: any): string {
  return t[type] || type.replace(/_/g, ' ');
}

/**
 * Group findings by indicator
 */
function groupByIndicator(findings: InstalledMalwareFinding[]): Record<string, InstalledMalwareFinding[]> {
  const groups: Record<string, InstalledMalwareFinding[]> = {};
  
  for (const finding of findings) {
    const indicator = finding.indicators[0] || MalwareIndicator.KNOWN_MALWARE;
    if (!groups[indicator]) {
      groups[indicator] = [];
    }
    groups[indicator].push(finding);
  }
  
  return groups;
}

/**
 * Format bytes to human-readable
 */
function formatBytes(bytes: number): string {
  if (bytes === 0) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
}

/**
 * Format duration
 */
function formatDuration(ms: number): string {
  if (ms < 1000) return `${ms}ms`;
  if (ms < 60000) return `${(ms / 1000).toFixed(1)}s`;
  return `${(ms / 60000).toFixed(1)}m`;
}

/**
 * Escape HTML
 */
function escapeHtml(text: string): string {
  return text
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

/**
 * Get CSS styles for installed deps section
 */
function getInstalledDepsStyles(): string {
  return `
    <style>
      /* Installed Dependencies Section Styles */
      .installed-deps-section {
        margin-top: 40px;
        padding: 30px;
        background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
        border-radius: 16px;
        border: 1px solid #30363d;
      }
      
      .installed-deps-section .section-title {
        display: flex;
        align-items: center;
        gap: 12px;
        font-size: 1.8em;
        color: #ff6b6b;
        margin-bottom: 25px;
      }
      
      .installed-summary {
        background: rgba(255, 255, 255, 0.03);
        border-radius: 12px;
        padding: 25px;
        margin-bottom: 30px;
      }
      
      .summary-status {
        display: flex;
        align-items: center;
        gap: 12px;
        padding: 15px 20px;
        border-radius: 8px;
        margin-bottom: 20px;
        font-size: 1.3em;
        font-weight: 600;
      }
      
      .status-secure {
        background: rgba(46, 204, 113, 0.15);
        border: 1px solid #2ecc71;
        color: #2ecc71;
      }
      
      .status-warning {
        background: rgba(241, 196, 15, 0.15);
        border: 1px solid #f1c40f;
        color: #f1c40f;
      }
      
      .status-critical {
        background: rgba(231, 76, 60, 0.15);
        border: 1px solid #e74c3c;
        color: #e74c3c;
      }
      
      .summary-stats {
        display: flex;
        gap: 20px;
        flex-wrap: wrap;
      }
      
      .stat-box {
        background: rgba(255, 255, 255, 0.05);
        padding: 15px 25px;
        border-radius: 8px;
        text-align: center;
        min-width: 120px;
      }
      
      .stat-box.stat-critical {
        background: rgba(231, 76, 60, 0.2);
        border: 1px solid #e74c3c;
      }
      
      .stat-box.stat-warning {
        background: rgba(241, 196, 15, 0.2);
        border: 1px solid #f1c40f;
      }
      
      .stat-value {
        display: block;
        font-size: 2em;
        font-weight: 700;
        color: #fff;
      }
      
      .stat-label {
        display: block;
        font-size: 0.85em;
        color: #8b949e;
        margin-top: 5px;
      }
      
      .subsection-title {
        display: flex;
        align-items: center;
        gap: 10px;
        font-size: 1.4em;
        color: #58a6ff;
        margin: 30px 0 20px;
        padding-bottom: 10px;
        border-bottom: 1px solid #30363d;
      }
      
      .indicator-group {
        margin-bottom: 25px;
      }
      
      .indicator-title {
        display: flex;
        align-items: center;
        gap: 8px;
        color: #c9d1d9;
        margin-bottom: 15px;
      }
      
      .indicator-count {
        color: #8b949e;
        font-weight: normal;
      }
      
      .malware-finding {
        background: rgba(0, 0, 0, 0.3);
        border-radius: 10px;
        padding: 20px;
        margin-bottom: 15px;
        border-left: 4px solid;
      }
      
      .malware-finding.severity-critical {
        border-color: #e74c3c;
      }
      
      .malware-finding.severity-high {
        border-color: #e67e22;
      }
      
      .malware-finding.severity-medium {
        border-color: #f1c40f;
      }
      
      .malware-finding.severity-low {
        border-color: #3498db;
      }
      
      .finding-header {
        display: flex;
        align-items: center;
        gap: 12px;
        margin-bottom: 15px;
      }
      
      .severity-badge {
        padding: 4px 10px;
        border-radius: 4px;
        font-size: 0.75em;
        font-weight: 600;
        text-transform: uppercase;
      }
      
      .severity-badge.critical {
        background: #e74c3c;
        color: white;
      }
      
      .severity-badge.high {
        background: #e67e22;
        color: white;
      }
      
      .severity-badge.medium {
        background: #f1c40f;
        color: #000;
      }
      
      .severity-badge.low {
        background: #3498db;
        color: white;
      }
      
      .finding-title {
        font-weight: 600;
        color: #fff;
        flex: 1;
      }
      
      .confidence-badge {
        background: rgba(88, 166, 255, 0.2);
        color: #58a6ff;
        padding: 4px 10px;
        border-radius: 4px;
        font-size: 0.8em;
      }
      
      .finding-details {
        display: grid;
        gap: 8px;
        margin-bottom: 15px;
      }
      
      .detail-row {
        display: flex;
        gap: 10px;
      }
      
      .detail-label {
        color: #8b949e;
        min-width: 100px;
      }
      
      .detail-value {
        color: #c9d1d9;
      }
      
      .package-name {
        font-family: 'Fira Code', monospace;
        color: #f0883e;
      }
      
      .file-path {
        font-family: 'Fira Code', monospace;
        font-size: 0.9em;
        word-break: break-all;
      }
      
      .code-snippet {
        background: #0d1117;
        border-radius: 8px;
        padding: 15px;
        margin: 15px 0;
        overflow-x: auto;
      }
      
      .code-snippet pre {
        margin: 0;
      }
      
      .code-snippet code {
        font-family: 'Fira Code', monospace;
        font-size: 0.85em;
        color: #e06c75;
      }
      
      .finding-recommendation {
        display: flex;
        align-items: flex-start;
        gap: 10px;
        background: rgba(46, 204, 113, 0.1);
        padding: 12px 15px;
        border-radius: 6px;
        margin-top: 15px;
      }
      
      .recommendation-text {
        color: #2ecc71;
      }
      
      .finding-standards {
        display: flex;
        gap: 8px;
        flex-wrap: wrap;
        margin-top: 15px;
      }
      
      .standard-badge {
        padding: 3px 8px;
        border-radius: 4px;
        font-size: 0.75em;
        font-weight: 500;
      }
      
      .standard-badge.cwe {
        background: rgba(155, 89, 182, 0.2);
        color: #9b59b6;
      }
      
      .standard-badge.mitre {
        background: rgba(52, 152, 219, 0.2);
        color: #3498db;
      }
      
      .standard-badge.owasp {
        background: rgba(231, 76, 60, 0.2);
        color: #e74c3c;
      }
      
      .integrity-table,
      .folders-table {
        width: 100%;
        border-collapse: collapse;
        margin-top: 15px;
      }
      
      .integrity-table th,
      .folders-table th {
        background: rgba(255, 255, 255, 0.05);
        padding: 12px;
        text-align: left;
        color: #8b949e;
        font-weight: 500;
        border-bottom: 1px solid #30363d;
      }
      
      .integrity-table td,
      .folders-table td {
        padding: 12px;
        border-bottom: 1px solid #21262d;
        color: #c9d1d9;
      }
      
      .integrity-table tr:hover,
      .folders-table tr:hover {
        background: rgba(255, 255, 255, 0.02);
      }
      
      .issue-type-badge {
        padding: 3px 8px;
        border-radius: 4px;
        font-size: 0.8em;
      }
      
      .issue-type-badge.version_mismatch {
        background: rgba(241, 196, 15, 0.2);
        color: #f1c40f;
      }
      
      .issue-type-badge.unexpected_package {
        background: rgba(155, 89, 182, 0.2);
        color: #9b59b6;
      }
      
      .issue-type-badge.missing_package {
        background: rgba(52, 152, 219, 0.2);
        color: #3498db;
      }
      
      .ecosystem-badge {
        padding: 3px 8px;
        border-radius: 4px;
        font-size: 0.8em;
      }
      
      .ecosystem-badge.npm {
        background: rgba(203, 56, 55, 0.2);
        color: #cb3837;
      }
      
      .ecosystem-badge.pip {
        background: rgba(53, 114, 165, 0.2);
        color: #3572a5;
      }
      
      .ecosystem-badge.composer {
        background: rgba(133, 109, 88, 0.2);
        color: #856d58;
      }
      
      .script-finding {
        background: rgba(0, 0, 0, 0.3);
        border-radius: 10px;
        padding: 20px;
        margin-bottom: 15px;
        border-left: 4px solid;
      }
      
      .script-header {
        display: flex;
        align-items: center;
        gap: 12px;
        margin-bottom: 12px;
      }
      
      .script-type {
        background: rgba(155, 89, 182, 0.2);
        color: #9b59b6;
        padding: 4px 10px;
        border-radius: 4px;
        font-size: 0.8em;
      }
      
      .script-command {
        background: #0d1117;
        padding: 10px 15px;
        border-radius: 6px;
        margin-bottom: 12px;
        overflow-x: auto;
      }
      
      .script-command code {
        font-family: 'Fira Code', monospace;
        font-size: 0.85em;
        color: #f0883e;
      }
      
      .script-description {
        color: #8b949e;
        margin-bottom: 12px;
      }
      
      .risk-indicators {
        display: flex;
        gap: 8px;
        flex-wrap: wrap;
        align-items: center;
      }
      
      .indicators-label {
        color: #8b949e;
        font-size: 0.9em;
      }
      
      .risk-indicator {
        background: rgba(231, 76, 60, 0.2);
        color: #e74c3c;
        padding: 3px 8px;
        border-radius: 4px;
        font-size: 0.75em;
        font-family: 'Fira Code', monospace;
      }
      
      .folder-path {
        font-family: 'Fira Code', monospace;
        font-size: 0.85em;
        word-break: break-all;
      }
    </style>
  `;
}

export default { generateInstalledDependenciesSection };
