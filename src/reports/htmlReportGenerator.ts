/**
 * HTML Report Generator
 * Generates professional security audit reports
 * Supports Spanish (default) and English
 */

import * as fs from 'fs';
import * as path from 'path';
import Handlebars from 'handlebars';
import { ScanResult, Finding, Severity, FindingCategory, ReportGenerator } from '../types';
import { escapeHtml, formatDuration, getSeverityColor, getSeverityBadge } from '../utils';
import { logger } from '../utils/logger';
import { Language, getTranslations, Translations, defaultLanguage } from '../i18n';

/**
 * HTML Report Generator Class
 */
export class HtmlReportGenerator implements ReportGenerator {
  name = 'HTML Report Generator';
  format: 'html' = 'html';
  private language: Language;
  private t: Translations;

  constructor(language: Language = defaultLanguage) {
    this.language = language;
    this.t = getTranslations(language);
  }

  /**
   * Set report language
   */
  setLanguage(language: Language): void {
    this.language = language;
    this.t = getTranslations(language);
  }

  /**
   * Generate HTML report
   */
  async generate(result: ScanResult): Promise<string> {
    logger.info('📄 Generando reporte HTML...');

    const template = this.getTemplate();
    const compiledTemplate = Handlebars.compile(template);

    // Register helpers
    this.registerHelpers();

    // Prepare data
    const data = this.prepareData(result);

    // Generate HTML
    const html = compiledTemplate(data);

    return html;
  }

  /**
   * Save report to file
   */
  async saveReport(result: ScanResult, outputPath: string): Promise<void> {
    const html = await this.generate(result);
    fs.writeFileSync(outputPath, html, 'utf-8');
    logger.info(`📁 Reporte guardado en: ${outputPath}`);
  }

  /**
   * Register Handlebars helpers
   */
  private registerHelpers(): void {
    Handlebars.registerHelper('severityColor', (severity: Severity) => getSeverityColor(severity));
    Handlebars.registerHelper('severityBadge', (severity: Severity) => getSeverityBadge(severity));
    Handlebars.registerHelper('escapeHtml', (text: string) => escapeHtml(text));
    Handlebars.registerHelper('formatDate', (date: Date) => new Date(date).toLocaleString());
    Handlebars.registerHelper('uppercase', (text: string) => text.toUpperCase());
    Handlebars.registerHelper('json', (obj: any) => JSON.stringify(obj, null, 2));
    Handlebars.registerHelper('eq', (a: any, b: any) => a === b);
    Handlebars.registerHelper('gt', (a: number, b: number) => a > b);
  }

  /**
   * Prepare data for template
   */
  private prepareData(result: ScanResult): any {
    const criticalCount = result.findings.filter(f => f.severity === Severity.CRITICAL).length;
    const highCount = result.findings.filter(f => f.severity === Severity.HIGH).length;
    const mediumCount = result.findings.filter(f => f.severity === Severity.MEDIUM).length;
    const lowCount = result.findings.filter(f => f.severity === Severity.LOW).length;
    const infoCount = result.findings.filter(f => f.severity === Severity.INFO).length;

    const malwareCount = result.findings.filter(f => f.category === FindingCategory.MALWARE).length;
    const vulnCount = result.findings.filter(f => f.category === FindingCategory.VULNERABILITY).length;

    // Group findings by file
    const findingsByFile: Record<string, Finding[]> = {};
    for (const finding of result.findings) {
      const file = finding.location.file;
      if (!findingsByFile[file]) {
        findingsByFile[file] = [];
      }
      findingsByFile[file].push(finding);
    }

    // Sort findings by severity
    const sortedFindings = [...result.findings].sort((a, b) => {
      const order = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
      return (order[a.severity] || 4) - (order[b.severity] || 4);
    });

    return {
      projectName: result.projectName,
      projectPath: result.projectPath,
      scanId: result.scanId,
      scanDate: new Date().toISOString(),
      riskScore: result.riskScore,
      riskLevel: result.riskLevel,
      totalFindings: result.findings.length,
      totalFiles: result.stats.totalFiles,
      totalLines: result.stats.totalLines,
      duration: formatDuration(result.stats.duration),
      
      // Severity counts
      criticalCount,
      highCount,
      mediumCount,
      lowCount,
      infoCount,
      
      // Category counts
      malwareCount,
      vulnCount,
      
      // Findings
      findings: sortedFindings,
      findingsByFile,
      
      // Stats
      filesByLanguage: result.stats.filesByLanguage,
      
      // Risk assessment
      hasCritical: criticalCount > 0,
      hasHigh: highCount > 0,
      hasMalware: malwareCount > 0,
      
      // Translations
      t: this.t,
      lang: this.language,
      malwareDescriptionText: this.t.malwareDescription(malwareCount),
      criticalDescriptionText: this.t.criticalDescription(criticalCount)
    };
  }

  /**
   * Get HTML template
   */
  private getTemplate(): string {
    return `<!DOCTYPE html>
<html lang="{{lang}}">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>{{t.reportTitle}} - {{projectName}}</title>
  <style>
    :root {
      --bg-primary: #0d1117;
      --bg-secondary: #161b22;
      --bg-tertiary: #21262d;
      --text-primary: #c9d1d9;
      --text-secondary: #8b949e;
      --border-color: #30363d;
      --critical-color: #f85149;
      --high-color: #db6d28;
      --medium-color: #d29922;
      --low-color: #3fb950;
      --info-color: #58a6ff;
      --accent-color: #238636;
    }

    * {
      margin: 0;
      padding: 0;
      box-sizing: border-box;
    }

    body {
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Helvetica, Arial, sans-serif;
      background: var(--bg-primary);
      color: var(--text-primary);
      line-height: 1.6;
    }

    .container {
      max-width: 1400px;
      margin: 0 auto;
      padding: 20px;
    }

    header {
      background: var(--bg-secondary);
      border-bottom: 1px solid var(--border-color);
      padding: 24px 0;
      margin-bottom: 24px;
    }

    .header-content {
      display: flex;
      justify-content: space-between;
      align-items: center;
      flex-wrap: wrap;
      gap: 16px;
    }

    .logo {
      display: flex;
      align-items: center;
      gap: 12px;
    }

    .logo h1 {
      font-size: 24px;
      font-weight: 600;
    }

    .logo-icon {
      font-size: 32px;
    }

    .scan-meta {
      text-align: right;
      color: var(--text-secondary);
      font-size: 14px;
    }

    .summary-cards {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
      gap: 16px;
      margin-bottom: 24px;
    }

    .card {
      background: var(--bg-secondary);
      border: 1px solid var(--border-color);
      border-radius: 8px;
      padding: 20px;
    }

    .card-title {
      font-size: 12px;
      text-transform: uppercase;
      color: var(--text-secondary);
      margin-bottom: 8px;
    }

    .card-value {
      font-size: 32px;
      font-weight: 600;
    }

    .risk-score {
      display: flex;
      align-items: center;
      gap: 12px;
    }

    .risk-meter {
      flex: 1;
      height: 8px;
      background: var(--bg-tertiary);
      border-radius: 4px;
      overflow: hidden;
    }

    .risk-meter-fill {
      height: 100%;
      border-radius: 4px;
      transition: width 0.5s ease;
    }

    .risk-safe { background: var(--low-color); }
    .risk-low { background: var(--low-color); }
    .risk-medium { background: var(--medium-color); }
    .risk-high { background: var(--high-color); }
    .risk-critical { background: var(--critical-color); }

    .severity-chart {
      display: flex;
      gap: 8px;
      margin-top: 12px;
    }

    .severity-bar {
      flex: 1;
      text-align: center;
      padding: 8px;
      border-radius: 4px;
      font-size: 14px;
      font-weight: 500;
    }

    .severity-critical { background: rgba(248, 81, 73, 0.2); border: 1px solid var(--critical-color); color: var(--critical-color); }
    .severity-high { background: rgba(219, 109, 40, 0.2); border: 1px solid var(--high-color); color: var(--high-color); }
    .severity-medium { background: rgba(210, 153, 34, 0.2); border: 1px solid var(--medium-color); color: var(--medium-color); }
    .severity-low { background: rgba(63, 185, 80, 0.2); border: 1px solid var(--low-color); color: var(--low-color); }
    .severity-info { background: rgba(88, 166, 255, 0.2); border: 1px solid var(--info-color); color: var(--info-color); }

    .section {
      background: var(--bg-secondary);
      border: 1px solid var(--border-color);
      border-radius: 8px;
      margin-bottom: 24px;
    }

    .section-header {
      padding: 16px 20px;
      border-bottom: 1px solid var(--border-color);
      display: flex;
      justify-content: space-between;
      align-items: center;
    }

    .section-title {
      font-size: 16px;
      font-weight: 600;
    }

    .section-content {
      padding: 20px;
    }

    .finding {
      background: var(--bg-tertiary);
      border: 1px solid var(--border-color);
      border-radius: 6px;
      margin-bottom: 16px;
      overflow: hidden;
    }

    .finding:last-child {
      margin-bottom: 0;
    }

    .finding-header {
      padding: 16px;
      display: flex;
      justify-content: space-between;
      align-items: flex-start;
      gap: 12px;
      cursor: pointer;
    }

    .finding-header:hover {
      background: rgba(255, 255, 255, 0.02);
    }

    .finding-title {
      font-weight: 600;
      margin-bottom: 4px;
    }

    .finding-location {
      font-size: 13px;
      color: var(--text-secondary);
      font-family: 'SFMono-Regular', Consolas, 'Liberation Mono', Menlo, monospace;
    }

    .badge {
      display: inline-block;
      padding: 4px 10px;
      border-radius: 20px;
      font-size: 12px;
      font-weight: 500;
      text-transform: uppercase;
    }

    .badge-critical { background: var(--critical-color); color: white; }
    .badge-high { background: var(--high-color); color: white; }
    .badge-medium { background: var(--medium-color); color: black; }
    .badge-low { background: var(--low-color); color: black; }
    .badge-info { background: var(--info-color); color: black; }

    .finding-body {
      padding: 0 16px 16px;
      display: none;
    }

    .finding.expanded .finding-body {
      display: block;
    }

    .finding-description {
      margin-bottom: 16px;
      color: var(--text-secondary);
    }

    .code-block {
      background: var(--bg-primary);
      border: 1px solid var(--border-color);
      border-radius: 6px;
      padding: 16px;
      overflow-x: auto;
      font-family: 'SFMono-Regular', Consolas, 'Liberation Mono', Menlo, monospace;
      font-size: 13px;
      line-height: 1.5;
      margin-bottom: 16px;
    }

    .code-line {
      white-space: pre;
    }

    .code-line-highlight {
      background: rgba(248, 81, 73, 0.15);
      display: block;
      margin: 0 -16px;
      padding: 0 16px;
    }

    .standards-list {
      display: flex;
      flex-wrap: wrap;
      gap: 8px;
      margin-bottom: 16px;
    }

    .standard-badge {
      background: var(--bg-primary);
      border: 1px solid var(--border-color);
      border-radius: 4px;
      padding: 4px 8px;
      font-size: 12px;
      color: var(--info-color);
    }

    .remediation {
      background: rgba(35, 134, 54, 0.1);
      border: 1px solid var(--accent-color);
      border-radius: 6px;
      padding: 12px 16px;
    }

    .remediation-title {
      font-weight: 600;
      color: var(--accent-color);
      margin-bottom: 8px;
    }

    .stats-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
      gap: 16px;
    }

    .stat-item {
      text-align: center;
    }

    .stat-value {
      font-size: 24px;
      font-weight: 600;
    }

    .stat-label {
      font-size: 12px;
      color: var(--text-secondary);
    }

    .warning-banner {
      background: rgba(248, 81, 73, 0.1);
      border: 1px solid var(--critical-color);
      border-radius: 8px;
      padding: 16px 20px;
      margin-bottom: 24px;
      display: flex;
      align-items: center;
      gap: 12px;
    }

    .warning-banner.malware {
      background: rgba(248, 81, 73, 0.2);
    }

    .warning-icon {
      font-size: 24px;
    }

    footer {
      text-align: center;
      padding: 24px;
      color: var(--text-secondary);
      font-size: 14px;
      border-top: 1px solid var(--border-color);
    }

    @media print {
      body { background: white; color: black; }
      .card, .section { border: 1px solid #ddd; }
      .finding-body { display: block !important; }
    }
  </style>
</head>
<body>
  <header>
    <div class="container">
      <div class="header-content">
        <div class="logo">
          <span class="logo-icon">🔐</span>
          <h1>Secure-Scan {{t.reportTitle}}</h1>
        </div>
        <div class="scan-meta">
          <div><strong>{{t.project}}:</strong> {{projectName}}</div>
          <div><strong>{{t.scanId}}:</strong> {{scanId}}</div>
          <div><strong>{{t.date}}:</strong> {{scanDate}}</div>
        </div>
      </div>
    </div>
  </header>

  <main class="container">
    {{#if hasMalware}}
    <div class="warning-banner malware">
      <span class="warning-icon">🦠</span>
      <div>
        <strong>{{t.malwareDetected}}</strong>
        <p>{{malwareDescriptionText}}</p>
      </div>
    </div>
    {{/if}}

    {{#if hasCritical}}
    <div class="warning-banner">
      <span class="warning-icon">⚠️</span>
      <div>
        <strong>{{t.criticalVulnerabilities}}</strong>
        <p>{{criticalDescriptionText}}</p>
      </div>
    </div>
    {{/if}}

    <div class="summary-cards">
      <div class="card">
        <div class="card-title">{{t.riskScore}}</div>
        <div class="card-value">{{riskScore}}/100</div>
        <div class="risk-score">
          <div class="risk-meter">
            <div class="risk-meter-fill risk-{{riskLevel}}" style="width: {{riskScore}}%"></div>
          </div>
        </div>
      </div>
      <div class="card">
        <div class="card-title">{{t.totalFindings}}</div>
        <div class="card-value">{{totalFindings}}</div>
        <div class="severity-chart">
          {{#if criticalCount}}<span class="severity-bar severity-critical">{{criticalCount}}</span>{{/if}}
          {{#if highCount}}<span class="severity-bar severity-high">{{highCount}}</span>{{/if}}
          {{#if mediumCount}}<span class="severity-bar severity-medium">{{mediumCount}}</span>{{/if}}
          {{#if lowCount}}<span class="severity-bar severity-low">{{lowCount}}</span>{{/if}}
          {{#if infoCount}}<span class="severity-bar severity-info">{{infoCount}}</span>{{/if}}
        </div>
      </div>
      <div class="card">
        <div class="card-title">{{t.filesScanned}}</div>
        <div class="card-value">{{totalFiles}}</div>
      </div>
      <div class="card">
        <div class="card-title">{{t.linesOfCode}}</div>
        <div class="card-value">{{totalLines}}</div>
      </div>
      <div class="card">
        <div class="card-title">{{t.scanDuration}}</div>
        <div class="card-value">{{duration}}</div>
      </div>
    </div>

    <div class="section">
      <div class="section-header">
        <h2 class="section-title">{{t.securityFindings}}</h2>
        <span>{{totalFindings}} {{t.issues}}</span>
      </div>
      <div class="section-content">
        {{#each findings}}
        <div class="finding" onclick="this.classList.toggle('expanded')">
          <div class="finding-header">
            <div>
              <div class="finding-title">{{this.title}}</div>
              <div class="finding-location">📄 {{this.location.file}}:{{this.location.startLine}}</div>
            </div>
            <span class="badge badge-{{this.severity}}">{{this.severity}}</span>
          </div>
          <div class="finding-body">
            <p class="finding-description">{{this.description}}</p>
            
            <div class="code-block">
              {{#if this.snippet.contextBefore}}<div class="code-line">{{this.snippet.contextBefore}}</div>{{/if}}
              <div class="code-line code-line-highlight">{{this.snippet.code}}</div>
              {{#if this.snippet.contextAfter}}<div class="code-line">{{this.snippet.contextAfter}}</div>{{/if}}
            </div>

            <div class="standards-list">
              {{#each this.standards}}
              <span class="standard-badge">{{this.name}}: {{this.id}}</span>
              {{/each}}
            </div>

            <div class="remediation">
              <div class="remediation-title">{{../t.remediation}}</div>
              <p>{{this.remediation}}</p>
            </div>
          </div>
        </div>
        {{/each}}

        {{#unless findings.length}}
        <p style="text-align: center; color: var(--text-secondary); padding: 40px;">
          {{t.noIssuesFound}}
        </p>
        {{/unless}}
      </div>
    </div>

    <div class="section">
      <div class="section-header">
        <h2 class="section-title">{{t.scanStatistics}}</h2>
      </div>
      <div class="section-content">
        <div class="stats-grid">
          <div class="stat-item">
            <div class="stat-value severity-critical">{{criticalCount}}</div>
            <div class="stat-label">{{t.critical}}</div>
          </div>
          <div class="stat-item">
            <div class="stat-value severity-high">{{highCount}}</div>
            <div class="stat-label">{{t.high}}</div>
          </div>
          <div class="stat-item">
            <div class="stat-value severity-medium">{{mediumCount}}</div>
            <div class="stat-label">{{t.medium}}</div>
          </div>
          <div class="stat-item">
            <div class="stat-value severity-low">{{lowCount}}</div>
            <div class="stat-label">{{t.low}}</div>
          </div>
          <div class="stat-item">
            <div class="stat-value severity-info">{{infoCount}}</div>
            <div class="stat-label">{{t.info}}</div>
          </div>
          <div class="stat-item">
            <div class="stat-value" style="color: var(--critical-color)">{{malwareCount}}</div>
            <div class="stat-label">{{t.malware}}</div>
          </div>
        </div>
      </div>
    </div>
  </main>

  <footer>
    <p>{{t.generatedBy}} <strong>Secure-Scan</strong> - Herramienta SAST</p>
    <p>© {{currentYear}} - {{t.securityReport}}</p>
  </footer>

  <script>
    // Expand first critical/high finding by default
    const firstCritical = document.querySelector('.finding');
    if (firstCritical) firstCritical.classList.add('expanded');
  </script>
</body>
</html>`;
  }
}

export default HtmlReportGenerator;
