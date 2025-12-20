/**
 * Dependency Report Generator
 * Generates HTML report section for dependency analysis
 */

import { 
  DependencyAnalysisResult, 
  DependencyVulnerability,
  DependencyRiskCategory,
  DependencyRecommendation,
  Dependency,
  PackageEcosystem
} from '../dependencies/types';
import { Severity } from '../types';
import { escapeHtml, formatDuration } from '../utils';
import { Language, getTranslations, Translations } from '../i18n';

/**
 * Dependency Report Translations
 */
const dependencyTranslations = {
  es: {
    dependencyAnalysis: 'Análisis de Dependencias',
    dependencySubtitle: 'Software Composition Analysis (SCA)',
    totalDependencies: 'Total Dependencias',
    directDependencies: 'Directas',
    transitiveDependencies: 'Transitivas',
    vulnerableDependencies: 'Vulnerables',
    ecosystems: 'Ecosistemas',
    vulnerabilities: 'Vulnerabilidades',
    supplyChainRisks: 'Riesgos Supply Chain',
    maliciousPackages: 'Paquetes Maliciosos',
    outdatedPackages: 'Paquetes Obsoletos',
    package: 'Paquete',
    version: 'Versión',
    ecosystem: 'Ecosistema',
    type: 'Tipo',
    severity: 'Severidad',
    category: 'Categoría',
    recommendation: 'Recomendación',
    references: 'Referencias',
    affectedVersion: 'Versión Afectada',
    fixedVersion: 'Versión Corregida',
    cve: 'CVE',
    cvss: 'CVSS',
    upgrade: 'Actualizar',
    replace: 'Reemplazar',
    remove: 'Eliminar',
    review: 'Revisar',
    monitor: 'Monitorear',
    direct: 'Directa',
    transitive: 'Transitiva',
    dev: 'Desarrollo',
    optional: 'Opcional',
    peer: 'Peer',
    noVulnerabilities: 'No se detectaron vulnerabilidades en las dependencias',
    dependencyDetails: 'Detalles de Dependencia',
    riskIndicators: 'Indicadores de Riesgo',
    securityStandards: 'Estándares de Seguridad',
    aiAnalysis: 'Análisis IA'
  },
  en: {
    dependencyAnalysis: 'Dependency Analysis',
    dependencySubtitle: 'Software Composition Analysis (SCA)',
    totalDependencies: 'Total Dependencies',
    directDependencies: 'Direct',
    transitiveDependencies: 'Transitive',
    vulnerableDependencies: 'Vulnerable',
    ecosystems: 'Ecosystems',
    vulnerabilities: 'Vulnerabilities',
    supplyChainRisks: 'Supply Chain Risks',
    maliciousPackages: 'Malicious Packages',
    outdatedPackages: 'Outdated Packages',
    package: 'Package',
    version: 'Version',
    ecosystem: 'Ecosystem',
    type: 'Type',
    severity: 'Severity',
    category: 'Category',
    recommendation: 'Recommendation',
    references: 'References',
    affectedVersion: 'Affected Version',
    fixedVersion: 'Fixed Version',
    cve: 'CVE',
    cvss: 'CVSS',
    upgrade: 'Upgrade',
    replace: 'Replace',
    remove: 'Remove',
    review: 'Review',
    monitor: 'Monitor',
    direct: 'Direct',
    transitive: 'Transitive',
    dev: 'Development',
    optional: 'Optional',
    peer: 'Peer',
    noVulnerabilities: 'No vulnerabilities detected in dependencies',
    dependencyDetails: 'Dependency Details',
    riskIndicators: 'Risk Indicators',
    securityStandards: 'Security Standards',
    aiAnalysis: 'AI Analysis'
  }
};

/**
 * Get dependency translations
 */
function getDependencyTranslations(language: Language) {
  return dependencyTranslations[language] || dependencyTranslations.en;
}

/**
 * Get ecosystem icon
 */
function getEcosystemIcon(ecosystem: PackageEcosystem): string {
  const icons: Record<PackageEcosystem, string> = {
    npm: '📦',
    pip: '🐍',
    composer: '🐘',
    maven: '☕',
    gradle: '🐘',
    nuget: '🔷',
    vcpkg: '⚙️',
    conan: '🔧',
    cmake: '🔨'
  };
  return icons[ecosystem] || '📦';
}

/**
 * Get recommendation icon
 */
function getRecommendationIcon(recommendation: DependencyRecommendation): string {
  const icons: Record<DependencyRecommendation, string> = {
    [DependencyRecommendation.UPGRADE]: '⬆️',
    [DependencyRecommendation.REPLACE]: '🔄',
    [DependencyRecommendation.REMOVE]: '❌',
    [DependencyRecommendation.REVIEW]: '🔍',
    [DependencyRecommendation.MONITOR]: '👁️'
  };
  return icons[recommendation] || '📋';
}

/**
 * Get category icon
 */
function getCategoryIcon(category: DependencyRiskCategory): string {
  const icons: Record<DependencyRiskCategory, string> = {
    [DependencyRiskCategory.VULNERABILITY]: '🔓',
    [DependencyRiskCategory.SUPPLY_CHAIN]: '🔗',
    [DependencyRiskCategory.MALICIOUS]: '🦠',
    [DependencyRiskCategory.OUTDATED]: '📅',
    [DependencyRiskCategory.LICENSE]: '📄',
    [DependencyRiskCategory.MAINTENANCE]: '🔧'
  };
  return icons[category] || '⚠️';
}

/**
 * Generate dependency analysis HTML section
 */
export function generateDependencyReportSection(
  result: DependencyAnalysisResult,
  language: Language = 'es'
): string {
  const t = getDependencyTranslations(language);
  const stats = result.stats;

  // Count by category
  const vulnCount = result.vulnerabilities.filter(
    v => v.category === DependencyRiskCategory.VULNERABILITY
  ).length;
  const supplyChainCount = result.vulnerabilities.filter(
    v => v.category === DependencyRiskCategory.SUPPLY_CHAIN
  ).length;
  const maliciousCount = result.vulnerabilities.filter(
    v => v.category === DependencyRiskCategory.MALICIOUS
  ).length;
  const outdatedCount = result.vulnerabilities.filter(
    v => v.category === DependencyRiskCategory.OUTDATED
  ).length;

  return `
    <!-- Dependency Analysis Section -->
    <div class="section dependency-section">
      <div class="section-header">
        <h2 class="section-title">📦 ${t.dependencyAnalysis}</h2>
        <span class="section-subtitle">${t.dependencySubtitle}</span>
      </div>
      <div class="section-content">
        <!-- Dependency Stats -->
        <div class="dep-stats-grid">
          <div class="dep-stat-card">
            <div class="dep-stat-icon">📊</div>
            <div class="dep-stat-value">${stats.totalDependencies}</div>
            <div class="dep-stat-label">${t.totalDependencies}</div>
          </div>
          <div class="dep-stat-card">
            <div class="dep-stat-icon">📎</div>
            <div class="dep-stat-value">${stats.directDependencies}</div>
            <div class="dep-stat-label">${t.directDependencies}</div>
          </div>
          <div class="dep-stat-card">
            <div class="dep-stat-icon">🔗</div>
            <div class="dep-stat-value">${stats.transitiveDependencies}</div>
            <div class="dep-stat-label">${t.transitiveDependencies}</div>
          </div>
          <div class="dep-stat-card vulnerable">
            <div class="dep-stat-icon">⚠️</div>
            <div class="dep-stat-value">${stats.vulnerableDependencies}</div>
            <div class="dep-stat-label">${t.vulnerableDependencies}</div>
          </div>
        </div>

        <!-- Ecosystems -->
        <div class="ecosystems-bar">
          ${result.ecosystems.map(eco => `
            <span class="ecosystem-badge">
              ${getEcosystemIcon(eco)} ${eco}
            </span>
          `).join('')}
        </div>

        <!-- Category Summary -->
        <div class="dep-category-summary">
          ${vulnCount > 0 ? `
            <div class="category-pill vulnerability">
              🔓 ${vulnCount} ${t.vulnerabilities}
            </div>
          ` : ''}
          ${supplyChainCount > 0 ? `
            <div class="category-pill supply-chain">
              🔗 ${supplyChainCount} ${t.supplyChainRisks}
            </div>
          ` : ''}
          ${maliciousCount > 0 ? `
            <div class="category-pill malicious">
              🦠 ${maliciousCount} ${t.maliciousPackages}
            </div>
          ` : ''}
          ${outdatedCount > 0 ? `
            <div class="category-pill outdated">
              📅 ${outdatedCount} ${t.outdatedPackages}
            </div>
          ` : ''}
        </div>

        <!-- Vulnerability List -->
        ${result.vulnerabilities.length > 0 ? `
          <div class="dep-vulnerabilities">
            ${result.vulnerabilities.map(vuln => generateVulnerabilityCard(vuln, t)).join('')}
          </div>
        ` : `
          <div class="no-vulnerabilities">
            <span class="success-icon">✅</span>
            <p>${t.noVulnerabilities}</p>
          </div>
        `}
      </div>
    </div>
  `;
}

/**
 * Generate vulnerability card HTML
 */
function generateVulnerabilityCard(vuln: DependencyVulnerability, t: any): string {
  const dep = vuln.dependency;
  
  return `
    <div class="dep-finding" onclick="this.classList.toggle('expanded')">
      <div class="dep-finding-header">
        <div class="dep-finding-info">
          <div class="dep-finding-title">
            ${getCategoryIcon(vuln.category)} ${escapeHtml(vuln.title)}
          </div>
          <div class="dep-finding-meta">
            <span class="dep-name">${getEcosystemIcon(dep.ecosystem)} ${escapeHtml(dep.name)}</span>
            <span class="dep-version">@${escapeHtml(dep.resolvedVersion || dep.version)}</span>
            <span class="dep-type badge-${dep.dependencyType}">${dep.dependencyType}</span>
          </div>
        </div>
        <div class="dep-finding-badges">
          <span class="badge badge-${vuln.severity}">${vuln.severity.toUpperCase()}</span>
          <span class="recommendation-badge">
            ${getRecommendationIcon(vuln.recommendation)} ${vuln.recommendation}
          </span>
        </div>
      </div>
      <div class="dep-finding-body">
        <p class="dep-description">${escapeHtml(vuln.description)}</p>
        
        ${vuln.cve ? `
          <div class="cve-info">
            <div class="cve-header">
              <span class="cve-id">${vuln.cve.id}</span>
              <span class="cvss-score cvss-${getCVSSLevel(vuln.cve.cvssScore)}">
                CVSS: ${vuln.cve.cvssScore}
              </span>
              ${vuln.cve.exploitAvailable ? '<span class="exploit-badge">⚠️ Exploit Available</span>' : ''}
            </div>
            ${vuln.cve.fixedVersion ? `
              <div class="fix-version">
                <strong>${t.fixedVersion}:</strong> ${vuln.cve.fixedVersion}
              </div>
            ` : ''}
            ${vuln.cve.references.length > 0 ? `
              <div class="cve-references">
                <strong>${t.references}:</strong>
                ${vuln.cve.references.slice(0, 3).map(ref => `
                  <a href="${escapeHtml(ref)}" target="_blank" rel="noopener">${getDomain(ref)}</a>
                `).join(' ')}
              </div>
            ` : ''}
          </div>
        ` : ''}

        ${vuln.supplyChainRisks && vuln.supplyChainRisks.length > 0 ? `
          <div class="risk-indicators">
            <strong>${t.riskIndicators}:</strong>
            ${vuln.supplyChainRisks.map(risk => `
              <span class="risk-badge">${formatRiskName(risk)}</span>
            `).join('')}
          </div>
        ` : ''}

        ${vuln.malwareIndicators && vuln.malwareIndicators.length > 0 ? `
          <div class="malware-indicators">
            <strong>🦠 Malware Indicators:</strong>
            ${vuln.malwareIndicators.map(ind => `
              <span class="malware-badge">${formatMalwareName(ind)}</span>
            `).join('')}
          </div>
        ` : ''}

        <div class="standards-list">
          ${vuln.standards.slice(0, 4).map(std => `
            <span class="standard-badge">${std.name}: ${std.id}</span>
          `).join('')}
        </div>

        <div class="dep-remediation">
          <div class="remediation-title">
            ${getRecommendationIcon(vuln.recommendation)} ${t.recommendation}
          </div>
          <p>${escapeHtml(vuln.recommendationDetails)}</p>
        </div>

        ${vuln.aiExplanation ? `
          <div class="ai-explanation">
            <div class="ai-title">🤖 ${t.aiAnalysis}</div>
            <p>${escapeHtml(vuln.aiExplanation)}</p>
          </div>
        ` : ''}
      </div>
    </div>
  `;
}

/**
 * Get CVSS level for styling
 */
function getCVSSLevel(score: number): string {
  if (score >= 9.0) return 'critical';
  if (score >= 7.0) return 'high';
  if (score >= 4.0) return 'medium';
  if (score >= 0.1) return 'low';
  return 'info';
}

/**
 * Get domain from URL
 */
function getDomain(url: string): string {
  try {
    return new URL(url).hostname.replace('www.', '');
  } catch {
    return url.substring(0, 30);
  }
}

/**
 * Format risk name
 */
function formatRiskName(risk: string): string {
  return risk.replace(/_/g, ' ').toLowerCase().replace(/\b\w/g, l => l.toUpperCase());
}

/**
 * Format malware name
 */
function formatMalwareName(indicator: string): string {
  return indicator.replace(/_/g, ' ').toLowerCase().replace(/\b\w/g, l => l.toUpperCase());
}

/**
 * Generate dependency CSS styles
 */
export function generateDependencyStyles(): string {
  return `
    /* Dependency Analysis Styles */
    .dependency-section .section-subtitle {
      font-size: 12px;
      color: var(--text-secondary);
      margin-left: 12px;
    }

    .dep-stats-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
      gap: 16px;
      margin-bottom: 20px;
    }

    .dep-stat-card {
      background: var(--bg-tertiary);
      border: 1px solid var(--border-color);
      border-radius: 8px;
      padding: 16px;
      text-align: center;
    }

    .dep-stat-card.vulnerable {
      border-color: var(--high-color);
      background: rgba(219, 109, 40, 0.1);
    }

    .dep-stat-icon {
      font-size: 24px;
      margin-bottom: 8px;
    }

    .dep-stat-value {
      font-size: 28px;
      font-weight: 600;
      color: var(--text-primary);
    }

    .dep-stat-card.vulnerable .dep-stat-value {
      color: var(--high-color);
    }

    .dep-stat-label {
      font-size: 12px;
      color: var(--text-secondary);
      margin-top: 4px;
    }

    .ecosystems-bar {
      display: flex;
      flex-wrap: wrap;
      gap: 8px;
      margin-bottom: 16px;
    }

    .ecosystem-badge {
      background: var(--bg-tertiary);
      border: 1px solid var(--border-color);
      border-radius: 20px;
      padding: 6px 12px;
      font-size: 13px;
    }

    .dep-category-summary {
      display: flex;
      flex-wrap: wrap;
      gap: 10px;
      margin-bottom: 20px;
    }

    .category-pill {
      padding: 8px 16px;
      border-radius: 20px;
      font-size: 13px;
      font-weight: 500;
    }

    .category-pill.vulnerability {
      background: rgba(219, 109, 40, 0.2);
      border: 1px solid var(--high-color);
      color: var(--high-color);
    }

    .category-pill.supply-chain {
      background: rgba(210, 153, 34, 0.2);
      border: 1px solid var(--medium-color);
      color: var(--medium-color);
    }

    .category-pill.malicious {
      background: rgba(248, 81, 73, 0.2);
      border: 1px solid var(--critical-color);
      color: var(--critical-color);
    }

    .category-pill.outdated {
      background: rgba(88, 166, 255, 0.2);
      border: 1px solid var(--info-color);
      color: var(--info-color);
    }

    .dep-vulnerabilities {
      display: flex;
      flex-direction: column;
      gap: 16px;
    }

    .dep-finding {
      background: var(--bg-tertiary);
      border: 1px solid var(--border-color);
      border-radius: 8px;
      overflow: hidden;
    }

    .dep-finding-header {
      padding: 16px;
      display: flex;
      justify-content: space-between;
      align-items: flex-start;
      gap: 16px;
      cursor: pointer;
    }

    .dep-finding-header:hover {
      background: rgba(255, 255, 255, 0.02);
    }

    .dep-finding-title {
      font-weight: 600;
      margin-bottom: 8px;
    }

    .dep-finding-meta {
      display: flex;
      flex-wrap: wrap;
      gap: 8px;
      font-size: 13px;
      color: var(--text-secondary);
    }

    .dep-name {
      font-family: 'SFMono-Regular', Consolas, monospace;
      color: var(--info-color);
    }

    .dep-version {
      font-family: 'SFMono-Regular', Consolas, monospace;
    }

    .dep-type {
      padding: 2px 8px;
      border-radius: 4px;
      font-size: 11px;
      text-transform: uppercase;
    }

    .badge-direct { background: var(--accent-color); color: white; }
    .badge-transitive { background: var(--bg-primary); border: 1px solid var(--border-color); }
    .badge-dev { background: rgba(88, 166, 255, 0.2); color: var(--info-color); }
    .badge-optional { background: rgba(210, 153, 34, 0.2); color: var(--medium-color); }
    .badge-peer { background: rgba(63, 185, 80, 0.2); color: var(--low-color); }

    .dep-finding-badges {
      display: flex;
      flex-direction: column;
      align-items: flex-end;
      gap: 8px;
    }

    .recommendation-badge {
      font-size: 12px;
      color: var(--text-secondary);
    }

    .dep-finding-body {
      padding: 0 16px 16px;
      display: none;
      border-top: 1px solid var(--border-color);
    }

    .dep-finding.expanded .dep-finding-body {
      display: block;
      padding-top: 16px;
    }

    .dep-description {
      color: var(--text-secondary);
      margin-bottom: 16px;
      line-height: 1.6;
    }

    .cve-info {
      background: var(--bg-primary);
      border: 1px solid var(--border-color);
      border-radius: 6px;
      padding: 12px 16px;
      margin-bottom: 16px;
    }

    .cve-header {
      display: flex;
      align-items: center;
      gap: 12px;
      margin-bottom: 8px;
    }

    .cve-id {
      font-weight: 600;
      font-family: 'SFMono-Regular', Consolas, monospace;
      color: var(--critical-color);
    }

    .cvss-score {
      padding: 4px 8px;
      border-radius: 4px;
      font-size: 12px;
      font-weight: 600;
    }

    .cvss-critical { background: var(--critical-color); color: white; }
    .cvss-high { background: var(--high-color); color: white; }
    .cvss-medium { background: var(--medium-color); color: black; }
    .cvss-low { background: var(--low-color); color: black; }
    .cvss-info { background: var(--info-color); color: black; }

    .exploit-badge {
      background: rgba(248, 81, 73, 0.2);
      color: var(--critical-color);
      padding: 4px 8px;
      border-radius: 4px;
      font-size: 12px;
    }

    .fix-version {
      font-size: 13px;
      margin-bottom: 8px;
    }

    .cve-references {
      font-size: 13px;
    }

    .cve-references a {
      color: var(--info-color);
      text-decoration: none;
      margin-left: 8px;
    }

    .cve-references a:hover {
      text-decoration: underline;
    }

    .risk-indicators, .malware-indicators {
      margin-bottom: 16px;
    }

    .risk-badge, .malware-badge {
      display: inline-block;
      background: rgba(210, 153, 34, 0.2);
      border: 1px solid var(--medium-color);
      color: var(--medium-color);
      padding: 4px 8px;
      border-radius: 4px;
      font-size: 12px;
      margin: 4px 4px 0 0;
    }

    .malware-badge {
      background: rgba(248, 81, 73, 0.2);
      border-color: var(--critical-color);
      color: var(--critical-color);
    }

    .dep-remediation {
      background: rgba(35, 134, 54, 0.1);
      border: 1px solid var(--accent-color);
      border-radius: 6px;
      padding: 12px 16px;
      margin-bottom: 16px;
    }

    .dep-remediation .remediation-title {
      font-weight: 600;
      color: var(--accent-color);
      margin-bottom: 8px;
    }

    .ai-explanation {
      background: rgba(88, 166, 255, 0.1);
      border: 1px solid var(--info-color);
      border-radius: 6px;
      padding: 12px 16px;
    }

    .ai-explanation .ai-title {
      font-weight: 600;
      color: var(--info-color);
      margin-bottom: 8px;
    }

    .no-vulnerabilities {
      text-align: center;
      padding: 40px;
      color: var(--text-secondary);
    }

    .no-vulnerabilities .success-icon {
      font-size: 48px;
      display: block;
      margin-bottom: 16px;
    }
  `;
}

export default {
  generateDependencyReportSection,
  generateDependencyStyles
};
