/**
 * SARIF Report Generator
 * Static Analysis Results Interchange Format (SARIF) v2.1.0
 * https://sarifweb.azurewebsites.net/
 * 
 * SARIF is the standard format for:
 * - GitHub Code Scanning
 * - VS Code Problems panel
 * - Azure DevOps security features
 * - Many other security tools
 */

import { ScanResult, Finding, Severity, SecurityStandard } from '../types';
import * as path from 'path';
import * as fs from 'fs';

/**
 * SARIF v2.1.0 Types
 */
interface SarifLog {
  $schema: string;
  version: string;
  runs: SarifRun[];
}

interface SarifRun {
  tool: {
    driver: {
      name: string;
      version: string;
      informationUri: string;
      rules: SarifRule[];
    };
  };
  results: SarifResult[];
  invocations: SarifInvocation[];
  artifacts?: SarifArtifact[];
}

interface SarifRule {
  id: string;
  name: string;
  shortDescription: {
    text: string;
  };
  fullDescription?: {
    text: string;
  };
  helpUri?: string;
  help?: {
    text: string;
    markdown?: string;
  };
  defaultConfiguration: {
    level: 'none' | 'note' | 'warning' | 'error';
  };
  properties?: {
    tags?: string[];
    precision?: 'very-high' | 'high' | 'medium' | 'low';
    'problem.severity'?: 'error' | 'warning' | 'recommendation';
    'security-severity'?: string;
  };
}

interface SarifResult {
  ruleId: string;
  ruleIndex: number;
  level: 'none' | 'note' | 'warning' | 'error';
  message: {
    text: string;
  };
  locations: SarifLocation[];
  fingerprints?: Record<string, string>;
  partialFingerprints?: Record<string, string>;
  codeFlows?: any[];
  relatedLocations?: SarifLocation[];
  fixes?: SarifFix[];
  properties?: Record<string, any>;
}

interface SarifLocation {
  physicalLocation: {
    artifactLocation: {
      uri: string;
      uriBaseId?: string;
    };
    region?: {
      startLine: number;
      startColumn?: number;
      endLine?: number;
      endColumn?: number;
      snippet?: {
        text: string;
      };
    };
  };
  message?: {
    text: string;
  };
}

interface SarifInvocation {
  executionSuccessful: boolean;
  commandLine?: string;
  startTimeUtc?: string;
  endTimeUtc?: string;
  workingDirectory?: {
    uri: string;
  };
  exitCode?: number;
  exitCodeDescription?: string;
}

interface SarifArtifact {
  location: {
    uri: string;
  };
  length?: number;
  mimeType?: string;
}

interface SarifFix {
  description: {
    text: string;
  };
  artifactChanges: Array<{
    artifactLocation: {
      uri: string;
    };
    replacements: Array<{
      deletedRegion: {
        startLine: number;
        endLine?: number;
      };
      insertedContent?: {
        text: string;
      };
    }>;
  }>;
}

/**
 * SARIF Report Generator Class
 */
export class SarifReportGenerator {
  private toolName = 'secure-scan';
  private toolVersion = '1.2.5';
  private informationUri = 'https://github.com/Luis000923/secure-scan';
  private schemaUri = 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json';

  /**
   * Convert severity to SARIF level
   */
  private severityToLevel(severity: Severity): 'none' | 'note' | 'warning' | 'error' {
    switch (severity) {
      case Severity.CRITICAL:
      case Severity.HIGH:
        return 'error';
      case Severity.MEDIUM:
        return 'warning';
      case Severity.LOW:
        return 'note';
      case Severity.INFO:
      default:
        return 'none';
    }
  }

  /**
   * Convert severity to security severity score (0.0 - 10.0)
   */
  private severityToScore(severity: Severity): string {
    switch (severity) {
      case Severity.CRITICAL:
        return '9.5';
      case Severity.HIGH:
        return '7.5';
      case Severity.MEDIUM:
        return '5.0';
      case Severity.LOW:
        return '2.5';
      case Severity.INFO:
      default:
        return '0.0';
    }
  }

  /**
   * Build tags from standards
   */
  private buildTags(finding: Finding): string[] {
    const tags: string[] = [finding.category, finding.threatType];
    
    for (const standard of finding.standards || []) {
      tags.push(`${standard.name}:${standard.id}`);
    }
    
    if (finding.tags) {
      tags.push(...finding.tags);
    }
    
    return [...new Set(tags)];
  }

  /**
   * Generate a rule from a finding
   */
  private findingToRule(finding: Finding): SarifRule {
    const helpText = [
      `**Threat Type:** ${finding.threatType}`,
      `**Category:** ${finding.category}`,
      '',
      '## Description',
      finding.description,
      '',
      '## Remediation',
      finding.remediation,
    ];

    // Add standards references
    if (finding.standards && finding.standards.length > 0) {
      helpText.push('', '## Security Standards');
      for (const standard of finding.standards) {
        helpText.push(`- **${standard.name} ${standard.id}**: ${standard.title}`);
        if (standard.url) {
          helpText.push(`  - [More info](${standard.url})`);
        }
      }
    }

    return {
      id: finding.ruleId || finding.id,
      name: finding.title,
      shortDescription: {
        text: finding.title
      },
      fullDescription: {
        text: finding.description
      },
      helpUri: this.getHelpUri(finding),
      help: {
        text: helpText.join('\n'),
        markdown: helpText.join('\n')
      },
      defaultConfiguration: {
        level: this.severityToLevel(finding.severity)
      },
      properties: {
        tags: this.buildTags(finding),
        precision: finding.confidence >= 90 ? 'very-high' :
                   finding.confidence >= 70 ? 'high' :
                   finding.confidence >= 50 ? 'medium' : 'low',
        'problem.severity': this.severityToLevel(finding.severity) === 'error' ? 'error' :
                           this.severityToLevel(finding.severity) === 'warning' ? 'warning' : 'recommendation',
        'security-severity': this.severityToScore(finding.severity)
      }
    };
  }

  /**
   * Get help URI for a finding
   */
  private getHelpUri(finding: Finding): string {
    // Try to find a CWE reference
    const cweStandard = finding.standards?.find(s => s.name === 'CWE');
    if (cweStandard) {
      const cweId = cweStandard.id.replace('CWE-', '');
      return `https://cwe.mitre.org/data/definitions/${cweId}.html`;
    }
    
    // Try OWASP
    const owaspStandard = finding.standards?.find(s => s.name === 'OWASP');
    if (owaspStandard) {
      return `https://owasp.org/Top10/`;
    }

    return this.informationUri;
  }

  /**
   * Convert finding to SARIF result
   */
  private findingToResult(finding: Finding, ruleIndex: number, baseDir: string): SarifResult {
    // Normalize file path for SARIF (use forward slashes)
    const relativePath = finding.location.file.replace(/\\/g, '/');
    
    return {
      ruleId: finding.ruleId || finding.id,
      ruleIndex,
      level: this.severityToLevel(finding.severity),
      message: {
        text: `${finding.title}: ${finding.description}`
      },
      locations: [{
        physicalLocation: {
          artifactLocation: {
            uri: relativePath,
            uriBaseId: '%SRCROOT%'
          },
          region: {
            startLine: finding.location.startLine,
            startColumn: finding.location.startColumn || 1,
            endLine: finding.location.endLine,
            endColumn: finding.location.endColumn,
            snippet: {
              text: finding.snippet?.code || ''
            }
          }
        }
      }],
      fingerprints: {
        'secure-scan/v1': finding.id
      },
      partialFingerprints: {
        'primaryLocationLineHash': this.hashString(`${relativePath}:${finding.location.startLine}:${finding.ruleId}`)
      },
      properties: {
        confidence: finding.confidence,
        category: finding.category,
        threatType: finding.threatType,
        analyzer: finding.analyzer
      }
    };
  }

  /**
   * Simple hash function for fingerprints
   */
  private hashString(str: string): string {
    let hash = 0;
    for (let i = 0; i < str.length; i++) {
      const char = str.charCodeAt(i);
      hash = ((hash << 5) - hash) + char;
      hash = hash & hash;
    }
    return Math.abs(hash).toString(16);
  }

  /**
   * Generate SARIF report from scan result
   */
  generate(result: ScanResult): SarifLog {
    const rules: SarifRule[] = [];
    const results: SarifResult[] = [];
    const ruleIdToIndex = new Map<string, number>();

    // Process each finding
    for (const finding of result.findings) {
      const ruleId = finding.ruleId || finding.id;
      
      // Add rule if not already added
      if (!ruleIdToIndex.has(ruleId)) {
        const ruleIndex = rules.length;
        rules.push(this.findingToRule(finding));
        ruleIdToIndex.set(ruleId, ruleIndex);
      }

      // Add result
      const ruleIndex = ruleIdToIndex.get(ruleId)!;
      results.push(this.findingToResult(finding, ruleIndex, result.projectPath));
    }

    // Build SARIF log
    const sarifLog: SarifLog = {
      $schema: this.schemaUri,
      version: '2.1.0',
      runs: [{
        tool: {
          driver: {
            name: this.toolName,
            version: this.toolVersion,
            informationUri: this.informationUri,
            rules
          }
        },
        results,
        invocations: [{
          executionSuccessful: true,
          startTimeUtc: result.scanStartTime || new Date().toISOString(),
          endTimeUtc: result.scanEndTime || new Date().toISOString(),
          workingDirectory: {
            uri: `file:///${result.projectPath.replace(/\\/g, '/')}`
          },
          exitCode: result.findings.some(f => f.severity === Severity.CRITICAL) ? 2 :
                   result.findings.some(f => f.severity === Severity.HIGH) ? 1 : 0,
          exitCodeDescription: result.findings.some(f => f.severity === Severity.CRITICAL) 
            ? 'Critical vulnerabilities found'
            : result.findings.some(f => f.severity === Severity.HIGH)
              ? 'High severity vulnerabilities found'
              : 'Scan completed successfully'
        }]
      }]
    };

    return sarifLog;
  }

  /**
   * Generate and save SARIF report to file
   */
  async saveToFile(result: ScanResult, outputPath: string): Promise<string> {
    const sarifLog = this.generate(result);
    const jsonContent = JSON.stringify(sarifLog, null, 2);
    
    // Ensure .sarif extension
    let finalPath = outputPath;
    if (!finalPath.endsWith('.sarif') && !finalPath.endsWith('.sarif.json')) {
      finalPath = finalPath.replace(/\.(html|json)$/, '') + '.sarif';
    }

    await fs.promises.writeFile(finalPath, jsonContent, 'utf-8');
    
    return finalPath;
  }

  /**
   * Generate SARIF JSON string
   */
  toString(result: ScanResult): string {
    const sarifLog = this.generate(result);
    return JSON.stringify(sarifLog, null, 2);
  }
}

// Export singleton instance
export const sarifReportGenerator = new SarifReportGenerator();

export default SarifReportGenerator;
