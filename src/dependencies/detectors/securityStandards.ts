/**
 * Security Standards for Dependency Analysis
 * Maps dependency risks to OWASP, CWE, MITRE, and SANS standards
 */

import { SecurityStandard } from '../../types';
import { DependencyRiskCategory } from '../types';

/**
 * OWASP A06:2021 - Vulnerable and Outdated Components
 */
const OWASP_A06: SecurityStandard = {
  name: 'OWASP',
  id: 'A06:2021',
  title: 'Vulnerable and Outdated Components',
  description: 'Components, such as libraries, frameworks, and other software modules, run with the same privileges as the application. If a vulnerable component is exploited, such an attack can facilitate serious data loss or server takeover.',
  url: 'https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/'
};

/**
 * CWE-937 - OWASP Top 10 2017 Category A9 - Using Components with Known Vulnerabilities
 */
const CWE_937: SecurityStandard = {
  name: 'CWE',
  id: 'CWE-937',
  title: 'Using Components with Known Vulnerabilities',
  description: 'The product uses a component that has a known vulnerability.',
  url: 'https://cwe.mitre.org/data/definitions/937.html'
};

/**
 * CWE-1035 - OWASP Top 10 2017 Category A9 - Using Components with Known Vulnerabilities
 */
const CWE_1035: SecurityStandard = {
  name: 'CWE',
  id: 'CWE-1035',
  title: 'OWASP Top 10 2017 Category A9',
  description: 'Weaknesses in this category are related to the A9 category Using Components with Known Vulnerabilities in the OWASP Top 10 2017.',
  url: 'https://cwe.mitre.org/data/definitions/1035.html'
};

/**
 * CWE-506 - Embedded Malicious Code
 */
const CWE_506: SecurityStandard = {
  name: 'CWE',
  id: 'CWE-506',
  title: 'Embedded Malicious Code',
  description: 'The product contains code that appears to be malicious in nature.',
  url: 'https://cwe.mitre.org/data/definitions/506.html'
};

/**
 * CWE-829 - Inclusion of Functionality from Untrusted Control Sphere
 */
const CWE_829: SecurityStandard = {
  name: 'CWE',
  id: 'CWE-829',
  title: 'Inclusion of Functionality from Untrusted Control Sphere',
  description: 'The product imports, requires, or includes executable functionality from a source that is outside of the intended control sphere.',
  url: 'https://cwe.mitre.org/data/definitions/829.html'
};

/**
 * CWE-1104 - Use of Unmaintained Third Party Components
 */
const CWE_1104: SecurityStandard = {
  name: 'CWE',
  id: 'CWE-1104',
  title: 'Use of Unmaintained Third Party Components',
  description: 'The product relies on third-party components that are not actively supported or maintained by the original developer or a trusted proxy.',
  url: 'https://cwe.mitre.org/data/definitions/1104.html'
};

/**
 * MITRE ATT&CK - Supply Chain Compromise
 */
const MITRE_SUPPLY_CHAIN: SecurityStandard = {
  name: 'MITRE',
  id: 'T1195',
  title: 'Supply Chain Compromise',
  description: 'Adversaries may manipulate products or product delivery mechanisms prior to receipt by a final consumer for the purpose of data or system compromise.',
  url: 'https://attack.mitre.org/techniques/T1195/'
};

/**
 * MITRE ATT&CK - Compromise Software Supply Chain
 */
const MITRE_T1195_002: SecurityStandard = {
  name: 'MITRE',
  id: 'T1195.002',
  title: 'Compromise Software Supply Chain',
  description: 'Adversaries may manipulate application software prior to receipt by a final consumer for the purpose of data or system compromise.',
  url: 'https://attack.mitre.org/techniques/T1195/002/'
};

/**
 * SANS Top 25 - Related entries
 */
const SANS_UNTRUSTED_INPUT: SecurityStandard = {
  name: 'SANS',
  id: 'SANS-1',
  title: 'Improper Neutralization of Special Elements',
  description: 'Failure to properly validate and sanitize input from untrusted sources.',
  url: 'https://www.sans.org/top25-software-errors/'
};

/**
 * Get standards for a specific CWE
 */
function getCWEStandard(cweId: string): SecurityStandard | null {
  const cweMap: Record<string, SecurityStandard> = {
    'CWE-937': CWE_937,
    'CWE-1035': CWE_1035,
    'CWE-506': CWE_506,
    'CWE-829': CWE_829,
    'CWE-1104': CWE_1104
  };

  if (cweMap[cweId]) {
    return cweMap[cweId];
  }

  // Create a generic CWE standard for unknown CWEs
  const cweNumber = cweId.replace('CWE-', '');
  return {
    name: 'CWE',
    id: cweId,
    title: `CWE-${cweNumber}`,
    description: `Common Weakness Enumeration ${cweNumber}`,
    url: `https://cwe.mitre.org/data/definitions/${cweNumber}.html`
  };
}

/**
 * Get security standards for a dependency risk category
 */
export function getStandardsForDependencyRisk(
  category: DependencyRiskCategory,
  cwes?: string[]
): SecurityStandard[] {
  const standards: SecurityStandard[] = [];

  // Always include OWASP A06 for dependency risks
  standards.push(OWASP_A06);

  switch (category) {
    case DependencyRiskCategory.VULNERABILITY:
      standards.push(CWE_937, CWE_1035);
      // Add specific CWEs if provided
      if (cwes) {
        for (const cwe of cwes) {
          const cweStandard = getCWEStandard(cwe);
          if (cweStandard && !standards.some(s => s.id === cweStandard.id)) {
            standards.push(cweStandard);
          }
        }
      }
      break;

    case DependencyRiskCategory.MALICIOUS:
      standards.push(CWE_506, CWE_829, MITRE_SUPPLY_CHAIN, MITRE_T1195_002);
      break;

    case DependencyRiskCategory.SUPPLY_CHAIN:
      standards.push(CWE_829, MITRE_SUPPLY_CHAIN, MITRE_T1195_002);
      break;

    case DependencyRiskCategory.OUTDATED:
      standards.push(CWE_1104);
      break;

    case DependencyRiskCategory.MAINTENANCE:
      standards.push(CWE_1104);
      break;

    case DependencyRiskCategory.LICENSE:
      // No specific security standards for license issues
      break;
  }

  return standards;
}

/**
 * Get all dependency-related security standards
 */
export function getAllDependencyStandards(): SecurityStandard[] {
  return [
    OWASP_A06,
    CWE_937,
    CWE_1035,
    CWE_506,
    CWE_829,
    CWE_1104,
    MITRE_SUPPLY_CHAIN,
    MITRE_T1195_002,
    SANS_UNTRUSTED_INPUT
  ];
}
