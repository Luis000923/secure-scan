/**
 * Known Vulnerable Packages Database
 * Static database of known CVEs for offline vulnerability detection
 * This is a sample database - in production, integrate with OSV, NVD, or Snyk APIs
 */

import { CVEInfo, PackageEcosystem, Severity } from '../types';

/**
 * CVE database entry
 */
export interface CVEDatabaseEntry {
  ecosystem: PackageEcosystem;
  packageName: string;
  cve: CVEInfo;
  vulnerableVersions: string[];
}

/**
 * Sample CVE database with well-known vulnerabilities
 */
export const CVE_DATABASE: CVEDatabaseEntry[] = [
  // Log4Shell - Critical Java vulnerability
  {
    ecosystem: 'maven',
    packageName: 'org.apache.logging.log4j:log4j-core',
    cve: {
      id: 'CVE-2021-44228',
      description: 'Apache Log4j2 JNDI features used in configuration, log messages, and parameters do not protect against attacker controlled LDAP and other JNDI related endpoints.',
      cvssScore: 10.0,
      severity: Severity.CRITICAL,
      publishedDate: '2021-12-10',
      references: [
        'https://nvd.nist.gov/vuln/detail/CVE-2021-44228',
        'https://logging.apache.org/log4j/2.x/security.html'
      ],
      fixedVersion: '2.17.0',
      cwes: ['CWE-502', 'CWE-400', 'CWE-20'],
      exploitAvailable: true
    },
    vulnerableVersions: ['2.0-beta9', '2.0-rc1', '2.0-rc2', '2.0', '2.0.1', '2.0.2', '2.1', '2.2', '2.3', '2.4', '2.4.1', '2.5', '2.6', '2.6.1', '2.6.2', '2.7', '2.8', '2.8.1', '2.8.2', '2.9.0', '2.9.1', '2.10.0', '2.11.0', '2.11.1', '2.11.2', '2.12.0', '2.12.1', '2.13.0', '2.13.1', '2.13.2', '2.13.3', '2.14.0', '2.14.1', '2.15.0', '2.16.0']
  },

  // Lodash prototype pollution
  {
    ecosystem: 'npm',
    packageName: 'lodash',
    cve: {
      id: 'CVE-2020-8203',
      description: 'Prototype pollution vulnerability in lodash before 4.17.20 allows attackers to cause denial of service or execute arbitrary code via merge, mergeWith, and defaultsDeep functions.',
      cvssScore: 7.4,
      severity: Severity.HIGH,
      publishedDate: '2020-07-15',
      references: [
        'https://nvd.nist.gov/vuln/detail/CVE-2020-8203',
        'https://github.com/lodash/lodash/issues/4744'
      ],
      fixedVersion: '4.17.20',
      cwes: ['CWE-1321'],
      exploitAvailable: true
    },
    vulnerableVersions: ['<4.17.20']
  },
  {
    ecosystem: 'npm',
    packageName: 'lodash',
    cve: {
      id: 'CVE-2021-23337',
      description: 'Lodash versions prior to 4.17.21 are vulnerable to Command Injection via the template function.',
      cvssScore: 7.2,
      severity: Severity.HIGH,
      publishedDate: '2021-02-15',
      references: [
        'https://nvd.nist.gov/vuln/detail/CVE-2021-23337',
        'https://snyk.io/vuln/SNYK-JS-LODASH-1040724'
      ],
      fixedVersion: '4.17.21',
      cwes: ['CWE-94'],
      exploitAvailable: true
    },
    vulnerableVersions: ['<4.17.21']
  },

  // Express.js vulnerabilities
  {
    ecosystem: 'npm',
    packageName: 'express',
    cve: {
      id: 'CVE-2022-24999',
      description: 'qs before 6.10.3 allows attackers to cause a Node process hang because an __ proto__ key can be used.',
      cvssScore: 7.5,
      severity: Severity.HIGH,
      publishedDate: '2022-11-26',
      references: [
        'https://nvd.nist.gov/vuln/detail/CVE-2022-24999'
      ],
      fixedVersion: '4.18.2',
      cwes: ['CWE-1321'],
      exploitAvailable: false
    },
    vulnerableVersions: ['<4.18.2']
  },

  // Django vulnerabilities
  {
    ecosystem: 'pip',
    packageName: 'django',
    cve: {
      id: 'CVE-2023-36053',
      description: 'Django 3.2 before 3.2.20, 4.1 before 4.1.10, and 4.2 before 4.2.3 allows a denial of service via EmailValidator/URLValidator regex backtracking.',
      cvssScore: 7.5,
      severity: Severity.HIGH,
      publishedDate: '2023-07-03',
      references: [
        'https://nvd.nist.gov/vuln/detail/CVE-2023-36053',
        'https://www.djangoproject.com/weblog/2023/jul/03/security-releases/'
      ],
      fixedVersion: '4.2.3',
      cwes: ['CWE-1333'],
      exploitAvailable: false
    },
    vulnerableVersions: ['<3.2.20', '>=4.0,<4.1.10', '>=4.2,<4.2.3']
  },
  {
    ecosystem: 'pip',
    packageName: 'django',
    cve: {
      id: 'CVE-2023-41164',
      description: 'Django 3.2.x before 3.2.21, 4.1.x before 4.1.11, and 4.2.x before 4.2.5 allows a denial of service in django.utils.encoding.uri_to_iri.',
      cvssScore: 7.5,
      severity: Severity.HIGH,
      publishedDate: '2023-09-04',
      references: [
        'https://nvd.nist.gov/vuln/detail/CVE-2023-41164'
      ],
      fixedVersion: '4.2.5',
      cwes: ['CWE-400'],
      exploitAvailable: false
    },
    vulnerableVersions: ['<3.2.21', '>=4.0,<4.1.11', '>=4.2,<4.2.5']
  },

  // Flask vulnerabilities
  {
    ecosystem: 'pip',
    packageName: 'flask',
    cve: {
      id: 'CVE-2023-30861',
      description: 'Flask is a lightweight WSGI web application framework. Versions prior to 2.2.5 and 2.3.2 are vulnerable to possible disclosure of permanent session cookie.',
      cvssScore: 7.5,
      severity: Severity.HIGH,
      publishedDate: '2023-05-02',
      references: [
        'https://nvd.nist.gov/vuln/detail/CVE-2023-30861',
        'https://github.com/pallets/flask/security/advisories/GHSA-m2qf-hxjv-5gpq'
      ],
      fixedVersion: '2.3.2',
      cwes: ['CWE-539'],
      exploitAvailable: false
    },
    vulnerableVersions: ['<2.2.5', '>=2.3,<2.3.2']
  },

  // Axios vulnerabilities
  {
    ecosystem: 'npm',
    packageName: 'axios',
    cve: {
      id: 'CVE-2023-45857',
      description: 'An issue in Axios allows a request to a non-HTTPS destination to leak the secret XSRF-TOKEN cookie value.',
      cvssScore: 6.5,
      severity: Severity.MEDIUM,
      publishedDate: '2023-11-08',
      references: [
        'https://nvd.nist.gov/vuln/detail/CVE-2023-45857'
      ],
      fixedVersion: '1.6.0',
      cwes: ['CWE-352'],
      exploitAvailable: false
    },
    vulnerableVersions: ['>=0.8.1,<1.6.0']
  },

  // jQuery vulnerabilities
  {
    ecosystem: 'npm',
    packageName: 'jquery',
    cve: {
      id: 'CVE-2020-11023',
      description: 'In jQuery versions greater than or equal to 1.0.3 and before 3.5.0, passing HTML containing <option> elements from untrusted sources to one of jQuerys DOM manipulation methods may execute untrusted code.',
      cvssScore: 6.1,
      severity: Severity.MEDIUM,
      publishedDate: '2020-04-29',
      references: [
        'https://nvd.nist.gov/vuln/detail/CVE-2020-11023',
        'https://blog.jquery.com/2020/04/10/jquery-3-5-0-released/'
      ],
      fixedVersion: '3.5.0',
      cwes: ['CWE-79'],
      exploitAvailable: true
    },
    vulnerableVersions: ['>=1.0.3,<3.5.0']
  },

  // Symfony vulnerabilities
  {
    ecosystem: 'composer',
    packageName: 'symfony/http-kernel',
    cve: {
      id: 'CVE-2023-46733',
      description: 'Symfony is a PHP framework. When using the RememberMe Bundle, an attacker can cause a session to survive an password change.',
      cvssScore: 6.5,
      severity: Severity.MEDIUM,
      publishedDate: '2023-11-10',
      references: [
        'https://nvd.nist.gov/vuln/detail/CVE-2023-46733',
        'https://symfony.com/cve-2023-46733'
      ],
      fixedVersion: '6.3.8',
      cwes: ['CWE-613'],
      exploitAvailable: false
    },
    vulnerableVersions: ['>=5.4,<5.4.31', '>=6.0,<6.3.8']
  },

  // Laravel vulnerabilities
  {
    ecosystem: 'composer',
    packageName: 'laravel/framework',
    cve: {
      id: 'CVE-2021-43617',
      description: 'Laravel Framework before 8.75.0 is vulnerable to cookie theft due to insecure default cookie serialization.',
      cvssScore: 9.8,
      severity: Severity.CRITICAL,
      publishedDate: '2021-11-18',
      references: [
        'https://nvd.nist.gov/vuln/detail/CVE-2021-43617'
      ],
      fixedVersion: '8.75.0',
      cwes: ['CWE-502'],
      exploitAvailable: true
    },
    vulnerableVersions: ['<8.75.0']
  },

  // Spring Framework vulnerabilities
  {
    ecosystem: 'maven',
    packageName: 'org.springframework:spring-core',
    cve: {
      id: 'CVE-2022-22965',
      description: 'Spring Framework RCE via Data Binding on JDK 9+ (Spring4Shell)',
      cvssScore: 9.8,
      severity: Severity.CRITICAL,
      publishedDate: '2022-03-31',
      references: [
        'https://nvd.nist.gov/vuln/detail/CVE-2022-22965',
        'https://spring.io/blog/2022/03/31/spring-framework-rce-early-announcement'
      ],
      fixedVersion: '5.3.18',
      cwes: ['CWE-94'],
      exploitAvailable: true
    },
    vulnerableVersions: ['>=5.3.0,<5.3.18', '>=5.2.0,<5.2.20']
  },

  // Jackson vulnerabilities
  {
    ecosystem: 'maven',
    packageName: 'com.fasterxml.jackson.core:jackson-databind',
    cve: {
      id: 'CVE-2020-36518',
      description: 'jackson-databind allows Java stack overflow exception via a deeply nested JSON array.',
      cvssScore: 7.5,
      severity: Severity.HIGH,
      publishedDate: '2022-03-11',
      references: [
        'https://nvd.nist.gov/vuln/detail/CVE-2020-36518'
      ],
      fixedVersion: '2.13.2.1',
      cwes: ['CWE-787'],
      exploitAvailable: false
    },
    vulnerableVersions: ['<2.13.2.1']
  },

  // Newtonsoft.Json vulnerabilities
  {
    ecosystem: 'nuget',
    packageName: 'Newtonsoft.Json',
    cve: {
      id: 'CVE-2024-21907',
      description: 'Newtonsoft.Json before 13.0.1 is vulnerable to a denial of service attack when parsing deeply nested JSON.',
      cvssScore: 7.5,
      severity: Severity.HIGH,
      publishedDate: '2024-01-03',
      references: [
        'https://nvd.nist.gov/vuln/detail/CVE-2024-21907'
      ],
      fixedVersion: '13.0.1',
      cwes: ['CWE-400'],
      exploitAvailable: false
    },
    vulnerableVersions: ['<13.0.1']
  },

  // OpenSSL vulnerabilities
  {
    ecosystem: 'vcpkg',
    packageName: 'openssl',
    cve: {
      id: 'CVE-2022-3602',
      description: 'X.509 Email Address 4-byte Buffer Overflow in OpenSSL.',
      cvssScore: 7.5,
      severity: Severity.HIGH,
      publishedDate: '2022-11-01',
      references: [
        'https://nvd.nist.gov/vuln/detail/CVE-2022-3602',
        'https://www.openssl.org/news/secadv/20221101.txt'
      ],
      fixedVersion: '3.0.7',
      cwes: ['CWE-120'],
      exploitAvailable: true
    },
    vulnerableVersions: ['>=3.0.0,<3.0.7']
  }
];

/**
 * Check if a version matches a vulnerable version pattern
 */
export function isVersionVulnerable(version: string, vulnerablePatterns: string[]): boolean {
  // Normalize version
  const normalizedVersion = version.replace(/^[v=]/, '').trim();
  
  for (const pattern of vulnerablePatterns) {
    if (matchVersionPattern(normalizedVersion, pattern)) {
      return true;
    }
  }
  
  return false;
}

/**
 * Match version against a pattern
 * Supports: exact match, <version, <=version, >version, >=version, range
 */
function matchVersionPattern(version: string, pattern: string): boolean {
  // Exact match
  if (pattern === version) return true;
  
  // Less than
  if (pattern.startsWith('<')) {
    const targetVersion = pattern.replace(/^<=?/, '');
    const isLessOrEqual = pattern.startsWith('<=');
    const comparison = compareVersions(version, targetVersion);
    return isLessOrEqual ? comparison <= 0 : comparison < 0;
  }
  
  // Greater than
  if (pattern.startsWith('>')) {
    const targetVersion = pattern.replace(/^>=?/, '');
    const isGreaterOrEqual = pattern.startsWith('>=');
    const comparison = compareVersions(version, targetVersion);
    return isGreaterOrEqual ? comparison >= 0 : comparison > 0;
  }
  
  // Range (e.g., ">=1.0.0,<2.0.0")
  if (pattern.includes(',')) {
    const parts = pattern.split(',');
    return parts.every(p => matchVersionPattern(version, p.trim()));
  }
  
  // Wildcard match
  if (pattern === '*') return true;
  
  return false;
}

/**
 * Compare two semver versions
 * Returns: -1 if a < b, 0 if a == b, 1 if a > b
 */
function compareVersions(a: string, b: string): number {
  const partsA = a.split('.').map(p => parseInt(p, 10) || 0);
  const partsB = b.split('.').map(p => parseInt(p, 10) || 0);
  
  const maxLength = Math.max(partsA.length, partsB.length);
  
  for (let i = 0; i < maxLength; i++) {
    const partA = partsA[i] || 0;
    const partB = partsB[i] || 0;
    
    if (partA < partB) return -1;
    if (partA > partB) return 1;
  }
  
  return 0;
}

/**
 * Get CVEs for a package
 */
export function getCVEsForPackage(packageName: string, ecosystem: PackageEcosystem, version?: string): CVEInfo[] {
  const entries = CVE_DATABASE.filter(e => 
    e.packageName.toLowerCase() === packageName.toLowerCase() && 
    e.ecosystem === ecosystem
  );
  
  if (!version) {
    return entries.map(e => e.cve);
  }
  
  // Filter by vulnerable version
  return entries
    .filter(e => isVersionVulnerable(version, e.vulnerableVersions))
    .map(e => e.cve);
}

/**
 * Get all CVEs in the database
 */
export function getAllCVEs(): CVEDatabaseEntry[] {
  return CVE_DATABASE;
}
