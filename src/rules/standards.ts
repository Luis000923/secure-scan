/**
 * Security Standards Database
 * OWASP Top 10, CWE, MITRE ATT&CK, SANS Top 25
 */

import { SecurityStandard, ThreatType } from '../types';

/**
 * OWASP Top 10 2021
 */
export const OWASP_TOP_10: Record<string, SecurityStandard> = {
  'A01:2021': {
    name: 'OWASP',
    id: 'A01:2021',
    title: 'Broken Access Control',
    description: 'Access control enforces policy such that users cannot act outside of their intended permissions.',
    url: 'https://owasp.org/Top10/A01_2021-Broken_Access_Control/'
  },
  'A02:2021': {
    name: 'OWASP',
    id: 'A02:2021',
    title: 'Cryptographic Failures',
    description: 'Failures related to cryptography which often lead to sensitive data exposure.',
    url: 'https://owasp.org/Top10/A02_2021-Cryptographic_Failures/'
  },
  'A03:2021': {
    name: 'OWASP',
    id: 'A03:2021',
    title: 'Injection',
    description: 'User-supplied data is not validated, filtered, or sanitized by the application.',
    url: 'https://owasp.org/Top10/A03_2021-Injection/'
  },
  'A04:2021': {
    name: 'OWASP',
    id: 'A04:2021',
    title: 'Insecure Design',
    description: 'Missing or ineffective control design.',
    url: 'https://owasp.org/Top10/A04_2021-Insecure_Design/'
  },
  'A05:2021': {
    name: 'OWASP',
    id: 'A05:2021',
    title: 'Security Misconfiguration',
    description: 'Missing appropriate security hardening or improperly configured permissions.',
    url: 'https://owasp.org/Top10/A05_2021-Security_Misconfiguration/'
  },
  'A06:2021': {
    name: 'OWASP',
    id: 'A06:2021',
    title: 'Vulnerable and Outdated Components',
    description: 'Using components with known vulnerabilities.',
    url: 'https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/'
  },
  'A07:2021': {
    name: 'OWASP',
    id: 'A07:2021',
    title: 'Identification and Authentication Failures',
    description: 'Confirmation of user identity, authentication, and session management.',
    url: 'https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/'
  },
  'A08:2021': {
    name: 'OWASP',
    id: 'A08:2021',
    title: 'Software and Data Integrity Failures',
    description: 'Code and infrastructure that does not protect against integrity violations.',
    url: 'https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/'
  },
  'A09:2021': {
    name: 'OWASP',
    id: 'A09:2021',
    title: 'Security Logging and Monitoring Failures',
    description: 'Insufficient logging, detection, monitoring, and active response.',
    url: 'https://owasp.org/Top10/A09_2021-Security_Logging_and_Monitoring_Failures/'
  },
  'A10:2021': {
    name: 'OWASP',
    id: 'A10:2021',
    title: 'Server-Side Request Forgery (SSRF)',
    description: 'SSRF flaws occur when a web application fetches a remote resource without validating the user-supplied URL.',
    url: 'https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/'
  }
};

/**
 * Common Weakness Enumeration (CWE)
 */
export const CWE_DATABASE: Record<string, SecurityStandard> = {
  'CWE-79': {
    name: 'CWE',
    id: 'CWE-79',
    title: 'Improper Neutralization of Input During Web Page Generation (XSS)',
    description: 'The software does not neutralize or incorrectly neutralizes user-controllable input before it is placed in output that is used as a web page.',
    url: 'https://cwe.mitre.org/data/definitions/79.html'
  },
  'CWE-89': {
    name: 'CWE',
    id: 'CWE-89',
    title: 'SQL Injection',
    description: 'The software constructs SQL commands using externally-influenced input from an upstream component.',
    url: 'https://cwe.mitre.org/data/definitions/89.html'
  },
  'CWE-78': {
    name: 'CWE',
    id: 'CWE-78',
    title: 'OS Command Injection',
    description: 'The software constructs OS commands using externally-influenced input without proper neutralization.',
    url: 'https://cwe.mitre.org/data/definitions/78.html'
  },
  'CWE-94': {
    name: 'CWE',
    id: 'CWE-94',
    title: 'Improper Control of Generation of Code (Code Injection)',
    description: 'The software constructs code segments using externally-influenced input without proper neutralization.',
    url: 'https://cwe.mitre.org/data/definitions/94.html'
  },
  'CWE-502': {
    name: 'CWE',
    id: 'CWE-502',
    title: 'Deserialization of Untrusted Data',
    description: 'The application deserializes untrusted data without sufficiently verifying that the resulting data will be valid.',
    url: 'https://cwe.mitre.org/data/definitions/502.html'
  },
  'CWE-798': {
    name: 'CWE',
    id: 'CWE-798',
    title: 'Use of Hard-coded Credentials',
    description: 'The software contains hard-coded credentials, such as passwords or cryptographic keys.',
    url: 'https://cwe.mitre.org/data/definitions/798.html'
  },
  'CWE-22': {
    name: 'CWE',
    id: 'CWE-22',
    title: 'Path Traversal',
    description: 'The software uses external input to construct a pathname without proper neutralization.',
    url: 'https://cwe.mitre.org/data/definitions/22.html'
  },
  'CWE-327': {
    name: 'CWE',
    id: 'CWE-327',
    title: 'Use of a Broken or Risky Cryptographic Algorithm',
    description: 'The use of a broken or risky cryptographic algorithm is an unnecessary risk.',
    url: 'https://cwe.mitre.org/data/definitions/327.html'
  },
  'CWE-330': {
    name: 'CWE',
    id: 'CWE-330',
    title: 'Use of Insufficiently Random Values',
    description: 'The software uses insufficiently random numbers or values in a security context.',
    url: 'https://cwe.mitre.org/data/definitions/330.html'
  },
  'CWE-352': {
    name: 'CWE',
    id: 'CWE-352',
    title: 'Cross-Site Request Forgery (CSRF)',
    description: 'The web application does not verify that the request was intentionally provided by the user.',
    url: 'https://cwe.mitre.org/data/definitions/352.html'
  },
  'CWE-90': {
    name: 'CWE',
    id: 'CWE-90',
    title: 'LDAP Injection',
    description: 'The software constructs LDAP statements using externally-influenced input.',
    url: 'https://cwe.mitre.org/data/definitions/90.html'
  },
  'CWE-200': {
    name: 'CWE',
    id: 'CWE-200',
    title: 'Exposure of Sensitive Information',
    description: 'The software exposes sensitive information to an actor not authorized to have access.',
    url: 'https://cwe.mitre.org/data/definitions/200.html'
  },
  'CWE-506': {
    name: 'CWE',
    id: 'CWE-506',
    title: 'Embedded Malicious Code',
    description: 'The application contains code that appears to be malicious in nature.',
    url: 'https://cwe.mitre.org/data/definitions/506.html'
  },
  'CWE-912': {
    name: 'CWE',
    id: 'CWE-912',
    title: 'Hidden Functionality',
    description: 'The software contains functionality that is not documented or accessible through the intended interface.',
    url: 'https://cwe.mitre.org/data/definitions/912.html'
  }
};

/**
 * MITRE ATT&CK Techniques
 */
export const MITRE_ATTACK: Record<string, SecurityStandard> = {
  'T1059': {
    name: 'MITRE',
    id: 'T1059',
    title: 'Command and Scripting Interpreter',
    description: 'Adversaries may abuse command and script interpreters to execute commands.',
    url: 'https://attack.mitre.org/techniques/T1059/'
  },
  'T1071': {
    name: 'MITRE',
    id: 'T1071',
    title: 'Application Layer Protocol',
    description: 'Adversaries may communicate using application layer protocols to avoid detection.',
    url: 'https://attack.mitre.org/techniques/T1071/'
  },
  'T1027': {
    name: 'MITRE',
    id: 'T1027',
    title: 'Obfuscated Files or Information',
    description: 'Adversaries may attempt to make files or information difficult to discover or analyze.',
    url: 'https://attack.mitre.org/techniques/T1027/'
  },
  'T1132': {
    name: 'MITRE',
    id: 'T1132',
    title: 'Data Encoding',
    description: 'Adversaries may encode data to make the content of command and control traffic more difficult to detect.',
    url: 'https://attack.mitre.org/techniques/T1132/'
  },
  'T1041': {
    name: 'MITRE',
    id: 'T1041',
    title: 'Exfiltration Over C2 Channel',
    description: 'Adversaries may steal data by exfiltrating it over an existing command and control channel.',
    url: 'https://attack.mitre.org/techniques/T1041/'
  },
  'T1496': {
    name: 'MITRE',
    id: 'T1496',
    title: 'Resource Hijacking',
    description: 'Adversaries may leverage the resources of systems to mine cryptocurrency.',
    url: 'https://attack.mitre.org/techniques/T1496/'
  },
  'T1056': {
    name: 'MITRE',
    id: 'T1056',
    title: 'Input Capture',
    description: 'Adversaries may use methods of capturing user input to obtain credentials or collect information.',
    url: 'https://attack.mitre.org/techniques/T1056/'
  }
};

/**
 * SANS Top 25
 */
export const SANS_TOP_25: Record<string, SecurityStandard> = {
  'SANS-1': {
    name: 'SANS',
    id: 'SANS-1',
    title: 'Out-of-bounds Write',
    description: 'Writing data past the end, or before the beginning, of the intended buffer.',
    url: 'https://www.sans.org/top25-software-errors/'
  },
  'SANS-2': {
    name: 'SANS',
    id: 'SANS-2',
    title: 'Improper Neutralization of Input During Web Page Generation',
    description: 'Cross-site scripting (XSS) vulnerabilities.',
    url: 'https://www.sans.org/top25-software-errors/'
  },
  'SANS-3': {
    name: 'SANS',
    id: 'SANS-3',
    title: 'SQL Injection',
    description: 'SQL injection vulnerabilities in database queries.',
    url: 'https://www.sans.org/top25-software-errors/'
  }
};

/**
 * Map threat types to relevant security standards
 */
export function getStandardsForThreat(threatType: ThreatType): SecurityStandard[] {
  const standards: SecurityStandard[] = [];

  switch (threatType) {
    case ThreatType.SQL_INJECTION:
      standards.push(OWASP_TOP_10['A03:2021']);
      standards.push(CWE_DATABASE['CWE-89']);
      standards.push(SANS_TOP_25['SANS-3']);
      break;

    case ThreatType.COMMAND_INJECTION:
      standards.push(OWASP_TOP_10['A03:2021']);
      standards.push(CWE_DATABASE['CWE-78']);
      standards.push(MITRE_ATTACK['T1059']);
      break;

    case ThreatType.XSS:
      standards.push(OWASP_TOP_10['A03:2021']);
      standards.push(CWE_DATABASE['CWE-79']);
      standards.push(SANS_TOP_25['SANS-2']);
      break;

    case ThreatType.CSRF:
      standards.push(OWASP_TOP_10['A01:2021']);
      standards.push(CWE_DATABASE['CWE-352']);
      break;

    case ThreatType.INSECURE_DESERIALIZATION:
      standards.push(OWASP_TOP_10['A08:2021']);
      standards.push(CWE_DATABASE['CWE-502']);
      break;

    case ThreatType.HARDCODED_CREDENTIALS:
      standards.push(OWASP_TOP_10['A07:2021']);
      standards.push(CWE_DATABASE['CWE-798']);
      break;

    case ThreatType.PATH_TRAVERSAL:
      standards.push(OWASP_TOP_10['A01:2021']);
      standards.push(CWE_DATABASE['CWE-22']);
      break;

    case ThreatType.LDAP_INJECTION:
      standards.push(OWASP_TOP_10['A03:2021']);
      standards.push(CWE_DATABASE['CWE-90']);
      break;

    case ThreatType.INSECURE_CRYPTO:
      standards.push(OWASP_TOP_10['A02:2021']);
      standards.push(CWE_DATABASE['CWE-327']);
      break;

    case ThreatType.WEAK_RANDOM:
      standards.push(OWASP_TOP_10['A02:2021']);
      standards.push(CWE_DATABASE['CWE-330']);
      break;

    case ThreatType.DANGEROUS_FUNCTION:
      standards.push(OWASP_TOP_10['A03:2021']);
      standards.push(CWE_DATABASE['CWE-94']);
      break;

    case ThreatType.BACKDOOR:
    case ThreatType.REVERSE_SHELL:
      standards.push(CWE_DATABASE['CWE-506']);
      standards.push(CWE_DATABASE['CWE-912']);
      standards.push(MITRE_ATTACK['T1059']);
      break;

    case ThreatType.OBFUSCATED_CODE:
      standards.push(CWE_DATABASE['CWE-506']);
      standards.push(MITRE_ATTACK['T1027']);
      break;

    case ThreatType.CRYPTOMINER:
      standards.push(CWE_DATABASE['CWE-506']);
      standards.push(MITRE_ATTACK['T1496']);
      break;

    case ThreatType.KEYLOGGER:
      standards.push(CWE_DATABASE['CWE-506']);
      standards.push(MITRE_ATTACK['T1056']);
      break;

    case ThreatType.DATA_EXFILTRATION:
      standards.push(CWE_DATABASE['CWE-200']);
      standards.push(MITRE_ATTACK['T1041']);
      break;

    case ThreatType.INFORMATION_DISCLOSURE:
      standards.push(OWASP_TOP_10['A01:2021']);
      standards.push(CWE_DATABASE['CWE-200']);
      break;

    default:
      standards.push(OWASP_TOP_10['A05:2021']);
  }

  return standards.filter(s => s !== undefined);
}
