/**
 * Rules Module Exports
 * All detection rules for vulnerabilities and malware
 */

export * from './standards';

// Re-export vulnerabilities with namespace prefix to avoid conflicts
export * as vulnerabilities from './vulnerabilities';
export { allVulnerabilityRules, VulnerabilityRuleEngine } from './vulnerabilities';

// Re-export malware with namespace prefix to avoid conflicts
export * as malware from './malware';
export { malwareRules, MalwareRuleEngine } from './malware';

// Re-export secrets detection
export * as secrets from './secrets';
export { getSecretRules, SECRET_PATTERNS } from './secrets';

import { Rule } from '../types';
import { allVulnerabilityRules } from './vulnerabilities';
import { malwareRules } from './malware';
import { getSecretRules } from './secrets';

/**
 * Get all rules
 */
export function getAllRules(): Rule[] {
  return [
    ...allVulnerabilityRules as unknown as Rule[], 
    ...malwareRules as unknown as Rule[],
    ...getSecretRules()
  ];
}

/**
 * Get rules by category
 */
export function getRulesByCategory(category: 'vulnerability' | 'malware'): Rule[] {
  if (category === 'vulnerability') {
    return allVulnerabilityRules as unknown as Rule[];
  }
  return malwareRules as unknown as Rule[];
}

/**
 * Get rule by ID
 */
export function getRuleById(id: string): Rule | undefined {
  return getAllRules().find(r => r.id === id);
}

/**
 * Get rules by language
 */
export function getRulesByLanguage(language: string): Rule[] {
  return getAllRules().filter(r =>
    r.languages.includes(language as any)
  );
}

/**
 * Get enabled rules
 */
export function getEnabledRules(): Rule[] {
  return getAllRules().filter(r => r.enabled);
}
