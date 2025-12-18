/**
 * Rules Module Exports
 * All detection rules for vulnerabilities and malware
 */

export * from './standards';
export * from './vulnerabilities';
export * from './malware';

import { Rule } from '../types';
import { vulnerabilityRules } from './vulnerabilities';
import { malwareRules } from './malware';

/**
 * Get all rules
 */
export function getAllRules(): Rule[] {
  return [...vulnerabilityRules, ...malwareRules];
}

/**
 * Get rules by category
 */
export function getRulesByCategory(category: 'vulnerability' | 'malware'): Rule[] {
  if (category === 'vulnerability') {
    return vulnerabilityRules;
  }
  return malwareRules;
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
