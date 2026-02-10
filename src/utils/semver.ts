/**
 * Semver Utility Module
 * Proper semantic versioning comparison for dependency analysis
 * 
 * Note: This is a lightweight implementation. For production, consider using the 'semver' npm package.
 */

/**
 * Parsed semantic version
 */
export interface ParsedVersion {
  major: number;
  minor: number;
  patch: number;
  prerelease: string[];
  build: string[];
  raw: string;
  valid: boolean;
}

/**
 * Version range types
 */
export type RangeOperator = '=' | '>' | '<' | '>=' | '<=' | '^' | '~';

/**
 * Parsed version range
 */
export interface ParsedRange {
  operator: RangeOperator;
  version: ParsedVersion;
  raw: string;
}

/**
 * Parse a semantic version string
 */
export function parseVersion(version: string): ParsedVersion {
  const result: ParsedVersion = {
    major: 0,
    minor: 0,
    patch: 0,
    prerelease: [],
    build: [],
    raw: version,
    valid: false
  };

  if (!version || typeof version !== 'string') {
    return result;
  }

  // Clean the version string
  let cleaned = version.trim();
  
  // Remove leading 'v' or '='
  if (cleaned.startsWith('v') || cleaned.startsWith('=')) {
    cleaned = cleaned.slice(1);
  }

  // Split build metadata
  const buildIndex = cleaned.indexOf('+');
  if (buildIndex !== -1) {
    result.build = cleaned.slice(buildIndex + 1).split('.');
    cleaned = cleaned.slice(0, buildIndex);
  }

  // Split prerelease
  const prereleaseIndex = cleaned.indexOf('-');
  if (prereleaseIndex !== -1) {
    result.prerelease = cleaned.slice(prereleaseIndex + 1).split('.');
    cleaned = cleaned.slice(0, prereleaseIndex);
  }

  // Parse version numbers
  const parts = cleaned.split('.');
  
  if (parts.length >= 1) {
    const major = parseInt(parts[0], 10);
    if (!isNaN(major)) {
      result.major = major;
      result.valid = true;
    }
  }
  
  if (parts.length >= 2) {
    const minor = parseInt(parts[1], 10);
    if (!isNaN(minor)) {
      result.minor = minor;
    }
  }
  
  if (parts.length >= 3) {
    const patch = parseInt(parts[2], 10);
    if (!isNaN(patch)) {
      result.patch = patch;
    }
  }

  return result;
}

/**
 * Compare two parsed versions
 * Returns: -1 if a < b, 0 if a === b, 1 if a > b
 */
export function compareVersions(a: ParsedVersion | string, b: ParsedVersion | string): number {
  const versionA = typeof a === 'string' ? parseVersion(a) : a;
  const versionB = typeof b === 'string' ? parseVersion(b) : b;

  // Compare major
  if (versionA.major !== versionB.major) {
    return versionA.major > versionB.major ? 1 : -1;
  }

  // Compare minor
  if (versionA.minor !== versionB.minor) {
    return versionA.minor > versionB.minor ? 1 : -1;
  }

  // Compare patch
  if (versionA.patch !== versionB.patch) {
    return versionA.patch > versionB.patch ? 1 : -1;
  }

  // Compare prerelease (version without prerelease > version with prerelease)
  if (versionA.prerelease.length === 0 && versionB.prerelease.length > 0) {
    return 1;
  }
  if (versionA.prerelease.length > 0 && versionB.prerelease.length === 0) {
    return -1;
  }

  // Compare prerelease identifiers
  const maxPre = Math.max(versionA.prerelease.length, versionB.prerelease.length);
  for (let i = 0; i < maxPre; i++) {
    const preA = versionA.prerelease[i];
    const preB = versionB.prerelease[i];

    if (preA === undefined) return -1;
    if (preB === undefined) return 1;

    const numA = parseInt(preA, 10);
    const numB = parseInt(preB, 10);

    if (!isNaN(numA) && !isNaN(numB)) {
      if (numA !== numB) return numA > numB ? 1 : -1;
    } else {
      const cmp = preA.localeCompare(preB);
      if (cmp !== 0) return cmp > 0 ? 1 : -1;
    }
  }

  return 0;
}

/**
 * Check if version satisfies a simple constraint
 */
export function satisfies(version: string | ParsedVersion, constraint: string): boolean {
  const parsedVersion = typeof version === 'string' ? parseVersion(version) : version;
  
  if (!parsedVersion.valid) {
    return false;
  }

  // Handle complex constraints with OR (||)
  if (constraint.includes('||')) {
    const orParts = constraint.split('||').map(s => s.trim());
    return orParts.some(part => satisfies(parsedVersion, part));
  }

  // Handle complex constraints with AND (space or comma)
  if (constraint.includes(' ') || constraint.includes(',')) {
    const andParts = constraint.split(/[, ]+/).map(s => s.trim()).filter(Boolean);
    return andParts.every(part => satisfies(parsedVersion, part));
  }

  // Parse simple constraint
  let operator: RangeOperator = '=';
  let constraintVersion: string;

  if (constraint.startsWith('>=')) {
    operator = '>=';
    constraintVersion = constraint.slice(2);
  } else if (constraint.startsWith('<=')) {
    operator = '<=';
    constraintVersion = constraint.slice(2);
  } else if (constraint.startsWith('>')) {
    operator = '>';
    constraintVersion = constraint.slice(1);
  } else if (constraint.startsWith('<')) {
    operator = '<';
    constraintVersion = constraint.slice(1);
  } else if (constraint.startsWith('^')) {
    operator = '^';
    constraintVersion = constraint.slice(1);
  } else if (constraint.startsWith('~')) {
    operator = '~';
    constraintVersion = constraint.slice(1);
  } else if (constraint.startsWith('=')) {
    operator = '=';
    constraintVersion = constraint.slice(1);
  } else {
    constraintVersion = constraint;
  }

  const parsedConstraint = parseVersion(constraintVersion);
  
  if (!parsedConstraint.valid) {
    return false;
  }

  const cmp = compareVersions(parsedVersion, parsedConstraint);

  switch (operator) {
    case '=':
      return cmp === 0;
    case '>':
      return cmp > 0;
    case '<':
      return cmp < 0;
    case '>=':
      return cmp >= 0;
    case '<=':
      return cmp <= 0;
    case '^':
      // Caret: allows changes that do not modify the left-most non-zero element
      if (cmp < 0) return false;
      if (parsedConstraint.major === 0) {
        if (parsedConstraint.minor === 0) {
          return parsedVersion.major === 0 && 
                 parsedVersion.minor === 0 && 
                 parsedVersion.patch === parsedConstraint.patch;
        }
        return parsedVersion.major === 0 && 
               parsedVersion.minor === parsedConstraint.minor;
      }
      return parsedVersion.major === parsedConstraint.major;
    case '~':
      // Tilde: allows patch-level changes
      if (cmp < 0) return false;
      return parsedVersion.major === parsedConstraint.major && 
             parsedVersion.minor === parsedConstraint.minor;
    default:
      return false;
  }
}

/**
 * Check if a version is within a vulnerable range
 * Supports multiple range formats commonly used in vulnerability databases
 * Note: This function is named checkVersionVulnerable to avoid conflict with
 * the isVersionVulnerable function in dependencies/database/cveDatabase.ts
 */
export function checkVersionVulnerable(
  version: string,
  vulnerableRanges: string[]
): boolean {
  const parsedVersion = parseVersion(version);
  
  if (!parsedVersion.valid) {
    return false;
  }

  for (const range of vulnerableRanges) {
    if (satisfies(parsedVersion, range)) {
      return true;
    }
  }

  return false;
}

/**
 * Alias for checkVersionVulnerable for backward compatibility
 * @deprecated Use checkVersionVulnerable instead to avoid naming conflicts
 */
export const isVersionInVulnerableRange = checkVersionVulnerable;

/**
 * Get the highest version from a list
 */
export function maxVersion(versions: string[]): string | null {
  if (versions.length === 0) return null;
  
  return versions.reduce((max, current) => {
    return compareVersions(current, max) > 0 ? current : max;
  });
}

/**
 * Get the lowest version from a list
 */
export function minVersion(versions: string[]): string | null {
  if (versions.length === 0) return null;
  
  return versions.reduce((min, current) => {
    return compareVersions(current, min) < 0 ? current : min;
  });
}

/**
 * Sort versions in ascending order
 */
export function sortVersions(versions: string[], descending = false): string[] {
  const sorted = [...versions].sort(compareVersions);
  return descending ? sorted.reverse() : sorted;
}

/**
 * Check if a version is a prerelease
 */
export function isPrerelease(version: string): boolean {
  const parsed = parseVersion(version);
  return parsed.prerelease.length > 0;
}

/**
 * Increment a version
 */
export function incrementVersion(
  version: string,
  release: 'major' | 'minor' | 'patch'
): string {
  const parsed = parseVersion(version);
  
  switch (release) {
    case 'major':
      return `${parsed.major + 1}.0.0`;
    case 'minor':
      return `${parsed.major}.${parsed.minor + 1}.0`;
    case 'patch':
      return `${parsed.major}.${parsed.minor}.${parsed.patch + 1}`;
    default:
      return version;
  }
}

/**
 * Coerce a loose version string to a valid semver
 */
export function coerce(version: string): string | null {
  const parsed = parseVersion(version);
  
  if (!parsed.valid) {
    // Try to extract version-like pattern
    const match = version.match(/(\d+)(?:\.(\d+))?(?:\.(\d+))?/);
    if (match) {
      const major = match[1] || '0';
      const minor = match[2] || '0';
      const patch = match[3] || '0';
      return `${major}.${minor}.${patch}`;
    }
    return null;
  }
  
  return `${parsed.major}.${parsed.minor}.${parsed.patch}`;
}
