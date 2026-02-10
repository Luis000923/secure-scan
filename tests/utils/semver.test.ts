/**
 * Unit Tests for Semver Utility
 * Tests semantic versioning comparison and parsing
 */

import {
  parseVersion,
  compareVersions,
  satisfies,
  checkVersionVulnerable,
  maxVersion,
  minVersion,
  sortVersions,
  isPrerelease,
  incrementVersion,
  coerce
} from '../../src/utils/semver';

describe('Semver Utility', () => {
  describe('parseVersion', () => {
    it('should parse simple versions', () => {
      const result = parseVersion('1.2.3');
      expect(result.major).toBe(1);
      expect(result.minor).toBe(2);
      expect(result.patch).toBe(3);
      expect(result.valid).toBe(true);
    });

    it('should parse versions with v prefix', () => {
      const result = parseVersion('v2.0.0');
      expect(result.major).toBe(2);
      expect(result.minor).toBe(0);
      expect(result.patch).toBe(0);
      expect(result.valid).toBe(true);
    });

    it('should parse versions with prerelease', () => {
      const result = parseVersion('1.0.0-alpha.1');
      expect(result.major).toBe(1);
      expect(result.prerelease).toEqual(['alpha', '1']);
      expect(result.valid).toBe(true);
    });

    it('should parse versions with build metadata', () => {
      const result = parseVersion('1.0.0+build.123');
      expect(result.major).toBe(1);
      expect(result.build).toEqual(['build', '123']);
      expect(result.valid).toBe(true);
    });

    it('should handle partial versions', () => {
      const result = parseVersion('1.2');
      expect(result.major).toBe(1);
      expect(result.minor).toBe(2);
      expect(result.patch).toBe(0);
      expect(result.valid).toBe(true);
    });

    it('should handle invalid versions', () => {
      const result = parseVersion('not-a-version');
      expect(result.valid).toBe(false);
    });
  });

  describe('compareVersions', () => {
    it('should compare major versions', () => {
      expect(compareVersions('2.0.0', '1.0.0')).toBe(1);
      expect(compareVersions('1.0.0', '2.0.0')).toBe(-1);
    });

    it('should compare minor versions', () => {
      expect(compareVersions('1.2.0', '1.1.0')).toBe(1);
      expect(compareVersions('1.1.0', '1.2.0')).toBe(-1);
    });

    it('should compare patch versions', () => {
      expect(compareVersions('1.0.2', '1.0.1')).toBe(1);
      expect(compareVersions('1.0.1', '1.0.2')).toBe(-1);
    });

    it('should return 0 for equal versions', () => {
      expect(compareVersions('1.2.3', '1.2.3')).toBe(0);
    });

    it('should handle prerelease versions', () => {
      // Release > prerelease
      expect(compareVersions('1.0.0', '1.0.0-alpha')).toBe(1);
      expect(compareVersions('1.0.0-alpha', '1.0.0')).toBe(-1);
      
      // Alpha < beta
      expect(compareVersions('1.0.0-alpha', '1.0.0-beta')).toBe(-1);
    });

    it('should accept string or parsed version', () => {
      const parsed = parseVersion('1.0.0');
      expect(compareVersions(parsed, '0.9.0')).toBe(1);
      expect(compareVersions('1.1.0', parsed)).toBe(1);
    });
  });

  describe('satisfies', () => {
    describe('exact match', () => {
      it('should match exact versions', () => {
        expect(satisfies('1.2.3', '1.2.3')).toBe(true);
        expect(satisfies('1.2.3', '1.2.4')).toBe(false);
      });
    });

    describe('greater than', () => {
      it('should check greater than', () => {
        expect(satisfies('2.0.0', '>1.0.0')).toBe(true);
        expect(satisfies('1.0.0', '>1.0.0')).toBe(false);
        expect(satisfies('0.9.0', '>1.0.0')).toBe(false);
      });
    });

    describe('less than', () => {
      it('should check less than', () => {
        expect(satisfies('0.9.0', '<1.0.0')).toBe(true);
        expect(satisfies('1.0.0', '<1.0.0')).toBe(false);
        expect(satisfies('2.0.0', '<1.0.0')).toBe(false);
      });
    });

    describe('greater than or equal', () => {
      it('should check greater than or equal', () => {
        expect(satisfies('2.0.0', '>=1.0.0')).toBe(true);
        expect(satisfies('1.0.0', '>=1.0.0')).toBe(true);
        expect(satisfies('0.9.0', '>=1.0.0')).toBe(false);
      });
    });

    describe('less than or equal', () => {
      it('should check less than or equal', () => {
        expect(satisfies('0.9.0', '<=1.0.0')).toBe(true);
        expect(satisfies('1.0.0', '<=1.0.0')).toBe(true);
        expect(satisfies('2.0.0', '<=1.0.0')).toBe(false);
      });
    });

    describe('caret range', () => {
      it('should allow compatible versions', () => {
        expect(satisfies('1.2.3', '^1.2.0')).toBe(true);
        expect(satisfies('1.9.9', '^1.2.0')).toBe(true);
        expect(satisfies('2.0.0', '^1.2.0')).toBe(false);
      });

      it('should handle 0.x versions specially', () => {
        expect(satisfies('0.2.1', '^0.2.0')).toBe(true);
        expect(satisfies('0.3.0', '^0.2.0')).toBe(false);
      });
    });

    describe('tilde range', () => {
      it('should allow patch updates', () => {
        expect(satisfies('1.2.3', '~1.2.0')).toBe(true);
        expect(satisfies('1.2.9', '~1.2.0')).toBe(true);
        expect(satisfies('1.3.0', '~1.2.0')).toBe(false);
      });
    });

    describe('complex ranges', () => {
      it('should handle AND conditions (space)', () => {
        expect(satisfies('1.5.0', '>=1.0.0 <2.0.0')).toBe(true);
        expect(satisfies('2.0.0', '>=1.0.0 <2.0.0')).toBe(false);
        expect(satisfies('0.9.0', '>=1.0.0 <2.0.0')).toBe(false);
      });

      it('should handle OR conditions (||)', () => {
        expect(satisfies('1.0.0', '1.0.0 || 2.0.0')).toBe(true);
        expect(satisfies('2.0.0', '1.0.0 || 2.0.0')).toBe(true);
        expect(satisfies('3.0.0', '1.0.0 || 2.0.0')).toBe(false);
      });
    });
  });

  describe('checkVersionVulnerable', () => {
    it('should detect vulnerable versions', () => {
      const ranges = ['<4.17.20'];
      
      expect(checkVersionVulnerable('4.17.15', ranges)).toBe(true);
      expect(checkVersionVulnerable('4.17.20', ranges)).toBe(false);
      expect(checkVersionVulnerable('4.17.21', ranges)).toBe(false);
    });

    it('should handle multiple ranges', () => {
      const ranges = ['<3.2.20', '>=4.0.0 <4.1.10', '>=4.2.0 <4.2.3'];
      
      expect(checkVersionVulnerable('3.2.0', ranges)).toBe(true);
      expect(checkVersionVulnerable('3.2.20', ranges)).toBe(false);
      expect(checkVersionVulnerable('4.1.5', ranges)).toBe(true);
      expect(checkVersionVulnerable('4.1.10', ranges)).toBe(false);
      expect(checkVersionVulnerable('4.2.0', ranges)).toBe(true);
      expect(checkVersionVulnerable('4.2.3', ranges)).toBe(false);
    });
  });

  describe('maxVersion', () => {
    it('should find the highest version', () => {
      expect(maxVersion(['1.0.0', '2.0.0', '1.5.0'])).toBe('2.0.0');
      expect(maxVersion(['0.1.0', '0.0.1', '0.2.0'])).toBe('0.2.0');
    });

    it('should return null for empty array', () => {
      expect(maxVersion([])).toBeNull();
    });
  });

  describe('minVersion', () => {
    it('should find the lowest version', () => {
      expect(minVersion(['1.0.0', '2.0.0', '0.5.0'])).toBe('0.5.0');
    });

    it('should return null for empty array', () => {
      expect(minVersion([])).toBeNull();
    });
  });

  describe('sortVersions', () => {
    it('should sort versions in ascending order', () => {
      const versions = ['2.0.0', '1.0.0', '1.5.0', '0.1.0'];
      expect(sortVersions(versions)).toEqual(['0.1.0', '1.0.0', '1.5.0', '2.0.0']);
    });

    it('should sort versions in descending order', () => {
      const versions = ['1.0.0', '2.0.0', '1.5.0'];
      expect(sortVersions(versions, true)).toEqual(['2.0.0', '1.5.0', '1.0.0']);
    });
  });

  describe('isPrerelease', () => {
    it('should identify prerelease versions', () => {
      expect(isPrerelease('1.0.0-alpha')).toBe(true);
      expect(isPrerelease('1.0.0-beta.1')).toBe(true);
      expect(isPrerelease('1.0.0-rc.1')).toBe(true);
    });

    it('should identify stable versions', () => {
      expect(isPrerelease('1.0.0')).toBe(false);
      expect(isPrerelease('2.1.3')).toBe(false);
    });
  });

  describe('incrementVersion', () => {
    it('should increment major version', () => {
      expect(incrementVersion('1.2.3', 'major')).toBe('2.0.0');
    });

    it('should increment minor version', () => {
      expect(incrementVersion('1.2.3', 'minor')).toBe('1.3.0');
    });

    it('should increment patch version', () => {
      expect(incrementVersion('1.2.3', 'patch')).toBe('1.2.4');
    });
  });

  describe('coerce', () => {
    it('should coerce valid versions', () => {
      expect(coerce('1.2.3')).toBe('1.2.3');
      expect(coerce('v1.2.3')).toBe('1.2.3');
    });

    it('should coerce partial versions', () => {
      expect(coerce('1')).toBe('1.0.0');
      expect(coerce('1.2')).toBe('1.2.0');
    });

    it('should extract versions from strings', () => {
      expect(coerce('version 1.2.3')).toBe('1.2.3');
    });

    it('should return null for invalid input', () => {
      expect(coerce('')).toBeNull();
    });
  });
});
