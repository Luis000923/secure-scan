/**
 * Unit Tests for Utility Functions
 * Tests common utility functions
 */

describe('Utility Functions', () => {
  let utils: any;

  beforeAll(async () => {
    utils = await import('../../src/utils');
  });

  describe('generateId', () => {
    it('should generate unique IDs', () => {
      const id1 = utils.generateId();
      const id2 = utils.generateId();

      expect(id1).toBeDefined();
      expect(id2).toBeDefined();
      expect(id1).not.toBe(id2);
    });

    it('should generate IDs with correct format', () => {
      const id = utils.generateId();
      
      expect(typeof id).toBe('string');
      expect(id.length).toBeGreaterThan(0);
    });
  });

  describe('isHigherOrEqualSeverity', () => {
    it('should correctly compare severities', () => {
      const { Severity } = require('../../src/types');
      
      expect(utils.isHigherOrEqualSeverity(Severity.CRITICAL, Severity.HIGH)).toBe(true);
      expect(utils.isHigherOrEqualSeverity(Severity.HIGH, Severity.MEDIUM)).toBe(true);
      expect(utils.isHigherOrEqualSeverity(Severity.MEDIUM, Severity.LOW)).toBe(true);
      expect(utils.isHigherOrEqualSeverity(Severity.LOW, Severity.INFO)).toBe(true);
    });

    it('should return true for equal severities', () => {
      const { Severity } = require('../../src/types');

      expect(utils.isHigherOrEqualSeverity(Severity.HIGH, Severity.HIGH)).toBe(true);
      expect(utils.isHigherOrEqualSeverity(Severity.CRITICAL, Severity.CRITICAL)).toBe(true);
    });

    it('should return false for lower severities', () => {
      const { Severity } = require('../../src/types');

      expect(utils.isHigherOrEqualSeverity(Severity.LOW, Severity.HIGH)).toBe(false);
      expect(utils.isHigherOrEqualSeverity(Severity.INFO, Severity.CRITICAL)).toBe(false);
    });
  });
});

describe('Logger', () => {
  let logger: any;
  let setLogLevel: any;

  beforeAll(async () => {
    const module = await import('../../src/utils/logger');
    logger = module.logger;
    setLogLevel = module.setLogLevel;
  });

  it('should have expected log methods', () => {
    expect(logger.info).toBeDefined();
    expect(logger.warn).toBeDefined();
    expect(logger.error).toBeDefined();
    expect(logger.debug).toBeDefined();
  });

  it('should allow setting log level', () => {
    expect(() => setLogLevel('debug')).not.toThrow();
    expect(() => setLogLevel('info')).not.toThrow();
    expect(() => setLogLevel('error')).not.toThrow();
  });
});
