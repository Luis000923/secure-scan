/**
 * Jest Test Setup
 * Global configuration for all tests
 */

// Increase timeout for integration tests
jest.setTimeout(30000);

// Mock console to reduce noise during tests
const originalConsoleLog = console.log;
const originalConsoleWarn = console.warn;
const originalConsoleError = console.error;

beforeAll(() => {
  // Suppress console output during tests unless DEBUG is set
  if (!process.env.DEBUG) {
    console.log = jest.fn();
    console.warn = jest.fn();
  }
});

afterAll(() => {
  console.log = originalConsoleLog;
  console.warn = originalConsoleWarn;
  console.error = originalConsoleError;
});

// Global test utilities
declare global {
  namespace NodeJS {
    interface Global {
      testUtils: {
        createMockFile: (content: string, language: string) => any;
        createMockFinding: (overrides?: Partial<any>) => any;
      };
    }
  }
}

export {};
