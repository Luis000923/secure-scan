/**
 * C/C++ Dependency Parser
 * Parses vcpkg.json, conanfile.txt, and CMakeLists.txt
 */

import { BaseDependencyParser } from '../base';
import { 
  DependencyManifest, 
  ManifestFileType, 
  PackageEcosystem,
  Dependency
} from '../../types';

/**
 * vcpkg.json structure
 */
interface VcpkgJson {
  name?: string;
  version?: string;
  dependencies?: (string | VcpkgDependency)[];
  'default-features'?: boolean;
  features?: Record<string, VcpkgFeature>;
}

interface VcpkgDependency {
  name: string;
  version?: string;
  'version>='?: string;
  features?: string[];
  platform?: string;
}

interface VcpkgFeature {
  description?: string;
  dependencies?: (string | VcpkgDependency)[];
}

/**
 * C/C++ Dependency Parser
 */
export class CppDependencyParser extends BaseDependencyParser {
  name = 'C/C++ Dependency Parser';
  supportedFiles: ManifestFileType[] = ['vcpkg.json', 'conanfile.txt', 'CMakeLists.txt'];
  ecosystem: PackageEcosystem = 'vcpkg';

  /**
   * Parse manifest file
   */
  async parse(filePath: string, content: string): Promise<DependencyManifest> {
    this.logParsing(filePath);

    const fileName = filePath.split(/[/\\]/).pop() || '';
    const dependencies: Dependency[] = [];
    const parseErrors: string[] = [];
    let ecosystem: PackageEcosystem = 'vcpkg';

    try {
      if (fileName === 'vcpkg.json') {
        dependencies.push(...this.parseVcpkgJson(content, filePath, parseErrors));
        ecosystem = 'vcpkg';
      } else if (fileName === 'conanfile.txt') {
        dependencies.push(...this.parseConanfile(content, filePath, parseErrors));
        ecosystem = 'conan';
      } else if (fileName === 'CMakeLists.txt') {
        dependencies.push(...this.parseCMakeLists(content, filePath, parseErrors));
        ecosystem = 'cmake';
      }
    } catch (error) {
      const errorMsg = error instanceof Error ? error.message : String(error);
      parseErrors.push(`Failed to parse ${fileName}: ${errorMsg}`);
      this.logError(filePath, errorMsg);
    }

    return {
      filePath,
      fileType: fileName as ManifestFileType,
      ecosystem,
      dependencies,
      parseErrors: parseErrors.length > 0 ? parseErrors : undefined,
      isLockFile: false
    };
  }

  /**
   * Check if parser supports file
   */
  supports(fileName: string): boolean {
    const baseName = fileName.split(/[/\\]/).pop() || '';
    return this.supportedFiles.some(ft => baseName === ft);
  }

  /**
   * Parse vcpkg.json
   */
  private parseVcpkgJson(content: string, filePath: string, errors: string[]): Dependency[] {
    const dependencies: Dependency[] = [];
    
    let vcpkg: VcpkgJson;
    try {
      vcpkg = JSON.parse(content);
    } catch (e) {
      errors.push('Invalid JSON in vcpkg.json');
      return dependencies;
    }

    if (vcpkg.dependencies) {
      for (const dep of vcpkg.dependencies) {
        if (typeof dep === 'string') {
          dependencies.push(this.createDependency(dep, '*', filePath, {
            dependencyType: 'direct',
            ecosystem: 'vcpkg'
          }));
        } else {
          const version = dep.version || dep['version>='] || '*';
          dependencies.push(this.createDependency(dep.name, version, filePath, {
            dependencyType: 'direct',
            ecosystem: 'vcpkg'
          }));
        }
      }
    }

    // Parse feature dependencies
    if (vcpkg.features) {
      for (const [featureName, feature] of Object.entries(vcpkg.features)) {
        if (feature.dependencies) {
          for (const dep of feature.dependencies) {
            const name = typeof dep === 'string' ? dep : dep.name;
            const version = typeof dep === 'string' ? '*' : (dep.version || dep['version>='] || '*');
            dependencies.push(this.createDependency(name, version, filePath, {
              dependencyType: 'optional',
              ecosystem: 'vcpkg'
            }));
          }
        }
      }
    }

    return dependencies;
  }

  /**
   * Parse conanfile.txt
   */
  private parseConanfile(content: string, filePath: string, errors: string[]): Dependency[] {
    const dependencies: Dependency[] = [];
    const lines = content.split('\n');
    let inRequires = false;
    let inBuildRequires = false;

    for (const line of lines) {
      const trimmed = line.trim();

      // Track sections
      if (trimmed === '[requires]') {
        inRequires = true;
        inBuildRequires = false;
        continue;
      }
      if (trimmed === '[build_requires]' || trimmed === '[tool_requires]') {
        inRequires = false;
        inBuildRequires = true;
        continue;
      }
      if (trimmed.startsWith('[')) {
        inRequires = false;
        inBuildRequires = false;
        continue;
      }

      // Skip comments and empty lines
      if (!trimmed || trimmed.startsWith('#')) continue;

      // Parse requirement line (format: package/version)
      if (inRequires || inBuildRequires) {
        const match = trimmed.match(/^([^/\s@]+)(?:\/([^@\s]+))?/);
        if (match) {
          const name = match[1];
          const version = match[2] || '*';
          dependencies.push(this.createDependency(name, version, filePath, {
            dependencyType: inBuildRequires ? 'dev' : 'direct',
            ecosystem: 'conan'
          }));
        }
      }
    }

    return dependencies;
  }

  /**
   * Parse CMakeLists.txt
   */
  private parseCMakeLists(content: string, filePath: string, errors: string[]): Dependency[] {
    const dependencies: Dependency[] = [];

    // find_package(Package VERSION x.x REQUIRED)
    const findPackageRegex = /find_package\s*\(\s*(\w+)(?:\s+(\d+(?:\.\d+)*))?[^)]*\)/gi;
    
    let match;
    while ((match = findPackageRegex.exec(content)) !== null) {
      const name = match[1];
      const version = match[2] || '*';
      
      // Skip CMake built-in packages
      const builtins = ['CMake', 'CTest', 'GTest'];
      if (builtins.includes(name)) continue;
      
      dependencies.push(this.createDependency(name, version, filePath, {
        dependencyType: 'direct',
        ecosystem: 'cmake'
      }));
    }

    // FetchContent_Declare(name GIT_REPOSITORY url GIT_TAG tag)
    const fetchContentRegex = /FetchContent_Declare\s*\(\s*(\w+)[^)]*GIT_TAG\s+([^\s)]+)/gi;
    
    while ((match = fetchContentRegex.exec(content)) !== null) {
      const name = match[1];
      const version = match[2] || '*';
      
      dependencies.push(this.createDependency(name, version, filePath, {
        dependencyType: 'direct',
        ecosystem: 'cmake'
      }));
    }

    // CPMAddPackage
    const cpmRegex = /CPMAddPackage\s*\([^)]*NAME\s+(\w+)[^)]*VERSION\s+([^\s)]+)/gi;
    
    while ((match = cpmRegex.exec(content)) !== null) {
      const name = match[1];
      const version = match[2] || '*';
      
      dependencies.push(this.createDependency(name, version, filePath, {
        dependencyType: 'direct',
        ecosystem: 'cmake'
      }));
    }

    return dependencies;
  }
}

export default CppDependencyParser;
