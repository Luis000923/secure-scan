/**
 * Java Dependency Parser
 * Parses pom.xml and build.gradle
 */

import { BaseDependencyParser } from '../base';
import { 
  DependencyManifest, 
  ManifestFileType, 
  PackageEcosystem,
  Dependency
} from '../../types';

/**
 * Java Dependency Parser
 */
export class JavaDependencyParser extends BaseDependencyParser {
  name = 'Java Dependency Parser';
  supportedFiles: ManifestFileType[] = ['pom.xml', 'build.gradle'];
  ecosystem: PackageEcosystem = 'maven';

  /**
   * Parse manifest file
   */
  async parse(filePath: string, content: string): Promise<DependencyManifest> {
    this.logParsing(filePath);

    const fileName = filePath.split(/[/\\]/).pop() || '';
    const dependencies: Dependency[] = [];
    const parseErrors: string[] = [];

    try {
      if (fileName === 'pom.xml') {
        dependencies.push(...this.parsePomXml(content, filePath, parseErrors));
      } else if (fileName === 'build.gradle') {
        dependencies.push(...this.parseBuildGradle(content, filePath, parseErrors));
      }
    } catch (error) {
      const errorMsg = error instanceof Error ? error.message : String(error);
      parseErrors.push(`Failed to parse ${fileName}: ${errorMsg}`);
      this.logError(filePath, errorMsg);
    }

    return {
      filePath,
      fileType: fileName as ManifestFileType,
      ecosystem: fileName === 'build.gradle' ? 'gradle' : 'maven',
      dependencies,
      parseErrors: parseErrors.length > 0 ? parseErrors : undefined,
      isLockFile: false
    };
  }

  /**
   * Parse pom.xml (Maven)
   */
  private parsePomXml(content: string, filePath: string, errors: string[]): Dependency[] {
    const dependencies: Dependency[] = [];
    
    // Simple XML parser for Maven dependencies
    // Pattern: <dependency><groupId>...</groupId><artifactId>...</artifactId><version>...</version></dependency>
    const dependencyRegex = /<dependency>\s*([\s\S]*?)<\/dependency>/g;
    const groupIdRegex = /<groupId>([^<]+)<\/groupId>/;
    const artifactIdRegex = /<artifactId>([^<]+)<\/artifactId>/;
    const versionRegex = /<version>([^<]+)<\/version>/;
    const scopeRegex = /<scope>([^<]+)<\/scope>/;

    let match;
    while ((match = dependencyRegex.exec(content)) !== null) {
      const depBlock = match[1];
      
      const groupId = groupIdRegex.exec(depBlock)?.[1];
      const artifactId = artifactIdRegex.exec(depBlock)?.[1];
      const version = versionRegex.exec(depBlock)?.[1] || '*';
      const scope = scopeRegex.exec(depBlock)?.[1] || 'compile';

      if (groupId && artifactId) {
        // Maven uses groupId:artifactId format
        const name = `${groupId}:${artifactId}`;
        
        // Determine dependency type based on scope
        let depType: 'direct' | 'dev' | 'optional' = 'direct';
        if (scope === 'test') depType = 'dev';
        if (scope === 'provided' || scope === 'optional') depType = 'optional';

        dependencies.push(this.createDependency(name, version, filePath, {
          dependencyType: depType
        }));
      }
    }

    // Also parse plugin dependencies
    const pluginRegex = /<plugin>\s*([\s\S]*?)<\/plugin>/g;
    while ((match = pluginRegex.exec(content)) !== null) {
      const pluginBlock = match[1];
      
      const groupId = groupIdRegex.exec(pluginBlock)?.[1] || 'org.apache.maven.plugins';
      const artifactId = artifactIdRegex.exec(pluginBlock)?.[1];
      const version = versionRegex.exec(pluginBlock)?.[1] || '*';

      if (artifactId) {
        const name = `${groupId}:${artifactId}`;
        dependencies.push(this.createDependency(name, version, filePath, {
          dependencyType: 'dev' // Plugins are build-time dependencies
        }));
      }
    }

    return dependencies;
  }

  /**
   * Parse build.gradle (Gradle)
   */
  private parseBuildGradle(content: string, filePath: string, errors: string[]): Dependency[] {
    const dependencies: Dependency[] = [];
    
    // Gradle dependency patterns
    // implementation 'group:artifact:version'
    // implementation "group:artifact:version"
    // implementation("group:artifact:version")
    // implementation group: 'x', name: 'y', version: 'z'
    
    const configTypes = [
      'implementation',
      'api',
      'compile',
      'compileOnly',
      'runtimeOnly',
      'testImplementation',
      'testCompile',
      'testRuntimeOnly',
      'annotationProcessor',
      'kapt'
    ];

    // Pattern for string notation: implementation 'group:artifact:version'
    const stringPattern = new RegExp(
      `(${configTypes.join('|')})\\s*[("']([^"')]+)[)"']`,
      'g'
    );

    // Pattern for map notation: implementation group: 'x', name: 'y', version: 'z'
    const mapPattern = new RegExp(
      `(${configTypes.join('|')})\\s+group:\\s*['"]([^'"]+)['"],\\s*name:\\s*['"]([^'"]+)['"](?:,\\s*version:\\s*['"]([^'"]+)['"])?`,
      'g'
    );

    let match;

    // Parse string notation
    while ((match = stringPattern.exec(content)) !== null) {
      const configType = match[1];
      const depString = match[2];
      
      // Parse group:artifact:version
      const parts = depString.split(':');
      if (parts.length >= 2) {
        const groupId = parts[0];
        const artifactId = parts[1];
        const version = parts[2] || '*';
        const name = `${groupId}:${artifactId}`;
        
        const depType = this.getGradleDepType(configType);
        
        dependencies.push(this.createDependency(name, version, filePath, {
          dependencyType: depType
        }));
      }
    }

    // Parse map notation
    while ((match = mapPattern.exec(content)) !== null) {
      const configType = match[1];
      const groupId = match[2];
      const artifactId = match[3];
      const version = match[4] || '*';
      const name = `${groupId}:${artifactId}`;
      
      const depType = this.getGradleDepType(configType);
      
      dependencies.push(this.createDependency(name, version, filePath, {
        dependencyType: depType
      }));
    }

    return dependencies;
  }

  /**
   * Map Gradle configuration to dependency type
   */
  private getGradleDepType(configType: string): 'direct' | 'dev' | 'optional' {
    const testConfigs = ['testImplementation', 'testCompile', 'testRuntimeOnly'];
    const devConfigs = ['annotationProcessor', 'kapt', 'compileOnly'];
    
    if (testConfigs.includes(configType)) return 'dev';
    if (devConfigs.includes(configType)) return 'dev';
    return 'direct';
  }
}

export default JavaDependencyParser;
