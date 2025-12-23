/**
 * C# Dependency Parser
 * Parses .csproj and packages.config
 */

import { BaseDependencyParser } from '../base';
import { 
  DependencyManifest, 
  ManifestFileType, 
  PackageEcosystem,
  Dependency
} from '../../types';

/**
 * C# Dependency Parser
 */
export class CSharpDependencyParser extends BaseDependencyParser {
  name = 'C# Dependency Parser';
  supportedFiles: ManifestFileType[] = ['csproj', 'packages.config'];
  ecosystem: PackageEcosystem = 'nuget';

  /**
   * Check if parser supports a file
   */
  supports(fileName: string): boolean {
    const baseName = fileName.split(/[/\\]/).pop() || '';
    return baseName.endsWith('.csproj') || baseName === 'packages.config';
  }

  /**
   * Parse manifest file
   */
  async parse(filePath: string, content: string): Promise<DependencyManifest> {
    this.logParsing(filePath);

    const fileName = filePath.split(/[/\\]/).pop() || '';
    const dependencies: Dependency[] = [];
    const parseErrors: string[] = [];

    try {
      if (fileName.endsWith('.csproj')) {
        dependencies.push(...this.parseCsproj(content, filePath, parseErrors));
      } else if (fileName === 'packages.config') {
        dependencies.push(...this.parsePackagesConfig(content, filePath, parseErrors));
      }
    } catch (error) {
      const errorMsg = error instanceof Error ? error.message : String(error);
      parseErrors.push(`Failed to parse ${fileName}: ${errorMsg}`);
      this.logError(filePath, errorMsg);
    }

    return {
      filePath,
      fileType: fileName.endsWith('.csproj') ? 'csproj' : 'packages.config',
      ecosystem: this.ecosystem,
      dependencies,
      parseErrors: parseErrors.length > 0 ? parseErrors : undefined,
      isLockFile: false
    };
  }

  /**
   * Parse .csproj (SDK-style or traditional)
   */
  private parseCsproj(content: string, filePath: string, errors: string[]): Dependency[] {
    const dependencies: Dependency[] = [];

    // SDK-style .csproj: <PackageReference Include="Package" Version="x.x.x" />
    const packageRefRegex = /<PackageReference\s+Include=["']([^"']+)["']\s*(?:Version=["']([^"']+)["'])?[^>]*\/?>/gi;
    
    let match;
    while ((match = packageRefRegex.exec(content)) !== null) {
      const name = match[1];
      const version = match[2] || '*';
      
      dependencies.push(this.createDependency(name, version, filePath, {
        dependencyType: 'direct'
      }));
    }

    // Also check for <Version> as child element
    const packageRefBlockRegex = /<PackageReference\s+Include=["']([^"']+)["'][^>]*>([\s\S]*?)<\/PackageReference>/gi;
    
    while ((match = packageRefBlockRegex.exec(content)) !== null) {
      const name = match[1];
      const block = match[2];
      const versionMatch = block.match(/<Version>([^<]+)<\/Version>/i);
      const version = versionMatch ? versionMatch[1] : '*';
      
      // Check if not already added
      if (!dependencies.some(d => d.name === name)) {
        dependencies.push(this.createDependency(name, version, filePath, {
          dependencyType: 'direct'
        }));
      }
    }

    // Traditional .csproj: <Reference Include="Package, Version=x.x.x.x, Culture=..." />
    const referenceRegex = /<Reference\s+Include=["']([^,"']+)(?:,\s*Version=([^,"']+))?[^>]*\/?>/gi;
    
    while ((match = referenceRegex.exec(content)) !== null) {
      const name = match[1];
      const version = match[2] || '*';
      
      // Skip system assemblies
      if (name.startsWith('System') || name.startsWith('Microsoft.CSharp')) continue;
      
      dependencies.push(this.createDependency(name, version, filePath, {
        dependencyType: 'direct'
      }));
    }

    // FrameworkReference for .NET Core/5+
    const frameworkRefRegex = /<FrameworkReference\s+Include=["']([^"']+)["'][^>]*\/?>/gi;
    
    while ((match = frameworkRefRegex.exec(content)) !== null) {
      const name = match[1];
      
      dependencies.push(this.createDependency(name, '*', filePath, {
        dependencyType: 'direct'
      }));
    }

    return dependencies;
  }

  /**
   * Parse packages.config (legacy NuGet)
   */
  private parsePackagesConfig(content: string, filePath: string, errors: string[]): Dependency[] {
    const dependencies: Dependency[] = [];

    // <package id="Package" version="x.x.x" />
    const packageRegex = /<package\s+id=["']([^"']+)["']\s+version=["']([^"']+)["'][^>]*\/?>/gi;
    
    let match;
    while ((match = packageRegex.exec(content)) !== null) {
      const name = match[1];
      const version = match[2];
      
      dependencies.push(this.createDependency(name, version, filePath, {
        dependencyType: 'direct',
        resolvedVersion: version
      }));
    }

    return dependencies;
  }
}

export default CSharpDependencyParser;
