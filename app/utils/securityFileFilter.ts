export interface SecurityFile {
  path: string;
  type: 'config' | 'dependency' | 'secret' | 'security' | 'deployment';
  priority: 'high' | 'medium' | 'low';
  reason: string;
}

export interface FileFilterOptions {
  includeConfigFiles?: boolean;
  includeDependencyFiles?: boolean;
  includeSecretFiles?: boolean;
  includeSecurityFiles?: boolean;
  includeDeploymentFiles?: boolean;
  maxFiles?: number;
}

export class SecurityFileFilter {
  private static readonly SECURITY_PATTERNS = {
    // Order matters! More specific patterns should come first
    secret: [
      '.env', '.env.local', '.env.production', '.env.staging',
      'secrets.json', 'credentials.json', 'keys.json',
      'secret', 'key', 'token', 'credential', 'password', 'auth'
    ],
    dependency: [
      'package.json', 'package-lock.json', 'yarn.lock', 'pnpm-lock.yaml',
      'requirements.txt', 'Pipfile', 'poetry.lock', 'pom.xml', 'build.gradle',
      'Gemfile', 'Gemfile.lock', 'composer.json', 'composer.lock',
      'Cargo.toml', 'Cargo.lock', 'go.mod', 'go.sum'
    ],
    security: [
      'security', 'auth', 'authentication', 'authorization', 'permission',
      'firewall', 'cors', 'csp', 'security.json', 'auth.json'
    ],
    deployment: [
      'dockerfile', 'docker-compose', 'kubernetes', 'k8s', 'helm',
      'terraform', 'ansible', 'deployment', 'infrastructure',
      '.dockerignore', 'docker-compose.yml', 'docker-compose.yaml'
    ],
    config: [
      'config', 'settings', 'properties', 'ini', 'yaml', 'yml',
      'xml', 'conf', 'cfg'
      // Removed 'toml' from config to avoid conflicts with Cargo.toml
    ]
  };

  /**
   * Determines if a file is security-relevant based on its path
   */
  static isSecurityRelevant(filePath: string, options: FileFilterOptions = {}): SecurityFile | null {
    const normalizedPath = filePath.toLowerCase();
    const fileName = normalizedPath.split('/').pop() || '';
    const fileExtension = fileName.includes('.') ? fileName.split('.').pop() : '';

    // Check each security category
    for (const [category, patterns] of Object.entries(this.SECURITY_PATTERNS)) {
      if (!this.shouldIncludeCategory(category, options)) continue;

      const isMatch = patterns.some(pattern => {
        // Make pattern matching case-insensitive
        const normalizedPattern = pattern.toLowerCase();
        
        // Exact filename match (highest priority)
        if (fileName === normalizedPattern) return true;
        
        // For dependency files, only exact matches
        if (category === 'dependency') {
          return fileName === normalizedPattern;
        }
        
        // For secret files, check for exact matches or specific patterns
        if (category === 'secret') {
          if (fileName === normalizedPattern) return true;
          if (normalizedPattern.startsWith('.') && fileName.startsWith(normalizedPattern)) return true;
          if (normalizedPath.includes(normalizedPattern) && !normalizedPath.includes('node_modules')) return true;
        }
        
        // For other categories, check pattern in path but be more specific
        if (normalizedPath.includes(normalizedPattern)) {
          // Avoid matching in node_modules or other common non-relevant paths
          if (normalizedPath.includes('node_modules')) return false;
          if (normalizedPath.includes('dist/')) return false;
          if (normalizedPath.includes('build/')) return false;
          return true;
        }
        
        // Extension match only for config files (and not for specific named files)
        if (category === 'config' && fileExtension && ['yaml', 'yml', 'xml', 'ini', 'conf'].includes(fileExtension)) {
          // Don't match .toml files as config if they're already matched as dependencies
          if (fileExtension === 'toml' && fileName !== 'config.toml') return false;
          // Don't match .json files as config if they're already matched as dependencies
          if (fileExtension === 'json' && fileName !== 'config.json') return false;
          return true;
        }
        
        return false;
      });

      if (isMatch) {
        return {
          path: filePath,
          type: category as SecurityFile['type'],
          priority: this.getPriority(category, normalizedPath),
          reason: `Matched ${category} pattern: ${patterns.find(p => normalizedPath.includes(p.toLowerCase())) || 'exact match'}`
        };
      }
    }

    return null;
  }

  /**
   * Filters a list of files to only include security-relevant ones
   */
  static filterFiles(filePaths: string[], options: FileFilterOptions = {}): SecurityFile[] {
    const securityFiles = filePaths
      .map(path => this.isSecurityRelevant(path, options))
      .filter((file): file is SecurityFile => file !== null)
      .sort((a, b) => {
        // Primary sort: by priority score
        const priorityDiff = this.getPriorityScore(b.priority) - this.getPriorityScore(a.priority);
        if (priorityDiff !== 0) return priorityDiff;
        
        // Secondary sort: by type (secret > dependency > security > deployment > config)
        const typeOrder = { secret: 5, dependency: 4, security: 3, deployment: 2, config: 1 };
        return typeOrder[b.type] - typeOrder[a.type];
      });

    // Apply max files limit
    if (options.maxFiles && securityFiles.length > options.maxFiles) {
      return securityFiles.slice(0, options.maxFiles);
    }

    return securityFiles;
  }

  /**
   * Groups security files by type for targeted analysis
   */
  static groupFilesByType(securityFiles: SecurityFile[]): Record<string, SecurityFile[]> {
    return securityFiles.reduce((groups, file) => {
      if (!groups[file.type]) {
        groups[file.type] = [];
      }
      groups[file.type].push(file);
      return groups;
    }, {} as Record<string, SecurityFile[]>);
  }

  /**
   * Gets analysis-specific file filters
   */
  static getAnalysisFilters(analysisType: string): FileFilterOptions {
    switch (analysisType) {
      case 'secrets':
        return {
          includeSecretFiles: true,
          includeConfigFiles: true,
          maxFiles: 20
        };
      case 'vulnerabilities':
        return {
          includeSecurityFiles: true,
          includeDependencyFiles: true,
          maxFiles: 15
        };
      case 'dependencies':
        return {
          includeDependencyFiles: true,
          maxFiles: 10
        };
      case 'code-patterns':
        return {
          includeSecurityFiles: true,
          includeConfigFiles: true,
          maxFiles: 25
        };
      default:
        return {
          includeConfigFiles: true,
          includeDependencyFiles: true,
          includeSecretFiles: true,
          includeSecurityFiles: true,
          includeDeploymentFiles: true,
          maxFiles: 30
        };
    }
  }

  private static shouldIncludeCategory(category: string, options: FileFilterOptions): boolean {
    switch (category) {
      case 'config': return options.includeConfigFiles !== false;
      case 'dependency': return options.includeDependencyFiles !== false;
      case 'secret': return options.includeSecretFiles !== false;
      case 'security': return options.includeSecurityFiles !== false;
      case 'deployment': return options.includeDeploymentFiles !== false;
      default: return true;
    }
  }

  private static getPriority(category: string, filePath: string): 'high' | 'medium' | 'low' {
    // High priority: secrets, root-level configs, main dependency files
    if (category === 'secret') return 'high';
    if (category === 'dependency' && !filePath.includes('/')) return 'high';
    if (category === 'config' && filePath.includes('.env')) return 'high';

    // Medium priority: security files, deployment configs
    if (category === 'security') return 'medium';
    if (category === 'deployment') return 'medium';

    // Low priority: other config files
    return 'low';
  }

  private static getPriorityScore(priority: 'high' | 'medium' | 'low'): number {
    switch (priority) {
      case 'high': return 3;
      case 'medium': return 2;
      case 'low': return 1;
      default: return 0;
    }
  }
} 