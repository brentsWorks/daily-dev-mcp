import { describe, it, expect } from 'vitest';
import { SecurityFileFilter, SecurityFile, FileFilterOptions } from '../../app/utils/securityFileFilter';

describe('SecurityFileFilter', () => {
  describe('isSecurityRelevant', () => {
    describe('secret files', () => {
      it('should identify .env as secret file', () => {
        const result = SecurityFileFilter.isSecurityRelevant('.env');
        expect(result?.type).toBe('secret');
      });

      it('should identify .env as high priority', () => {
        const result = SecurityFileFilter.isSecurityRelevant('.env');
        expect(result?.priority).toBe('high');
      });

      it('should identify secrets.json as secret file', () => {
        const result = SecurityFileFilter.isSecurityRelevant('secrets.json');
        expect(result?.type).toBe('secret');
      });

      it('should identify credentials.json as secret file', () => {
        const result = SecurityFileFilter.isSecurityRelevant('credentials.json');
        expect(result?.type).toBe('secret');
      });

      it('should identify api_keys.txt as secret file', () => {
        const result = SecurityFileFilter.isSecurityRelevant('api_keys.txt');
        expect(result?.type).toBe('secret');
      });

      it('should identify auth.config as secret file', () => {
        const result = SecurityFileFilter.isSecurityRelevant('auth.config');
        expect(result?.type).toBe('secret');
      });
    });

    describe('dependency files', () => {
      it('should identify package.json as dependency file', () => {
        const result = SecurityFileFilter.isSecurityRelevant('package.json');
        expect(result?.type).toBe('dependency');
      });

      it('should identify requirements.txt as dependency file', () => {
        const result = SecurityFileFilter.isSecurityRelevant('requirements.txt');
        expect(result?.type).toBe('dependency');
      });

      it('should identify pom.xml as dependency file', () => {
        const result = SecurityFileFilter.isSecurityRelevant('pom.xml');
        expect(result?.type).toBe('dependency');
      });

      it('should identify Gemfile as dependency file', () => {
        const result = SecurityFileFilter.isSecurityRelevant('Gemfile');
        expect(result?.type).toBe('dependency');
      });

      it('should identify Cargo.toml as dependency file', () => {
        const result = SecurityFileFilter.isSecurityRelevant('Cargo.toml');
        expect(result?.type).toBe('dependency');
      });
    });

    describe('config files', () => {
      it('should identify config.json as config file', () => {
        const result = SecurityFileFilter.isSecurityRelevant('config.json');
        expect(result?.type).toBe('config');
      });

      it('should identify settings.yaml as config file', () => {
        const result = SecurityFileFilter.isSecurityRelevant('settings.yaml');
        expect(result?.type).toBe('config');
      });

      it('should identify app.config as config file', () => {
        const result = SecurityFileFilter.isSecurityRelevant('app.config');
        expect(result?.type).toBe('config');
      });

      it('should identify database.ini as config file', () => {
        const result = SecurityFileFilter.isSecurityRelevant('database.ini');
        expect(result?.type).toBe('config');
      });
    });

    describe('non-security files', () => {
      it('should return null for README.md', () => {
        const result = SecurityFileFilter.isSecurityRelevant('README.md');
        expect(result).toBeNull();
      });

      it('should return null for index.js', () => {
        const result = SecurityFileFilter.isSecurityRelevant('index.js');
        expect(result).toBeNull();
      });

      it('should return null for styles.css', () => {
        const result = SecurityFileFilter.isSecurityRelevant('styles.css');
        expect(result).toBeNull();
      });

      it('should return null for image.png', () => {
        const result = SecurityFileFilter.isSecurityRelevant('image.png');
        expect(result).toBeNull();
      });

      it('should return null for test.js', () => {
        const result = SecurityFileFilter.isSecurityRelevant('test.js');
        expect(result).toBeNull();
      });
    });
  });

  describe('filterFiles', () => {
    it('should filter out non-security files', () => {
      const allFiles = [
        'README.md',
        '.env',
        'package.json',
        'config.json',
        'index.js',
        'secrets.json',
        'styles.css'
      ];

      const result = SecurityFileFilter.filterFiles(allFiles);
      
      expect(result).toHaveLength(4);
    });

    it('should prioritize .env as first secret file', () => {
      const allFiles = [
        'README.md',
        '.env',
        'package.json',
        'config.json',
        'index.js',
        'secrets.json',
        'styles.css'
      ];

      const result = SecurityFileFilter.filterFiles(allFiles);
      
      expect(result[0].type).toBe('secret');
    });

    it('should prioritize secrets.json as second secret file', () => {
      const allFiles = [
        'README.md',
        '.env',
        'package.json',
        'config.json',
        'index.js',
        'secrets.json',
        'styles.css'
      ];

      const result = SecurityFileFilter.filterFiles(allFiles);
      
      expect(result[1].type).toBe('secret');
    });

    it('should include package.json as dependency file', () => {
      const allFiles = [
        'README.md',
        '.env',
        'package.json',
        'config.json',
        'index.js',
        'secrets.json',
        'styles.css'
      ];

      const result = SecurityFileFilter.filterFiles(allFiles);
      
      expect(result[2].type).toBe('dependency');
    });

    it('should include config.json as config file', () => {
      const allFiles = [
        'README.md',
        '.env',
        'package.json',
        'config.json',
        'index.js',
        'secrets.json',
        'styles.css'
      ];

      const result = SecurityFileFilter.filterFiles(allFiles);
      
      expect(result[3].type).toBe('config');
    });

    it('should respect maxFiles limit', () => {
      const manyFiles = Array.from({ length: 50 }, (_, i) => `config${i}.json`);
      
      const result = SecurityFileFilter.filterFiles(manyFiles, { maxFiles: 10 });
      
      expect(result).toHaveLength(10);
    });

    it('should filter to only secret files when specified', () => {
      const files = ['.env', 'package.json', 'config.json', 'secrets.json'];
      
      const result = SecurityFileFilter.filterFiles(files, { 
        includeSecretFiles: true,
        includeDependencyFiles: false,
        includeConfigFiles: false
      });
      
      expect(result).toHaveLength(2);
    });

    it('should only include secret files when only secret files are allowed', () => {
      const files = ['.env', 'package.json', 'config.json', 'secrets.json'];
      
      const result = SecurityFileFilter.filterFiles(files, { 
        includeSecretFiles: true,
        includeDependencyFiles: false,
        includeConfigFiles: false
      });
      
      expect(result.every(f => f.type === 'secret')).toBe(true);
    });
  });

  describe('groupFilesByType', () => {
    it('should group files into correct number of categories', () => {
      const files: SecurityFile[] = [
        { path: '.env', type: 'secret', priority: 'high', reason: 'test' },
        { path: 'package.json', type: 'dependency', priority: 'high', reason: 'test' },
        { path: 'config.json', type: 'config', priority: 'low', reason: 'test' },
        { path: 'secrets.json', type: 'secret', priority: 'high', reason: 'test' }
      ];

      const groups = SecurityFileFilter.groupFilesByType(files);
      
      expect(Object.keys(groups)).toHaveLength(3);
    });

    it('should group secret files correctly', () => {
      const files: SecurityFile[] = [
        { path: '.env', type: 'secret', priority: 'high', reason: 'test' },
        { path: 'package.json', type: 'dependency', priority: 'high', reason: 'test' },
        { path: 'config.json', type: 'config', priority: 'low', reason: 'test' },
        { path: 'secrets.json', type: 'secret', priority: 'high', reason: 'test' }
      ];

      const groups = SecurityFileFilter.groupFilesByType(files);
      
      expect(groups.secret).toHaveLength(2);
    });

    it('should group dependency files correctly', () => {
      const files: SecurityFile[] = [
        { path: '.env', type: 'secret', priority: 'high', reason: 'test' },
        { path: 'package.json', type: 'dependency', priority: 'high', reason: 'test' },
        { path: 'config.json', type: 'config', priority: 'low', reason: 'test' },
        { path: 'secrets.json', type: 'secret', priority: 'high', reason: 'test' }
      ];

      const groups = SecurityFileFilter.groupFilesByType(files);
      
      expect(groups.dependency).toHaveLength(1);
    });

    it('should group config files correctly', () => {
      const files: SecurityFile[] = [
        { path: '.env', type: 'secret', priority: 'high', reason: 'test' },
        { path: 'package.json', type: 'dependency', priority: 'high', reason: 'test' },
        { path: 'config.json', type: 'config', priority: 'low', reason: 'test' },
        { path: 'secrets.json', type: 'secret', priority: 'high', reason: 'test' }
      ];

      const groups = SecurityFileFilter.groupFilesByType(files);
      
      expect(groups.config).toHaveLength(1);
    });
  });

  describe('getAnalysisFilters', () => {
    describe('secrets analysis', () => {
      it('should include secret files for secrets analysis', () => {
        const filters = SecurityFileFilter.getAnalysisFilters('secrets');
        expect(filters.includeSecretFiles).toBe(true);
      });

      it('should include config files for secrets analysis', () => {
        const filters = SecurityFileFilter.getAnalysisFilters('secrets');
        expect(filters.includeConfigFiles).toBe(true);
      });

      it('should set correct max files for secrets analysis', () => {
        const filters = SecurityFileFilter.getAnalysisFilters('secrets');
        expect(filters.maxFiles).toBe(20);
      });
    });

    describe('vulnerabilities analysis', () => {
      it('should include security files for vulnerabilities analysis', () => {
        const filters = SecurityFileFilter.getAnalysisFilters('vulnerabilities');
        expect(filters.includeSecurityFiles).toBe(true);
      });

      it('should include dependency files for vulnerabilities analysis', () => {
        const filters = SecurityFileFilter.getAnalysisFilters('vulnerabilities');
        expect(filters.includeDependencyFiles).toBe(true);
      });

      it('should set correct max files for vulnerabilities analysis', () => {
        const filters = SecurityFileFilter.getAnalysisFilters('vulnerabilities');
        expect(filters.maxFiles).toBe(15);
      });
    });

    describe('dependencies analysis', () => {
      it('should include dependency files for dependencies analysis', () => {
        const filters = SecurityFileFilter.getAnalysisFilters('dependencies');
        expect(filters.includeDependencyFiles).toBe(true);
      });

      it('should set correct max files for dependencies analysis', () => {
        const filters = SecurityFileFilter.getAnalysisFilters('dependencies');
        expect(filters.maxFiles).toBe(10);
      });
    });

    describe('unknown analysis type', () => {
      it('should include config files for unknown analysis', () => {
        const filters = SecurityFileFilter.getAnalysisFilters('unknown');
        expect(filters.includeConfigFiles).toBe(true);
      });

      it('should include dependency files for unknown analysis', () => {
        const filters = SecurityFileFilter.getAnalysisFilters('unknown');
        expect(filters.includeDependencyFiles).toBe(true);
      });

      it('should include secret files for unknown analysis', () => {
        const filters = SecurityFileFilter.getAnalysisFilters('unknown');
        expect(filters.includeSecretFiles).toBe(true);
      });

      it('should include security files for unknown analysis', () => {
        const filters = SecurityFileFilter.getAnalysisFilters('unknown');
        expect(filters.includeSecurityFiles).toBe(true);
      });

      it('should include deployment files for unknown analysis', () => {
        const filters = SecurityFileFilter.getAnalysisFilters('unknown');
        expect(filters.includeDeploymentFiles).toBe(true);
      });

      it('should set correct max files for unknown analysis', () => {
        const filters = SecurityFileFilter.getAnalysisFilters('unknown');
        expect(filters.maxFiles).toBe(30);
      });
    });
  });
}); 