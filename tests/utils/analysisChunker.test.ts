import { describe, it, expect, beforeEach } from 'vitest';
import { AnalysisChunker, AnalysisChunk } from '../../app/utils/analysisChunker';
import { SecurityFile } from '../../app/utils/securityFileFilter';

describe('AnalysisChunker', () => {
  let chunker: AnalysisChunker;

  beforeEach(() => {
    chunker = new AnalysisChunker();
  });

  describe('chunkByType', () => {
    it('should create correct number of chunks for different file types', () => {
      const securityFiles: SecurityFile[] = [
        { path: '.env', type: 'secret', priority: 'high', reason: 'Environment file' },
        { path: 'secrets.json', type: 'secret', priority: 'high', reason: 'Secrets file' },
        { path: 'package.json', type: 'dependency', priority: 'high', reason: 'Dependencies' },
        { path: 'config.json', type: 'config', priority: 'low', reason: 'Configuration' }
      ];

      const chunks = chunker.chunkByType(securityFiles);

      expect(chunks).toHaveLength(3);
    });

    it('should create secret chunk when secret files are present', () => {
      const securityFiles: SecurityFile[] = [
        { path: '.env', type: 'secret', priority: 'high', reason: 'Environment file' }
      ];

      const chunks = chunker.chunkByType(securityFiles);
      const secretChunk = chunks.find(c => c.type === 'secret');

      expect(secretChunk).toBeDefined();
    });

    it('should create dependency chunk when dependency files are present', () => {
      const securityFiles: SecurityFile[] = [
        { path: 'package.json', type: 'dependency', priority: 'high', reason: 'Dependencies' }
      ];

      const chunks = chunker.chunkByType(securityFiles);
      const dependencyChunk = chunks.find(c => c.type === 'dependency');

      expect(dependencyChunk).toBeDefined();
    });

    it('should assign high priority when any file in chunk is high priority', () => {
      const securityFiles: SecurityFile[] = [
        { path: '.env', type: 'secret', priority: 'high', reason: 'Environment file' },
        { path: 'config.json', type: 'config', priority: 'low', reason: 'Configuration' }
      ];

      const chunks = chunker.chunkByType(securityFiles);
      const secretChunk = chunks.find(c => c.type === 'secret');

      expect(secretChunk?.priority).toBe('high');
    });

    it('should assign medium priority when no high priority files exist', () => {
      const securityFiles: SecurityFile[] = [
        { path: 'config.json', type: 'config', priority: 'medium', reason: 'Configuration' },
        { path: 'settings.json', type: 'config', priority: 'low', reason: 'Settings' }
      ];

      const chunks = chunker.chunkByType(securityFiles);
      const configChunk = chunks.find(c => c.type === 'config');

      expect(configChunk?.priority).toBe('medium');
    });

    it('should assign low priority when all files are low priority', () => {
      const securityFiles: SecurityFile[] = [
        { path: 'config.json', type: 'config', priority: 'low', reason: 'Configuration' },
        { path: 'settings.json', type: 'config', priority: 'low', reason: 'Settings' }
      ];

      const chunks = chunker.chunkByType(securityFiles);
      const configChunk = chunks.find(c => c.type === 'config');

      expect(configChunk?.priority).toBe('low');
    });

    it('should generate unique chunk IDs', () => {
      const securityFiles: SecurityFile[] = [
        { path: '.env', type: 'secret', priority: 'high', reason: 'Environment file' },
        { path: 'package.json', type: 'dependency', priority: 'high', reason: 'Dependencies' }
      ];

      const chunks = chunker.chunkByType(securityFiles);
      const ids = chunks.map(c => c.id);
      const uniqueIds = new Set(ids);

      expect(uniqueIds.size).toBe(chunks.length);
    });

    it('should include all files in chunks', () => {
      const securityFiles: SecurityFile[] = [
        { path: '.env', type: 'secret', priority: 'high', reason: 'Environment file' },
        { path: 'secrets.json', type: 'secret', priority: 'high', reason: 'Secrets file' },
        { path: 'package.json', type: 'dependency', priority: 'high', reason: 'Dependencies' }
      ];

      const chunks = chunker.chunkByType(securityFiles);
      const totalFilesInChunks = chunks.reduce((sum, chunk) => sum + chunk.files.length, 0);

      expect(totalFilesInChunks).toBe(securityFiles.length);
    });

    it('should estimate tokens for secret chunk', () => {
      const securityFiles: SecurityFile[] = [
        { path: '.env', type: 'secret', priority: 'high', reason: 'Environment file' }
      ];

      const chunks = chunker.chunkByType(securityFiles);
      const secretChunk = chunks.find(c => c.type === 'secret');

      expect(secretChunk?.estimatedTokens).toBeGreaterThan(0);
    });

    it('should estimate tokens for dependency chunk', () => {
      const securityFiles: SecurityFile[] = [
        { path: 'package.json', type: 'dependency', priority: 'high', reason: 'Dependencies' }
      ];

      const chunks = chunker.chunkByType(securityFiles);
      const dependencyChunk = chunks.find(c => c.type === 'dependency');

      expect(dependencyChunk?.estimatedTokens).toBeGreaterThan(0);
    });

    it('should estimate tokens for config chunk', () => {
      const securityFiles: SecurityFile[] = [
        { path: 'config.json', type: 'config', priority: 'low', reason: 'Configuration' }
      ];

      const chunks = chunker.chunkByType(securityFiles);
      const configChunk = chunks.find(c => c.type === 'config');

      expect(configChunk?.estimatedTokens).toBeGreaterThan(0);
    });
  });

  describe('getChunkSummary', () => {
    it('should include total chunk count in summary', () => {
      const securityFiles: SecurityFile[] = [
        { path: '.env', type: 'secret', priority: 'high', reason: 'Environment file' },
        { path: 'package.json', type: 'dependency', priority: 'high', reason: 'Dependencies' }
      ];

      const chunks = chunker.chunkByType(securityFiles);
      const summary = chunker.getChunkSummary(chunks);

      expect(summary).toContain('Created 2 chunks');
    });

    it('should include secret chunk information in summary', () => {
      const securityFiles: SecurityFile[] = [
        { path: '.env', type: 'secret', priority: 'high', reason: 'Environment file' }
      ];

      const chunks = chunker.chunkByType(securityFiles);
      const summary = chunker.getChunkSummary(chunks);

      expect(summary).toContain('secret: 1 files');
    });

    it('should include dependency chunk information in summary', () => {
      const securityFiles: SecurityFile[] = [
        { path: 'package.json', type: 'dependency', priority: 'high', reason: 'Dependencies' }
      ];

      const chunks = chunker.chunkByType(securityFiles);
      const summary = chunker.getChunkSummary(chunks);

      expect(summary).toContain('dependency: 1 files');
    });

    it('should include priority information in summary', () => {
      const securityFiles: SecurityFile[] = [
        { path: '.env', type: 'secret', priority: 'high', reason: 'Environment file' }
      ];

      const chunks = chunker.chunkByType(securityFiles);
      const summary = chunker.getChunkSummary(chunks);

      expect(summary).toContain('high priority');
    });

    it('should include token estimates in summary', () => {
      const securityFiles: SecurityFile[] = [
        { path: '.env', type: 'secret', priority: 'high', reason: 'Environment file' }
      ];

      const chunks = chunker.chunkByType(securityFiles);
      const summary = chunker.getChunkSummary(chunks);

      expect(summary).toContain('tokens');
    });
  });
}); 