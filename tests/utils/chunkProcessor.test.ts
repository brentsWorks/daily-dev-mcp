import { describe, it, expect, beforeEach } from 'vitest';
import { ChunkProcessor, ChunkResult, ChunkFinding } from '../../app/utils/chunkProcessor';
import { AnalysisChunk } from '../../app/utils/analysisChunker';
import { SecurityFile } from '../../app/utils/securityFileFilter';

describe('ChunkProcessor', () => {
  let processor: ChunkProcessor;

  beforeEach(() => {
    processor = new ChunkProcessor('secrets', 'test-owner/test-repo');
  });

  describe('processChunk', () => {
    it('should process secret chunk and return results', async () => {
      const chunk: AnalysisChunk = {
        id: 'test-chunk',
        type: 'secret',
        files: [
          { path: '.env', type: 'secret', priority: 'high', reason: 'Environment file' }
        ],
        priority: 'high',
        description: '1 secret files',
        estimatedTokens: 200
      };

      const result = await processor.processChunk(chunk);

      expect(result.chunkId).toBe('test-chunk');
    });

    it('should process dependency chunk and return results', async () => {
      const chunk: AnalysisChunk = {
        id: 'test-chunk',
        type: 'dependency',
        files: [
          { path: 'package.json', type: 'dependency', priority: 'high', reason: 'Dependencies' }
        ],
        priority: 'high',
        description: '1 dependency files',
        estimatedTokens: 150
      };

      const result = await processor.processChunk(chunk);

      expect(result.chunkType).toBe('dependency');
    });

    it('should process config chunk and return results', async () => {
      const chunk: AnalysisChunk = {
        id: 'test-chunk',
        type: 'config',
        files: [
          { path: 'config.json', type: 'config', priority: 'low', reason: 'Configuration' }
        ],
        priority: 'low',
        description: '1 config files',
        estimatedTokens: 100
      };

      const result = await processor.processChunk(chunk);

      expect(result.analysisType).toBe('secrets');
    });

    it('should include processing time in results', async () => {
      const chunk: AnalysisChunk = {
        id: 'test-chunk',
        type: 'secret',
        files: [
          { path: '.env', type: 'secret', priority: 'high', reason: 'Environment file' }
        ],
        priority: 'high',
        description: '1 secret files',
        estimatedTokens: 200
      };

      const result = await processor.processChunk(chunk);

      expect(result.processingTime).toBeGreaterThanOrEqual(0);
    });

    it('should include token usage estimate in results', async () => {
      const chunk: AnalysisChunk = {
        id: 'test-chunk',
        type: 'secret',
        files: [
          { path: '.env', type: 'secret', priority: 'high', reason: 'Environment file' }
        ],
        priority: 'high',
        description: '1 secret files',
        estimatedTokens: 200
      };

      const result = await processor.processChunk(chunk);

      expect(result.tokensUsed).toBeGreaterThan(0);
    });
  });

  describe('secret file analysis', () => {
    it('should detect environment files as high severity', async () => {
      const chunk: AnalysisChunk = {
        id: 'test-chunk',
        type: 'secret',
        files: [
          { path: '.env', type: 'secret', priority: 'high', reason: 'Environment file' }
        ],
        priority: 'high',
        description: '1 secret files',
        estimatedTokens: 200
      };

      const result = await processor.processChunk(chunk);
      const envFinding = result.findings.find(f => f.filePath === '.env');

      expect(envFinding?.severity).toBe('high');
    });

    it('should detect secrets files as critical severity', async () => {
      const chunk: AnalysisChunk = {
        id: 'test-chunk',
        type: 'secret',
        files: [
          { path: 'secrets.json', type: 'secret', priority: 'high', reason: 'Secrets file' }
        ],
        priority: 'high',
        description: '1 secret files',
        estimatedTokens: 200
      };

      const result = await processor.processChunk(chunk);
      const secretsFinding = result.findings.find(f => f.filePath === 'secrets.json');

      expect(secretsFinding?.severity).toBe('critical');
    });

    it('should include recommendations for secret files', async () => {
      const chunk: AnalysisChunk = {
        id: 'test-chunk',
        type: 'secret',
        files: [
          { path: '.env', type: 'secret', priority: 'high', reason: 'Environment file' }
        ],
        priority: 'high',
        description: '1 secret files',
        estimatedTokens: 200
      };

      const result = await processor.processChunk(chunk);
      const envFinding = result.findings.find(f => f.filePath === '.env');

      expect(envFinding?.recommendation).toBeDefined();
    });
  });

  describe('dependency file analysis', () => {
    it('should detect package.json files', async () => {
      const chunk: AnalysisChunk = {
        id: 'test-chunk',
        type: 'dependency',
        files: [
          { path: 'package.json', type: 'dependency', priority: 'high', reason: 'Dependencies' }
        ],
        priority: 'high',
        description: '1 dependency files',
        estimatedTokens: 150
      };

      const result = await processor.processChunk(chunk);
      const packageFinding = result.findings.find(f => f.filePath === 'package.json');

      expect(packageFinding?.type).toBe('dependency');
    });

    it('should detect requirements.txt files', async () => {
      const chunk: AnalysisChunk = {
        id: 'test-chunk',
        type: 'dependency',
        files: [
          { path: 'requirements.txt', type: 'dependency', priority: 'high', reason: 'Dependencies' }
        ],
        priority: 'high',
        description: '1 dependency files',
        estimatedTokens: 150
      };

      const result = await processor.processChunk(chunk);
      const requirementsFinding = result.findings.find(f => f.filePath === 'requirements.txt');

      expect(requirementsFinding?.type).toBe('dependency');
    });
  });

  describe('deployment file analysis', () => {
    it('should detect Dockerfile files', async () => {
      const chunk: AnalysisChunk = {
        id: 'test-chunk',
        type: 'deployment',
        files: [
          { path: 'Dockerfile', type: 'deployment', priority: 'medium', reason: 'Docker configuration' }
        ],
        priority: 'medium',
        description: '1 deployment files',
        estimatedTokens: 120
      };

      const result = await processor.processChunk(chunk);
      const dockerFinding = result.findings.find(f => f.filePath === 'Dockerfile');

      expect(dockerFinding?.type).toBe('security');
    });

    it('should detect docker-compose files', async () => {
      const chunk: AnalysisChunk = {
        id: 'test-chunk',
        type: 'deployment',
        files: [
          { path: 'docker-compose.yml', type: 'deployment', priority: 'medium', reason: 'Docker Compose configuration' }
        ],
        priority: 'medium',
        description: '1 deployment files',
        estimatedTokens: 120
      };

      const result = await processor.processChunk(chunk);
      const composeFinding = result.findings.find(f => f.filePath === 'docker-compose.yml');

      expect(composeFinding?.type).toBe('security');
    });
  });

  describe('summary generation', () => {
    it('should generate correct summary for chunk with findings', async () => {
      const chunk: AnalysisChunk = {
        id: 'test-chunk',
        type: 'secret',
        files: [
          { path: '.env', type: 'secret', priority: 'high', reason: 'Environment file' },
          { path: 'secrets.json', type: 'secret', priority: 'high', reason: 'Secrets file' }
        ],
        priority: 'high',
        description: '2 secret files',
        estimatedTokens: 400
      };

      const result = await processor.processChunk(chunk);

      expect(result.summary.totalFindings).toBeGreaterThan(0);
    });

    it('should set overall risk to critical when critical findings exist', async () => {
      const chunk: AnalysisChunk = {
        id: 'test-chunk',
        type: 'secret',
        files: [
          { path: 'secrets.json', type: 'secret', priority: 'high', reason: 'Secrets file' }
        ],
        priority: 'high',
        description: '1 secret files',
        estimatedTokens: 200
      };

      const result = await processor.processChunk(chunk);

      expect(result.summary.overallRisk).toBe('critical');
    });

    it('should set overall risk to high when high findings exist', async () => {
      const chunk: AnalysisChunk = {
        id: 'test-chunk',
        type: 'secret',
        files: [
          { path: '.env', type: 'secret', priority: 'high', reason: 'Environment file' }
        ],
        priority: 'high',
        description: '1 secret files',
        estimatedTokens: 200
      };

      const result = await processor.processChunk(chunk);

      expect(result.summary.overallRisk).toBe('high');
    });

    it('should set overall risk to safe when no findings exist', async () => {
      const chunk: AnalysisChunk = {
        id: 'test-chunk',
        type: 'config',
        files: [
          { path: 'config.json', type: 'config', priority: 'low', reason: 'Configuration' }
        ],
        priority: 'low',
        description: '1 config files',
        estimatedTokens: 100
      };

      const result = await processor.processChunk(chunk);

      expect(result.summary.overallRisk).toBe('low');
    });
  });

  describe('getProcessingStats', () => {
    it('should generate readable processing statistics', async () => {
      const chunk: AnalysisChunk = {
        id: 'test-chunk',
        type: 'secret',
        files: [
          { path: '.env', type: 'secret', priority: 'high', reason: 'Environment file' }
        ],
        priority: 'high',
        description: '1 secret files',
        estimatedTokens: 200
      };

      const result = await processor.processChunk(chunk);
      const stats = processor.getProcessingStats(chunk, result);

      expect(stats).toContain('Chunk secret');
      expect(stats).toContain('findings');
      expect(stats).toContain('ms');
      expect(stats).toContain('tokens');
    });
  });
}); 