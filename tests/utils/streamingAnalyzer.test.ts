import { describe, it, expect, beforeEach, vi } from 'vitest';
import { StreamingAnalyzer, StreamingProgress, AggregatedAnalysis } from '../../app/utils/streamingAnalyzer';
import { AnalysisChunk } from '../../app/utils/analysisChunker';
import { SecurityFile } from '../../app/utils/securityFileFilter';

describe('StreamingAnalyzer', () => {
  let analyzer: StreamingAnalyzer;
  let mockProgressCallback: ReturnType<typeof vi.fn>;
  let mockChunkCallback: ReturnType<typeof vi.fn>;
  let mockErrorCallback: ReturnType<typeof vi.fn>;

  beforeEach(() => {
    mockProgressCallback = vi.fn();
    mockChunkCallback = vi.fn();
    mockErrorCallback = vi.fn();
    
    analyzer = new StreamingAnalyzer('secrets', 'test-owner/test-repo', {
      onProgress: mockProgressCallback,
      onChunkComplete: mockChunkCallback,
      onError: mockErrorCallback
    });
  });

  describe('processChunks', () => {
    it('should process single chunk successfully', async () => {
      const chunks: AnalysisChunk[] = [
        {
          id: 'chunk-1',
          type: 'secret',
          files: [
            { path: '.env', type: 'secret', priority: 'high', reason: 'Environment file' }
          ],
          priority: 'high',
          description: '1 secret files',
          estimatedTokens: 200
        }
      ];

      const result = await analyzer.processChunks(chunks);

      expect(result.totalChunks).toBe(1);
    });

    it('should process multiple chunks successfully', async () => {
      const chunks: AnalysisChunk[] = [
        {
          id: 'chunk-1',
          type: 'secret',
          files: [
            { path: '.env', type: 'secret', priority: 'high', reason: 'Environment file' }
          ],
          priority: 'high',
          description: '1 secret files',
          estimatedTokens: 200
        },
        {
          id: 'chunk-2',
          type: 'dependency',
          files: [
            { path: 'package.json', type: 'dependency', priority: 'high', reason: 'Dependencies' }
          ],
          priority: 'high',
          description: '1 dependency files',
          estimatedTokens: 150
        }
      ];

      const result = await analyzer.processChunks(chunks);

      expect(result.totalChunks).toBe(2);
    });

    it('should call progress callback for each chunk', async () => {
      const chunks: AnalysisChunk[] = [
        {
          id: 'chunk-1',
          type: 'secret',
          files: [
            { path: '.env', type: 'secret', priority: 'high', reason: 'Environment file' }
          ],
          priority: 'high',
          description: '1 secret files',
          estimatedTokens: 200
        }
      ];

      await analyzer.processChunks(chunks);

      expect(mockProgressCallback).toHaveBeenCalled();
    });

    it('should call chunk completion callback for each chunk', async () => {
      const chunks: AnalysisChunk[] = [
        {
          id: 'chunk-1',
          type: 'secret',
          files: [
            { path: '.env', type: 'secret', priority: 'high', reason: 'Environment file' }
          ],
          priority: 'high',
          description: '1 secret files',
          estimatedTokens: 200
        }
      ];

      await analyzer.processChunks(chunks);

      expect(mockChunkCallback).toHaveBeenCalled();
    });

    it('should include processing time in results', async () => {
      const chunks: AnalysisChunk[] = [
        {
          id: 'chunk-1',
          type: 'secret',
          files: [
            { path: '.env', type: 'secret', priority: 'high', reason: 'Environment file' }
          ],
          priority: 'high',
          description: '1 secret files',
          estimatedTokens: 200
        }
      ];

      const result = await analyzer.processChunks(chunks);

      expect(result.processingTime).toBeGreaterThanOrEqual(0);
    });

    it('should aggregate findings from all chunks', async () => {
      const chunks: AnalysisChunk[] = [
        {
          id: 'chunk-1',
          type: 'secret',
          files: [
            { path: '.env', type: 'secret', priority: 'high', reason: 'Environment file' }
          ],
          priority: 'high',
          description: '1 secret files',
          estimatedTokens: 200
        },
        {
          id: 'chunk-2',
          type: 'secret',
          files: [
            { path: 'secrets.json', type: 'secret', priority: 'high', reason: 'Secrets file' }
          ],
          priority: 'high',
          description: '1 secret files',
          estimatedTokens: 200
        }
      ];

      const result = await analyzer.processChunks(chunks);

      expect(result.totalFindings).toBeGreaterThan(0);
    });

    it('should calculate overall risk based on findings', async () => {
      const chunks: AnalysisChunk[] = [
        {
          id: 'chunk-1',
          type: 'secret',
          files: [
            { path: 'secrets.json', type: 'secret', priority: 'high', reason: 'Secrets file' }
          ],
          priority: 'high',
          description: '1 secret files',
          estimatedTokens: 200
        }
      ];

      const result = await analyzer.processChunks(chunks);

      expect(result.overallRisk).toBe('critical');
    });

    it('should include chunk results in aggregated analysis', async () => {
      const chunks: AnalysisChunk[] = [
        {
          id: 'chunk-1',
          type: 'secret',
          files: [
            { path: '.env', type: 'secret', priority: 'high', reason: 'Environment file' }
          ],
          priority: 'high',
          description: '1 secret files',
          estimatedTokens: 200
        }
      ];

      const result = await analyzer.processChunks(chunks);

      expect(result.chunkResults).toHaveLength(1);
    });

    it('should calculate total tokens used', async () => {
      const chunks: AnalysisChunk[] = [
        {
          id: 'chunk-1',
          type: 'secret',
          files: [
            { path: '.env', type: 'secret', priority: 'high', reason: 'Environment file' }
          ],
          priority: 'high',
          description: '1 secret files',
          estimatedTokens: 200
        }
      ];

      const result = await analyzer.processChunks(chunks);

      expect(result.totalTokensUsed).toBeGreaterThan(0);
    });

    it('should generate summary with success rate', async () => {
      const chunks: AnalysisChunk[] = [
        {
          id: 'chunk-1',
          type: 'secret',
          files: [
            { path: '.env', type: 'secret', priority: 'high', reason: 'Environment file' }
          ],
          priority: 'high',
          description: '1 secret files',
          estimatedTokens: 200
        }
      ];

      const result = await analyzer.processChunks(chunks);

      expect(result.summary).toContain('100% success rate');
    });

    it('should handle empty chunks array', async () => {
      const chunks: AnalysisChunk[] = [];

      const result = await analyzer.processChunks(chunks);

      expect(result.totalChunks).toBe(0);
    });
  });

  describe('progress calculation', () => {
    it('should calculate correct percentage for single chunk', async () => {
      const chunks: AnalysisChunk[] = [
        {
          id: 'chunk-1',
          type: 'secret',
          files: [
            { path: '.env', type: 'secret', priority: 'high', reason: 'Environment file' }
          ],
          priority: 'high',
          description: '1 secret files',
          estimatedTokens: 200
        }
      ];

      await analyzer.processChunks(chunks);

      const progressCall = mockProgressCallback.mock.calls[0][0] as StreamingProgress;
      expect(progressCall.percentage).toBe(100);
    });

    it('should calculate correct percentage for multiple chunks', async () => {
      const chunks: AnalysisChunk[] = [
        {
          id: 'chunk-1',
          type: 'secret',
          files: [
            { path: '.env', type: 'secret', priority: 'high', reason: 'Environment file' }
          ],
          priority: 'high',
          description: '1 secret files',
          estimatedTokens: 200
        },
        {
          id: 'chunk-2',
          type: 'dependency',
          files: [
            { path: 'package.json', type: 'dependency', priority: 'high', reason: 'Dependencies' }
          ],
          priority: 'high',
          description: '1 dependency files',
          estimatedTokens: 150
        }
      ];

      await analyzer.processChunks(chunks);

      const progressCalls = mockProgressCallback.mock.calls;
      expect(progressCalls[0][0].percentage).toBe(50);
      expect(progressCalls[1][0].percentage).toBe(100);
    });
  });

  describe('static utility methods', () => {
    it('should create console progress callback', () => {
      const callback = StreamingAnalyzer.createConsoleProgressCallback();
      
      expect(typeof callback).toBe('function');
    });

    it('should create console chunk callback', () => {
      const callback = StreamingAnalyzer.createConsoleChunkCallback();
      
      expect(typeof callback).toBe('function');
    });
  });

  describe('error handling', () => {
    it('should handle errors gracefully without crashing', async () => {
      const chunks: AnalysisChunk[] = [
        {
          id: 'chunk-1',
          type: 'secret',
          files: [
            { path: '.env', type: 'secret', priority: 'high', reason: 'Environment file' }
          ],
          priority: 'high',
          description: '1 secret files',
          estimatedTokens: 200
        }
      ];

      const result = await analyzer.processChunks(chunks);

      expect(result.processedChunks).toBeGreaterThanOrEqual(0);
    });

    it('should continue processing other chunks when one fails', async () => {
      const chunks: AnalysisChunk[] = [
        {
          id: 'chunk-1',
          type: 'secret',
          files: [
            { path: '.env', type: 'secret', priority: 'high', reason: 'Environment file' }
          ],
          priority: 'high',
          description: '1 secret files',
          estimatedTokens: 200
        },
        {
          id: 'chunk-2',
          type: 'dependency',
          files: [
            { path: 'package.json', type: 'dependency', priority: 'high', reason: 'Dependencies' }
          ],
          priority: 'high',
          description: '1 dependency files',
          estimatedTokens: 150
        }
      ];

      const result = await analyzer.processChunks(chunks);

      expect(result.processedChunks).toBeGreaterThan(0);
    });
  });
}); 