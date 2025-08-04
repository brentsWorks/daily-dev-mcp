import { describe, it, expect, beforeEach, vi } from 'vitest';
import { analyzeSecurityWithAIChunked } from '../../app/utils/githubSecurityClient';
import { SecurityFile } from '../../app/utils/securityFileFilter';

// Mock environment variables
vi.mock('../../app/config/env', () => ({
  env: {
    REDIS_URL: 'redis://localhost:6379',
    SMITHERY_GITHUB_API_KEY: 'test-key',
    GOOGLE_API_KEY: 'test-google-key'
  }
}));

// Mock the OpenAI client
vi.mock('openai', () => ({
  OpenAI: vi.fn().mockImplementation(() => ({
    chat: {
      completions: {
        create: vi.fn().mockResolvedValue({
          choices: [{
            message: {
              content: JSON.stringify({
                executive_summary: {
                  overall_risk: "Low",
                  security_posture: "Test security posture",
                  key_concerns: []
                },
                critical_findings: [],
                vulnerability_assessment: [],
                risk_analysis: {
                  high_risk_items: [],
                  medium_risk_items: [],
                  low_risk_items: [],
                  risk_factors: []
                },
                recommendations: [],
                security_score: {
                  score: 7,
                  justification: "Test score",
                  factors: []
                }
              })
            }
          }]
        })
      }
    }
  }))
}));

describe('Chunked Integration', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  describe('analyzeSecurityWithAIChunked', () => {
    it('should process repository with multiple file types', async () => {
      const githubData = {
        repository: 'test-owner/test-repo',
        analysis_type: 'secrets',
        targeted_files: [
          { path: '.env', type: 'secret', priority: 'high', reason: 'Environment file' },
          { path: 'package.json', type: 'dependency', priority: 'high', reason: 'Dependencies' },
          { path: 'config.json', type: 'config', priority: 'low', reason: 'Configuration' }
        ]
      };

      const result = await analyzeSecurityWithAIChunked(
        githubData,
        'secrets',
        'test-owner/test-repo'
      );

      expect(result.ai_analysis).toBeDefined();
    });

    it('should handle repository with no targeted files', async () => {
      const githubData = {
        repository: 'test-owner/test-repo',
        analysis_type: 'secrets',
        targeted_files: []
      };

      const result = await analyzeSecurityWithAIChunked(
        githubData,
        'secrets',
        'test-owner/test-repo'
      );

      expect(result.ai_analysis).toBeDefined();
    });

    it('should include chunked analysis metadata', async () => {
      const githubData = {
        repository: 'test-owner/test-repo',
        analysis_type: 'secrets',
        targeted_files: [
          { path: '.env', type: 'secret', priority: 'high', reason: 'Environment file' },
          { path: 'package.json', type: 'dependency', priority: 'high', reason: 'Dependencies' }
        ]
      };

      const result = await analyzeSecurityWithAIChunked(
        githubData,
        'secrets',
        'test-owner/test-repo'
      );

      expect(result.chunked_analysis).toBeDefined();
      expect(result.chunked_analysis.total_chunks).toBeGreaterThan(0);
    });

    it('should process secret files correctly', async () => {
      const githubData = {
        repository: 'test-owner/test-repo',
        analysis_type: 'secrets',
        targeted_files: [
          { path: '.env', type: 'secret', priority: 'high', reason: 'Environment file' },
          { path: 'secrets.json', type: 'secret', priority: 'high', reason: 'Secrets file' }
        ]
      };

      const result = await analyzeSecurityWithAIChunked(
        githubData,
        'secrets',
        'test-owner/test-repo'
      );

      expect(result.chunked_analysis.chunk_results).toBeDefined();
      expect(result.chunked_analysis.chunk_results.length).toBeGreaterThan(0);
    });

    it('should process dependency files correctly', async () => {
      const githubData = {
        repository: 'test-owner/test-repo',
        analysis_type: 'dependencies',
        targeted_files: [
          { path: 'package.json', type: 'dependency', priority: 'high', reason: 'Dependencies' },
          { path: 'requirements.txt', type: 'dependency', priority: 'high', reason: 'Python dependencies' }
        ]
      };

      const result = await analyzeSecurityWithAIChunked(
        githubData,
        'dependencies',
        'test-owner/test-repo'
      );

      expect(result.chunked_analysis.chunk_results).toBeDefined();
      expect(result.chunked_analysis.chunk_results.length).toBeGreaterThan(0);
    });

    it('should aggregate results from multiple chunks', async () => {
      const githubData = {
        repository: 'test-owner/test-repo',
        analysis_type: 'secrets',
        targeted_files: [
          { path: '.env', type: 'secret', priority: 'high', reason: 'Environment file' },
          { path: 'package.json', type: 'dependency', priority: 'high', reason: 'Dependencies' },
          { path: 'config.json', type: 'config', priority: 'low', reason: 'Configuration' }
        ]
      };

      const result = await analyzeSecurityWithAIChunked(
        githubData,
        'secrets',
        'test-owner/test-repo'
      );

      expect(result.ai_analysis.executive_summary).toBeDefined();
      expect(result.ai_analysis.security_score).toBeDefined();
    });

    it('should include processing statistics', async () => {
      const githubData = {
        repository: 'test-owner/test-repo',
        analysis_type: 'secrets',
        targeted_files: [
          { path: '.env', type: 'secret', priority: 'high', reason: 'Environment file' }
        ]
      };

      const result = await analyzeSecurityWithAIChunked(
        githubData,
        'secrets',
        'test-owner/test-repo'
      );

      expect(result.chunked_analysis.total_tokens_used).toBeGreaterThanOrEqual(0);
      expect(result.chunked_analysis.processed_chunks).toBeGreaterThanOrEqual(0);
    });

    it('should handle analysis type parameter correctly', async () => {
      const githubData = {
        repository: 'test-owner/test-repo',
        analysis_type: 'vulnerabilities',
        targeted_files: [
          { path: 'package.json', type: 'dependency', priority: 'high', reason: 'Dependencies' }
        ]
      };

      const result = await analyzeSecurityWithAIChunked(
        githubData,
        'vulnerabilities',
        'test-owner/test-repo'
      );

      expect(result.ai_analysis).toBeDefined();
      expect(result.model_used).toBe('gemini-2.0-flash');
    });

    it('should include timestamp in results', async () => {
      const githubData = {
        repository: 'test-owner/test-repo',
        analysis_type: 'secrets',
        targeted_files: [
          { path: '.env', type: 'secret', priority: 'high', reason: 'Environment file' }
        ]
      };

      const result = await analyzeSecurityWithAIChunked(
        githubData,
        'secrets',
        'test-owner/test-repo'
      );

      expect(result.analysis_timestamp).toBeDefined();
      expect(new Date(result.analysis_timestamp)).toBeInstanceOf(Date);
    });
  });
}); 