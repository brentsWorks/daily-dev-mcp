import { AnalysisChunk } from './analysisChunker';
import { ChunkProcessor, ChunkResult } from './chunkProcessor';

export interface StreamingProgress {
  currentChunk: number;
  totalChunks: number;
  currentChunkType: string;
  processedChunks: number;
  failedChunks: number;
  totalFindings: number;
  estimatedTimeRemaining: number;
  percentage: number;
}

export interface AggregatedAnalysis {
  totalChunks: number;
  processedChunks: number;
  failedChunks: number;
  totalFindings: number;
  criticalFindings: number;
  highFindings: number;
  mediumFindings: number;
  lowFindings: number;
  infoFindings: number;
  overallRisk: 'critical' | 'high' | 'medium' | 'low' | 'safe';
  chunkResults: ChunkResult[];
  processingTime: number;
  totalTokensUsed: number;
  summary: string;
}

export interface StreamingOptions {
  onProgress?: (progress: StreamingProgress) => void;
  onChunkComplete?: (result: ChunkResult) => void;
  onError?: (error: Error, chunk: AnalysisChunk) => void;
  maxConcurrentChunks?: number;
}

export class StreamingAnalyzer {
  private analysisType: string;
  private repository: string;
  private options: StreamingOptions;

  constructor(analysisType: string, repository: string, options: StreamingOptions = {}) {
    this.analysisType = analysisType;
    this.repository = repository;
    this.options = {
      onProgress: () => {},
      onChunkComplete: () => {},
      onError: () => {},
      maxConcurrentChunks: 1, // Sequential processing for now
      ...options
    };
  }

  /**
   * Process chunks sequentially with real-time feedback
   */
  async processChunks(chunks: AnalysisChunk[]): Promise<AggregatedAnalysis> {
    const startTime = Date.now();
    console.log(`🚀 Starting streaming analysis of ${chunks.length} chunks...`);

    const chunkResults: ChunkResult[] = [];
    let totalFindings = 0;
    let failedChunks = 0;

    // Process chunks sequentially
    for (let i = 0; i < chunks.length; i++) {
      const chunk = chunks[i];
      const currentChunk = i + 1;

      try {
        // Update progress
        const progress = this.calculateProgress(i, chunks.length, totalFindings, failedChunks, chunk.type);
        this.options.onProgress!(progress);

        console.log(`📊 Progress: ${progress.percentage}% (${currentChunk}/${chunks.length})`);

        // Process the chunk
        const processor = new ChunkProcessor(this.analysisType, this.repository);
        const result = await processor.processChunk(chunk);

        // Update totals
        totalFindings += result.findings.length;
        chunkResults.push(result);

        // Notify chunk completion
        this.options.onChunkComplete!(result);

        console.log(`✅ ${processor.getProcessingStats(chunk, result)}`);

      } catch (error) {
        failedChunks++;
        console.error(`❌ Failed to process chunk ${chunk.type}:`, error);
        this.options.onError!(error as Error, chunk);
      }
    }

    // Generate aggregated results
    const aggregatedAnalysis = this.aggregateResults(
      chunkResults,
      chunks.length,
      failedChunks,
      totalFindings,
      Date.now() - startTime
    );

    console.log(`🎉 Streaming analysis completed: ${aggregatedAnalysis.summary}`);

    return aggregatedAnalysis;
  }

  /**
   * Calculate current progress
   */
  private calculateProgress(
    currentIndex: number,
    totalChunks: number,
    totalFindings: number,
    failedChunks: number,
    currentChunkType: string
  ): StreamingProgress {
    const percentage = Math.round(((currentIndex + 1) / totalChunks) * 100);
    const processedChunks = currentIndex;
    
    // Rough time estimation (assume 100ms per chunk)
    const estimatedTimePerChunk = 100;
    const remainingChunks = totalChunks - currentIndex - 1;
    const estimatedTimeRemaining = remainingChunks * estimatedTimePerChunk;

    return {
      currentChunk: currentIndex + 1,
      totalChunks,
      currentChunkType,
      processedChunks,
      failedChunks,
      totalFindings,
      estimatedTimeRemaining,
      percentage
    };
  }

  /**
   * Aggregate results from all chunks
   */
  private aggregateResults(
    chunkResults: ChunkResult[],
    totalChunks: number,
    failedChunks: number,
    totalFindings: number,
    processingTime: number
  ): AggregatedAnalysis {
    // Aggregate findings by severity
    let criticalFindings = 0;
    let highFindings = 0;
    let mediumFindings = 0;
    let lowFindings = 0;
    let infoFindings = 0;
    let totalTokensUsed = 0;

    for (const result of chunkResults) {
      criticalFindings += result.summary.criticalFindings;
      highFindings += result.summary.highFindings;
      mediumFindings += result.summary.mediumFindings;
      lowFindings += result.summary.lowFindings;
      infoFindings += result.summary.infoFindings;
      totalTokensUsed += result.tokensUsed;
    }

    // Determine overall risk
    let overallRisk: 'critical' | 'high' | 'medium' | 'low' | 'safe' = 'safe';
    if (criticalFindings > 0) overallRisk = 'critical';
    else if (highFindings > 0) overallRisk = 'high';
    else if (mediumFindings > 0) overallRisk = 'medium';
    else if (lowFindings > 0) overallRisk = 'low';

    // Generate summary
    const summary = this.generateSummary(
      totalChunks,
      chunkResults.length,
      failedChunks,
      totalFindings,
      criticalFindings,
      highFindings,
      mediumFindings,
      lowFindings,
      processingTime,
      totalTokensUsed
    );

    return {
      totalChunks,
      processedChunks: chunkResults.length,
      failedChunks,
      totalFindings,
      criticalFindings,
      highFindings,
      mediumFindings,
      lowFindings,
      infoFindings,
      overallRisk,
      chunkResults,
      processingTime,
      totalTokensUsed,
      summary
    };
  }

  /**
   * Generate human-readable summary
   */
  private generateSummary(
    totalChunks: number,
    processedChunks: number,
    failedChunks: number,
    totalFindings: number,
    criticalFindings: number,
    highFindings: number,
    mediumFindings: number,
    lowFindings: number,
    processingTime: number,
    totalTokensUsed: number
  ): string {
    const successRate = Math.round((processedChunks / totalChunks) * 100);
    
    return [
      `Processed ${processedChunks}/${totalChunks} chunks (${successRate}% success rate)`,
      `Found ${totalFindings} security issues:`,
      `  • Critical: ${criticalFindings}`,
      `  • High: ${highFindings}`,
      `  • Medium: ${mediumFindings}`,
      `  • Low: ${lowFindings}`,
      `Completed in ${processingTime}ms using ~${totalTokensUsed} tokens`
    ].join('\n');
  }

  /**
   * Get a simple progress callback for console output
   */
  static createConsoleProgressCallback(): (progress: StreamingProgress) => void {
    return (progress: StreamingProgress) => {
      const bar = '█'.repeat(Math.floor(progress.percentage / 5)) + '░'.repeat(20 - Math.floor(progress.percentage / 5));
      console.log(`\r📊 [${bar}] ${progress.percentage}% - ${progress.currentChunk}/${progress.totalChunks} chunks (${progress.totalFindings} findings)`);
    };
  }

  /**
   * Get a simple chunk completion callback for console output
   */
  static createConsoleChunkCallback(): (result: ChunkResult) => void {
    return (result: ChunkResult) => {
      const riskEmoji = {
        'critical': '🔴',
        'high': '🟠',
        'medium': '🟡',
        'low': '🟢',
        'safe': '🟢'
      }[result.summary.overallRisk] || '⚪';
      
      console.log(`  ${riskEmoji} ${result.chunkType}: ${result.findings.length} findings (${result.processingTime}ms)`);
    };
  }
} 