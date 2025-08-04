import { SecurityFile } from './securityFileFilter';

export interface AnalysisChunk {
  id: string;
  type: 'secret' | 'dependency' | 'config' | 'security' | 'deployment';
  files: SecurityFile[];
  priority: 'high' | 'medium' | 'low';
  description: string;
  estimatedTokens: number;
}

export class AnalysisChunker {
  /**
   * Basic chunking strategy: Group files by their security type
   */
  chunkByType(securityFiles: SecurityFile[]): AnalysisChunk[] {
    const chunks: AnalysisChunk[] = [];
    const filesByType = new Map<string, SecurityFile[]>();

    // Group files by type
    for (const file of securityFiles) {
      if (!filesByType.has(file.type)) {
        filesByType.set(file.type, []);
      }
      filesByType.get(file.type)!.push(file);
    }

    // Create chunks for each type
    for (const [type, files] of filesByType) {
      if (files.length === 0) continue;

      const chunk: AnalysisChunk = {
        id: `chunk-${type}-${Date.now()}`,
        type: type as any,
        files: files,
        priority: this.getChunkPriority(files),
        description: `${files.length} ${type} files`,
        estimatedTokens: this.estimateTokens(files)
      };

      chunks.push(chunk);
    }

    return chunks;
  }

  /**
   * Get the highest priority from files in the chunk
   */
  private getChunkPriority(files: SecurityFile[]): 'high' | 'medium' | 'low' {
    const priorities = files.map(f => f.priority);
    
    if (priorities.includes('high')) return 'high';
    if (priorities.includes('medium')) return 'medium';
    return 'low';
  }

  /**
   * Rough token estimation based on file count and type
   */
  private estimateTokens(files: SecurityFile[]): number {
    let baseTokens = files.length * 100; // Base tokens per file
    
    // Adjust based on file type
    const type = files[0]?.type;
    switch (type) {
      case 'secret':
        baseTokens *= 2; // Secrets need more detailed analysis
        break;
      case 'dependency':
        baseTokens *= 1.5; // Dependencies have structured data
        break;
      case 'config':
        baseTokens *= 1.2; // Config files are usually smaller
        break;
      default:
        baseTokens *= 1;
    }

    return Math.min(baseTokens, 4000); // Cap at 4k tokens per chunk
  }

  /**
   * Get a summary of chunks for logging
   */
  getChunkSummary(chunks: AnalysisChunk[]): string {
    const summary = chunks.map(chunk => 
      `${chunk.type}: ${chunk.files.length} files (${chunk.priority} priority, ~${chunk.estimatedTokens} tokens)`
    ).join(', ');
    
    return `Created ${chunks.length} chunks: ${summary}`;
  }
} 