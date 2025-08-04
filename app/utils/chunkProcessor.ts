import { AnalysisChunk } from './analysisChunker';
import { SecurityFile } from './securityFileFilter';

export interface ChunkResult {
  chunkId: string;
  chunkType: string;
  analysisType: string;
  findings: ChunkFinding[];
  summary: ChunkSummary;
  processingTime: number;
  tokensUsed: number;
}

export interface ChunkFinding {
  type: 'vulnerability' | 'secret' | 'dependency' | 'configuration' | 'security';
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  title: string;
  description: string;
  filePath?: string;
  lineNumber?: number;
  recommendation?: string;
}

export interface ChunkSummary {
  totalFindings: number;
  criticalFindings: number;
  highFindings: number;
  mediumFindings: number;
  lowFindings: number;
  infoFindings: number;
  overallRisk: 'critical' | 'high' | 'medium' | 'low' | 'safe';
}

export class ChunkProcessor {
  private analysisType: string;
  private repository: string;

  constructor(analysisType: string, repository: string) {
    this.analysisType = analysisType;
    this.repository = repository;
  }

  /**
   * Process a single chunk and return analysis results
   */
  async processChunk(chunk: AnalysisChunk): Promise<ChunkResult> {
    const startTime = Date.now();
    
    console.log(`🔍 Processing chunk: ${chunk.type} (${chunk.files.length} files)`);
    
    // Analyze the chunk based on its type
    const findings = await this.analyzeChunkByType(chunk);
    
    // Generate summary
    const summary = this.generateSummary(findings);
    
    // Estimate tokens used (rough calculation)
    const tokensUsed = this.estimateTokensUsed(chunk, findings);
    
    const processingTime = Date.now() - startTime;
    
    console.log(`✅ Chunk processed in ${processingTime}ms: ${findings.length} findings`);
    
    return {
      chunkId: chunk.id,
      chunkType: chunk.type,
      analysisType: this.analysisType,
      findings,
      summary,
      processingTime,
      tokensUsed
    };
  }

  /**
   * Analyze chunk based on its type and the overall analysis type
   */
  private async analyzeChunkByType(chunk: AnalysisChunk): Promise<ChunkFinding[]> {
    const findings: ChunkFinding[] = [];

    switch (chunk.type) {
      case 'secret':
        findings.push(...this.analyzeSecretFiles(chunk.files));
        break;
      case 'dependency':
        findings.push(...this.analyzeDependencyFiles(chunk.files));
        break;
      case 'config':
        findings.push(...this.analyzeConfigFiles(chunk.files));
        break;
      case 'security':
        findings.push(...this.analyzeSecurityFiles(chunk.files));
        break;
      case 'deployment':
        findings.push(...this.analyzeDeploymentFiles(chunk.files));
        break;
    }

    return findings;
  }

  /**
   * Analyze secret files for potential exposures
   */
  private analyzeSecretFiles(files: SecurityFile[]): ChunkFinding[] {
    const findings: ChunkFinding[] = [];

    for (const file of files) {
      // Check for common secret file patterns
      if (file.path.includes('.env')) {
        findings.push({
          type: 'secret',
          severity: 'high',
          title: 'Environment file detected',
          description: `Environment file found: ${file.path}. Ensure this file is not committed to version control.`,
          filePath: file.path,
          recommendation: 'Add .env files to .gitignore and use environment variables for secrets.'
        });
      }

      if (file.path.includes('secrets.json') || file.path.includes('credentials.json')) {
        findings.push({
          type: 'secret',
          severity: 'critical',
          title: 'Secrets file detected',
          description: `Secrets file found: ${file.path}. This file may contain sensitive credentials.`,
          filePath: file.path,
          recommendation: 'Use a secrets management service instead of storing secrets in files.'
        });
      }
    }

    return findings;
  }

  /**
   * Analyze dependency files for vulnerabilities
   */
  private analyzeDependencyFiles(files: SecurityFile[]): ChunkFinding[] {
    const findings: ChunkFinding[] = [];

    for (const file of files) {
      if (file.path.includes('package.json')) {
        findings.push({
          type: 'dependency',
          severity: 'medium',
          title: 'Dependency file detected',
          description: `Dependency file found: ${file.path}. Review dependencies for known vulnerabilities.`,
          filePath: file.path,
          recommendation: 'Run npm audit regularly and keep dependencies updated.'
        });
      }

      if (file.path.includes('requirements.txt')) {
        findings.push({
          type: 'dependency',
          severity: 'medium',
          title: 'Python dependencies detected',
          description: `Python dependency file found: ${file.path}. Review for security vulnerabilities.`,
          filePath: file.path,
          recommendation: 'Use tools like safety to check for known vulnerabilities.'
        });
      }
    }

    return findings;
  }

  /**
   * Analyze configuration files for security issues
   */
  private analyzeConfigFiles(files: SecurityFile[]): ChunkFinding[] {
    const findings: ChunkFinding[] = [];

    for (const file of files) {
      findings.push({
        type: 'configuration',
        severity: 'low',
        title: 'Configuration file detected',
        description: `Configuration file found: ${file.path}. Review for security settings.`,
        filePath: file.path,
        recommendation: 'Ensure configuration files have appropriate security settings.'
      });
    }

    return findings;
  }

  /**
   * Analyze security-specific files
   */
  private analyzeSecurityFiles(files: SecurityFile[]): ChunkFinding[] {
    const findings: ChunkFinding[] = [];

    for (const file of files) {
      findings.push({
        type: 'security',
        severity: 'medium',
        title: 'Security file detected',
        description: `Security-related file found: ${file.path}. Review security configurations.`,
        filePath: file.path,
        recommendation: 'Ensure security configurations follow best practices.'
      });
    }

    return findings;
  }

  /**
   * Analyze deployment files for security issues
   */
  private analyzeDeploymentFiles(files: SecurityFile[]): ChunkFinding[] {
    const findings: ChunkFinding[] = [];

    for (const file of files) {
      if (file.path.toLowerCase().includes('dockerfile')) {
        findings.push({
          type: 'security',
          severity: 'medium',
          title: 'Dockerfile detected',
          description: `Dockerfile found: ${file.path}. Review for security best practices.`,
          filePath: file.path,
          recommendation: 'Use multi-stage builds, run as non-root user, and scan for vulnerabilities.'
        });
      }

      if (file.path.toLowerCase().includes('docker-compose')) {
        findings.push({
          type: 'security',
          severity: 'low',
          title: 'Docker Compose file detected',
          description: `Docker Compose file found: ${file.path}. Review container configurations.`,
          filePath: file.path,
          recommendation: 'Ensure containers don\'t run as root and use secure base images.'
        });
      }
    }

    return findings;
  }

  /**
   * Generate summary from findings
   */
  private generateSummary(findings: ChunkFinding[]): ChunkSummary {
    const criticalFindings = findings.filter(f => f.severity === 'critical').length;
    const highFindings = findings.filter(f => f.severity === 'high').length;
    const mediumFindings = findings.filter(f => f.severity === 'medium').length;
    const lowFindings = findings.filter(f => f.severity === 'low').length;
    const infoFindings = findings.filter(f => f.severity === 'info').length;

    let overallRisk: 'critical' | 'high' | 'medium' | 'low' | 'safe' = 'safe';
    if (criticalFindings > 0) overallRisk = 'critical';
    else if (highFindings > 0) overallRisk = 'high';
    else if (mediumFindings > 0) overallRisk = 'medium';
    else if (lowFindings > 0) overallRisk = 'low';

    return {
      totalFindings: findings.length,
      criticalFindings,
      highFindings,
      mediumFindings,
      lowFindings,
      infoFindings,
      overallRisk
    };
  }

  /**
   * Estimate tokens used for this chunk analysis
   */
  private estimateTokensUsed(chunk: AnalysisChunk, findings: ChunkFinding[]): number {
    // Base tokens for chunk processing
    let tokens = chunk.estimatedTokens;
    
    // Add tokens for findings (rough estimate)
    tokens += findings.length * 50;
    
    // Add tokens for summary generation
    tokens += 100;
    
    return Math.round(tokens);
  }

  /**
   * Get processing statistics for a chunk
   */
  getProcessingStats(chunk: AnalysisChunk, result: ChunkResult): string {
    return `Chunk ${chunk.type}: ${result.findings.length} findings, ${result.processingTime}ms, ~${result.tokensUsed} tokens`;
  }
} 