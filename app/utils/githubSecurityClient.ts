import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import { createSmitheryUrl } from "@smithery/sdk";
import { OpenAI } from "openai";
import { env } from "../config/env";
import { SecurityFileFilter, SecurityFile } from "./securityFileFilter";
import { AnalysisChunker } from './analysisChunker';
import { StreamingAnalyzer } from './streamingAnalyzer';

const geminiClient = new OpenAI({ 
  apiKey: env.GOOGLE_API_KEY,
  baseURL: "https://generativelanguage.googleapis.com/v1beta/openai/"
});

export class GitHubSecurityClient {
  private client: Client | null = null;
  private transport: StreamableHTTPClientTransport | null = null;
  private serverUrl: string;
  private apiKey: string;
  private profile: string;

  constructor(serverUrl: string, apiKey: string, profile: string) {
    this.serverUrl = serverUrl;
    this.apiKey = apiKey;
    this.profile = profile;
  }

  async connect(): Promise<void> {
    try {
      const smitheryUrl = createSmitheryUrl(this.serverUrl, {
        apiKey: this.apiKey,
        profile: this.profile
      });

      this.transport = new StreamableHTTPClientTransport(smitheryUrl);

      this.client = new Client({
        name: 'github-security-client',
        version: '1.0.0'
      });

      await this.client.connect(this.transport);
      console.log(`✅ Connected to Smithery.ai GitHub MCP server: ${this.serverUrl}`);
    } catch (error) {
      console.error("❌ Failed to connect to Smithery.ai GitHub MCP server:", error);
      throw error;
    }
  }

  async disconnect(): Promise<void> {
    if (this.client) {
      this.client.close();
      this.client = null;
      this.transport = null;
    }
  }

  async listTools(): Promise<any> {
    if (!this.client) {
      throw new Error("Client not connected. Call connect() first.");
    }
    return await this.client.listTools();
  }

  async callTool(toolName: string, arguments_: any): Promise<any> {
    if (!this.client) {
      throw new Error("Client not connected. Call connect() first.");
    }
    return await this.client.callTool({ name: toolName, arguments: arguments_ });
  }

  async listResources(): Promise<any> {
    if (!this.client) {
      throw new Error("Client not connected. Call connect() first.");
    }
    return await this.client.listResources();
  }

  async readResource(uri: string): Promise<any> {
    if (!this.client) {
      throw new Error("Client not connected. Call connect() first.");
    }
    return await this.client.readResource({ name: uri, uri });
  }

  getServerCapabilities() {
    if (!this.client) {
      throw new Error("Client not connected. Call connect() first.");
    }
    return this.client.getServerCapabilities();
  }

  isConnected(): boolean {
    return this.client !== null;
  }
}

// New function for targeted data collection using SecurityFileFilter
async function collectTargetedSecurityData(
  client: GitHubSecurityClient,
  owner: string,
  repo: string,
  analysisType: 'secrets' | 'vulnerabilities' | 'dependencies' | 'code-patterns'
): Promise<any> {
  const results: {
    repository: string;
    analysis_type: string;
    scan_date: string;
    targeted_files: SecurityFile[];
    findings: Array<{
      type: string;
      data?: any;
      description?: string;
      error?: string;
    }>;
  } = {
    repository: `${owner}/${repo}`,
    analysis_type: analysisType,
    scan_date: new Date().toISOString(),
    targeted_files: [],
    findings: []
  };

  try {
    // Step 1: Get repository structure to identify security-relevant files
    console.log(`🔍 Identifying security-relevant files for ${owner}/${repo}...`);
    
    // Get repository details first
    const repoDetails = await client.callTool("get_repository", { owner, repo });
    results.findings.push({
      type: "REPOSITORY_DETAILS",
      data: repoDetails,
      description: "Repository information for analysis"
    });

    // Step 2: Get file listing (this would need to be implemented based on available GitHub API tools)
    // For now, we'll use targeted searches based on analysis type
    const filterOptions = SecurityFileFilter.getAnalysisFilters(analysisType);
    
    // Step 3: Perform targeted searches based on analysis type
    switch (analysisType) {
      case 'secrets':
        // Search for secret-related files specifically
        try {
          const secretFiles = await client.callTool("search_code", {
            q: `repo:${owner}/${repo} filename:.env filename:secrets filename:credentials filename:keys`,
            per_page: filterOptions.maxFiles || 20
          });
          
          // Filter the results to only include security-relevant files
          let securityFiles: SecurityFile[] = [];
          if (secretFiles.items) {
            const filePaths = secretFiles.items.map((item: any) => item.path);
            securityFiles = SecurityFileFilter.filterFiles(filePaths, filterOptions);
            results.targeted_files = securityFiles;
          }
          
          results.findings.push({
            type: "TARGETED_SECRET_SEARCH",
            data: secretFiles,
            description: `Targeted search for ${securityFiles.length} security-relevant files`
          });
        } catch (error) {
          results.findings.push({
            type: "SECRET_SEARCH_ERROR",
            error: error instanceof Error ? error.message : 'Unknown error'
          });
        }
        break;

      case 'vulnerabilities':
        // Search for security-related issues and vulnerable dependencies
        try {
          // Get security issues
          const securityIssues = await client.callTool("search_issues", {
            q: `repo:${owner}/${repo} security vulnerability CVE`,
            per_page: 10
          });
          
          // Get dependency files
          const dependencyFiles = await client.callTool("search_code", {
            q: `repo:${owner}/${repo} filename:package.json filename:requirements.txt filename:pom.xml`,
            per_page: filterOptions.maxFiles || 15
          });
          
          let securityFiles: SecurityFile[] = [];
          if (dependencyFiles.items) {
            const filePaths = dependencyFiles.items.map((item: any) => item.path);
            securityFiles = SecurityFileFilter.filterFiles(filePaths, filterOptions);
            results.targeted_files = securityFiles;
          }
          
          results.findings.push({
            type: "SECURITY_ISSUES",
            data: securityIssues,
            description: "Security-related issues"
          });
          
          results.findings.push({
            type: "TARGETED_DEPENDENCY_SEARCH",
            data: dependencyFiles,
            description: `Targeted search for ${securityFiles.length} dependency files`
          });
        } catch (error) {
          results.findings.push({
            type: "VULNERABILITY_SEARCH_ERROR",
            error: error instanceof Error ? error.message : 'Unknown error'
          });
        }
        break;

      case 'dependencies':
        // Focus on dependency files
        try {
          const dependencyFiles = await client.callTool("search_code", {
            q: `repo:${owner}/${repo} filename:package.json filename:requirements.txt filename:pom.xml filename:Gemfile filename:Cargo.toml`,
            per_page: filterOptions.maxFiles || 10
          });
          
          let securityFiles: SecurityFile[] = [];
          if (dependencyFiles.items) {
            const filePaths = dependencyFiles.items.map((item: any) => item.path);
            securityFiles = SecurityFileFilter.filterFiles(filePaths, filterOptions);
            results.targeted_files = securityFiles;
          }
          
          results.findings.push({
            type: "TARGETED_DEPENDENCY_SEARCH",
            data: dependencyFiles,
            description: `Targeted search for ${securityFiles.length} dependency files`
          });
        } catch (error) {
          results.findings.push({
            type: "DEPENDENCY_SEARCH_ERROR",
            error: error instanceof Error ? error.message : 'Unknown error'
          });
        }
        break;

      case 'code-patterns':
        // Search for security-relevant code patterns in targeted files
        try {
          const codePatterns = await client.callTool("search_code", {
            q: `repo:${owner}/${repo} "SQL injection" "eval(" "exec(" "dangerous" filename:config filename:security`,
            per_page: filterOptions.maxFiles || 25
          });
          
          let securityFiles: SecurityFile[] = [];
          if (codePatterns.items) {
            const filePaths = codePatterns.items.map((item: any) => item.path);
            securityFiles = SecurityFileFilter.filterFiles(filePaths, filterOptions);
            results.targeted_files = securityFiles;
          }
          
          results.findings.push({
            type: "TARGETED_CODE_PATTERNS",
            data: codePatterns,
            description: `Targeted search for ${securityFiles.length} files with security patterns`
          });
        } catch (error) {
          results.findings.push({
            type: "CODE_PATTERNS_ERROR",
            error: error instanceof Error ? error.message : 'Unknown error'
          });
        }
        break;
    }

    console.log(`✅ Targeted data collection completed. Found ${results.targeted_files.length} security-relevant files.`);
    return results;
  } catch (error) {
    console.error('Error in targeted data collection:', error);
    throw error;
  }
}

// Helper function to easily call Smithery.ai GitHub tools
export async function callGitHubTool(
  serverUrl: string,
  apiKey: string,
  profile: string,
  toolName: string,
  parameters: any
): Promise<any> {
  const client = new GitHubSecurityClient(serverUrl, apiKey, profile);

  try {
    await client.connect();
    const result = await client.callTool(toolName, parameters);
    await client.disconnect();
    return result;
  } catch (error) {
    console.error('Error calling Smithery.ai GitHub tool:', error);
    throw error;
  }
}

// AI-powered security analysis using Gemini
export async function analyzeSecurityWithAI(
  githubData: any,
  analysisType: string,
  repository: string
): Promise<any> {
  const securityExpertPrompt = `You are a Senior Security Software Engineer with 15+ years of experience in application security, vulnerability assessment, and secure code review. You specialize in identifying security vulnerabilities, code weaknesses, and potential attack vectors in software projects.

Your expertise includes:
- Static Application Security Testing (SAST)
- Dynamic Application Security Testing (DAST)
- Dependency vulnerability analysis
- Secret detection and credential management
- Code injection vulnerabilities
- Authentication and authorization flaws
- Data exposure risks
- Security misconfigurations

Analyze the following GitHub repository data for security vulnerabilities and provide a comprehensive security assessment.

Repository: ${repository}
Analysis Type: ${analysisType}
GitHub Data: ${JSON.stringify(githubData, null, 2)}

IMPORTANT: Respond with ONLY valid JSON format. Do not include any markdown formatting, headers, or explanatory text.

Return a JSON object with the following structure:
IMPORTANT: If no security issues are found, return empty arrays for findings. Do not create fake or generic findings.

{
  "executive_summary": {
    "overall_risk": "Low|Medium|High",
    "security_posture": "string describing overall security state",
    "key_concerns": ["array of main security concerns - empty if none"]
  },
  "critical_findings": [
    {
      "finding": "string describing the finding",
      "severity": "Critical|High|Medium|Low",
      "impact": "string describing potential impact",
      "location": "string describing where this was found"
    }
  ],
  "vulnerability_assessment": [
    {
      "vulnerability": "string describing the vulnerability",
      "type": "string categorizing the vulnerability",
      "risk_level": "Critical|High|Medium|Low",
      "description": "detailed description of the vulnerability"
    }
  ],
  "risk_analysis": {
    "high_risk_items": ["array of high risk items - empty if none"],
    "medium_risk_items": ["array of medium risk items - empty if none"],
    "low_risk_items": ["array of low risk items - empty if none"],
    "risk_factors": ["array of contributing risk factors - empty if none"]
  },
  "recommendations": [
    {
      "recommendation": "string describing the recommendation",
      "priority": "Immediate|High|Medium|Low",
      "effort": "Low|Medium|High",
      "impact": "string describing expected impact of implementing this"
    }
  ],
  "security_score": {
    "score": number (1-10),
    "justification": "string explaining the score",
    "factors": ["array of factors contributing to the score"]
  }
}`;

  try {
    const response = await geminiClient.chat.completions.create({
      model: "gemini-2.0-flash",
      messages: [
        {
          role: "user",
          content: securityExpertPrompt
        }
      ],
      temperature: 0.1,
      max_tokens: 2000,
      response_format: { type: "json_object" }
    });

    const aiResponse = response.choices[0]?.message?.content || "{}";
    
    // Parse the JSON response from Gemini (guaranteed to be valid JSON)
    let parsedAnalysis;
    try {
      parsedAnalysis = JSON.parse(aiResponse);
    } catch (parseError) {
      console.error('Unexpected error parsing JSON response:', parseError);
      parsedAnalysis = {
        error: "Failed to parse AI response",
        raw_response: aiResponse
      };
    }
    
    return {
      ai_analysis: parsedAnalysis,
      model_used: "gemini-2.0-flash",
      analysis_timestamp: new Date().toISOString(),
      original_data: githubData
    };
  } catch (error) {
    console.error('Error performing AI security analysis:', error);
    return {
      ai_analysis: `Error performing AI analysis: ${error instanceof Error ? error.message : 'Unknown error'}`,
      model_used: "gemini-2.0-flash",
      analysis_timestamp: new Date().toISOString(),
      original_data: githubData
    };
  }
}

/**
 * Analyze security with AI using chunked processing for better efficiency
 */
export async function analyzeSecurityWithAIChunked(
  githubData: any,
  analysisType: string,
  repository: string
): Promise<any> {
  console.log(`🔧 Starting chunked AI analysis for ${repository}...`);
  
  // Extract targeted files from the GitHub data
  const targetedFiles = githubData.targeted_files || [];
  
  if (targetedFiles.length === 0) {
    console.log(`📝 No targeted files found for ${repository}, using basic AI analysis`);
    return await analyzeSecurityWithAI(githubData, analysisType, repository);
  }
  
  // Create chunks from the targeted files
  const chunker = new AnalysisChunker();
  const chunks = chunker.chunkByType(targetedFiles);
  
  console.log(`📦 Created ${chunks.length} chunks: ${chunker.getChunkSummary(chunks)}`);
  
  if (chunks.length === 0) {
    console.log(`📝 No chunks created for ${repository}, using basic AI analysis`);
    return await analyzeSecurityWithAI(githubData, analysisType, repository);
  }
  
  // Create streaming analyzer with console callbacks
  const streamingAnalyzer = new StreamingAnalyzer(analysisType, repository, {
    onProgress: StreamingAnalyzer.createConsoleProgressCallback(),
    onChunkComplete: StreamingAnalyzer.createConsoleChunkCallback()
  });
  
  // Process chunks with streaming analysis
  const aggregatedResults = await streamingAnalyzer.processChunks(chunks);
  
  // Now perform AI analysis on each chunk individually
  const chunkAIResults = [];
  let totalTokensUsed = 0;
  
  console.log(`🤖 Performing AI analysis on ${chunks.length} chunks...`);
  
  for (let i = 0; i < chunks.length; i++) {
    const chunk = chunks[i];
    console.log(`🧠 Analyzing chunk ${i + 1}/${chunks.length}: ${chunk.type}`);
    
    try {
      // Create chunk-specific data for AI analysis
      const chunkData = {
        repository,
        analysis_type: analysisType,
        chunk_type: chunk.type,
        chunk_priority: chunk.priority,
        files: chunk.files,
        chunk_description: chunk.description
      };
      
      // Perform AI analysis on this chunk
      const chunkAIResult = await analyzeSecurityWithAI(
        chunkData, 
        analysisType, 
        `${repository} (${chunk.type} chunk)`
      );
      
      chunkAIResults.push({
        chunk_id: chunk.id,
        chunk_type: chunk.type,
        chunk_priority: chunk.priority,
        ai_analysis: chunkAIResult,
        processing_stats: aggregatedResults.chunkResults[i]
      });
      
      totalTokensUsed += chunkAIResult.tokens_used || 0;
      
      console.log(`✅ AI analysis completed for ${chunk.type} chunk`);
      
    } catch (error) {
      console.error(`❌ AI analysis failed for ${chunk.type} chunk:`, error);
      chunkAIResults.push({
        chunk_id: chunk.id,
        chunk_type: chunk.type,
        chunk_priority: chunk.priority,
        ai_analysis: { error: `AI analysis failed: ${error}` },
        processing_stats: aggregatedResults.chunkResults[i]
      });
    }
  }
  
  // Aggregate AI results into a comprehensive analysis
  const aggregatedAI = aggregateChunkAIResults(chunkAIResults, repository, analysisType);
  
  console.log(`🎉 Chunked AI analysis completed for ${repository}`);
  console.log(`📊 Total tokens used: ~${totalTokensUsed}`);
  
  return {
    ai_analysis: aggregatedAI,
    chunked_analysis: {
      total_chunks: chunks.length,
      processed_chunks: aggregatedResults.processedChunks,
      failed_chunks: aggregatedResults.failedChunks,
      chunk_results: chunkAIResults,
      streaming_results: aggregatedResults,
      total_tokens_used: totalTokensUsed
    },
    model_used: "gemini-2.0-flash",
    analysis_timestamp: new Date().toISOString(),
    original_data: githubData
  };
}

/**
 * Aggregate AI results from multiple chunks into a comprehensive analysis
 */
function aggregateChunkAIResults(
  chunkAIResults: any[], 
  repository: string, 
  analysisType: string
): any {
  const allFindings = [];
  const allRecommendations = [];
  const allRiskFactors = [];
  let totalScore = 0;
  let validScores = 0;
  
  // Collect all findings and recommendations from chunks
  for (const chunkResult of chunkAIResults) {
    const aiAnalysis = chunkResult.ai_analysis?.ai_analysis;
    if (!aiAnalysis) continue;
    
    // Aggregate critical findings
    if (aiAnalysis.critical_findings) {
      allFindings.push(...aiAnalysis.critical_findings.map((f: any) => ({
        ...f,
        chunk_type: chunkResult.chunk_type,
        chunk_priority: chunkResult.chunk_priority
      })));
    }
    
    // Aggregate recommendations
    if (aiAnalysis.recommendations) {
      allRecommendations.push(...aiAnalysis.recommendations);
    }
    
    // Aggregate risk factors
    if (aiAnalysis.risk_analysis?.risk_factors) {
      allRiskFactors.push(...aiAnalysis.risk_analysis.risk_factors);
    }
    
    // Aggregate security scores
    if (aiAnalysis.security_score?.score) {
      totalScore += aiAnalysis.security_score.score;
      validScores++;
    }
  }
  
  // Calculate overall risk based on findings
  let overallRisk = 'Low';
  if (allFindings.some((f: any) => f.severity === 'Critical')) {
    overallRisk = 'Critical';
  } else if (allFindings.some((f: any) => f.severity === 'High')) {
    overallRisk = 'High';
  } else if (allFindings.some((f: any) => f.severity === 'Medium')) {
    overallRisk = 'Medium';
  }
  
  // Calculate average security score
  const averageScore = validScores > 0 ? Math.round(totalScore / validScores) : 7;
  
  return {
    executive_summary: {
      overall_risk: overallRisk,
      security_posture: `Comprehensive security analysis of ${repository} using chunked processing. Found ${allFindings.length} security issues across ${chunkAIResults.length} file type categories.`,
      key_concerns: allFindings.filter((f: any) => f.severity === 'Critical' || f.severity === 'High').map((f: any) => f.finding || f.title)
    },
    critical_findings: allFindings.filter((f: any) => f.severity === 'Critical' || f.severity === 'High'),
    vulnerability_assessment: allFindings,
    risk_analysis: {
      high_risk_items: allFindings.filter((f: any) => f.severity === 'High').map((f: any) => f.finding || f.title),
      medium_risk_items: allFindings.filter((f: any) => f.severity === 'Medium').map((f: any) => f.finding || f.title),
      low_risk_items: allFindings.filter((f: any) => f.severity === 'Low').map((f: any) => f.finding || f.title),
      risk_factors: [...new Set(allRiskFactors)] // Remove duplicates
    },
    recommendations: allRecommendations.slice(0, 10), // Limit to top 10 recommendations
    security_score: {
      score: averageScore,
      justification: `Aggregated score from ${validScores} chunk analyses. Score reflects overall security posture across all file types.`,
      factors: [
        `Analyzed ${chunkAIResults.length} file type categories`,
        `Found ${allFindings.length} total security issues`,
        `Chunked processing for better accuracy`
      ]
    }
  };
}

// Security-specific helper functions
export async function analyzeRepositorySecurity(
  serverUrl: string,
  apiKey: string,
  profile: string,
  owner: string,
  repo: string,
  analysisType: 'secrets' | 'vulnerabilities' | 'dependencies' | 'code-patterns' = 'secrets'
): Promise<any> {
  const client = new GitHubSecurityClient(serverUrl, apiKey, profile);
  
  try {
    await client.connect();
    
    // Use targeted data collection instead of broad searches
    console.log(`🎯 Starting targeted security analysis for ${owner}/${repo} (${analysisType})...`);
    const targetedData = await collectTargetedSecurityData(client, owner, repo, analysisType);
    
    await client.disconnect();
    
    // Perform AI-powered security analysis using chunked processing
    console.log(`🤖 Performing chunked AI security analysis for ${owner}/${repo}...`);
    const aiAnalysis = await analyzeSecurityWithAIChunked(targetedData, analysisType, `${owner}/${repo}`);
    
    // Combine targeted data with AI analysis
    const enhancedResults = {
      ...targetedData,
      ai_analysis: aiAnalysis
    };
    
    console.log(`✅ Targeted security analysis completed for ${owner}/${repo}`);
    return enhancedResults;
  } catch (error) {
    console.error('Error analyzing repository security:', error);
    throw error;
  }
}

export async function scanMultipleRepositories(
  serverUrl: string,
  apiKey: string,
  profile: string,
  repositories: string[],
  scanTypes: string[] = ['secrets', 'vulnerabilities']
): Promise<any> {
  const results = [];
  
  for (const repo of repositories) {
    const [owner, repoName] = repo.split('/');
    try {
      const result = await analyzeRepositorySecurity(serverUrl, apiKey, profile, owner, repoName);
      results.push({
        repository: repo,
        status: 'success',
        data: result
      });
    } catch (error) {
      results.push({
        repository: repo,
        status: 'error',
        error: error instanceof Error ? error.message : 'Unknown error'
      });
    }
  }
  
  return {
    total_repos_scanned: repositories.length,
    successful_scans: results.filter(r => r.status === 'success').length,
    failed_scans: results.filter(r => r.status === 'error').length,
    results
  };
} 