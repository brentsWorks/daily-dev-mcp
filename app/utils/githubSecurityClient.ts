import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import { createSmitheryUrl } from "@smithery/sdk";
import { OpenAI } from "openai";
import { env } from "../config/env";

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
    
    const results: {
      repository: string;
      analysis_type: string;
      scan_date: string;
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
      findings: []
    };

    // Perform security analysis based on type
    switch (analysisType) {
      case 'secrets':
        // Search for potential secrets in code
        try {
          const secretSearch = await client.callTool("search_code", {
            q: `repo:${owner}/${repo} API_KEY password secret token credential`,
            per_page: 10
          });
          results.findings.push({
            type: "SECRET_SEARCH",
            data: secretSearch,
            description: "Code search for potential secrets"
          });
        } catch (error) {
          results.findings.push({
            type: "SECRET_SEARCH_ERROR",
            error: error instanceof Error ? error.message : 'Unknown error'
          });
        }
        break;

      case 'vulnerabilities':
        // Search for security-related issues
        try {
          const securityIssues = await client.callTool("search_issues", {
            q: `repo:${owner}/${repo} security vulnerability CVE`,
            per_page: 10
          });
          results.findings.push({
            type: "SECURITY_ISSUES",
            data: securityIssues,
            description: "Security-related issues"
          });
        } catch (error) {
          results.findings.push({
            type: "SECURITY_ISSUES_ERROR",
            error: error instanceof Error ? error.message : 'Unknown error'
          });
        }
        break;

      case 'dependencies':
        // Get repository details to analyze dependencies
        try {
          const repoDetails = await client.callTool("get_repository", { owner, repo });
          results.findings.push({
            type: "REPOSITORY_DETAILS",
            data: repoDetails,
            description: "Repository information for dependency analysis"
          });
        } catch (error) {
          results.findings.push({
            type: "REPOSITORY_DETAILS_ERROR",
            error: error instanceof Error ? error.message : 'Unknown error'
          });
        }
        break;

      case 'code-patterns':
        // Search for common security code patterns
        try {
          const codePatterns = await client.callTool("search_code", {
            q: `repo:${owner}/${repo} SQL injection eval exec dangerous`,
            per_page: 10
          });
          results.findings.push({
            type: "CODE_PATTERNS",
            data: codePatterns,
            description: "Potentially dangerous code patterns"
          });
        } catch (error) {
          results.findings.push({
            type: "CODE_PATTERNS_ERROR",
            error: error instanceof Error ? error.message : 'Unknown error'
          });
        }
        break;
    }

    await client.disconnect();
    
    // Perform AI-powered security analysis on the collected data
    console.log(`🤖 Performing AI security analysis for ${owner}/${repo}...`);
    const aiAnalysis = await analyzeSecurityWithAI(results, analysisType, `${owner}/${repo}`);
    
    // Combine GitHub data with AI analysis
    const enhancedResults = {
      ...results,
      ai_analysis: aiAnalysis
    };
    
    console.log(`✅ AI security analysis completed for ${owner}/${repo}`);
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