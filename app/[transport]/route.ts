import { createMcpHandler } from "@vercel/mcp-adapter";
import { z } from "zod";
import { env } from "../config/env";
import { analyzeRepositorySecurity, scanMultipleRepositories } from "../utils/githubSecurityClient";

const handler = createMcpHandler(
  async (server) => {
    // GitHub Security Analysis Tool
    server.tool(
      "analyze-github-security",
      "Analyze GitHub repositories for potential security vulnerabilities",
      {
        owner: z.string(),
        repo: z.string(),
        analysisType: z.enum(["secrets", "vulnerabilities", "dependencies", "code-patterns"]).optional(),
        timeframe: z.enum(["day", "week", "month", "all"]).optional(),
      },
      async ({ owner, repo, analysisType = "secrets", timeframe = "week" }) => {
        try {
          // Use real GitHub MCP server
          const serverUrl = "https://server.smithery.ai/@smithery-ai/github";
          const apiKey = env.SMITHERY_GITHUB_API_KEY;
          const profile = "radical-hawk-AyMmPj";
          
          const result = await analyzeRepositorySecurity(
            serverUrl,
            apiKey,
            profile,
            owner,
            repo,
            analysisType
          );
          
          return {
            content: [{ 
              type: "text", 
              text: JSON.stringify(result, null, 2)
            }],
          };
        } catch (error) {
          return {
            content: [{ 
              type: "text", 
              text: `❌ Error analyzing ${owner}/${repo}: ${error instanceof Error ? error.message : 'Unknown error'}\n\n💡 Note: This may be due to authentication or repository access issues.` 
            }],
          };
        }
      }
    );

    // GitHub Repository Scanner Tool
    server.tool(
      "scan-github-repos",
      "Scan multiple GitHub repositories for security issues",
      {
        organizations: z.array(z.string()).optional(),
        repositories: z.array(z.string()).optional(),
        scanTypes: z.array(z.enum(["secrets", "vulnerabilities", "dependencies", "code-patterns"])).optional(),
      },
      async ({ organizations = [], repositories = [], scanTypes = ["secrets", "vulnerabilities"] }) => {
        try {
          // Use real GitHub MCP server
          const serverUrl = "https://server.smithery.ai/@smithery-ai/github";
          const apiKey = env.SMITHERY_GITHUB_API_KEY;
          const profile = "radical-hawk-AyMmPj";
          
          // Scan the provided repositories
          // TODO: Add organization scanning when we understand the available tools
          const reposToScan = repositories.length > 0 ? repositories : [];
          
          if (reposToScan.length === 0) {
            return {
              content: [{ 
                type: "text", 
                text: JSON.stringify({
                  error: "No repositories provided for scanning",
                  message: "Please provide a list of repositories to scan",
                  example: ["owner/repo1", "owner/repo2"]
                }, null, 2)
              }],
            };
          }
          
          const result = await scanMultipleRepositories(
            serverUrl,
            apiKey,
            profile,
            reposToScan,
            scanTypes
          );
          
          return {
            content: [{ 
              type: "text", 
              text: JSON.stringify(result, null, 2)
            }],
          };
        } catch (error) {
          return {
            content: [{ 
              type: "text", 
              text: `❌ Error scanning repositories: ${error instanceof Error ? error.message : 'Unknown error'}\n\n💡 Note: This may be due to authentication or repository access issues.` 
            }],
          };
        }
      }
    );

    // Security Report Generator Tool
    server.tool(
      "generate-security-report",
      "Generate a comprehensive security report for GitHub repositories",
      {
        owner: z.string(),
        repo: z.string(),
        reportFormat: z.enum(["markdown", "json", "html"]).optional(),
        includeRecommendations: z.boolean().optional(),
      },
      async ({ owner, repo, reportFormat = "markdown", includeRecommendations = true }) => {
        try {
          // Use real GitHub MCP server and AI analysis
          const serverUrl = "https://server.smithery.ai/@smithery-ai/github";
          const apiKey = env.SMITHERY_GITHUB_API_KEY;
          const profile = "radical-hawk-AyMmPj";
          
          // Perform comprehensive security analysis
          const result = await analyzeRepositorySecurity(
            serverUrl,
            apiKey,
            profile,
            owner,
            repo,
            "dependencies" // Get comprehensive data for report
          );
          
          // Extract AI analysis for report generation
          const aiAnalysis = result.ai_analysis?.ai_analysis || {};
          
          // Generate real report based on actual findings
          const realReport = {
            repository: `${owner}/${repo}`,
            scan_date: result.scan_date,
            summary: {
              total_issues: aiAnalysis.critical_findings?.length || 0,
              critical: aiAnalysis.critical_findings?.filter((f: any) => f.severity === "Critical").length || 0,
              high: aiAnalysis.critical_findings?.filter((f: any) => f.severity === "High").length || 0,
              medium: aiAnalysis.critical_findings?.filter((f: any) => f.severity === "Medium").length || 0,
              low: aiAnalysis.critical_findings?.filter((f: any) => f.severity === "Low").length || 0,
              security_score: aiAnalysis.security_score?.score || 0,
              overall_risk: aiAnalysis.executive_summary?.overall_risk || null
            },
            findings: aiAnalysis.critical_findings?.map((finding: any, index: number) => ({
              id: `SEC-${String(index + 1).padStart(3, '0')}`,
              type: finding.type || null,
              severity: finding.severity || null,
              title: finding.finding || null,
              description: finding.impact || finding.description || null,
              location: finding.location || null,
              recommendation: finding.recommendation || null
            })).filter((finding: any) =>  
              finding.type && finding.severity && finding.title && finding.description
            ) || [],
            recommendations: includeRecommendations ? 
              (aiAnalysis.recommendations?.map((rec: any) => rec.recommendation) || []) : [],
            ai_analysis: aiAnalysis,
            github_data: result.findings
          };
          
          let reportContent = "";
          if (reportFormat === "markdown") {
            reportContent = `# Security Report: ${owner}/${repo}

## Executive Summary
- **Repository**: ${realReport.repository}
- **Scan Date**: ${realReport.scan_date}
- **Overall Risk**: ${realReport.summary.overall_risk}
- **Security Score**: ${realReport.summary.security_score}/10
- **Total Issues**: ${realReport.summary.total_issues}
- **Critical**: ${realReport.summary.critical}
- **High**: ${realReport.summary.high}
- **Medium**: ${realReport.summary.medium}
- **Low**: ${realReport.summary.low}

## AI Analysis Summary
${aiAnalysis.executive_summary?.security_posture || "No security posture analysis available."}

## Findings
${realReport.findings.length > 0 ? 
  realReport.findings.map((f: any) => `### ${f.title} (${f.severity})
- **Type**: ${f.type}
- **Location**: ${f.location}
- **Description**: ${f.description}
- **Recommendation**: ${f.recommendation}
`).join('\n') : 
  "No critical findings identified in this analysis."
}

${includeRecommendations && realReport.recommendations.length > 0 ? `## Recommendations
${realReport.recommendations.map((r: any) => `- ${r}`).join('\n')}` : ''}

## Risk Analysis
- **High Risk Items**: ${aiAnalysis.risk_analysis?.high_risk_items?.join(', ') || 'None identified'}
- **Medium Risk Items**: ${aiAnalysis.risk_analysis?.medium_risk_items?.join(', ') || 'None identified'}
- **Low Risk Items**: ${aiAnalysis.risk_analysis?.low_risk_items?.join(', ') || 'None identified'}

---
*Report generated on ${realReport.scan_date} using real GitHub data and AI-powered security analysis*`;
          } else {
            reportContent = JSON.stringify(realReport, null, 2);
          }
          
          return {
            content: [{ 
              type: "text", 
              text: reportContent
            }],
          };
        } catch (error) {
          return {
            content: [{ 
              type: "text", 
              text: `❌ Error generating security report for ${owner}/${repo}: ${error instanceof Error ? error.message : 'Unknown error'}\n\n💡 Note: This may be due to authentication or repository access issues.` 
            }],
          };
        }
      }
    );
  },
  {
    capabilities: {
      tools: {
        "analyze-github-security": {
          description: "Analyze GitHub repositories for potential security vulnerabilities",
          parameters: z.object({
            owner: z.string(),
            repo: z.string(),
            analysisType: z.enum(["secrets", "vulnerabilities", "dependencies", "code-patterns"]).optional(),
            timeframe: z.enum(["day", "week", "month", "all"]).optional(),
          }),
        },
        "scan-github-repos": {
          description: "Scan multiple GitHub repositories for security issues",
          parameters: z.object({
            organizations: z.array(z.string()).optional(),
            repositories: z.array(z.string()).optional(),
            scanTypes: z.array(z.enum(["secrets", "vulnerabilities", "dependencies", "code-patterns"])).optional(),
          }),
        },
        "generate-security-report": {
          description: "Generate a comprehensive security report for GitHub repositories",
          parameters: z.object({
            owner: z.string(),
            repo: z.string(),
            reportFormat: z.enum(["markdown", "json", "html"]).optional(),
            includeRecommendations: z.boolean().optional(),
          }),
        },
      },
    },
  },
  {
    basePath: "",
    redisUrl: env.REDIS_URL,
    verboseLogs: true,
    maxDuration: 60,
  }
);

export { handler as GET, handler as POST, handler as DELETE };
