import { GitHubClientTest } from "../github/github-client.test";
import { GeminiClientTest } from "../ai/gemini-client.test";

export class SecurityAnalysisIntegrationTest {
  private githubTest: GitHubClientTest;
  private geminiTest: GeminiClientTest;

  constructor(geminiApiKey: string) {
    this.githubTest = new GitHubClientTest();
    this.geminiTest = new GeminiClientTest(geminiApiKey);
  }

  async runFullSecurityAnalysis(owner: string, repo: string): Promise<any> {
    console.log(`🛡️ Running full security analysis for ${owner}/${repo}...`);
    
    try {
      // Step 1: Connect to GitHub and collect data
      await this.githubTest.connect();
      
      const githubData: {
        repository: string;
        analysis_type: string;
        scan_date: string;
        findings: Array<{
          type: string;
          data: any;
          description: string;
        }>;
      } = {
        repository: `${owner}/${repo}`,
        analysis_type: "comprehensive",
        scan_date: new Date().toISOString(),
        findings: []
      };

      // Collect repository details
      console.log("📋 Collecting repository details...");
      const repoDetails = await this.githubTest.testRepositoryAccess(owner, repo);
      githubData.findings.push({
        type: "REPOSITORY_DETAILS",
        data: repoDetails,
        description: "Repository information"
      });

      // Collect code search results
      console.log("🔍 Collecting code search results...");
      const codeResults = await this.githubTest.testCodeSearch(owner, repo, "API_KEY password secret");
      githubData.findings.push({
        type: "CODE_SEARCH",
        data: codeResults,
        description: "Code search for potential secrets"
      });

      // Collect issue search results
      console.log("📝 Collecting issue search results...");
      const issueResults = await this.githubTest.testIssueSearch(owner, repo, "security vulnerability");
      githubData.findings.push({
        type: "ISSUE_SEARCH",
        data: issueResults,
        description: "Security-related issues"
      });

      // Step 2: Perform AI security analysis
      console.log("🤖 Performing AI security analysis...");
      const aiAnalysis = await this.geminiTest.testSecurityAnalysis(githubData, `${owner}/${repo}`);

      // Step 3: Compile results
      const results = {
        repository: `${owner}/${repo}`,
        scan_date: new Date().toISOString(),
        github_data: githubData,
        ai_analysis: aiAnalysis,
        summary: {
          total_findings: githubData.findings.length,
          ai_model_used: "gemini-2.0-flash",
          analysis_complete: true
        }
      };

      console.log("✅ Full security analysis completed successfully!");
      return results;

    } catch (error) {
      console.error("❌ Security analysis failed:", error);
      throw error;
    } finally {
      await this.githubTest.disconnect();
    }
  }

  async runQuickAnalysis(owner: string, repo: string): Promise<any> {
    console.log(`⚡ Running quick security analysis for ${owner}/${repo}...`);
    
    try {
      await this.githubTest.connect();
      
      // Just get repository details for quick analysis
      const repoDetails = await this.githubTest.testRepositoryAccess(owner, repo);
      
      const githubData = {
        repository: `${owner}/${repo}`,
        analysis_type: "quick",
        scan_date: new Date().toISOString(),
        findings: [
          {
            type: "REPOSITORY_DETAILS",
            data: repoDetails,
            description: "Repository information"
          }
        ]
      };

      const aiAnalysis = await this.geminiTest.testSecurityAnalysis(githubData, `${owner}/${repo}`);
      
      return {
        repository: `${owner}/${repo}`,
        scan_date: new Date().toISOString(),
        github_data: githubData,
        ai_analysis: aiAnalysis,
        summary: {
          analysis_type: "quick",
          ai_model_used: "gemini-2.0-flash",
          analysis_complete: true
        }
      };

    } catch (error) {
      console.error("❌ Quick analysis failed:", error);
      throw error;
    } finally {
      await this.githubTest.disconnect();
    }
  }
}

// Test runner
async function runIntegrationTests() {
  const geminiApiKey = process.env.GOOGLE_API_KEY || "your-google-api-key-here";
  
  if (geminiApiKey === "your-google-api-key-here") {
    console.log("⚠️  Please set GOOGLE_API_KEY environment variable");
    return;
  }
  
  const test = new SecurityAnalysisIntegrationTest(geminiApiKey);
  
  try {
    // Run quick analysis
    console.log("\n" + "=".repeat(60));
    console.log("🚀 RUNNING QUICK SECURITY ANALYSIS");
    console.log("=".repeat(60));
    
    const quickResults = await test.runQuickAnalysis("brentsWorks", "aven-ai-support");
    
    console.log("\n📊 Quick Analysis Results:");
    console.log("Repository:", quickResults.repository);
    console.log("Analysis Type:", quickResults.summary.analysis_type);
    console.log("AI Model:", quickResults.summary.ai_model_used);
    
    console.log("\n🤖 AI Security Analysis:");
    console.log(JSON.stringify(quickResults.ai_analysis, null, 2));
    
    console.log("\n✅ Integration tests completed successfully!");
    
  } catch (error) {
    console.error("❌ Integration tests failed:", error);
  }
}

// Run tests if this file is executed directly
if (require.main === module) {
  runIntegrationTests();
} 