import { GitHubClientTest } from "./github/github-client.test";
import { GeminiClientTest } from "./ai/gemini-client.test";
import { SecurityAnalysisIntegrationTest } from "./integration/security-analysis.test";

async function runGitHubTests() {
  console.log("\n" + "=".repeat(60));
  console.log("🔗 RUNNING GITHUB TESTS");
  console.log("=".repeat(60));
  
  const test = new GitHubClientTest();
  
  try {
    await test.connect();
    
    // Test repository access
    const repoDetails = await test.testRepositoryAccess("brentsWorks", "aven-ai-support");
    console.log("📊 Repository Details:", JSON.stringify(repoDetails, null, 2).substring(0, 500) + "...");
    
    // Test code search
    const codeResults = await test.testCodeSearch("brentsWorks", "aven-ai-support", "API_KEY");
    console.log("🔍 Code Search Results:", JSON.stringify(codeResults, null, 2).substring(0, 500) + "...");
    
    // Test issue search
    const issueResults = await test.testIssueSearch("brentsWorks", "aven-ai-support", "security");
    console.log("📝 Issue Search Results:", JSON.stringify(issueResults, null, 2).substring(0, 500) + "...");
    
    console.log("✅ GitHub tests completed successfully!");
    
  } catch (error) {
    console.error("❌ GitHub tests failed:", error);
  } finally {
    await test.disconnect();
  }
}

async function runGeminiTests() {
  console.log("\n" + "=".repeat(60));
  console.log("🤖 RUNNING GEMINI TESTS");
  console.log("=".repeat(60));
  
  const apiKey = process.env.GOOGLE_API_KEY || "your-google-api-key-here";
  
  if (apiKey === "your-google-api-key-here") {
    console.log("⚠️  Please set GOOGLE_API_KEY environment variable");
    return;
  }
  
  const test = new GeminiClientTest(apiKey);
  
  try {
    // Test simple query
    const simpleResult = await test.testSimpleQuery("What is 2 + 2?");
    console.log("🧮 Simple Query Result:", simpleResult);
    
    // Test security analysis with mock data
    const mockGitHubData = {
      repository: "test/repo",
      analysis_type: "dependencies",
      scan_date: new Date().toISOString(),
      findings: [
        {
          type: "REPOSITORY_DETAILS",
          data: { name: "test-repo", language: "JavaScript" },
          description: "Mock repository information"
        }
      ]
    };
    
    const securityResult = await test.testSecurityAnalysis(mockGitHubData, "test/repo");
    console.log("🛡️ Security Analysis Result:", JSON.stringify(securityResult, null, 2));
    
    console.log("✅ Gemini tests completed successfully!");
    
  } catch (error) {
    console.error("❌ Gemini tests failed:", error);
  }
}

async function runIntegrationTests() {
  console.log("\n" + "=".repeat(60));
  console.log("🛡️ RUNNING INTEGRATION TESTS");
  console.log("=".repeat(60));
  
  const geminiApiKey = process.env.GOOGLE_API_KEY || "your-google-api-key-here";
  
  if (geminiApiKey === "your-google-api-key-here") {
    console.log("⚠️  Please set GOOGLE_API_KEY environment variable");
    return;
  }
  
  const test = new SecurityAnalysisIntegrationTest(geminiApiKey);
  
  try {
    // Run quick analysis
    const quickResults = await test.runQuickAnalysis("brentsWorks", "aven-ai-support");
    
    console.log("\n📊 Quick Analysis Results:");
    console.log("Repository:", quickResults.repository);
    console.log("Analysis Type:", quickResults.summary.analysis_type);
    console.log("AI Model:", quickResults.summary.ai_model_used);
    
    console.log("\n🤖 AI Security Analysis:");
    console.log(JSON.stringify(quickResults.ai_analysis, null, 2));
    
    console.log("✅ Integration tests completed successfully!");
    
  } catch (error) {
    console.error("❌ Integration tests failed:", error);
  }
}

async function runAllTests() {
  console.log("🚀 STARTING ALL TESTS");
  console.log("=".repeat(60));
  
  await runGitHubTests();
  await runGeminiTests();
  await runIntegrationTests();
  
  console.log("\n" + "=".repeat(60));
  console.log("🎉 ALL TESTS COMPLETED");
  console.log("=".repeat(60));
}

// Main function
async function main() {
  const testType = process.argv[2] || "all";
  
  switch (testType) {
    case "github":
      await runGitHubTests();
      break;
    case "gemini":
      await runGeminiTests();
      break;
    case "integration":
      await runIntegrationTests();
      break;
    case "all":
    default:
      await runAllTests();
      break;
  }
}

// Run if this file is executed directly
if (require.main === module) {
  main().catch(console.error);
} 