import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import { createSmitheryUrl } from "@smithery/sdk";

// Load environment variables from .env file manually
import { readFileSync } from 'fs';
import { join } from 'path';

// Simple .env loader
function loadEnv() {
  try {
    const envPath = join(process.cwd(), '.env');
    console.log("📁 Loading .env file from:", envPath);
    const envContent = readFileSync(envPath, 'utf8');
    const envVars = envContent.split('\n').reduce((acc: any, line) => {
      const [key, ...valueParts] = line.split('=');
      if (key && valueParts.length > 0) {
        let value = valueParts.join('=').trim();
        // Remove quotes if present
        if ((value.startsWith('"') && value.endsWith('"')) || 
            (value.startsWith("'") && value.endsWith("'"))) {
          value = value.slice(1, -1);
        }
        acc[key.trim()] = value;
      }
      return acc;
    }, {});
    
    console.log("🔑 Found environment variables:", Object.keys(envVars));
    
    // Set environment variables
    Object.entries(envVars).forEach(([key, value]) => {
      if (!process.env[key]) {
        process.env[key] = value as string;
        console.log(`✅ Set ${key} = ${(value as string).substring(0, 10)}...`);
      }
    });
  } catch (error) {
    console.log("⚠️  Could not load .env file, using existing environment variables");
    console.log("Error:", error);
  }
}

loadEnv();

export class GitHubClientTest {
  private client: Client | null = null;
  private transport: StreamableHTTPClientTransport | null = null;

  async connect(): Promise<void> {
    try {
      const serverUrl = "https://server.smithery.ai/@smithery-ai/github";
      const apiKey = process.env.SMITHERY_GITHUB_API_KEY || "9c337e32-7f6f-475c-9855-965117c459cc";
      const profile = "radical-hawk-AyMmPj";
      
      console.log("🔗 Connecting to GitHub MCP server...");
      
      const smitheryUrl = createSmitheryUrl(serverUrl, { apiKey, profile });
      this.transport = new StreamableHTTPClientTransport(smitheryUrl);
      
      this.client = new Client({
        name: "github-client-test",
        version: "1.0.0"
      });

      await this.client.connect(this.transport);
      console.log("✅ Connected to Smithery.ai GitHub MCP server");
    } catch (error) {
      console.error("❌ Failed to connect to GitHub MCP server:", error);
      throw error;
    }
  }

  async disconnect(): Promise<void> {
    if (this.client) {
      this.client.close();
      this.client = null;
      this.transport = null;
      console.log("🔌 Disconnected from GitHub MCP server");
    }
  }

  async testRepositoryAccess(owner: string, repo: string): Promise<any> {
    if (!this.client) {
      throw new Error("Client not connected. Call connect() first.");
    }

    console.log(`📋 Testing repository access: ${owner}/${repo}`);
    
    const repoDetails = await this.client.callTool({
      name: "get_repository",
      arguments: { owner, repo }
    });

    console.log("✅ Repository details retrieved successfully");
    return repoDetails;
  }

  async testCodeSearch(owner: string, repo: string, query: string): Promise<any> {
    if (!this.client) {
      throw new Error("Client not connected. Call connect() first.");
    }

    console.log(`🔍 Testing code search: ${owner}/${repo} - "${query}"`);
    
    const searchResults = await this.client.callTool({
      name: "search_code",
      arguments: {
        q: `repo:${owner}/${repo} ${query}`,
        per_page: 5
      }
    });

    console.log("✅ Code search completed successfully");
    return searchResults;
  }

  async testIssueSearch(owner: string, repo: string, query: string): Promise<any> {
    if (!this.client) {
      throw new Error("Client not connected. Call connect() first.");
    }

    console.log(`📝 Testing issue search: ${owner}/${repo} - "${query}"`);
    
    const searchResults = await this.client.callTool({
      name: "search_issues",
      arguments: {
        q: `repo:${owner}/${repo} ${query}`,
        per_page: 5
      }
    });

    console.log("✅ Issue search completed successfully");
    return searchResults;
  }
}

// Test runner
async function runGitHubTests() {
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
    
    console.log("✅ All GitHub tests completed successfully!");
    
  } catch (error) {
    console.error("❌ GitHub tests failed:", error);
  } finally {
    await test.disconnect();
  }
}

// Run tests if this file is executed directly
if (require.main === module) {
  runGitHubTests();
} 