import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import { createSmitheryUrl } from "@smithery/sdk";

async function exploreGitHubTools() {
  try {
    console.log("🔍 Exploring Smithery.ai GitHub MCP Server Tools...");
    
    const serverUrl = "https://server.smithery.ai/@smithery-ai/github";
    const apiKey = "9c337e32-7f6f-475c-9855-965117c459cc";
    const profile = "radical-hawk-AyMmPj";
    
    const smitheryUrl = createSmitheryUrl(serverUrl, { apiKey, profile });
    const transport = new StreamableHTTPClientTransport(smitheryUrl);
    const client = new Client({
      name: "github-explorer",
      version: "1.0.0"
    });

    await client.connect(transport);
    console.log("✅ Connected to Smithery.ai GitHub MCP server");

    // List all available tools
    const tools = await client.listTools();
    console.log("\n📋 Available GitHub Tools:");
    tools.tools.forEach((tool, index) => {
      console.log(`${index + 1}. ${tool.name}`);
      if (tool.description) {
        console.log(`   Description: ${tool.description}`);
      }
      if (tool.inputSchema && tool.inputSchema.properties) {
        console.log(`   Parameters: ${Object.keys(tool.inputSchema.properties).join(', ')}`);
      }
      console.log('');
    });

    // Test a few specific tools
    console.log("🧪 Testing specific GitHub tools...\n");

    // Test search_repositories
    console.log("1. Testing search_repositories...");
    try {
      const searchResult = await client.callTool({
        name: "search_repositories",
        arguments: {
          query: "security vulnerability",
          per_page: 3
        }
      });
      console.log("Search result:", JSON.stringify(searchResult, null, 2).substring(0, 500) + "...");
    } catch (error) {
      console.log("❌ Search repositories error:", error.message);
    }

    // Test search_code
    console.log("\n2. Testing search_code...");
    try {
      const codeResult = await client.callTool({
        name: "search_code",
        arguments: {
          q: "API_KEY password secret",
          per_page: 2
        }
      });
      console.log("Code search result:", JSON.stringify(codeResult, null, 2).substring(0, 500) + "...");
    } catch (error) {
      console.log("❌ Code search error:", error.message);
    }

    // Test list_issues
    console.log("\n3. Testing list_issues...");
    try {
      const issuesResult = await client.callTool({
        name: "list_issues",
        arguments: {
          owner: "octocat",
          repo: "Hello-World",
          state: "open",
          per_page: 2
        }
      });
      console.log("Issues result:", JSON.stringify(issuesResult, null, 2).substring(0, 500) + "...");
    } catch (error) {
      console.log("❌ List issues error:", error.message);
    }

    client.close();
    console.log("\n✅ GitHub tools exploration completed!");

  } catch (error) {
    console.error("❌ Error:", error.message);
  }
}

exploreGitHubTools(); 