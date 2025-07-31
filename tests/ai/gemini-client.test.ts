import { OpenAI } from "openai";

export class GeminiClientTest {
  private client: OpenAI;

  constructor(apiKey: string) {
    this.client = new OpenAI({ 
      apiKey,
      baseURL: "https://generativelanguage.googleapis.com/v1beta/openai/"
    });
  }

  async testSecurityAnalysis(githubData: any, repository: string): Promise<any> {
    console.log("🤖 Testing Gemini security analysis...");
    
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
GitHub Data: ${JSON.stringify(githubData, null, 2)}

IMPORTANT: Respond with ONLY valid JSON format. Do not include any markdown formatting, headers, or explanatory text.

Return a JSON object with the following structure:
{
  "executive_summary": {
    "overall_risk": "Low|Medium|High",
    "security_posture": "string describing overall security state",
    "key_concerns": ["array of main security concerns"]
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
    "high_risk_items": ["array of high risk items"],
    "medium_risk_items": ["array of medium risk items"],
    "low_risk_items": ["array of low risk items"],
    "risk_factors": ["array of contributing risk factors"]
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
    "score": 7,
    "justification": "string explaining the score",
    "factors": ["array of factors contributing to the score"]
  }
}`;

    try {
      const response = await this.client.chat.completions.create({
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
      const aiAnalysis = JSON.parse(aiResponse);
      
      console.log("✅ Gemini security analysis completed successfully");
      return aiAnalysis;
    } catch (error) {
      console.error("❌ Gemini security analysis failed:", error);
      throw error;
    }
  }

  async testSimpleQuery(prompt: string): Promise<any> {
    console.log("🤖 Testing simple Gemini query...");
    
    try {
      const response = await this.client.chat.completions.create({
        model: "gemini-2.0-flash",
        messages: [
          {
            role: "user",
            content: prompt
          }
        ],
        temperature: 0.1,
        max_tokens: 500
      });

      const result = response.choices[0]?.message?.content || "No response";
      console.log("✅ Simple query completed successfully");
      return result;
    } catch (error) {
      console.error("❌ Simple query failed:", error);
      throw error;
    }
  }
}

// Test runner
async function runGeminiTests() {
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
    
    console.log("✅ All Gemini tests completed successfully!");
    
  } catch (error) {
    console.error("❌ Gemini tests failed:", error);
  }
}

// Run tests if this file is executed directly
if (require.main === module) {
  runGeminiTests();
} 