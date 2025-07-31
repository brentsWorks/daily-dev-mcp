import { z } from "zod";
import { Logger } from "../utils/logger";

const logger = new Logger("Config:Env");

// Schema for environment variables
const envSchema = z.object({
  NODE_ENV: z.string(),
  REDIS_URL: z.string(),
  SMITHERY_GITHUB_API_KEY: z.string(),
  GOOGLE_API_KEY: z.string(),
});

// Function to validate environment variables
const validateEnv = () => {
  try {
    logger.info("Validating environment variables");
    const env = {
      NODE_ENV: process.env.NODE_ENV,
      REDIS_URL: process.env.REDIS_URL,
      SMITHERY_GITHUB_API_KEY: process.env.SMITHERY_GITHUB_API_KEY,
      GOOGLE_API_KEY: process.env.GOOGLE_API_KEY,
    };
    const parsed = envSchema.parse(env);
    logger.info("Environment variables validated successfully");
    return parsed;
  } catch (error) {
    if (error instanceof z.ZodError) {
      const missingVars = error.errors.map(err => err.path.join("."));
      logger.error("Invalid environment variables", { error: { missingVars } });
      throw new Error(
        `❌ Invalid environment variables: ${missingVars.join(
          ", "
        )}. Please check your .env file`
      );
    }
    throw error;
  }
};

export const env = validateEnv();
