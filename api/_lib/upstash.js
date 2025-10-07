import { Redis } from "@upstash/redis";

// This check ensures that the app crashes hard during boot if the environment variables are not set.
if (!process.env.UPSTASH_REDIS_REST_URL || !process.env.UPSTASH_REDIS_REST_TOKEN) {
  throw new Error("FATAL: Upstash Redis credentials are not configured in environment variables.");
}

const redis = new Redis({
  url: process.env.UPSTASH_REDIS_REST_URL,
  token: process.env.UPSTASH_REDIS_REST_TOKEN,
});

export default redis;