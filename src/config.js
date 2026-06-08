// Central configuration. Loads environment variables (via dotenv) and exposes
// a single validated config object used across the engine.
import 'dotenv/config';

function list(value, fallback) {
  if (!value) return fallback;
  return value
    .split(',')
    .map((item) => item.trim().toLowerCase())
    .filter(Boolean);
}

function bool(value, fallback = false) {
  if (value === undefined) return fallback;
  return ['1', 'true', 'yes', 'on'].includes(String(value).toLowerCase());
}

export function getConfig() {
  return {
    // Anthropic
    anthropicApiKey: process.env.ANTHROPIC_API_KEY || '',
    // The spec referenced "claude-opus-4-20250805", which is not a valid model
    // id. We default to the current most-capable Opus and allow an override.
    anthropicModel: process.env.ANTHROPIC_MODEL || 'claude-opus-4-8',
    maxTokens: Number(process.env.MAX_TOKENS || 1500),

    // TCG market data
    tcgApiKey: process.env.TCG_API_KEY || '',
    tcgApiBase: process.env.TCG_API_BASE || 'https://api.tcgapi.dev/v1',

    // What to fetch / what to produce
    cardCategories: list(process.env.CARD_CATEGORIES, ['sports', 'pokemon', 'magic']),
    platforms: list(process.env.PLATFORMS, [
      'reddit',
      'twitter',
      'tiktok',
      'instagram',
      'email',
      'market-analysis',
    ]),

    // Output
    outputDir: process.env.OUTPUT_DIR || './content',

    // Automation
    schedule: process.env.SCHEDULE || '0 8 * * *',

    // Optional extra delivery channel (POSTs the full batch as JSON)
    webhookUrl: process.env.WEBHOOK_URL || '',

    // Force the offline sample dataset instead of calling the TCG API.
    useSampleData: bool(process.env.USE_SAMPLE_DATA, false),
  };
}

// Validates that required secrets are present. Returns a list of problems
// (empty when everything needed is set).
export function validateConfig(config) {
  const problems = [];
  if (!config.anthropicApiKey) {
    problems.push('ANTHROPIC_API_KEY is not set — content generation will fail.');
  }
  if (!config.platforms.length) {
    problems.push('PLATFORMS is empty — nothing to generate.');
  }
  return problems;
}
