// Generates platform-specific content from the market analysis using Claude.
//
// Each platform is its own function so you can tune one prompt without touching
// the others. To add a platform: write a generator here, register it in
// GENERATORS, and add a writer in outputHandler.js.
//
// House rules (from the spec):
//   - Authentic market analysis, NOT promotional.
//   - Do not mention or promote Qosmo (engagement-first strategy).
//   - Reddit posts never mention products at all.
//   - Max ~1500 tokens per piece; every call falls back gracefully on error.
import Anthropic from '@anthropic-ai/sdk';
import { logger } from './logger.js';

const SYSTEM_PROMPT = [
  'You are a sharp, credible sports card and TCG market analyst.',
  'You write authentic, data-driven market insight — never hype, never promotional.',
  'You never mention or promote any product, app, brand, or service (including "Qosmo").',
  'Ground every claim in the specific cards and numbers provided. Be concrete.',
  'Write like a knowledgeable collector talking to peers, not a marketer.',
].join(' ');

function pct(n) {
  return `${n > 0 ? '+' : ''}${n}%`;
}

// Compact, model-friendly snapshot of the market for the prompt body.
function marketBrief(analysis, alerts) {
  const line = (c) => `- ${c.name} [${c.game}/${c.grade}] $${c.price} (24h ${pct(c.priceChange24h)}, 7d ${pct(c.priceChange7d)}, 30d ${pct(c.priceChange30d)}, vol ${c.volume})`;
  return [
    `Market snapshot (${analysis.generatedAt}):`,
    `Tracked cards: ${analysis.totalCards} across ${analysis.games.join(', ')}.`,
    `Avg 24h move: ${pct(analysis.stats.avgChange24h)}, avg 7d: ${pct(analysis.stats.avgChange7d)}, total 24h volume: ${analysis.stats.totalVolume}.`,
    '',
    'Top gainers (24h):',
    ...analysis.topGainers.map(line),
    '',
    'Top losers (24h):',
    ...analysis.topLosers.map(line),
    '',
    'Volume leaders:',
    ...analysis.volumeLeaders.map(line),
    '',
    alerts.length ? `Alerts: ${alerts.map((a) => a.message).join(' ')}` : 'Alerts: none.',
  ].join('\n');
}

export function createClient(config) {
  if (!config.anthropicApiKey) {
    throw new Error('ANTHROPIC_API_KEY is required for content generation.');
  }
  return new Anthropic({ apiKey: config.anthropicApiKey });
}

// Single point of contact with the API. Returns plain text or throws.
async function callClaude(client, config, userPrompt) {
  const response = await client.messages.create({
    model: config.anthropicModel,
    max_tokens: config.maxTokens,
    system: SYSTEM_PROMPT,
    messages: [{ role: 'user', content: userPrompt }],
  });
  return response.content
    .filter((block) => block.type === 'text')
    .map((block) => block.text)
    .join('\n')
    .trim();
}

const PROMPTS = {
  reddit: (brief) =>
    `${brief}\n\nWrite ONE Reddit post for a sports card / TCG community. It must be a genuine discussion starter built around the data above — an observation or question, not an announcement. Absolutely no product mentions of any kind. Return a title line prefixed with "Title:" then the post body.`,
  twitter: (brief) =>
    `${brief}\n\nWrite a Twitter/X thread (4-7 tweets) of market analysis built on the data above. Number each tweet (1/, 2/, ...). Lead with the most interesting move. Keep each tweet under 280 characters. No hashtags spam, no promotion.`,
  tiktok: (brief) =>
    `${brief}\n\nWrite a 30-45 second TikTok script about the most interesting move in the data. Include a strong 3-second hook, 2-3 punchy talking points, and a closing line. Mark sections as [HOOK], [BODY], [CLOSE]. Conversational, no promotion.`,
  instagram: (brief) =>
    `${brief}\n\nWrite THREE distinct Instagram caption variations about today's market, each 2-4 short paragraphs with tasteful line breaks and a few relevant emoji. Label them "Variation 1:", "Variation 2:", "Variation 3:". Insightful, not salesy, no product mentions.`,
  email: (brief) =>
    `${brief}\n\nWrite a market newsletter email. Start with a subject line prefixed "Subject:". Then a short intro, a "What moved" section covering the top gainers/losers with brief reasoning, a "Watching" section on the volume/anomaly signals, and a one-line sign-off. Informative and credible.`,
  'market-analysis': (brief) =>
    `${brief}\n\nWrite a detailed market analysis report (markdown). Include: an executive summary, a movers breakdown with plausible drivers, a volume & liquidity read, 1-2 specific opportunities with the reasoning and the risk, and a short outlook. Analytical and specific.`,
};

const GENERATORS = Object.fromEntries(
  Object.keys(PROMPTS).map((platform) => [
    platform,
    async (client, config, brief) => callClaude(client, config, PROMPTS[platform](brief)),
  ]),
);

// Generates content for every requested platform. Each platform is isolated:
// a failure on one is logged and recorded as an error entry rather than
// aborting the whole batch.
export async function generateAll(analysis, alerts, config) {
  const client = createClient(config);
  const brief = marketBrief(analysis, alerts);
  const content = {};

  for (const platform of config.platforms) {
    const generate = GENERATORS[platform];
    if (!generate) {
      logger.warn(`No generator for platform "${platform}" — skipping.`);
      continue;
    }
    try {
      logger.info(`Generating ${platform} content...`);
      const text = await generate(client, config, brief);
      content[platform] = { platform, text, generatedAt: new Date().toISOString() };
      logger.success(`Generated ${platform} content (${text.length} chars)`);
    } catch (error) {
      logger.error(`Failed to generate ${platform} content: ${error.message}`);
      content[platform] = { platform, error: error.message, generatedAt: new Date().toISOString() };
    }
  }

  return content;
}
