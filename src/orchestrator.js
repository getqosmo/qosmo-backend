// Main pipeline: data fetch -> analysis -> alerts -> content generation ->
// output. Coordinates the other modules and is the single function both the
// one-shot entry point (index.js) and the scheduler (scheduler.js) call.
import { getConfig, validateConfig } from './config.js';
import { fetchMarketData, analyzeMarket, generateAlerts } from './dataFetcher.js';
import { generateAll } from './contentGenerator.js';
import { saveOutputs, postToWebhook } from './outputHandler.js';
import { logger } from './logger.js';

export async function run(overrides = {}) {
  const config = { ...getConfig(), ...overrides };

  const problems = validateConfig(config);
  if (problems.length) {
    problems.forEach((p) => logger.error(p));
    throw new Error('Invalid configuration — see errors above.');
  }

  logger.info('=== Qosmo Content Engine: run started ===');
  logger.info(
    `Model: ${config.anthropicModel} | categories: ${config.cardCategories.join(', ')} | platforms: ${config.platforms.join(', ')}`,
  );

  // 1. Data
  const cards = await fetchMarketData(config);

  // 2. Analysis
  const analysis = analyzeMarket(cards);
  logger.info(
    `Analyzed ${analysis.totalCards} cards — top gainer ${analysis.topGainers[0]?.name} (+${analysis.topGainers[0]?.priceChange24h}%)`,
  );

  // 3. Alerts (rule-based, no model call)
  const alerts = generateAlerts(analysis);
  logger.info(`Generated ${alerts.length} alert(s)`);

  // 4. Content
  const content = await generateAll(analysis, alerts, config);

  // 5. Output
  const batch = { generatedAt: new Date().toISOString(), analysis, alerts, content };
  const { written, schedule } = await saveOutputs(batch, config);
  await postToWebhook({ ...batch, schedule }, config);

  const failures = Object.values(content).filter((c) => c.error).length;
  logger.success(
    `=== Run complete: ${Object.keys(content).length - failures}/${Object.keys(content).length} platforms generated, ${written.length} files ===`,
  );

  return { batch, schedule, written };
}
