// Persists generated content to disk and prepares it for review/posting.
//
// Layout produced under OUTPUT_DIR:
//   reddit/ twitter/ tiktok/ instagram/ email/ market-analysis/   (one file each)
//   alerts/alerts-<stamp>.json        trading alerts (JSON)
//   schedule-<stamp>.json             suggested publishing schedule
//   batch-<stamp>.json                complete generation data
//   summary-<stamp>.txt               human-readable overview
import { mkdir, writeFile } from 'node:fs/promises';
import path from 'node:path';
import axios from 'axios';
import { logger } from './logger.js';

// Filesystem-safe timestamp, e.g. 2026-06-08T14-30-00.
function stamp(date = new Date()) {
  return date.toISOString().replace(/:/g, '-').replace(/\..+$/, '');
}

// Default posting cadence per platform (local time). Adjust to taste.
const POST_TIMES = {
  reddit: '09:00',
  twitter: '12:00',
  tiktok: '17:00',
  instagram: '18:30',
  email: '07:30',
  'market-analysis': '08:00',
};

function buildSchedule(content, when) {
  const date = when.toISOString().slice(0, 10);
  return {
    date,
    generatedAt: when.toISOString(),
    posts: Object.values(content)
      .filter((item) => !item.error)
      .map((item) => ({
        platform: item.platform,
        suggestedTime: `${date}T${POST_TIMES[item.platform] || '12:00'}:00`,
        status: 'pending_review',
      })),
  };
}

function asMarkdown(item, analysis) {
  if (item.error) {
    return `# ${item.platform} — generation failed\n\nError: ${item.error}\n`;
  }
  return [
    `# ${item.platform} content`,
    '',
    `Generated: ${item.generatedAt}`,
    `Market as of: ${analysis.generatedAt}`,
    '',
    '---',
    '',
    item.text,
    '',
  ].join('\n');
}

function buildSummary(batch) {
  const { analysis, alerts, content } = batch;
  const lines = [
    'QOSMO CONTENT ENGINE — RUN SUMMARY',
    '==================================',
    `Run at:        ${batch.generatedAt}`,
    `Market as of:  ${analysis.generatedAt}`,
    `Tracked cards: ${analysis.totalCards} (${analysis.games.join(', ')})`,
    `Avg 24h move:  ${analysis.stats.avgChange24h}%`,
    `Alerts:        ${alerts.length}`,
    '',
    'TOP GAINERS (24h):',
    ...analysis.topGainers.map((c) => `  ${c.name}: +${c.priceChange24h}% ($${c.price})`),
    '',
    'TOP LOSERS (24h):',
    ...analysis.topLosers.map((c) => `  ${c.name}: ${c.priceChange24h}% ($${c.price})`),
    '',
    'CONTENT GENERATED:',
    ...Object.values(content).map(
      (item) => `  ${item.platform}: ${item.error ? `FAILED (${item.error})` : 'ok'}`,
    ),
    '',
  ];
  return lines.join('\n');
}

// Writes the whole batch to disk and returns the paths created.
export async function saveOutputs(batch, config) {
  const when = new Date(batch.generatedAt);
  const id = stamp(when);
  const root = path.resolve(config.outputDir);
  const written = [];

  // Per-platform content files.
  for (const item of Object.values(batch.content)) {
    const dir = path.join(root, item.platform);
    await mkdir(dir, { recursive: true });
    const file = path.join(dir, `${item.platform}-${id}.md`);
    await writeFile(file, asMarkdown(item, batch.analysis), 'utf8');
    written.push(file);
  }

  // Alerts.
  const alertsDir = path.join(root, 'alerts');
  await mkdir(alertsDir, { recursive: true });
  const alertsFile = path.join(alertsDir, `alerts-${id}.json`);
  await writeFile(alertsFile, JSON.stringify(batch.alerts, null, 2), 'utf8');
  written.push(alertsFile);

  // Publishing schedule.
  const schedule = buildSchedule(batch.content, when);
  const scheduleFile = path.join(root, `schedule-${id}.json`);
  await writeFile(scheduleFile, JSON.stringify(schedule, null, 2), 'utf8');
  written.push(scheduleFile);

  // Complete batch + human summary.
  const batchFile = path.join(root, `batch-${id}.json`);
  await writeFile(batchFile, JSON.stringify({ ...batch, schedule }, null, 2), 'utf8');
  written.push(batchFile);

  const summaryFile = path.join(root, `summary-${id}.txt`);
  await writeFile(summaryFile, buildSummary(batch), 'utf8');
  written.push(summaryFile);

  logger.success(`Wrote ${written.length} files to ${root}`);
  return { written, schedule };
}

// Optional extra delivery channel: POST the full batch as JSON to a webhook.
export async function postToWebhook(batch, config) {
  if (!config.webhookUrl) return false;
  try {
    await axios.post(config.webhookUrl, batch, {
      headers: { 'Content-Type': 'application/json' },
      timeout: 15000,
    });
    logger.success(`Posted batch to webhook: ${config.webhookUrl}`);
    return true;
  } catch (error) {
    logger.error(`Webhook POST failed: ${error.message}`);
    return false;
  }
}
