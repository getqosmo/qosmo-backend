// Runs content generation on a cron schedule: `npm run schedule`.
// Pass `--now` to also generate immediately on startup:
//   npm run schedule -- --now
import schedule from 'node-schedule';
import { run } from './orchestrator.js';
import { getConfig } from './config.js';
import { logger } from './logger.js';

const runNow = process.argv.includes('--now');
const config = getConfig();

async function safeRun(label) {
  logger.info(`Scheduler: starting ${label} run`);
  try {
    await run();
  } catch (error) {
    // Never let a single failed run kill the long-lived scheduler process.
    logger.error(`Scheduled run failed: ${error.message}`);
  }
}

if (runNow) {
  await safeRun('immediate');
}

const job = schedule.scheduleJob(config.schedule, () => {
  safeRun('scheduled');
});

if (!job) {
  logger.error(`Invalid cron expression: "${config.schedule}". Check SCHEDULE in .env.`);
  process.exit(1);
}

logger.success(`Scheduler active. Cron: "${config.schedule}". Next run: ${job.nextInvocation()}`);
logger.info('Press Ctrl+C to stop.');

// Keep the process alive and shut down cleanly.
for (const sig of ['SIGINT', 'SIGTERM']) {
  process.on(sig, () => {
    logger.info(`Received ${sig} — shutting down scheduler.`);
    schedule.gracefulShutdown().then(() => process.exit(0));
  });
}
