// Entry point for one-time runs: `npm start`.
// Fetches data, generates all content once, writes it to OUTPUT_DIR, and exits.
import { run } from './orchestrator.js';
import { logger } from './logger.js';

run()
  .then(({ written }) => {
    logger.info(`Done. Review your content (${written.length} files) before posting.`);
    process.exit(0);
  })
  .catch((error) => {
    logger.error(error.message);
    process.exit(1);
  });
