# Qosmo Content Engine — Developer Guide

Autonomous sports card market content generation system.

## Tech Stack

- Node.js + JavaScript (ES modules)
- Anthropic Claude API (content generation)
- TCG API (sports card market data, with offline fallback)
- node-schedule (automation)
- Axios (HTTP requests)

## Project Structure

- `src/config.js` — Loads/validates environment configuration.
- `src/logger.js` — Timestamped logging.
- `src/dataFetcher.js` — Fetches and analyzes market data; `generateAlerts()`.
- `src/sampleData.js` — Offline fallback dataset.
- `src/contentGenerator.js` — Generates content for all platforms via Claude (one function per platform).
- `src/outputHandler.js` — Saves content to files, builds publishing schedule, optional webhook.
- `src/orchestrator.js` — Main pipeline: data fetch → analysis → alerts → generation → output.
- `src/index.js` — Entry point for one-time runs.
- `src/scheduler.js` — Runs generation on a cron schedule.

## Commands

- `npm install` — Install dependencies.
- `npm start` — Generate content once (uses `index.js`).
- `npm run schedule` — Run scheduler (generates daily at 8 AM by default).
- `npm run schedule -- --now` — Run scheduler and generate immediately.
- `npm run dev` — Watch mode (auto-restart on changes).

## Development Rules

- Use ES modules (import/export).
- Content must be authentic market analysis (not promotional). Reddit posts never mention products.
- Claude API calls use the model from `ANTHROPIC_MODEL` (default `claude-opus-4-8`).
  - The original spec said `claude-opus-4-20250805`, which is not a valid model id; we default to `claude-opus-4-8` and keep the model configurable.
- Max 1500 tokens per content piece (`MAX_TOKENS`).
- Error handling required for API calls — fall back gracefully (TCG → sample data; per-platform failures are recorded, not fatal).

## Key Configurations

- `.env` file required (copy from `.env.example`).
- Output directory: `content/` (configurable via `OUTPUT_DIR`).
- Cron schedule: `0 8 * * *` (configurable via `SCHEDULE`).
- API keys: `ANTHROPIC_API_KEY`, `TCG_API_KEY`.

## How to Extend

1. **Add a new platform**: add a prompt + register it in `PROMPTS`/`GENERATORS` in `contentGenerator.js`, then add its post time in `POST_TIMES` in `outputHandler.js`.
2. **Change data source**: replace the fetch logic in `dataFetcher.js`, keeping the normalized card shape (`{ name, game, set, grade, price, priceChange24h/7d/30d, volume }`).
3. **Customize content**: edit the prompts in `contentGenerator.js` (each platform is its own prompt).
4. **Add new alerts**: modify `generateAlerts()` in `dataFetcher.js`.

## Debugging

- `content/batch-*.json` — complete generation data.
- `content/summary-*.txt` — run overview.
- `content/alerts/` — generated trading alerts.
- Platform content in respective folders (`reddit/`, `twitter/`, etc.).

## Important Notes

- TCG API free tier: ~100 requests/day; the engine falls back to sample data when unavailable.
- Anthropic usage: ~$0.01–0.05 per full run.
- Content is market-focused, NOT promoting Qosmo (initially).
- All Reddit posts avoid product mentions (engagement-first strategy).
