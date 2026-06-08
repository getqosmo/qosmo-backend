# Qosmo Content Engine

Autonomous sports card market content generation system. Pulls market data,
analyzes it, and generates platform-specific content for Reddit, Twitter,
TikTok, Instagram, and email — ready to review and post.

## What It Does

Every day (or on your schedule):

1. **Fetches** sports card market data (Pokémon, Magic, sports).
2. **Analyzes** price movements, volume, and market anomalies.
3. **Generates** rule-based trading alerts.
4. **Creates** authentic, platform-optimized content (not promotional):
   - Reddit posts (discussion starters, no product mentions)
   - Twitter/X threads (market analysis)
   - TikTok scripts (short-form, with hooks)
   - Instagram captions (3 variations)
   - Email newsletters (detailed)
   - Market analysis reports (deep dives)
5. **Outputs** everything to `content/`, plus a suggested publishing schedule.

## Quick Start

### 1. Install dependencies

```bash
npm install
```

### 2. Configure environment

```bash
cp .env.example .env
```

Then edit `.env` and set at minimum:

- `ANTHROPIC_API_KEY` — from <https://console.anthropic.com>
- `TCG_API_KEY` — optional; from <https://tcgapi.dev> (leave blank for the free tier)

### 3. Generate content once

```bash
npm start
```

This fetches market data and generates all content. Check the `content/` folder.

### 4. Run on a schedule (optional)

```bash
npm run schedule
```

Or run immediately and then keep the schedule:

```bash
npm run schedule -- --now
```

## Output Structure

```
content/
├── reddit/            # Reddit posts (.md)
├── twitter/           # Twitter threads (.md)
├── tiktok/            # TikTok scripts (.md)
├── instagram/         # Instagram captions (.md)
├── email/             # Email newsletters (.md)
├── market-analysis/   # Detailed reports (.md)
├── alerts/            # Trading alerts (.json)
├── schedule-*.json    # Suggested publishing schedule
├── batch-*.json       # Complete generation data
└── summary-*.txt      # Human-readable run overview
```

## How It Works

```
Market Data ➜ Analysis ➜ Alerts ➜ Content Gen ➜ Platform Files ➜ Ready to Post
```

### Data source

Uses the **TCG API** (`tcgapi.dev`). If the API is unreachable, rate-limited,
or returns nothing (or if `USE_SAMPLE_DATA=true`), the engine falls back to a
built-in, realistically-shaped **offline sample dataset** so a run always
produces content. To swap data sources, replace the fetch logic in
`src/dataFetcher.js` and keep the normalized card shape.

### Content strategy

- **Reddit**: educational insights, no product mentions.
- **Twitter**: market-analysis threads with specific cards.
- **TikTok/Instagram**: short scripts/captions with hooks.
- **Email**: comprehensive market summary.
- **Analysis**: deep dives on specific opportunities and risks.

## Configuration

All configuration is via `.env` (see `.env.example`):

| Variable           | Default                                                   | Purpose                                   |
| ------------------ | -------------------------------------------------------- | ----------------------------------------- |
| `ANTHROPIC_API_KEY`| —                                                       | **Required.** Claude API key.             |
| `ANTHROPIC_MODEL`  | `claude-opus-4-8`                                        | Model used for generation.                |
| `MAX_TOKENS`       | `1500`                                                   | Max tokens per content piece.             |
| `TCG_API_KEY`      | —                                                       | Optional TCG API key.                     |
| `TCG_API_BASE`     | `https://api.tcgapi.dev/v1`                              | TCG API base URL.                         |
| `USE_SAMPLE_DATA`  | `false`                                                  | Force the offline sample dataset.         |
| `CARD_CATEGORIES`  | `sports,pokemon,magic`                                   | Card games to fetch.                      |
| `PLATFORMS`        | `reddit,twitter,tiktok,instagram,email,market-analysis` | Platforms to generate.                    |
| `OUTPUT_DIR`       | `./content`                                              | Where output is written.                  |
| `SCHEDULE`         | `0 8 * * *`                                              | Cron for the scheduler.                   |
| `WEBHOOK_URL`      | —                                                       | Optional: also POST the batch JSON here.  |

> **Model note:** the project brief referenced `claude-opus-4-20250805`, which
> is not a valid Claude model id. The engine defaults to `claude-opus-4-8`
> (current most-capable Opus). Override with `ANTHROPIC_MODEL` if you need a
> different model.

## Cost & Limits

- **Anthropic**: roughly $0.01–0.05 per full run (6 pieces × ~1500 tokens).
- **TCG API** free tier: ~100 requests/day.

## Troubleshooting

- **"ANTHROPIC_API_KEY is required"** — create `.env` from `.env.example` and set a valid key.
- **"TCG API fetch failed … using sample data"** — the API was unreachable or rate-limited; the run still completes on sample data. Set `USE_SAMPLE_DATA=true` to skip the network entirely.
- **Content looks generic** — review and customize before posting; the first few runs help you tune the prompts in `src/contentGenerator.js`.

## For Qosmo Integration

Content is intentionally market-focused and **does not promote Qosmo**
(engagement-first strategy). As the Qosmo app develops you can replace the data
source with your own feed, then gradually introduce Qosmo into non-Reddit
content.

---

**Built for**: Qosmo collectibles platform · **Version**: 1.0
