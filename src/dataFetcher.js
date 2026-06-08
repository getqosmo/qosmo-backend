// Fetches and analyzes sports card market data.
//
// The TCG API free tier is best-effort: if the request fails (rate limit,
// network policy, schema drift) we fall back to a representative offline
// dataset so the rest of the pipeline still produces content. To swap data
// sources, replace `fetchCategory()` but keep the normalized card shape:
//
//   { id, name, game, set, number, rarity, grade,
//     price, priceChange24h, priceChange7d, priceChange30d, volume }
//
import axios from 'axios';
import { logger } from './logger.js';
import { sampleCards } from './sampleData.js';

const ROUND = (n) => Math.round(n * 100) / 100;

// Normalize an arbitrary TCG API record into our internal card shape. This is
// intentionally defensive — different endpoints/versions name fields
// differently, so we probe a few common keys.
function normalizeCard(raw, game) {
  const price =
    raw.price ?? raw.marketPrice ?? raw.market_price ?? raw.prices?.market ?? null;
  if (price == null) return null;
  return {
    id: String(raw.id ?? raw.uuid ?? `${game}-${raw.name}`),
    name: raw.name ?? raw.cardName ?? 'Unknown card',
    game,
    set: raw.set ?? raw.setName ?? raw.set_name ?? '',
    number: raw.number ?? raw.collectorNumber ?? '',
    rarity: raw.rarity ?? '',
    grade: raw.grade ?? 'raw',
    price: ROUND(Number(price)),
    priceChange24h: ROUND(Number(raw.priceChange24h ?? raw.change_24h ?? 0)),
    priceChange7d: ROUND(Number(raw.priceChange7d ?? raw.change_7d ?? 0)),
    priceChange30d: ROUND(Number(raw.priceChange30d ?? raw.change_30d ?? 0)),
    volume: Number(raw.volume ?? raw.sales24h ?? raw.salesCount ?? 0),
  };
}

async function fetchCategory(category, config) {
  const url = `${config.tcgApiBase}/cards`;
  const headers = config.tcgApiKey ? { Authorization: `Bearer ${config.tcgApiKey}` } : {};
  const response = await axios.get(url, {
    headers,
    params: { game: category, sort: 'volume', limit: 50 },
    timeout: 15000,
  });
  const records = Array.isArray(response.data) ? response.data : response.data?.data ?? [];
  return records.map((r) => normalizeCard(r, category)).filter(Boolean);
}

// Returns a flat, normalized list of cards across all requested categories.
// Always returns *something* usable — falls back to sample data per category.
export async function fetchMarketData(config) {
  const cards = [];
  for (const category of config.cardCategories) {
    if (config.useSampleData) {
      cards.push(...sampleCards(category));
      continue;
    }
    try {
      const fetched = await fetchCategory(category, config);
      if (fetched.length) {
        logger.success(`Fetched ${fetched.length} ${category} cards from TCG API`);
        cards.push(...fetched);
      } else {
        logger.warn(`TCG API returned no ${category} cards — using sample data`);
        cards.push(...sampleCards(category));
      }
    } catch (error) {
      logger.warn(`TCG API fetch failed for ${category} (${error.message}) — using sample data`);
      cards.push(...sampleCards(category));
    }
  }
  return cards;
}

function topBy(cards, key, count, dir = 'desc') {
  const sorted = [...cards].sort((a, b) => (dir === 'desc' ? b[key] - a[key] : a[key] - b[key]));
  return sorted.slice(0, count);
}

// Computes the market picture the content generator reasons over.
export function analyzeMarket(cards) {
  const count = cards.length || 1;
  const avgChange24h = ROUND(cards.reduce((s, c) => s + c.priceChange24h, 0) / count);
  const avgChange7d = ROUND(cards.reduce((s, c) => s + c.priceChange7d, 0) / count);
  const totalVolume = cards.reduce((s, c) => s + c.volume, 0);

  // Anomalies: high relative volume but flat/declining price (accumulation), or
  // a sharp 24h move that diverges from the 7d trend (potential reversal).
  const avgVolume = totalVolume / count;
  const anomalies = cards
    .filter(
      (c) =>
        (c.volume > avgVolume * 2 && c.priceChange24h <= 1) ||
        Math.sign(c.priceChange24h) !== Math.sign(c.priceChange7d && c.priceChange7d),
    )
    .slice(0, 5);

  return {
    generatedAt: new Date().toISOString(),
    totalCards: cards.length,
    games: [...new Set(cards.map((c) => c.game))],
    topGainers: topBy(cards, 'priceChange24h', 5, 'desc'),
    topLosers: topBy(cards, 'priceChange24h', 5, 'asc'),
    volumeLeaders: topBy(cards, 'volume', 5, 'desc'),
    biggestMovers7d: topBy(
      cards.map((c) => ({ ...c, abs7d: Math.abs(c.priceChange7d) })),
      'abs7d',
      5,
      'desc',
    ),
    anomalies,
    stats: { avgChange24h, avgChange7d, totalVolume, avgVolume: ROUND(avgVolume) },
  };
}

// Rule-based trading alerts derived from the analysis. These are deterministic
// (no model call) so they're cheap, reproducible, and safe to act on.
export function generateAlerts(analysis) {
  const alerts = [];
  const now = new Date().toISOString();

  for (const card of analysis.topGainers) {
    if (card.priceChange24h >= 10) {
      alerts.push({
        type: 'surge',
        severity: card.priceChange24h >= 25 ? 'high' : 'medium',
        card: card.name,
        game: card.game,
        metric: `+${card.priceChange24h}% (24h)`,
        price: card.price,
        message: `${card.name} surged ${card.priceChange24h}% in 24h to $${card.price}.`,
        timestamp: now,
      });
    }
  }

  for (const card of analysis.topLosers) {
    if (card.priceChange24h <= -10) {
      alerts.push({
        type: 'drop',
        severity: card.priceChange24h <= -25 ? 'high' : 'medium',
        card: card.name,
        game: card.game,
        metric: `${card.priceChange24h}% (24h)`,
        price: card.price,
        message: `${card.name} dropped ${card.priceChange24h}% in 24h to $${card.price}.`,
        timestamp: now,
      });
    }
  }

  for (const card of analysis.anomalies) {
    alerts.push({
      type: 'volume_anomaly',
      severity: 'low',
      card: card.name,
      game: card.game,
      metric: `${card.volume} sales / 24h`,
      price: card.price,
      message: `Unusual volume on ${card.name} (${card.volume} sales) without a matching price move — possible accumulation.`,
      timestamp: now,
    });
  }

  return alerts;
}
