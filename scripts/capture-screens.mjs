/**
 * Capture real product screenshots.
 *
 *   mybot demo && mybot serve        # :8000
 *   cd apps/web && npm run build && npx next start   # :3000
 *   node scripts/capture-screens.mjs
 *
 * Real screenshots rather than recreated mockups. A marketing page that draws
 * its own version of the product is a page that can drift from it — and the
 * drift always flatters. These come from the running app.
 *
 * Output: www/shots/
 */
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import { chromium } from 'playwright';

const here = path.dirname(fileURLToPath(import.meta.url));
const OUT = process.env.SHOT_DIR ?? path.join(here, '..', 'www', 'shots');
fs.mkdirSync(OUT, { recursive: true });

const SCREENS = [
  // `full` keeps the sidebar — used for the link-preview card, where showing
  // that this is a real application matters.
  { path: '/', name: 'today', wait: '.inbox-card, h1', full: true },
  // The rest are cropped past the navigation. On a page showing two shots side
  // by side the sidebar appears twice and says nothing the second time; the
  // content is what has to be legible at half width.
  { path: '/egress', name: 'egress', wait: '.stat' },
  { path: '/growth', name: 'growth', wait: '.stat' },
  { path: '/inbox', name: 'inbox', wait: 'h1' },
];

/** Left edge of the content column, past the fixed sidebar. */
const SIDEBAR = 232;

const browser = await chromium.launch({ executablePath: process.env.CHROMIUM_PATH });
// 2x for retina; the site serves them at half size.
const page = await browser.newPage({ viewport: { width: 1240, height: 880 }, deviceScaleFactor: 2 });

await page.goto('http://localhost:3000/', { waitUntil: 'networkidle' });
await page.click('button.btn-primary');
await page.waitForSelector('.nav-secondary', { timeout: 20000 });
await page.waitForTimeout(1500);

for (const screen of SCREENS) {
  await page.goto(`http://localhost:3000${screen.path}`, { waitUntil: 'networkidle' });
  await page.waitForSelector(screen.wait, { timeout: 20000 });
  await page.waitForTimeout(1200);
  await page.screenshot({
    path: path.join(OUT, `${screen.name}.png`),
    ...(screen.full
      ? {}
      : { clip: { x: SIDEBAR, y: 0, width: 1240 - SIDEBAR, height: 880 } }),
  });
  console.log(`  ${screen.name}.png${screen.full ? '' : ' (content only)'}`);
}

await browser.close();
console.log(`\nWritten to ${OUT}`);
