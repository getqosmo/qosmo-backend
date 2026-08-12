/**
 * Rasterise the brand SVGs into the PNG sizes browsers and app stores want.
 *
 * Uses the Chromium that Playwright already provides rather than adding an
 * image-processing dependency for something that runs twice a year.
 *
 *   node scripts/render-brand.mjs
 *
 * Set CHROMIUM_PATH if Playwright's bundled browser is not where it expects.
 */

import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

import { chromium } from 'playwright';

const here = path.dirname(fileURLToPath(import.meta.url));
const BRAND = path.join(here, '..', 'apps', 'web', 'public', 'brand');

const TARGETS = [
  { source: 'mark.svg', out: 'icon-180.png', width: 180, height: 180 },
  { source: 'mark.svg', out: 'icon-512.png', width: 512, height: 512 },
  { source: 'mark.svg', out: 'icon-192.png', width: 192, height: 192 },
];

const browser = await chromium.launch({
  executablePath: process.env.CHROMIUM_PATH || undefined,
});

for (const target of TARGETS) {
  const svg = fs.readFileSync(path.join(BRAND, target.source), 'utf8');
  const page = await browser.newPage({
    viewport: { width: target.width, height: target.height },
  });
  await page.setContent(
    `<html><body style="margin:0">${svg.replace(
      /width="\d+" height="\d+"/,
      `width="${target.width}" height="${target.height}"`,
    )}</body></html>`,
  );
  await page.screenshot({
    path: path.join(BRAND, target.out),
    omitBackground: true,
  });
  await page.close();
  console.log(`rendered ${target.out} (${target.width}×${target.height})`);
}

// Link preview card. Composed here rather than kept as a binary so it stays
// editable and stays in sync with the design tokens.
const og = await browser.newPage({ viewport: { width: 1200, height: 630 } });
const mark = fs.readFileSync(path.join(BRAND, 'mark.svg'), 'utf8');
await og.setContent(`
<html><body style="margin:0">
  <div style="
      width:1200px;height:630px;background:#fbfaf9;color:#1c1a18;
      font-family:-apple-system,BlinkMacSystemFont,Inter,Segoe UI,Roboto,sans-serif;
      display:flex;flex-direction:column;justify-content:center;padding:0 96px;
      box-sizing:border-box;">
    <div style="transform:scale(1.6);transform-origin:left center;width:64px;">${mark}</div>
    <div style="font-size:76px;font-weight:650;letter-spacing:-2.4px;margin-top:56px;">
      Your life. Running itself.
    </div>
    <div style="font-size:30px;color:#5f5952;margin-top:22px;max-width:820px;line-height:1.45;">
      A local-first personal operating system. It remembers what matters,
      notices what needs you, and acts only where you have said it may.
    </div>
    <div style="position:absolute;bottom:64px;left:96px;font-size:24px;color:#8b847c;">
      MyBot
    </div>
  </div>
</body></html>`);
await og.screenshot({ path: path.join(BRAND, 'og.png') });
console.log('rendered og.png (1200×630)');

await browser.close();
