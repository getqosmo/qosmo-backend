/**
 * Rasterise the brand SVGs into the PNG sizes browsers and app stores want,
 * and compose the link-preview card.
 *
 * Uses the Chromium Playwright already provides rather than adding an
 * image-processing dependency for something that runs twice a year.
 *
 *   node scripts/capture-screens.mjs     # first — the OG card uses a real one
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
const SHOTS = path.join(here, '..', 'www', 'shots');

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

/**
 * The link-preview card.
 *
 * This is the single image most people will ever see of MyBot — it is what
 * appears when the link is pasted anywhere. It previously showed the tagline
 * on an empty background, which told a stranger nothing about what the thing
 * *is*.
 *
 * It now carries a real screenshot of the running app, bleeding off the right
 * edge. Real rather than a recreation: a marketing image that draws its own
 * version of the product can drift from it, and the drift always flatters.
 */
const shotPath = path.join(SHOTS, 'today.png');
const shot = fs.existsSync(shotPath)
  ? `data:image/png;base64,${fs.readFileSync(shotPath).toString('base64')}`
  : null;

if (!shot) {
  console.warn('! www/shots/today.png missing — run scripts/capture-screens.mjs first');
}

const mark = fs.readFileSync(path.join(BRAND, 'mark.svg'), 'utf8');
const og = await browser.newPage({ viewport: { width: 1200, height: 630 } });
await og.setContent(`
<html><body style="margin:0">
  <div style="
      width:1200px;height:630px;background:#fbfaf9;color:#1c1a18;position:relative;overflow:hidden;
      font-family:-apple-system,BlinkMacSystemFont,Inter,Segoe UI,Roboto,sans-serif;
      display:flex;align-items:center;">

    <!-- Left: who this is and what it claims. -->
    <div style="width:560px;padding:0 0 0 72px">
      <div style="display:flex;align-items:center;gap:14px">
        <div style="width:52px;height:52px">${mark.replace(/width="\d+" height="\d+"/, 'width="52" height="52"')}</div>
        <div style="font-size:27px;font-weight:650;letter-spacing:-0.8px">MyBot</div>
      </div>

      <div style="font-size:62px;font-weight:650;letter-spacing:-2.3px;line-height:1.02;margin-top:42px">
        Your life.<br/>Running itself.
      </div>

      <div style="font-size:23px;color:#5f5952;margin-top:26px;line-height:1.45;max-width:440px">
        A private chief of staff that lives on your machine. It prepares —
        <span style="color:#2f6f5e;font-weight:600">you approve.</span>
      </div>
    </div>

    <!--
      Right: the actual product, cropped past the sidebar and bleeding off the
      edge. Two clean zones rather than a gradient fade -- a wash over a
      screenshot reads as a rendering fault, not as a design decision, and it
      obscures the very thing the image is there to show.
    -->
    ${
      shot
        ? `<div style="position:absolute;left:600px;top:52px;width:700px;height:526px;
                 border-radius:16px 0 0 16px;overflow:hidden;
                 box-shadow:0 40px 90px -44px rgba(28,26,24,.5), 0 0 0 1px rgba(28,26,24,.08);">
             <img src="${shot}" style="width:1015px;margin-left:-206px;display:block"/>
           </div>`
        : ''
    }
  </div>
</body></html>`);
await og.screenshot({ path: path.join(BRAND, 'og.png') });
console.log('rendered og.png (1200×630)');

await browser.close();
