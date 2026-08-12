/**
 * Render the social asset kit.
 *
 *   node scripts/render-social.mjs
 *
 * Composes every tile from HTML and rasterises it with the Chromium Playwright
 * already provides, rather than keeping a folder of binaries somebody has to
 * open a design tool to change. A tile is a few lines of markup here, so
 * fixing a typo is a one-line diff instead of a redesign.
 *
 * Palette and type come from the product's own design system, so the feed and
 * the thing it sells look like one company.
 *
 * Output: www/social/
 */

import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

import { chromium } from 'playwright';

const here = path.dirname(fileURLToPath(import.meta.url));
const OUT = path.join(here, '..', 'www', 'social');
fs.mkdirSync(OUT, { recursive: true });

const PAPER = '#fbfaf9';
const INK = '#1c1a18';
const INK2 = '#5f5952';
const INK3 = '#8b847c';
const ACCENT = '#2f6f5e';
const ACCENT_SOFT = '#eaf2ef';
const DARK = '#14130f';
const DARK_INK = '#f0ece5';

const SANS =
  "-apple-system,BlinkMacSystemFont,Inter,'Segoe UI',Roboto,'Helvetica Neue',Arial,sans-serif";
const SERIF =
  "ui-serif,'Iowan Old Style','Palatino Linotype',Palatino,Georgia,'Times New Roman',serif";
const MONO = "ui-monospace,'SF Mono',Menlo,Consolas,monospace";

/** The mark, inline so it inherits whatever colour the tile wants. */
const mark = (size = 72, tile = ACCENT, stroke = '#ffffff') => `
  <svg width="${size}" height="${size}" viewBox="0 0 64 64">
    <rect width="64" height="64" rx="16" fill="${tile}"/>
    <path d="M16 44V26.5a1.5 1.5 0 0 1 2.56-1.06L32 38.88l13.44-13.44A1.5 1.5 0 0 1 48 26.5V44"
      fill="none" stroke="${stroke}" stroke-width="5.5" stroke-linecap="round" stroke-linejoin="round"/>
    <circle cx="32" cy="20" r="3.25" fill="${stroke}"/>
  </svg>`;

const frame = (inner, { bg = PAPER, fg = INK, pad = 96 } = {}) => `
<html><body style="margin:0">
  <div style="
      width:100%;height:100vh;background:${bg};color:${fg};
      font-family:${SANS};box-sizing:border-box;padding:${pad}px;
      display:flex;flex-direction:column;justify-content:space-between;">
    ${inner}
  </div>
</body></html>`;

/** A tile whose whole job is one sentence. Restraint is the brand. */
const statement = (kicker, headline, footnote, opts = {}) => {
  const { bg = PAPER, fg = INK, sub = INK2, kick = INK3 } = opts;
  return frame(
    `
    <div style="font-size:26px;letter-spacing:0.16em;text-transform:uppercase;font-weight:600;color:${kick}">
      ${kicker}
    </div>
    <div style="font-size:${headline.length > 60 ? 76 : 94}px;line-height:1.04;letter-spacing:-0.04em;
                font-weight:600;text-wrap:balance;">
      ${headline}
    </div>
    <div style="display:flex;align-items:flex-end;justify-content:space-between;gap:40px">
      <div style="font-size:30px;line-height:1.45;color:${sub};max-width:660px">${footnote}</div>
      ${mark(64, opts.markTile ?? ACCENT, opts.markStroke ?? '#ffffff')}
    </div>`,
    { bg, fg },
  );
};

/** The nine-tile launch grid. Read top-left to bottom-right. */
const POSTS = [
  {
    name: '01-hero',
    html: frame(
      `
      <div>${mark(88)}</div>
      <div>
        <div style="font-size:104px;line-height:1;letter-spacing:-0.045em;font-weight:600">
          Your life.<br/>Running itself.
        </div>
        <div style="font-size:32px;color:${INK2};margin-top:38px;line-height:1.45;max-width:760px">
          A private chief of staff that lives on your machine.
        </div>
      </div>
      <div style="font-size:26px;color:${INK3};letter-spacing:0.02em">MyBot</div>`,
    ),
  },
  {
    name: '02-prepares',
    html: statement(
      'The line',
      'MyBot prepares.<br/>You approve.',
      'Anything that touches the world outside your machine waits for you to say yes.',
    ),
  },
  {
    name: '03-brief',
    html: frame(
      `
      <div style="font-size:26px;letter-spacing:0.16em;text-transform:uppercase;font-weight:600;color:${INK3}">
        Every morning
      </div>
      <div style="background:#fff;border:1px solid #e8e4e0;border-radius:28px;padding:56px 52px;
                  font-family:${SERIF};box-shadow:0 24px 60px -40px rgba(28,26,24,.4)">
        <div style="font-size:44px;letter-spacing:-0.02em">Good morning, Alex.</div>
        <div style="font-size:26px;color:${INK3};margin-top:6px">Wednesday, 12 August</div>
        <div style="font-size:30px;color:${INK2};margin-top:34px">Four things need you.</div>
        <div style="font-size:29px;line-height:1.5;margin-top:22px;color:${INK}">
          1.&nbsp; Electric bill is due in 2 days. $148.20.<br/>
          2.&nbsp; Adobe renews 14 August for $79.00.<br/>
          3.&nbsp; Dentist and investor meeting overlap Friday.<br/>
          4.&nbsp; Registration expires in 3 days.
        </div>
        <div style="font-size:27px;color:${INK3};margin-top:34px;font-style:italic">
          Nothing else requires your attention.
        </div>
      </div>
      <div style="font-size:27px;color:${INK2};line-height:1.45">
        No model writes your brief. It comes straight from your own records.
      </div>`,
      { pad: 84 },
    ),
  },
  {
    name: '04-money',
    html: statement(
      "What it won't do — 01",
      'It won’t move<br/>your money.',
      'Not in this version. The plumbing exists and is deliberately switched off.',
      { bg: DARK, fg: DARK_INK, sub: '#b0a99f', kick: '#857e74', markTile: '#6fbfa4', markStroke: DARK },
    ),
  },
  {
    name: '05-email',
    html: statement(
      "What it won't do — 02",
      'It won’t take orders<br/>from your inbox.',
      'Anything that arrives from outside is data, never instructions — including when it’s written to look like instructions.',
    ),
  },
  {
    name: '06-approval',
    html: frame(
      `
      <div style="font-size:26px;letter-spacing:0.16em;text-transform:uppercase;font-weight:600;color:${INK3}">
        Before it acts
      </div>
      <div style="background:#fff;border:1px solid #e8e4e0;border-radius:28px;overflow:hidden;
                  box-shadow:0 24px 60px -40px rgba(28,26,24,.4)">
        <div style="padding:40px 44px;border-bottom:1px solid #e8e4e0;display:flex;align-items:center;gap:18px;flex-wrap:wrap">
          <span style="font-family:${SERIF};font-size:36px">Reschedule “Dentist”</span>
          <span style="font-size:20px;font-weight:600;letter-spacing:.06em;text-transform:uppercase;
                       padding:7px 16px;border-radius:99px;background:${ACCENT_SOFT};color:${ACCENT};
                       border:1px solid #c4ddd4">Low risk</span>
        </div>
        <div style="padding:38px 44px;font-size:28px;line-height:2.0">
          <span style="color:${INK3};display:inline-block;width:210px">Why</span> It overlaps your investor meeting.<br/>
          <span style="color:${INK3};display:inline-block;width:210px">Change</span> Fri 14:00 → Tue 09:30<br/>
          <span style="color:${INK3};display:inline-block;width:210px">If wrong</span> One tap to put it back.
        </div>
        <div style="padding:34px 44px;border-top:1px solid #e8e4e0;background:#f4f2f0;display:flex;gap:16px">
          <span style="background:${ACCENT};color:#fff;font-size:26px;font-weight:600;padding:16px 38px;border-radius:14px">Approve</span>
          <span style="border:1px solid #d6d0ca;font-size:26px;padding:16px 38px;border-radius:14px">Not now</span>
        </div>
      </div>
      <div style="font-size:27px;color:${INK2};line-height:1.45">
        The reason, the change, and whether it can be undone. Every time.
      </div>`,
      { pad: 84 },
    ),
  },
  {
    name: '07-private',
    html: statement(
      'Private by construction',
      'There is no server<br/>holding your life.',
      'Not “we don’t sell your data”. MyBot runs on your machine, and it can be told never to talk to anything it doesn’t run itself.',
      { bg: ACCENT, fg: '#ffffff', sub: 'rgba(255,255,255,.82)', kick: 'rgba(255,255,255,.6)', markTile: '#ffffff', markStroke: ACCENT },
    ),
  },
  {
    name: '08-unhackable',
    html: statement(
      "What it won't do — 03",
      'It won’t call itself<br/>unhackable.',
      'It’s software. It keeps an append-only record of everything it does, so you can check rather than trust.',
    ),
  },
  {
    name: '09-owned',
    html: statement(
      'MyBot',
      'Built to be owned,<br/>not subscribed to.',
      'Your records, your machine, your keys. Including the part where losing them means losing the data — we’d rather say so.',
      { bg: DARK, fg: DARK_INK, sub: '#b0a99f', kick: '#857e74', markTile: '#6fbfa4', markStroke: DARK },
    ),
  },
];

const STORIES = [
  {
    name: 'story-01-tagline',
    html: frame(
      `
      <div>${mark(80)}</div>
      <div>
        <div style="font-size:96px;line-height:1.02;letter-spacing:-0.04em;font-weight:600">
          Your life.<br/>Running itself.
        </div>
        <div style="font-size:34px;color:${INK2};margin-top:40px;line-height:1.45">
          A private chief of staff that lives on your machine — and asks before it acts.
        </div>
      </div>
      <div style="font-size:28px;color:${INK3};font-family:${MONO}">mybot demo</div>`,
      { pad: 110 },
    ),
  },
  {
    name: 'story-02-line',
    html: frame(
      `
      <div style="font-size:26px;letter-spacing:.16em;text-transform:uppercase;font-weight:600;color:${INK3}">
        The line
      </div>
      <div>
        <div style="font-size:88px;line-height:1.04;letter-spacing:-0.04em;font-weight:600">
          MyBot prepares.<br/>You approve.
        </div>
        <div style="margin-top:56px;border-top:3px solid ${ACCENT};padding-top:36px;
                    font-size:32px;color:${INK2};line-height:1.5">
          It can read, notice, draft and remember on its own.<br/><br/>
          Sending, paying, and changing what it’s allowed to do are only ever you.
        </div>
      </div>
      <div>${mark(64)}</div>`,
      { pad: 110 },
    ),
  },
];

const browser = await chromium.launch({ executablePath: process.env.CHROMIUM_PATH || undefined });

async function shoot(html, file, width, height) {
  const page = await browser.newPage({ viewport: { width, height }, deviceScaleFactor: 1 });
  await page.setContent(html, { waitUntil: 'networkidle' });
  await page.screenshot({ path: path.join(OUT, file) });
  await page.close();
  console.log(`  ${file}  ${width}×${height}`);
}

console.log('Feed posts (1080×1080):');
for (const post of POSTS) await shoot(post.html, `${post.name}.png`, 1080, 1080);

console.log('Stories (1080×1920):');
for (const story of STORIES) await shoot(story.html, `${story.name}.png`, 1080, 1920);

console.log('Profile:');
await shoot(
  `<html><body style="margin:0;background:${PAPER}">
     <div style="width:100vw;height:100vh;display:flex;align-items:center;justify-content:center">
       ${mark(600)}
     </div>
   </body></html>`,
  'profile.png',
  720,
  720,
);

await browser.close();
console.log(`\nWritten to ${OUT}`);
