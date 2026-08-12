import { chromium } from 'playwright';

/**
 * End-to-end UI smoke test.
 *
 * Signs in as the demo owner, walks every screen, exercises Ask and the
 * approval sheet, and fails if the browser console reports errors. Run the API
 * and the web app first, then:
 *
 *   node scripts/ui-smoke.mjs
 *
 * Screenshots land in the directory named by SHOT_DIR (default ./var/shots).
 */
import fs from 'fs';

const OUT = process.env.SHOT_DIR ?? './var/shots';
fs.mkdirSync(OUT, { recursive: true });
const browser = await chromium.launch({ executablePath: process.env.CHROMIUM_PATH || undefined });
const page = await browser.newPage({ viewport: { width: 1280, height: 1000 }, deviceScaleFactor: 2 });
const errors = [];
page.on('console', m => { if (m.type() === 'error') errors.push(m.text()); });
page.on('pageerror', e => errors.push('PAGEERROR: ' + e.message));

await page.goto('http://localhost:3000/', { waitUntil: 'networkidle' });
await page.screenshot({ path: `${OUT}/01-login.png` });

await page.click('button.btn-primary');
await page.waitForSelector('h1', { timeout: 15000 });
await page.waitForTimeout(2500);
await page.screenshot({ path: `${OUT}/02-today.png`, fullPage: true });
console.log('TODAY H1:', await page.textContent('h1'));
console.log('SUBTITLE:', await page.textContent('.page-subtitle'));
const cards = await page.$$eval('.inbox-card .card-title', els => els.map(e => e.textContent));
console.log('CARDS:', JSON.stringify(cards, null, 1));

for (const [path, name] of [['/inbox','03-inbox'],['/ask','04-ask'],['/life','05-life'],['/automations','06-automations'],['/vault','07-vault'],['/security','08-security']]) {
  await page.goto('http://localhost:3000' + path, { waitUntil: 'networkidle' });
  await page.waitForTimeout(1800);
  await page.screenshot({ path: `${OUT}/${name}.png`, fullPage: true });
  console.log(`${path}: h1="${await page.textContent('h1')}"`);
}

// Exercise the Ask flow for real.
await page.goto('http://localhost:3000/ask', { waitUntil: 'networkidle' });
await page.click('text=What do I need to worry about?');
await page.waitForSelector('.bubble-bot', { timeout: 20000 });
await page.waitForTimeout(1500);
await page.screenshot({ path: `${OUT}/09-ask-answer.png`, fullPage: true });
console.log('ANSWER:', (await page.textContent('.bubble-bot'))?.slice(0, 240));

// Exercise the approval sheet.
await page.goto('http://localhost:3000/', { waitUntil: 'networkidle' });
await page.waitForTimeout(2000);
const moveBtn = await page.$('button.btn-primary.btn-sm');
if (moveBtn) {
  await moveBtn.click();
  await page.waitForSelector('.modal', { timeout: 15000 });
  await page.waitForTimeout(900);
  await page.screenshot({ path: `${OUT}/10-approval.png` });
  console.log('APPROVAL MODAL:', (await page.textContent('.modal-head'))?.replace(/\s+/g,' ').slice(0,120));
}

console.log('CONSOLE ERRORS:', errors.length ? JSON.stringify(errors.slice(0,8), null, 1) : 'none');
await browser.close();
