/**
 * Build the standalone marketing page.
 *
 *   node scripts/capture-screens.mjs
 *   node scripts/build-site.mjs
 *
 * Inlines the real product screenshots as data URIs so `www/index.html` is a
 * single self-contained file — it can be dropped on any host, or published as
 * an artifact, with nothing to go missing. Source of truth is
 * `www/index.src.html`; the `{{shot:name}}` placeholders are substituted here.
 *
 * Screenshots are real rather than recreated. A marketing page that draws its
 * own version of the product can drift from it, and the drift always flatters.
 */
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const here = path.dirname(fileURLToPath(import.meta.url));
const WWW = path.join(here, '..', 'www');

let html = fs.readFileSync(path.join(WWW, 'index.src.html'), 'utf8');

html = html.replace(/\{\{shot:([a-z-]+)\}\}/g, (_match, name) => {
  const file = path.join(WWW, 'shots', `${name}.png`);
  if (!fs.existsSync(file)) {
    throw new Error(`missing screenshot: ${file} — run scripts/capture-screens.mjs`);
  }
  return `data:image/png;base64,${fs.readFileSync(file).toString('base64')}`;
});

fs.writeFileSync(path.join(WWW, 'index.html'), html);
const kb = Math.round(fs.statSync(path.join(WWW, 'index.html')).size / 1024);
console.log(`built www/index.html (${kb} KB)`);
