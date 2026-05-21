import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';

const localeDir = resolve('src/i18n/locales');
const locales = ['en', 'nl', 'de', 'fr'];

function readLocale(locale) {
  return JSON.parse(readFileSync(resolve(localeDir, `${locale}.json`), 'utf8'));
}

const dictionaries = Object.fromEntries(locales.map((locale) => [locale, readLocale(locale)]));
const baseKeys = Object.keys(dictionaries.en).sort();
let failed = false;

for (const locale of locales) {
  const keys = Object.keys(dictionaries[locale]).sort();
  const missing = baseKeys.filter((key) => !keys.includes(key));
  const extra = keys.filter((key) => !baseKeys.includes(key));
  const empty = keys.filter((key) => String(dictionaries[locale][key]).trim() === '');

  if (missing.length || extra.length || empty.length) {
    failed = true;
    console.error(`Locale ${locale} is not in parity with en.`);
    if (missing.length) console.error(`  Missing: ${missing.join(', ')}`);
    if (extra.length) console.error(`  Extra: ${extra.join(', ')}`);
    if (empty.length) console.error(`  Empty: ${empty.join(', ')}`);
  }
}

if (failed) {
  process.exit(1);
}

console.log(`i18n key parity OK: ${baseKeys.length} keys across ${locales.join(', ')}`);
