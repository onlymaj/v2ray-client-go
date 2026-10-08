// Prints the gzipped size of every file in dist/ and fails over the budget.
import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join, relative } from 'node:path';
import { gzipSync, constants } from 'node:zlib';

const LIMIT = 150 * 1024;
const dist = new URL('../dist', import.meta.url).pathname;

function walk(dir) {
  return readdirSync(dir).flatMap((f) => {
    const p = join(dir, f);
    return statSync(p).isDirectory() ? walk(p) : [p];
  });
}

let total = 0;
const rows = [];
for (const file of walk(dist)) {
  if (file.endsWith('.gz')) continue;
  const raw = readFileSync(file);
  const gz = gzipSync(raw, { level: constants.Z_BEST_COMPRESSION }).length;
  total += gz;
  rows.push([relative(dist, file), raw.length, gz]);
}
rows.sort((a, b) => b[2] - a[2]);
const kb = (n) => (n / 1024).toFixed(1).padStart(8) + ' KB';
for (const [name, raw, gz] of rows) console.log(`${kb(raw)} raw ${kb(gz)} gz  ${name}`);
console.log(`total gzipped: ${(total / 1024).toFixed(1)} KB (limit ${LIMIT / 1024} KB)`);
if (total > LIMIT) {
  console.error('over size budget');
  process.exit(1);
}
