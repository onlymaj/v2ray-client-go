import { readdirSync, readFileSync, writeFileSync, statSync } from 'node:fs';
import { join } from 'node:path';
import { gzipSync, constants } from 'node:zlib';

const COMPRESSIBLE = /\.(html|js|css|svg|json|txt|map)$/;

function walk(dir) {
  return readdirSync(dir).flatMap((f) => {
    const p = join(dir, f);
    return statSync(p).isDirectory() ? walk(p) : [p];
  });
}

// Writes a .gz next to every text asset in outDir so the Go server can embed
// and serve them with Content-Encoding: gzip. Originals are kept.
export function gzipAssets() {
  let outDir;
  return {
    name: 'v2ray-gzip-assets',
    apply: 'build',
    configResolved(cfg) {
      outDir = cfg.build.outDir;
    },
    closeBundle() {
      for (const file of walk(outDir)) {
        if (!COMPRESSIBLE.test(file)) continue;
        const gz = gzipSync(readFileSync(file), { level: constants.Z_BEST_COMPRESSION });
        writeFileSync(file + '.gz', gz);
      }
    },
  };
}
